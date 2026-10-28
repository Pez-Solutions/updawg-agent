//! Reads the files that say what this machine is.
//!
//! Every read goes through a [`Root`] so tests can point it at a fixture
//! directory. An optional source that is missing gives `None`; only the facts
//! nothing works without return an error.

use crate::{CollectorError, Result};
use std::{
    path::{Path, PathBuf},
    process::Command,
};
use updawg_protocol::Ecosystem;

/// A filesystem to read facts from. `/` in production, a fixture in tests.
#[derive(Debug, Clone)]
pub struct Root {
    path: PathBuf,
}

impl Default for Root {
    fn default() -> Self {
        Self::new("/")
    }
}

impl Root {
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    #[must_use]
    pub fn join(&self, rel: &str) -> PathBuf {
        self.path.join(rel)
    }

    #[must_use]
    pub fn exists(&self, rel: &str) -> bool {
        self.join(rel).exists()
    }

    /// Reads a file, trimmed. `None` if it is absent, unreadable or empty.
    #[must_use]
    pub fn read(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.join(rel))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Like [`Root::read`], but a missing file is an error.
    pub fn require(&self, rel: &str, name: &'static str) -> Result<String> {
        self.read(rel)
            .ok_or(CollectorError::SourceUnavailable { input: name })
    }

    /// Whether this root is the real filesystem.
    ///
    /// Subprocesses always see the real machine, so collectors only shell out
    /// when this is true. Otherwise a test would report the machine it runs on.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.path == Path::new("/")
    }
}

/* ------------------------------------------------------------- os-release */

/// The fields of `/etc/os-release` the agent uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsRelease {
    pub id: String,
    pub version_id: String,
    pub codename: Option<String>,
    /// `ID_LIKE`, split: `rhel fedora` on Rocky, `fedora` on Amazon Linux.
    /// Lets unlisted derivatives be classified by family.
    pub like: Vec<String>,
}

impl OsRelease {
    /// # Errors
    /// [`CollectorError::Unparseable`] if there is no `ID` field.
    pub fn parse(raw: &str) -> Result<Self> {
        let mut id = None;
        let mut version_id = None;
        let mut codename = None;
        let mut id_like = Vec::new();

        for raw_line in raw.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((field, raw_value)) = line.split_once('=') else {
                continue;
            };
            // values may or may not be quoted: VERSION_ID="24.04", ID=debian
            let value = raw_value.trim().trim_matches(['"', '\'']).to_string();
            match field.trim() {
                "ID" => id = Some(value),
                "VERSION_ID" => version_id = Some(value),
                "VERSION_CODENAME" => codename = Some(value),
                "ID_LIKE" => {
                    id_like = value.split_whitespace().map(ToString::to_string).collect();
                }
                _ => {}
            }
        }

        let Some(id) = id.filter(|s| !s.is_empty()) else {
            return Err(CollectorError::Unparseable {
                input: "/etc/os-release",
                detail: "no ID field".into(),
            });
        };

        Ok(Self {
            id,
            // Rolling releases (Arch) have no VERSION_ID. The EOL logic
            // knows "rolling".
            version_id: version_id
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "rolling".into()),
            codename: codename.filter(|s| !s.is_empty()),
            like: id_like,
        })
    }

    /// Whether this is a Red Hat-family distribution. Checks `ID_LIKE` as well
    /// as `ID`, so Rocky, Alma, Amazon Linux and future rebuilds match without
    /// being listed.
    #[must_use]
    pub fn is_rhel_like(&self) -> bool {
        const FAMILY: [&str; 4] = ["rhel", "fedora", "centos", "amzn"];
        FAMILY.contains(&self.id.as_str()) || self.like.iter().any(|l| FAMILY.contains(&l.as_str()))
    }

    #[must_use]
    pub fn is_debian_like(&self) -> bool {
        const FAMILY: [&str; 2] = ["debian", "ubuntu"];
        FAMILY.contains(&self.id.as_str()) || self.like.iter().any(|l| FAMILY.contains(&l.as_str()))
    }
}

/// Parses `/etc/os-release`, falling back to `/usr/lib/os-release`.
pub fn os_release(root: &Root) -> Result<OsRelease> {
    let raw = root
        .read("etc/os-release")
        .or_else(|| root.read("usr/lib/os-release"))
        .ok_or(CollectorError::SourceUnavailable {
            input: "/etc/os-release",
        })?;
    OsRelease::parse(&raw)
}

/* -------------------------------------------------------------- identity */

/// `/etc/machine-id`, falling back to the D-Bus copy on older systems.
///
/// # Errors
/// Fails if it is missing or empty. Images meant for cloning ship an empty
/// file for first boot to fill in, and using it would give every clone the
/// same identity.
pub fn machine_id(root: &Root) -> Result<String> {
    let id = root
        .read("etc/machine-id")
        .or_else(|| root.read("var/lib/dbus/machine-id"))
        .ok_or(CollectorError::SourceUnavailable {
            input: "/etc/machine-id",
        })?;

    if id.is_empty() {
        return Err(CollectorError::Unparseable {
            input: "/etc/machine-id",
            detail: "empty; this host has not been assigned a machine id yet".into(),
        });
    }
    // systemd specifies 32 lowercase hex characters. We only ever compare it
    // for equality, so warn about anything else and use it anyway.
    if id.len() != 32 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        tracing::warn!(
            machine_id_len = id.len(),
            "machine id is not the usual 32 hex characters; using it anyway"
        );
    }
    Ok(id)
}

/// The kernel release, as `uname -r` prints it.
pub fn kernel(root: &Root) -> Result<String> {
    root.require("proc/sys/kernel/osrelease", "/proc/sys/kernel/osrelease")
}

pub fn hostname(root: &Root) -> Result<String> {
    if let Some(name) = root.read("proc/sys/kernel/hostname") {
        return Ok(name);
    }
    if !root.is_live() {
        return Err(CollectorError::SourceUnavailable {
            input: "/proc/sys/kernel/hostname",
        });
    }
    // not Linux, or a container without the usual /proc
    run("hostname", &[]).ok_or(CollectorError::SourceUnavailable {
        input: "/proc/sys/kernel/hostname",
    })
}

/// The fully-qualified name, if this host has one. Many hosts don't. It goes
/// through the resolver and can hang, so it is optional.
#[must_use]
pub fn fqdn(root: &Root) -> Option<String> {
    if !root.is_live() {
        return None;
    }
    run("hostname", &["--fqdn"]).filter(|f| f.contains('.'))
}

/// The architecture this binary was built for, which is the one it runs on.
/// Avoids parsing `uname -m`.
#[must_use]
pub fn arch() -> String {
    std::env::consts::ARCH.to_string()
}

/// What this host is virtualized by, if anything.
///
/// Asks `systemd-detect-virt` first, then falls back to `/sys` for hosts
/// without systemd. `None` covers both bare metal and "could not tell".
#[must_use]
pub fn virtualization(root: &Root) -> Option<String> {
    if root.is_live()
        && let Some(v) = run("systemd-detect-virt", &[])
        && v != "none"
    {
        return Some(v);
    }
    // Xen
    if let Some(t) = root.read("sys/hypervisor/type") {
        return Some(t);
    }
    let product = root.read("sys/class/dmi/id/product_name")?;
    known_hypervisor(&product).map(ToString::to_string)
}

fn known_hypervisor(product: &str) -> Option<&'static str> {
    let p = product.to_ascii_lowercase();
    if p.contains("kvm") {
        Some("kvm")
    } else if p.contains("vmware") {
        Some("vmware")
    } else if p.contains("virtualbox") {
        Some("oracle")
    } else if p.contains("hvm domu") {
        Some("xen")
    } else if p.contains("virtual machine") {
        Some("microsoft")
    } else {
        None
    }
}

pub fn ecosystem(root: &Root) -> Result<Ecosystem> {
    if root.exists("usr/bin/dpkg") {
        Ok(Ecosystem::Deb)
    } else if root.exists("usr/bin/rpm") {
        Ok(Ecosystem::Rpm)
    } else {
        Err(CollectorError::SourceUnavailable {
            input: "dpkg or rpm",
        })
    }
}

/// The current boot's identifier. The server uses a change in it to detect
/// reboots it didn't ask for.
pub fn boot_id(root: &Root) -> Result<String> {
    root.require(
        "proc/sys/kernel/random/boot_id",
        "/proc/sys/kernel/random/boot_id",
    )
}

/* ------------------------------------------------------------ subprocess */

/// Runs a command and returns its trimmed stdout, or `None` on any failure.
/// Callers treat a missing tool and a failing one the same way.
#[must_use]
pub fn run(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Runs a command and returns its exit status.
#[must_use]
pub fn run_status(program: &str, args: &[&str]) -> Option<i32> {
    Command::new(program)
        .args(args)
        .output()
        .ok()?
        .status
        .code()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_handles_quoted_and_unquoted_values() {
        let parsed = OsRelease::parse(
            "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID_LIKE=debian\n",
        )
        .unwrap();
        assert_eq!(parsed.id, "ubuntu");
        assert_eq!(parsed.version_id, "24.04");
        assert_eq!(parsed.codename.as_deref(), Some("noble"));
        assert_eq!(parsed.like, vec!["debian"]);
    }

    // Real os-release contents. Family detection picks the reboot-required
    // check, so this matters.
    #[test]
    fn every_supported_family_is_recognised() {
        let cases = [
            (
                "ID=ubuntu\nVERSION_ID=\"24.04\"\nID_LIKE=debian\n",
                true,
                false,
            ),
            ("ID=debian\nVERSION_ID=\"13\"\n", true, false),
            (
                "ID=\"rocky\"\nVERSION_ID=\"9.4\"\nID_LIKE=\"rhel centos fedora\"\n",
                false,
                true,
            ),
            (
                "ID=\"almalinux\"\nVERSION_ID=\"9.4\"\nID_LIKE=\"rhel centos fedora\"\n",
                false,
                true,
            ),
            (
                "ID=\"amzn\"\nVERSION_ID=\"2023\"\nID_LIKE=\"fedora\"\n",
                false,
                true,
            ),
            ("ID=rhel\nVERSION_ID=\"9.4\"\n", false, true),
        ];

        for (raw, debian, rhel) in cases {
            let os = OsRelease::parse(raw).unwrap();
            assert_eq!(os.is_debian_like(), debian, "debian-like for {}", os.id);
            assert_eq!(os.is_rhel_like(), rhel, "rhel-like for {}", os.id);
        }
    }

    #[test]
    fn an_unknown_rebuild_is_placed_by_id_like() {
        let os = OsRelease::parse("ID=somethingnew\nID_LIKE=\"rhel\"\n").unwrap();
        assert!(os.is_rhel_like());
        assert!(!os.is_debian_like());
    }

    #[test]
    fn a_rolling_release_without_a_version_still_collects() {
        let parsed = OsRelease::parse("ID=arch\nNAME=\"Arch Linux\"\n").unwrap();
        assert_eq!(parsed.version_id, "rolling");
        assert!(!parsed.is_debian_like());
        assert!(!parsed.is_rhel_like());
    }

    #[test]
    fn os_release_without_an_id_is_an_error_not_a_guess() {
        let err = OsRelease::parse("NAME=\"Something\"\n").unwrap_err();
        assert!(
            matches!(err, CollectorError::Unparseable { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn dmi_product_names_map_onto_hypervisors() {
        assert_eq!(known_hypervisor("KVM"), Some("kvm"));
        assert_eq!(known_hypervisor("VMware Virtual Platform"), Some("vmware"));
        assert_eq!(known_hypervisor("VirtualBox"), Some("oracle"));
        assert_eq!(known_hypervisor("HVM domU"), Some("xen"));
        assert_eq!(known_hypervisor("Virtual Machine"), Some("microsoft"));
        assert_eq!(known_hypervisor("PowerEdge R640"), None);
    }

    #[test]
    fn a_fixture_root_never_runs_a_subprocess() {
        let root = Root::new("/nonexistent-fixture");
        assert!(!root.is_live());
        assert!(fqdn(&root).is_none());
        assert!(hostname(&root).is_err());
    }
}
