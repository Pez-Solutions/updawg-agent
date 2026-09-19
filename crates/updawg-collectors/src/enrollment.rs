//! The facts needed to enroll, gathered before the host has an identity.
//!
//! Deliberately smaller than the full inventory (DAWG-33). Enrollment needs
//! just enough to create the host record and tell one machine from another;
//! everything else arrives on the first inventory upload, after the host has a
//! certificate and the operator has had a chance to look at what is being sent.
//!
//! Everything reads from files under a root that the tests can redirect, so
//! this is testable without a Linux host and without mocking the filesystem.

use crate::{CollectorError, Result};
use std::path::{Path, PathBuf};
use updawg_protocol::HostFacts;

/// What identifies this machine, before the server has named it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentFacts {
    /// `/etc/machine-id`. The server matches on this to recognise a host it has
    /// seen before, so a rebuilt machine keeps its history.
    pub machine_id: String,
    pub hostname: String,
    pub facts: HostFacts,
}

/// Reads the handful of files enrollment needs.
#[derive(Debug, Clone)]
pub struct EnrollmentCollector {
    root: PathBuf,
}

impl Default for EnrollmentCollector {
    fn default() -> Self {
        Self::new("/")
    }
}

impl EnrollmentCollector {
    #[must_use]
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    fn read(&self, rel: &str) -> std::io::Result<String> {
        std::fs::read_to_string(self.root.join(rel))
    }

    /// Gather everything `POST /enroll` needs.
    ///
    /// # Errors
    /// Fails if the machine id or the distribution cannot be determined. Both
    /// are required: enrolling a host whose identity or platform is unknown
    /// would create a record nobody can act on.
    pub fn gather(&self) -> Result<EnrollmentFacts> {
        let machine_id = self.machine_id()?;
        let hostname = self.hostname()?;
        let os = self.os_release()?;

        Ok(EnrollmentFacts {
            machine_id,
            hostname,
            facts: HostFacts {
                distro: os.id,
                version: os.version_id,
                codename: os.codename,
                kernel: self.kernel()?,
                // `ARCH` is the architecture this binary was built for, which
                // is the one it is running on — more reliable than parsing
                // `uname -m`, and it needs no subprocess.
                arch: std::env::consts::ARCH.to_string(),
                virtualization: None,
                // Cloud metadata means talking to a link-local endpoint before
                // the host has enrolled. That belongs with the rest of the fact
                // collectors in DAWG-33, where it can be disabled.
                cloud: None,
            },
        })
    }

    /// `/etc/machine-id`, falling back to the D-Bus copy on older systems.
    fn machine_id(&self) -> Result<String> {
        let raw = self
            .read("etc/machine-id")
            .or_else(|_| self.read("var/lib/dbus/machine-id"))
            .map_err(|_| CollectorError::SourceUnavailable {
                input: "/etc/machine-id",
            })?;

        let id = raw.trim().to_string();
        // An empty `/etc/machine-id` is a real state: systemd creates the file
        // empty in images meant to be cloned, expecting first boot to fill it.
        // Enrolling then would give every clone of that image the same identity.
        if id.is_empty() {
            return Err(CollectorError::Unparseable {
                input: "/etc/machine-id",
                detail: "empty — this host has not been assigned a machine id yet".into(),
            });
        }
        // systemd specifies 32 lowercase hex characters, but refusing to enroll
        // a host that has something else would be picking a fight with reality
        // over a value we only ever compare for equality. Say so and carry on.
        if id.len() != 32 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
            tracing::warn!(
                machine_id_len = id.len(),
                "machine id is not the usual 32 hex characters; enrolling with it anyway"
            );
        }
        Ok(id)
    }

    fn hostname(&self) -> Result<String> {
        if let Ok(raw) = self.read("proc/sys/kernel/hostname") {
            let name = raw.trim().to_string();
            if !name.is_empty() {
                return Ok(name);
            }
        }
        // Not Linux, or a container without /proc mounted the usual way.
        let out = std::process::Command::new("hostname")
            .output()
            .map_err(|_| CollectorError::SourceUnavailable {
                input: "/proc/sys/kernel/hostname",
            })?;
        let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if name.is_empty() {
            return Err(CollectorError::SourceUnavailable {
                input: "/proc/sys/kernel/hostname",
            });
        }
        Ok(name)
    }

    fn kernel(&self) -> Result<String> {
        let raw = self.read("proc/sys/kernel/osrelease").map_err(|_| {
            CollectorError::SourceUnavailable {
                input: "/proc/sys/kernel/osrelease",
            }
        })?;
        Ok(raw.trim().to_string())
    }

    fn os_release(&self) -> Result<OsRelease> {
        let raw = self
            .read("etc/os-release")
            .or_else(|_| self.read("usr/lib/os-release"))
            .map_err(|_| CollectorError::SourceUnavailable {
                input: "/etc/os-release",
            })?;
        OsRelease::parse(&raw)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct OsRelease {
    id: String,
    version_id: String,
    codename: Option<String>,
}

impl OsRelease {
    fn parse(raw: &str) -> Result<Self> {
        let mut id = None;
        let mut version_id = None;
        let mut codename = None;

        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            // Values are shell-quoted: `VERSION_ID="24.04"` and `ID=debian` are
            // both valid and both appear in the wild.
            let value = value.trim().trim_matches(['"', '\'']).to_string();
            match key.trim() {
                "ID" => id = Some(value),
                "VERSION_ID" => version_id = Some(value),
                "VERSION_CODENAME" => codename = Some(value),
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
            // Rolling releases genuinely have no VERSION_ID. Reporting "rolling"
            // is more useful than refusing to enroll an Arch box, and the EOL
            // logic can recognise it.
            version_id: version_id
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "rolling".into()),
            codename: codename.filter(|s| !s.is_empty()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// A fake root with the files a Debian host would have.
    fn fake_root() -> PathBuf {
        let n = NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("updawg-enroll-facts-{}-{n}", std::process::id()));
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::create_dir_all(root.join("proc/sys/kernel")).unwrap();
        fs::write(
            root.join("etc/machine-id"),
            "3f2a9c1d4e5b6a7c8d9e0f1a2b3c4d5e\n",
        )
        .unwrap();
        fs::write(root.join("proc/sys/kernel/hostname"), "web-03\n").unwrap();
        fs::write(root.join("proc/sys/kernel/osrelease"), "6.12.0-amd64\n").unwrap();
        fs::write(
            root.join("etc/os-release"),
            "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\n",
        )
        .unwrap();
        root
    }

    #[test]
    fn a_debian_host_reports_the_facts_the_design_document_shows() {
        let root = fake_root();
        let got = EnrollmentCollector::new(&root).gather().unwrap();

        assert_eq!(got.machine_id, "3f2a9c1d4e5b6a7c8d9e0f1a2b3c4d5e");
        assert_eq!(got.hostname, "web-03");
        assert_eq!(got.facts.distro, "debian");
        assert_eq!(got.facts.version, "13");
        assert_eq!(got.facts.codename.as_deref(), Some("trixie"));
        assert_eq!(got.facts.kernel, "6.12.0-amd64");
        assert!(!got.facts.arch.is_empty());
        fs::remove_dir_all(root).ok();
    }

    /// A cloned golden image is the case this guards. systemd leaves
    /// `/etc/machine-id` empty on purpose so first boot fills it in; enrolling
    /// before that gives every clone the same identity.
    #[test]
    fn an_empty_machine_id_refuses_to_enroll() {
        let root = fake_root();
        fs::write(root.join("etc/machine-id"), "\n").unwrap();
        let err = EnrollmentCollector::new(&root).gather().unwrap_err();
        assert!(
            matches!(err, CollectorError::Unparseable { input, .. } if input == "/etc/machine-id"),
            "got {err:?}"
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn a_missing_machine_id_falls_back_to_the_dbus_copy() {
        let root = fake_root();
        fs::remove_file(root.join("etc/machine-id")).unwrap();
        fs::create_dir_all(root.join("var/lib/dbus")).unwrap();
        fs::write(
            root.join("var/lib/dbus/machine-id"),
            "aaaabbbbccccddddeeeeffff00001111",
        )
        .unwrap();

        let got = EnrollmentCollector::new(&root).gather().unwrap();
        assert_eq!(got.machine_id, "aaaabbbbccccddddeeeeffff00001111");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn os_release_handles_quoted_and_unquoted_values() {
        let parsed = OsRelease::parse(
            "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n",
        )
        .unwrap();
        assert_eq!(parsed.id, "ubuntu");
        assert_eq!(parsed.version_id, "24.04");
        assert_eq!(parsed.codename.as_deref(), Some("noble"));
    }

    #[test]
    fn a_rolling_release_without_a_version_still_enrolls() {
        let parsed = OsRelease::parse("ID=arch\nNAME=\"Arch Linux\"\n").unwrap();
        assert_eq!(parsed.id, "arch");
        assert_eq!(parsed.version_id, "rolling");
        assert_eq!(parsed.codename, None);
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
    fn a_host_with_no_os_release_is_reported_clearly() {
        let root = fake_root();
        fs::remove_file(root.join("etc/os-release")).unwrap();
        let err = EnrollmentCollector::new(&root).gather().unwrap_err();
        assert!(
            matches!(err, CollectorError::SourceUnavailable { input } if input == "/etc/os-release"),
            "got {err:?}"
        );
        fs::remove_dir_all(root).ok();
    }
}
