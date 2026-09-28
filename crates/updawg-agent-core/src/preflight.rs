//! Preflight: checks that change nothing and report everything (DAWG-147,
//! DAWG-148).
//!
//! A `run_preflight` job asks whether a change — these packages at these
//! versions, or a release upgrade — can go ahead, and the answer is one
//! [`PreflightCheck`] per check, each `pass`, `warn` or `fail` with a sentence
//! saying what to do and the specifics as a list.
//!
//! Two halves, so the thresholds are tested without a host: [`gather`] reads
//! the host, and [`evaluate`] decides. Gathering runs only commands that read
//! — `df`, `findmnt`, `dpkg-query`, `rpm -V`, `md5sum`, `dkms status` — and
//! the package backend's `held_packages`, which is `apt-mark showhold` or
//! `dnf versionlock list`. Nothing here installs, refreshes, snapshots or
//! reboots, and the executor's tests hold it to that.
//!
//! # Thresholds
//!
//! | check | fail | warn |
//! |---|---|---|
//! | `disk_space` (`/`) | under 500 MiB (2 GiB for a release upgrade) | under 2 GiB (5 GiB) |
//! | `disk_space` (`/boot`, when separate and a kernel is involved) | under 50 MiB | under 150 MiB |
//! | `held_packages` | a package in the change is held | a release upgrade with anything held |
//! | `modified_conffiles` | — | a package in the change has an edited configuration file |
//! | `dkms_modules` | — | modules to rebuild for a new kernel |
//! | `snapshot` | — | no snapshot provider, so no rollback |
//! | `reboot` | — | the change needs a reboot, or the host already does |
//!
//! A check that cannot find out says `warn`, with why. Never `pass`.

use std::collections::BTreeSet;
use updawg_protocol::{CheckStatus, PreflightCheck, RebootRequired, job::Preflight};

const MIB: u64 = 1024 * 1024;

/// What the checks look at, gathered once.
#[derive(Debug, Clone)]
pub struct Facts {
    /// A release upgrade rather than a package change.
    pub release_upgrade: bool,
    /// The packages the change names. Empty for a release upgrade.
    pub planned: Vec<String>,
    pub root_free: Option<u64>,
    /// `None` when `/boot` is not a filesystem of its own.
    pub boot_free: Option<u64>,
    pub held: Result<Vec<String>, String>,
    /// Configuration files edited on this host, of the packages concerned.
    pub modified_conffiles: Result<Vec<String>, String>,
    /// `None` when DKMS is not installed.
    pub dkms: Option<Vec<String>>,
    /// The snapshot provider, or why there is none.
    pub snapshots: Result<String, String>,
    pub reboot_now: RebootRequired,
}

/// Nothing known: every "could not tell" is a warning, so this is the
/// cautious starting point, not a healthy host.
impl Default for Facts {
    fn default() -> Self {
        Self {
            release_upgrade: false,
            planned: vec![],
            root_free: None,
            boot_free: None,
            held: Err("not looked at".into()),
            modified_conffiles: Err("not looked at".into()),
            dkms: None,
            snapshots: Err("not looked at".into()),
            reboot_now: RebootRequired::Unknown,
        }
    }
}

impl Facts {
    /// Whether a new kernel is part of the change.
    #[must_use]
    pub fn kernel_involved(&self) -> bool {
        self.release_upgrade || self.planned.iter().any(|p| is_kernel(p))
    }
}

/// A kernel, by the names the families give it.
fn is_kernel(name: &str) -> bool {
    ["linux-image", "linux-modules", "kernel"]
        .iter()
        .any(|k| name == *k || name.starts_with(&format!("{k}-")))
}

/// Packages whose new version is not in use until the host restarts.
fn needs_reboot(name: &str) -> bool {
    is_kernel(name)
        || [
            "libc6",
            "glibc",
            "systemd",
            "dbus",
            "dbus-broker",
            "intel-microcode",
            "amd64-microcode",
            "microcode_ctl",
            "linux-firmware",
        ]
        .contains(&name)
}

fn check(
    name: &str,
    status: CheckStatus,
    summary: impl Into<String>,
    items: Vec<String>,
) -> PreflightCheck {
    PreflightCheck {
        name: name.to_owned(),
        status,
        summary: summary.into(),
        items,
    }
}

fn mib(bytes: u64) -> String {
    format!("{} MiB", bytes / MIB)
}

/// Decide every check from what was gathered.
#[must_use]
pub fn evaluate(f: &Facts) -> Vec<PreflightCheck> {
    vec![
        disk_space(f),
        held_packages(f),
        modified_conffiles(f),
        dkms_modules(f),
        snapshot(f),
        reboot(f),
    ]
}

fn disk_space(f: &Facts) -> PreflightCheck {
    let (fail, warn) = if f.release_upgrade {
        (2048 * MIB, 5120 * MIB)
    } else {
        (500 * MIB, 2048 * MIB)
    };
    let mut items = Vec::new();
    let mut status = CheckStatus::Pass;
    let mut worse = |s: CheckStatus| {
        if rank(s) > rank(status) {
            status = s;
        }
    };
    if let Some(free) = f.root_free {
        items.push(format!("/: {} free", mib(free)));
        if free < fail {
            worse(CheckStatus::Fail);
        } else if free < warn {
            worse(CheckStatus::Warn);
        }
    } else {
        items.push("/: could not be measured".into());
        worse(CheckStatus::Warn);
    }
    if let Some(free) = f.boot_free
        && f.kernel_involved()
    {
        items.push(format!("/boot: {} free", mib(free)));
        if free < 50 * MIB {
            worse(CheckStatus::Fail);
        } else if free < 150 * MIB {
            worse(CheckStatus::Warn);
        }
    }
    let summary = match status {
        CheckStatus::Pass => "Enough free space.",
        CheckStatus::Warn => {
            "Free space is low: the change may run out partway. Free some before going ahead."
        }
        CheckStatus::Fail => {
            "Not enough free space: the change would run out partway. Free space first."
        }
    };
    check("disk_space", status, summary, items)
}

fn held_packages(f: &Facts) -> PreflightCheck {
    let held = match &f.held {
        Ok(held) => held,
        Err(why) => {
            return check(
                "held_packages",
                CheckStatus::Warn,
                format!("Could not tell which packages are held: {why}"),
                vec![],
            );
        }
    };
    let held_set: BTreeSet<&str> = held.iter().map(String::as_str).collect();
    let blocked: Vec<String> = f
        .planned
        .iter()
        .filter(|p| held_set.contains(p.as_str()))
        .cloned()
        .collect();
    if !blocked.is_empty() {
        return check(
            "held_packages",
            CheckStatus::Fail,
            "Held on this host, so they will not be upgraded whatever is approved. Unhold them or leave them out.",
            blocked,
        );
    }
    if f.release_upgrade && !held.is_empty() {
        return check(
            "held_packages",
            CheckStatus::Warn,
            "Held packages stay at their versions through a release upgrade, which can leave them broken or block it.",
            held.clone(),
        );
    }
    check(
        "held_packages",
        CheckStatus::Pass,
        "Nothing in the change is held.",
        vec![],
    )
}

fn modified_conffiles(f: &Facts) -> PreflightCheck {
    match &f.modified_conffiles {
        Err(why) => check(
            "modified_conffiles",
            CheckStatus::Warn,
            format!("Could not tell whether configuration files were edited: {why}"),
            vec![],
        ),
        Ok(files) if files.is_empty() => check(
            "modified_conffiles",
            CheckStatus::Pass,
            "No configuration file the change touches has been edited here.",
            vec![],
        ),
        Ok(files) => check(
            "modified_conffiles",
            CheckStatus::Warn,
            "Edited here. They are kept as they are, and the new version's defaults are written beside them (.dpkg-dist or .rpmnew) for a person to merge.",
            files.clone(),
        ),
    }
}

fn dkms_modules(f: &Facts) -> PreflightCheck {
    match &f.dkms {
        Some(modules) if !modules.is_empty() && f.kernel_involved() => check(
            "dkms_modules",
            CheckStatus::Warn,
            "Built for each kernel by DKMS. A new kernel needs them rebuilt, and a module that fails to build is missing after the reboot.",
            modules.clone(),
        ),
        Some(modules) if !modules.is_empty() => check(
            "dkms_modules",
            CheckStatus::Pass,
            "DKMS modules are installed; no new kernel is involved.",
            vec![],
        ),
        _ => check(
            "dkms_modules",
            CheckStatus::Pass,
            "No DKMS modules.",
            vec![],
        ),
    }
}

fn snapshot(f: &Facts) -> PreflightCheck {
    match &f.snapshots {
        Ok(provider) => check(
            "snapshot",
            CheckStatus::Pass,
            format!("A {provider} snapshot can be taken first, and rolled back to."),
            vec![],
        ),
        Err(why) => check(
            "snapshot",
            CheckStatus::Warn,
            format!("No snapshot can be taken, so the change cannot be rolled back: {why}"),
            vec![],
        ),
    }
}

fn reboot(f: &Facts) -> PreflightCheck {
    let mut items: Vec<String> = f
        .planned
        .iter()
        .filter(|p| needs_reboot(p))
        .cloned()
        .collect();
    if f.release_upgrade {
        items.push("the release upgrade".into());
    }
    match (items.is_empty(), f.reboot_now) {
        (true, RebootRequired::No) => check(
            "reboot",
            CheckStatus::Pass,
            "No reboot needed, before or after.",
            vec![],
        ),
        (true, RebootRequired::Unknown) => check(
            "reboot",
            CheckStatus::Pass,
            "The change needs no reboot. Whether the host already needs one, it cannot say.",
            vec![],
        ),
        (true, RebootRequired::Yes) => check(
            "reboot",
            CheckStatus::Warn,
            "The host already needs a reboot, from an earlier change.",
            vec![],
        ),
        (false, _) => check(
            "reboot",
            CheckStatus::Warn,
            "Not in use until the host reboots. Plan the reboot, or allow it in the rule's window.",
            items,
        ),
    }
}

const fn rank(s: CheckStatus) -> u8 {
    match s {
        CheckStatus::Pass => 0,
        CheckStatus::Warn => 1,
        CheckStatus::Fail => 2,
    }
}

/* ------------------------------------------------------------ gathering */

/// Read the host for `preflight`. Only commands that read.
pub async fn gather(
    preflight: &Preflight,
    backend: Option<&dyn updawg_backends::PackageBackend>,
    snapshots: Result<String, String>,
    reboot_now: RebootRequired,
) -> Facts {
    let planned: Vec<String> = preflight.packages.iter().map(|p| p.name.clone()).collect();
    let root_free = free_bytes("/").await;
    let boot_free = if mount_source("/boot").await.is_some() {
        free_bytes("/boot").await
    } else {
        None
    };
    let held = match backend {
        Some(b) => b.held_packages().await.map_err(|e| e.to_string()),
        None => Err("this host has no package manager the agent can drive".into()),
    };
    let ecosystem = backend.map(updawg_backends::PackageBackend::ecosystem);
    let modified_conffiles = match ecosystem {
        Some(updawg_protocol::Ecosystem::Deb) => deb_modified_conffiles(&planned).await,
        Some(updawg_protocol::Ecosystem::Rpm) => rpm_modified_conffiles(&planned).await,
        _ => Err("no package manager to ask".into()),
    };
    Facts {
        release_upgrade: preflight.target_release.is_some(),
        planned,
        root_free,
        boot_free,
        held,
        modified_conffiles,
        dkms: dkms_modules_installed().await,
        snapshots,
        reboot_now,
    }
}

async fn read(program: &str, args: &[&str]) -> Option<(bool, String)> {
    let out = tokio::process::Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .kill_on_drop(true)
        .output()
        .await
        .ok()?;
    Some((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    ))
}

async fn free_bytes(path: &str) -> Option<u64> {
    let (_, out) = read("df", &["-P", path]).await?;
    let blocks: u64 = out
        .lines()
        .nth(1)?
        .split_whitespace()
        .nth(3)?
        .parse()
        .ok()?;
    Some(blocks.saturating_mul(1024))
}

async fn mount_source(path: &str) -> Option<String> {
    let (ok, out) = read("findmnt", &["-n", "-o", "SOURCE", path]).await?;
    let source = out.trim();
    (ok && !source.is_empty()).then(|| source.to_owned())
}

/// `dkms status`: one module per line, `name/version, kernel, arch: state`.
/// `None` when DKMS is not installed.
async fn dkms_modules_installed() -> Option<Vec<String>> {
    let (_, out) = read("dkms", &["status"]).await?;
    Some(parse_dkms(&out))
}

/// The distinct `name/version` of each module `dkms status` lists.
#[must_use]
pub fn parse_dkms(out: &str) -> Vec<String> {
    let mut modules: Vec<String> = out
        .lines()
        .filter_map(|l| l.split([',', ':']).next())
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .map(str::to_owned)
        .collect();
    modules.sort();
    modules.dedup();
    modules
}

/// Debian: each package's conffiles as dpkg recorded them, and whether the
/// file's MD5 still matches. For a release upgrade, every package's.
async fn deb_modified_conffiles(planned: &[String]) -> Result<Vec<String>, String> {
    let mut args = vec!["-W", "-f=${Conffiles}\n"];
    args.extend(planned.iter().map(String::as_str));
    let Some((_, out)) = read("dpkg-query", &args).await else {
        return Err("dpkg-query could not be run".into());
    };
    let recorded = parse_conffiles(&out);
    if recorded.is_empty() {
        return Ok(vec![]);
    }
    let files: Vec<&str> = recorded.iter().map(|(f, _)| f.as_str()).collect();
    // `md5sum` reads; a file removed since is simply absent from its output.
    let Some((_, sums)) = read("md5sum", &files).await else {
        return Err("md5sum could not be run".into());
    };
    Ok(modified(&recorded, &sums))
}

/// ` /etc/x 0123abcd…` lines from `dpkg-query -f='${Conffiles}'`, skipping
/// the ones dpkg marks obsolete.
#[must_use]
pub fn parse_conffiles(out: &str) -> Vec<(String, String)> {
    out.lines()
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            let (file, sum) = (words.next()?, words.next()?);
            (file.starts_with('/') && words.next() != Some("obsolete"))
                .then(|| (file.to_owned(), sum.to_owned()))
        })
        .collect()
}

/// The recorded files whose current MD5 differs, from `md5sum` output.
#[must_use]
pub fn modified(recorded: &[(String, String)], md5sum: &str) -> Vec<String> {
    let now: std::collections::BTreeMap<&str, &str> = md5sum
        .lines()
        .filter_map(|l| {
            let (sum, file) = l.split_once("  ")?;
            Some((file, sum))
        })
        .collect();
    let mut changed: Vec<String> = recorded
        .iter()
        .filter(|(file, sum)| now.get(file.as_str()).is_some_and(|n| n != sum))
        .map(|(file, _)| file.clone())
        .collect();
    changed.sort();
    changed.dedup();
    changed
}

/// RPM: `rpm -V --configfiles`, whose flags say which config files differ
/// (`5` is the digest). For a release upgrade, every package's.
async fn rpm_modified_conffiles(planned: &[String]) -> Result<Vec<String>, String> {
    let mut args = vec!["-V", "--configfiles"];
    if planned.is_empty() {
        args.push("-a");
    }
    args.extend(planned.iter().map(String::as_str));
    // Exits 1 when anything differs, which is the answer, not a failure.
    let Some((_, out)) = read("rpm", &args).await else {
        return Err("rpm could not be run".into());
    };
    Ok(parse_rpm_verify(&out))
}

/// Lines like `S.5....T.  c /etc/httpd/conf/httpd.conf`: the config files
/// whose digest changed. `missing` lines are files removed, not edited.
#[must_use]
pub fn parse_rpm_verify(out: &str) -> Vec<String> {
    let mut files: Vec<String> = out
        .lines()
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            let flags = words.next()?;
            let marker = words.next()?;
            let file = words.next()?;
            (flags.len() >= 3 && flags.as_bytes()[2] == b'5' && marker == "c")
                .then(|| file.to_owned())
        })
        .collect();
    files.sort();
    files.dedup();
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        Facts {
            root_free: Some(10 * 1024 * MIB),
            held: Ok(vec![]),
            modified_conffiles: Ok(vec![]),
            snapshots: Ok("snapper".into()),
            reboot_now: RebootRequired::No,
            ..Facts::default()
        }
    }

    fn status(checks: &[PreflightCheck], name: &str) -> CheckStatus {
        checks.iter().find(|c| c.name == name).unwrap().status
    }

    #[test]
    fn a_healthy_host_passes_every_check_and_every_check_is_there() {
        let checks = evaluate(&Facts {
            planned: vec!["openssl".into()],
            ..facts()
        });
        let names: Vec<&str> = checks.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "disk_space",
                "held_packages",
                "modified_conffiles",
                "dkms_modules",
                "snapshot",
                "reboot"
            ]
        );
        assert!(
            checks.iter().all(|c| c.status == CheckStatus::Pass),
            "{checks:#?}"
        );
    }

    #[test]
    fn disk_space_thresholds_are_stricter_for_a_release_upgrade() {
        let at = |free_mib: u64, upgrade: bool| {
            status(
                &evaluate(&Facts {
                    root_free: Some(free_mib * MIB),
                    release_upgrade: upgrade,
                    ..facts()
                }),
                "disk_space",
            )
        };
        assert_eq!(at(400, false), CheckStatus::Fail);
        assert_eq!(at(1000, false), CheckStatus::Warn);
        assert_eq!(at(3000, false), CheckStatus::Pass);
        assert_eq!(at(1000, true), CheckStatus::Fail);
        assert_eq!(at(3000, true), CheckStatus::Warn);
        assert_eq!(at(6000, true), CheckStatus::Pass);
        // Unmeasured is not fine.
        let unknown = evaluate(&Facts {
            root_free: None,
            ..facts()
        });
        assert_eq!(status(&unknown, "disk_space"), CheckStatus::Warn);
    }

    #[test]
    fn a_small_boot_matters_only_when_a_kernel_is_involved() {
        let with = |planned: &str| {
            status(
                &evaluate(&Facts {
                    boot_free: Some(40 * MIB),
                    planned: vec![planned.into()],
                    ..facts()
                }),
                "disk_space",
            )
        };
        assert_eq!(with("openssl"), CheckStatus::Pass);
        assert_eq!(with("linux-image-amd64"), CheckStatus::Fail);
        assert_eq!(with("kernel-core"), CheckStatus::Fail);
    }

    #[test]
    fn a_held_package_in_the_change_fails_and_names_it() {
        let checks = evaluate(&Facts {
            planned: vec!["openssl".into(), "curl".into()],
            held: Ok(vec!["curl".into(), "nginx".into()]),
            ..facts()
        });
        let held = checks.iter().find(|c| c.name == "held_packages").unwrap();
        assert_eq!(held.status, CheckStatus::Fail);
        assert_eq!(held.items, ["curl"]);
        // Not in the change: fine for a package change, not for a release upgrade.
        let other = evaluate(&Facts {
            planned: vec!["openssl".into()],
            held: Ok(vec!["nginx".into()]),
            ..facts()
        });
        assert_eq!(status(&other, "held_packages"), CheckStatus::Pass);
        let upgrade = evaluate(&Facts {
            release_upgrade: true,
            held: Ok(vec!["nginx".into()]),
            ..facts()
        });
        assert_eq!(status(&upgrade, "held_packages"), CheckStatus::Warn);
    }

    #[test]
    fn what_could_not_be_found_out_is_a_warning_never_a_pass() {
        let checks = evaluate(&Facts {
            held: Err("apt-mark: not found".into()),
            modified_conffiles: Err("dpkg-query could not be run".into()),
            snapshots: Err("snapper is not installed".into()),
            ..facts()
        });
        for name in ["held_packages", "modified_conffiles", "snapshot"] {
            assert_eq!(status(&checks, name), CheckStatus::Warn, "{name}");
        }
    }

    #[test]
    fn dkms_and_reboot_speak_up_for_a_kernel() {
        let checks = evaluate(&Facts {
            planned: vec!["linux-image-6.12.48+deb13-amd64".into()],
            dkms: Some(vec!["zfs/2.2.2".into()]),
            ..facts()
        });
        assert_eq!(status(&checks, "dkms_modules"), CheckStatus::Warn);
        let reboot = checks.iter().find(|c| c.name == "reboot").unwrap();
        assert_eq!(reboot.status, CheckStatus::Warn);
        assert_eq!(reboot.items, ["linux-image-6.12.48+deb13-amd64"]);
        let already = evaluate(&Facts {
            reboot_now: RebootRequired::Yes,
            ..facts()
        });
        assert_eq!(status(&already, "reboot"), CheckStatus::Warn);
    }

    #[test]
    fn conffiles_are_edited_when_the_digest_moved() {
        let recorded = parse_conffiles(
            " /etc/nginx/nginx.conf 3b1a9f6e8f5b7a0e9c1d2f3a4b5c6d7e\n /etc/nginx/mime.types 1111\n /etc/old.conf 2222 obsolete\n\n",
        );
        assert_eq!(recorded.len(), 2);
        let sums = "ffff0000ffff0000ffff0000ffff0000  /etc/nginx/nginx.conf\n1111  /etc/nginx/mime.types\n";
        assert_eq!(modified(&recorded, sums), ["/etc/nginx/nginx.conf"]);
    }

    #[test]
    fn rpm_verify_names_config_files_whose_digest_changed() {
        let out = "S.5....T.  c /etc/httpd/conf/httpd.conf\n.......T.  c /etc/sysconfig/httpd\nmissing   c /etc/httpd/conf.d/welcome.conf\n";
        assert_eq!(parse_rpm_verify(out), ["/etc/httpd/conf/httpd.conf"]);
    }

    #[test]
    fn dkms_status_lists_each_module_once() {
        let out = "zfs/2.2.2, 6.8.0-1-generic, x86_64: installed\nzfs/2.2.2, 6.8.0-2-generic, x86_64: installed\nnvidia/535.1: added\n";
        assert_eq!(parse_dkms(out), ["nvidia/535.1", "zfs/2.2.2"]);
    }
}
