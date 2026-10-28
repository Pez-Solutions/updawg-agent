//! Ubuntu release upgrade via Canonical's `do-release-upgrade`, run
//! non-interactively with its output in the job log.
//!
//! The upgrader rewrites sources itself from Canonical's meta-release list
//! and comments out third-party repositories. The agent's job is to make sure
//! it goes to the approved release and to catch, up front, anything the
//! upgrader would refuse.
//!
//! 1. Check for blockers ([`blockers`], also used by the preflight): Ubuntu
//!    only, a newer release, no `Prompt=never` in
//!    `/etc/update-manager/release-upgrades` (local config wins),
//!    `do-release-upgrade` installed, nothing held or half-installed. Also
//!    the upgrader's own checks (as of 22.04's 1:22.04.21): no pending
//!    non-phased updates, and no reboot pending for `libc6`, `linux-base` or
//!    a kernel.
//! 2. Confirm the offered release is the approved one. The upgrader can't be
//!    given a target, so `do-release-upgrade -c` shows where `Prompt` and the
//!    meta-release list lead. Canonical only offers LTS-to-LTS upgrades from
//!    the first point release (24.04.1), so this refuses for months after an
//!    LTS ships.
//! 3. Run `do-release-upgrade -f DistUpgradeViewNonInteractive`, keeping
//!    locally edited config files via an `apt.conf.d` drop-in for dpkg and
//!    `UCF_FORCE_CONFFOLD` for ucf. The frontend would also keep them on its
//!    own, but only by writing to a terminal after a five-second sleep. It
//!    never reboots; the job's reboot policy handles that.
//! 4. Check `/etc/os-release` reports the target. If not, the job failed
//!    regardless of the upgrader's exit status.
//!
//! The job runs `apt-get update` between steps 1 and 2 so the pending-update
//! check uses current lists.

use crate::debian_upgrade::{apt, changes, half_installed, held, streamed};
use crate::release::{self, Host};
use crate::{BackendError, LogSink, Result};
use std::path::Path;

const UPGRADER: &str = "/usr/bin/do-release-upgrade";
const PROMPT_FILE: &str = "/etc/update-manager/release-upgrades";
const REBOOT_PKGS: &str = "/var/run/reboot-required.pkgs";
/// Removed after the upgrade.
const DROP_IN: &str = "/etc/apt/apt.conf.d/99updawg-release-upgrade";

/// The upgrader's own pending-update rule (upgradable and not phasing),
/// via python3-apt, which the upgrader depends on anyway.
const PENDING: &str = "import apt\nfor p in apt.Cache():\n    if p.is_upgradable and 'Phased-Update-Percentage' not in p.candidate.record:\n        print(p.name)\n";

fn version(v: &str) -> Option<(u32, u32)> {
    let (year, month) = v.trim().split_once('.')?;
    Some((year.parse().ok()?, month.parse().ok()?))
}

/// # Errors
/// Why not.
pub fn plan(host: &Host, target: &str) -> std::result::Result<(), String> {
    if host.id != "ubuntu" {
        return Err(format!(
            "this is Ubuntu's release upgrade, and this host is {}",
            host.id
        ));
    }
    let (Some(now), Some(to)) = (version(&host.version), version(target)) else {
        return Err(format!(
            "cannot tell how {} relates to {target}",
            host.version
        ));
    };
    if to <= now {
        return Err(format!(
            "this host is on {}, which is not older than {target}",
            host.version
        ));
    }
    Ok(())
}

/// `Prompt` in `/etc/update-manager/release-upgrades`.
#[must_use]
pub fn prompt(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (key, value) = l.trim().split_once('=')?;
        (key.trim() == "Prompt").then(|| value.trim().to_ascii_lowercase())
    })
}

/// Packages in `/var/run/reboot-required.pkgs` that make the upgrader
/// insist on a reboot first.
#[must_use]
pub fn reboot_owed(pkgs: &str) -> Vec<String> {
    pkgs.lines()
        .map(str::trim)
        .filter(|l| *l == "libc6" || *l == "linux-base" || l.starts_with("linux-image-"))
        .map(str::to_owned)
        .collect()
}

/// The release `do-release-upgrade -c` offers, so `New release '24.04.3 LTS'
/// available.` gives `24.04.3`.
#[must_use]
pub fn offered(out: &str) -> Option<String> {
    out.lines().find_map(|l| {
        let rest = l.trim().strip_prefix("New release '")?;
        let (release, _) = rest.split_once('\'')?;
        release.split_whitespace().next().map(str::to_owned)
    })
}

/// Whether the offered release (`24.04.3`) is `target` (`24.04`).
#[must_use]
pub fn is_target(offered: &str, target: &str) -> bool {
    offered == target || offered.starts_with(&format!("{target}."))
}

/// Check-only output without the banner, on one line.
fn said(out: &str) -> String {
    out.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && *l != "Checking for a new Ubuntu release")
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) async fn read(program: &'static str, args: &[&str]) -> Result<(i32, String)> {
    let out = tokio::process::Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BackendError::ToolMissing { tool: program }
            } else {
                BackendError::Io(e)
            }
        })?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.code().unwrap_or(-1), text))
}

/// Reasons [`upgrade`] would refuse `target` (steps 1 and 2 in the module
/// docs). Changes nothing. Empty when nothing blocks the upgrade.
///
/// # Errors
/// When the host could not be asked.
pub async fn blockers(
    backend: &dyn crate::PackageBackend,
    host: &Host,
    target: &str,
) -> Result<Vec<String>> {
    if let Err(why) = plan(host, target) {
        return Ok(vec![why]);
    }
    let mut out = Vec::new();
    let prompt = std::fs::read_to_string(PROMPT_FILE)
        .ok()
        .and_then(|t| prompt(&t));
    if prompt.as_deref() == Some("never") {
        out.push(format!(
            "{PROMPT_FILE} says Prompt=never, and this host's configuration wins"
        ));
    }
    let tool = Path::new(UPGRADER).exists();
    if !tool {
        out.push(format!(
            "{UPGRADER} is not installed (ubuntu-release-upgrader-core)"
        ));
    }
    out.extend(held(backend).await?);
    out.extend(half_installed().await?);
    let owed = reboot_owed(&std::fs::read_to_string(REBOOT_PKGS).unwrap_or_default());
    if !owed.is_empty() {
        out.push(format!(
            "a reboot is owed for {}, and Canonical's upgrader will not start until it happens",
            owed.join(", ")
        ));
    }
    let (status, pending) = read("python3", &["-c", PENDING]).await?;
    if status != 0 {
        return Err(BackendError::CommandFailed {
            tool: "python3",
            status,
            stderr: pending.trim().to_owned(),
        });
    }
    let pending: Vec<&str> = pending.split_whitespace().collect();
    if !pending.is_empty() {
        out.push(format!(
            "{} update(s) for this release are not installed, and Canonical's upgrader will not start until they are: {}{}",
            pending.len(),
            pending.iter().take(10).copied().collect::<Vec<_>>().join(", "),
            if pending.len() > 10 { ", ..." } else { "" }
        ));
    }
    if tool && prompt.as_deref() != Some("never") {
        let (_, check) = read("do-release-upgrade", &["-c"]).await?;
        match offered(&check) {
            Some(release) if is_target(&release, target) => {}
            Some(release) => out.push(format!(
                "do-release-upgrade would go to {release}, not {target} (Prompt={})",
                prompt.as_deref().unwrap_or("lts")
            )),
            None => out.push(format!(
                "do-release-upgrade offers no release after {} (an LTS is offered to the previous one from its first point release): {}",
                host.version,
                said(&check)
            )),
        }
    }
    Ok(out)
}

/// Writes the conffile drop-in and removes it on drop.
struct KeepConffiles;

impl KeepConffiles {
    fn write(log: &dyn LogSink) -> Result<Self> {
        std::fs::write(
            DROP_IN,
            "// Written by updawg for a release upgrade and removed after it:\n// keep every configuration file edited on this host.\nDpkg::Options { \"--force-confdef\"; \"--force-confold\"; };\n",
        )?;
        log.line(&format!(
            "{DROP_IN}: keep every configuration file edited on this host"
        ));
        Ok(Self)
    }
}

impl Drop for KeepConffiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(DROP_IN);
    }
}

/// Upgrades this host to Ubuntu `target`. See the module docs.
///
/// # Errors
/// [`BackendError::Refused`] when nothing was changed; any other error once
/// the upgrader has started.
pub async fn upgrade(
    backend: &dyn crate::PackageBackend,
    target: &str,
    log: &dyn LogSink,
) -> Result<crate::ApplyOutcome> {
    let host = release::this_host()?;
    plan(&host, target).map_err(BackendError::Refused)?;
    log.line(&format!(
        "upgrading Ubuntu {} ({}) to {target}",
        host.version, host.codename
    ));
    if apt(&["update"], log).await? != 0 {
        return Err(BackendError::Refused(
            "apt-get update failed, so nothing was changed".into(),
        ));
    }
    let refused = blockers(backend, &host, target).await?;
    if !refused.is_empty() {
        return Err(BackendError::Refused(refused.join("; ")));
    }

    let before = backend.installed().await?;
    let status = {
        let _keep = KeepConffiles::write(log)?;
        streamed(
            "do-release-upgrade",
            &["-f", "DistUpgradeViewNonInteractive"],
            log,
        )
        .await?
    };

    let now = release::this_host().ok();
    if now.as_ref().map(|h| h.version.as_str()) != Some(target) {
        return Err(BackendError::CommandFailed {
            tool: "do-release-upgrade",
            status,
            stderr: format!(
                "the upgrader finished and /etc/os-release says {}, not {target}; the job log has its output, and the host has /var/log/dist-upgrade",
                now.map_or_else(|| "nothing it can read".into(), |h| h.version)
            ),
        });
    }
    if status != 0 {
        log.line(&format!(
            "do-release-upgrade exited {status}, and the host is on {target}"
        ));
    }
    let after = backend.installed().await?;
    let changed = changes(&before, &after);
    log.line(&format!(
        "now Ubuntu {target}: {} package(s) changed; the new kernel is in use after a reboot",
        changed.len()
    ));
    Ok(crate::ApplyOutcome {
        changed,
        reboot_required: true,
        after_reboot: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(id: &str, version: &str) -> Host {
        Host {
            id: id.into(),
            version: version.into(),
            codename: "jammy".into(),
        }
    }

    #[test]
    fn only_ubuntu_and_only_forwards() {
        assert_eq!(plan(&host("ubuntu", "22.04"), "24.04"), Ok(()));
        assert_eq!(plan(&host("ubuntu", "24.04"), "24.10"), Ok(()));
        for (h, target, says) in [
            (host("debian", "12"), "13", "this host is debian"),
            (host("ubuntu", "24.04"), "22.04", "not older"),
            (host("ubuntu", "24.04"), "24.04", "not older"),
            (host("ubuntu", "22.04"), "noble", "cannot tell"),
        ] {
            let why = plan(&h, target).unwrap_err();
            assert!(why.contains(says), "{why}");
        }
    }

    #[test]
    fn prompt_is_read_from_the_default_section() {
        let text = "# Default behavior for the release upgrader.\n\n[DEFAULT]\n# Default prompting and upgrade behavior, valid options:\n#  never  - Never check for, or allow upgrading to, a new release.\nPrompt=lts\n";
        assert_eq!(prompt(text).as_deref(), Some("lts"));
        assert_eq!(
            prompt("[DEFAULT]\nPrompt = never\n").as_deref(),
            Some("never")
        );
        assert_eq!(prompt("[DEFAULT]\n"), None);
    }

    #[test]
    fn a_reboot_is_owed_only_for_what_the_upgrader_waits_for() {
        let pkgs = "linux-image-5.15.0-161-generic\nlinux-base\ndbus\nlibc6\n";
        assert_eq!(
            reboot_owed(pkgs),
            ["linux-image-5.15.0-161-generic", "linux-base", "libc6"]
        );
        assert!(reboot_owed("dbus\nsystemd\n").is_empty());
    }

    #[test]
    fn the_offered_release_is_read_and_matched_to_the_target() {
        let yes = "Checking for a new Ubuntu release\nNew release '24.04.3 LTS' available.\nRun 'do-release-upgrade' to upgrade to it.\n";
        assert_eq!(offered(yes).as_deref(), Some("24.04.3"));
        assert!(is_target("24.04.3", "24.04"));
        assert!(is_target("24.10", "24.10"));
        assert!(!is_target("24.10", "24.1"));
        assert!(!is_target("26.04.1", "24.04"));

        let no = "Checking for a new Ubuntu release\nThere is no development version of an LTS available.\nTo upgrade to the latest non-LTS development release \nset Prompt=normal in /etc/update-manager/release-upgrades.\n";
        assert_eq!(offered(no), None);
        assert_eq!(
            said(no),
            "There is no development version of an LTS available. To upgrade to the latest non-LTS development release set Prompt=normal in /etc/update-manager/release-upgrades."
        );
    }
}
