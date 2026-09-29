//! An Ubuntu release upgrade (DAWG-150): Canonical's `do-release-upgrade`,
//! driven non-interactively, its output in the job log.
//!
//! Unlike Debian's, nothing here rewrites sources: the upgrader does that
//! itself, from Canonical's meta-release list, and comments out third-party
//! repositories as it goes (the preflight's `third_party_repos` names them).
//! What the agent adds is making it go where it was approved to, and
//! refusing, before anything changes, what the upgrader would refuse.
//!
//! 1. **Refuse** ([`blockers`], which a preflight asks too). Ubuntu only; a
//!    newer release; not `Prompt=never` in `/etc/update-manager/release-upgrades`,
//!    which is local configuration and wins; `do-release-upgrade` installed;
//!    nothing held; nothing half-installed. And the upgrader's own two
//!    refusals, as `/usr/bin/do-release-upgrade` decides them (22.04's
//!    1:22.04.21): an update not yet installed that is not phasing, and a
//!    reboot owed for `libc6`, `linux-base` or a kernel. Both mean a patch
//!    proposal, and a reboot, first.
//! 2. **The release it would go to is the approved one.** It cannot be told
//!    a target: `do-release-upgrade -c` says which release `Prompt` and the
//!    meta-release list lead to, and anything else is refused. Canonical
//!    offers an LTS to the previous LTS from its first point release
//!    (24.04.1), so for months after an LTS comes out, this refuses.
//! 3. **`do-release-upgrade -f DistUpgradeViewNonInteractive`**, keeping
//!    every configuration file edited on the host: an `apt.conf.d` drop-in
//!    for dpkg (`--force-confold`, `--force-confdef`), `UCF_FORCE_CONFFOLD`
//!    for ucf. The frontend answers a conffile prompt "keep" on its own too,
//!    but by writing to a terminal after a five-second sleep. It never
//!    reboots; the job's reboot policy does that.
//! 4. **It says it is the target now**, in `/etc/os-release`. Otherwise the
//!    job failed, whatever the upgrader said.
//!
//! `apt-get update` runs between 1 and 2 in the job, so the pending-update
//! refusal is against today's lists; it changes no package.

use crate::debian_upgrade::{apt, changes, half_installed, held, streamed};
use crate::release::{self, Host};
use crate::{BackendError, LogSink, Result};
use std::path::Path;

const UPGRADER: &str = "/usr/bin/do-release-upgrade";
const PROMPT_FILE: &str = "/etc/update-manager/release-upgrades";
const REBOOT_PKGS: &str = "/var/run/reboot-required.pkgs";
/// dpkg's options for the upgrade, removed after it.
const DROP_IN: &str = "/etc/apt/apt.conf.d/99updawg-release-upgrade";

/// The upgrader's pending-update rule, in its own terms (python3-apt, which
/// it needs anyway): upgradable, and not phasing.
const PENDING: &str = "import apt\nfor p in apt.Cache():\n    if p.is_upgradable and 'Phased-Update-Percentage' not in p.candidate.record:\n        print(p.name)\n";

/// `22.04` as `(22, 4)`.
fn version(v: &str) -> Option<(u32, u32)> {
    let (year, month) = v.trim().split_once('.')?;
    Some((year.parse().ok()?, month.parse().ok()?))
}

/// Whether this host may be upgraded to `target` at all.
///
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

/// The packages in `/var/run/reboot-required.pkgs` the upgrader will not
/// go on without a reboot for.
#[must_use]
pub fn reboot_owed(pkgs: &str) -> Vec<String> {
    pkgs.lines()
        .map(str::trim)
        .filter(|l| *l == "libc6" || *l == "linux-base" || l.starts_with("linux-image-"))
        .map(str::to_owned)
        .collect()
}

/// The release `do-release-upgrade -c` offers: `New release '24.04.3 LTS'
/// available.` is `24.04.3`.
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

/// What a check-only run printed, without its banner, on one line.
fn said(out: &str) -> String {
    out.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && *l != "Checking for a new Ubuntu release")
        .collect::<Vec<_>>()
        .join(" ")
}

/// Run `program` and keep what it printed. Reads only.
async fn read(program: &'static str, args: &[&str]) -> Result<(i32, String)> {
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

/// Why this host would refuse to be upgraded to `target`, found without
/// changing anything (see the module note, step 1 and 2). What [`upgrade`]
/// checks after `apt-get update`, and what a preflight asks ahead of time.
/// Empty when nothing stands in the way.
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
            if pending.len() > 10 { ", …" } else { "" }
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

/// The drop-in that keeps edited configuration files, removed when dropped.
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

/// Upgrade this host to Ubuntu `target`. See the module note.
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
