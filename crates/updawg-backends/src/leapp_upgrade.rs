//! A RHEL-family release upgrade (DAWG-152): leapp, which Red Hat ships for
//! RHEL and AlmaLinux's ELevate project packages for Rocky, AlmaLinux and
//! CentOS Stream.
//!
//! Leapp does its own preflight, so the agent's part is mostly to drive it
//! and report what it says, faithfully.
//!
//! 1. **Refuse** ([`blockers`], which a preflight asks too): the RHEL family
//!    only; one major release on (8 to 9, never 8 to 10); leapp installed —
//!    the agent does not install it, because on Rocky and Alma it comes from
//!    a third-party repository, and which one to trust is the host owner's
//!    call; nothing held (`dnf versionlock`). Then **`leapp preupgrade`**,
//!    and every report entry it flags as an inhibitor is a refusal, with the
//!    remediation leapp suggests; an error that stops it (no known upgrade
//!    path, say) is one too. It changes no package, but it is not quick: it
//!    downloads the target's metadata and writes its report under
//!    `/var/log/leapp`.
//! 2. **`leapp upgrade`**, its output in the job log. It repeats the checks,
//!    downloads every target package and builds the upgrade's initramfs. Still
//!    nothing installed: a failure here leaves the host as it was, apart from
//!    leapp's own files.
//! 3. **The reboot does the upgrade.** Leapp's initramfs replaces the
//!    packages, then boots the new release (twice, where SELinux relabels).
//!    So the job must reboot, and its outcome is only known after it: the
//!    agent checks `/etc/os-release` for the target and works out what
//!    changed once the host is back (`AfterReboot`). A host that comes back
//!    on the old release failed, and `/var/log/leapp/leapp-upgrade.log` says
//!    why.

use crate::release::Host;
use crate::{BackendError, LogSink, Result};
use std::path::Path;
use updawg_protocol::InstalledPackage;

const LEAPP: &str = "/usr/bin/leapp";
const REPORT: &str = "/var/log/leapp/leapp-report.json";

/// The distributions leapp upgrades, as `/etc/os-release` names them.
const FAMILY: &[&str] = &["rhel", "rocky", "almalinux", "centos", "ol"];

/// What the agent checks once the host is back from the reboot that does
/// the upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AfterReboot {
    /// The release it should be on now, by major version (`9`).
    pub release: String,
    /// What was installed before, to tell what changed.
    pub before: Vec<InstalledPackage>,
}

/// `8.10` is `8`.
fn major(version: &str) -> Option<u32> {
    version.trim().split('.').next()?.parse().ok()
}

/// Whether `host` is on major release `target` now.
#[must_use]
pub fn arrived(host: &Host, target: &str) -> bool {
    major(&host.version).is_some() && major(&host.version) == major(target)
}

/// Whether this host may be upgraded to `target` at all.
///
/// # Errors
/// Why not.
pub fn plan(host: &Host, target: &str) -> std::result::Result<(), String> {
    if !FAMILY.contains(&host.id.as_str()) {
        return Err(format!(
            "leapp upgrades the RHEL family, and this host is {}",
            host.id
        ));
    }
    let (Some(now), Some(to)) = (major(&host.version), major(target)) else {
        return Err(format!(
            "cannot tell how {} relates to {target}",
            host.version
        ));
    };
    if to != now + 1 {
        return Err(format!(
            "leapp upgrades one major release at a time, and this host is on {now}, so the next is {}, not {to}",
            now + 1
        ));
    }
    Ok(())
}

/// Every entry in leapp's JSON report that stops the upgrade, as its title
/// and the remediation leapp suggests. Flagged `inhibitor` in `flags` by
/// leapp 0.20, in `groups` by later ones.
///
/// # Errors
/// A report that is not leapp's JSON.
pub fn inhibitors(report: &str) -> std::result::Result<Vec<String>, String> {
    let report: serde_json::Value =
        serde_json::from_str(report).map_err(|e| format!("leapp's report is not JSON: {e}"))?;
    let entries = report
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or("leapp's report has no entries")?;
    let flagged = |entry: &serde_json::Value, field: &str| {
        entry
            .get(field)
            .and_then(serde_json::Value::as_array)
            .is_some_and(|list| list.iter().any(|f| f.as_str() == Some("inhibitor")))
    };
    Ok(entries
        .iter()
        .filter(|e| flagged(e, "flags") || flagged(e, "groups"))
        .map(|e| {
            let title = e
                .get("title")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("an inhibitor with no title");
            let hints: Vec<&str> = e
                .pointer("/detail/remediations")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter(|r| r.get("type").and_then(serde_json::Value::as_str) == Some("hint"))
                .filter_map(|r| r.get("context").and_then(serde_json::Value::as_str))
                .collect();
            if hints.is_empty() {
                title.to_owned()
            } else {
                format!("{title}: {}", hints.join(" "))
            }
        })
        .collect())
}

/// The errors leapp prints when it cannot go on at all, each as its
/// `Message:` line.
#[must_use]
pub fn errors(out: &str) -> Vec<String> {
    let Some((_, rest)) = out.split_once("Following errors occurred") else {
        return vec![];
    };
    rest.lines()
        .take_while(|l| !l.contains("Reports summary") && !l.starts_with('='))
        .filter_map(|l| l.trim().strip_prefix("Message:"))
        .map(|m| m.trim().to_owned())
        .collect()
}

/// Why this host would refuse to be upgraded to `target`: see the module
/// note, step 1. Runs `leapp preupgrade`. Empty when nothing stands in the
/// way.
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
    if !Path::new(LEAPP).exists() {
        return Ok(vec![format!(
            "leapp is not installed. On RHEL: dnf install leapp-upgrade. On Rocky, AlmaLinux and CentOS Stream it comes from AlmaLinux's ELevate: dnf install http://repo.almalinux.org/elevate/elevate-release-latest-el{0}.noarch.rpm, then dnf install leapp-upgrade and the data package for this distribution (leapp-data-rocky, leapp-data-almalinux)",
            major(&host.version).unwrap_or_default()
        )]);
    }
    let mut out = Vec::new();
    let held = backend.held_packages().await?;
    if !held.is_empty() {
        out.push(format!(
            "version-locked packages stop a release upgrade; release them first: {}",
            held.join(", ")
        ));
    }
    let (status, said) = crate::ubuntu_upgrade::read("leapp", &["preupgrade"]).await?;
    out.extend(what_leapp_said(status, &said)?);
    Ok(out)
}

/// A preupgrade's or an upgrade's refusals: the inhibitors in its report,
/// else its errors, else, when it failed and said neither, that it failed.
fn what_leapp_said(status: i32, said: &str) -> Result<Vec<String>> {
    let report = std::fs::read_to_string(REPORT).unwrap_or_default();
    let mut found = if report.is_empty() {
        vec![]
    } else {
        inhibitors(&report).map_err(|detail| BackendError::Unparseable {
            tool: "leapp",
            detail,
        })?
    };
    if found.is_empty() {
        found = errors(said);
    }
    if found.is_empty() && status != 0 {
        found.push(format!(
            "leapp exited {status} and named no inhibitor; /var/log/leapp/leapp-preupgrade.log says why"
        ));
    }
    Ok(found)
}

/// Prepare this host's upgrade to `target`. See the module note: what it
/// returns is not the upgrade, which happens during the reboot, but what to
/// check once it is done.
///
/// # Errors
/// [`BackendError::Refused`] when nothing was changed, which is every
/// failure here: leapp installs nothing before the reboot.
pub async fn upgrade(
    backend: &dyn crate::PackageBackend,
    target: &str,
    log: &dyn LogSink,
) -> Result<crate::ApplyOutcome> {
    let host = crate::release::this_host()?;
    plan(&host, target).map_err(BackendError::Refused)?;
    log.line(&format!(
        "upgrading {} {} to {target} with leapp: checking first (leapp preupgrade)",
        host.id, host.version
    ));
    let refused = blockers(backend, &host, target).await?;
    if !refused.is_empty() {
        return Err(BackendError::Refused(refused.join("; ")));
    }
    let before = backend.installed().await?;
    let status = crate::debian_upgrade::streamed("leapp", &["upgrade"], log).await?;
    if status != 0 {
        let why = what_leapp_said(status, "")?;
        return Err(BackendError::Refused(format!(
            "leapp upgrade stopped before the reboot, so nothing was installed: {}",
            why.join("; ")
        )));
    }
    log.line(&format!(
        "leapp has prepared the upgrade to {target}; it happens during the reboot, and the agent checks the release once the host is back"
    ));
    Ok(crate::ApplyOutcome {
        changed: vec![],
        reboot_required: true,
        after_reboot: Some(AfterReboot {
            release: target.to_owned(),
            before,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(id: &str, version: &str) -> Host {
        Host {
            id: id.into(),
            version: version.into(),
            codename: String::new(),
        }
    }

    #[test]
    fn only_the_rhel_family_and_only_the_next_major_release() {
        assert_eq!(plan(&host("rocky", "8.10"), "9"), Ok(()));
        assert_eq!(plan(&host("almalinux", "9.6"), "10"), Ok(()));
        for (h, target, says) in [
            (host("rocky", "8.10"), "10", "one major release at a time"),
            (host("rocky", "9.6"), "9", "one major release at a time"),
            (host("debian", "12"), "13", "this host is debian"),
            (host("rocky", "8.10"), "nine", "cannot tell"),
        ] {
            let why = plan(&h, target).unwrap_err();
            assert!(why.contains(says), "{why}");
        }
        assert!(arrived(&host("rocky", "9.6"), "9"));
        assert!(!arrived(&host("rocky", "8.10"), "9"));
    }

    /// Trimmed from a real `leapp preupgrade` on Rocky 8.10 (ELevate,
    /// leapp 0.20), 2026-09-29.
    const ROCKY_8_REPORT: &str = r#"{"entries": [
        {"title": "SElinux will be set to permissive mode", "severity": "low", "groups": null, "flags": [],
         "detail": {"remediations": [{"context": "Make sure there are no SElinux related warnings after the upgrade.", "type": "hint"}]}},
        {"title": "Firewalld Configuration AllowZoneDrifting Is Unsupported", "severity": "high", "groups": null, "flags": ["inhibitor"],
         "detail": {"remediations": [{"context": "Set AllowZoneDrifting=no in /etc/firewalld/firewalld.conf", "type": "hint"},
                                     {"context": ["sed", "-i", "s/^AllowZoneDrifting=.*/AllowZoneDrifting=no/", "/etc/firewalld/firewalld.conf"], "type": "command"}]}}
    ], "leapp_run_id": "x"}"#;

    #[test]
    fn inhibitors_are_read_from_flags_or_groups_with_leapps_hints() {
        assert_eq!(
            inhibitors(ROCKY_8_REPORT).unwrap(),
            [
                "Firewalld Configuration AllowZoneDrifting Is Unsupported: Set AllowZoneDrifting=no in /etc/firewalld/firewalld.conf"
            ]
        );
        let newer = r#"{"entries": [{"title": "Missing required answers", "groups": ["inhibitor", "sanity"]}]}"#;
        assert_eq!(inhibitors(newer).unwrap(), ["Missing required answers"]);
        assert!(inhibitors("{}").is_err());
    }

    #[test]
    fn an_error_that_stops_leapp_is_read_from_its_output() {
        let out = "Following errors occurred and the upgrade cannot continue:\n    1. Actor: ipu_workflow_config\n       Message: Could not determine the target version for the in-place upgrade.\n\nReports summary:\n    Errors:                      1\n";
        assert_eq!(
            errors(out),
            ["Could not determine the target version for the in-place upgrade."]
        );
        assert!(errors("all fine").is_empty());
    }
}
