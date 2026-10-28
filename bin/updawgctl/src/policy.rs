//! `updawgctl sign --policy FILE`: what unattended signing may sign.
//!
//! `--yes` on a schedule signs every job waiting for the organization's key,
//! so anyone who can get a proposal approved gets a signature. A policy file
//! limits that to what the organization decided in advance; anything outside
//! it is left for a person, with the reason.
//!
//! ```toml
//! # Job kinds it may sign. Anything else waits.
//! allow = ["refresh_inventory", "run_preflight", "apply_updates"]
//! # Whether a job may restart the host: a reboot job, or an update that
//! # asks for one. Off unless said.
//! reboot = false
//! # An update touching more packages than this waits.
//! max_packages = 50
//! # An update touching any package matching these waits. `*` matches
//! # anything.
//! deny_packages = ["linux-image-*", "kernel*", "openssh-server"]
//! ```
//!
//! Decisions are based on the job document about to be signed, not on what
//! the server says about it.

use anyhow::{Context as _, Result};
use std::path::Path;
use updawg_protocol::{
    Job, JobKind,
    job::{JobSpec, PackagePin, RebootPolicy},
};

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignPolicy {
    /// Job kinds it may sign. If absent, nothing is signed.
    #[serde(default)]
    allow: Vec<JobKind>,
    #[serde(default)]
    reboot: bool,
    #[serde(default)]
    max_packages: Option<usize>,
    #[serde(default)]
    deny_packages: Vec<String>,
}

impl SignPolicy {
    /// Unknown keys are an error, so a misspelt `deny_package` can't be
    /// silently ignored.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the policy in {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("{} is not a signing policy", path.display()))
    }

    /// Why this job is outside the policy, or `None` if it may be signed.
    pub(crate) fn refuses(&self, job: &Job) -> Option<String> {
        let kind = job.kind();
        if !self.allow.contains(&kind) {
            return Some(format!(
                "the policy does not allow {}",
                crate::sign::word(&kind)
            ));
        }
        let (packages, reboot): (&[PackagePin], bool) = match &job.spec {
            JobSpec::ApplyUpdates(a) => (&a.packages, a.reboot != RebootPolicy::Never),
            JobSpec::DistUpgrade(d) => (&[], d.reboot != RebootPolicy::Never),
            JobSpec::Reboot(_) => (&[], true),
            _ => (&[], false),
        };
        if reboot && !self.reboot {
            return Some("it may reboot the host, and the policy does not allow that".into());
        }
        if let Some(max) = self.max_packages
            && packages.len() > max
        {
            return Some(format!(
                "it changes {} packages, more than the policy's {max}",
                packages.len()
            ));
        }
        packages.iter().find_map(|p| {
            self.deny_packages
                .iter()
                .find(|pattern| matches(pattern, &p.name))
                .map(|pattern| format!("{} matches the policy's `{pattern}`", p.name))
        })
    }
}

/// `*` matches any run of characters, including none; everything else
/// matches literally.
fn matches(pattern: &str, name: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        return rest.is_empty();
    };
    for part in middle {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use updawg_protocol::job::{ApplyUpdates, Reboot, SnapshotPolicy};

    fn policy(text: &str) -> SignPolicy {
        toml::from_str(text).unwrap()
    }

    fn update(packages: &[&str], reboot: RebootPolicy) -> Job {
        Job {
            id: updawg_protocol::JobId::new("job_1"),
            host_id: updawg_protocol::HostId::new("hst_1"),
            spec: JobSpec::ApplyUpdates(ApplyUpdates {
                packages: packages
                    .iter()
                    .map(|name| PackagePin {
                        name: (*name).into(),
                        arch: "amd64".into(),
                        from: "1".into(),
                        to: "2".into(),
                    })
                    .collect(),
                reboot,
                snapshot: SnapshotPolicy::Never,
                timeout_s: 1800,
            }),
            not_before: None,
            expires_at: chrono::Utc::now(),
            key_id: updawg_protocol::SigningKeyId::new("sk_1"),
            signature: String::new(),
        }
    }

    #[test]
    fn patterns_match_as_a_person_reads_them() {
        assert!(matches("linux-image-*", "linux-image-6.12.0-1-amd64"));
        assert!(matches("kernel*", "kernel"));
        assert!(matches("*ssl*", "libssl3"));
        assert!(matches("openssh-server", "openssh-server"));
        assert!(!matches("openssh-server", "openssh-server-extra"));
        assert!(!matches("kernel*", "the-kernel"));
        assert!(!matches("a*b*c", "acb"));
    }

    #[test]
    fn a_job_inside_the_policy_may_be_signed() {
        let p = policy(
            r#"allow = ["apply_updates"]
max_packages = 2
deny_packages = ["linux-image-*"]"#,
        );
        assert_eq!(
            p.refuses(&update(&["openssl", "curl"], RebootPolicy::Never)),
            None
        );
    }

    #[test]
    fn everything_outside_it_waits_and_says_why() {
        let p = policy(
            r#"allow = ["apply_updates"]
max_packages = 2
deny_packages = ["linux-image-*"]"#,
        );
        let why = |job| p.refuses(&job).unwrap();
        assert!(why(update(&["a", "b", "c"], RebootPolicy::Never)).contains("3 packages"));
        assert!(why(update(&["linux-image-amd64"], RebootPolicy::Never)).contains("linux-image-*"));
        assert!(why(update(&["openssl"], RebootPolicy::IfRequired)).contains("reboot"));
        let mut reboot = update(&[], RebootPolicy::Never);
        reboot.spec = JobSpec::Reboot(Reboot::default());
        assert!(why(reboot).contains("does not allow reboot"));
    }

    #[test]
    fn a_policy_that_names_nothing_signs_nothing_and_typos_do_not_load() {
        assert!(
            policy("")
                .refuses(&update(&["openssl"], RebootPolicy::Never))
                .is_some()
        );
        assert!(toml::from_str::<SignPolicy>("deny_package = [\"x\"]").is_err());
        assert!(toml::from_str::<SignPolicy>("allow = [\"apply_update\"]").is_err());
    }
}
