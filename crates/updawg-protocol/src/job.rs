//! Jobs: the closed set of things the server may ask an agent to do.
//!
//! This enum is deliberately closed. There is no "run this script" variant, so
//! full control of the Updawg control plane still cannot run arbitrary commands
//! on a customer host. Adding a variant here is a security decision, not a
//! routine change.

use crate::ids::{HostId, JobId, OrgId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// What an agent is being asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    /// Refresh package metadata and upload a full inventory.
    RefreshInventory,
    /// Run checks for a proposed change without changing anything.
    RunPreflight,
    /// Install an exact list of package versions.
    ApplyUpdates,
    /// Upgrade to a named target release using the distro's supported tool.
    DistUpgrade,
    /// Reboot, optionally only if one is required.
    Reboot,
    /// Create a filesystem snapshot.
    Snapshot,
    /// Roll back to a previously created snapshot.
    Rollback,
    /// Install a specific signed agent release.
    SelfUpdate,
}

impl JobKind {
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

/// A signed instruction for exactly one host.
///
/// The signature covers the whole envelope. The agent verifies it against the
/// organization key pinned at enrollment before looking at anything else.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Job {
    pub id: JobId,
    pub org_id: OrgId,
    pub host_id: HostId,
    pub kind: JobKind,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Kind-specific payload. DAWG-21 replaces this with a typed enum.
    pub payload: serde_json::Value,
    /// Detached Ed25519 signature over the canonical encoding of this job.
    pub signature: String,
}

/// How a job ended, from the agent's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Running,
    Succeeded,
    Failed,
    /// Local configuration forbade it. A normal outcome, not an error.
    RejectedByHost,
}

/// The result an agent reports back when a job finishes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JobOutcome {
    pub job_id: JobId,
    pub status: JobStatus,
    pub finished_at: DateTime<Utc>,
    pub reboot_required: bool,
    /// Present when the status is `RejectedByHost` or `Failed`.
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_jobs_are_not_mutating() {
        assert!(!JobKind::RefreshInventory.is_mutating());
        assert!(!JobKind::RunPreflight.is_mutating());
    }

    #[test]
    fn everything_that_touches_the_host_is_mutating() {
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

    #[test]
    fn job_kinds_serialise_as_snake_case_for_the_wire() {
        let json = serde_json::to_string(&JobKind::ApplyUpdates).unwrap_or_default();
        assert_eq!(json, "\"apply_updates\"");
    }
}
