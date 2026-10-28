//! Configuration, both directions.
//!
//! [`ServerConfig`] is what the server would like the agent to do, fetched from
//! `GET /agent/v1/config`. [`LocalPolicy`] is what `/etc/updawg/agent.toml`
//! permits, which the agent reports on every check-in.
//!
//! The server can narrow what the local file allows but never widen it. The
//! agent does the intersection.

use crate::job::JobKind;
use serde::{Deserialize, Deserializer, Serialize};

/// Intervals and feature flags the server would like the agent to use.
///
/// The agent intersects this with `/etc/updawg/agent.toml`, so a compromised
/// server can't grant itself a permission the operator withheld. That's also
/// why there are no permission-granting fields here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// How long the gateway will hold a check-in open.
    pub checkin_timeout_s: u64,
    /// How often to collect and upload a full inventory.
    pub inventory_interval_s: u64,
    /// How often to refresh package manager metadata.
    #[serde(default = "default_refresh_interval")]
    pub refresh_metadata_interval_s: u64,
    /// Bumped when the server-side configuration changes, so a check-in can
    /// tell the agent to re-fetch it.
    #[serde(default)]
    pub config_version: u64,
    /// Job kinds the server is currently willing to issue. Advisory; the
    /// agent's local deny list still wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enabled_job_kinds: Vec<crate::job::JobKind>,
}

const fn default_refresh_interval() -> u64 {
    3600
}

/// What the operator has allowed the agent to do.
///
/// Sent from agent to server on every check-in. [`ServerConfig`] can narrow
/// it, nothing widens it. The server records it so it can tell that a host
/// will refuse, say, `dist_upgrade` before anyone approves a proposal for it.
///
/// It's on the check-in rather than enrollment because the local file can
/// change at any time.
///
/// Absent means unknown. Agents older than this field send nothing, and
/// reading that as `observe` with no permissions would be wrong for every
/// host in a fleet that's mid-upgrade.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LocalPolicy {
    pub mode: AgentMode,
    /// Job kinds `/etc/updawg/agent.toml` permits, sorted and deduplicated.
    ///
    /// Bounded by the size of [`JobKind`], so it's sent in full rather than as
    /// a hash.
    ///
    /// In [`AgentMode::Observe`] this is still what the file says; the server
    /// applies the mode. Flattening it in the agent would lose the difference
    /// between "not configured" and "configured but disabled".
    #[serde(
        default,
        deserialize_with = "known_job_kinds",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub permitted_job_kinds: Vec<JobKind>,
}

/// Whether the agent will change anything at all. Spelled the same as in
/// `/etc/updawg/agent.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMode {
    /// Report only. Never change anything, whatever the server sends.
    #[default]
    Observe,
    /// Execute signed jobs, subject to the permissions above.
    Managed,
}

impl AgentMode {
    #[must_use]
    pub const fn is_managed(self) -> bool {
        matches!(self, Self::Managed)
    }
}

impl LocalPolicy {
    /// Whether this host would accept a job of this kind.
    ///
    /// For the server deciding what to propose. The agent re-checks its own
    /// file when a job arrives, since the file may have changed and the server
    /// isn't trusted to enforce it.
    #[must_use]
    pub fn permits(&self, kind: JobKind) -> bool {
        if kind.is_mutating() && !self.mode.is_managed() {
            return false;
        }
        self.permitted_job_kinds.contains(&kind)
    }
}

/// Job kinds, dropping any this build doesn't recognise.
///
/// A newer agent can permit a kind an older server doesn't know. Failing the
/// whole check-in over that would be worse, and dropping it only makes the
/// server's view of the host narrower than reality, which is the safe side.
fn known_job_kinds<'de, D>(d: D) -> Result<Vec<JobKind>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Maybe {
        Known(JobKind),
        Unknown(serde::de::IgnoredAny),
    }

    Ok(Vec::<Maybe>::deserialize(d)?
        .into_iter()
        .filter_map(|m| match m {
            Maybe::Known(kind) => Some(kind),
            Maybe::Unknown(_) => None,
        })
        .collect())
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            checkin_timeout_s: crate::CHECKIN_LONG_POLL_SECONDS,
            inventory_interval_s: 6 * 3600,
            refresh_metadata_interval_s: default_refresh_interval(),
            config_version: 0,
            enabled_job_kinds: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_policy_is_not_an_empty_one() {
        // an agent too old to report a policy sends nothing
        let json = r#"{"boot_id":"b","uptime_s":1,"inventory_hash":"h",
            "state":{"reboot_required":false,"pending_updates":0,"security_updates":0},
            "metrics":{"load1":0.0,"mem_used_pct":0.0,"root_free_bytes":0}}"#;
        let req: crate::CheckinRequest = serde_json::from_str(json).unwrap();
        assert!(req.local_policy.is_none());
    }

    #[test]
    fn an_unknown_job_kind_is_dropped_rather_than_failing_the_request() {
        let policy: LocalPolicy = serde_json::from_str(
            r#"{"mode":"managed","permitted_job_kinds":["reboot","teleport","apply_updates"]}"#,
        )
        .unwrap();
        assert_eq!(
            policy.permitted_job_kinds,
            vec![JobKind::Reboot, JobKind::ApplyUpdates]
        );
    }

    #[test]
    fn observe_mode_permits_nothing_that_changes_the_host() {
        let policy = LocalPolicy {
            mode: AgentMode::Observe,
            permitted_job_kinds: vec![JobKind::ApplyUpdates, JobKind::RefreshInventory],
        };
        assert!(!policy.permits(JobKind::ApplyUpdates));
        assert!(policy.permits(JobKind::RefreshInventory));
        assert!(!policy.permits(JobKind::Reboot));
    }

    #[test]
    fn managed_mode_still_needs_the_permission() {
        let policy = LocalPolicy {
            mode: AgentMode::Managed,
            permitted_job_kinds: vec![JobKind::ApplyUpdates],
        };
        assert!(policy.permits(JobKind::ApplyUpdates));
        assert!(!policy.permits(JobKind::DistUpgrade));
    }

    #[test]
    fn a_policy_with_nothing_in_it_is_two_fields_on_the_wire() {
        let json = serde_json::to_string(&LocalPolicy::default()).unwrap();
        assert_eq!(json, r#"{"mode":"observe"}"#);
    }

    #[test]
    fn the_mode_is_spelled_the_way_the_config_file_spells_it() {
        assert_eq!(
            serde_json::to_string(&AgentMode::Managed).unwrap(),
            r#""managed""#
        );
    }
}
