//! Configuration, both directions.
//!
//! [`ServerConfig`] is what the server would like the agent to do, fetched from
//! `GET /agent/v1/config`. [`LocalPolicy`] is what `/etc/updawg/agent.toml`
//! permits, which the agent reports on every check-in.
//!
//! They are two halves of one rule and they are deliberately in the same file:
//! **the server narrows, the agent decides.** The intersection happens in the
//! agent, against the local file, and there is no direction in which the server
//! can widen it.

use crate::job::JobKind;
use serde::{Deserialize, Deserializer, Serialize};

/// Intervals and feature flags the server would like the agent to use.
///
/// **This narrows local configuration; it never widens it.** The agent
/// intersects whatever arrives here with `/etc/updawg/agent.toml`, so a server
/// that has been compromised cannot grant itself a permission the operator
/// withheld. That intersection lives in the agent, not here, but it is the
/// reason this type carries no permission-granting fields at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// How long the gateway will hold a check-in open.
    pub checkin_timeout_s: u64,
    /// How often to collect and upload a full inventory.
    pub inventory_interval_s: u64,
    /// How often to refresh package manager metadata.
    #[serde(default = "default_refresh_interval")]
    pub refresh_metadata_interval_s: u64,
    /// Bumped whenever the server-side configuration changes, so a check-in can
    /// tell the agent to re-read it without sending the whole thing every time.
    #[serde(default)]
    pub config_version: u64,
    /// Job kinds the server is currently willing to issue. Advisory only — the
    /// agent's local deny list still wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enabled_job_kinds: Vec<crate::job::JobKind>,
}

const fn default_refresh_interval() -> u64 {
    3600
}

/// How much the operator has allowed the agent to do (DAWG-223).
///
/// This travels **agent to server**, on every check-in, and it is the ceiling:
/// [`ServerConfig`] narrows it and nothing widens it. The server records it so
/// the product can say a host will refuse `dist_upgrade` *before* somebody
/// approves a proposal that targets it, rather than one refused job at a time.
///
/// It rides on the check-in rather than on enrollment because the local file
/// changes without one. Carrying it in both places would mean two sources for
/// one fact and a window in which they disagree; the check-in is the one that
/// can never go stale.
///
/// Absent means *unknown*, not *nothing permitted*. An agent older than this
/// field sends no policy at all, and a server that read that as `observe` with
/// no permissions would be confidently wrong about every host in a fleet
/// mid-upgrade — which is the same failure DAWG-223 was filed for.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LocalPolicy {
    pub mode: AgentMode,
    /// Job kinds `/etc/updawg/agent.toml` permits, sorted and deduplicated.
    ///
    /// Bounded by the size of [`JobKind`], which is why this is a list rather
    /// than a hash and a second round trip: eight short words on a request that
    /// is already carrying a boot id and a content hash.
    ///
    /// In [`AgentMode::Observe`] this is what the file says, not what the mode
    /// allows. The mode is the stronger statement and the server applies it; a
    /// host reported as `observe` with `apply_patch` permitted is a host whose
    /// operator has the permission written down and the mode switched off, and
    /// flattening that at the agent would lose the difference between "not
    /// configured" and "configured and disabled".
    #[serde(
        default,
        deserialize_with = "known_job_kinds",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub permitted_job_kinds: Vec<JobKind>,
}

/// Whether the agent will change anything at all.
///
/// The same two words `/etc/updawg/agent.toml` spells, so the file, the wire
/// and the database all say `observe` and `managed` rather than three
/// dialects of the same idea.
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
    /// Whether this mode will execute a mutating job at all.
    #[must_use]
    pub const fn is_managed(self) -> bool {
        matches!(self, Self::Managed)
    }
}

impl LocalPolicy {
    /// Whether this host would accept a job of this kind.
    ///
    /// The server's answer to "is it worth proposing this here?", and only
    /// that: the agent checks its own file again when the job arrives, because
    /// the file may have changed and because a permission checked only by the
    /// party asking is not a permission.
    #[must_use]
    pub fn permits(&self, kind: JobKind) -> bool {
        if kind.is_mutating() && !self.mode.is_managed() {
            return false;
        }
        self.permitted_job_kinds.contains(&kind)
    }
}

/// Job kinds, with anything this build does not recognise dropped.
///
/// A newer agent can permit a kind an older server has never heard of, and
/// failing the whole request over one word is the worst answer available — the
/// server would lose the check-in rather than one field of it. Dropping the
/// unknown ones leaves the server's view of the host **narrower** than the
/// truth, which is the only direction this crate is allowed to be wrong in.
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
        // The distinction the server depends on: an agent too old to report a
        // policy sends nothing, and nothing must not read as `observe` with no
        // permissions.
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
        // Written down in the file and switched off by the mode. Both facts
        // survive the trip; the mode is the one that decides.
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
