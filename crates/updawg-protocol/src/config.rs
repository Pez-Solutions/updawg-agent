//! Server-side configuration: `GET /agent/v1/config`.

use serde::{Deserialize, Serialize};

/// Intervals and feature flags the server would like the agent to use.
///
/// **This narrows local configuration; it never widens it.** The agent
/// intersects whatever arrives here with `/etc/updawg/agent.toml`, so a server
/// that has been compromised cannot grant itself a permission the operator
/// withheld. That intersection lives in the agent, not here, but it is the
/// reason this type carries no permission-granting fields at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
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
