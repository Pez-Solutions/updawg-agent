//! Check-in: `POST /agent/v1/checkin`.
//!
//! The hot path. The gateway returns immediately if jobs are waiting or the
//! agent's inventory hash is stale; otherwise it holds the request open, waits
//! on a notification for that host, and answers as soon as a job appears or the
//! timeout is reached. Near-instant delivery without persistent sockets.
//!
//! The request body is deliberately small. It rides on every check-in, which at
//! fleet scale is roughly nine hundred a second.

use crate::{config::ServerConfig, ids::JobId, job::Job};
use serde::{Deserialize, Serialize};

/// Cheap state, small enough to send every time.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HostStateReport {
    pub reboot_required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services_need_restart: Vec<String>,
    pub pending_updates: u32,
    pub security_updates: u32,
    /// Another tool holds the package manager lock. The server uses this to
    /// avoid scheduling work that would only queue behind it.
    #[serde(default)]
    pub package_lock_held: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostMetrics {
    pub load1: f32,
    pub mem_used_pct: f32,
    pub root_free_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckinRequest {
    /// Changes on reboot, which is how the server detects one it did not ask
    /// for.
    pub boot_id: String,
    pub uptime_s: u64,
    /// Hash of the inventory the agent last uploaded. If it disagrees with what
    /// the server holds, the server asks for a fresh one.
    pub inventory_hash: String,
    pub state: HostStateReport,
    pub metrics: HostMetrics,
    /// Jobs the agent believes it is still running, so a gateway restart does
    /// not hand out the same work twice.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub running_job_ids: Vec<JobId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckinResponse {
    /// Seconds to wait before checking in again. Zero means immediately, which
    /// is the normal long-poll case.
    pub next_checkin_s: u64,
    /// The server wants a full inventory, usually because the hash disagreed.
    pub inventory_requested: bool,
    /// Bumped when server-side configuration changes; the agent re-reads
    /// `/config` when it moves.
    pub config_version: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jobs: Vec<Job>,
    /// Sent inline when the agent's config version is behind, saving a round
    /// trip on the hot path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<ServerConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_checkin_response_is_small() {
        let resp = CheckinResponse {
            next_checkin_s: 0,
            inventory_requested: false,
            config_version: 7,
            jobs: vec![],
            config: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        // The common case is "nothing for you". It rides on every check-in
        // across the whole fleet, so it should stay tiny.
        assert!(json.len() < 100, "empty check-in response grew: {json}");
        assert!(!json.contains("jobs"));
    }
}
