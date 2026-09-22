//! Check-in: `POST /agent/v1/checkin`.
//!
//! The hot path. The gateway returns immediately if jobs are waiting or the
//! agent's inventory hash is stale; otherwise it holds the request open, waits
//! on a notification for that host, and answers as soon as a job appears or the
//! timeout is reached. Near-instant delivery without persistent sockets.
//!
//! The request body is deliberately small. It rides on every check-in, which at
//! fleet scale is roughly nine hundred a second.

use crate::{
    config::{LocalPolicy, ServerConfig},
    ids::JobId,
    job::Job,
};
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
    /// The longest the agent would like this request held open (DAWG-205).
    ///
    /// A long poll looks exactly like an idle connection, and a great deal of
    /// corporate networking equipment exists to kill those. An agent that has
    /// watched something trim its polls after thirty seconds asks for
    /// comfortably less than thirty and completes them instead.
    ///
    /// **Advisory, and clamped.** The gateway decides, through
    /// [`CheckinRequest::hold_seconds`]; a client cannot ask to be held for
    /// ever, and a gateway too old to know about this field simply holds for
    /// its own default — which is why the agent must not shorten its own
    /// request timeout to match what it asked for. Doing that is how an agent
    /// starts abandoning polls the gateway was about to answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_hold_s: Option<u64>,
    /// What `/etc/updawg/agent.toml` permits (DAWG-223).
    ///
    /// Sent every check-in rather than at enrollment, because the file changes
    /// without one. `None` means an agent too old to say — which is not the
    /// same as an agent that may do nothing, and the server must not read it
    /// that way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_policy: Option<LocalPolicy>,
}

impl CheckinRequest {
    /// How long to actually hold this request open, in seconds.
    ///
    /// The one place the negotiation happens, so that no gateway can forget to
    /// clamp: a request asking for a day is held for `max`, one asking for
    /// nothing at all is held for `max`, and one asking for less than
    /// [`CHECKIN_MIN_HOLD_SECONDS`](crate::CHECKIN_MIN_HOLD_SECONDS) is held
    /// for that floor. The floor matters more than the ceiling — an agent that
    /// asked for zero and was given zero would poll as fast as the network
    /// allows, which is a self-inflicted denial of service that looks like a
    /// busy fleet.
    #[must_use]
    pub fn hold_seconds(&self, max: u64) -> u64 {
        let max = max.max(crate::CHECKIN_MIN_HOLD_SECONDS);
        match self.max_hold_s {
            Some(asked) => asked.clamp(crate::CHECKIN_MIN_HOLD_SECONDS, max),
            None => max,
        }
    }
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

    fn request() -> CheckinRequest {
        CheckinRequest {
            boot_id: "b".into(),
            uptime_s: 1,
            inventory_hash: "sha256:1b4f0e".into(),
            state: HostStateReport::default(),
            metrics: HostMetrics {
                load1: 0.0,
                mem_used_pct: 0.0,
                root_free_bytes: 0,
            },
            running_job_ids: vec![],
            max_hold_s: None,
            local_policy: None,
        }
    }

    #[test]
    fn a_request_that_asks_for_nothing_gets_the_gateway_default() {
        assert_eq!(request().hold_seconds(55), 55);
    }

    #[test]
    fn a_request_cannot_ask_to_be_held_longer_than_the_gateway_allows() {
        let mut req = request();
        req.max_hold_s = Some(86_400);
        assert_eq!(req.hold_seconds(55), 55);
    }

    #[test]
    fn a_shorter_hold_is_honoured() {
        let mut req = request();
        req.max_hold_s = Some(25);
        assert_eq!(req.hold_seconds(55), 25);
    }

    #[test]
    fn a_request_cannot_ask_to_be_answered_immediately_for_ever() {
        // Zero would be a self-inflicted denial of service: the agent would
        // reconnect as fast as the network allows and it would look like a busy
        // fleet rather than a bug.
        let mut req = request();
        req.max_hold_s = Some(0);
        assert_eq!(req.hold_seconds(55), crate::CHECKIN_MIN_HOLD_SECONDS);
    }

    #[test]
    fn a_gateway_configured_below_the_floor_still_holds_for_the_floor() {
        let mut req = request();
        req.max_hold_s = Some(1);
        assert_eq!(req.hold_seconds(0), crate::CHECKIN_MIN_HOLD_SECONDS);
        assert_eq!(request().hold_seconds(0), crate::CHECKIN_MIN_HOLD_SECONDS);
    }

    #[test]
    fn the_new_fields_are_absent_rather_than_null_when_unused() {
        let json = serde_json::to_string(&request()).unwrap();
        assert!(!json.contains("max_hold_s"), "{json}");
        assert!(!json.contains("local_policy"), "{json}");
        assert!(!json.contains("null"), "{json}");
    }

    #[test]
    fn an_older_gateway_reading_a_newer_request_ignores_what_it_does_not_know() {
        // The other direction of the same promise: this crate's own structs are
        // what the server deserialises with, so a field it has never heard of
        // must not fail the parse.
        let mut req = request();
        req.max_hold_s = Some(30);
        let mut value: serde_json::Value = serde_json::to_value(&req).unwrap();
        value["something_from_the_future"] = serde_json::json!("hello");
        let back: CheckinRequest = serde_json::from_value(value).unwrap();
        assert_eq!(back.max_hold_s, Some(30));
    }

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
