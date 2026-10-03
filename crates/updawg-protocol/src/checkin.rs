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

/// Whether the host needs a reboot, as it can tell (DAWG-210).
///
/// Three values, because the mechanisms are uneven across distributions and
/// **a host that cannot answer is not a host whose answer is no**. Before 0.4
/// this was a `bool` on the wire, the one place the unknown was flattened
/// into `false`.
///
/// Reads the old `true`/`false` too, so a gateway on 0.4 understands an agent
/// that is not; an absent field is [`RebootRequired::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebootRequired {
    Yes,
    No,
    /// No mechanism on this host could answer. Never to be read as `No`.
    #[default]
    Unknown,
}

impl RebootRequired {
    #[must_use]
    pub fn is_yes(self) -> bool {
        self == Self::Yes
    }

    #[must_use]
    pub fn is_known(self) -> bool {
        self != Self::Unknown
    }

    /// `Some` when the host could say, which is how the database stores it.
    #[must_use]
    pub const fn known(self) -> Option<bool> {
        match self {
            Self::Yes => Some(true),
            Self::No => Some(false),
            Self::Unknown => None,
        }
    }
}

impl<'de> Deserialize<'de> for RebootRequired {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            /// An agent before 0.4.
            Bool(bool),
            Word(String),
        }
        Ok(match Wire::deserialize(d)? {
            Wire::Bool(true) => Self::Yes,
            Wire::Bool(false) => Self::No,
            Wire::Word(w) => match w.as_str() {
                "yes" => Self::Yes,
                "no" => Self::No,
                // Including a word from a newer agent: not knowing what it
                // means is not knowing.
                _ => Self::Unknown,
            },
        })
    }
}

/// Whether the host can take snapshots before a change, and roll back to
/// them (DAWG-115). Detected by the agent at start.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SnapshotSupport {
    /// The provider in use, e.g. `snapper`. `None`: this host cannot take
    /// snapshots, and [`SnapshotSupport::reason`] says why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// How the agent was installed, which decides how it updates (DAWG-46,
/// protocol 0.9). Detected by the agent at start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInstall {
    pub method: InstallMethod,
    /// The channel the host's package repository follows, as the repository
    /// spells it (`stable`, `beta`). A package host can only move to builds
    /// its own repository holds, so a stable host offered a beta build
    /// refuses it. `None` for a binary install, which can take either, and
    /// when the repository file could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallMethod {
    /// The .deb from pkg.updawg.net, through apt.
    Apt,
    /// The .rpm from pkg.updawg.net, through dnf.
    Dnf,
    /// install.sh's binaries in /usr/local/bin, updated from the signed
    /// manifest.
    Binary,
    /// A method this version does not know, from a newer agent, or an agent
    /// installed some way it cannot update itself.
    #[serde(other)]
    Other,
}

/// Cheap state, small enough to send every time.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HostStateReport {
    #[serde(default)]
    pub reboot_required: RebootRequired,
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
    /// Whether this host can take snapshots (DAWG-115). `None` means an agent
    /// too old to say, which is not the same as a host that cannot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshots: Option<SnapshotSupport>,
    /// The agent build this host is running, as its packages name it
    /// (`0.2.0-20261003083653.gdd21454`).
    ///
    /// Sent every check-in so the server's idea of a host's version cannot go
    /// stale: before this it learnt the version at enrollment, certificate
    /// renewal and a reported self-update, and missed any upgrade done by hand
    /// (`apt upgrade`, a rerun of the installer). `None` means an agent too old
    /// to say; the server keeps what it last knew.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    /// How this agent was installed and which channel it follows (protocol
    /// 0.9). `None` from an agent too old to say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install: Option<AgentInstall>,
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
            snapshots: None,
            agent_version: None,
            install: None,
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

    /// DAWG-210: an agent before 0.4 sends a bool, and one that says nothing
    /// is one that could not tell.
    #[test]
    fn reboot_required_reads_the_old_bool_and_the_new_words() {
        let read = |v: serde_json::Value| -> RebootRequired {
            let mut state = serde_json::json!({"pending_updates": 0, "security_updates": 0});
            if !v.is_null() {
                state["reboot_required"] = v;
            }
            serde_json::from_value::<HostStateReport>(state)
                .unwrap()
                .reboot_required
        };
        assert_eq!(read(serde_json::json!(true)), RebootRequired::Yes);
        assert_eq!(read(serde_json::json!(false)), RebootRequired::No);
        assert_eq!(read(serde_json::json!("yes")), RebootRequired::Yes);
        assert_eq!(read(serde_json::json!("no")), RebootRequired::No);
        assert_eq!(read(serde_json::json!("unknown")), RebootRequired::Unknown);
        assert_eq!(read(serde_json::json!("perhaps")), RebootRequired::Unknown);
        assert_eq!(read(serde_json::Value::Null), RebootRequired::Unknown);
        assert_eq!(
            serde_json::to_value(RebootRequired::Unknown).unwrap(),
            "unknown"
        );
        assert_eq!(RebootRequired::Unknown.known(), None);
        assert_eq!(RebootRequired::No.known(), Some(false));
    }

    #[test]
    fn snapshot_support_says_which_or_why_not() {
        let none = SnapshotSupport {
            provider: None,
            reason: Some("snapper is not installed".into()),
        };
        assert_eq!(
            serde_json::to_value(&none).unwrap(),
            serde_json::json!({"reason": "snapper is not installed"})
        );
        let mut req = request();
        req.snapshots = Some(SnapshotSupport {
            provider: Some("snapper".into()),
            reason: None,
        });
        let back: CheckinRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(back.snapshots.unwrap().provider.as_deref(), Some("snapper"));
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
