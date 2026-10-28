//! Check-in: `POST /agent/v1/checkin`.
//!
//! The gateway returns immediately if jobs are waiting or the agent's
//! inventory hash is stale. Otherwise it holds the request open until a job
//! appears or the timeout is reached, which gives near-instant delivery
//! without persistent sockets.
//!
//! This is the hot path, so the request body is kept small.

use crate::{
    config::{LocalPolicy, ServerConfig},
    ids::{JobId, SigningKeyId},
    job::Job,
};
use serde::{Deserialize, Serialize};

/// Whether the host needs a reboot, as far as it can tell.
///
/// Detection varies across distributions, so some hosts can't answer. Before
/// 0.4 this was a `bool` and unknown was reported as `false`.
///
/// Still accepts the old `true`/`false`. An absent field is
/// [`RebootRequired::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebootRequired {
    Yes,
    No,
    /// No mechanism on this host could answer. Don't treat it as `No`.
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

    /// `None` for unknown.
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
                // includes words from a newer agent
                _ => Self::Unknown,
            },
        })
    }
}

/// Whether the host can take snapshots before a change and roll back to them.
/// Detected by the agent at start.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SnapshotSupport {
    /// The provider in use, such as `snapper`. `None` if this host can't take
    /// snapshots, in which case [`SnapshotSupport::reason`] says why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// How the agent was installed, which decides how it updates. Detected by the
/// agent at start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInstall {
    pub method: InstallMethod,
    /// The channel the host's package repository follows (`stable`, `beta`).
    /// A package install can only move to builds its repository holds, so a
    /// stable host refuses a beta build. `None` for a binary install, which
    /// can take either, or when the repository file couldn't be read.
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
    /// Binaries from `install.sh` in `/usr/local/bin`, updated from the
    /// signed manifest.
    Binary,
    /// Unknown to this version, or an install the agent can't update itself.
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
    /// Changes on reboot, so the server can spot one it didn't ask for.
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
    /// The longest the agent would like this request held open.
    ///
    /// Some middleboxes kill connections that look idle. An agent that has
    /// seen its polls cut off after 30 seconds can ask for less than that.
    ///
    /// Advisory: the gateway clamps it in [`CheckinRequest::hold_seconds`],
    /// and an older gateway ignores it and holds for its own default. So the
    /// agent must not shorten its own request timeout to match, or it will
    /// abandon polls the gateway was about to answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_hold_s: Option<u64>,
    /// What `/etc/updawg/agent.toml` permits. `None` means the agent is too
    /// old to report it, not that it may do nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_policy: Option<LocalPolicy>,
    /// Whether this host can take snapshots. `None` means the agent is too old
    /// to report it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshots: Option<SnapshotSupport>,
    /// The agent build this host is running, as its packages name it
    /// (`0.2.0-20261003083653.gdd21454`).
    ///
    /// Sent on every check-in so the server notices manual upgrades (`apt
    /// upgrade`, rerunning the installer). `None` from older agents; the
    /// server keeps the last version it knew.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    /// How this agent was installed and which channel it follows. `None` from
    /// older agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install: Option<AgentInstall>,
    /// The organization signing keys this agent has pinned, by id.
    ///
    /// The server only knows what it offered, which doesn't show whether an
    /// endorsement was refused or a renewal never happened. An organization
    /// moving to its own signing key uses this to confirm every host has it
    /// before retiring the old one. `None` from older agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_keys: Option<Vec<SigningKeyId>>,
}

impl CheckinRequest {
    /// How long to actually hold this request open, in seconds.
    ///
    /// The request's `max_hold_s` clamped to between
    /// [`CHECKIN_MIN_HOLD_SECONDS`](crate::CHECKIN_MIN_HOLD_SECONDS) and `max`,
    /// or `max` if it didn't ask.
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
    /// Bumped when server-side configuration changes; the agent re-fetches
    /// `/config` when it moves.
    pub config_version: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jobs: Vec<Job>,
    /// Sent inline when the agent's config version is behind, saving a round
    /// trip on the hot path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<ServerConfig>,
    /// Renew the client certificate now rather than when it falls due.
    ///
    /// Set when the organization has a signing key this host hasn't been
    /// offered. Hosts pick up keys at renewal, so without this a host could
    /// keep verifying against the old key for weeks after a rotation. The
    /// agent renews within minutes, with per-host jitter.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub renew_certificate: bool,
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
            pinned_keys: None,
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
        // the server deserialises with these same structs
        let mut req = request();
        req.max_hold_s = Some(30);
        let mut value: serde_json::Value = serde_json::to_value(&req).unwrap();
        value["something_from_the_future"] = serde_json::json!("hello");
        let back: CheckinRequest = serde_json::from_value(value).unwrap();
        assert_eq!(back.max_hold_s, Some(30));
    }

    /// Agents before 0.4 send a bool.
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
            renew_certificate: false,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.len() < 100, "empty check-in response grew: {json}");
        assert!(!json.contains("jobs"));
    }
}
