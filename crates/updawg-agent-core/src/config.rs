//! `/etc/updawg/agent.toml`.
//!
//! The rule this module exists to enforce: **local configuration always wins**.
//! The server may narrow what the agent will do and must never be able to widen
//! it. That is a load-bearing security property, not a preference, which is why
//! [`Permissions::intersect`] is an intersection and there is deliberately no
//! union anywhere in this file.
//!
//! Scope note: DAWG-19 defines and tests the config model. DAWG-38 wires it
//! into job admission end to end.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use updawg_protocol::JobKind;

/// How much the agent is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Report only. Never change anything, whatever the server sends.
    #[default]
    Observe,
    /// Execute signed jobs, subject to `[permissions]`.
    Managed,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Permissions {
    #[serde(default)]
    pub allow: BTreeSet<String>,
    #[serde(default)]
    pub deny: BTreeSet<String>,
}

impl Permissions {
    /// Whether a job kind is permitted.
    ///
    /// Deny beats allow. An empty allow list permits nothing, so a malformed or
    /// truncated config fails closed rather than open.
    #[must_use]
    pub fn permits(&self, kind: JobKind) -> bool {
        let p = kind.permission();
        !self.deny.contains(p) && self.allow.contains(p)
    }

    /// Narrow these permissions by what the server offers.
    ///
    /// The result can only ever be smaller than `self`. There is no code path
    /// that makes it larger, and the tests below assert that.
    #[must_use]
    pub fn intersect(&self, server: &Self) -> Self {
        Self {
            allow: self.allow.intersection(&server.allow).cloned().collect(),
            deny: self.deny.union(&server.deny).cloned().collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    #[serde(default = "default_inventory_interval")]
    pub inventory_interval: String,
    #[serde(default = "default_refresh_metadata")]
    pub refresh_metadata: String,
}

fn default_inventory_interval() -> String {
    "6h".into()
}
fn default_refresh_metadata() -> String {
    "1h".into()
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            inventory_interval: default_inventory_interval(),
            refresh_metadata: default_refresh_metadata(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub server: String,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub schedule: Schedule,
}

impl AgentConfig {
    /// Parse the on-disk configuration.
    ///
    /// # Errors
    /// Returns the TOML error if the file is not valid configuration. The agent
    /// refuses to start on a malformed config rather than falling back to a
    /// default that might be more permissive than intended.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Final answer on whether a job may run on this host.
    #[must_use]
    pub fn admits(&self, kind: JobKind, server: Option<&Permissions>) -> bool {
        if self.mode == Mode::Observe && kind.is_mutating() {
            return false;
        }
        match server {
            Some(s) => self.permissions.intersect(s).permits(kind),
            None => self.permissions.permits(kind),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn perms(allow: &[&str], deny: &[&str]) -> Permissions {
        Permissions {
            allow: allow.iter().map(|s| (*s).to_string()).collect(),
            deny: deny.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn managed(allow: &[&str], deny: &[&str]) -> AgentConfig {
        AgentConfig {
            server: "https://agents.updawg.net".into(),
            mode: Mode::Managed,
            permissions: perms(allow, deny),
            schedule: Schedule::default(),
        }
    }

    #[test]
    fn observe_mode_refuses_every_mutating_job() {
        let cfg = AgentConfig {
            mode: Mode::Observe,
            ..managed(&["refresh", "apply_patch", "reboot", "dist_upgrade"], &[])
        };
        assert!(!cfg.admits(JobKind::ApplyUpdates, None));
        assert!(!cfg.admits(JobKind::Reboot, None));
        assert!(!cfg.admits(JobKind::DistUpgrade, None));
        // Read-only work still happens; that is the point of observe mode.
        assert!(cfg.admits(JobKind::RefreshInventory, None));
    }

    /// Fail-closed applies to read-only jobs too: a `refresh_inventory` job is
    /// still a job, and the allow list still gates it. That is why the example
    /// configuration in the design document lists `refresh` explicitly. The
    /// agent's own scheduled inventory runs are not jobs and are unaffected.
    #[test]
    fn a_refresh_job_is_gated_by_the_allow_list_like_any_other() {
        let cfg = AgentConfig {
            mode: Mode::Observe,
            ..managed(&[], &[])
        };
        assert!(!cfg.admits(JobKind::RefreshInventory, None));
    }

    #[test]
    fn deny_beats_allow() {
        let cfg = managed(&["dist_upgrade"], &["dist_upgrade"]);
        assert!(!cfg.admits(JobKind::DistUpgrade, None));
    }

    #[test]
    fn an_empty_allow_list_fails_closed() {
        let cfg = managed(&[], &[]);
        assert!(!cfg.admits(JobKind::ApplyUpdates, None));
    }

    /// The property the whole security model rests on: the server can take
    /// permissions away and can never hand them out.
    #[test]
    fn the_server_cannot_widen_local_permissions() {
        let local = managed(&["apply_patch"], &["dist_upgrade"]);
        let server = perms(&["apply_patch", "dist_upgrade", "reboot"], &[]);

        // The server offers dist_upgrade and reboot. Local config says no.
        assert!(!local.admits(JobKind::DistUpgrade, Some(&server)));
        assert!(!local.admits(JobKind::Reboot, Some(&server)));
        // What both agree on still works.
        assert!(local.admits(JobKind::ApplyUpdates, Some(&server)));
    }

    #[test]
    fn the_server_can_narrow_local_permissions() {
        let local = managed(&["apply_patch", "reboot"], &[]);
        let server = perms(&["apply_patch"], &["reboot"]);
        assert!(local.admits(JobKind::ApplyUpdates, Some(&server)));
        assert!(!local.admits(JobKind::Reboot, Some(&server)));
    }

    #[test]
    fn intersection_never_grows_the_allow_list() {
        let local = perms(&["a", "b"], &[]);
        let server = perms(&["a", "b", "c", "d"], &[]);
        let merged = local.intersect(&server);
        assert!(merged.allow.len() <= local.allow.len());
        assert!(!merged.allow.contains("c"));
    }

    #[test]
    fn the_documented_example_config_parses() {
        let cfg = AgentConfig::from_toml(
            r#"
server = "https://agents.updawg.net"
mode = "managed"

[permissions]
allow = ["refresh", "apply_security", "apply_patch", "apply_kernel", "reboot", "snapshot"]
deny  = ["dist_upgrade"]

[schedule]
inventory_interval = "6h"
refresh_metadata   = "1h"
"#,
        )
        .expect("example config from the design document should parse");
        assert_eq!(cfg.mode, Mode::Managed);
        assert!(cfg.permissions.deny.contains("dist_upgrade"));
        assert!(!cfg.admits(JobKind::DistUpgrade, None));
    }

    #[test]
    fn mode_defaults_to_observe_when_omitted() {
        let cfg = AgentConfig::from_toml(r#"server = "https://agents.updawg.net""#)
            .expect("minimal config should parse");
        assert_eq!(cfg.mode, Mode::Observe);
    }
}
