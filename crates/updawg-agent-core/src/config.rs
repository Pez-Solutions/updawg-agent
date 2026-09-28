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

use crate::duration::HumanDuration;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, time::Duration};
use updawg_protocol::JobKind;

/// How much the agent is allowed to do.
///
/// The protocol's own type rather than a second one that happens to agree: the
/// mode is reported to the server on every check-in (DAWG-223), and a file, a
/// wire format and a database column that each spell it their own way is three
/// chances for one of them to be wrong. `observe` and `managed` are what
/// `/etc/updawg/agent.toml` has always said, so nothing on disk changes.
pub use updawg_protocol::AgentMode as Mode;

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
    /// How often to collect and upload a full inventory.
    #[serde(default = "default_inventory_interval")]
    pub inventory_interval: HumanDuration,
    /// How often to refresh package manager metadata.
    #[serde(default = "default_refresh_metadata")]
    pub refresh_metadata: HumanDuration,
}

fn default_inventory_interval() -> HumanDuration {
    HumanDuration(Duration::from_secs(6 * 3600))
}
fn default_refresh_metadata() -> HumanDuration {
    HumanDuration(Duration::from_secs(3600))
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            inventory_interval: default_inventory_interval(),
            refresh_metadata: default_refresh_metadata(),
        }
    }
}

/// Which snapshot mechanism to use before a mutating job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotProvider {
    /// Detect whatever is available at startup.
    #[default]
    Auto,
    Snapper,
    Zfs,
    Lvm,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshots {
    #[serde(default)]
    pub provider: SnapshotProvider,
    /// How many snapshots to retain. Unbounded snapshots fill disks, which is
    /// its own outage.
    #[serde(default = "default_keep")]
    pub keep: u32,
}

const fn default_keep() -> u32 {
    3
}

impl SnapshotProvider {
    /// The provider crate's name for this choice.
    #[must_use]
    pub const fn provider(self) -> updawg_snapshots::Provider {
        match self {
            Self::Auto => updawg_snapshots::Provider::Auto,
            Self::Snapper => updawg_snapshots::Provider::Snapper,
            Self::Zfs => updawg_snapshots::Provider::Zfs,
            Self::Lvm => updawg_snapshots::Provider::Lvm,
            Self::None => updawg_snapshots::Provider::None,
        }
    }
}

impl Default for Snapshots {
    fn default() -> Self {
        Self {
            provider: SnapshotProvider::default(),
            keep: default_keep(),
        }
    }
}

/// `[reboot]`: how this host warns people before a job reboots it (DAWG-103).
///
/// The host's, not the server's: whoever runs it knows who is logged in and
/// how long they need. Whether a reboot may happen at all is
/// `[permissions]`'s `reboot`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebootSettings {
    /// How long between the warning and the reboot. Rounded **up** to whole
    /// minutes, because that is what `shutdown` counts in, and a warning must
    /// not arrive late. At least a minute.
    #[serde(default = "default_reboot_delay")]
    pub delay: HumanDuration,
    /// What logged-in users see.
    #[serde(default = "default_reboot_message")]
    pub message: String,
}

fn default_reboot_delay() -> HumanDuration {
    HumanDuration(Duration::from_secs(60))
}
fn default_reboot_message() -> String {
    "Updawg: rebooting shortly to finish an approved update".to_owned()
}

impl Default for RebootSettings {
    fn default() -> Self {
        Self {
            delay: default_reboot_delay(),
            message: default_reboot_message(),
        }
    }
}

impl RebootSettings {
    /// The delay in seconds, never under a minute: a reboot without warning
    /// anybody is not something configuration can ask for by accident.
    #[must_use]
    pub fn delay_s(&self) -> u64 {
        self.delay.0.as_secs().max(60)
    }
}

/// One `[[health_check]]` entry.
///
/// Checks run after every mutating job, and a failure is what halts a rollout.
/// A check that cannot run reports a failure rather than quietly passing —
/// "I could not tell" and "it is fine" are very different answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum HealthCheck {
    Systemd {
        name: String,
        unit: String,
        #[serde(default = "default_check_timeout")]
        timeout: HumanDuration,
    },
    Http {
        name: String,
        url: String,
        #[serde(default = "default_expect_status")]
        expect_status: u16,
        #[serde(default = "default_check_timeout")]
        timeout: HumanDuration,
    },
    Command {
        name: String,
        /// Argument vector, never a shell string. There is no shell here on
        /// purpose: a health check is the operator's own configuration, but it
        /// still should not grow a quoting-and-injection surface.
        argv: Vec<String>,
        #[serde(default = "default_check_timeout")]
        timeout: HumanDuration,
    },
}

fn default_check_timeout() -> HumanDuration {
    HumanDuration(Duration::from_secs(5))
}
const fn default_expect_status() -> u16 {
    200
}

impl HealthCheck {
    /// What the executor runs for this entry (DAWG-104).
    #[must_use]
    pub fn to_check(&self) -> updawg_executor::health::Check {
        use updawg_executor::health::{Check, CheckKind};
        let (kind, timeout) = match self {
            Self::Systemd { unit, timeout, .. } => {
                (CheckKind::Systemd { unit: unit.clone() }, timeout)
            }
            Self::Http {
                url,
                expect_status,
                timeout,
                ..
            } => (
                CheckKind::Http {
                    url: url.clone(),
                    expect_status: *expect_status,
                },
                timeout,
            ),
            Self::Command { argv, timeout, .. } => {
                (CheckKind::Command { argv: argv.clone() }, timeout)
            }
        };
        Check {
            name: self.name().to_owned(),
            kind,
            timeout: timeout.0,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Systemd { name, .. } | Self::Http { name, .. } | Self::Command { name, .. } => {
                name
            }
        }
    }
}

/// See [`AgentConfig::mode`]. Not the protocol's `AgentMode::default()`,
/// which stays `observe`: that one is what a report that omits the mode means,
/// and nothing may be read as more permissive than it said.
const fn default_mode() -> Mode {
    Mode::Managed
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub server: String,
    /// `managed` when the file does not say: an agent is installed to act on
    /// what its organization approves. What it may do is still only what
    /// `[permissions]` allows, and an empty allow list permits nothing — so a
    /// truncated file still fails closed.
    #[serde(default = "default_mode")]
    pub mode: Mode,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub schedule: Schedule,
    #[serde(default)]
    pub snapshots: Snapshots,
    #[serde(default)]
    pub reboot: RebootSettings,
    /// `[[health_check]]` entries, in the order they were written.
    #[serde(default, rename = "health_check")]
    pub health_checks: Vec<HealthCheck>,
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

    /// Read and parse the on-disk configuration.
    ///
    /// # Errors
    /// Fails if the file cannot be read or is not valid configuration. The
    /// agent refuses to start on a malformed config rather than falling back to
    /// a default that might permit more than the operator intended.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_toml(&raw).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source,
        })
    }

    /// What this file permits, in the shape the server is told about it
    /// (DAWG-223).
    ///
    /// Derived from `[permissions]` rather than sent as the allow and deny
    /// lists themselves. The server has no business knowing that `snapshot`
    /// covers two job kinds or that deny beats allow — those are the agent's
    /// rules, they are enforced here, and shipping them would invite a second
    /// implementation of them somewhere that cannot be audited. What travels is
    /// the answer: the kinds this host would accept.
    ///
    /// The mode travels **separately** and is not folded in, so a host in
    /// observe mode with `apply_patch` written down reads as exactly that. An
    /// operator who has switched the mode off has not deleted the permission,
    /// and the two facts are worth telling apart on a dashboard.
    #[must_use]
    pub fn local_policy(&self) -> updawg_protocol::LocalPolicy {
        updawg_protocol::LocalPolicy {
            mode: self.mode,
            permitted_job_kinds: JobKind::ALL
                .into_iter()
                .filter(|kind| self.permissions.permits(*kind))
                .collect(),
        }
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

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("could not read {path}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is not valid configuration")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
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
            snapshots: Snapshots::default(),
            reboot: RebootSettings::default(),
            health_checks: Vec::new(),
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

    /// The complete example from section 3.6 of the design document, verbatim.
    /// If this stops parsing, either the document or the code has drifted.
    #[test]
    fn the_documented_example_config_parses_in_full() {
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

[snapshots]
provider = "auto"
keep     = 3

[[health_check]]
name = "nginx running"
type = "systemd"
unit = "nginx.service"

[[health_check]]
name = "app responds"
type = "http"
url  = "http://127.0.0.1:8080/healthz"
expect_status = 200
timeout = "5s"
"#,
        )
        .expect("example config from the design document should parse");

        assert_eq!(cfg.mode, Mode::Managed);
        assert!(cfg.permissions.deny.contains("dist_upgrade"));
        assert!(!cfg.admits(JobKind::DistUpgrade, None));

        assert_eq!(
            cfg.schedule.inventory_interval.as_duration(),
            Duration::from_secs(21_600)
        );
        assert_eq!(
            cfg.schedule.refresh_metadata.as_duration(),
            Duration::from_secs(3600)
        );

        assert_eq!(cfg.snapshots.provider, SnapshotProvider::Auto);
        assert_eq!(cfg.snapshots.keep, 3);

        assert_eq!(cfg.health_checks.len(), 2);
        assert_eq!(cfg.health_checks[0].name(), "nginx running");
        assert!(matches!(cfg.health_checks[0], HealthCheck::Systemd { .. }));
        match &cfg.health_checks[1] {
            HealthCheck::Http {
                url,
                expect_status,
                timeout,
                ..
            } => {
                assert_eq!(url, "http://127.0.0.1:8080/healthz");
                assert_eq!(*expect_status, 200);
                assert_eq!(timeout.as_duration(), Duration::from_secs(5));
            }
            other => panic!("expected an http check, got {other:?}"),
        }
    }

    #[test]
    fn defaults_apply_when_sections_are_omitted() {
        let cfg = AgentConfig::from_toml(r#"server = "https://agents.updawg.net""#).unwrap();
        assert_eq!(cfg.snapshots.provider, SnapshotProvider::Auto);
        assert_eq!(cfg.snapshots.keep, 3);
        assert!(cfg.health_checks.is_empty());
        assert_eq!(
            cfg.schedule.inventory_interval.as_duration(),
            Duration::from_secs(21_600)
        );
    }

    #[test]
    fn a_malformed_duration_fails_the_whole_config() {
        let err = AgentConfig::from_toml(
            r#"
server = "https://agents.updawg.net"
[schedule]
inventory_interval = "6 hours"
"#,
        );
        assert!(
            err.is_err(),
            "an unparseable duration must not silently fall back to a default"
        );
    }

    #[test]
    fn mode_defaults_to_managed_when_omitted() {
        let cfg = AgentConfig::from_toml(r#"server = "https://agents.updawg.net""#)
            .expect("minimal config should parse");
        assert_eq!(cfg.mode, Mode::Managed);
    }

    #[test]
    fn managed_by_default_still_permits_nothing_it_was_not_given() {
        // The mode defaulting to managed is safe only because permissions do
        // not default to anything: a file with neither permits no change.
        let cfg = AgentConfig::from_toml(r#"server = "https://agents.updawg.net""#)
            .expect("minimal config should parse");
        for kind in [JobKind::ApplyUpdates, JobKind::Reboot, JobKind::DistUpgrade] {
            assert!(!cfg.permissions.permits(kind), "{kind:?}");
        }
    }

    #[test]
    fn observe_written_down_is_still_observe() {
        let cfg =
            AgentConfig::from_toml("server = \"https://agents.updawg.net\"\nmode = \"observe\"")
                .expect("parse");
        assert_eq!(cfg.mode, Mode::Observe);
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    fn config(mode: Mode, allow: &[&str]) -> AgentConfig {
        AgentConfig {
            server: "https://agents.updawg.net".into(),
            mode,
            permissions: Permissions {
                allow: allow.iter().map(|s| (*s).to_string()).collect(),
                deny: BTreeSet::default(),
            },
            schedule: Schedule::default(),
            snapshots: Snapshots::default(),
            reboot: RebootSettings::default(),
            health_checks: Vec::new(),
        }
    }

    #[test]
    fn the_reported_policy_is_what_the_file_permits() {
        let policy = config(Mode::Managed, &["refresh", "apply_patch"]).local_policy();
        assert_eq!(
            policy.permitted_job_kinds,
            vec![JobKind::RefreshInventory, JobKind::ApplyUpdates]
        );
        assert_eq!(policy.mode, Mode::Managed);
    }

    #[test]
    fn one_permission_covering_two_kinds_reports_both() {
        // `snapshot` gates Snapshot and Rollback. The server is told about job
        // kinds, not about the agent's permission names, so both appear.
        let policy = config(Mode::Managed, &["snapshot"]).local_policy();
        assert_eq!(
            policy.permitted_job_kinds,
            vec![JobKind::Snapshot, JobKind::Rollback]
        );
    }

    #[test]
    fn a_denied_permission_never_reaches_the_server_as_permitted() {
        let mut cfg = config(Mode::Managed, &["refresh", "reboot"]);
        cfg.permissions.deny.insert("reboot".into());
        assert_eq!(
            cfg.local_policy().permitted_job_kinds,
            vec![JobKind::RefreshInventory]
        );
    }

    #[test]
    fn observe_mode_reports_the_mode_without_erasing_the_permissions() {
        // The two facts stay apart: the operator wrote the permission down and
        // switched the mode off, which is not the same as never writing it.
        let policy = config(Mode::Observe, &["apply_patch"]).local_policy();
        assert_eq!(policy.mode, Mode::Observe);
        assert_eq!(policy.permitted_job_kinds, vec![JobKind::ApplyUpdates]);
        // And the server reading it back reaches the same answer the agent does.
        assert!(!policy.permits(JobKind::ApplyUpdates));
    }

    #[test]
    fn the_reported_policy_agrees_with_admits_for_every_kind() {
        // The property that makes this worth sending at all: what the server is
        // told and what the agent will actually do are the same answer. Anything
        // else and the portal promises something the host refuses.
        for allow in [
            vec![],
            vec!["refresh"],
            vec!["refresh", "apply_patch", "reboot", "dist_upgrade"],
            vec!["snapshot", "self_update", "preflight"],
        ] {
            for mode in [Mode::Observe, Mode::Managed] {
                let cfg = config(mode, &allow);
                let policy = cfg.local_policy();
                for kind in JobKind::ALL {
                    assert_eq!(
                        policy.permits(kind),
                        cfg.admits(kind, None),
                        "{mode:?} {allow:?} {kind:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_reboot_warning_is_the_hosts_to_set_and_never_under_a_minute() {
        let base = "server = \"https://agents.example\"\n";
        let default = AgentConfig::from_toml(base).unwrap();
        assert_eq!(default.reboot.delay_s(), 60);
        assert!(!default.reboot.message.is_empty());

        let set = AgentConfig::from_toml(&format!(
            "{base}[reboot]\ndelay = \"10m\"\nmessage = \"db01 reboots for patching; save your work\"\n"
        ))
        .unwrap();
        assert_eq!(set.reboot.delay_s(), 600);
        assert_eq!(
            set.reboot.message,
            "db01 reboots for patching; save your work"
        );

        let rushed = AgentConfig::from_toml(&format!("{base}[reboot]\ndelay = \"5s\"\n")).unwrap();
        assert_eq!(
            rushed.reboot.delay_s(),
            60,
            "a reboot without warning was configurable"
        );
    }
}
