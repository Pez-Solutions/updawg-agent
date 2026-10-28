//! `/etc/updawg/agent.toml`.
//!
//! Local configuration always wins. The server can narrow what the agent will
//! do but never widen it, which is why [`Permissions::intersect`] only ever
//! shrinks the allow list.

use crate::duration::HumanDuration;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, time::Duration};
use updawg_protocol::JobKind;

/// How much the agent is allowed to do. Reuses the protocol type since the
/// mode is reported on every check-in.
pub use updawg_protocol::AgentMode as Mode;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Permissions {
    #[serde(default)]
    pub allow: BTreeSet<String>,
    #[serde(default)]
    pub deny: BTreeSet<String>,
}

impl Permissions {
    /// Deny beats allow. An empty allow list permits nothing, so a truncated
    /// config fails closed.
    #[must_use]
    pub fn permits(&self, kind: JobKind) -> bool {
        let p = kind.permission();
        !self.deny.contains(p) && self.allow.contains(p)
    }

    /// Narrows these permissions by what the server offers. The result is
    /// never larger than `self`.
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
    /// How many snapshots to retain.
    #[serde(default = "default_keep")]
    pub keep: u32,
    /// Skip the snapshot if less than this many MiB are free where it would
    /// live. A snapshot pins the files an install replaces, so the install
    /// needs room for both old and new.
    #[serde(default = "default_min_free_mb")]
    pub min_free_mb: u64,
}

const fn default_keep() -> u32 {
    3
}

const fn default_min_free_mb() -> u64 {
    1024
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
            min_free_mb: default_min_free_mb(),
        }
    }
}

/// `[reboot]`: how this host warns users before a job reboots it. Set
/// locally since the host's operator knows who is logged in. Whether a reboot
/// is allowed at all is the `reboot` permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebootSettings {
    /// Time between the warning and the reboot. Rounded up to whole minutes
    /// for `shutdown`, minimum one minute.
    #[serde(default = "default_reboot_delay")]
    pub delay: HumanDuration,
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
    /// The delay in seconds, never under a minute.
    #[must_use]
    pub fn delay_s(&self) -> u64 {
        self.delay.0.as_secs().max(60)
    }
}

/// One `[[health_check]]` entry. Checks run after every mutating job and a
/// failure halts the rollout. A check that can't run counts as failed.
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
        /// Argument vector, run without a shell to avoid quoting and
        /// injection problems.
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
    /// The executor's check for this entry.
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

/// See [`AgentConfig::mode`]. Differs from `AgentMode::default()`, which is
/// `observe` because that's how a report without a mode must be read.
const fn default_mode() -> Mode {
    Mode::Managed
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub server: String,
    /// Defaults to `managed`. This is safe because `[permissions]` defaults
    /// to an empty allow list, which permits nothing.
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
    /// `[[health_check]]` entries, in file order.
    #[serde(default, rename = "health_check")]
    pub health_checks: Vec<HealthCheck>,
    /// The organization signing key this host trusts, for organizations that
    /// hold their own key: the base64 SPKI printed by `updawgctl keygen`, with
    /// or without the `ed25519:` prefix.
    ///
    /// If set, enrollment pins it. The server must offer this key and any
    /// other key must be endorsed by a chain from it, so a compromised server
    /// still can't create jobs for hosts enrolled afterwards. It lives here
    /// because the server can't change this file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_org_key: Option<String>,
}

impl AgentConfig {
    /// Parses the configuration.
    ///
    /// # Errors
    /// Returns the TOML error if the file is not valid configuration.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Reads and parses the configuration.
    ///
    /// # Errors
    /// Fails if the file cannot be read or is not valid configuration. There
    /// is no fallback to defaults, which might permit more than intended.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let config = Self::from_toml(&raw).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source,
        })?;
        // fail at startup rather than at enrollment
        config.trusted_org_key()?;
        Ok(config)
    }

    /// The organization key this host is told to trust, parsed.
    ///
    /// # Errors
    /// [`ConfigError::TrustedOrgKey`] if it is set and is not an Ed25519 key.
    pub fn trusted_org_key(&self) -> Result<Option<updawg_crypto::OrgPublicKey>, ConfigError> {
        self.trusted_org_key
            .as_deref()
            .map(|encoded| {
                updawg_crypto::OrgPublicKey::parse_configured("trusted_org_key", encoded)
                    .map_err(|e| ConfigError::TrustedOrgKey(e.to_string()))
            })
            .transpose()
    }

    /// What this file permits, as reported to the server.
    ///
    /// Sends the resulting job kinds rather than the raw allow and deny lists,
    /// so the permission rules only exist in the agent. The mode is reported
    /// separately and not folded in, so observe mode doesn't hide which
    /// permissions are configured.
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

    /// Whether a job may run on this host.
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
    #[error("trusted_org_key is not usable: {0}")]
    TrustedOrgKey(String),
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
            trusted_org_key: None,
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
        // read-only jobs still run
        assert!(cfg.admits(JobKind::RefreshInventory, None));
    }

    /// Scheduled inventory runs are not jobs and aren't affected by this.
    #[test]
    fn a_refresh_job_is_gated_by_the_allow_list_like_any_other() {
        let cfg = AgentConfig {
            mode: Mode::Observe,
            ..managed(&[], &[])
        };
        assert!(!cfg.admits(JobKind::RefreshInventory, None));
    }

    #[test]
    fn a_trusted_org_key_is_optional_and_checked_when_present() {
        let without = AgentConfig::from_toml("server = \"https://a\"\n").unwrap();
        assert!(without.trusted_org_key().unwrap().is_none());

        let with = AgentConfig::from_toml(
            "server = \"https://a\"\n\
             trusted_org_key = \"MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\"\n",
        )
        .unwrap();
        assert!(with.trusted_org_key().unwrap().is_some());

        let typo = AgentConfig::from_toml(
            "server = \"https://a\"\ntrusted_org_key = \"MCowBQYDK2VwAyEAGb9E\"\n",
        )
        .unwrap();
        assert!(matches!(
            typo.trusted_org_key(),
            Err(ConfigError::TrustedOrgKey(_))
        ));
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

    #[test]
    fn the_server_cannot_widen_local_permissions() {
        let local = managed(&["apply_patch"], &["dist_upgrade"]);
        let server = perms(&["apply_patch", "dist_upgrade", "reboot"], &[]);

        assert!(!local.admits(JobKind::DistUpgrade, Some(&server)));
        assert!(!local.admits(JobKind::Reboot, Some(&server)));
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

    /// The full documented example config.
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
        .expect("the example config should parse");

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
        assert_eq!(cfg.snapshots.min_free_mb, 1024);

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
        // defaulting to managed is only safe because permissions default to
        // nothing
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
            trusted_org_key: None,
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
        // `snapshot` gates both Snapshot and Rollback
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
        let policy = config(Mode::Observe, &["apply_patch"]).local_policy();
        assert_eq!(policy.mode, Mode::Observe);
        assert_eq!(policy.permitted_job_kinds, vec![JobKind::ApplyUpdates]);
        assert!(!policy.permits(JobKind::ApplyUpdates));
    }

    #[test]
    fn the_reported_policy_agrees_with_admits_for_every_kind() {
        // what the server is told must match what the agent will actually do
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
