//! Package manager backends.
//!
//! Adding support for a distro family means implementing [`PackageBackend`] and
//! adding a row to the integration test matrix. Nothing else in the agent
//! should need to change.
//!
//! The backends shell out to the package managers in their machine-readable
//! modes instead of linking `libapt` or `libdnf`. That keeps the binary
//! statically linked against musl, so one build per architecture runs on every
//! supported distro.
//!
//! An operation a backend doesn't support returns an error saying so, never an
//! empty result, so the server can tell "nothing there" from "couldn't check".

pub mod apt;
pub mod debian_upgrade;
pub mod dnf;
pub mod leapp_upgrade;
pub mod release;
pub mod ubuntu_upgrade;

use async_trait::async_trait;
use std::collections::BTreeSet;
use updawg_protocol::{AvailableUpdate, Ecosystem, InstalledPackage, PendingRemoval, Repository};

/// Anything that can go wrong talking to a package manager.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("package manager tool `{tool}` not found on this host")]
    ToolMissing { tool: &'static str },
    #[error("`{tool}` exited with status {status}: {stderr}")]
    CommandFailed {
        tool: &'static str,
        status: i32,
        stderr: String,
    },
    #[error("could not parse output of `{tool}`: {detail}")]
    Unparseable { tool: &'static str, detail: String },
    /// Another tool holds the lock. The caller waits and retries rather than
    /// forcing it, because forcing it corrupts the package database.
    #[error("package manager is locked by another process")]
    Locked,
    /// The plan can't be carried out as approved, so nothing was done: the
    /// installed version moved, the approved one is no longer available, or
    /// applying it would remove or add a package nobody reviewed. Nothing on
    /// the host changed.
    #[error("{0}")]
    Refused(String),
    /// The question can't be answered without changing the host first, such
    /// as asking leapp about a host it isn't installed on yet (the upgrade
    /// would install it). A preflight reports this as a warning, not a pass.
    #[error("{0}")]
    CannotTell(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, BackendError>;

/// One package, from exactly one version to exactly another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub name: String,
    pub arch: String,
    pub from: String,
    pub to: String,
}

/// An exact set of package versions to install. If the candidate has moved
/// on since the change was approved, the executor refuses the job.
#[derive(Debug, Clone, Default)]
pub struct ApplyPlan {
    pub packages: Vec<Pin>,
    pub allow_reboot: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub name: String,
    pub arch: String,
    pub from: String,
    pub to: String,
}

/// What actually changed after an apply.
#[derive(Debug, Clone, Default)]
pub struct ApplyOutcome {
    pub changed: Vec<Change>,
    pub reboot_required: bool,
    /// For a release upgrade that completes during the reboot (leapp): what
    /// to check once the host is back.
    pub after_reboot: Option<leapp_upgrade::AfterReboot>,
}

/// What the package manager would do if asked to upgrade everything.
///
/// Removals are kept separate because an obsoletion is a removal plus an
/// install, and [`AvailableUpdate`] (one name, two versions) can't represent
/// that without showing it as an upgrade of the wrong package.
#[derive(Debug, Clone, Default)]
pub struct PendingChanges {
    pub updates: Vec<AvailableUpdate>,
    /// Packages an upgrade would remove. Usually empty; non-empty when an
    /// installed package is obsoleted.
    pub removals: Vec<PendingRemoval>,
}

/// Somewhere to stream log lines as a job runs.
pub trait LogSink: Send + Sync {
    fn line(&self, line: &str);
}

#[async_trait]
pub trait PackageBackend: Send + Sync {
    fn ecosystem(&self) -> Ecosystem;
    async fn installed(&self) -> Result<Vec<InstalledPackage>>;
    /// Whether [`installed`](PackageBackend::installed) fills in module
    /// streams, so `module: None` means "not modular" and not "not asked".
    /// apt has no modules.
    fn reports_modules(&self) -> bool {
        false
    }
    /// `apt-get update` / `dnf makecache`.
    async fn refresh_metadata(&self) -> Result<()>;
    /// Updates and removals together. On apt both come from one
    /// `apt-get -s dist-upgrade` run, which is the expensive part of a
    /// collection pass, so splitting this would run it twice.
    async fn pending_changes(&self) -> Result<PendingChanges>;
    async fn repositories(&self) -> Result<Vec<Repository>>;
    /// Packages held or version-locked locally (`apt-mark showhold`,
    /// `dnf versionlock list`). These won't be upgraded, so a plan that
    /// includes them would report success without changing anything.
    async fn held_packages(&self) -> Result<Vec<String>>;

    /// What pins this host's package sources to a point in time, if anything.
    /// See [`updawg_protocol::Frozen`].
    async fn frozen(&self) -> Result<Option<updawg_protocol::Frozen>> {
        Ok(None)
    }

    /// Which of `updates` the package manager itself marks as security fixes.
    /// A local hint for the heartbeat; the server makes the real call from
    /// advisory data.
    ///
    /// apt marks it by pocket (an archive ending in `-security`, already in
    /// [`AvailableUpdate::repo`]). dnf has no security pocket, so it relies on
    /// [`AvailableUpdate::advisories`], filled from `updateinfo` during
    /// [`PackageBackend::pending_changes`]. Filtering on the pocket alone would
    /// find nothing on RHEL-family hosts.
    async fn security_updates(&self, updates: &[AvailableUpdate]) -> Result<BTreeSet<String>>;

    /// Every repository with its location and what is installed from it, for
    /// the release-upgrade preflight. Errors by default so an unsupported
    /// family isn't mistaken for one with no third-party repositories.
    async fn release_sources(&self) -> Result<Vec<RepoSource>> {
        Err(BackendError::Refused(
            "listing repository locations is not built for this package manager yet".into(),
        ))
    }

    /// Whether installing exactly `pins` would change only what they name
    /// (on apt, plus new packages built from the same source as one of them,
    /// such as a new kernel's ABI package). Runs the same simulation as
    /// [`PackageBackend::apply`] without changing anything. Returns the
    /// extra packages it would install, as `name version`.
    ///
    /// # Errors
    /// [`BackendError::Refused`] naming what the install would do that was
    /// not approved, or why it cannot be installed.
    async fn check_pins(&self, pins: &[Pin]) -> Result<Vec<String>> {
        let _ = pins;
        Err(BackendError::Refused(
            "simulating an install is not built for this package manager yet".into(),
        ))
    }

    async fn apply(&self, plan: &ApplyPlan, log: &dyn LogSink) -> Result<ApplyOutcome>;

    /// Reasons a `dist_upgrade` to `target` would be refused, using the same
    /// checks the upgrade runs before it starts. Empty when nothing blocks it.
    ///
    /// # Errors
    /// When the host could not be asked.
    async fn release_upgrade_blockers(&self, target: &str) -> Result<Vec<String>> {
        let _ = target;
        Ok(vec![
            "release upgrades are not built for this package manager yet".into(),
        ])
    }

    /// Whether the release upgrade completes during the following reboot
    /// (leapp). A job that isn't allowed to reboot must not start one.
    fn upgrade_finishes_at_reboot(&self) -> bool {
        false
    }

    /// Upgrades the host to release `target` (`13`, `24.04`). See
    /// [`debian_upgrade`], [`ubuntu_upgrade`] and [`leapp_upgrade`].
    ///
    /// # Errors
    /// [`BackendError::Refused`] when nothing was changed; anything else once
    /// the upgrade has begun.
    async fn dist_upgrade(&self, target: &str, log: &dyn LogSink) -> Result<ApplyOutcome> {
        let _ = (target, log);
        Err(BackendError::Refused(
            "release upgrades are not built for this package manager yet".into(),
        ))
    }
}

/// A repository's location, used to ask whether it publishes a release, and
/// the installed packages that came from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSource {
    /// The base URL apt fetches from: `https://packages.cloud.google.com/apt`.
    pub uri: String,
    /// The directory under `dists/`: `cloud-sdk-trixie`, `noble-updates`.
    pub suite: String,
    pub third_party: bool,
    /// Installed packages whose installed version this repository carries.
    pub packages: Vec<String>,
}

/// Picks the backend for this host.
///
/// # Errors
/// Returns [`BackendError::ToolMissing`] when neither family is detected.
pub fn detect() -> Result<Box<dyn PackageBackend>> {
    if std::path::Path::new("/usr/bin/dpkg").exists() {
        Ok(Box::new(apt::AptBackend::new()))
    } else if std::path::Path::new("/usr/bin/rpm").exists() {
        Ok(Box::new(dnf::DnfBackend::new()))
    } else {
        Err(BackendError::ToolMissing {
            tool: "dpkg or rpm",
        })
    }
}
