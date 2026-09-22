//! Package manager backends.
//!
//! Adding support for a distro family means implementing [`PackageBackend`] and
//! adding a row to the integration test matrix. Nothing else in the agent
//! should need to change.
//!
//! These backends shell out to the package managers in machine-readable modes
//! rather than linking `libapt` or `libdnf`. That is a deliberate trade: it
//! keeps the binary statically linked against musl, so one build per
//! architecture runs on every supported distro.
//!
//! Scope note: DAWG-19 defines the trait, DAWG-34 implements apt and DAWG-35
//! implements dnf. Both report the whole of what they can see; neither can apply
//! anything yet, because the mutating half belongs with job execution and its
//! permission checks (DAWG-38), and both say so by name rather than by returning
//! an empty result. "No packages" and "I cannot tell you" must never look the
//! same to the server.

pub mod apt;
pub mod dnf;

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
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, BackendError>;

/// An exact set of package versions to install.
///
/// Exact, not "latest": if the candidate has moved on since the change was
/// approved, the executor refuses the job rather than installing something
/// nobody reviewed.
#[derive(Debug, Clone, Default)]
pub struct ApplyPlan {
    pub packages: Vec<(String, String)>,
    pub allow_reboot: bool,
}

/// What actually changed after an apply.
#[derive(Debug, Clone, Default)]
pub struct ApplyOutcome {
    pub changed: Vec<(String, String, String)>,
    pub reboot_required: bool,
}

/// What the package manager would do if asked to upgrade everything.
///
/// Two lists rather than one, because an obsoletion is a removal and an install
/// rather than a version moving, and [`AvailableUpdate`] has one name and two
/// versions. Squeezing a replacement into that shape produces a row that reads
/// like an upgrade, names the wrong package, and would be believed (DAWG-232).
#[derive(Debug, Clone, Default)]
pub struct PendingChanges {
    pub updates: Vec<AvailableUpdate>,
    /// Packages an upgrade would **remove**. Empty is the normal answer and the
    /// interesting one is never empty: a host with an obsoleted package
    /// installed is a host where applying updates takes something away.
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
    /// `apt-get update` / `dnf makecache`.
    async fn refresh_metadata(&self) -> Result<()>;
    /// Everything one look at the upgrade path found.
    ///
    /// Updates and removals together, in one call, because on apt they come out
    /// of one command: `apt-get -s dist-upgrade` prints `Inst` and `Remv` lines
    /// in the same simulation, and it is the expensive call in a collection
    /// pass. Splitting the trait in two would double it for the shape of the
    /// answer rather than for the answer. dnf needs two commands either way and
    /// says so in its own implementation.
    async fn pending_changes(&self) -> Result<PendingChanges>;
    async fn repositories(&self) -> Result<Vec<Repository>>;
    /// Packages pinned or held locally, which will not be upgraded whatever a
    /// proposal says.
    ///
    /// A package question, and therefore the backend's: it is `apt-mark
    /// showhold` on one family and `dnf versionlock list` on another. This is why
    /// `held_packages` was removed from `HostState` rather than left permanently
    /// empty — a collector could never answer it.
    ///
    /// It matters because a plan that ignores these is a plan that silently does
    /// nothing: the job reports success, the version does not move, and the host
    /// stays vulnerable while the dashboard says it was patched.
    async fn held_packages(&self) -> Result<Vec<String>>;

    /// Which of `updates` the package manager itself calls a security fix.
    ///
    /// A local hint for the heartbeat, not a classification — the authoritative
    /// answer is the server's, against advisory data.
    ///
    /// It is the backend's question because **the two families keep the answer in
    /// different places**. apt puts it on the update: the candidate comes from a
    /// pocket whose archive ends in `-security`, which is already on
    /// [`AvailableUpdate::repo`]. dnf has no security pocket at all — a fix and a
    /// rebuild are published to the same `baseos` — and keeps it in a separate
    /// `updateinfo` database that has to be asked. A caller filtering on the
    /// pocket gets the right answer on Debian and **zero on every RHEL host in
    /// the fleet**, which is the shape of wrongness this product exists to
    /// prevent.
    ///
    /// Takes the updates rather than collecting them again, because on both
    /// families the answer is already in them: apt puts the pocket on
    /// [`AvailableUpdate::repo`] and dnf fills
    /// [`AvailableUpdate::advisories`] from `updateinfo` during
    /// [`PackageBackend::pending_changes`]. Collecting again would re-run
    /// `apt-get -s dist-upgrade`, which is most of the cost of a pass.
    async fn security_updates(&self, updates: &[AvailableUpdate]) -> Result<BTreeSet<String>>;

    async fn apply(&self, plan: &ApplyPlan, log: &dyn LogSink) -> Result<ApplyOutcome>;
}

/// Pick the backend for the host we are running on.
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
