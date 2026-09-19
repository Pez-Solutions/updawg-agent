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
//! Scope note: DAWG-19 defines the trait. DAWG-34 implements apt and DAWG-35
//! implements dnf.

pub mod apt;
pub mod dnf;

use async_trait::async_trait;
use updawg_protocol::{AvailableUpdate, Ecosystem, InstalledPackage, Repository};

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
    async fn available_updates(&self) -> Result<Vec<AvailableUpdate>>;
    async fn repositories(&self) -> Result<Vec<Repository>>;
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
