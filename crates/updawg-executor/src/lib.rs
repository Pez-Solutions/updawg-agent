//! Job executors and health checks.
//!
//! Only one mutating job runs at a time, since concurrent package operations
//! can corrupt the package database. The scheduler enforces this and
//! executors rely on it.

pub mod health;

use async_trait::async_trait;
use updawg_protocol::{Job, JobComplete, JobKind};

#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error("job kind {kind:?} is not permitted by local configuration: {reason}")]
    RejectedByHost { kind: JobKind, reason: String },
    #[error("approved version for `{package}` is {approved}, host offers {candidate}")]
    CandidateMoved {
        package: String,
        approved: String,
        candidate: String,
    },
    #[error("job timed out after {seconds}s")]
    TimedOut { seconds: u64 },
    #[error(transparent)]
    Backend(#[from] updawg_backends::BackendError),
    #[error(transparent)]
    Snapshot(#[from] updawg_snapshots::SnapshotError),
}

pub type Result<T> = std::result::Result<T, ExecutorError>;

#[async_trait]
pub trait Executor: Send + Sync {
    fn handles(&self) -> JobKind;
    async fn execute(&self, job: &Job) -> Result<JobComplete>;
}
