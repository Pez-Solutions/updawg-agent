//! Job executors and health checks.
//!
//! One mutating job runs at a time. Concurrency here means a corrupted package
//! database, so the scheduler serialises them and the executor assumes it.
//!
//! Scope note: DAWG-19 defines the surface. DAWG-70 onwards implement the
//! individual executors.

pub mod health;

use async_trait::async_trait;
use updawg_protocol::{Job, JobKind, JobOutcome};

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
    async fn execute(&self, job: &Job) -> Result<JobOutcome>;
}
