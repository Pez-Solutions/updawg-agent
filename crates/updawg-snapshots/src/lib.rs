//! Filesystem snapshot providers.
//!
//! Being able to undo is what lets a customer agree to automatic patching.
//! Where the filesystem supports it, the executor takes a snapshot before it
//! changes anything.
//!
//! Scope note: DAWG-19 defines the trait. DAWG-95 onwards implement snapper,
//! ZFS and LVM thin.

use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("no snapshot provider is available on this host")]
    Unavailable,
    #[error("not enough free space to take a snapshot: {detail}")]
    InsufficientSpace { detail: String },
    #[error("snapshot `{id}` not found")]
    NotFound { id: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SnapshotError>;

/// Which mechanism is in use. `Auto` resolves at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Auto,
    Snapper,
    Zfs,
    Lvm,
    None,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub id: String,
    pub description: String,
}

#[async_trait]
pub trait SnapshotProvider: Send + Sync {
    fn provider(&self) -> Provider;
    async fn is_available(&self) -> bool;
    async fn create(&self, description: &str) -> Result<Snapshot>;
    async fn list(&self) -> Result<Vec<Snapshot>>;
    async fn rollback(&self, id: &str) -> Result<()>;
    /// Unbounded snapshots fill disks, which is its own outage.
    async fn prune(&self, keep: usize) -> Result<()>;
}
