//! Filesystem snapshot providers.
//!
//! Where the filesystem supports it, the executor takes a snapshot before
//! changing anything, and a `rollback` job restores it. A new provider needs
//! a [`SnapshotProvider`] implementation and a case in [`detect`]. Snapper
//! (btrfs), ZFS and LVM thin are implemented.
//!
//! # Kernels and a separate `/boot`
//!
//! Snapshots cover `/`. If `/boot` is a separate filesystem (the Fedora and
//! RHEL default, or a ZFS `bpool`), rolling back past a kernel install leaves
//! that kernel and its boot entry in `/boot` but removes its modules, and the
//! host may not boot. [`SnapshotProvider::kernels_rolled_away`] reports those
//! kernels and the executor refuses the rollback.
//!
//! # Scope of a rollback
//!
//! A rollback restores the whole filesystem, not just the packages: config
//! edits and logs written since are reverted too if they live on it. The
//! agent's own state directory is carried across by the executor so no job
//! runs twice.
//!
//! # Ownership
//!
//! Providers only list, restore and prune snapshots the agent took. Snapshots
//! made by an administrator or by the distribution (snapper pre/post pairs)
//! can't be rolled back to and are never pruned.

pub mod lvm;
pub mod snapper;
pub mod zfs;

use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("no snapshot provider is available on this host: {0}")]
    Unavailable(String),
    #[error("not enough free space to take a snapshot: {detail}")]
    InsufficientSpace { detail: String },
    /// Absent, or not one the agent took, which for a rollback is the same.
    #[error("snapshot `{id}` not found among the ones this agent took")]
    NotFound { id: String },
    /// An id for a different provider, or not an id at all.
    #[error("`{id}` is not a {provider} snapshot id")]
    ForeignId { id: String, provider: &'static str },
    #[error("`{tool}` exited with status {status}: {stderr}")]
    CommandFailed {
        tool: &'static str,
        status: i32,
        stderr: String,
    },
    #[error("could not parse output of `{tool}`: {detail}")]
    Unparseable { tool: &'static str, detail: String },
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

impl Provider {
    /// The prefix of this provider's snapshot ids (`snapper` in
    /// `snapper:412`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Snapper => "snapper",
            Self::Zfs => "zfs",
            Self::Lvm => "lvm",
            Self::None => "none",
        }
    }
}

/// One snapshot the agent took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Provider-qualified, like `snapper:412:job_abc`. Sent as
    /// `JobComplete::snapshot_id` and returned in a `rollback` job.
    pub id: String,
    pub description: String,
    pub job: String,
    /// As the provider prints it. Display only; ordering is by id.
    pub created: String,
}

/// What a rollback put back, in the provider's terms.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Restored {
    pub created: u64,
    pub modified: u64,
    pub deleted: u64,
    /// The restore happens at the next boot (LVM), so there are no counts.
    pub at_next_boot: bool,
}

impl std::fmt::Display for Restored {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.at_next_boot {
            return f.write_str("restored at the next boot; nothing has changed until then");
        }
        write!(
            f,
            "{} file(s) put back, {} restored to their earlier contents, {} removed",
            self.created, self.modified, self.deleted
        )
    }
}

#[async_trait]
pub trait SnapshotProvider: Send + Sync {
    fn provider(&self) -> Provider;
    /// Whether this provider can take a snapshot on this host now, and if
    /// not, why not.
    async fn available(&self) -> std::result::Result<(), String>;
    /// Bytes free where a snapshot would live. A snapshot pins the files an
    /// install replaces, so the install needs room for both.
    async fn free_bytes(&self) -> Result<u64>;
    /// Takes a snapshot, marked as the agent's and tagged with `job`.
    async fn create(&self, description: &str, job: &str) -> Result<Snapshot>;
    /// The agent's snapshots, oldest first.
    async fn list(&self) -> Result<Vec<Snapshot>>;
    async fn rollback(&self, id: &str) -> Result<Restored>;
    /// Deletes all but the newest `keep` of the agent's snapshots and returns
    /// the ids removed.
    async fn prune(&self, keep: usize) -> Result<Vec<String>>;
    /// Kernels installed since snapshot `id` (module directory names such as
    /// `6.8.0-2`), which rolling back would remove.
    async fn kernels_rolled_away(&self, id: &str) -> Result<Vec<String>>;
    /// Whether a rollback takes effect only at the next boot, as an LVM merge
    /// into a mounted root does.
    fn restores_at_next_boot(&self) -> bool {
        false
    }
    /// For providers that restore at the next boot: copy the current `dir`
    /// into snapshot `id` so the agent's state survives the rollback. Other
    /// providers roll back while the agent is running, and the executor
    /// restores the state itself.
    async fn carry_into(&self, _id: &str, _dir: &std::path::Path) -> Result<()> {
        Ok(())
    }
}

/// The kernel name if `path` is exactly `lib/modules/<kernel>` or
/// `usr/lib/modules/<kernel>` (relative to the root).
#[must_use]
pub fn kernel_dir(path: &str) -> Option<String> {
    let path = path.trim_start_matches('/');
    let rest = path
        .strip_prefix("usr/lib/modules/")
        .or_else(|| path.strip_prefix("lib/modules/"))?;
    let kernel = rest.trim_end_matches('/');
    (!kernel.is_empty() && !kernel.contains('/')).then(|| kernel.to_owned())
}

/// The provider `wanted` names on this host, or why there is none.
///
/// `Auto` picks the first usable provider. An explicitly configured provider
/// that isn't usable is an error; we don't fall back to another one.
pub async fn detect(wanted: Provider) -> std::result::Result<Box<dyn SnapshotProvider>, String> {
    match wanted {
        Provider::None => Err("agent.toml sets `[snapshots] provider = \"none\"`".into()),
        Provider::Snapper => {
            let snapper = snapper::Snapper::root();
            snapper.available().await?;
            Ok(Box::new(snapper))
        }
        Provider::Zfs => {
            let zfs = zfs::Zfs::root().await?;
            zfs.available().await?;
            Ok(Box::new(zfs))
        }
        Provider::Lvm => {
            let lvm = lvm::Lvm::root().await?;
            lvm.available().await?;
            Ok(Box::new(lvm))
        }
        Provider::Auto => {
            let snapper = snapper::Snapper::root();
            let snapper_why = match snapper.available().await {
                Ok(()) => return Ok(Box::new(snapper)),
                Err(why) => why,
            };
            let zfs_why = match zfs::Zfs::root().await {
                Ok(zfs) => match zfs.available().await {
                    Ok(()) => return Ok(Box::new(zfs)),
                    Err(why) => why,
                },
                Err(why) => why,
            };
            let lvm_why = match lvm::Lvm::root().await {
                Ok(lvm) => match lvm.available().await {
                    Ok(()) => return Ok(Box::new(lvm)),
                    Err(why) => why,
                },
                Err(why) => why,
            };
            Err(format!(
                "none detected (snapper: {snapper_why}; zfs: {zfs_why}; lvm: {lvm_why})"
            ))
        }
    }
}
