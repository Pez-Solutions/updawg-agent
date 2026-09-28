//! Filesystem snapshot providers (DAWG-115).
//!
//! Being able to undo is what lets a customer agree to automatic patching.
//! Where the filesystem supports it, the executor takes a snapshot before it
//! changes anything, and a `rollback` job puts the host back.
//!
//! Adding a provider means implementing [`SnapshotProvider`] and a row in
//! [`detect`]; nothing else in the agent changes. Snapper (btrfs, DAWG-116),
//! ZFS (DAWG-117) and LVM thin (DAWG-118) are built.
//!
//! # A kernel the rollback would take away
//!
//! A snapshot is of `/`. Where `/boot` is a filesystem of its own — Fedora's
//! and RHEL's default, a ZFS `bpool` — a rollback that removes a kernel
//! installed since leaves that kernel in `/boot`, its boot entry pointing at
//! it, and its modules gone: the next boot can come up with none.
//! [`SnapshotProvider::kernels_rolled_away`] says which, and the executor
//! refuses such a rollback before changing anything.
//!
//! # What a rollback restores, and what it does not
//!
//! A snapshot is of a filesystem, not of a package change. Rolling back puts
//! **everything** on that filesystem back as it was: the packages and the
//! package database, and also configuration somebody edited since and logs
//! written since, if they live on it. That is the honest meaning of the word,
//! and the portal says so before anybody confirms one (DAWG-120). The agent's
//! own state is the exception: it is carried across by the executor, because
//! forgetting which jobs have run would let one run twice.
//!
//! # Only our own
//!
//! A provider lists, restores and prunes only the snapshots the agent took.
//! An administrator's snapshots, or the distribution's own pre/post pairs,
//! are theirs: the server cannot name one to roll back to, and pruning never
//! counts or deletes them.

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
    /// The prefix of this provider's snapshot ids, e.g. `snapper` in
    /// `snapper:412`.
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
    /// Provider-qualified, e.g. `snapper:412:job_…`. What goes into
    /// `JobComplete::snapshot_id` and comes back in a `rollback` job.
    pub id: String,
    pub description: String,
    /// The job it was taken for.
    pub job: String,
    /// As the provider prints it. Informational only: ordering is by id.
    pub created: String,
}

/// What a rollback put back, in the provider's terms.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Restored {
    pub created: u64,
    pub modified: u64,
    pub deleted: u64,
    /// Nothing has changed yet: it happens at the next boot (LVM), and there
    /// are no counts to give.
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
    /// Bytes free where a snapshot would live (DAWG-121). A snapshot pins
    /// the files an install replaces, so the install needs room for both.
    async fn free_bytes(&self) -> Result<u64>;
    /// Take one, marked as the agent's and as taken for `job`.
    async fn create(&self, description: &str, job: &str) -> Result<Snapshot>;
    /// The agent's own, oldest first.
    async fn list(&self) -> Result<Vec<Snapshot>>;
    /// Put the filesystem back as it was when `id` was taken.
    async fn rollback(&self, id: &str) -> Result<Restored>;
    /// Delete the agent's own beyond the newest `keep`, and say which went.
    /// Unbounded snapshots fill disks, which is its own outage.
    async fn prune(&self, keep: usize) -> Result<Vec<String>>;
    /// Kernels installed since snapshot `id` — their module directories, e.g.
    /// `6.8.0-2` — which rolling back to it would take away.
    async fn kernels_rolled_away(&self, id: &str) -> Result<Vec<String>>;
    /// Whether a rollback takes effect only at the next boot, as an LVM merge
    /// into a mounted root does.
    fn restores_at_next_boot(&self) -> bool {
        false
    }
    /// For a provider whose rollback happens at the next boot: make `dir` in
    /// snapshot `id` exactly what it is now, so the agent's own state is not
    /// rolled back with everything else. Nothing to do for the others, whose
    /// rollback happens while the agent watches and puts it back itself.
    async fn carry_into(&self, _id: &str, _dir: &std::path::Path) -> Result<()> {
        Ok(())
    }
}

/// The kernel whose module directory `path` is — `lib/modules/<kernel>` or
/// `usr/lib/modules/<kernel>`, relative to the root and nothing deeper.
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
/// `Auto` tries each built provider in turn and settles on the first that is
/// usable; `None` is a choice, not a failure, and says so. A provider named
/// explicitly and not usable is reported as such rather than silently
/// replaced by another: whoever wrote `agent.toml` asked for that one.
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
