//! Durable local state under `/var/lib/updawg`.
//!
//! Holds the enrollment identity, the pinned organization key, seen job ids for
//! replay protection, and enough context to report the result of a job that
//! required a reboot once the host comes back.
//!
//! Scope note: DAWG-19 defines the surface, DAWG-29 implements it, DAWG-39 adds
//! replay protection.

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("state directory `{0}` is not writable")]
    NotWritable(PathBuf),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StateError>;

#[derive(Debug, Clone)]
pub struct LocalState {
    root: PathBuf,
}

impl LocalState {
    #[must_use]
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn is_enrolled(&self) -> bool {
        self.root.join("identity.json").exists()
    }
}
