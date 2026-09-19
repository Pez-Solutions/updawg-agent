//! System fact collectors.
//!
//! Everything here is read-only and cheap. The exhaustive list of what is
//! collected lives in `updawg_protocol::inventory`; anything not represented
//! there must not be gathered. No file contents, no environment variables, no
//! process arguments, no user data, no credentials.
//!
//! # Where the line is
//!
//! This crate collects facts about the *machine*. Anything that is a question
//! about the *package manager* — installed packages, available updates,
//! configured repositories, held packages — belongs to `updawg-backends`,
//! whose [`PackageBackend`] trait already declares it. Held packages in
//! particular look like host state but are not: "held" means `apt-mark
//! showhold` on one family and `dnf versionlock` on another, and splitting that
//! knowledge across two crates would mean maintaining it twice.
//!
//! [`PackageBackend`]: https://docs.rs/updawg-backends
//!
//! # Degrading
//!
//! A collector whose source is missing degrades rather than failing the whole
//! run: a host without `systemd-detect-virt` is not a broken host. The
//! exception is where not knowing is itself important — see
//! [`state::RebootRequired`], which has an `Unknown` variant precisely so that
//! "I could not tell" never gets flattened into "everything is fine".
//!
//! Scope note: DAWG-19 defines the surface, DAWG-33 implements the collectors.
//! DAWG-30 added [`enrollment`], the smaller set of facts needed before the
//! host has an identity at all.

pub mod enrollment;
pub mod facts;
pub mod platform;
pub mod state;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

use async_trait::async_trait;
use updawg_protocol::SystemFacts;

pub use facts::PlatformFacts;
pub use platform::{OsRelease, Root};
pub use state::{HostState, RebootRequired, SystemState};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CollectorError {
    #[error("required source `{input}` is unavailable on this host")]
    SourceUnavailable { input: &'static str },
    #[error("could not parse `{input}`: {detail}")]
    Unparseable { input: &'static str, detail: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CollectorError>;

#[async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    /// A collector whose source is missing degrades rather than failing the
    /// whole inventory run.
    async fn is_available(&self) -> bool;
}

#[async_trait]
pub trait FactCollector: Collector {
    async fn facts(&self) -> Result<SystemFacts>;
}

#[async_trait]
pub trait StateCollector: Collector {
    async fn state(&self) -> Result<HostState>;
}
