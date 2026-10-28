//! System fact collectors.
//!
//! Everything here is read-only and cheap. The full list of what is collected
//! lives in `updawg_protocol::inventory`, and nothing outside it is gathered:
//! no file contents, environment variables, process arguments, user data or
//! credentials.
//!
//! # Scope
//!
//! This crate collects facts about the machine. Questions for the package
//! manager (installed packages, available updates, repositories, held
//! packages) belong to `updawg-backends` and its [`PackageBackend`] trait.
//! Held packages look like host state, but "held" means `apt-mark showhold`
//! on one family and `dnf versionlock` on another, so that knowledge stays in
//! one crate.
//!
//! [`PackageBackend`]: https://docs.rs/updawg-backends
//!
//! # Missing sources
//!
//! A collector whose source is missing degrades instead of failing the whole
//! run; a host without `systemd-detect-virt` is not a broken host. Where not
//! knowing matters, the type says so: [`state::RebootRequired`] has an
//! `Unknown` variant so an unreadable answer is not reported as "no reboot
//! needed". [`enrollment`] holds the smaller set of facts needed before the
//! host has an identity.

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
