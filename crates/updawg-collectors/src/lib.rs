//! System fact collectors.
//!
//! Everything here is read-only and cheap. The exhaustive list of what is
//! collected lives in `updawg_protocol::inventory`; anything not represented
//! there must not be gathered.
//!
//! Scope note: DAWG-19 defines the surface, DAWG-33 implements the collectors.
//! DAWG-30 adds [`enrollment`], the smaller set of facts needed before the host
//! has an identity at all.

pub mod enrollment;

use async_trait::async_trait;
use updawg_protocol::SystemFacts;

#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    #[error("required source `{input}` is unavailable on this host")]
    SourceUnavailable { input: &'static str },
    #[error("could not parse `{input}`: {detail}")]
    Unparseable { input: &'static str, detail: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CollectorError>;

/// Volatile state reported on every check-in, kept small on purpose.
#[derive(Debug, Clone, Default)]
pub struct HostState {
    pub reboot_required: bool,
    pub services_needing_restart: Vec<String>,
    pub held_packages: Vec<String>,
    pub uptime_seconds: u64,
    pub load1: f32,
    pub mem_used_pct: u8,
    pub root_disk_free_pct: u8,
}

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
