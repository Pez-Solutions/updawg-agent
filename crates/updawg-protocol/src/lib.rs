//! Wire types for the Updawg agent API.
//!
//! This crate is the single source of truth for the contract between the agent
//! and the gateway. It lives in the agent repository on purpose: the agent is
//! the thing customers audit, and the format it speaks should be defined where
//! they can read it. `updawg-server` consumes this crate from crates.io rather
//! than redefining these types, so the two sides cannot drift.
//!
//! Scope note: this is the v0 skeleton created by DAWG-19. DAWG-21 fills in the
//! full request and response bodies and publishes 0.1.0 to crates.io.

#![doc(html_root_url = "https://docs.rs/updawg-protocol/0.1.0")]

pub mod ids;
pub mod inventory;
pub mod job;

pub use ids::{HostId, JobId, OrgId};
pub use inventory::{AvailableUpdate, Ecosystem, InstalledPackage, Repository, SystemFacts};
pub use job::{Job, JobKind, JobOutcome, JobStatus};

/// The agent API version this crate speaks. Sent as a header on every request
/// so the gateway can reject an agent that is too old to trust.
pub const API_VERSION: &str = "v1";

/// Maximum wall time the gateway holds a check-in open before replying empty.
pub const CHECKIN_LONG_POLL_SECONDS: u64 = 55;
