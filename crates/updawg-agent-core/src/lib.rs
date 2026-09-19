//! Scheduler, transport and local state: the spine the rest of the agent hangs off.
//!
//! Scope note: DAWG-19 creates this skeleton. DAWG-29 implements the scheduler
//! and local state, DAWG-31 the mTLS transport, DAWG-32 the check-in loop.

pub mod config;
pub mod state;
pub mod transport;

/// The agent version, taken from the crate version at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default location of the agent configuration file.
pub const CONFIG_PATH: &str = "/etc/updawg/agent.toml";

/// Default location of durable local state.
pub const STATE_DIR: &str = "/var/lib/updawg";
