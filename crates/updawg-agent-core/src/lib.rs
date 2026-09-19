//! Scheduler, transport and local state: the spine the rest of the agent hangs off.
//!
//! Scope note: DAWG-19 creates this skeleton. DAWG-29 implements the scheduler
//! and local state, DAWG-30 enrollment, DAWG-31 the mTLS transport and DAWG-32
//! the check-in loop.

pub mod checkin;
pub mod config;
pub mod duration;
pub mod enroll;
pub mod logging;
pub mod scheduler;
pub mod state;

#[cfg(test)]
mod testing;
pub mod transport;

/// The agent version, taken from the crate version at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default location of the agent configuration file.
pub const CONFIG_PATH: &str = "/etc/updawg/agent.toml";

/// Default location of durable local state.
pub const STATE_DIR: &str = "/var/lib/updawg";
