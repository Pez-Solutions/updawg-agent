//! Scheduler, transport and local state: the spine the rest of the agent hangs off.
//!
//! Scope note: DAWG-19 creates this skeleton. DAWG-29 implements the scheduler
//! and local state, DAWG-30 enrollment, DAWG-31 the mTLS transport and DAWG-32
//! the check-in loop.

pub mod checkin;
pub mod config;
pub mod duration;
pub mod enroll;
#[cfg(feature = "insecure-extra-root")]
pub mod insecure;
pub mod inventory;
pub mod joblog;
pub mod jobs;
pub mod logging;
pub mod preflight;
pub mod readiness;
pub mod restart;
pub mod scheduler;
pub mod self_update;
pub mod state;

#[cfg(test)]
mod testing;
pub mod transport;

/// The agent version: the build, as its packages name it.
///
/// `0.1.0-20260930183310.g8c53d52` for a build of main, `0.2.0-1` for a tag —
/// the package version exactly, so the server can compare what a host runs
/// with what a channel holds (DAWG-46). Before this every build said `0.1.0`
/// and nothing could tell two apart. Set by `build.rs` from `UPDAWG_BUILD`,
/// which the release workflow exports; `-dev` for any other build.
pub const VERSION: &str = env!("UPDAWG_VERSION");

/// Default location of the agent configuration file.
pub const CONFIG_PATH: &str = "/etc/updawg/agent.toml";

/// Default location of durable local state.
pub const STATE_DIR: &str = "/var/lib/updawg";
