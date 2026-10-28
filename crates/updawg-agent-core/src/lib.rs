//! Scheduler, transport, enrollment and local state for the agent.

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

/// The agent version, identical to the package version.
///
/// `0.1.0-20260930183310.g8c53d52` for a build of main, `0.2.0-1` for a tag.
/// The server compares it with what a channel holds. Set by `build.rs` from
/// `UPDAWG_BUILD`, which the release workflow exports; `-dev` otherwise.
pub const VERSION: &str = env!("UPDAWG_VERSION");

/// Default location of the agent configuration file.
pub const CONFIG_PATH: &str = "/etc/updawg/agent.toml";

/// Default location of durable local state.
pub const STATE_DIR: &str = "/var/lib/updawg";
