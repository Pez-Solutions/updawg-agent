//! Logging setup.
//!
//! Journald already stamps every line it receives with a timestamp and records
//! the unit it came from. Printing our own timestamp and ANSI colour into that
//! stream gives you `Sep 19 18:04:11 host updawgd[1234]: 2026-09-19T18:04:11Z
//! INFO ...` — the same time, twice, one of them wrapped in escape codes.
//!
//! systemd sets `JOURNAL_STREAM` when it has connected a service's stderr to
//! the journal, so that is the signal to drop both.

use tracing_subscriber::{EnvFilter, fmt::time::SystemTime};

/// Whether this process is writing into the journal.
#[must_use]
pub fn under_journald() -> bool {
    std::env::var_os("JOURNAL_STREAM").is_some()
}

/// Initialise tracing for the agent.
///
/// Honours `UPDAWG_LOG` for filtering. Under systemd it omits timestamps and
/// colour; run by hand it includes both.
pub fn init() {
    let filter = EnvFilter::try_from_env("UPDAWG_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,hyper=warn,rustls=warn"));

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);

    if under_journald() {
        builder.without_time().with_ansi(false).init();
    } else {
        builder.with_timer(SystemTime).init();
    }
}
