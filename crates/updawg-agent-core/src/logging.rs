//! Logging setup.
//!
//! Journald timestamps every line itself, so under systemd we drop our own
//! timestamp and ANSI colour. systemd sets `JOURNAL_STREAM` when a service's
//! stderr is connected to the journal.

use tracing_subscriber::{EnvFilter, fmt::time::SystemTime};

/// Whether this process is writing into the journal.
#[must_use]
pub fn under_journald() -> bool {
    std::env::var_os("JOURNAL_STREAM").is_some()
}

/// Initialises tracing. `UPDAWG_LOG` sets the filter.
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
