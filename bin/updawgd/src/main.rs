//! The Updawg agent daemon.
//!
//! Runs as root, because installing packages requires it, with systemd
//! hardening that stops short of breaking package management. It makes only
//! outbound connections and executes only the closed set of signed job kinds
//! defined in `updawg-protocol`.
//!
//! Scope note: DAWG-19 produces a daemon that starts, reads its configuration,
//! reports what it is permitted to do and shuts down cleanly. The check-in loop
//! arrives in DAWG-32.

use anyhow::{Context, Result};
use clap::Parser;
use updawg_agent_core::{CONFIG_PATH, STATE_DIR, VERSION, config::AgentConfig};
use updawg_protocol::JobKind;

#[derive(Debug, Parser)]
#[command(
    name = "updawgd",
    version = VERSION,
    about = "The Updawg agent daemon",
    long_about = "Reports installed packages and pending updates to Updawg, and executes \
                  signed jobs permitted by /etc/updawg/agent.toml. Makes outbound \
                  connections only."
)]
struct Cli {
    /// Path to the agent configuration file.
    #[arg(long, default_value = CONFIG_PATH, env = "UPDAWG_CONFIG")]
    config: String,

    /// Directory holding durable local state.
    #[arg(long, default_value = STATE_DIR, env = "UPDAWG_STATE_DIR")]
    state_dir: String,

    /// Parse the configuration, report what it permits, and exit.
    #[arg(long)]
    check_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("UPDAWG_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!(version = VERSION, "updawgd starting");

    let raw =
        std::fs::read_to_string(&cli.config).with_context(|| format!("reading {}", cli.config))?;
    // A malformed config fails startup rather than falling back to a default
    // that might permit more than the operator intended.
    let config = AgentConfig::from_toml(&raw).with_context(|| format!("parsing {}", cli.config))?;

    tracing::info!(
        server = %config.server,
        mode = ?config.mode,
        state_dir = %cli.state_dir,
        "configuration loaded"
    );

    for kind in [
        JobKind::RefreshInventory,
        JobKind::ApplyUpdates,
        JobKind::Reboot,
        JobKind::Snapshot,
        JobKind::DistUpgrade,
    ] {
        tracing::info!(
            ?kind,
            permitted = config.admits(kind, None),
            "local permission"
        );
    }

    if cli.check_config {
        tracing::info!("configuration is valid");
        return Ok(());
    }

    tracing::warn!("check-in loop is not implemented yet (DAWG-32); idling until shutdown");

    tokio::signal::ctrl_c()
        .await
        .context("waiting for shutdown signal")?;
    tracing::info!("shutting down");
    Ok(())
}
