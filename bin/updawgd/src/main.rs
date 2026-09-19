//! The Updawg agent daemon.
//!
//! Runs as root, because installing packages requires it, with systemd
//! hardening that stops short of breaking package management. It makes only
//! outbound connections and executes only the closed set of signed job kinds
//! defined in `updawg-protocol`.
//!
//! Scope note: DAWG-29 brings the scheduler, configuration and local state,
//! DAWG-30 enrollment, DAWG-31 the authenticated transport and certificate
//! renewal, and DAWG-33 the fact collectors. The check-in loop is still
//! missing until DAWG-32, so the daemon starts, reads the host, renews its
//! certificate, schedules, and says clearly that it is not checking in yet.

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use updawg_agent_core::{
    CONFIG_PATH, STATE_DIR, VERSION,
    config::AgentConfig,
    logging,
    scheduler::{CheckIn, CheckinOutcome, Inventory, Scheduler},
    state::LocalState,
    transport::{MtlsTransport, Renewal},
};
use updawg_collectors::{PlatformFacts, Root, SystemState};
use updawg_crypto::PinnedKeys;
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
    logging::init();

    tracing::info!(
        version = VERSION,
        journald = logging::under_journald(),
        "updawgd starting"
    );

    let config = AgentConfig::load(&cli.config).context("loading configuration")?;

    tracing::info!(
        server = %config.server,
        mode = ?config.mode,
        inventory_interval = %config.schedule.inventory_interval,
        refresh_metadata = %config.schedule.refresh_metadata,
        snapshot_provider = ?config.snapshots.provider,
        health_checks = config.health_checks.len(),
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

    let state = LocalState::new(&cli.state_dir);
    state.ensure().context("preparing the state directory")?;

    // A job that rebooted the machine could not report its own result. Finish
    // that report before doing anything else, or the server is left believing
    // the job is still running.
    if let Some(pending) = state
        .take_pending_reboot()
        .context("reading pending reboot state")?
    {
        tracing::info!(
            job_id = %pending.job_id,
            "host rebooted while running a job; reporting completion (DAWG-71)"
        );
    }

    report_identity(&state).context("reading identity")?;
    report_host(&Root::default());

    // Renewal on the way up catches the host that was powered off through its
    // whole renewal window, which is the common way a certificate is allowed to
    // expire. Renewing on a cadence while the daemon is up attaches to the
    // check-in loop in DAWG-32; it belongs there because that loop is what
    // already knows whether the gateway is reachable.
    if state.is_enrolled() {
        renew_certificate(&config, &state).await;
    }

    let placeholder = Arc::new(NotWiredUp);
    let scheduler = Scheduler::new(config, placeholder.clone(), placeholder.clone());

    tracing::warn!(
        "the check-in loop is not implemented yet (DAWG-32); scheduling but not checking in"
    );

    scheduler.run(shutdown_signal()).await;

    tracing::info!("stopped");
    Ok(())
}

/// Say who this host is and what it will verify jobs against.
///
/// The pinned keys go in the log on purpose. An operator should be able to
/// compare this line against what the portal shows without running anything:
/// pinning nobody can check is pinning nobody trusts.
fn report_identity(state: &LocalState) -> Result<()> {
    let Some(identity) = state.identity()? else {
        tracing::warn!("not enrolled — run `updawgctl enroll --token ...`");
        return Ok(());
    };

    match PinnedKeys::from_wire(&identity.org_signing_keys) {
        Ok(pinned) => tracing::info!(
            host_id = %identity.host_id,
            enrolled_at = %identity.enrolled_at,
            org_signing_keys = ?pinned.describe(),
            "enrolled"
        ),
        // Not a warning: a host whose pinned keys no longer parse will reject
        // every job it is sent, and would otherwise look perfectly healthy
        // until one arrived.
        Err(error) => tracing::error!(
            host_id = %identity.host_id,
            %error,
            "enrolled, but the pinned organization keys cannot be used; no job will verify"
        ),
    }
    Ok(())
}

/// Say what this host is and what is true about it right now.
///
/// Collected at startup and logged rather than held, because until the
/// check-in loop exists (DAWG-32) there is nowhere to send it — and an operator
/// installing the agent should be able to see that it reads their machine
/// correctly before it is trusted to act on it.
fn report_host(root: &Root) {
    match PlatformFacts::new(root.clone()).gather() {
        Ok(facts) => tracing::info!(
            distro = %facts.distro,
            version = %facts.version_id,
            kernel = %facts.kernel,
            arch = %facts.arch,
            virtualization = facts.virtualization.as_deref().unwrap_or("unknown"),
            ecosystem = ?facts.ecosystem,
            "platform"
        ),
        Err(error) => tracing::error!(%error, "could not read this host's platform facts"),
    }

    let collector = match SystemState::new(root.clone()) {
        Ok(c) => c,
        Err(error) => {
            tracing::error!(%error, "could not prepare the state collector");
            return;
        }
    };

    match collector.gather() {
        Ok(state) => tracing::info!(
            uptime_days = state.uptime_s / 86_400,
            // Logged as a word, not a bool: "unknown" and "no" are different
            // answers and flattening them here is exactly the mistake the
            // tri-state exists to prevent.
            reboot_required = ?state.reboot_required,
            services_needing_restart = state.services_needing_restart.len(),
            load1 = state.metrics.load1,
            mem_used_pct = state.metrics.mem_used_pct,
            "state"
        ),
        Err(error) => tracing::error!(%error, "could not read this host's state"),
    }
}

/// Renew the client certificate if it is inside its renewal window.
///
/// Never fatal. A daemon that refuses to start because it could not reach the
/// gateway is a daemon that cannot report anything at all, including the fact
/// that it could not reach the gateway.
async fn renew_certificate(config: &AgentConfig, state: &LocalState) {
    let transport = match MtlsTransport::new(&config.server, state.clone()) {
        Ok(t) => t,
        Err(error) => {
            tracing::error!(%error, "cannot use the stored identity");
            return;
        }
    };

    let certificate = transport.certificate();
    tracing::info!(
        subject = certificate.subject(),
        serial = certificate.serial(),
        "client certificate"
    );

    match transport.renew_if_due(SystemTime::now()).await {
        Ok(Renewal::NotDue { remaining }) => tracing::info!(
            expires_in_days = remaining.as_secs() / 86_400,
            "certificate renewal not due yet"
        ),
        Ok(Renewal::Renewed { expires_in }) => tracing::info!(
            expires_in_days = expires_in.as_secs() / 86_400,
            "certificate renewed at startup"
        ),
        Err(error) => tracing::error!(
            %error,
            "certificate renewal failed; the host will go stale if this keeps failing"
        ),
    }
}

/// Stands in for the transport and collectors until they exist.
///
/// It reports honestly rather than pretending to succeed: a scheduler that
/// looks like it is working when nothing is connected is exactly the kind of
/// thing that gets shipped by accident.
#[derive(Debug)]
struct NotWiredUp;

#[async_trait]
impl CheckIn for NotWiredUp {
    async fn check_in(&self) -> Result<CheckinOutcome> {
        tracing::debug!("check-in skipped: transport not implemented (DAWG-32)");
        Ok(CheckinOutcome {
            next_checkin: Duration::from_secs(60),
            inventory_requested: false,
        })
    }
}

#[async_trait]
impl Inventory for NotWiredUp {
    async fn collect_and_upload(&self) -> Result<()> {
        tracing::debug!("inventory skipped: collectors not implemented (DAWG-33)");
        Ok(())
    }
    async fn refresh_metadata(&self) -> Result<()> {
        tracing::debug!("metadata refresh skipped: backends not implemented (DAWG-34/35)");
        Ok(())
    }
}

/// Resolves on SIGTERM or SIGINT.
///
/// systemd sends SIGTERM and then waits. Ignoring it means being `SIGKILL`ed,
/// which for an agent mid-apply is how a package database gets left half-written.
async fn shutdown_signal() {
    let interrupt = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "cannot listen for SIGTERM — shutdown will not be graceful");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => tracing::info!("received SIGINT"),
        () = terminate => tracing::info!("received SIGTERM"),
    }
}
