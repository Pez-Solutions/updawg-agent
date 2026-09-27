//! The Updawg agent daemon.
//!
//! Runs as root, because installing packages requires it, with systemd
//! hardening that stops short of breaking package management. It makes only
//! outbound connections and executes only the closed set of signed job kinds
//! defined in `updawg-protocol`.
//!
//! Scope note: DAWG-29 brings the scheduler, configuration and local state,
//! DAWG-30 enrollment, DAWG-31 the authenticated transport and certificate
//! renewal, DAWG-32 the check-in loop and DAWG-33 the fact collectors. Jobs
//! that arrive are reported and not run, because verifying and executing one
//! is DAWG-38; the daemon says so rather than dropping them quietly.

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use updawg_agent_core::{
    CONFIG_PATH, STATE_DIR, VERSION,
    checkin::GatewayCheckIn,
    config::AgentConfig,
    inventory::GatewayInventory,
    jobs::{Executor, Reporter},
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

    #[command(flatten)]
    extra_root: extra_root::ExtraRoot,
}

/// The `--insecure-extra-root` flag, which exists only in a build that asked
/// for it.
///
/// Two definitions of one struct, chosen by feature. The disabled one has no
/// fields, so clap has never heard of the flag and `--insecure-extra-root
/// ca.pem` comes back as "unexpected argument". That is what DAWG-206 asked
/// for: not a flag that refuses, a flag that is not there.
///
/// Flattening it means the rest of this binary calls `load()` once and carries
/// no `#[cfg]` anywhere.
mod extra_root {
    #[cfg(feature = "insecure-extra-root")]
    #[derive(Debug, clap::Args)]
    pub(super) struct ExtraRoot {
        /// PEM certificate authority to trust in addition to the system store.
        ///
        /// For running against a gateway you started yourself. Deliberately
        /// accepts no environment variable: every other option here does, and
        /// this is the one that should not be settable by something inherited.
        #[arg(long = "insecure-extra-root", value_name = "PEM")]
        path: Option<std::path::PathBuf>,
    }

    #[cfg(not(feature = "insecure-extra-root"))]
    #[derive(Debug, clap::Args)]
    pub(super) struct ExtraRoot {}

    impl ExtraRoot {
        /// The PEM to trust, if this build can be told to trust one and was.
        ///
        /// Returns `Ok(None)` in a release build without looking at anything,
        /// because there is nothing to look at.
        #[cfg(feature = "insecure-extra-root")]
        pub(super) fn load(&self) -> anyhow::Result<Option<Vec<u8>>> {
            use anyhow::Context as _;
            let Some(path) = &self.path else {
                return Ok(None);
            };
            let pem = updawg_agent_core::insecure::load_root(path)
                .with_context(|| format!("reading {}", path.display()))?;
            tracing::warn!(root = %path.display(), "trusting an extra certificate authority");
            for line in updawg_agent_core::insecure::WARNING.lines() {
                tracing::warn!("{line}");
            }
            Ok(Some(pem))
        }

        #[cfg(not(feature = "insecure-extra-root"))]
        #[expect(
            clippy::unnecessary_wraps,
            clippy::unused_self,
            reason = "same signature as the build that can be told to trust one"
        )]
        pub(super) fn load(&self) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(None)
        }
    }
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

    // Loaded before anything talks to the gateway, so the warning is in the
    // log above the first request rather than somewhere in the middle of it.
    let extra_root = cli.extra_root.load()?;

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

    // A job that rebooted the machine is finished by
    // `Executor::resume_after_reboot`, started in `build_checkin` once there is
    // a transport to report through (DAWG-103). ⚠️ Nothing before that may
    // read the pending-reboot record: reading it takes it, and a report taken
    // and not sent leaves the job running on the server for ever.

    report_identity(&state).context("reading identity")?;
    report_host(&Root::default());

    // Renewal on the way up catches the host that was powered off through its
    // whole renewal window, which is the common way a certificate is allowed to
    // expire. Renewing on a cadence while the daemon is up attaches to the
    // check-in loop in DAWG-32; it belongs there because that loop is what
    // already knows whether the gateway is reachable.
    if state.is_enrolled() {
        renew_certificate(&config, &state, extra_root.as_deref()).await;
    }

    let placeholder = Arc::new(NotWiredUp);
    // Not fatal when there is no identity. An agent that schedules and says
    // what it needs is more useful than one that exits: the operator may be
    // about to run `updawgctl enroll`, and a dead unit is harder to notice
    // than a running one complaining.
    // Inventory first: the job executor uploads a fresh one after every job,
    // so the server sees what changed without waiting six hours.
    let real_inventory = build_inventory(&config, &state, extra_root.as_deref());
    let checkin: Arc<dyn CheckIn> = build_checkin(
        &config,
        &state,
        extra_root.as_deref(),
        real_inventory.clone(),
    )
    .unwrap_or_else(|| {
        tracing::warn!("not checking in: this host has no usable identity");
        placeholder.clone()
    });

    let inventory: Arc<dyn Inventory> = real_inventory.unwrap_or_else(|| {
        tracing::warn!("not collecting inventory: this host has no usable identity or backend");
        placeholder.clone()
    });

    let scheduler = Scheduler::new(config, checkin, inventory);

    scheduler.run(shutdown_signal()).await;

    tracing::info!("stopped");
    Ok(())
}

/// The one place a transport is built, so an extra root cannot reach two of the
/// three callers and miss the third.
///
/// It was three copies of `MtlsTransport::new` before DAWG-206, which is fine
/// until they need to agree about something.
fn transport(
    config: &AgentConfig,
    state: &LocalState,
    extra_root: Option<&[u8]>,
) -> Result<MtlsTransport, updawg_agent_core::transport::TransportError> {
    MtlsTransport::with_extra_root(
        &config.server,
        state.clone(),
        extra_root.map(<[u8]>::to_vec),
    )
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

/// Build the real check-in loop, if this host can talk to the gateway at all.
fn build_checkin(
    config: &AgentConfig,
    state: &LocalState,
    extra_root: Option<&[u8]>,
    inventory: Option<Arc<dyn Inventory>>,
) -> Option<Arc<dyn CheckIn>> {
    if !state.is_enrolled() {
        return None;
    }
    let transport = match transport(config, state, extra_root) {
        Ok(t) => Arc::new(t),
        Err(error) => {
            tracing::error!(%error, "cannot build the gateway transport");
            return None;
        }
    };
    let collector = match SystemState::new(Root::default()) {
        Ok(c) => c,
        Err(error) => {
            tracing::error!(%error, "cannot prepare the state collector");
            return None;
        }
    };

    // `None` on a host with no package manager the agent knows: jobs are then
    // refused with that reason, rather than failing halfway.
    let backend: Option<Arc<dyn updawg_backends::PackageBackend>> =
        updawg_backends::detect().ok().map(Arc::from);
    // Verified, permission-checked and run (DAWG-38, DAWG-102). Observe mode
    // refuses every job that changes the host, and says so to the server.
    let jobs = Arc::new(Executor::new(
        Arc::clone(&transport) as Arc<dyn Reporter>,
        state.clone(),
        config.clone(),
        backend,
        inventory,
    ));
    // A job that rebooted this host is finished from here (DAWG-103): the
    // health checks run again and the report goes out. In the background, so
    // a slow check does not hold up the first check-in.
    tokio::spawn({
        let jobs = Arc::clone(&jobs);
        async move { jobs.resume_after_reboot().await }
    });

    Some(Arc::new(GatewayCheckIn::new(
        transport,
        state.clone(),
        collector,
        jobs,
        // What this file permits, reported on every check-in so the server can
        // narrow against it rather than guess (DAWG-223).
        config.local_policy(),
    )))
}

/// Wire up inventory collection and upload, if this host can do it (DAWG-36).
///
/// `None` rather than a stub on failure, and the caller logs why. A host with no
/// recognised package manager is a real thing — it still enrolls, heartbeats and
/// reports its release — and it should say so rather than uploading an empty
/// package list, which the server would take as "this host has nothing
/// installed".
fn build_inventory(
    config: &AgentConfig,
    state: &LocalState,
    extra_root: Option<&[u8]>,
) -> Option<Arc<dyn Inventory>> {
    if !state.is_enrolled() {
        return None;
    }
    let transport = match transport(config, state, extra_root) {
        Ok(t) => Arc::new(t),
        Err(error) => {
            tracing::error!(%error, "cannot build the gateway transport for inventory");
            return None;
        }
    };
    let backend = match updawg_backends::detect() {
        Ok(b) => Arc::from(b),
        Err(error) => {
            tracing::warn!(%error, "no package backend on this host; not collecting inventory");
            return None;
        }
    };
    let facts = Arc::new(PlatformFacts::new(Root::default()));

    Some(Arc::new(GatewayInventory::new(
        transport,
        state.clone(),
        backend,
        facts,
    )))
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
async fn renew_certificate(config: &AgentConfig, state: &LocalState, extra_root: Option<&[u8]>) {
    let transport = match transport(config, state, extra_root) {
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
        tracing::debug!("check-in skipped: this host is not enrolled");
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
