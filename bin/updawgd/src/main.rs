//! The Updawg agent daemon.
//!
//! Runs as root, since installing packages requires it, with as much systemd
//! hardening as package management tolerates. It makes only outbound
//! connections and executes only the closed set of signed job kinds defined in
//! `updawg-protocol`.

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

/// The `--insecure-extra-root` flag, only present in builds with the
/// `insecure-extra-root` feature.
///
/// Without the feature the struct has no fields, so clap rejects the flag as
/// an unexpected argument. Flattening it keeps `#[cfg]` out of the rest of the
/// binary.
mod extra_root {
    #[cfg(feature = "insecure-extra-root")]
    #[derive(Debug, clap::Args)]
    pub(super) struct ExtraRoot {
        /// PEM certificate authority to trust in addition to the system store.
        ///
        /// For running against a gateway you started yourself. Unlike the other
        /// options, this can't be set from the environment.
        #[arg(long = "insecure-extra-root", value_name = "PEM")]
        path: Option<std::path::PathBuf>,
    }

    #[cfg(not(feature = "insecure-extra-root"))]
    #[derive(Debug, clap::Args)]
    pub(super) struct ExtraRoot {}

    impl ExtraRoot {
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

    // load before any gateway traffic so the warning comes first in the log
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
    // a transport. Nothing before that may read the pending-reboot record:
    // reading it consumes it, and if the report isn't sent the job stays
    // "running" on the server.

    report_identity(&config, &state).context("reading identity")?;
    report_host(&Root::default());

    // Renewing at startup covers a host that was powered off through its whole
    // renewal window. While running, the check-in loop checks hourly, and
    // renews within minutes when the gateway asks.
    if state.is_enrolled() {
        renew_certificate(&config, &state, extra_root.as_deref()).await;
    }

    // No identity isn't fatal. The operator may be about to run `updawgctl
    // enroll`, and a running unit that logs what it needs is easier to notice
    // than a dead one.
    let placeholder = Arc::new(NotWiredUp);
    // built first so the job executor can upload a fresh inventory after each
    // job
    let real_inventory = build_inventory(&config, &state, extra_root.as_deref());
    // Detected once. Having none is normal; jobs that require a snapshot are
    // then refused with the reason.
    let snapshots: updawg_agent_core::jobs::Snapshots =
        updawg_snapshots::detect(config.snapshots.provider.provider())
            .await
            .map(Arc::from);
    match &snapshots {
        Ok(p) => tracing::info!(provider = p.provider().name(), "snapshots available"),
        Err(why) => tracing::info!(%why, "no snapshots on this host"),
    }
    let checkin: Arc<dyn CheckIn> = build_checkin(
        &config,
        &state,
        extra_root.as_deref(),
        real_inventory.clone(),
        snapshots,
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

/// Every transport is built here so the extra root applies to all of them.
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

/// Logs the host identity and the pinned keys, so an operator can compare
/// them with what the portal shows.
fn report_identity(config: &AgentConfig, state: &LocalState) -> Result<()> {
    let Some(identity) = state.identity()? else {
        tracing::warn!("not enrolled, run `updawgctl enroll --token ...`");
        return Ok(());
    };

    match PinnedKeys::from_wire(&identity.org_signing_keys) {
        Ok(pinned) => {
            tracing::info!(
                host_id = %identity.host_id,
                enrolled_at = %identity.enrolled_at,
                org_signing_keys = ?pinned.describe(),
                "enrolled"
            );
            // `load` already refused a malformed one.
            if let Ok(Some(trusted)) = config.trusted_org_key()
                && !pinned.contains_material(&trusted)
            {
                tracing::warn!(
                    trusted_org_key = %trusted.fingerprint(),
                    "trusted_org_key is not pinned yet: this host enrolled before it was set, and \
                     follows it at its next certificate renewal once the organization has taken \
                     over signing (or `updawgctl enroll --force` pins it now)"
                );
            }
        }
        // An error, not a warning: this host will reject every job, and would
        // otherwise look healthy until one arrived.
        Err(error) => tracing::error!(
            host_id = %identity.host_id,
            %error,
            "enrolled, but the pinned organization keys cannot be used; no job will verify"
        ),
    }
    Ok(())
}

fn build_checkin(
    config: &AgentConfig,
    state: &LocalState,
    extra_root: Option<&[u8]>,
    inventory: Option<Arc<dyn Inventory>>,
    snapshots: updawg_agent_core::jobs::Snapshots,
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

    // `None` with no known package manager; jobs are then refused up front
    // instead of failing halfway.
    let backend: Option<Arc<dyn updawg_backends::PackageBackend>> =
        updawg_backends::detect().ok().map(Arc::from);
    let support = updawg_agent_core::jobs::snapshot_support(&snapshots);
    let jobs = Arc::new(
        Executor::new(
            Arc::clone(&transport) as Arc<dyn Reporter>,
            state.clone(),
            config.clone(),
            backend,
            inventory,
        )
        .with_snapshots(snapshots),
    );
    // Finish a job that rebooted this host: rerun its health checks and send
    // the report. In the background so a slow check doesn't delay the first
    // check-in.
    tokio::spawn({
        let jobs = Arc::clone(&jobs);
        async move { jobs.resume_after_reboot().await }
    });
    // Same for a self-update, which waits for the first check-in before
    // reporting.
    tokio::spawn({
        let jobs = Arc::clone(&jobs);
        async move { jobs.resume_after_self_update().await }
    });

    Some(Arc::new(
        GatewayCheckIn::new(
            transport,
            state.clone(),
            collector,
            jobs,
            config.local_policy(),
        )
        .with_snapshots(support)
        // Detected once. It asks dpkg or rpm who owns this binary, and the
        // agent restarts whenever a package or install.sh replaces it.
        .with_install(updawg_agent_core::self_update::install()),
    ))
}

/// `None` if this host can't collect inventory. A host with no recognised
/// package manager still enrolls and checks in, but it must not upload an
/// empty package list, which the server would read as nothing installed.
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

/// Logs platform facts and current state at startup, so an operator can see
/// the agent reads the machine correctly.
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
            // keep unknown distinct from no
            reboot_required = ?state.reboot_required,
            services_needing_restart = state.services_needing_restart.len(),
            load1 = state.metrics.load1,
            mem_used_pct = state.metrics.mem_used_pct,
            "state"
        ),
        Err(error) => tracing::error!(%error, "could not read this host's state"),
    }
}

/// Renews the client certificate if it's inside its renewal window. Failure
/// is logged, never fatal.
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

/// Stands in for check-in and inventory when the host has no usable identity
/// or package backend.
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
        tracing::debug!("inventory skipped: no usable identity or package backend");
        Ok(())
    }
    async fn refresh_metadata(&self) -> Result<()> {
        tracing::debug!("metadata refresh skipped: no usable identity or package backend");
        Ok(())
    }
}

/// Resolves on SIGTERM or SIGINT. Ignoring SIGTERM gets us `SIGKILL`ed by
/// systemd, which mid-apply can leave the package database half-written.
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
                tracing::error!(%error, "cannot listen for SIGTERM; shutdown will not be graceful");
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
