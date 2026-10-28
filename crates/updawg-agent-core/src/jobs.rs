//! Running the jobs a check-in delivers.
//!
//! Each job goes through these steps, and every one before the last can only
//! refuse it:
//!
//! 1. Job ids already recorded are ignored. The id is recorded before anything
//!    runs, so a crash mid-install can't run it again on restart.
//! 2. The job must name this host, verify under an organization key pinned at
//!    enrollment that may still sign (and be the key it names), not have
//!    expired, and not be early.
//! 3. Local configuration wins: observe mode refuses every job that changes
//!    anything, and the deny list refuses what it names. A refusal is reported
//!    with a reason and halts the proposal for someone to review.
//! 4. Run it in the background, one at a time, report the result and upload a
//!    fresh inventory.
//!
//! `refresh_inventory` jobs are refused as not implemented yet, which halts
//! the proposal.
//!
//! # Snapshots
//!
//! If the policy asks for one, `apply_updates` takes a snapshot before changing
//! anything and always reports its id, since a failed install is the likeliest
//! thing to roll back. With `required` and no snapshot (no provider, not
//! permitted, or it failed) nothing is changed; with `if_available` the job
//! carries on without one. Either way the report says why. The agent's own
//! snapshots beyond `[snapshots] keep` are pruned after each new one.

use crate::{
    config::AgentConfig,
    joblog::{AFTER_REBOOT, JobLog},
    scheduler::Inventory,
    state::LocalState,
    transport::{JobAnswer, MtlsTransport},
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use tokio::sync::Mutex;
use updawg_backends::{ApplyPlan, BackendError, PackageBackend, Pin};
use updawg_crypto::PinnedKeys;
use updawg_executor::health::{self, Check};
use updawg_protocol::{
    HealthCheckReport, InstalledPackage, Job, JobAck, JobComplete, JobKind, JobStatus,
    PackageChange,
    job::{JobSpec, RebootPolicy, SnapshotPolicy},
};
use updawg_snapshots::SnapshotProvider;

/// The snapshot provider this host has, or why it has none.
pub type Snapshots = std::result::Result<Arc<dyn SnapshotProvider>, String>;

/// Snapshot support as reported to the server.
#[must_use]
pub fn snapshot_support(snapshots: &Snapshots) -> updawg_protocol::SnapshotSupport {
    match snapshots {
        Ok(provider) => updawg_protocol::SnapshotSupport {
            provider: Some(provider.provider().name().to_owned()),
            reason: None,
        },
        Err(why) => updawg_protocol::SnapshotSupport {
            provider: None,
            reason: Some(why.clone()),
        },
    }
}

/// Allowed clock skew before `not_before`. The gateway holds jobs back until
/// then anyway.
const EARLY: Duration = Duration::minutes(5);

/// Rebooting, behind a trait so tests never do it for real.
#[async_trait]
pub trait Rebooter: Send + Sync {
    /// The kernel boot id. A changed id proves a reboot happened.
    fn boot_id(&self) -> Option<String>;
    /// Whether the distribution says a reboot is needed.
    async fn reboot_required(&self) -> bool;
    /// Reboots after `delay_s`, showing `message` on terminals.
    async fn reboot(&self, delay_s: u64, message: &str) -> anyhow::Result<()>;
    /// Whether `/boot` is a separate filesystem, which a snapshot of `/`
    /// would not cover.
    async fn boot_is_separate(&self) -> bool;
}

/// Reboots with `shutdown -r`.
#[derive(Debug, Default)]
pub struct SystemRebooter;

#[async_trait]
impl Rebooter for SystemRebooter {
    fn boot_id(&self) -> Option<String> {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|s| s.trim().to_owned())
    }

    async fn reboot_required(&self) -> bool {
        // Debian and Ubuntu touch a file; the RHEL family answers
        // `needs-restarting -r` with exit 1.
        if std::path::Path::new("/var/run/reboot-required").exists() {
            return true;
        }
        tokio::process::Command::new("needs-restarting")
            .arg("-r")
            .output()
            .await
            .is_ok_and(|o| o.status.code() == Some(1))
    }

    async fn reboot(&self, delay_s: u64, message: &str) -> anyhow::Result<()> {
        // shutdown takes minutes; round up so logged-in users never get less
        // warning than promised
        let when = match delay_s.div_ceil(60) {
            0 => "now".to_owned(),
            minutes => format!("+{minutes}"),
        };
        let out = tokio::process::Command::new("shutdown")
            .args(["-r", &when, message])
            .output()
            .await?;
        anyhow::ensure!(
            out.status.success(),
            "shutdown -r {when} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        Ok(())
    }

    async fn boot_is_separate(&self) -> bool {
        // findmnt prints nothing and exits 1 unless /boot is a mount point
        tokio::process::Command::new("findmnt")
            .args(["-n", "-o", "SOURCE", "/boot"])
            .output()
            .await
            .is_ok_and(|o| o.status.success() && !o.stdout.trim_ascii().is_empty())
    }
}

/// Where job acks, results and logs are sent. The gateway, in production.
#[async_trait]
pub trait Reporter: Send + Sync {
    async fn ack(&self, job: &Job, ack: &JobAck) -> anyhow::Result<()>;
    async fn complete(&self, job: &Job, done: &JobComplete) -> anyhow::Result<()>;
    /// Sends a batch of the job's log as NDJSON. `Ok(false)` means it was
    /// rejected for good and should be dropped, not retried.
    async fn logs(&self, job: &Job, ndjson: String) -> anyhow::Result<bool>;
}

#[async_trait]
impl Reporter for MtlsTransport {
    async fn ack(&self, job: &Job, ack: &JobAck) -> anyhow::Result<()> {
        log_answer(job, "ack", self.ack_job(&job.id, ack).await?);
        Ok(())
    }

    async fn complete(&self, job: &Job, done: &JobComplete) -> anyhow::Result<()> {
        log_answer(job, "complete", self.complete_job(&job.id, done).await?);
        Ok(())
    }

    async fn logs(&self, job: &Job, ndjson: String) -> anyhow::Result<bool> {
        Ok(self.upload_logs(&job.id, ndjson).await?)
    }
}

fn log_answer(job: &Job, what: &str, answer: JobAnswer) {
    if answer == JobAnswer::AlreadyMoved {
        tracing::info!(job = %job.id, what, "the gateway had already recorded this job moving on");
    }
}

/// Checks that a delivered job is addressed to this host, verifies, and is
/// within its time window. Local policy is checked separately.
///
/// # Errors
/// The reason for refusal, as it should appear in the report.
pub fn check_job(
    job: &Job,
    host_id: &str,
    keys: &PinnedKeys,
    now: DateTime<Utc>,
) -> Result<(), String> {
    if job.host_id.as_str() != host_id {
        return Err(format!(
            "the job is for {}, and this host is {host_id}",
            job.host_id
        ));
    }
    keys.verify_job(job)
        .map_err(|e| format!("the job does not verify: {e}"))?;
    if job.expires_at <= now {
        return Err(format!("the job expired at {}", job.expires_at));
    }
    if let Some(start) = job.not_before
        && start > now + EARLY
    {
        return Err(format!("the job may not start until {start}"));
    }
    Ok(())
}

pub struct Executor {
    reporter: Arc<dyn Reporter>,
    state: LocalState,
    config: AgentConfig,
    backend: Option<Arc<dyn PackageBackend>>,
    inventory: Option<Arc<dyn Inventory>>,
    rebooter: Arc<dyn Rebooter>,
    snapshots: Snapshots,
    /// Serialises mutating jobs.
    running: Arc<Mutex<()>>,
}

impl std::fmt::Debug for Executor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Executor")
            .field("mode", &self.config.mode)
            .field("backend", &self.backend.as_ref().map(|b| b.ecosystem()))
            .finish_non_exhaustive()
    }
}

impl Executor {
    #[must_use]
    pub fn new(
        reporter: Arc<dyn Reporter>,
        state: LocalState,
        config: AgentConfig,
        backend: Option<Arc<dyn PackageBackend>>,
        inventory: Option<Arc<dyn Inventory>>,
    ) -> Self {
        Self {
            reporter,
            state,
            config,
            backend,
            inventory,
            rebooter: Arc::new(SystemRebooter),
            snapshots: Err("no snapshot provider was looked for".into()),
            running: Arc::default(),
        }
    }

    /// Sets the result of `updawg_snapshots::detect`.
    #[must_use]
    pub fn with_snapshots(mut self, snapshots: Snapshots) -> Self {
        self.snapshots = snapshots;
        self
    }

    /// Replaces the rebooter. For tests.
    #[must_use]
    pub fn with_rebooter(mut self, rebooter: Arc<dyn Rebooter>) -> Self {
        self.rebooter = rebooter;
        self
    }

    /// Finishes a self-update. Call once at startup, like
    /// [`Self::resume_after_reboot`].
    ///
    /// - The new version waits for its first successful check-in (what the
    ///   helper also waits for) and reports success. If that never happens it
    ///   reports nothing; the helper restores the old version, which reports.
    /// - A restored old version reports the helper's reason.
    /// - An old version with no recorded reason does nothing while the helper
    ///   is still running (it will restart the agent), and otherwise reports
    ///   that the update stopped part-way.
    pub async fn resume_after_self_update(&self) {
        let pending = match self.state.self_update() {
            Ok(Some(pending)) => pending,
            Ok(None) => return,
            Err(error) => {
                tracing::error!(%error, "cannot read the record of a self-update");
                return;
            }
        };
        let job = pending.job.clone();
        let mut done = pending.report.clone();
        let log = JobLog::start(Arc::clone(&self.reporter), job.clone(), AFTER_REBOOT);
        if crate::VERSION == pending.to {
            let began = Utc::now();
            let deadline = tokio::time::Instant::now() + crate::self_update::CONFIRM_WITHIN;
            loop {
                if let Ok(Some(last)) = self.state.last_checkin()
                    && last.ok
                    && last.at >= began
                    && last.agent.as_deref() == Some(crate::VERSION)
                {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    tracing::error!(job = %job.id, "updated, and never checked in; the helper puts the previous version back");
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            log.agent(format!("now {}, and checked in", pending.to));
            done.status = JobStatus::Succeeded;
            done.changes = vec![PackageChange {
                name: crate::self_update::PACKAGE.into(),
                arch: std::env::consts::ARCH.into(),
                from: pending.from.clone(),
                to: pending.to.clone(),
            }];
        } else {
            let outcome = self.state.self_update_outcome();
            // checked up front rather than in a match guard because it's async
            let helper_running =
                matches!(outcome, Ok(None)) && crate::self_update::helper_running().await;
            match outcome {
                Ok(Some(outcome)) => {
                    log.agent(&outcome.detail);
                    done.status = JobStatus::Failed;
                    done.error = Some(outcome.detail);
                }
                Ok(None) if helper_running => {
                    tracing::info!(job = %job.id, "the self-update helper is still running");
                    return;
                }
                Ok(None) | Err(_) => {
                    let why = format!(
                        "the update to {} stopped before it finished; {} is still running",
                        pending.to,
                        crate::VERSION
                    );
                    log.agent(&why);
                    done.status = JobStatus::Failed;
                    done.error = Some(why);
                }
            }
        }
        log.finish().await;
        done.finished_at = Utc::now();
        note_done(&self.state, &job, &done);
        // Report before clearing the record, retrying until delivered or the
        // job expires. If the gateway is unreachable and the record is already
        // gone, the server would show the job as running until it expired.
        // Keeping the record also means a restart retries the report.
        let mut wait = std::time::Duration::from_secs(15);
        loop {
            match self.reporter.complete(&job, &done).await {
                Ok(()) => break,
                Err(error) if Utc::now() < job.expires_at => {
                    tracing::warn!(job = %job.id, error = format!("{error:#}"), retry_in_s = wait.as_secs(), "could not report how the self-update went; trying again");
                    tokio::time::sleep(wait).await;
                    wait = (wait * 2).min(std::time::Duration::from_secs(600));
                }
                Err(error) => {
                    tracing::error!(job = %job.id, error = format!("{error:#}"), "could not report how the self-update went, and the job has expired");
                    break;
                }
            }
        }
        if let Err(error) = self.state.take_self_update() {
            tracing::error!(job = %job.id, %error, "cannot clear the record of the self-update");
        }
        if let Some(inventory) = &self.inventory
            && let Err(error) = inventory.collect_and_upload().await
        {
            tracing::warn!(job = %job.id, error = format!("{error:#}"), "could not upload the inventory after the self-update");
        }
    }

    /// Finishes a job that rebooted the host. Call once at startup.
    ///
    /// A changed boot id means the host did reboot; health checks run again
    /// before the job is reported. An unchanged id means only the agent
    /// restarted, which is reported as a failure.
    pub async fn resume_after_reboot(&self) {
        let pending = match self.state.take_pending_reboot() {
            Ok(Some(pending)) => pending,
            Ok(None) => return,
            Err(error) => {
                tracing::error!(%error, "cannot read the record of a pending reboot");
                return;
            }
        };
        let job = pending.job;
        let mut done = pending.report;
        let log = JobLog::start(Arc::clone(&self.reporter), job.clone(), AFTER_REBOOT);
        let now = self.rebooter.boot_id();
        if now.as_deref() == Some(pending.boot_id_before.as_str()) || now.is_none() {
            tracing::error!(job = %job.id, "a reboot was asked for and the host has not rebooted");
            log.agent("the agent restarted, and the host has not rebooted");
            done.status = JobStatus::Failed;
            done.error = Some("the job asked for a reboot, and the host has not rebooted".into());
        } else {
            log.agent("rebooted; running the health checks again");
            done.health_checks = checks_reported(&job, &self.checks(), &log).await;
        }
        // a release upgrade that finishes during the reboot (leapp) only has
        // an outcome now
        match self.state.take_release_check() {
            Ok(Some(check)) if check.job == job.id && done.status == JobStatus::Succeeded => {
                self.finish_release(&check, &mut done, &log).await;
            }
            Ok(_) => {}
            Err(error) => {
                tracing::error!(job = %job.id, %error, "cannot read what to check after the upgrade");
                done.status = JobStatus::Failed;
                done.error = Some(format!(
                    "the agent could not read what to check after the upgrade: {error}"
                ));
            }
        }
        log.finish().await;
        done.reboot_required = self.rebooter.reboot_required().await;
        done.finished_at = Utc::now();
        note_done(&self.state, &job, &done);
        if let Err(error) = self.reporter.complete(&job, &done).await {
            tracing::error!(job = %job.id, error = format!("{error:#}"), "could not report how the job went");
        }
        if let Some(inventory) = &self.inventory
            && let Err(error) = inventory.collect_and_upload().await
        {
            tracing::warn!(job = %job.id, error = format!("{error:#}"), "could not upload the inventory after the reboot");
        }
    }

    /// Checks that the host came back on the target release, and fills in
    /// the package changes by diffing against the pre-upgrade list.
    async fn finish_release(
        &self,
        check: &crate::state::ReleaseCheck,
        done: &mut JobComplete,
        log: &JobLog,
    ) {
        let host = updawg_backends::release::this_host();
        match host {
            Ok(host) if updawg_backends::leapp_upgrade::arrived(&host, &check.release) => {
                if let Some(backend) = &self.backend {
                    match backend.installed().await {
                        Ok(after) => done.changes = package_changes(&check.before, &after),
                        Err(error) => log.agent(format!(
                            "could not list what is installed now, so the report names no changes: {error}"
                        )),
                    }
                }
                log.agent(format!(
                    "now {} {}: {} package(s) changed",
                    host.id,
                    host.version,
                    done.changes.len()
                ));
            }
            Ok(host) => {
                let why = format!(
                    "the host came back on {} {}, not {}: the upgrade did not complete, and /var/log/leapp/leapp-upgrade.log says why",
                    host.id, host.version, check.release
                );
                log.agent(&why);
                done.status = JobStatus::Failed;
                done.error = Some(why);
            }
            Err(error) => {
                let why = format!("cannot tell which release the host came back on: {error}");
                log.agent(&why);
                done.status = JobStatus::Failed;
                done.error = Some(why);
            }
        }
    }

    fn checks(&self) -> Vec<Check> {
        self.config
            .health_checks
            .iter()
            .map(crate::config::HealthCheck::to_check)
            .collect()
    }

    async fn refuse(&self, job: &Job, reason: String) {
        tracing::warn!(job = %job.id, kind = ?job.kind(), %reason, "refused a job");
        note(&self.state, job, "refused", Some(&reason));
        let ack = JobAck {
            accepted: false,
            rejection_reason: Some(reason),
            at: Utc::now(),
        };
        if let Err(error) = self.reporter.ack(job, &ack).await {
            tracing::error!(job = %job.id, error = format!("{error:#}"), "could not report a refusal");
        }
    }

    /// Why local configuration refuses this job, if it does.
    ///
    /// A job that may reboot is refused outright on a host that doesn't permit
    /// reboots, rather than installing and silently skipping the reboot.
    fn not_permitted(&self, job: &Job) -> Option<String> {
        if !self.config.admits(job.kind(), None) {
            return Some(if self.config.mode == crate::config::Mode::Observe {
                "this agent is in observe mode, which refuses every job that changes the host"
                    .to_owned()
            } else {
                format!(
                    "local configuration does not permit {}",
                    job.kind().permission()
                )
            });
        }
        if let Some((reboot, _)) = changes_packages(&job.spec)
            && reboot != RebootPolicy::Never
            && !self.config.admits(JobKind::Reboot, None)
        {
            return Some(
                "the job may reboot this host, and local configuration does not permit reboot"
                    .to_owned(),
            );
        }
        // same for a required snapshot
        if let Some((_, snapshot)) = changes_packages(&job.spec)
            && snapshot == SnapshotPolicy::Required
        {
            if !self.config.admits(JobKind::Snapshot, None) {
                return Some(
                    "the job requires a snapshot, and local configuration does not permit snapshot"
                        .to_owned(),
                );
            }
            if let Err(why) = &self.snapshots {
                return Some(format!(
                    "the job requires a snapshot, and this host cannot take one: {why}"
                ));
            }
        }
        None
    }

    fn provider_for(&self, job: &Job) -> std::result::Result<Arc<dyn SnapshotProvider>, String> {
        self.snapshots.clone().map_err(|why| {
            format!(
                "this host cannot run {} jobs, having no snapshot provider: {why}",
                job.kind().permission()
            )
        })
    }

    /// The snapshot to take before a change under `policy`, if any.
    ///
    /// `if_available` on a host that doesn't permit snapshots goes without,
    /// same as with no provider. `required` was already refused in
    /// [`Self::not_permitted`].
    fn snapshot_first(&self, policy: SnapshotPolicy) -> Option<SnapshotFirst> {
        match (policy, &self.snapshots) {
            (SnapshotPolicy::Never, _) | (_, Err(_)) => None,
            (_, Ok(_)) if !self.config.admits(JobKind::Snapshot, None) => None,
            (policy, Ok(provider)) => Some(SnapshotFirst {
                provider: Arc::clone(provider),
                required: policy == SnapshotPolicy::Required,
            }),
        }
    }

    fn work_for(&self, job: &Job) -> std::result::Result<Work, String> {
        Ok(match &job.spec {
            JobSpec::ApplyUpdates(apply) => {
                let Some(backend) = self.backend.clone() else {
                    return Err("this host has no package manager the agent can drive".into());
                };
                Work::Apply(
                    ApplyPlan {
                        packages: apply
                            .packages
                            .iter()
                            .map(|p| Pin {
                                name: p.name.clone(),
                                arch: p.arch.clone(),
                                from: p.from.clone(),
                                to: p.to.clone(),
                            })
                            .collect(),
                        allow_reboot: apply.reboot != RebootPolicy::Never,
                    },
                    backend,
                    apply.reboot,
                    self.snapshot_first(apply.snapshot),
                )
            }
            // the backend refuses upgrade paths it doesn't support
            JobSpec::DistUpgrade(upgrade) => {
                let Some(backend) = self.backend.clone() else {
                    return Err("this host has no package manager the agent can drive".into());
                };
                Work::DistUpgrade(
                    upgrade.target_release.clone(),
                    backend,
                    upgrade.reboot,
                    self.snapshot_first(upgrade.snapshot),
                )
            }
            JobSpec::Reboot(reboot) => Work::Reboot(reboot.policy),
            // read-only, so observe mode allows it
            JobSpec::RunPreflight(preflight) => Work::Preflight(
                preflight.clone(),
                self.backend.clone(),
                self.snapshots
                    .as_ref()
                    .map(|p| p.provider().name().to_owned())
                    .map_err(Clone::clone),
            ),
            JobSpec::Snapshot(snapshot) => Work::Snapshot(
                self.provider_for(job)?,
                snapshot
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("updawg: {}", job.id)),
            ),
            JobSpec::Rollback(rollback) => {
                let provider = self.provider_for(job)?;
                let name = provider.provider().name();
                if !rollback.snapshot_id.starts_with(&format!("{name}:")) {
                    return Err(format!(
                        "{} is not a snapshot this host's provider ({name}) took",
                        rollback.snapshot_id
                    ));
                }
                Work::Rollback(provider, rollback.snapshot_id.clone(), self.backend.clone())
            }
            JobSpec::SelfUpdate(spec) => Work::SelfUpdate(spec.clone()),
            JobSpec::RefreshInventory => {
                return Err(format!(
                    "this agent version does not run {:?} jobs yet",
                    job.kind()
                ));
            }
        })
    }

    /// Everything up to and including the ack. `None` if the job was ignored
    /// or refused.
    async fn admit(&self, job: &Job) -> Option<Work> {
        match self.state.has_seen_job(&job.id) {
            Ok(true) => {
                tracing::info!(job = %job.id, "already seen; ignoring");
                return None;
            }
            Ok(false) => {}
            Err(error) => {
                // can't tell whether it already ran, so don't
                self.refuse(
                    job,
                    format!("this host cannot read its record of jobs it has run: {error}"),
                )
                .await;
                return None;
            }
        }
        // Record it before anything else, refusals included, so a crash
        // from here on can't bring it back on restart.
        if let Err(error) = self.state.record_job(&job.id) {
            tracing::error!(job = %job.id, %error, "cannot record the job; not running it");
            return None;
        }

        let Ok(Some(identity)) = self.state.identity() else {
            self.refuse(
                job,
                "this host has no enrolled identity to check the job against".into(),
            )
            .await;
            return None;
        };
        let keys = match PinnedKeys::from_wire(&identity.org_signing_keys) {
            Ok(keys) => keys,
            Err(error) => {
                self.refuse(
                    job,
                    format!("this host's pinned organization keys are unusable: {error}"),
                )
                .await;
                return None;
            }
        };
        if let Err(reason) = check_job(job, identity.host_id.as_str(), &keys, Utc::now()) {
            self.refuse(job, reason).await;
            return None;
        }
        if let Some(reason) = self.not_permitted(job) {
            self.refuse(job, reason).await;
            return None;
        }
        let work = match self.work_for(job) {
            Ok(work) => work,
            Err(reason) => {
                self.refuse(job, reason).await;
                return None;
            }
        };

        note(&self.state, job, "running", None);
        let ack = JobAck {
            accepted: true,
            rejection_reason: None,
            at: Utc::now(),
        };
        if let Err(error) = self.reporter.ack(job, &ack).await {
            // run anyway; the gateway accepts `complete` for a job still in
            // `delivered`, so a lost ack doesn't strand it
            tracing::warn!(job = %job.id, error = format!("{error:#}"), "could not acknowledge; running anyway");
        }
        Some(work)
    }
}

enum Work {
    Apply(
        ApplyPlan,
        Arc<dyn PackageBackend>,
        RebootPolicy,
        Option<SnapshotFirst>,
    ),
    /// Target release.
    DistUpgrade(
        String,
        Arc<dyn PackageBackend>,
        RebootPolicy,
        Option<SnapshotFirst>,
    ),
    /// Reboot only, for a maintenance-window reboot after an install that
    /// ran outside the window.
    Reboot(RebootPolicy),
    /// Snapshot with this description.
    Snapshot(Arc<dyn SnapshotProvider>, String),
    /// Roll back to a snapshot id. The backend, if any, is used to list the
    /// packages that changed.
    Rollback(
        Arc<dyn SnapshotProvider>,
        String,
        Option<Arc<dyn PackageBackend>>,
    ),
    /// Read-only checks from `crate::preflight`, with the snapshot provider
    /// name or why there is none.
    Preflight(
        updawg_protocol::job::Preflight,
        Option<Arc<dyn PackageBackend>>,
        std::result::Result<String, String>,
    ),
    /// Prepared here, carried out by the helper in its own unit (see
    /// `crate::self_update`).
    SelfUpdate(updawg_protocol::SelfUpdate),
}

/// Reboot and snapshot policies for jobs that change packages.
fn changes_packages(spec: &JobSpec) -> Option<(RebootPolicy, SnapshotPolicy)> {
    match spec {
        JobSpec::ApplyUpdates(apply) => Some((apply.reboot, apply.snapshot)),
        JobSpec::DistUpgrade(upgrade) => Some((upgrade.reboot, upgrade.snapshot)),
        _ => None,
    }
}

struct SnapshotFirst {
    provider: Arc<dyn SnapshotProvider>,
    /// If set, no snapshot means no install.
    required: bool,
}

#[async_trait]
impl crate::checkin::JobSink for Executor {
    async fn deliver(&self, job: Job) {
        let Some(work) = self.admit(&job).await else {
            return;
        };
        let (reporter, inventory, running) = (
            Arc::clone(&self.reporter),
            self.inventory.clone(),
            Arc::clone(&self.running),
        );
        let checks = self.checks();
        let (state, rebooter) = (self.state.clone(), Arc::clone(&self.rebooter));
        let room = Room::from(&self.config.snapshots);
        let warning = self.config.reboot.clone();
        // installs can take minutes; don't block the check-in
        tokio::spawn(async move {
            let _one_at_a_time = running.lock().await;
            let log = JobLog::start(Arc::clone(&reporter), job.clone(), 0);
            if let Work::SelfUpdate(spec) = &work {
                self_update(&job, spec, &state, reporter.as_ref(), &log).await;
                return;
            }
            let (mut done, policy) =
                perform(&job, &work, &checks, &state, rebooter.as_ref(), room, &log).await;
            if wants_reboot(policy, &done) {
                log.agent(format!(
                    "rebooting in {} s to finish the job",
                    warning.delay_s()
                ));
                // flush now, this may be the last chance
                log.finish().await;
                match reboot(&job, &done, &state, rebooter.as_ref(), &warning).await {
                    // resume_after_reboot reports after the reboot
                    Ok(()) => {
                        note(&state, &job, "rebooting", None);
                        return;
                    }
                    Err(why) => {
                        tracing::error!(job = %job.id, %why, "could not reboot");
                        log.agent(format!("could not reboot: {why}"));
                        done.status = JobStatus::Failed;
                        done.error = Some(why);
                    }
                }
            }
            log.agent(match done.status {
                JobStatus::Succeeded => format!(
                    "done: {} package(s) changed{}",
                    done.changes.len(),
                    done.snapshot_id
                        .as_deref()
                        .map(|id| format!(", snapshot {id}"))
                        .unwrap_or_default()
                ),
                _ => format!(
                    "{:?}: {}",
                    done.status,
                    done.error.as_deref().unwrap_or("no detail")
                ),
            });
            log.finish().await;
            note_done(&state, &job, &done);
            if let Err(error) = reporter.complete(&job, &done).await {
                tracing::error!(job = %job.id, error = format!("{error:#}"), "could not report how the job went");
            }
            if let Some(inventory) = inventory
                && let Err(error) = inventory.collect_and_upload().await
            {
                tracing::warn!(job = %job.id, error = format!("{error:#}"), "could not upload the inventory after the job");
            }
            // if the install upgraded the agent itself, restart now that the
            // job is reported (see `crate::restart`)
            crate::restart::restart_if_replaced();
        });
    }
}

fn misrouted() -> (JobComplete, RebootPolicy) {
    let now = Utc::now();
    let why = "a self-update reached the wrong path in the agent".to_owned();
    (
        failed(JobStatus::Failed, now, now, why),
        RebootPolicy::Never,
    )
}

/// Prepares a `self_update` and hands it to the helper. The report normally
/// comes from [`Executor::resume_after_self_update`], in the new agent or the
/// restored old one. It's reported here only if there was nothing to do or it
/// was refused before anything changed.
async fn self_update(
    job: &Job,
    spec: &updawg_protocol::SelfUpdate,
    state: &LocalState,
    reporter: &dyn Reporter,
    log: &JobLog,
) {
    let started = Utc::now();
    let skeleton = ended(JobStatus::Succeeded, started, started, None);
    let done = match crate::self_update::start(job, spec, skeleton, state, log).await {
        Ok(crate::self_update::Started::Handed) => {
            note(state, job, "updating", None);
            log.finish().await;
            return;
        }
        Ok(crate::self_update::Started::AlreadyThere) => {
            ended(JobStatus::Succeeded, started, Utc::now(), None)
        }
        Err(why) => {
            log.agent(format!("not updating: {why}"));
            failed(JobStatus::Failed, started, Utc::now(), why)
        }
    };
    log.finish().await;
    note_done(state, job, &done);
    if let Err(error) = reporter.complete(job, &done).await {
        tracing::error!(job = %job.id, error = format!("{error:#}"), "could not report how the job went");
    }
}

/// Applies the plan, then runs the health checks.
///
/// A failed health check doesn't change the job's status; the report keeps
/// install failures and health failures separate, and the server halts the
/// rollout on either.
///
/// Checks also run after a failed install, which can leave some packages
/// changed, but not after a refusal.
async fn run(
    job: &Job,
    plan: &ApplyPlan,
    backend: &dyn PackageBackend,
    checks: &[Check],
    log: &JobLog,
) -> JobComplete {
    let started_at = Utc::now();
    let outcome = backend.apply(plan, log).await;
    let mut done = report(job, started_at, outcome);
    if done.status != JobStatus::RejectedByHost {
        done.health_checks = checks_reported(job, checks, log).await;
        done.finished_at = Utc::now();
    }
    done
}

/// Pre-reboot report for a `reboot` job. With `if_required`, a host that was
/// already rebooted some other way reports success and stays up. With
/// `always` the reboot happens regardless.
async fn reboot_only(rebooter: &dyn Rebooter, policy: RebootPolicy, log: &JobLog) -> JobComplete {
    let now = Utc::now();
    let reboot_required = rebooter.reboot_required().await;
    log.agent(match (policy, reboot_required) {
        (RebootPolicy::Always, _) => "a reboot job: rebooting, as asked",
        (_, true) => "a reboot job, and the host needs one",
        (_, false) => "a reboot job, and the host no longer needs one: nothing to do",
    });
    JobComplete {
        status: JobStatus::Succeeded,
        started_at: now,
        finished_at: now,
        snapshot_id: None,
        changes: vec![],
        health_checks: vec![],
        reboot_required,
        inventory_hash: None,
        error: None,
        preflight: vec![],
    }
}

/// Records job progress locally for `updawgctl jobs`. Failures are ignored.
fn note(state: &LocalState, job: &Job, status: &str, detail: Option<&str>) {
    let record = crate::state::JobRecord {
        id: job.id.as_str().to_owned(),
        // wire name (`apply_updates`)
        kind: serde_json::to_value(job.kind())
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("{:?}", job.kind())),
        status: status.to_owned(),
        at: Utc::now(),
        detail: detail.map(str::to_owned),
    };
    if let Err(error) = state.record_job_status(&record) {
        tracing::debug!(job = %job.id, %error, "could not record the job for updawgctl");
    }
}

fn note_done(state: &LocalState, job: &Job, done: &JobComplete) {
    let status = match done.status {
        JobStatus::Succeeded => "succeeded",
        JobStatus::Failed => "failed",
        JobStatus::RejectedByHost => "refused",
    };
    let detail = done.error.clone().or_else(|| {
        (!done.changes.is_empty()).then(|| format!("{} package(s) changed", done.changes.len()))
    });
    note(state, job, status, detail.as_deref());
}

/// Runs an admitted job. Returns the report and the reboot policy to apply.
async fn perform(
    job: &Job,
    work: &Work,
    checks: &[Check],
    state: &LocalState,
    rebooter: &dyn Rebooter,
    room: Room,
    log: &JobLog,
) -> (JobComplete, RebootPolicy) {
    match work {
        Work::Apply(plan, backend, policy, snapshot) => {
            let started_at = Utc::now();
            match snapshot_first(job, snapshot.as_ref(), room, log).await {
                // required snapshot failed; nothing changed
                Err(why) => (
                    failed(JobStatus::RejectedByHost, started_at, Utc::now(), why),
                    RebootPolicy::Never,
                ),
                Ok(taken) => {
                    log.agent(format!(
                        "installing {} package{} at exactly the approved versions",
                        plan.packages.len(),
                        if plan.packages.len() == 1 { "" } else { "s" }
                    ));
                    let mut done = run(job, plan, backend.as_ref(), checks, log).await;
                    // even on failure, which is when a rollback is most likely
                    done.snapshot_id = taken;
                    done.started_at = started_at;
                    (done, *policy)
                }
            }
        }
        Work::DistUpgrade(target, backend, policy, snapshot) => {
            upgrade_release(
                job,
                Upgrade {
                    target,
                    backend: backend.as_ref(),
                    policy: *policy,
                    snapshot: snapshot.as_ref(),
                },
                checks,
                state,
                room,
                log,
            )
            .await
        }
        Work::Reboot(policy) => (reboot_only(rebooter, *policy, log).await, *policy),
        // handled in `deliver`
        Work::SelfUpdate(_) => misrouted(),
        Work::Snapshot(provider, description) => {
            let started_at = Utc::now();
            let done = match take(job, provider.as_ref(), description, room, log).await {
                Ok(id) => JobComplete {
                    snapshot_id: Some(id),
                    ..ended(JobStatus::Succeeded, started_at, Utc::now(), None)
                },
                Err(why) => failed(JobStatus::Failed, started_at, Utc::now(), why),
            };
            (done, RebootPolicy::Never)
        }
        Work::Preflight(preflight, backend, snapshots) => {
            let started_at = Utc::now();
            let reboot_now = if rebooter.reboot_required().await {
                updawg_protocol::RebootRequired::Yes
            } else {
                updawg_protocol::RebootRequired::No
            };
            let facts = crate::preflight::gather(
                preflight,
                backend.as_deref(),
                snapshots.clone(),
                reboot_now,
            )
            .await;
            let checks = crate::preflight::evaluate(&facts);
            for c in &checks {
                log.agent(format!(
                    "preflight {}: {:?}: {}",
                    c.name, c.status, c.summary
                ));
            }
            // a failing check is a result, not a failed job
            (
                JobComplete {
                    preflight: checks,
                    ..ended(JobStatus::Succeeded, started_at, Utc::now(), None)
                },
                RebootPolicy::Never,
            )
        }
        Work::Rollback(provider, id, backend) => {
            let mut done = roll_back(
                state,
                provider.as_ref(),
                id,
                backend.as_deref(),
                rebooter,
                log,
            )
            .await;
            if done.status == JobStatus::Succeeded {
                done.reboot_required = done.reboot_required || rebooter.reboot_required().await;
            }
            // also after a failure, since a partial rollback can leave the
            // host in any state
            done.health_checks = checks_reported(job, checks, log).await;
            done.finished_at = Utc::now();
            (done, RebootPolicy::Never)
        }
    }
}

struct Upgrade<'a> {
    target: &'a str,
    backend: &'a dyn PackageBackend,
    policy: RebootPolicy,
    snapshot: Option<&'a SnapshotFirst>,
}

/// Release upgrade: optional snapshot, the backend's upgrade, then health
/// checks.
///
/// An upgrade that happens during the reboot (leapp) is refused if the job
/// may not reboot. Otherwise its checks wait until the host is back up:
/// [`Executor::resume_after_reboot`] reads the [`ReleaseCheck`] saved here.
///
/// [`ReleaseCheck`]: crate::state::ReleaseCheck
async fn upgrade_release(
    job: &Job,
    upgrade: Upgrade<'_>,
    checks: &[Check],
    state: &LocalState,
    room: Room,
    log: &JobLog,
) -> (JobComplete, RebootPolicy) {
    let Upgrade {
        target,
        backend,
        policy,
        snapshot,
    } = upgrade;
    let started_at = Utc::now();
    if backend.upgrade_finishes_at_reboot() && policy == RebootPolicy::Never {
        let why = "this release upgrade is carried out by the reboot that follows it, and the job may not reboot, so nothing was changed";
        log.agent(why);
        return (
            failed(
                JobStatus::RejectedByHost,
                started_at,
                Utc::now(),
                why.into(),
            ),
            RebootPolicy::Never,
        );
    }
    let taken = match snapshot_first(job, snapshot, room, log).await {
        Ok(taken) => taken,
        Err(why) => {
            return (
                failed(JobStatus::RejectedByHost, started_at, Utc::now(), why),
                RebootPolicy::Never,
            );
        }
    };
    log.agent(format!("upgrading this host to release {target}"));
    let outcome = backend.dist_upgrade(target, log).await;
    let after = outcome.as_ref().ok().and_then(|o| o.after_reboot.clone());
    let mut done = report(job, started_at, outcome);
    done.snapshot_id = taken;
    if let Some(after) = after {
        // nothing has changed yet; check after the reboot
        let check = crate::state::ReleaseCheck {
            job: job.id.clone(),
            release: after.release,
            before: after.before,
        };
        if let Err(error) = state.set_release_check(&check) {
            let why = format!(
                "the upgrade is prepared and could not be recorded for checking after the reboot ({error}), so the agent did not reboot; the next reboot carries it out"
            );
            log.agent(&why);
            done.status = JobStatus::Failed;
            done.error = Some(why);
            return (done, RebootPolicy::Never);
        }
        return (done, policy);
    }
    if done.status != JobStatus::RejectedByHost {
        done.health_checks = checks_reported(job, checks, log).await;
        done.finished_at = Utc::now();
    }
    (done, policy)
}

/// Takes the pre-install snapshot, if any.
///
/// `Ok(None)` when none was requested, or `if_available` couldn't get one.
/// `Err` only when a required snapshot failed, in which case nothing is
/// installed.
async fn snapshot_first(
    job: &Job,
    first: Option<&SnapshotFirst>,
    room: Room,
    log: &JobLog,
) -> Result<Option<String>, String> {
    let Some(first) = first else {
        return Ok(None);
    };
    let description = format!("updawg: before {}", job.id);
    match take(job, first.provider.as_ref(), &description, room, log).await {
        Ok(id) => Ok(Some(id)),
        Err(why) if first.required => {
            let why = format!(
                "the job requires a snapshot and none could be taken, so nothing was changed: {why}"
            );
            log.agent(&why);
            Err(why)
        }
        Err(why) => {
            log.agent(format!("carrying on without a snapshot: {why}"));
            Ok(None)
        }
    }
}

/// `[snapshots]` retention and free-space settings from agent.toml.
#[derive(Debug, Clone, Copy)]
struct Room {
    /// At least 1, so the snapshot just taken is never pruned.
    keep: usize,
    min_free_bytes: u64,
}

impl From<&crate::config::Snapshots> for Room {
    fn from(s: &crate::config::Snapshots) -> Self {
        Self {
            keep: usize::try_from(s.keep).unwrap_or(usize::MAX).max(1),
            min_free_bytes: s.min_free_mb.saturating_mul(1024 * 1024),
        }
    }
}

/// Takes a snapshot for `job`, then prunes the agent's snapshots to `keep`.
///
/// Refuses with less than `min_free_mb` free. If free space can't be measured
/// it goes ahead anyway. A failed prune is logged but doesn't fail the job.
async fn take(
    job: &Job,
    provider: &dyn SnapshotProvider,
    description: &str,
    room: Room,
    log: &JobLog,
) -> Result<String, String> {
    let Room {
        keep,
        min_free_bytes,
    } = room;
    match provider.free_bytes().await {
        Ok(free) if free < min_free_bytes => {
            return Err(format!(
                "only {} MiB free where the snapshot would live, and [snapshots] min_free_mb is {}",
                free / (1024 * 1024),
                min_free_bytes / (1024 * 1024)
            ));
        }
        Ok(_) => {}
        Err(error) => log.agent(format!("could not tell how much space is free: {error}")),
    }
    log.agent(format!("taking a {} snapshot", provider.provider().name()));
    let snapshot = provider
        .create(description, job.id.as_str())
        .await
        .map_err(|e| format!("could not take a snapshot: {e}"))?;
    log.agent(format!("snapshot {} taken", snapshot.id));
    match provider.prune(keep).await {
        Ok(gone) if gone.is_empty() => {}
        Ok(gone) => log.agent(format!(
            "pruned {} older snapshot(s), keeping {keep}: {}",
            gone.len(),
            gone.join(", ")
        )),
        Err(error) => {
            tracing::warn!(job = %job.id, %error, "could not prune snapshots");
            log.agent(format!("could not prune older snapshots: {error}"));
        }
    }
    Ok(snapshot.id)
}

/// Rolls back to snapshot `id` and reports the package changes.
///
/// The agent's own state is preserved (see [`LocalState::carry`]). Changes
/// come from diffing the package manager's list before and after.
async fn roll_back(
    state: &LocalState,
    provider: &dyn SnapshotProvider,
    id: &str,
    backend: Option<&dyn PackageBackend>,
    rebooter: &dyn Rebooter,
    log: &JobLog,
) -> JobComplete {
    let started_at = Utc::now();
    if let Some(why) = takes_a_kernel_from_boot(provider, id, rebooter).await {
        log.agent(&why);
        return failed(JobStatus::RejectedByHost, started_at, Utc::now(), why);
    }
    let fail = |why: String| {
        log.agent(&why);
        failed(JobStatus::Failed, started_at, Utc::now(), why)
    };
    // A rollback applied at next boot replaces this directory with the
    // snapshot's copy after the job has ended, so write the current state
    // into the snapshot now or don't roll back.
    if provider.restores_at_next_boot()
        && let Err(error) = provider.carry_into(id, state.root()).await
    {
        let why = format!(
            "could not write the agent's own state into the snapshot, so did not roll back: {error}"
        );
        log.agent(&why);
        return failed(JobStatus::RejectedByHost, started_at, Utc::now(), why);
    }
    let carried = match state.carry() {
        Ok(carried) => carried,
        Err(error) => {
            // without it the agent would forget which jobs it has run
            return failed(
                JobStatus::RejectedByHost,
                started_at,
                Utc::now(),
                format!(
                    "could not hold the agent's own state across the rollback, so did not roll back: {error}"
                ),
            );
        }
    };
    let before = match backend {
        Some(b) => b.installed().await.ok(),
        None => None,
    };
    log.agent(format!("rolling back to snapshot {id}"));
    let restored = provider.rollback(id).await;
    // restore even on failure; the rollback may have got partway
    if let Err(error) = state.put_back(&carried) {
        tracing::error!(%error, "could not put the agent's state back after a rollback");
        return fail(format!(
            "the agent's own state could not be put back after the rollback: {error}"
        ));
    }
    let restored = match restored {
        Ok(restored) => restored,
        Err(error) => return fail(format!("the rollback failed: {error}")),
    };
    log.agent(format!("rolled back: {restored}"));
    if restored.at_next_boot {
        // nothing has changed yet; the post-reboot inventory will show it
        return JobComplete {
            reboot_required: true,
            ..ended(JobStatus::Succeeded, started_at, Utc::now(), None)
        };
    }
    let changes = match (before, backend) {
        (Some(before), Some(b)) => match b.installed().await {
            Ok(after) => package_changes(&before, &after),
            Err(_) => vec![],
        },
        _ => vec![],
    };
    for c in &changes {
        log.agent(format!(
            "{} {}: {} -> {}",
            c.name,
            c.arch,
            or_none(&c.from),
            or_none(&c.to)
        ));
    }
    JobComplete {
        changes,
        ..ended(JobStatus::Succeeded, started_at, Utc::now(), None)
    }
}

/// Refuses a rollback that would remove a kernel still present on a separate
/// `/boot`, since the host could then boot a kernel with no modules. Also
/// refuses if that can't be determined.
async fn takes_a_kernel_from_boot(
    provider: &dyn SnapshotProvider,
    id: &str,
    rebooter: &dyn Rebooter,
) -> Option<String> {
    if !rebooter.boot_is_separate().await {
        return None;
    }
    match provider.kernels_rolled_away(id).await {
        Ok(kernels) if kernels.is_empty() => None,
        Ok(kernels) => Some(format!(
            "rolling back would remove kernel {} from / and not from /boot, which is its own filesystem; \
             the host could boot a kernel whose modules are gone, so nothing was changed",
            kernels.join(", ")
        )),
        Err(error) => Some(format!(
            "could not tell whether rolling back would remove a kernel /boot still holds \
             (/boot is its own filesystem), so nothing was changed: {error}"
        )),
    }
}

fn or_none(version: &str) -> &str {
    if version.is_empty() {
        "(none)"
    } else {
        version
    }
}

/// Diffs two package lists by name and architecture. A package missing on
/// one side gets an empty version there.
fn package_changes(before: &[InstalledPackage], after: &[InstalledPackage]) -> Vec<PackageChange> {
    use std::collections::BTreeMap;
    let index = |list: &[InstalledPackage]| -> BTreeMap<(String, String), String> {
        list.iter()
            .map(|p| ((p.name.clone(), p.arch.clone()), p.version.clone()))
            .collect()
    };
    let (before, after) = (index(before), index(after));
    let mut keys: Vec<&(String, String)> = before.keys().chain(after.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter_map(|key| {
            let from = before.get(key).cloned().unwrap_or_default();
            let to = after.get(key).cloned().unwrap_or_default();
            (from != to).then(|| PackageChange {
                name: key.0.clone(),
                arch: key.1.clone(),
                from,
                to,
            })
        })
        .collect()
}

/// Whether to reboot now. Never after a failure: rebooting a host in an
/// unknown state could leave it unbootable, so that's left to a person.
fn wants_reboot(policy: RebootPolicy, done: &JobComplete) -> bool {
    done.status == JobStatus::Succeeded
        && match policy {
            RebootPolicy::Never => false,
            RebootPolicy::IfRequired => done.reboot_required,
            RebootPolicy::Always => true,
        }
}

/// Saves the report, then requests the reboot. On `Err` nothing is left
/// pending.
async fn reboot(
    job: &Job,
    done: &JobComplete,
    state: &LocalState,
    rebooter: &dyn Rebooter,
    warning: &crate::config::RebootSettings,
) -> Result<(), String> {
    let Some(boot_id) = rebooter.boot_id() else {
        return Err("this host has no boot id to tell a reboot by, so it did not reboot".into());
    };
    // write first; the reboot may happen before this function returns
    state
        .set_pending_reboot(&crate::state::PendingReboot {
            job: job.clone(),
            report: done.clone(),
            boot_id_before: boot_id,
        })
        .map_err(|e| format!("could not record the pending reboot, so did not reboot: {e}"))?;
    tracing::warn!(job = %job.id, delay_s = warning.delay_s(), "rebooting to finish the job");
    if let Err(error) = rebooter.reboot(warning.delay_s(), &warning.message).await {
        let _ = state.take_pending_reboot();
        return Err(format!("could not reboot: {error:#}"));
    }
    Ok(())
}

async fn checks_reported(job: &Job, checks: &[Check], log: &JobLog) -> Vec<HealthCheckReport> {
    health::run_all(checks)
        .await
        .into_iter()
        .map(|r| {
            if r.passed {
                log.agent(format!("health check {}: passed", r.name));
            } else {
                tracing::warn!(job = %job.id, check = %r.name, detail = ?r.detail, "health check failed");
                log.agent(format!(
                    "health check {}: FAILED{}",
                    r.name,
                    r.detail.as_deref().map(|d| format!(" ({d})")).unwrap_or_default()
                ));
            }
            HealthCheckReport {
                name: r.name,
                passed: r.passed,
                duration_ms: u64::try_from(r.duration.as_millis()).unwrap_or(u64::MAX),
                detail: r.detail,
            }
        })
        .collect()
}

fn report(
    job: &Job,
    started_at: DateTime<Utc>,
    outcome: updawg_backends::Result<updawg_backends::ApplyOutcome>,
) -> JobComplete {
    let finished_at = Utc::now();
    match outcome {
        Ok(outcome) => {
            tracing::info!(job = %job.id, changed = outcome.changed.len(), "applied");
            JobComplete {
                status: JobStatus::Succeeded,
                started_at,
                finished_at,
                snapshot_id: None,
                changes: outcome
                    .changed
                    .into_iter()
                    .map(|c| PackageChange {
                        name: c.name,
                        arch: c.arch,
                        from: c.from,
                        to: c.to,
                    })
                    .collect(),
                health_checks: vec![],
                reboot_required: outcome.reboot_required,
                inventory_hash: None,
                error: None,
                preflight: vec![],
            }
        }
        // nothing changed: the plan couldn't be applied as approved
        Err(BackendError::Refused(why)) => {
            failed(JobStatus::RejectedByHost, started_at, finished_at, why)
        }
        Err(error) => failed(
            JobStatus::Failed,
            started_at,
            finished_at,
            error.to_string(),
        ),
    }
}

fn failed(
    status: JobStatus,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    error: String,
) -> JobComplete {
    ended(status, started_at, finished_at, Some(error))
}

fn ended(
    status: JobStatus,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    error: Option<String>,
) -> JobComplete {
    JobComplete {
        status,
        started_at,
        finished_at,
        snapshot_id: None,
        changes: vec![],
        health_checks: vec![],
        reboot_required: false,
        inventory_hash: None,
        error,
        preflight: vec![],
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::{checkin::JobSink as _, state::Identity};
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
    use base64::Engine as _;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use updawg_backends::{ApplyOutcome, Change, LogSink, PendingChanges};
    use updawg_protocol::{
        AvailableUpdate, Ecosystem, HostId, InstalledPackage, JobId, OrgSigningKey, Repository,
        SigningKeyId, SigningKeyStatus,
        job::{ApplyUpdates, PackagePin},
    };

    const HOST: &str = "hst_0190a0de000070008000000000000002";
    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[derive(Default)]
    struct Gateway {
        acks: std::sync::Mutex<Vec<JobAck>>,
        completes: std::sync::Mutex<Vec<JobComplete>>,
        logged: std::sync::Mutex<Vec<updawg_protocol::LogLine>>,
        logged_after_complete: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl Reporter for Gateway {
        async fn ack(&self, _job: &Job, ack: &JobAck) -> anyhow::Result<()> {
            self.acks.lock().unwrap().push(ack.clone());
            Ok(())
        }
        async fn complete(&self, _job: &Job, done: &JobComplete) -> anyhow::Result<()> {
            self.completes.lock().unwrap().push(done.clone());
            Ok(())
        }
        async fn logs(&self, _job: &Job, ndjson: String) -> anyhow::Result<bool> {
            if !self.completes.lock().unwrap().is_empty() {
                self.logged_after_complete.store(true, Ordering::SeqCst);
            }
            self.logged
                .lock()
                .unwrap()
                .extend(updawg_protocol::LogLine::from_ndjson(&ndjson)?);
            Ok(true)
        }
    }

    /// Fake package manager; `apply` returns `outcome`.
    struct Backend {
        outcome: fn(&ApplyPlan) -> updawg_backends::Result<ApplyOutcome>,
        applied: AtomicUsize,
        packages: std::sync::Mutex<Vec<InstalledPackage>>,
        /// Target of a leapp-style upgrade that completes at reboot.
        upgrades_at_reboot: std::sync::Mutex<Option<String>>,
    }

    #[async_trait]
    impl PackageBackend for Backend {
        fn ecosystem(&self) -> Ecosystem {
            Ecosystem::Deb
        }
        async fn installed(&self) -> updawg_backends::Result<Vec<InstalledPackage>> {
            Ok(self.packages.lock().unwrap().clone())
        }
        async fn refresh_metadata(&self) -> updawg_backends::Result<()> {
            Ok(())
        }
        async fn pending_changes(&self) -> updawg_backends::Result<PendingChanges> {
            Ok(PendingChanges::default())
        }
        async fn repositories(&self) -> updawg_backends::Result<Vec<Repository>> {
            Ok(vec![])
        }
        async fn held_packages(&self) -> updawg_backends::Result<Vec<String>> {
            Ok(vec![])
        }
        async fn security_updates(
            &self,
            _updates: &[AvailableUpdate],
        ) -> updawg_backends::Result<std::collections::BTreeSet<String>> {
            Ok(std::collections::BTreeSet::new())
        }
        async fn apply(
            &self,
            plan: &ApplyPlan,
            log: &dyn LogSink,
        ) -> updawg_backends::Result<ApplyOutcome> {
            self.applied.fetch_add(1, Ordering::SeqCst);
            log.line("Unpacking openssl (3.5.1-2) over (3.5.1-1) ...");
            log.line("Setting up openssl (3.5.1-2) ...");
            (self.outcome)(plan)
        }
        fn upgrade_finishes_at_reboot(&self) -> bool {
            self.upgrades_at_reboot.lock().unwrap().is_some()
        }
        async fn dist_upgrade(
            &self,
            target: &str,
            _log: &dyn LogSink,
        ) -> updawg_backends::Result<ApplyOutcome> {
            let Some(release) = self.upgrades_at_reboot.lock().unwrap().clone() else {
                return Err(BackendError::Refused("not built".into()));
            };
            assert_eq!(release, target);
            Ok(ApplyOutcome {
                changed: vec![],
                reboot_required: true,
                after_reboot: Some(updawg_backends::leapp_upgrade::AfterReboot {
                    release,
                    before: self.packages.lock().unwrap().clone(),
                }),
            })
        }
    }

    // signature has to match `Backend::outcome`
    #[allow(clippy::unnecessary_wraps)]
    fn succeeds(plan: &ApplyPlan) -> updawg_backends::Result<ApplyOutcome> {
        Ok(ApplyOutcome {
            changed: plan
                .packages
                .iter()
                .map(|p| Change {
                    name: p.name.clone(),
                    arch: p.arch.clone(),
                    from: p.from.clone(),
                    to: p.to.clone(),
                })
                .collect(),
            reboot_required: false,
            after_reboot: None,
        })
    }

    fn refuses(_plan: &ApplyPlan) -> updawg_backends::Result<ApplyOutcome> {
        Err(BackendError::Refused(
            "openssl is at 3.5.0-9, and the job was approved for 3.5.1-1 to 3.5.1-2".into(),
        ))
    }

    struct World {
        key: Ed25519KeyPair,
        gateway: Arc<Gateway>,
        backend: Arc<Backend>,
        executor: Executor,
    }

    fn world(
        mode: &str,
        outcome: fn(&ApplyPlan) -> updawg_backends::Result<ApplyOutcome>,
    ) -> World {
        world_with(mode, outcome, "")
    }

    /// Like [`world`], with extra `agent.toml` appended.
    fn world_with(
        mode: &str,
        outcome: fn(&ApplyPlan) -> updawg_backends::Result<ApplyOutcome>,
        extra_toml: &str,
    ) -> World {
        world_allowing(mode, outcome, extra_toml, "\"apply_patch\"")
    }

    /// Like [`world_with`], with a `[permissions] allow` list.
    fn world_allowing(
        mode: &str,
        outcome: fn(&ApplyPlan) -> updawg_backends::Result<ApplyOutcome>,
        extra_toml: &str,
        allow: &str,
    ) -> World {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let key =
            Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref())
                .unwrap();
        let mut spki = updawg_crypto::ED25519_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(key.public_key().as_ref());

        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("updawg-jobs-test-{}-{n}", std::process::id()));
        let state = LocalState::new(&dir);
        state.ensure().unwrap();
        state
            .save_identity(&Identity {
                host_id: HostId::new(HOST),
                certificate: String::new(),
                ca_chain: vec![],
                org_signing_keys: vec![OrgSigningKey {
                    key_id: SigningKeyId::new("sk_a"),
                    public_key: format!(
                        "ed25519:{}",
                        base64::engine::general_purpose::STANDARD.encode(&spki)
                    ),
                    status: SigningKeyStatus::Active,
                    endorsement: None,
                }],
                enrolled_at: "2026-09-26T00:00:00Z".into(),
            })
            .unwrap();
        let config = AgentConfig::from_toml(&format!(
            "server = \"https://agents.example\"\nmode = \"{mode}\"\n[permissions]\nallow = [{allow}]\n{extra_toml}"
        ))
        .unwrap();
        let gateway = Arc::new(Gateway::default());
        let backend = Arc::new(Backend {
            outcome,
            applied: AtomicUsize::new(0),
            packages: std::sync::Mutex::default(),
            upgrades_at_reboot: std::sync::Mutex::default(),
        });
        let executor = Executor::new(
            Arc::clone(&gateway) as Arc<dyn Reporter>,
            state,
            config,
            Some(Arc::clone(&backend) as Arc<dyn PackageBackend>),
            None,
        );
        World {
            key,
            gateway,
            backend,
            executor,
        }
    }

    fn job(w: &World, edit: impl FnOnce(&mut Job)) -> Job {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let mut job = Job {
            id: JobId::new(format!("job_0190a0de00007000800000000000{n:04}")),
            host_id: HostId::new(HOST),
            spec: JobSpec::ApplyUpdates(ApplyUpdates {
                packages: vec![PackagePin {
                    name: "openssl".into(),
                    arch: "amd64".into(),
                    from: "3.5.1-1".into(),
                    to: "3.5.1-2".into(),
                }],
                ..ApplyUpdates::default()
            }),
            not_before: None,
            expires_at: Utc::now() + Duration::hours(1),
            key_id: SigningKeyId::new("sk_a"),
            signature: String::new(),
        };
        edit(&mut job);
        job.signature = base64::engine::general_purpose::STANDARD
            .encode(w.key.sign(&job.signing_bytes().unwrap()).as_ref());
        job
    }

    /// Wait for the background run to report.
    async fn completed(w: &World) -> JobComplete {
        for _ in 0..200 {
            if let Some(done) = w.gateway.completes.lock().unwrap().first().cloned() {
                return done;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the job never reported how it went");
    }

    fn refusals(w: &World) -> Vec<String> {
        w.gateway
            .acks
            .lock()
            .unwrap()
            .iter()
            .filter(|a| !a.accepted)
            .map(|a| a.rejection_reason.clone().unwrap_or_default())
            .collect()
    }

    #[tokio::test]
    async fn a_genuine_permitted_job_is_acknowledged_run_and_reported_once() {
        let w = world("managed", succeeds);
        let job = job(&w, |_| {});
        w.executor.deliver(job.clone()).await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::Succeeded);
        assert_eq!(done.changes[0].to, "3.5.1-2");
        assert!(w.gateway.acks.lock().unwrap()[0].accepted);

        // redelivered (replay, or a racing check-in)
        w.executor.deliver(job).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(w.gateway.acks.lock().unwrap().len(), 1);
        assert_eq!(w.backend.applied.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn observe_mode_refuses_and_touches_nothing() {
        let w = world("observe", succeeds);
        w.executor.deliver(job(&w, |_| {})).await;
        let refused = refusals(&w);
        assert_eq!(refused.len(), 1);
        assert!(refused[0].contains("observe mode"), "{refused:?}");
        assert_eq!(w.backend.applied.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_job_that_is_not_genuinely_this_hosts_is_refused() {
        let w = world("managed", succeeds);

        // Edited after signing.
        let mut tampered = job(&w, |_| {});
        if let JobSpec::ApplyUpdates(ref mut p) = tampered.spec {
            p.packages[0].to = "3.5.1-99".into();
        }
        w.executor.deliver(tampered).await;
        // Signed for another host.
        w.executor
            .deliver(job(&w, |j| j.host_id = HostId::new("hst_somebody_else")))
            .await;
        // Expired.
        w.executor
            .deliver(job(&w, |j| {
                j.expires_at = Utc::now() - Duration::minutes(1);
            }))
            .await;
        // Hours early.
        w.executor
            .deliver(job(&w, |j| {
                j.not_before = Some(Utc::now() + Duration::hours(3));
            }))
            .await;

        let refused = refusals(&w);
        assert_eq!(refused.len(), 4, "{refused:?}");
        assert!(refused[0].contains("does not verify"), "{}", refused[0]);
        assert!(refused[1].contains("hst_somebody_else"), "{}", refused[1]);
        assert!(refused[2].contains("expired"), "{}", refused[2]);
        assert!(refused[3].contains("may not start"), "{}", refused[3]);
        assert_eq!(w.backend.applied.load(Ordering::SeqCst), 0);
    }

    /// The installed version changed after approval.
    #[tokio::test]
    async fn a_plan_that_cannot_be_carried_out_as_approved_is_reported_as_refused() {
        let w = world("managed", refuses);
        w.executor.deliver(job(&w, |_| {})).await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::RejectedByHost);
        assert!(done.changes.is_empty());
        assert!(done.error.unwrap().contains("3.5.0-9"));
    }

    const CHECKS: &str = r#"
[[health_check]]
name = "always fine"
type = "command"
argv = ["true"]

[[health_check]]
name = "the app"
type = "command"
argv = ["sh", "-c", "echo app is down >&2; exit 1"]
"#;

    /// A failing check doesn't change the job status; the packages did
    /// install.
    #[tokio::test]
    async fn health_checks_run_after_a_job_and_a_failure_is_reported_beside_it() {
        let w = world_with("managed", succeeds, CHECKS);
        w.executor.deliver(job(&w, |_| {})).await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::Succeeded);
        let checks: Vec<(&str, bool)> = done
            .health_checks
            .iter()
            .map(|c| (c.name.as_str(), c.passed))
            .collect();
        assert_eq!(checks, [("always fine", true), ("the app", false)]);
        assert_eq!(
            done.health_checks[1].detail.as_deref(),
            Some("exited 1: app is down")
        );
    }

    #[tokio::test]
    async fn a_refused_job_runs_no_health_checks() {
        let w = world_with("managed", refuses, CHECKS);
        w.executor.deliver(job(&w, |_| {})).await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::RejectedByHost);
        assert!(done.health_checks.is_empty());
    }

    /* ------------------------------------------------------------ rebooting */

    /// Counts reboot requests. Tests simulate a reboot by changing the boot
    /// id.
    struct FakeRebooter {
        boot_id: std::sync::Mutex<String>,
        requested: AtomicUsize,
        still_required: bool,
        fail: bool,
        separate_boot: bool,
    }

    impl FakeRebooter {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                boot_id: std::sync::Mutex::new("boot-1".into()),
                requested: AtomicUsize::new(0),
                still_required: false,
                fail: false,
                separate_boot: false,
            })
        }
    }

    #[async_trait]
    impl Rebooter for FakeRebooter {
        fn boot_id(&self) -> Option<String> {
            Some(self.boot_id.lock().unwrap().clone())
        }
        async fn reboot_required(&self) -> bool {
            self.still_required
        }
        async fn reboot(&self, delay_s: u64, message: &str) -> anyhow::Result<()> {
            assert!(delay_s >= 60, "rebooted without warning anybody");
            assert!(!message.is_empty());
            self.requested.fetch_add(1, Ordering::SeqCst);
            anyhow::ensure!(!self.fail, "shutdown: permission denied");
            Ok(())
        }
        async fn boot_is_separate(&self) -> bool {
            self.separate_boot
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    fn needs_reboot(plan: &ApplyPlan) -> updawg_backends::Result<ApplyOutcome> {
        let mut outcome = succeeds(plan)?;
        outcome.reboot_required = true;
        Ok(outcome)
    }

    const ALLOW_REBOOT: &str = "\"apply_patch\", \"reboot\"";

    fn rebooting(w: &World, policy: RebootPolicy) -> Job {
        job(w, |j| {
            if let JobSpec::ApplyUpdates(apply) = &mut j.spec {
                apply.reboot = policy;
            }
        })
    }

    /// Wait for the background run to either report or ask to reboot.
    async fn settled(w: &World, rebooter: &FakeRebooter) {
        for _ in 0..200 {
            if !w.gateway.completes.lock().unwrap().is_empty()
                || rebooter.requested.load(Ordering::SeqCst) > 0
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the job neither reported nor rebooted");
    }

    #[tokio::test]
    async fn a_job_that_needs_a_reboot_reboots_and_reports_from_the_other_side() {
        let rebooter = FakeRebooter::new();
        let mut w = world_allowing("managed", needs_reboot, CHECKS, ALLOW_REBOOT);
        w.executor = w
            .executor
            .with_rebooter(Arc::clone(&rebooter) as Arc<dyn Rebooter>);
        w.executor
            .deliver(rebooting(&w, RebootPolicy::IfRequired))
            .await;
        settled(&w, &rebooter).await;

        // nothing reported until the host comes back
        assert_eq!(rebooter.requested.load(Ordering::SeqCst), 1);
        assert!(w.gateway.completes.lock().unwrap().is_empty());

        // reboot, agent restarts
        *rebooter.boot_id.lock().unwrap() = "boot-2".into();
        w.executor.resume_after_reboot().await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::Succeeded);
        assert_eq!(done.changes[0].to, "3.5.1-2");
        assert!(!done.reboot_required, "the reboot happened");
        assert_eq!(
            done.health_checks.len(),
            2,
            "the checks ran again after the reboot"
        );

        w.executor.resume_after_reboot().await;
        assert_eq!(w.gateway.completes.lock().unwrap().len(), 1);
    }

    /// A signed leapp-style upgrade job to `release`.
    fn upgrading_at_reboot(w: &World, release: &str, policy: RebootPolicy) -> Job {
        *w.backend.upgrades_at_reboot.lock().unwrap() = Some(release.to_owned());
        job(w, |j| {
            j.spec = JobSpec::DistUpgrade(updawg_protocol::job::DistUpgrade {
                target_release: release.to_owned(),
                snapshot: SnapshotPolicy::Never,
                reboot: policy,
                timeout_s: 14_400,
            });
        })
    }

    const ALLOW_UPGRADE: &str = "\"dist_upgrade\", \"reboot\"";

    #[tokio::test]
    async fn a_release_upgrade_the_reboot_carries_out_is_refused_when_the_job_may_not_reboot() {
        let rebooter = FakeRebooter::new();
        let mut w = world_allowing("managed", succeeds, "", ALLOW_UPGRADE);
        w.executor = w
            .executor
            .with_rebooter(Arc::clone(&rebooter) as Arc<dyn Rebooter>);
        w.executor
            .deliver(upgrading_at_reboot(&w, "99", RebootPolicy::Never))
            .await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::RejectedByHost);
        assert!(done.error.unwrap().contains("may not reboot"));
        assert_eq!(rebooter.requested.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_release_upgrade_the_reboot_carries_out_is_judged_once_the_host_is_back() {
        // came back on the old release
        let rebooter = FakeRebooter::new();
        let mut w = world_allowing("managed", succeeds, CHECKS, ALLOW_UPGRADE);
        w.executor = w
            .executor
            .with_rebooter(Arc::clone(&rebooter) as Arc<dyn Rebooter>);
        w.executor
            .deliver(upgrading_at_reboot(&w, "99", RebootPolicy::IfRequired))
            .await;
        settled(&w, &rebooter).await;
        assert_eq!(rebooter.requested.load(Ordering::SeqCst), 1);
        assert!(
            w.gateway.completes.lock().unwrap().is_empty(),
            "nothing to report until the host is back"
        );
        *rebooter.boot_id.lock().unwrap() = "boot-2".into();
        w.executor.resume_after_reboot().await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::Failed);
        assert!(done.error.unwrap().contains("not 99"));
        assert_eq!(done.health_checks.len(), 2, "checked after the reboot");

        // Use this machine's own release as the target, since that's what
        // the host will appear to have come back on.
        let Ok(here) = updawg_backends::release::this_host() else {
            return;
        };
        let major = here.version.split('.').next().unwrap().to_owned();
        let rebooter = FakeRebooter::new();
        let mut w = world_allowing("managed", succeeds, "", ALLOW_UPGRADE);
        w.executor = w
            .executor
            .with_rebooter(Arc::clone(&rebooter) as Arc<dyn Rebooter>);
        let package = |version: &str| InstalledPackage {
            name: "bash".into(),
            version: version.into(),
            arch: "x86_64".into(),
            repo: None,
            source: None,
            module: None,
        };
        *w.backend.packages.lock().unwrap() = vec![package("4.4")];
        w.executor
            .deliver(upgrading_at_reboot(&w, &major, RebootPolicy::IfRequired))
            .await;
        settled(&w, &rebooter).await;
        *w.backend.packages.lock().unwrap() = vec![package("5.1")];
        *rebooter.boot_id.lock().unwrap() = "boot-2".into();
        w.executor.resume_after_reboot().await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::Succeeded, "{:?}", done.error);
        assert_eq!(done.changes.len(), 1);
        assert_eq!(
            (done.changes[0].from.as_str(), done.changes[0].to.as_str()),
            ("4.4", "5.1")
        );
    }

    #[tokio::test]
    async fn an_agent_that_restarted_without_a_reboot_says_so_rather_than_waiting_for_ever() {
        let rebooter = FakeRebooter::new();
        let mut w = world_allowing("managed", needs_reboot, "", ALLOW_REBOOT);
        w.executor = w
            .executor
            .with_rebooter(Arc::clone(&rebooter) as Arc<dyn Rebooter>);
        w.executor
            .deliver(rebooting(&w, RebootPolicy::Always))
            .await;
        settled(&w, &rebooter).await;

        // same boot id: only the agent restarted
        w.executor.resume_after_reboot().await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::Failed);
        assert!(done.error.unwrap().contains("has not rebooted"));
    }

    #[tokio::test]
    async fn if_required_does_not_reboot_a_host_that_does_not_need_it() {
        let rebooter = FakeRebooter::new();
        let mut w = world_allowing("managed", succeeds, "", ALLOW_REBOOT);
        w.executor = w
            .executor
            .with_rebooter(Arc::clone(&rebooter) as Arc<dyn Rebooter>);
        w.executor
            .deliver(rebooting(&w, RebootPolicy::IfRequired))
            .await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::Succeeded);
        assert_eq!(rebooter.requested.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_host_that_does_not_permit_reboots_refuses_a_job_that_might() {
        let rebooter = FakeRebooter::new();
        let mut w = world_with("managed", needs_reboot, "");
        w.executor = w
            .executor
            .with_rebooter(Arc::clone(&rebooter) as Arc<dyn Rebooter>);
        w.executor
            .deliver(rebooting(&w, RebootPolicy::IfRequired))
            .await;
        let why = refusals(&w);
        assert_eq!(why.len(), 1);
        assert!(why[0].contains("does not permit reboot"), "{why:?}");
        assert_eq!(w.backend.applied.load(Ordering::SeqCst), 0);
        assert_eq!(rebooter.requested.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_failed_install_is_never_followed_by_a_reboot() {
        fn fails(_plan: &ApplyPlan) -> updawg_backends::Result<ApplyOutcome> {
            Err(BackendError::CommandFailed {
                tool: "apt-get",
                status: 100,
                stderr: "dpkg was interrupted".into(),
            })
        }
        let rebooter = FakeRebooter::new();
        let mut w = world_allowing("managed", fails, "", ALLOW_REBOOT);
        w.executor = w
            .executor
            .with_rebooter(Arc::clone(&rebooter) as Arc<dyn Rebooter>);
        w.executor
            .deliver(rebooting(&w, RebootPolicy::Always))
            .await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::Failed);
        assert_eq!(rebooter.requested.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_reboot_that_cannot_be_asked_for_is_reported_and_leaves_nothing_pending() {
        let rebooter = Arc::new(FakeRebooter {
            fail: true,
            ..Arc::try_unwrap(FakeRebooter::new()).ok().unwrap()
        });
        let mut w = world_allowing("managed", needs_reboot, "", ALLOW_REBOOT);
        w.executor = w
            .executor
            .with_rebooter(Arc::clone(&rebooter) as Arc<dyn Rebooter>);
        w.executor
            .deliver(rebooting(&w, RebootPolicy::Always))
            .await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::Failed);
        assert!(done.error.unwrap().contains("could not reboot"));
        assert!(w.executor.state.take_pending_reboot().unwrap().is_none());
    }

    /* ---------------------------------------------- a reboot job of its own */

    fn reboot_job(w: &World) -> Job {
        job(w, |j| {
            j.spec = JobSpec::Reboot(updawg_protocol::Reboot {
                policy: RebootPolicy::IfRequired,
                ..updawg_protocol::Reboot::default()
            });
        })
    }

    fn still_needing_a_reboot() -> Arc<FakeRebooter> {
        Arc::new(FakeRebooter {
            boot_id: std::sync::Mutex::new("boot-1".into()),
            requested: AtomicUsize::new(0),
            still_required: true,
            fail: false,
            separate_boot: false,
        })
    }

    #[tokio::test]
    async fn a_reboot_job_reboots_a_host_that_needs_it_and_installs_nothing() {
        let rebooter = still_needing_a_reboot();
        let mut w = world_allowing("managed", succeeds, CHECKS, ALLOW_REBOOT);
        w.executor = w
            .executor
            .with_rebooter(Arc::clone(&rebooter) as Arc<dyn Rebooter>);
        w.executor.deliver(reboot_job(&w)).await;
        settled(&w, &rebooter).await;
        assert_eq!(rebooter.requested.load(Ordering::SeqCst), 1);
        assert_eq!(w.backend.applied.load(Ordering::SeqCst), 0);
        assert!(w.gateway.completes.lock().unwrap().is_empty());

        *rebooter.boot_id.lock().unwrap() = "boot-2".into();
        w.executor.resume_after_reboot().await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::Succeeded);
        assert!(done.changes.is_empty());
        assert_eq!(done.health_checks.len(), 2, "the checks ran after it");
    }

    /// `if_required` on a host that was already rebooted some other way.
    #[tokio::test]
    async fn a_reboot_job_leaves_a_host_that_no_longer_needs_one_alone() {
        let rebooter = FakeRebooter::new();
        let mut w = world_allowing("managed", succeeds, "", ALLOW_REBOOT);
        w.executor = w
            .executor
            .with_rebooter(Arc::clone(&rebooter) as Arc<dyn Rebooter>);
        w.executor.deliver(reboot_job(&w)).await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::Succeeded);
        assert!(!done.reboot_required);
        assert_eq!(rebooter.requested.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_host_that_does_not_permit_reboots_refuses_a_reboot_job() {
        let rebooter = still_needing_a_reboot();
        let mut w = world_with("managed", succeeds, "");
        w.executor = w
            .executor
            .with_rebooter(Arc::clone(&rebooter) as Arc<dyn Rebooter>);
        w.executor.deliver(reboot_job(&w)).await;
        let why = refusals(&w);
        assert_eq!(why.len(), 1);
        assert!(why[0].contains("does not permit reboot"), "{why:?}");
        assert_eq!(rebooter.requested.load(Ordering::SeqCst), 0);
    }

    /* ------------------------------------------------------ the job's log */

    /// Package manager output is sent in sequence, interleaved with the
    /// agent's lines, and all of it before the report.
    #[tokio::test]
    async fn a_jobs_output_is_streamed_before_its_report() {
        let w = world_with("managed", succeeds, CHECKS);
        w.executor.deliver(job(&w, |_| {})).await;
        completed(&w).await;

        let lines = w.gateway.logged.lock().unwrap().clone();
        let seqs: Vec<u64> = lines.iter().map(|l| l.seq).collect();
        assert_eq!(
            seqs,
            (0..seqs.len() as u64).collect::<Vec<_>>(),
            "{lines:#?}"
        );
        let text: Vec<&str> = lines.iter().map(|l| l.line.as_str()).collect();
        assert!(
            text.contains(&"Setting up openssl (3.5.1-2) ..."),
            "{text:#?}"
        );
        assert!(
            text.iter().any(|l| l.starts_with("health check")),
            "{text:#?}"
        );
        assert!(text.last().unwrap().starts_with("done:"), "{text:#?}");
        assert_eq!(
            lines
                .iter()
                .find(|l| l.line.starts_with("Setting up"))
                .unwrap()
                .stream,
            updawg_protocol::LogStream::Stdout
        );
        assert!(
            !w.gateway.logged_after_complete.load(Ordering::SeqCst),
            "a log batch arrived after the report"
        );
    }

    #[tokio::test]
    async fn the_log_carries_on_after_a_reboot() {
        let rebooter = FakeRebooter::new();
        let mut w = world_allowing("managed", needs_reboot, "", ALLOW_REBOOT);
        w.executor = w
            .executor
            .with_rebooter(Arc::clone(&rebooter) as Arc<dyn Rebooter>);
        w.executor
            .deliver(rebooting(&w, RebootPolicy::IfRequired))
            .await;
        settled(&w, &rebooter).await;
        // flushed before the reboot
        assert!(
            w.gateway
                .logged
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.line.starts_with("rebooting"))
        );

        *rebooter.boot_id.lock().unwrap() = "boot-2".into();
        w.executor.resume_after_reboot().await;
        completed(&w).await;
        let lines = w.gateway.logged.lock().unwrap().clone();
        let resumed = lines
            .iter()
            .find(|l| l.line.starts_with("rebooted"))
            .expect("a line from after the reboot");
        assert!(resumed.seq >= crate::joblog::AFTER_REBOOT, "{resumed:?}");
    }

    /* ----------------------------------------------------------- snapshots */

    const ALLOW_SNAPSHOT: &str = "\"apply_patch\", \"snapshot\"";

    /// Restores the files it covers on rollback: the agent's job records and
    /// the package list.
    struct FakeSnapshots {
        state_dir: std::path::PathBuf,
        backend: Arc<Backend>,
        fail_create: bool,
        kernels: std::sync::Mutex<Vec<String>>,
        /// Like LVM.
        at_next_boot: std::sync::atomic::AtomicBool,
        carried_into: std::sync::Mutex<Vec<std::path::PathBuf>>,
        free: AtomicU64,
        taken: std::sync::Mutex<Vec<Taken>>,
        kept: std::sync::Mutex<Vec<usize>>,
        rolled_back: AtomicUsize,
    }

    struct Taken {
        id: String,
        seen_jobs: Option<Vec<u8>>,
        packages: Vec<InstalledPackage>,
    }

    #[async_trait]
    impl SnapshotProvider for FakeSnapshots {
        fn provider(&self) -> updawg_snapshots::Provider {
            updawg_snapshots::Provider::Snapper
        }
        async fn available(&self) -> Result<(), String> {
            Ok(())
        }
        async fn free_bytes(&self) -> updawg_snapshots::Result<u64> {
            Ok(self.free.load(Ordering::SeqCst))
        }
        async fn create(
            &self,
            description: &str,
            job: &str,
        ) -> updawg_snapshots::Result<updawg_snapshots::Snapshot> {
            if self.fail_create {
                return Err(updawg_snapshots::SnapshotError::InsufficientSpace {
                    detail: "1% free".into(),
                });
            }
            let mut taken = self.taken.lock().unwrap();
            let id = format!("snapper:{}:{job}", taken.len() + 1);
            taken.push(Taken {
                id: id.clone(),
                seen_jobs: std::fs::read(self.state_dir.join("seen-jobs.json")).ok(),
                packages: self.backend.packages.lock().unwrap().clone(),
            });
            Ok(updawg_snapshots::Snapshot {
                id,
                description: description.into(),
                job: job.into(),
                created: String::new(),
            })
        }
        async fn list(&self) -> updawg_snapshots::Result<Vec<updawg_snapshots::Snapshot>> {
            Ok(vec![])
        }
        async fn rollback(&self, id: &str) -> updawg_snapshots::Result<updawg_snapshots::Restored> {
            if self.at_next_boot.load(Ordering::SeqCst) {
                // LVM merges at next boot; nothing changes now
                self.rolled_back.fetch_add(1, Ordering::SeqCst);
                return Ok(updawg_snapshots::Restored {
                    at_next_boot: true,
                    ..updawg_snapshots::Restored::default()
                });
            }
            let taken = self.taken.lock().unwrap();
            let Some(Taken {
                seen_jobs,
                packages,
                ..
            }) = taken.iter().find(|t| t.id == id)
            else {
                return Err(updawg_snapshots::SnapshotError::NotFound { id: id.into() });
            };
            let file = self.state_dir.join("seen-jobs.json");
            match seen_jobs {
                Some(bytes) => std::fs::write(&file, bytes).unwrap(),
                None => std::fs::remove_file(&file).unwrap(),
            }
            self.backend.packages.lock().unwrap().clone_from(packages);
            self.rolled_back.fetch_add(1, Ordering::SeqCst);
            Ok(updawg_snapshots::Restored {
                modified: 1,
                ..updawg_snapshots::Restored::default()
            })
        }
        async fn prune(&self, keep: usize) -> updawg_snapshots::Result<Vec<String>> {
            self.kept.lock().unwrap().push(keep);
            Ok(vec![])
        }
        async fn kernels_rolled_away(&self, _id: &str) -> updawg_snapshots::Result<Vec<String>> {
            Ok(self.kernels.lock().unwrap().clone())
        }
        fn restores_at_next_boot(&self) -> bool {
            self.at_next_boot.load(Ordering::SeqCst)
        }
        async fn carry_into(
            &self,
            _id: &str,
            dir: &std::path::Path,
        ) -> updawg_snapshots::Result<()> {
            self.carried_into.lock().unwrap().push(dir.to_path_buf());
            Ok(())
        }
    }

    fn with_snapshots(w: World, fail_create: bool) -> (World, Arc<FakeSnapshots>) {
        let fake = Arc::new(FakeSnapshots {
            state_dir: w.executor.state.root().to_path_buf(),
            backend: Arc::clone(&w.backend),
            fail_create,
            kernels: std::sync::Mutex::default(),
            at_next_boot: std::sync::atomic::AtomicBool::new(false),
            carried_into: std::sync::Mutex::default(),
            free: AtomicU64::new(u64::MAX),
            taken: std::sync::Mutex::default(),
            kept: std::sync::Mutex::default(),
            rolled_back: AtomicUsize::new(0),
        });
        let World {
            key,
            gateway,
            backend,
            executor,
        } = w;
        let executor = executor.with_snapshots(Ok(Arc::clone(&fake) as Arc<dyn SnapshotProvider>));
        (
            World {
                key,
                gateway,
                backend,
                executor,
            },
            fake,
        )
    }

    fn snapshotting(w: &World, policy: SnapshotPolicy) -> Job {
        job(w, |j| {
            if let JobSpec::ApplyUpdates(apply) = &mut j.spec {
                apply.snapshot = policy;
            }
        })
    }

    /// Waits for the `n`th report.
    async fn report_number(w: &World, n: usize) -> JobComplete {
        for _ in 0..200 {
            if let Some(done) = w.gateway.completes.lock().unwrap().get(n).cloned() {
                return done;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("report {n} never came");
    }

    fn openssl(version: &str) -> InstalledPackage {
        InstalledPackage {
            name: "openssl".into(),
            version: version.into(),
            arch: "amd64".into(),
            repo: None,
            source: None,
            module: None,
        }
    }

    #[tokio::test]
    async fn a_snapshot_is_taken_before_the_install_and_its_id_reported() {
        let (w, snapshots) = with_snapshots(
            world_allowing("managed", succeeds, "[snapshots]\nkeep = 5", ALLOW_SNAPSHOT),
            false,
        );
        let job = snapshotting(&w, SnapshotPolicy::Required);
        w.executor.deliver(job.clone()).await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::Succeeded);
        assert_eq!(
            done.snapshot_id.as_deref(),
            Some(format!("snapper:1:{}", job.id).as_str())
        );
        assert_eq!(w.backend.applied.load(Ordering::SeqCst), 1);
        assert_eq!(*snapshots.kept.lock().unwrap(), [5]);
    }

    #[tokio::test]
    async fn a_required_snapshot_the_host_cannot_take_is_refused_before_anything_changes() {
        // No provider.
        let w = world_allowing("managed", succeeds, "", ALLOW_SNAPSHOT);
        w.executor
            .deliver(snapshotting(&w, SnapshotPolicy::Required))
            .await;
        // Not permitted.
        let (n, _) = with_snapshots(
            world_allowing("managed", succeeds, "", "\"apply_patch\""),
            false,
        );
        n.executor
            .deliver(snapshotting(&n, SnapshotPolicy::Required))
            .await;

        let (no_provider, not_permitted) = (refusals(&w), refusals(&n));
        assert!(
            no_provider[0].contains("cannot take one"),
            "{no_provider:?}"
        );
        assert!(
            not_permitted[0].contains("does not permit snapshot"),
            "{not_permitted:?}"
        );
        assert_eq!(w.backend.applied.load(Ordering::SeqCst), 0);
        assert_eq!(n.backend.applied.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_required_snapshot_that_fails_installs_nothing() {
        let (w, _) = with_snapshots(
            world_allowing("managed", succeeds, "", ALLOW_SNAPSHOT),
            true,
        );
        w.executor
            .deliver(snapshotting(&w, SnapshotPolicy::Required))
            .await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::RejectedByHost);
        assert!(done.error.unwrap().contains("nothing was changed"));
        assert_eq!(w.backend.applied.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn no_snapshot_is_taken_with_less_room_than_agent_toml_asks_for() {
        let (w, snapshots) = with_snapshots(
            world_allowing(
                "managed",
                succeeds,
                "[snapshots]\nmin_free_mb = 2048",
                ALLOW_SNAPSHOT,
            ),
            false,
        );
        snapshots.free.store(1024 * 1024 * 1024, Ordering::SeqCst);
        w.executor
            .deliver(snapshotting(&w, SnapshotPolicy::Required))
            .await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::RejectedByHost);
        let error = done.error.unwrap();
        assert!(error.contains("only 1024 MiB free"), "{error}");
        assert!(snapshots.taken.lock().unwrap().is_empty());
        assert_eq!(w.backend.applied.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn if_available_goes_ahead_without_one() {
        // No provider at all.
        let w = world_allowing("managed", succeeds, "", ALLOW_SNAPSHOT);
        w.executor
            .deliver(snapshotting(&w, SnapshotPolicy::IfAvailable))
            .await;
        // A provider that fails.
        let (f, _) = with_snapshots(
            world_allowing("managed", succeeds, "", ALLOW_SNAPSHOT),
            true,
        );
        f.executor
            .deliver(snapshotting(&f, SnapshotPolicy::IfAvailable))
            .await;
        for w in [&w, &f] {
            let done = completed(w).await;
            assert_eq!(done.status, JobStatus::Succeeded);
            assert_eq!(done.snapshot_id, None);
            assert_eq!(w.backend.applied.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn a_failed_install_still_reports_its_snapshot() {
        fn breaks(_plan: &ApplyPlan) -> updawg_backends::Result<ApplyOutcome> {
            Err(BackendError::CommandFailed {
                tool: "apt-get",
                status: 100,
                stderr: "dpkg: error processing package openssl".into(),
            })
        }
        let (w, _) = with_snapshots(world_allowing("managed", breaks, "", ALLOW_SNAPSHOT), false);
        w.executor
            .deliver(snapshotting(&w, SnapshotPolicy::IfAvailable))
            .await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::Failed);
        assert!(done.snapshot_id.is_some());
    }

    #[tokio::test]
    async fn a_snapshot_job_takes_one_and_says_which() {
        let (w, _) = with_snapshots(
            world_allowing("managed", succeeds, "", ALLOW_SNAPSHOT),
            false,
        );
        w.executor
            .deliver(job(&w, |j| {
                j.spec = JobSpec::Snapshot(updawg_protocol::Snapshot {
                    description: Some("before the migration".into()),
                });
            }))
            .await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::Succeeded, "{done:?}");
        assert!(done.snapshot_id.unwrap().starts_with("snapper:1:"));
        assert_eq!(done.error, None);
    }

    /// Install with a snapshot, then roll back. The rollback also restores
    /// the state directory, so the agent must carry its job records across.
    #[tokio::test]
    async fn a_rollback_restores_the_packages_and_the_agent_remembers_its_jobs() {
        let (w, snapshots) = with_snapshots(
            world_allowing("managed", succeeds, "", ALLOW_SNAPSHOT),
            false,
        );
        w.backend.packages.lock().unwrap().push(openssl("3.5.1-1"));

        let install = snapshotting(&w, SnapshotPolicy::Required);
        w.executor.deliver(install.clone()).await;
        let installed = completed(&w).await;
        *w.backend.packages.lock().unwrap() = vec![openssl("3.5.1-2")];

        let rollback = job(&w, |j| {
            j.spec = JobSpec::Rollback(updawg_protocol::Rollback {
                snapshot_id: installed.snapshot_id.clone().unwrap(),
            });
        });
        w.executor.deliver(rollback.clone()).await;
        let done = report_number(&w, 1).await;
        assert_eq!(done.status, JobStatus::Succeeded, "{done:?}");
        assert_eq!(snapshots.rolled_back.load(Ordering::SeqCst), 1);
        assert_eq!(done.changes.len(), 1, "{:?}", done.changes);
        assert_eq!(
            (done.changes[0].from.as_str(), done.changes[0].to.as_str()),
            ("3.5.1-2", "3.5.1-1")
        );
        // The snapshot predates the rollback job's record. Without carrying
        // state across, that job would be forgotten and could run again.
        assert!(w.executor.state.has_seen_job(&rollback.id).unwrap());
        assert!(w.executor.state.has_seen_job(&install.id).unwrap());
        w.executor.deliver(rollback).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(snapshots.rolled_back.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_rollback_to_another_providers_snapshot_is_refused() {
        let (w, snapshots) = with_snapshots(
            world_allowing("managed", succeeds, "", ALLOW_SNAPSHOT),
            false,
        );
        w.executor
            .deliver(job(&w, |j| {
                j.spec = JobSpec::Rollback(updawg_protocol::Rollback {
                    snapshot_id: "zfs:rpool/ROOT/debian@updawg-1".into(),
                });
            }))
            .await;
        let refused = refusals(&w);
        assert!(refused[0].contains("not a snapshot"), "{refused:?}");
        assert_eq!(snapshots.rolled_back.load(Ordering::SeqCst), 0);
    }

    /// With `/boot` on `/` the kernel is rolled back with everything else,
    /// so the rollback runs.
    #[tokio::test]
    async fn a_rollback_that_would_leave_boot_holding_a_kernel_without_modules_is_refused() {
        for separate in [true, false] {
            let (mut w, snapshots) = with_snapshots(
                world_allowing("managed", succeeds, "", ALLOW_SNAPSHOT),
                false,
            );
            let rebooter = Arc::new(FakeRebooter {
                separate_boot: separate,
                ..Arc::try_unwrap(FakeRebooter::new()).ok().unwrap()
            });
            w.executor = w
                .executor
                .with_rebooter(Arc::clone(&rebooter) as Arc<dyn Rebooter>);
            *snapshots.kernels.lock().unwrap() = vec!["6.12.48+deb13-amd64".into()];
            w.executor
                .deliver(snapshotting(&w, SnapshotPolicy::Required))
                .await;
            let installed = completed(&w).await;
            w.executor
                .deliver(job(&w, |j| {
                    j.spec = JobSpec::Rollback(updawg_protocol::Rollback {
                        snapshot_id: installed.snapshot_id.clone().unwrap(),
                    });
                }))
                .await;
            let done = report_number(&w, 1).await;
            if separate {
                assert_eq!(done.status, JobStatus::RejectedByHost, "{done:?}");
                assert!(done.error.unwrap().contains("6.12.48+deb13-amd64"));
                assert_eq!(snapshots.rolled_back.load(Ordering::SeqCst), 0);
            } else {
                assert_eq!(done.status, JobStatus::Succeeded, "{done:?}");
                assert_eq!(snapshots.rolled_back.load(Ordering::SeqCst), 1);
            }
        }
    }

    /// LVM rolls back at next boot: state is written into the snapshot
    /// first, and the report lists no changes yet.
    #[tokio::test]
    async fn a_rollback_at_the_next_boot_carries_the_agents_state_and_asks_for_a_reboot() {
        let (w, snapshots) = with_snapshots(
            world_allowing("managed", succeeds, "", ALLOW_SNAPSHOT),
            false,
        );
        snapshots.at_next_boot.store(true, Ordering::SeqCst);
        w.executor
            .deliver(snapshotting(&w, SnapshotPolicy::Required))
            .await;
        let installed = completed(&w).await;
        w.executor
            .deliver(job(&w, |j| {
                j.spec = JobSpec::Rollback(updawg_protocol::Rollback {
                    snapshot_id: installed.snapshot_id.clone().unwrap(),
                });
            }))
            .await;
        let done = report_number(&w, 1).await;
        assert_eq!(done.status, JobStatus::Succeeded, "{done:?}");
        assert!(done.reboot_required);
        assert!(done.changes.is_empty());
        assert_eq!(
            *snapshots.carried_into.lock().unwrap(),
            vec![w.executor.state.root().to_path_buf()]
        );
    }

    /// The fakes count every mutating call, and the state directory should
    /// gain nothing but the job's own records.
    #[tokio::test]
    async fn preflight_runs_in_observe_mode_and_changes_nothing() {
        let (mut w, snapshots) = with_snapshots(
            world_allowing("observe", succeeds, "", "\"preflight\""),
            false,
        );
        let rebooter = FakeRebooter::new();
        w.executor = w
            .executor
            .with_rebooter(Arc::clone(&rebooter) as Arc<dyn Rebooter>);
        let before: Vec<_> = std::fs::read_dir(w.executor.state.root())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();

        w.executor
            .deliver(job(&w, |j| {
                j.spec = JobSpec::RunPreflight(updawg_protocol::job::Preflight {
                    target_release: None,
                    packages: vec![PackagePin {
                        name: "openssl".into(),
                        arch: "amd64".into(),
                        from: "3.5.1-1".into(),
                        to: "3.5.1-2".into(),
                    }],
                });
            }))
            .await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::Succeeded, "{done:?}");
        let names: Vec<&str> = done.preflight.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "disk_space",
                "held_packages",
                "modified_conffiles",
                "dkms_modules",
                "snapshot",
                "reboot",
                // simulated only; `applied` stays at 0 below
                "approved_only"
            ]
        );
        assert_eq!(w.backend.applied.load(Ordering::SeqCst), 0);
        assert!(snapshots.taken.lock().unwrap().is_empty());
        assert_eq!(snapshots.rolled_back.load(Ordering::SeqCst), 0);
        assert!(snapshots.kept.lock().unwrap().is_empty(), "nothing pruned");
        assert_eq!(rebooter.requested.load(Ordering::SeqCst), 0);
        let mut after: Vec<_> = std::fs::read_dir(w.executor.state.root())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        // seen-jobs and the `updawgctl jobs` history, nothing else
        let own = |f: &std::ffi::OsString| f != "seen-jobs.json" && f != "job-history.json";
        after.retain(own);
        let mut before = before;
        before.retain(own);
        assert_eq!(after, before, "preflight left something behind");
    }

    #[test]
    fn package_changes_are_by_name_and_arch_both_ways() {
        let gone = InstalledPackage {
            name: "libfoo".into(),
            ..openssl("1.0")
        };
        let changes = package_changes(&[openssl("3.5.1-2"), gone], &[openssl("3.5.1-1")]);
        let pairs: Vec<_> = changes
            .iter()
            .map(|c| (c.name.as_str(), c.from.as_str(), c.to.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [("libfoo", "1.0", ""), ("openssl", "3.5.1-2", "3.5.1-1")]
        );
    }
}
