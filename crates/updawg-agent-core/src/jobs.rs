//! Running the jobs a check-in delivers (DAWG-38, DAWG-39, DAWG-102).
//!
//! Replaces `UnhandledJobs`, which logged every job and ran none. What happens
//! to one, in order — and every step before the last can only say no:
//!
//! 1. **Seen before?** A job id already recorded is ignored. The record is
//!    written *before* anything runs, so a crash halfway through an install
//!    cannot run it a second time on restart (DAWG-39).
//! 2. **Is it really a job for this host?** It names this host, it verifies
//!    under an organization key pinned at enrollment that may still sign, and
//!    that key is the one it names; it has not expired, and it is not early.
//! 3. **Does this host allow it?** Local configuration always wins: observe
//!    mode refuses every job that changes anything, and the deny list refuses
//!    what it names (DAWG-38). Refusing is a normal outcome, reported with a
//!    reason, and it halts the proposal for a person to look at.
//! 4. **Run it**, in the background and one at a time (DAWG-106), then say how
//!    it went and upload a fresh inventory so the server sees the new state.
//!
//! `apply_updates` and `reboot` run (DAWG-103). The others are refused as not
//! built, which is honest and halts rather than pretends.

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
    HealthCheckReport, Job, JobAck, JobComplete, JobKind, JobStatus, PackageChange,
    job::{JobSpec, RebootPolicy},
};

/// How far ahead of `not_before` a job may arrive and still be taken. The
/// gateway withholds a job until then, so this is only clock skew.
const EARLY: Duration = Duration::minutes(5);

/// Rebooting, behind a seam, because it is the one thing a test must never do
/// for real (DAWG-103).
#[async_trait]
pub trait Rebooter: Send + Sync {
    /// This boot's id. A different one after a reboot is the proof it happened.
    fn boot_id(&self) -> Option<String>;
    /// Whether the host still needs a reboot, as the distribution says.
    async fn reboot_required(&self) -> bool;
    /// Ask the system to reboot after `delay_s`, with `message` on terminals.
    async fn reboot(&self, delay_s: u64, message: &str) -> anyhow::Result<()>;
}

/// The real one: `shutdown -r`.
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
        // `shutdown` counts in minutes. Round up: a delay is a promise to the
        // people logged in, and it must not arrive early.
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
}

/// Where answers about jobs go. The gateway, in production.
#[async_trait]
pub trait Reporter: Send + Sync {
    async fn ack(&self, job: &Job, ack: &JobAck) -> anyhow::Result<()>;
    async fn complete(&self, job: &Job, done: &JobComplete) -> anyhow::Result<()>;
    /// A batch of the job's log, as NDJSON (DAWG-101). `Ok(false)` when it
    /// will never be taken, so the caller drops it rather than retrying.
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

/// Whether a delivered job is one this host should run, before asking what
/// the host allows. Pure, so every refusal is tested without a gateway.
///
/// # Errors
/// Why not, in words that go into the refusal.
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
    /// One mutating job at a time (DAWG-106).
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
            running: Arc::default(),
        }
    }

    /// Replace how this executor reboots. Tests, and nothing else.
    #[must_use]
    pub fn with_rebooter(mut self, rebooter: Arc<dyn Rebooter>) -> Self {
        self.rebooter = rebooter;
        self
    }

    /// Finish a job that rebooted the host (DAWG-103). Call once at startup.
    ///
    /// The boot id is the evidence: a different one means the host really
    /// did restart, and the health checks run again — those are the ones that
    /// matter — before the job is reported. The same one means the agent
    /// restarted and the host did not, which is reported as a failure rather
    /// than left hanging for ever.
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
        log.finish().await;
        done.reboot_required = self.rebooter.reboot_required().await;
        done.finished_at = Utc::now();
        if let Err(error) = self.reporter.complete(&job, &done).await {
            tracing::error!(job = %job.id, error = format!("{error:#}"), "could not report how the job went");
        }
        if let Some(inventory) = &self.inventory
            && let Err(error) = inventory.collect_and_upload().await
        {
            tracing::warn!(job = %job.id, error = format!("{error:#}"), "could not upload the inventory after the reboot");
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
        let ack = JobAck {
            accepted: false,
            rejection_reason: Some(reason),
            at: Utc::now(),
        };
        if let Err(error) = self.reporter.ack(job, &ack).await {
            tracing::error!(job = %job.id, error = format!("{error:#}"), "could not report a refusal");
        }
    }

    /// Why local configuration will not run this job, if it will not.
    ///
    /// Local configuration always wins (DAWG-38), rebooting included
    /// (DAWG-103): a job that may reboot is refused whole on a host that does
    /// not permit reboots — explicitly, before anything changes, rather than
    /// installing and then quietly skipping the part it was approved for.
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
        if let JobSpec::ApplyUpdates(apply) = &job.spec
            && apply.reboot != RebootPolicy::Never
            && !self.config.admits(JobKind::Reboot, None)
        {
            return Some(
                "the job may reboot this host, and local configuration does not permit reboot"
                    .to_owned(),
            );
        }
        None
    }

    /// Everything up to and including the acknowledgement. Returns what to
    /// run, or `None` when the job was ignored or refused.
    async fn admit(&self, job: &Job) -> Option<Work> {
        match self.state.has_seen_job(&job.id) {
            Ok(true) => {
                tracing::info!(job = %job.id, "already seen; ignoring");
                return None;
            }
            Ok(false) => {}
            Err(error) => {
                // Cannot tell whether this ran before, so it must not run now.
                self.refuse(
                    job,
                    format!("this host cannot read its record of jobs it has run: {error}"),
                )
                .await;
                return None;
            }
        }
        // ⚠️ Recorded before anything else, refusals included: a job this host
        // has answered is answered, and a crash from here on must not bring
        // it back on restart.
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
        let work = match &job.spec {
            JobSpec::ApplyUpdates(apply) => {
                let Some(backend) = self.backend.clone() else {
                    self.refuse(
                        job,
                        "this host has no package manager the agent can drive".into(),
                    )
                    .await;
                    return None;
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
                )
            }
            // Permission was checked above: `reboot` is its own kind, and
            // agent.toml must allow it.
            JobSpec::Reboot(reboot) => Work::Reboot(reboot.policy),
            _ => {
                self.refuse(
                    job,
                    format!("this agent version does not run {:?} jobs yet", job.kind()),
                )
                .await;
                return None;
            }
        };

        let ack = JobAck {
            accepted: true,
            rejection_reason: None,
            at: Utc::now(),
        };
        if let Err(error) = self.reporter.ack(job, &ack).await {
            // Run anyway: the job verified and is permitted, and `complete`
            // is accepted from `delivered` precisely so a lost ack does not
            // strand it.
            tracing::warn!(job = %job.id, error = format!("{error:#}"), "could not acknowledge; running anyway");
        }
        Some(work)
    }
}

/// What an admitted job is to do.
enum Work {
    /// Install exactly these, then reboot as the policy says.
    Apply(ApplyPlan, Arc<dyn PackageBackend>, RebootPolicy),
    /// Reboot and nothing else — the one a rule wanted in its window, after
    /// an install that ran outside it (DAWG-103).
    Reboot(RebootPolicy),
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
        // The warning is the host's to set, in agent.toml's `[reboot]`.
        let warning = self.config.reboot.clone();
        // In the background: an install can take minutes, and the check-in
        // that delivered it must not wait for it.
        tokio::spawn(async move {
            let _one_at_a_time = running.lock().await;
            let log = JobLog::start(Arc::clone(&reporter), job.clone(), 0);
            let (mut done, policy) = match work {
                Work::Apply(plan, backend, policy) => {
                    log.agent(format!(
                        "installing {} package{} at exactly the approved versions",
                        plan.packages.len(),
                        if plan.packages.len() == 1 { "" } else { "s" }
                    ));
                    (
                        run(&job, &plan, backend.as_ref(), &checks, &log).await,
                        policy,
                    )
                }
                Work::Reboot(policy) => (reboot_only(rebooter.as_ref(), &log).await, policy),
            };
            if wants_reboot(policy, &done) {
                log.agent(format!(
                    "rebooting in {} s to finish the job",
                    warning.delay_s()
                ));
                // Before the reboot: it may be the last chance to send them.
                log.finish().await;
                match reboot(&job, &done, &state, rebooter.as_ref(), &warning).await {
                    // The report is finished by `resume_after_reboot` on the
                    // other side, with the checks run again.
                    Ok(()) => return,
                    Err(why) => {
                        tracing::error!(job = %job.id, %why, "could not reboot");
                        log.agent(format!("could not reboot: {why}"));
                        done.status = JobStatus::Failed;
                        done.error = Some(why);
                    }
                }
            }
            log.agent(match done.status {
                JobStatus::Succeeded => format!("done: {} package(s) changed", done.changes.len()),
                _ => format!(
                    "{:?}: {}",
                    done.status,
                    done.error.as_deref().unwrap_or("no detail")
                ),
            });
            log.finish().await;
            if let Err(error) = reporter.complete(&job, &done).await {
                tracing::error!(job = %job.id, error = format!("{error:#}"), "could not report how the job went");
            }
            if let Some(inventory) = inventory
                && let Err(error) = inventory.collect_and_upload().await
            {
                tracing::warn!(job = %job.id, error = format!("{error:#}"), "could not upload the inventory after the job");
            }
        });
    }
}

/// Run the plan, then the host's health checks, and say how it went.
///
/// ⚠️ **A failed health check does not change the job's status** (DAWG-104).
/// "The packages installed and nginx is down" and "the packages did not
/// install" are different facts, and the report keeps them apart: the status
/// is the job's, the checks are the host's. The server halts the rollout on
/// either.
///
/// Checks run after a success and after a failure — a failed install can
/// leave half the packages changed — but not after a refusal, which changed
/// nothing.
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

/// A `reboot` job's report before any reboot: nothing installed, and whether
/// the host still needs one — which, with `if_required`, decides whether it
/// happens at all. A host rebooted by other means since its install reports
/// success and stays up.
async fn reboot_only(rebooter: &dyn Rebooter, log: &JobLog) -> JobComplete {
    let now = Utc::now();
    let reboot_required = rebooter.reboot_required().await;
    log.agent(if reboot_required {
        "a reboot job, and the host needs one"
    } else {
        "a reboot job, and the host no longer needs one: nothing to do"
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
    }
}

/// Whether this job's policy says to reboot now.
///
/// Only after a success: a failed install is a host in an unknown state, and
/// rebooting it is the one move that could turn a broken service into a
/// broken host. A person decides that.
fn wants_reboot(policy: RebootPolicy, done: &JobComplete) -> bool {
    done.status == JobStatus::Succeeded
        && match policy {
            RebootPolicy::Never => false,
            RebootPolicy::IfRequired => done.reboot_required,
            RebootPolicy::Always => true,
        }
}

/// Persist the report, then ask for the reboot. `Err` with why when the
/// reboot could not be asked for, in which case nothing is left pending.
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
    // Written first: the reboot may come before this function returns.
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

/// Run the checks and shape them for the report.
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

/// What the backend's answer means for the report.
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
            }
        }
        // ⚠️ Nothing changed: the plan could not be carried out as approved.
        // Reported as the host refusing, which is what it is.
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
    JobComplete {
        status,
        started_at,
        finished_at,
        snapshot_id: None,
        changes: vec![],
        health_checks: vec![],
        reboot_required: false,
        inventory_hash: None,
        error: Some(error),
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
        /// Every log line sent, in the order the batches arrived, and whether
        /// any batch reached the gateway after the report did.
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

    /// A package manager that answers `apply` with `outcome`, and counts.
    struct Backend {
        outcome: fn(&ApplyPlan) -> updawg_backends::Result<ApplyOutcome>,
        applied: AtomicUsize,
    }

    #[async_trait]
    impl PackageBackend for Backend {
        fn ecosystem(&self) -> Ecosystem {
            Ecosystem::Deb
        }
        async fn installed(&self) -> updawg_backends::Result<Vec<InstalledPackage>> {
            Ok(vec![])
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
            // What apt would print, so a test can see it arrive.
            log.line("Unpacking openssl (3.5.1-2) over (3.5.1-1) ...");
            log.line("Setting up openssl (3.5.1-2) ...");
            (self.outcome)(plan)
        }
    }

    // Must match `Backend::outcome`'s signature, which the refusing case needs.
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

    /// As [`world`], with more `agent.toml` appended — health checks, say.
    fn world_with(
        mode: &str,
        outcome: fn(&ApplyPlan) -> updawg_backends::Result<ApplyOutcome>,
        extra_toml: &str,
    ) -> World {
        world_allowing(mode, outcome, extra_toml, "\"apply_patch\"")
    }

    /// As [`world_with`], with the `[permissions] allow` list given.
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

        // ⚠️ Delivered again — a replay, or a check-in that raced — and nothing
        // happens: not a second ack, not a second install.
        w.executor.deliver(job).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(w.gateway.acks.lock().unwrap().len(), 1);
        assert_eq!(w.backend.applied.load(Ordering::SeqCst), 1);
    }

    /// Local configuration always wins (DAWG-38).
    #[tokio::test]
    async fn observe_mode_refuses_and_touches_nothing() {
        let w = world("observe", succeeds);
        w.executor.deliver(job(&w, |_| {})).await;
        let refused = refusals(&w);
        assert_eq!(refused.len(), 1);
        assert!(refused[0].contains("observe mode"), "{refused:?}");
        assert_eq!(w.backend.applied.load(Ordering::SeqCst), 0);
    }

    /// Each of these is a job this host must not run, and it says why.
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

    /// The installed version moved since the approval: nothing changes, and it
    /// is reported as the host refusing, with the reason.
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

    /// DAWG-104: the checks the host's own config names run after the job,
    /// in order, and a failing one is reported without changing the job's
    /// status — the packages did install.
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

    /// A refusal changed nothing, so there is nothing to check.
    #[tokio::test]
    async fn a_refused_job_runs_no_health_checks() {
        let w = world_with("managed", refuses, CHECKS);
        w.executor.deliver(job(&w, |_| {})).await;
        let done = completed(&w).await;
        assert_eq!(done.status, JobStatus::RejectedByHost);
        assert!(done.health_checks.is_empty());
    }

    /* ------------------------------------------------- rebooting (DAWG-103) */

    /// A host that never really reboots: it counts the requests, and a test
    /// "reboots" it by changing the boot id.
    struct FakeRebooter {
        boot_id: std::sync::Mutex<String>,
        requested: AtomicUsize,
        still_required: bool,
        fail: bool,
    }

    impl FakeRebooter {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                boot_id: std::sync::Mutex::new("boot-1".into()),
                requested: AtomicUsize::new(0),
                still_required: false,
                fail: false,
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

        // Asked to reboot, and nothing reported yet: the report is waiting
        // for the host to come back.
        assert_eq!(rebooter.requested.load(Ordering::SeqCst), 1);
        assert!(w.gateway.completes.lock().unwrap().is_empty());

        // The host reboots; the agent starts again.
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

        // And only once.
        w.executor.resume_after_reboot().await;
        assert_eq!(w.gateway.completes.lock().unwrap().len(), 1);
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

        // Same boot id: the agent restarted, the host did not.
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

    /// Local configuration wins: a job that may reboot is refused whole on a
    /// host that does not permit reboots, and nothing is installed.
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

    /* ----------------------------------- a reboot job of its own (DAWG-103) */

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

    /// `if_required`: a host rebooted by other means since its install has
    /// nothing to do, and says so.
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

    /* ------------------------------------------- the job's log (DAWG-101) */

    /// What the package manager printed reaches the gateway, numbered in
    /// order, among the agent's own lines — and all of it before the report,
    /// so a portal that sees the job finished sees its whole log.
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

    /// After a reboot the log carries on, numbered clear of the first half.
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
        // Sent before rebooting, which may be the last chance.
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
}
