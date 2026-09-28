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
//! `apply_updates`, `reboot` (DAWG-103), `snapshot` and `rollback` (DAWG-119)
//! run. The others are refused as not built, which is honest and halts rather
//! than pretends.
//!
//! # Snapshots
//!
//! An `apply_updates` job whose policy asks for one takes a snapshot before
//! it changes anything, and reports its id whatever happens next — a failed
//! install is exactly the one somebody wants to roll back. `required` with no
//! snapshot (no provider, not permitted, or it failed) changes nothing and
//! says why; `if_available` carries on without and says that too. The agent's
//! own snapshots beyond `[snapshots] keep` are pruned each time one is taken.

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
    snapshots: Snapshots,
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
            snapshots: Err("no snapshot provider was looked for".into()),
            running: Arc::default(),
        }
    }

    /// The snapshot provider `updawg_snapshots::detect` found, or why none.
    #[must_use]
    pub fn with_snapshots(mut self, snapshots: Snapshots) -> Self {
        self.snapshots = snapshots;
        self
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
        // The same for a snapshot the job cannot do without: refused whole,
        // before anything changes (DAWG-119).
        if let JobSpec::ApplyUpdates(apply) = &job.spec
            && apply.snapshot == SnapshotPolicy::Required
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

    /// The provider, for a job that cannot run without one, or why not.
    fn provider_for(&self, job: &Job) -> std::result::Result<Arc<dyn SnapshotProvider>, String> {
        self.snapshots.clone().map_err(|why| {
            format!(
                "this host cannot run {} jobs, having no snapshot provider: {why}",
                job.kind().permission()
            )
        })
    }

    /// What a verified, permitted job is to do, or why this host cannot.
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
                    // `if_available` on a host that does not permit snapshots
                    // goes without, like one with no provider: it is the
                    // host's call (DAWG-38). `required` was refused already.
                    match (apply.snapshot, &self.snapshots) {
                        (SnapshotPolicy::Never, _) | (_, Err(_)) => None,
                        (_, Ok(_)) if !self.config.admits(JobKind::Snapshot, None) => None,
                        (policy, Ok(provider)) => Some(SnapshotFirst {
                            provider: Arc::clone(provider),
                            required: policy == SnapshotPolicy::Required,
                        }),
                    },
                )
            }
            // Permission was checked already: `reboot` is its own kind, and
            // agent.toml must allow it.
            JobSpec::Reboot(reboot) => Work::Reboot(reboot.policy),
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
            _ => {
                return Err(format!(
                    "this agent version does not run {:?} jobs yet",
                    job.kind()
                ));
            }
        })
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
        let work = match self.work_for(job) {
            Ok(work) => work,
            Err(reason) => {
                self.refuse(job, reason).await;
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
    /// Install exactly these, then reboot as the policy says, after a
    /// snapshot if one is to be taken.
    Apply(
        ApplyPlan,
        Arc<dyn PackageBackend>,
        RebootPolicy,
        Option<SnapshotFirst>,
    ),
    /// Reboot and nothing else — the one a rule wanted in its window, after
    /// an install that ran outside it (DAWG-103).
    Reboot(RebootPolicy),
    /// Take one, with this description (DAWG-119).
    Snapshot(Arc<dyn SnapshotProvider>, String),
    /// Put the host back as this snapshot has it. The backend, when there is
    /// one, says which packages that moved.
    Rollback(
        Arc<dyn SnapshotProvider>,
        String,
        Option<Arc<dyn PackageBackend>>,
    ),
}

/// A snapshot to take before an install.
struct SnapshotFirst {
    provider: Arc<dyn SnapshotProvider>,
    /// `required`: no snapshot, no install.
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
        // The warning is the host's to set, in agent.toml's `[reboot]`.
        let warning = self.config.reboot.clone();
        // In the background: an install can take minutes, and the check-in
        // that delivered it must not wait for it.
        tokio::spawn(async move {
            let _one_at_a_time = running.lock().await;
            let log = JobLog::start(Arc::clone(&reporter), job.clone(), 0);
            let (mut done, policy) =
                perform(&job, &work, &checks, &state, rebooter.as_ref(), room, &log).await;
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

/// Run what was admitted: how it went, and the reboot policy to apply now.
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
                // `required`, and none: nothing was changed.
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
                    // Whatever happened: a failed install is the one somebody
                    // wants to roll back.
                    done.snapshot_id = taken;
                    done.started_at = started_at;
                    (done, *policy)
                }
            }
        }
        Work::Reboot(policy) => (reboot_only(rebooter, log).await, *policy),
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
        Work::Rollback(provider, id, backend) => {
            let mut done = roll_back(state, provider.as_ref(), id, backend.as_deref(), log).await;
            if done.status == JobStatus::Succeeded {
                done.reboot_required = rebooter.reboot_required().await;
            }
            // After a failure too: a rollback that stopped halfway is a host
            // in a state nobody chose.
            done.health_checks = checks_reported(job, checks, log).await;
            done.finished_at = Utc::now();
            (done, RebootPolicy::Never)
        }
    }
}

/// The snapshot an install takes first, if it takes one.
///
/// `Ok(None)` when none was asked for, or `if_available` could not have one
/// and the install goes ahead; `Err` only when one was required and could not
/// be taken, and then nothing is installed.
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

/// How many of its own snapshots the agent keeps, and how much room one needs
/// (`[snapshots]` in agent.toml).
#[derive(Debug, Clone, Copy)]
struct Room {
    /// At least one: the snapshot just taken is the one a rollout needs.
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

/// Take a snapshot for `job`, then prune the agent's own down to `keep`.
///
/// Not with less than `min_free_mb` free (DAWG-121). Space that cannot be
/// measured does not stop it: the check is a guard against a known-full
/// disk, not a condition for patching.
///
/// A failed prune is logged and does not fail the job: the snapshot it was
/// for exists, and a disk filling slowly is for a person to see, not a
/// reason to leave a host unpatched.
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

/// Put the host back as snapshot `id` has it, and say what that moved.
///
/// The agent's own state is carried across (see [`LocalState::carry`]).
/// Which packages moved is the package manager's answer before and after,
/// not the snapshot's: that is what the server and the person reading the
/// report think in.
async fn roll_back(
    state: &LocalState,
    provider: &dyn SnapshotProvider,
    id: &str,
    backend: Option<&dyn PackageBackend>,
    log: &JobLog,
) -> JobComplete {
    let started_at = Utc::now();
    let fail = |why: String| {
        log.agent(&why);
        failed(JobStatus::Failed, started_at, Utc::now(), why)
    };
    let carried = match state.carry() {
        Ok(carried) => carried,
        Err(error) => {
            // Refused rather than risked: without it the agent would forget
            // the jobs it has run.
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
    // Put back whether or not the rollback finished: it may have got partway.
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

fn or_none(version: &str) -> &str {
    if version.is_empty() {
        "(none)"
    } else {
        version
    }
}

/// What moved between two package lists, by name and architecture. A
/// package on one side only has an empty version on the other.
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
    ended(status, started_at, finished_at, Some(error))
}

/// A report with nothing in it but how it ended.
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
        /// What `installed` answers.
        packages: std::sync::Mutex<Vec<InstalledPackage>>,
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
            packages: std::sync::Mutex::default(),
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

    /* ------------------------------------------------ snapshots (DAWG-119) */

    const ALLOW_SNAPSHOT: &str = "\"apply_patch\", \"snapshot\"";

    /// A snapshot provider that, like a real one, puts back the files it
    /// covers — here the agent's record of jobs, and the package list.
    struct FakeSnapshots {
        state_dir: std::path::PathBuf,
        backend: Arc<Backend>,
        fail_create: bool,
        free: AtomicU64,
        taken: std::sync::Mutex<Vec<Taken>>,
        kept: std::sync::Mutex<Vec<usize>>,
        rolled_back: AtomicUsize,
    }

    /// One the fake took: its id, and what it will put back.
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
                created: 0,
                modified: 1,
                deleted: 0,
            })
        }
        async fn prune(&self, keep: usize) -> updawg_snapshots::Result<Vec<String>> {
            self.kept.lock().unwrap().push(keep);
            Ok(vec![])
        }
    }

    /// `w`, with a fake snapshot provider.
    fn with_snapshots(w: World, fail_create: bool) -> (World, Arc<FakeSnapshots>) {
        let fake = Arc::new(FakeSnapshots {
            state_dir: w.executor.state.root().to_path_buf(),
            backend: Arc::clone(&w.backend),
            fail_create,
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

    /// The `n`th report, waiting for it.
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

    /// `required` on a host that cannot: refused whole, before anything.
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

    /// A snapshot pins what the install replaces: not on a full disk.
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

    /// A failed install is exactly the one somebody wants to roll back.
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

    /// The whole round: install after a snapshot, roll back, and the report
    /// says which packages moved — while the agent still remembers every job
    /// it ran, although the rollback put its state directory back too.
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
        // The snapshot was taken after the install job was recorded and
        // before the rollback job was: without carrying the state across,
        // the rollback job would be forgotten and could run again.
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
