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
//! `apply_updates` is the only kind that runs so far. The others are refused
//! as not built, which is honest and halts rather than pretends.

use crate::{
    config::AgentConfig,
    scheduler::Inventory,
    state::LocalState,
    transport::{JobAnswer, MtlsTransport},
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use tokio::sync::Mutex;
use updawg_backends::{ApplyPlan, BackendError, LogSink, PackageBackend, Pin};
use updawg_crypto::PinnedKeys;
use updawg_protocol::{
    Job, JobAck, JobComplete, JobStatus, PackageChange,
    job::{JobSpec, RebootPolicy},
};

/// How far ahead of `not_before` a job may arrive and still be taken. The
/// gateway withholds a job until then, so this is only clock skew.
const EARLY: Duration = Duration::minutes(5);

/// Where answers about jobs go. The gateway, in production.
#[async_trait]
pub trait Reporter: Send + Sync {
    async fn ack(&self, job: &Job, ack: &JobAck) -> anyhow::Result<()>;
    async fn complete(&self, job: &Job, done: &JobComplete) -> anyhow::Result<()>;
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
            running: Arc::default(),
        }
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

    /// Everything up to and including the acknowledgement. Returns the plan
    /// to run, or `None` when the job was ignored or refused.
    async fn admit(&self, job: &Job) -> Option<(ApplyPlan, Arc<dyn PackageBackend>)> {
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
        if !self.config.admits(job.kind(), None) {
            let reason = if self.config.mode == crate::config::Mode::Observe {
                "this agent is in observe mode, which refuses every job that changes the host"
                    .to_owned()
            } else {
                format!(
                    "local configuration does not permit {}",
                    job.kind().permission()
                )
            };
            self.refuse(job, reason).await;
            return None;
        }
        let JobSpec::ApplyUpdates(apply) = &job.spec else {
            self.refuse(
                job,
                format!("this agent version does not run {:?} jobs yet", job.kind()),
            )
            .await;
            return None;
        };
        let Some(backend) = self.backend.clone() else {
            self.refuse(
                job,
                "this host has no package manager the agent can drive".into(),
            )
            .await;
            return None;
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
        let plan = ApplyPlan {
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
        };
        Some((plan, backend))
    }
}

#[async_trait]
impl crate::checkin::JobSink for Executor {
    async fn deliver(&self, job: Job) {
        let Some((plan, backend)) = self.admit(&job).await else {
            return;
        };
        let (reporter, inventory, running) = (
            Arc::clone(&self.reporter),
            self.inventory.clone(),
            Arc::clone(&self.running),
        );
        // In the background: an install can take minutes, and the check-in
        // that delivered it must not wait for it.
        tokio::spawn(async move {
            let _one_at_a_time = running.lock().await;
            let done = run(&job, &plan, backend.as_ref()).await;
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

struct Logged<'a>(&'a Job);

impl LogSink for Logged<'_> {
    fn line(&self, line: &str) {
        tracing::info!(job = %self.0.id, "{line}");
    }
}

/// Run the plan and say how it went.
async fn run(job: &Job, plan: &ApplyPlan, backend: &dyn PackageBackend) -> JobComplete {
    let started_at = Utc::now();
    let outcome = backend.apply(plan, &Logged(job)).await;
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
    use updawg_backends::{ApplyOutcome, Change, PendingChanges};
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
            _log: &dyn LogSink,
        ) -> updawg_backends::Result<ApplyOutcome> {
            self.applied.fetch_add(1, Ordering::SeqCst);
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
            "server = \"https://agents.example\"\nmode = \"{mode}\"\n[permissions]\nallow = [\"apply_patch\"]\n"
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
}
