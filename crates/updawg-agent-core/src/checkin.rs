//! The check-in loop: the hot path.
//!
//! Every agent holds one request open against the gateway for up to fifty-five
//! seconds. The gateway answers the moment a job appears, so delivery is
//! near-instant without anybody keeping a socket open per host or the agent
//! polling every few seconds. At fleet scale this is roughly nine hundred
//! requests a second, which is why the body is small and why nothing expensive
//! happens per check-in.
//!
//! # The thing that makes this hard
//!
//! A long-poll spends almost all of its life looking like an idle connection,
//! and a great deal of corporate networking equipment exists to kill idle
//! connections. When that happens the agent sees a connection error that is
//! indistinguishable, at a glance, from the gateway being down — and treating
//! it as an outage means backing off, which is precisely wrong: the gateway is
//! fine and the agent has just made itself slow to reach for no reason.
//!
//! So a connection failure on a poll that had already been waiting a while is
//! read as a trimmed idle connection, not a failure: the agent polls straight
//! back rather than backing off.
//!
//! What it deliberately does **not** do is shorten its own request timeout to
//! fit. That was the first thing I tried and it is wrong — the gateway decides
//! how long it holds, and an agent that gives up earlier simply abandons polls
//! the gateway was about to answer, turning a working system into one that
//! misses jobs. It spirals: once the agent's timeout is below the gateway's
//! hold, every poll ends in its own timeout, which reads as another trim and
//! shortens it again.
//!
//! So the agent **asks** instead (DAWG-205). `CheckinRequest::max_hold_s`
//! carries the hold it would like, the gateway clamps it and honours it, and
//! the request timeout stays at the gateway's full hold whatever was asked —
//! because a gateway too old to know about the field holds for its own default
//! and answers perfectly well, and an agent that had shortened its timeout to
//! match its request would abandon every one of those.

use crate::{
    scheduler::{CheckIn, CheckinOutcome},
    state::LocalState,
    transport::{MtlsTransport, Renewal, TransportError},
};
use async_trait::async_trait;
use std::{
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant, SystemTime},
};
use updawg_collectors::{StateCollector, SystemState};
use updawg_protocol::{CheckinRequest, HostStateReport, Job, LocalPolicy};

/// A poll that survived at least this long was doing its job.
///
/// A gateway that is actually down fails fast — connection refused, DNS
/// failure, a TLS handshake that never completes. Anything that waited seconds
/// before dying was connected and idle, which is the signature of something in
/// the middle tidying up.
const SETTLED: Duration = Duration::from_secs(5);

/// How much of an observed idle limit to ask to be held for.
///
/// Two thirds, so a proxy that trims at thirty seconds is asked for twenty. The
/// margin is deliberately generous: the observed limit is the shortest poll
/// that *survived* before being cut, which is an upper bound on a number that
/// may itself vary, and asking for almost all of it would spend the saving on
/// being trimmed anyway.
const HOLD_FRACTION: u32 = 3;

/// Where jobs go once a check-in returns them.
///
/// Behind a trait because verifying and executing a job is a different problem
/// with a different security story (DAWG-38), and the loop should not grow one.
#[async_trait]
pub trait JobSink: Send + Sync {
    async fn deliver(&self, job: Job);
}

/// Logs jobs and does not run them. The honest placeholder until DAWG-38.
#[derive(Debug, Default)]
pub struct UnhandledJobs;

#[async_trait]
impl JobSink for UnhandledJobs {
    async fn deliver(&self, job: Job) {
        tracing::warn!(
            job_id = %job.id,
            kind = ?job.kind(),
            "received a job but job execution is not implemented yet (DAWG-38); ignoring it"
        );
    }
}

/// How often a running agent looks at whether its certificate is due
/// (DAWG-308). Renewal used to happen only when `updawgd` started, so a
/// daemon that ran for a month without a restart let its certificate lapse.
const RENEWAL_CHECK: Duration = Duration::from_secs(3600);

/// The window a renewal the server asks for is spread across, by this host's
/// stable offset, so a fleet told at once does not renew at once.
const RENEW_NOW_SPREAD: Duration = Duration::from_secs(600);

/// How long to wait before trying an asked-for renewal again after it failed.
const RENEW_NOW_RETRY: Duration = Duration::from_secs(600);

/// When this agent next renews, or looks at whether to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RenewalPlan {
    /// The next look at whether the certificate is due.
    next_check: Instant,
    /// A renewal asked for, by the server or by hand, and when to do it.
    forced_at: Option<Instant>,
}

/// What to do about renewal after a check-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RenewalStep {
    Nothing,
    /// Renew if the certificate is due.
    Check,
    /// Renew now, whatever its age.
    Force,
}

impl RenewalPlan {
    fn new(now: Instant) -> Self {
        // `updawgd` renews on the way up, so the first look is an hour out.
        Self {
            next_check: now + RENEWAL_CHECK,
            forced_at: None,
        }
    }

    /// Take in what this check-in brought and say what to do. A request by
    /// hand goes now; the server's is spread by `spread` (0 to 1) and not
    /// pushed back by being repeated on every check-in until it happens.
    fn step(
        &mut self,
        now: Instant,
        server_asked: bool,
        asked_by_hand: bool,
        spread: f64,
    ) -> RenewalStep {
        if asked_by_hand {
            self.forced_at = Some(now);
        } else if server_asked && self.forced_at.is_none() {
            self.forced_at = Some(now + RENEW_NOW_SPREAD.mul_f64(spread.clamp(0.0, 1.0)));
        }
        if self.forced_at.is_some_and(|at| at <= now) {
            return RenewalStep::Force;
        }
        if now >= self.next_check {
            self.next_check = now + RENEWAL_CHECK;
            return RenewalStep::Check;
        }
        RenewalStep::Nothing
    }

    fn renewed(&mut self, now: Instant) {
        self.forced_at = None;
        self.next_check = now + RENEWAL_CHECK;
    }

    fn failed(&mut self, now: Instant) {
        self.forced_at = Some(now + RENEW_NOW_RETRY);
    }
}

/// Checks in with the gateway.
pub struct GatewayCheckIn {
    transport: Arc<MtlsTransport>,
    state: LocalState,
    collector: SystemState,
    jobs: Arc<dyn JobSink>,
    /// What `/etc/updawg/agent.toml` permits, as the server is told it.
    ///
    /// Read once at startup, like the rest of the configuration: the agent is
    /// restarted when the file changes, and a check-in that re-read a file from
    /// disk nine hundred times a second across a fleet would be a strange thing
    /// to build.
    policy: LocalPolicy,
    /// Whether this host can take snapshots, detected at start (DAWG-115).
    snapshots: Option<updawg_protocol::SnapshotSupport>,
    /// How the agent was installed and the channel it follows, detected at
    /// start (protocol 0.9).
    install: Option<updawg_protocol::AgentInstall>,
    /// The shortest a poll has survived before being cut off, if it ever has.
    ///
    /// Recorded rather than acted on: see the module docs. It is what turns
    /// "check-ins seem flaky" into "something between this host and the
    /// gateway closes idle connections after about thirty seconds", which is a
    /// sentence somebody can do something with.
    observed_idle_limit: RwLock<Option<Duration>>,
    /// When the client certificate is next renewed, or looked at (DAWG-308).
    renewal: Mutex<RenewalPlan>,
}

impl std::fmt::Debug for GatewayCheckIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayCheckIn")
            .field("hold", &self.hold())
            .finish_non_exhaustive()
    }
}

impl GatewayCheckIn {
    #[must_use]
    pub fn new(
        transport: Arc<MtlsTransport>,
        state: LocalState,
        collector: SystemState,
        jobs: Arc<dyn JobSink>,
        policy: LocalPolicy,
    ) -> Self {
        Self {
            transport,
            state,
            collector,
            jobs,
            policy,
            snapshots: None,
            install: None,
            observed_idle_limit: RwLock::new(None),
            renewal: Mutex::new(RenewalPlan::new(Instant::now())),
        }
    }

    /// Report this snapshot support on every check-in (DAWG-115).
    #[must_use]
    pub fn with_snapshots(mut self, snapshots: updawg_protocol::SnapshotSupport) -> Self {
        self.snapshots = Some(snapshots);
        self
    }

    /// Report how this agent was installed on every check-in (protocol 0.9).
    #[must_use]
    pub fn with_install(mut self, install: updawg_protocol::AgentInstall) -> Self {
        self.install = Some(install);
        self
    }

    /// How long one poll is allowed to run.
    ///
    /// The gateway's full hold, **whatever [`Self::requested_hold`] asked for**.
    /// A gateway too old for DAWG-205 ignores the request and answers at its own
    /// timeout; an agent whose client timeout had followed its request would
    /// abandon every one of those polls a moment before they were answered.
    #[must_use]
    pub fn hold(&self) -> Duration {
        Duration::from_secs(updawg_protocol::CHECKIN_LONG_POLL_SECONDS)
    }

    /// The hold to ask the gateway for, if this host has reason to ask for one
    /// (DAWG-205).
    ///
    /// `None` until something has actually trimmed a poll. Asking for less than
    /// the default on a network that never trims anything would cost a
    /// reconnection every twenty seconds to solve a problem the host does not
    /// have.
    #[must_use]
    pub fn requested_hold(&self) -> Option<u64> {
        let observed = self.observed_idle_limit()?.as_secs();
        let asked = (observed * u64::from(HOLD_FRACTION - 1) / u64::from(HOLD_FRACTION))
            .max(updawg_protocol::CHECKIN_MIN_HOLD_SECONDS);
        // An idle limit longer than the gateway's own hold is not a problem to
        // work around, and asking for the default is the same as asking for
        // nothing.
        (asked < updawg_protocol::CHECKIN_LONG_POLL_SECONDS).then_some(asked)
    }

    /// The shortest a poll has survived before being cut off, if ever.
    #[must_use]
    pub fn observed_idle_limit(&self) -> Option<Duration> {
        self.observed_idle_limit.read().ok().and_then(|l| *l)
    }

    /// Note that something closed an idle poll after this long.
    ///
    /// Logged only when it is the shortest seen so far, so a network that does
    /// this every minute produces one line rather than a log full of them.
    fn record_idle_limit(&self, survived: Duration) {
        let Ok(mut limit) = self.observed_idle_limit.write() else {
            return;
        };
        if limit.is_some_and(|l| l <= survived) {
            return;
        }
        *limit = Some(survived);
        tracing::info!(
            after_s = survived.as_secs(),
            hold_s = updawg_protocol::CHECKIN_LONG_POLL_SECONDS,
            "something between this host and the gateway is closing idle connections before \
             the check-in hold elapses; check-ins still work, but each one reconnects rather \
             than waiting out the hold"
        );
    }

    /// Assemble the check-in body.
    ///
    /// Everything here is cheap on purpose. If a collector cannot answer, the
    /// check-in still goes out — a heartbeat that says less is worth much more
    /// than no heartbeat, because a host that stops checking in is indistinguishable
    /// from a host that has been switched off.
    async fn request(&self) -> CheckinRequest {
        let state = self.collector.state().await.unwrap_or_else(|error| {
            tracing::warn!(%error, "could not read host state; checking in without it");
            updawg_collectors::HostState::default()
        });

        // Zero before the first inventory, which is honest: nothing has counted
        // yet. It is not "no updates" — the server knows this host has no
        // inventory and is asking for one on every check-in until it arrives.
        let counts = self
            .state
            .inventory_snapshot()
            .unwrap_or_default()
            .map_or((0, 0), |s| (s.pending_updates, s.security_updates));

        CheckinRequest {
            boot_id: state.boot_id,
            uptime_s: state.uptime_s,
            inventory_hash: self
                .state
                .inventory_hash()
                .unwrap_or_default()
                .unwrap_or_default(),
            state: HostStateReport {
                // Three-valued on the wire since protocol 0.4 (DAWG-210).
                reboot_required: state.reboot_required,
                services_need_restart: state.services_needing_restart,
                // From the last inventory collection, not from the package
                // manager. These are package questions and answering them
                // properly means `apt-get -s dist-upgrade`, which takes seconds
                // and reads the whole package database — on a request that runs
                // every fifty-five seconds, for ever. The counts are a heartbeat
                // signal between inventories, and the inventory is what makes
                // them true; the authoritative answer was always the server's.
                pending_updates: counts.0,
                security_updates: counts.1,
                package_lock_held: false,
            },
            metrics: state.metrics,
            // Reported by whatever is executing jobs, once anything is
            // (DAWG-38). An empty list is correct today: nothing is running.
            running_job_ids: Vec::new(),
            max_hold_s: self.requested_hold(),
            // Every check-in, not once at enrollment: the local file changes
            // without one, and a host whose operator narrowed it this morning
            // should not read as last week's configuration until it is
            // re-enrolled (DAWG-223).
            local_policy: Some(self.policy.clone()),
            snapshots: self.snapshots.clone(),
            // Every check-in too, so an upgrade nobody proposed (`apt
            // upgrade` by hand) still reaches the hosts list.
            agent_version: Some(crate::VERSION.to_owned()),
            install: self.install.clone(),
            // Read each time rather than once: a certificate renewal adopts a
            // rotated key, and the organization watching its hosts move onto
            // its own key (DAWG-293) should see that at the next check-in.
            pinned_keys: self.pinned_keys(),
        }
    }

    /// The ids of the organization keys this host verifies jobs against.
    /// `None` if the identity cannot be read, which says nothing rather than
    /// claiming the host pins no key.
    fn pinned_keys(&self) -> Option<Vec<updawg_protocol::SigningKeyId>> {
        match self.state.identity() {
            Ok(Some(identity)) => Some(
                identity
                    .org_signing_keys
                    .into_iter()
                    .map(|k| k.key_id)
                    .collect(),
            ),
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(%error, "could not read the pinned keys; checking in without them");
                None
            }
        }
    }
}

#[async_trait]
impl CheckIn for GatewayCheckIn {
    async fn check_in(&self) -> anyhow::Result<CheckinOutcome> {
        let result = self.check_in_once().await;
        // For `updawgctl status` (DAWG-37). A write that fails is logged and
        // costs the check-in nothing.
        let last = crate::state::LastCheckin {
            at: chrono::Utc::now(),
            ok: result.is_ok(),
            error: result.as_ref().err().map(|e| format!("{e:#}")),
            agent: Some(crate::VERSION.to_owned()),
        };
        if let Err(error) = self.state.set_last_checkin(&last) {
            tracing::debug!(%error, "could not record the check-in for updawgctl");
        }
        result
    }
}

impl GatewayCheckIn {
    /// Renew the certificate if the server asked, an operator asked, or it is
    /// due (DAWG-308). Never fails the check-in: a renewal that did not work
    /// is retried, and the certificate in use stays in use.
    async fn renew(&self, server_asked: bool) {
        let by_hand = self.state.take_renewal_request();
        let step = {
            let Ok(mut plan) = self.renewal.lock() else {
                return;
            };
            plan.step(
                Instant::now(),
                server_asked,
                by_hand,
                self.transport.spread(),
            )
        };
        if server_asked && step == RenewalStep::Nothing {
            tracing::debug!("the server asked for a certificate renewal; it is scheduled");
        }
        match step {
            RenewalStep::Nothing => {}
            RenewalStep::Force => {
                let result = self.transport.renew_now().await;
                if let Ok(mut plan) = self.renewal.lock() {
                    match &result {
                        Ok(_) => plan.renewed(Instant::now()),
                        Err(_) => plan.failed(Instant::now()),
                    }
                }
                match result {
                    Ok(renewal) => tracing::info!(
                        ?renewal,
                        "client certificate renewed as asked, picking up the organization's keys"
                    ),
                    Err(error) => {
                        tracing::warn!(%error, "an asked-for certificate renewal failed; trying again later");
                    }
                }
            }
            RenewalStep::Check => match self.transport.renew_if_due(SystemTime::now()).await {
                Ok(Renewal::Renewed { expires_in }) => tracing::info!(
                    expires_in_days = expires_in.as_secs() / 86_400,
                    "client certificate renewed"
                ),
                Ok(Renewal::NotDue { .. }) => {}
                Err(error) => tracing::error!(
                    %error,
                    "certificate renewal failed; the host will go stale if this keeps failing"
                ),
            },
        }
    }

    async fn check_in_once(&self) -> anyhow::Result<CheckinOutcome> {
        let request = self.request().await;
        if request.boot_id.is_empty() {
            tracing::debug!("checking in without a boot id; /proc is not readable");
        }

        let started = Instant::now();
        let hold = self.hold();
        let result = self.transport.check_in(&request, hold).await;
        let elapsed = started.elapsed();

        let response = match result {
            Ok(response) => response,
            // A connection that died after sitting still for a while was
            // connected and idle — trimmed by something in the middle, not a
            // gateway that is down. Poll again rather than backing off, and
            // ask for less time next round.
            Err(TransportError::Unreachable { .. }) if elapsed >= SETTLED => {
                self.record_idle_limit(elapsed);
                tracing::debug!(
                    waited_s = elapsed.as_secs(),
                    "long poll was closed while idle; treating as an empty check-in"
                );
                return Ok(CheckinOutcome {
                    next_checkin: Duration::ZERO,
                    inventory_requested: false,
                });
            }
            Err(e) => return Err(e.into()),
        };

        for job in response.jobs {
            self.jobs.deliver(job).await;
        }

        if let Some(config) = &response.config {
            tracing::debug!(
                config_version = response.config_version,
                checkin_timeout_s = config.checkin_timeout_s,
                "server configuration received"
            );
        }

        self.renew(response.renew_certificate).await;

        Ok(CheckinOutcome {
            next_checkin: Duration::from_secs(response.next_checkin_s),
            inventory_requested: response.inventory_requested,
        })
    }
}

#[cfg(test)]
mod tests;
