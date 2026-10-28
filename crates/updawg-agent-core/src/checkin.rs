//! The check-in loop.
//!
//! Each agent holds one long-poll request open against the gateway for up to
//! 55 seconds, and the gateway answers as soon as a job appears. Across a fleet
//! this is a lot of requests per second, so the body is kept small and nothing
//! expensive happens per check-in.
//!
//! # Idle connection trimming
//!
//! A long poll looks like an idle connection, and plenty of proxies and
//! firewalls close those. The resulting connection error looks like the
//! gateway being down, but backing off would only make the agent slower to
//! reach. A connection failure on a poll that had already been waiting a while
//! is therefore treated as a trimmed connection and the agent polls again
//! straight away.
//!
//! The agent does not shorten its own request timeout to fit. The gateway
//! decides how long it holds, so a shorter client timeout abandons polls the
//! gateway was about to answer, and each of those timeouts looks like another
//! trim. Instead the agent asks for a shorter hold through
//! `CheckinRequest::max_hold_s`, and keeps the request timeout at the full
//! hold. Older gateways ignore the field and hold for their default.

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

/// A poll that fails after at least this long was connected and idle. A
/// gateway that is down fails fast (connection refused, DNS, TLS handshake).
const SETTLED: Duration = Duration::from_secs(5);

/// Ask for (n-1)/n of the observed idle limit: two thirds, so a proxy that
/// trims at 30s gets asked for 20s. The observed limit is only an upper bound
/// and may vary, hence the margin.
const HOLD_FRACTION: u32 = 3;

/// Where jobs go once a check-in returns them. Verifying and running jobs is
/// kept out of the check-in loop.
#[async_trait]
pub trait JobSink: Send + Sync {
    async fn deliver(&self, job: Job);
}

/// Logs jobs without running them. Placeholder until job execution exists.
#[derive(Debug, Default)]
pub struct UnhandledJobs;

#[async_trait]
impl JobSink for UnhandledJobs {
    async fn deliver(&self, job: Job) {
        tracing::warn!(
            job_id = %job.id,
            kind = ?job.kind(),
            "received a job but job execution is not implemented yet; ignoring it"
        );
    }
}

/// How often a running agent checks whether its certificate is due, so a
/// daemon that is never restarted still renews.
const RENEWAL_CHECK: Duration = Duration::from_secs(3600);

/// Server-requested renewals are spread over this window by the host's stable
/// offset, so the whole fleet doesn't renew at once.
const RENEW_NOW_SPREAD: Duration = Duration::from_secs(600);

/// Retry delay for a failed forced renewal.
const RENEW_NOW_RETRY: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RenewalPlan {
    next_check: Instant,
    /// Set when the server or an operator asked for a renewal.
    forced_at: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RenewalStep {
    Nothing,
    /// Renew if the certificate is due.
    Check,
    /// Renew regardless of age.
    Force,
}

impl RenewalPlan {
    fn new(now: Instant) -> Self {
        // updawgd already renews at startup
        Self {
            next_check: now + RENEWAL_CHECK,
            forced_at: None,
        }
    }

    /// A manual request renews immediately. A server request is delayed by
    /// `spread` (0 to 1) of the window, and repeating it on later check-ins
    /// doesn't push it back.
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
    /// Policy from `/etc/updawg/agent.toml`, read once at startup. The agent
    /// is restarted when the file changes.
    policy: LocalPolicy,
    snapshots: Option<updawg_protocol::SnapshotSupport>,
    install: Option<updawg_protocol::AgentInstall>,
    /// Shortest time a poll survived before being cut off. Used for logging
    /// and for `requested_hold`; the client timeout is not changed.
    observed_idle_limit: RwLock<Option<Duration>>,
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

    /// Report this snapshot support on every check-in.
    #[must_use]
    pub fn with_snapshots(mut self, snapshots: updawg_protocol::SnapshotSupport) -> Self {
        self.snapshots = Some(snapshots);
        self
    }

    /// Report how this agent was installed on every check-in.
    #[must_use]
    pub fn with_install(mut self, install: updawg_protocol::AgentInstall) -> Self {
        self.install = Some(install);
        self
    }

    /// Client timeout for one poll. Always the gateway's full hold, regardless
    /// of [`Self::requested_hold`]: an older gateway ignores the request and
    /// holds for its default.
    #[must_use]
    pub fn hold(&self) -> Duration {
        Duration::from_secs(updawg_protocol::CHECKIN_LONG_POLL_SECONDS)
    }

    /// The hold to ask the gateway for. `None` until a poll has actually been
    /// trimmed, since a shorter hold just means more reconnections.
    #[must_use]
    pub fn requested_hold(&self) -> Option<u64> {
        let observed = self.observed_idle_limit()?.as_secs();
        let asked = (observed * u64::from(HOLD_FRACTION - 1) / u64::from(HOLD_FRACTION))
            .max(updawg_protocol::CHECKIN_MIN_HOLD_SECONDS);
        // no point asking for the default or more
        (asked < updawg_protocol::CHECKIN_LONG_POLL_SECONDS).then_some(asked)
    }

    /// The shortest a poll has survived before being cut off, if ever.
    #[must_use]
    pub fn observed_idle_limit(&self) -> Option<Duration> {
        self.observed_idle_limit.read().ok().and_then(|l| *l)
    }

    /// Only logs when this is a new minimum, so a network that trims every
    /// poll logs once.
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

    /// Builds the check-in body. Must stay cheap. If a collector fails, the
    /// check-in still goes out without that data; a host that stops checking
    /// in looks switched off.
    async fn request(&self) -> CheckinRequest {
        let state = self.collector.state().await.unwrap_or_else(|error| {
            tracing::warn!(%error, "could not read host state; checking in without it");
            updawg_collectors::HostState::default()
        });

        // Zero before the first inventory. The server knows there's no
        // inventory yet and keeps asking for one, so it won't read this as
        // "no updates".
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
                reboot_required: state.reboot_required,
                services_need_restart: state.services_needing_restart,
                // Taken from the last inventory. Asking the package manager
                // means something like `apt-get -s dist-upgrade`, which is far
                // too slow to run on every check-in.
                pending_updates: counts.0,
                security_updates: counts.1,
                package_lock_held: false,
            },
            metrics: state.metrics,
            // nothing executes jobs yet
            running_job_ids: Vec::new(),
            max_hold_s: self.requested_hold(),
            // Sent every time since the file can change after enrollment.
            local_policy: Some(self.policy.clone()),
            snapshots: self.snapshots.clone(),
            // Also every time, so a manual `apt upgrade` shows up.
            agent_version: Some(crate::VERSION.to_owned()),
            install: self.install.clone(),
            // Read each time: a renewal can pick up a rotated key.
            pinned_keys: self.pinned_keys(),
        }
    }

    /// Ids of the organization keys this host verifies jobs against. `None`
    /// if the identity can't be read, so we don't report an empty set.
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
        // for `updawgctl status`; failure to write is only logged
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
    /// Renews the certificate if the server or an operator asked, or if it's
    /// due. Failures are retried later and never fail the check-in.
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
            // Died after sitting idle for a while: trimmed by something in
            // between, not a dead gateway. Poll again without backing off.
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
