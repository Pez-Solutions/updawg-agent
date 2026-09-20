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
//! misses jobs. Making the hold negotiable means a field in `CheckinRequest`
//! and a gateway that honours it; until then the agent records what it
//! observed and says so, which is the part an operator can act on.

use crate::{
    scheduler::{CheckIn, CheckinOutcome},
    state::LocalState,
    transport::{MtlsTransport, TransportError},
};
use async_trait::async_trait;
use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use updawg_collectors::{RebootRequired, StateCollector, SystemState};
use updawg_protocol::{CheckinRequest, HostStateReport, Job};

/// A poll that survived at least this long was doing its job.
///
/// A gateway that is actually down fails fast — connection refused, DNS
/// failure, a TLS handshake that never completes. Anything that waited seconds
/// before dying was connected and idle, which is the signature of something in
/// the middle tidying up.
const SETTLED: Duration = Duration::from_secs(5);

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

/// Checks in with the gateway.
pub struct GatewayCheckIn {
    transport: Arc<MtlsTransport>,
    state: LocalState,
    collector: SystemState,
    jobs: Arc<dyn JobSink>,
    /// The shortest a poll has survived before being cut off, if it ever has.
    ///
    /// Recorded rather than acted on: see the module docs. It is what turns
    /// "check-ins seem flaky" into "something between this host and the
    /// gateway closes idle connections after about thirty seconds", which is a
    /// sentence somebody can do something with.
    observed_idle_limit: RwLock<Option<Duration>>,
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
    ) -> Self {
        Self {
            transport,
            state,
            collector,
            jobs,
            observed_idle_limit: RwLock::new(None),
        }
    }

    /// How long one poll is allowed to run. The gateway's hold, from the
    /// protocol — not something the agent gets to choose.
    #[must_use]
    pub fn hold(&self) -> Duration {
        Duration::from_secs(updawg_protocol::CHECKIN_LONG_POLL_SECONDS)
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
        note_unknown_reboot_state(state.reboot_required);

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
                // Unknown is reported as false, because the wire type is a
                // bool — but it is logged on the way past, so the gap is
                // visible rather than silently absorbed. Widening the wire
                // type is a protocol change (DAWG-210).
                reboot_required: state.reboot_required.is_yes(),
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
        }
    }
}

#[async_trait]
impl CheckIn for GatewayCheckIn {
    async fn check_in(&self) -> anyhow::Result<CheckinOutcome> {
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

        Ok(CheckinOutcome {
            next_checkin: Duration::from_secs(response.next_checkin_s),
            inventory_requested: response.inventory_requested,
        })
    }
}

/// Log the gap between what the host knows and what the wire can say.
///
/// Kept as a free function so the one place that flattens `Unknown` into
/// `false` is greppable.
pub fn note_unknown_reboot_state(reboot: RebootRequired) {
    if !reboot.is_known() {
        tracing::debug!(
            "cannot tell whether this host needs a reboot; reporting false, which is not the \
             same thing"
        );
    }
}

#[cfg(test)]
mod tests;
