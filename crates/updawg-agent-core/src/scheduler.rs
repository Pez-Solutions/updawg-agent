//! The scheduler.
//!
//! Three things run concurrently on their own cadences: the check-in loop, the
//! inventory collector and the package metadata refresh. Each is driven through
//! a trait so the scheduler can be built and tested before the transport and
//! collectors exist, and so it stays testable afterwards.
//!
//! Two behaviours here exist because of how this fails at scale:
//!
//! - **Startup jitter.** A fleet that loses power and comes back together would
//!   otherwise check in simultaneously forever. Every periodic task waits a
//!   random fraction of its interval before its first run.
//! - **Backoff on failure.** A gateway having a bad day should not be hit
//!   harder by every agent in the fleet retrying instantly.

use crate::config::AgentConfig;
use async_trait::async_trait;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// What a check-in produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckinOutcome {
    /// How long to wait before checking in again. Zero means immediately,
    /// which is the normal long-poll case.
    pub next_checkin: Duration,
    /// The server asked for a fresh inventory.
    pub inventory_requested: bool,
}

#[async_trait]
pub trait CheckIn: Send + Sync {
    async fn check_in(&self) -> anyhow::Result<CheckinOutcome>;
}

#[async_trait]
pub trait Inventory: Send + Sync {
    async fn collect_and_upload(&self) -> anyhow::Result<()>;
    async fn refresh_metadata(&self) -> anyhow::Result<()>;
}

/// Ceiling on backoff, so a long outage does not leave agents checking in once
/// an hour when the gateway comes back.
const MAX_BACKOFF: Duration = Duration::from_secs(300);
const MIN_BACKOFF: Duration = Duration::from_secs(2);

/// A cheap spread, seeded from the clock.
///
/// Not cryptographic and does not need to be: the job is to stop a fleet
/// marching in lockstep, and any dispersion achieves that. Avoiding a random
/// number generator dependency in something that runs as root is worth more
/// than the uniformity.
fn jitter_fraction() -> f64 {
    let nanos: u32 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    f64::from(nanos % 1_000_000) / 1_000_000.0
}

fn jittered(interval: Duration) -> Duration {
    interval.mul_f64(jitter_fraction())
}

pub struct Scheduler {
    config: AgentConfig,
    checkin: Arc<dyn CheckIn>,
    inventory: Arc<dyn Inventory>,
}

impl std::fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scheduler")
            .field("mode", &self.config.mode)
            .finish_non_exhaustive()
    }
}

impl Scheduler {
    #[must_use]
    pub fn new(
        config: AgentConfig,
        checkin: Arc<dyn CheckIn>,
        inventory: Arc<dyn Inventory>,
    ) -> Self {
        Self {
            config,
            checkin,
            inventory,
        }
    }

    /// Run until `shutdown` resolves.
    pub async fn run<S>(self, shutdown: S)
    where
        S: std::future::Future<Output = ()> + Send + 'static,
    {
        let cancel = tokio_util_token();
        let checkin_task = tokio::spawn(checkin_loop(
            self.checkin.clone(),
            self.inventory.clone(),
            cancel.clone(),
        ));
        let inventory_task = tokio::spawn(periodic(
            "inventory",
            self.config.schedule.inventory_interval.as_duration(),
            self.inventory.clone(),
            InventoryJob::Collect,
            cancel.clone(),
        ));
        let refresh_task = tokio::spawn(periodic(
            "refresh-metadata",
            self.config.schedule.refresh_metadata.as_duration(),
            self.inventory.clone(),
            InventoryJob::Refresh,
            cancel.clone(),
        ));

        shutdown.await;
        tracing::info!("shutdown requested, stopping scheduler");
        cancel.cancel();

        let _ = tokio::join!(checkin_task, inventory_task, refresh_task);
        tracing::info!("scheduler stopped");
    }
}

#[derive(Debug, Clone, Copy)]
enum InventoryJob {
    Collect,
    Refresh,
}

/// Minimal cancellation token, so the crate does not take a dependency for one
/// flag and a notify.
#[derive(Debug, Clone)]
pub struct Cancel {
    inner: Arc<(std::sync::atomic::AtomicBool, tokio::sync::Notify)>,
}

impl Cancel {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new((
                std::sync::atomic::AtomicBool::new(false),
                tokio::sync::Notify::new(),
            )),
        }
    }

    pub fn cancel(&self) {
        self.inner
            .0
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.inner.1.notify_waiters();
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.0.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Sleep, waking early if cancelled. Returns false if cancelled.
    pub async fn sleep(&self, d: Duration) -> bool {
        if self.is_cancelled() {
            return false;
        }
        tokio::select! {
            () = tokio::time::sleep(d) => !self.is_cancelled(),
            () = self.inner.1.notified() => false,
        }
    }
}

impl Default for Cancel {
    fn default() -> Self {
        Self::new()
    }
}

fn tokio_util_token() -> Cancel {
    Cancel::new()
}

async fn checkin_loop(checkin: Arc<dyn CheckIn>, inventory: Arc<dyn Inventory>, cancel: Cancel) {
    let mut backoff = MIN_BACKOFF;

    while !cancel.is_cancelled() {
        match checkin.check_in().await {
            Ok(outcome) => {
                backoff = MIN_BACKOFF;
                if outcome.inventory_requested {
                    tracing::info!("server requested a fresh inventory");
                    if let Err(error) = inventory.collect_and_upload().await {
                        tracing::warn!(%error, "inventory upload failed");
                    }
                }
                if !outcome.next_checkin.is_zero() && !cancel.sleep(outcome.next_checkin).await {
                    break;
                }
            }
            Err(error) => {
                tracing::warn!(%error, backoff_s = backoff.as_secs(), "check-in failed");
                if !cancel.sleep(backoff).await {
                    break;
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
    tracing::debug!("check-in loop stopped");
}

async fn periodic(
    name: &'static str,
    interval: Duration,
    inventory: Arc<dyn Inventory>,
    job: InventoryJob,
    cancel: Cancel,
) {
    // Spread first runs across the fleet.
    let first = jittered(interval);
    tracing::debug!(
        task = name,
        delay_s = first.as_secs(),
        "first run scheduled"
    );
    if !cancel.sleep(first).await {
        return;
    }

    while !cancel.is_cancelled() {
        let result = match job {
            InventoryJob::Collect => inventory.collect_and_upload().await,
            InventoryJob::Refresh => inventory.refresh_metadata().await,
        };
        if let Err(error) = result {
            tracing::warn!(task = name, %error, "periodic task failed");
        }
        if !cancel.sleep(interval).await {
            break;
        }
    }
    tracing::debug!(task = name, "periodic task stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Debug, Default)]
    struct Counters {
        checkins: AtomicU32,
        collects: AtomicU32,
        refreshes: AtomicU32,
        fail_checkin: std::sync::atomic::AtomicBool,
    }

    struct Fake(Arc<Counters>);

    #[async_trait]
    impl CheckIn for Fake {
        async fn check_in(&self) -> anyhow::Result<CheckinOutcome> {
            self.0.checkins.fetch_add(1, Ordering::SeqCst);
            if self.0.fail_checkin.load(Ordering::SeqCst) {
                anyhow::bail!("gateway unreachable");
            }
            Ok(CheckinOutcome {
                next_checkin: Duration::from_millis(5),
                inventory_requested: false,
            })
        }
    }

    #[async_trait]
    impl Inventory for Fake {
        async fn collect_and_upload(&self) -> anyhow::Result<()> {
            self.0.collects.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn refresh_metadata(&self) -> anyhow::Result<()> {
            self.0.refreshes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn config(inventory: &str, refresh: &str) -> AgentConfig {
        AgentConfig::from_toml(&format!(
            r#"
server = "https://agents.updawg.net"
mode = "managed"
[schedule]
inventory_interval = "{inventory}"
refresh_metadata = "{refresh}"
"#
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn the_checkin_loop_runs_repeatedly_until_shutdown() {
        let counters = Arc::new(Counters::default());
        let fake = Arc::new(Fake(counters.clone()));
        let sched = Scheduler::new(config("1h", "1h"), fake.clone(), fake.clone());

        let (tx, rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(sched.run(async move {
            let _ = rx.await;
        }));

        tokio::time::sleep(Duration::from_millis(80)).await;
        let _ = tx.send(());
        handle.await.unwrap();

        assert!(
            counters.checkins.load(Ordering::SeqCst) > 1,
            "check-in should loop, not run once"
        );
    }

    #[tokio::test]
    async fn periodic_tasks_fire_on_their_interval() {
        let counters = Arc::new(Counters::default());
        let fake = Arc::new(Fake(counters.clone()));
        // 1s intervals: jitter puts the first run somewhere inside the first
        // second, so a 1.2s window reliably catches at least one.
        let sched = Scheduler::new(config("1s", "1s"), fake.clone(), fake.clone());

        let (tx, rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(sched.run(async move {
            let _ = rx.await;
        }));

        tokio::time::sleep(Duration::from_millis(1200)).await;
        let _ = tx.send(());
        handle.await.unwrap();

        assert!(
            counters.collects.load(Ordering::SeqCst) >= 1,
            "inventory never ran"
        );
        assert!(
            counters.refreshes.load(Ordering::SeqCst) >= 1,
            "metadata refresh never ran"
        );
    }

    #[tokio::test]
    async fn a_failing_gateway_is_backed_off_rather_than_hammered() {
        let counters = Arc::new(Counters::default());
        counters.fail_checkin.store(true, Ordering::SeqCst);
        let fake = Arc::new(Fake(counters.clone()));
        let sched = Scheduler::new(config("1h", "1h"), fake.clone(), fake.clone());

        let (tx, rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(sched.run(async move {
            let _ = rx.await;
        }));

        // MIN_BACKOFF is 2s, so in 300ms a backing-off agent tries once or
        // twice. One that ignores failure would spin thousands of times.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = tx.send(());
        handle.await.unwrap();

        let tries = counters.checkins.load(Ordering::SeqCst);
        assert!(tries >= 1, "should have tried at least once");
        assert!(
            tries < 10,
            "backoff is not being applied: {tries} attempts in 300ms"
        );
    }

    #[tokio::test]
    async fn shutdown_stops_everything_promptly() {
        let counters = Arc::new(Counters::default());
        let fake = Arc::new(Fake(counters.clone()));
        let sched = Scheduler::new(config("1h", "1h"), fake.clone(), fake.clone());

        let (tx, rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(sched.run(async move {
            let _ = rx.await;
        }));

        tokio::time::sleep(Duration::from_millis(20)).await;
        let started = std::time::Instant::now();
        let _ = tx.send(());
        handle.await.unwrap();

        // Everything waits on the cancel token, so nothing sits out a full
        // sleep before noticing. A service that ignores SIGTERM gets SIGKILLed.
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "shutdown took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn jitter_stays_within_the_interval() {
        for _ in 0..100 {
            let j = jittered(Duration::from_secs(60));
            assert!(j <= Duration::from_secs(60));
        }
    }
}
