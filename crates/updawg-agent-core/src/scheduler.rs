//! The scheduler.
//!
//! Runs the check-in loop, inventory collection and package metadata refresh
//! concurrently, each on its own cadence. They're behind traits so the
//! scheduler can be tested on its own.
//!
//! Every periodic task waits a random fraction of its interval before its
//! first run, so a fleet that boots together doesn't stay in lockstep. Failed
//! check-ins back off exponentially.

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

/// Kept low so agents reconnect reasonably soon after a long outage.
const MAX_BACKOFF: Duration = Duration::from_secs(300);
const MIN_BACKOFF: Duration = Duration::from_secs(2);

/// Window the first check-in of a process is spread across. Short, since it
/// only matters when many hosts start at once.
const STARTUP_SPREAD: Duration = Duration::from_secs(10);

/// A value in [0, 1) seeded from the clock. Not random in any real sense, but
/// enough to spread a fleet out without pulling in an RNG crate.
fn jitter_fraction() -> f64 {
    let nanos: u32 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    f64::from(nanos % 1_000_000) / 1_000_000.0
}

fn jittered(interval: Duration) -> Duration {
    interval.mul_f64(jitter_fraction())
}

/// The backoff, or the gateway's `Retry-After` if that is longer.
fn wait_after(error: &anyhow::Error, backoff: Duration) -> Duration {
    error
        .chain()
        .find_map(|e| e.downcast_ref::<crate::transport::TransportError>())
        .and_then(crate::transport::TransportError::retry_after)
        .map_or(backoff, |asked| asked.max(backoff))
}

/// Somewhere in [base/2, base]. Full jitter from zero would halve the
/// effective backoff.
fn with_jitter(base: Duration) -> Duration {
    base.mul_f64(0.5 + jitter_fraction() / 2.0)
}

pub struct Scheduler {
    config: AgentConfig,
    checkin: Arc<dyn CheckIn>,
    inventory: Arc<dyn Inventory>,
    startup_spread: Duration,
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
            startup_spread: STARTUP_SPREAD,
        }
    }

    /// Overrides [`STARTUP_SPREAD`]. Mostly for tests.
    #[must_use]
    pub fn with_startup_spread(mut self, spread: Duration) -> Self {
        self.startup_spread = spread;
        self
    }

    pub async fn run<S>(self, shutdown: S)
    where
        S: std::future::Future<Output = ()> + Send + 'static,
    {
        let cancel = tokio_util_token();
        let checkin_task = tokio::spawn(checkin_loop(
            self.checkin.clone(),
            self.inventory.clone(),
            self.startup_spread,
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

/// Minimal cancellation token, to avoid a dependency for a flag and a notify.
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
        tokio::select! {
            () = tokio::time::sleep(d) => !self.is_cancelled(),
            () = self.cancelled() => false,
        }
    }

    /// Resolves when cancelled, immediately if it already has been. Used to
    /// abort the long poll on shutdown instead of waiting up to 55 seconds.
    ///
    /// `Notify::notify_waiters` only wakes waiters that are already
    /// registered, so the future is registered with `enable()` before the
    /// flag is checked a second time. Otherwise a cancel between the first
    /// check and the registration would be lost.
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.inner.1.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.is_cancelled() {
            return;
        }
        notified.await;
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

async fn checkin_loop(
    checkin: Arc<dyn CheckIn>,
    inventory: Arc<dyn Inventory>,
    startup_spread: Duration,
    cancel: Cancel,
) {
    let mut backoff = MIN_BACKOFF;

    // Only the first check-in needs spreading. After that the long polls
    // finish at different times anyway.
    if !startup_spread.is_zero() {
        let settle = jittered(startup_spread);
        tracing::debug!(delay_ms = settle.as_millis(), "first check-in scheduled");
        if !cancel.sleep(settle).await {
            return;
        }
    }

    while !cancel.is_cancelled() {
        // The long poll can be held for 55s, so race it against shutdown.
        // Dropping it just looks like a trimmed connection to the gateway.
        // The inventory upload below is quick and is left to finish.
        let result = tokio::select! {
            result = checkin.check_in() => result,
            () = cancel.cancelled() => break,
        };
        match result {
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
                // jittered so the fleet doesn't retry in lockstep
                let wait = wait_after(&error, with_jitter(backoff));
                tracing::warn!(
                    %error,
                    backoff_s = backoff.as_secs(),
                    waiting_s = wait.as_secs(),
                    "check-in failed"
                );
                if !cancel.sleep(wait).await {
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

    /// A check-in that never returns, like a held long poll. `Fake` returns
    /// immediately, so it can't test interrupting one.
    struct Held {
        started: Arc<tokio::sync::Semaphore>,
    }

    #[async_trait]
    impl CheckIn for Held {
        async fn check_in(&self) -> anyhow::Result<CheckinOutcome> {
            self.started.add_permits(1);
            tokio::time::sleep(Duration::from_secs(3600)).await;
            unreachable!("the held check-in was allowed to finish")
        }
    }

    #[async_trait]
    impl Inventory for Held {
        async fn collect_and_upload(&self) -> anyhow::Result<()> {
            Ok(())
        }
        async fn refresh_metadata(&self) -> anyhow::Result<()> {
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
        let sched = Scheduler::new(config("1h", "1h"), fake.clone(), fake.clone())
            .with_startup_spread(Duration::ZERO);

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
        let sched = Scheduler::new(config("1s", "1s"), fake.clone(), fake.clone())
            .with_startup_spread(Duration::ZERO);

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

    #[test]
    fn a_rate_limited_check_in_waits_at_least_as_long_as_it_was_asked() {
        let limited = || crate::transport::TransportError::RateLimited {
            url: "https://agents.updawg.net/agent/v1/checkin".into(),
            retry_after: Duration::from_secs(30),
        };
        let backoff = Duration::from_secs(2);
        assert_eq!(
            wait_after(&anyhow::Error::from(limited()), backoff),
            Duration::from_secs(30)
        );
        // wrapped in context, as the check-in does
        assert_eq!(
            wait_after(
                &anyhow::Error::from(limited()).context("checking in"),
                backoff
            ),
            Duration::from_secs(30)
        );
        assert_eq!(
            wait_after(&anyhow::Error::from(limited()), Duration::from_secs(120)),
            Duration::from_secs(120)
        );
        assert_eq!(wait_after(&anyhow::anyhow!("refused"), backoff), backoff);
    }

    #[tokio::test]
    async fn a_failing_gateway_is_backed_off_rather_than_hammered() {
        let counters = Arc::new(Counters::default());
        counters.fail_checkin.store(true, Ordering::SeqCst);
        let fake = Arc::new(Fake(counters.clone()));
        let sched = Scheduler::new(config("1h", "1h"), fake.clone(), fake.clone())
            .with_startup_spread(Duration::ZERO);

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
    async fn shutdown_does_not_wait_out_a_held_check_in() {
        let started = Arc::new(tokio::sync::Semaphore::new(0));
        let held = Arc::new(Held {
            started: started.clone(),
        });
        let sched = Scheduler::new(config("1h", "1h"), held.clone(), held.clone())
            .with_startup_spread(Duration::ZERO);

        let (tx, rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(sched.run(async move {
            let _ = rx.await;
        }));

        // wait until the check-in is actually in flight
        let _permit = tokio::time::timeout(Duration::from_secs(5), started.acquire())
            .await
            .expect("the check-in never started");

        let at = std::time::Instant::now();
        let _ = tx.send(());
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("shutdown hung with a check-in in flight")
            .expect("the scheduler task panicked");

        assert!(
            at.elapsed() < Duration::from_secs(2),
            "shutdown waited {:?} for a held check-in",
            at.elapsed()
        );
    }

    #[tokio::test]
    async fn cancelling_between_the_check_and_the_wait_is_not_missed() {
        // Repeated to hit the window between the flag check and registering
        // with the Notify.
        for _ in 0..200 {
            let cancel = Cancel::new();
            let waiter = {
                let cancel = cancel.clone();
                tokio::spawn(async move { cancel.cancelled().await })
            };
            tokio::task::yield_now().await;
            cancel.cancel();
            tokio::time::timeout(Duration::from_secs(5), waiter)
                .await
                .expect("cancelled() missed a cancel and waited for ever")
                .expect("waiter panicked");
        }
    }

    #[tokio::test]
    async fn cancelling_before_waiting_resolves_immediately() {
        let cancel = Cancel::new();
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), cancel.cancelled())
            .await
            .expect("a cancel that already happened was not noticed");
        assert!(!cancel.sleep(Duration::from_secs(3600)).await);
    }

    #[test]
    fn backoff_jitter_stays_in_the_upper_half() {
        for base in [MIN_BACKOFF, Duration::from_secs(30), MAX_BACKOFF] {
            for _ in 0..200 {
                let wait = with_jitter(base);
                assert!(
                    wait >= base / 2 && wait <= base,
                    "{wait:?} outside [{:?}, {base:?}]",
                    base / 2
                );
            }
        }
    }

    #[test]
    fn a_mass_restart_is_spread_across_the_startup_window() {
        let delays: Vec<Duration> = (0..500).map(|_| jittered(STARTUP_SPREAD)).collect();

        for d in &delays {
            assert!(*d <= STARTUP_SPREAD, "{d:?} exceeds the window");
        }
        // clock-seeded, so a tight loop can repeat values; just check it varies
        let distinct: std::collections::BTreeSet<u128> =
            delays.iter().map(std::time::Duration::as_millis).collect();
        assert!(
            distinct.len() > 1,
            "every host would start at the same moment"
        );
    }

    #[tokio::test]
    async fn shutdown_stops_everything_promptly() {
        let counters = Arc::new(Counters::default());
        let fake = Arc::new(Fake(counters.clone()));
        let sched = Scheduler::new(config("1h", "1h"), fake.clone(), fake.clone())
            .with_startup_spread(Duration::ZERO);

        let (tx, rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(sched.run(async move {
            let _ = rx.await;
        }));

        tokio::time::sleep(Duration::from_millis(20)).await;
        let started = std::time::Instant::now();
        let _ = tx.send(());
        handle.await.unwrap();

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
