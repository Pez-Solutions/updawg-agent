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

/// Window the first check-in of a process is spread across.
///
/// Short, because it delays nothing else and a host that has just booted has
/// little to say. It exists for the case where ten thousand hosts boot at once.
const STARTUP_SPREAD: Duration = Duration::from_secs(10);

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

/// Somewhere in the upper half of `base`.
///
/// Full jitter — a uniform draw from zero — would keep the average retry delay
/// half of what the backoff says, which quietly makes a long outage four times
/// noisier than intended. Half to full keeps the backoff meaningful while still
/// breaking up the herd.
fn with_jitter(base: Duration) -> Duration {
    base.mul_f64(0.5 + jitter_fraction() / 2.0)
}

pub struct Scheduler {
    config: AgentConfig,
    checkin: Arc<dyn CheckIn>,
    inventory: Arc<dyn Inventory>,
    /// Window the first check-in is spread across. See [`STARTUP_SPREAD`].
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

    /// Change how long the first check-in is delayed.
    ///
    /// Exists because the spread is measured in seconds and a test that has to
    /// wait through it is a test nobody runs. An operator with a single host
    /// has a fair use for it too: spreading a fleet of one achieves nothing.
    #[must_use]
    pub fn with_startup_spread(mut self, spread: Duration) -> Self {
        self.startup_spread = spread;
        self
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
        tokio::select! {
            () = tokio::time::sleep(d) => !self.is_cancelled(),
            () = self.cancelled() => false,
        }
    }

    /// Resolves when cancelled, immediately if it already has been.
    ///
    /// For racing against work that would otherwise have to finish. The
    /// check-in long poll is held open by the gateway for up to 55 seconds, and
    /// waiting that out on every SIGTERM is the difference between
    /// `systemctl restart` taking a second and taking a minute (DAWG-222).
    ///
    /// # The registration has to come before the second check
    ///
    /// `Notify::notify_waiters` wakes the waiters that are *already*
    /// registered and remembers nothing for anybody who arrives later. A cancel
    /// landing between the flag check and the registration would therefore be
    /// missed for ever, and this future would never resolve. `enable()` is
    /// tokio's way of joining the wait list without polling to completion, so
    /// the flag can be re-read afterwards and the window is closed.
    ///
    /// The old `sleep` had the same race with a milder symptom: it would have
    /// waited out the full duration and then noticed. Which for the inventory
    /// timer is six hours.
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

    // A fleet that loses power and comes back does so together, and every
    // agent would otherwise open its first check-in in the same second. The
    // first one waits a moment; after that the long poll spreads them out on
    // its own, because they finish at different times.
    if !startup_spread.is_zero() {
        let settle = jittered(startup_spread);
        tracing::debug!(delay_ms = settle.as_millis(), "first check-in scheduled");
        if !cancel.sleep(settle).await {
            return;
        }
    }

    while !cancel.is_cancelled() {
        // Raced against the cancel token rather than awaited, because this is
        // the call the gateway deliberately holds open for up to 55 seconds.
        // Dropping the future aborts the request, which the gateway already
        // copes with — a long poll dropped by the client is indistinguishable
        // from one a network trimmed, and it handles that every day.
        //
        // The inventory upload below is *not* raced. It takes well under a
        // second, and interrupting a write to the server is a worse trade than
        // waiting for it.
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
                // Sleep somewhere in [half, full] of the current backoff. A
                // gateway coming back from an outage is met by a fleet that
                // has been failing in lockstep, and retrying in lockstep is
                // how it goes down again immediately.
                let wait = with_jitter(backoff);
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

    /// A check-in that never answers, which is what a held long poll looks
    /// like from here.
    ///
    /// The gateway holds a check-in open for up to 55 seconds when there is
    /// nothing to report. `Fake` above returns immediately, so every shutdown
    /// test written against it has been measuring a scheduler that had nothing
    /// to interrupt.
    struct Held {
        started: Arc<tokio::sync::Semaphore>,
    }

    #[async_trait]
    impl CheckIn for Held {
        async fn check_in(&self) -> anyhow::Result<CheckinOutcome> {
            self.started.add_permits(1);
            // An hour, not a minute: the assertion should fail by being slow,
            // not by the test hanging for ever if the race is wrong.
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

    /// Half to full, never zero. Full jitter would halve the effective
    /// backoff, quietly making a long outage noisier than the constants say.
    #[tokio::test]
    async fn shutdown_does_not_wait_out_a_held_check_in() {
        // DAWG-222. Measured at 39 seconds against a real gateway before the
        // fix, because the in-flight long poll was awaited rather than raced.
        //
        // `shutdown_stops_everything_promptly` below asserts exactly this and
        // passed throughout, because its check-in returns immediately. The
        // assertion was right; the input could not exercise it.
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

        // Wait for the check-in to actually be in flight. Sleeping a fixed
        // amount here is the difference between a test that is slow and a test
        // that is flaky, and it would also let a shutdown that never had
        // anything to interrupt pass by accident.
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
        // `notify_waiters` wakes only the waiters already registered, so a
        // cancel landing in the window between reading the flag and joining
        // the wait list would be lost and `cancelled()` would never resolve.
        //
        // Run enough times to hit the window, and with a timeout, so the
        // failure is a failure rather than a hang.
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

    /// Mass restart: ten thousand hosts booting together must not open their
    /// first check-in in the same instant. The spread is what stops the
    /// gateway meeting the whole fleet at once.
    #[test]
    fn a_mass_restart_is_spread_across_the_startup_window() {
        let delays: Vec<Duration> = (0..500).map(|_| jittered(STARTUP_SPREAD)).collect();

        for d in &delays {
            assert!(*d <= STARTUP_SPREAD, "{d:?} exceeds the window");
        }
        // Jitter is seeded from the clock, so a tight loop can draw the same
        // value repeatedly; what matters is that it is not one fixed value.
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
