//! Tests for the check-in loop.
//!
//! Against a real TLS gateway that can hold a request open and hang up
//! mid-poll, because the interesting behaviour here is entirely about timing
//! and about telling a trimmed idle connection apart from an outage. A mock
//! that returns errors instantly cannot tell those apart either, which is the
//! bug this is guarding.

use super::*;
use crate::testing::{EnrolledHost, Reply, TestCa, TestGateway, transport};
use std::sync::atomic::{AtomicUsize, Ordering};
use updawg_collectors::testing::FakeHost;

const THIRTY_DAYS: Duration = Duration::from_secs(30 * 86_400);

/// Records what it was handed instead of running it.
#[derive(Debug, Default)]
struct RecordingSink {
    delivered: std::sync::Mutex<Vec<String>>,
    count: AtomicUsize,
}

#[async_trait]
impl JobSink for RecordingSink {
    async fn deliver(&self, job: Job) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.delivered
            .lock()
            .unwrap()
            .push(job.id.as_str().to_string());
    }
}

struct Harness {
    host: EnrolledHost,
    /// Kept alive: dropping it removes the fixture directory the collector reads.
    _fake: FakeHost,
    checkin: GatewayCheckIn,
    sink: Arc<RecordingSink>,
    gateway: TestGateway,
}

async fn harness(replies: Vec<Reply>) -> Harness {
    let ca = TestCa::new();
    let host = EnrolledHost::new(&ca, THIRTY_DAYS);
    let gateway = TestGateway::scripted(&ca, replies).await;
    let transport = Arc::new(transport(&host, &gateway, &ca));

    let fake = FakeHost::debian();
    let collector = SystemState::new(fake.root()).unwrap();
    let sink = Arc::new(RecordingSink::default());

    let checkin = GatewayCheckIn::new(
        transport,
        host.state.clone(),
        collector,
        sink.clone() as Arc<dyn JobSink>,
        updawg_protocol::LocalPolicy::default(),
    );

    Harness {
        host,
        _fake: fake,
        checkin,
        sink,
        gateway,
    }
}

fn empty_response() -> String {
    r#"{"next_checkin_s":0,"inventory_requested":false,"config_version":1}"#.into()
}

fn response_with_job() -> String {
    serde_json::json!({
        "next_checkin_s": 0,
        "inventory_requested": false,
        "config_version": 1,
        "jobs": [{
            "id": "job_01J9ZD",
            "host_id": "hst_01J9ZC6Q",
            "kind": "apply_updates",
            "payload": { "packages": [], "reboot": "never", "snapshot": "never" },
            "expires_at": "2026-09-19T21:00:00Z",
            "key_id": "sk_01J8",
            "signature": "AAAA"
        }]
    })
    .to_string()
}

/// The check-in body is what the whole system runs on. It must carry what the
/// collectors found, and it must be assembled from them rather than invented.
#[tokio::test]
async fn the_check_in_carries_what_the_collectors_found() {
    let h = harness(vec![Reply::Now(200, empty_response())]).await;
    h.checkin.check_in().await.unwrap();

    let seen = h.gateway.seen.lock().unwrap();
    let body: serde_json::Value = serde_json::from_str(&seen[0].body).unwrap();

    assert_eq!(seen[0].path, "/agent/v1/checkin");
    assert_eq!(body["boot_id"], "b81e5c7a-1f2d-4c3b-9a8e-0d1f2a3b4c5d");
    assert_eq!(body["uptime_s"], 864_000);
    // A word since protocol 0.4 (DAWG-210): a Debian host with no flag file.
    assert_eq!(body["state"]["reboot_required"], "no");
    // 16 GB total, 12 GB available.
    assert!((body["metrics"]["mem_used_pct"].as_f64().unwrap() - 25.0).abs() < 0.01);
}

/// Every check-in says which organization keys the host verifies against
/// (DAWG-293), read from its own identity rather than from anything the
/// server offered, so a rotation adopted at renewal shows at the next one.
#[tokio::test]
async fn the_check_in_says_which_keys_the_host_has_pinned() {
    let h = harness(vec![Reply::Now(200, empty_response())]).await;
    let mut identity = h.host.state.identity().unwrap().unwrap();
    identity.org_signing_keys = vec![updawg_protocol::OrgSigningKey {
        key_id: updawg_protocol::SigningKeyId::new("sk_01J8"),
        public_key: "ed25519:AAAA".into(),
        status: updawg_protocol::SigningKeyStatus::Active,
        endorsement: None,
    }];
    h.host.state.save_identity(&identity).unwrap();

    h.checkin.check_in().await.unwrap();

    let seen = h.gateway.seen.lock().unwrap();
    let body: serde_json::Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(body["pinned_keys"], serde_json::json!(["sk_01J8"]));
}

/// The point of a long poll: it comes back the moment there is something to
/// come back with, not on the next tick of a timer.
#[tokio::test]
async fn a_job_arriving_mid_poll_returns_promptly() {
    let h = harness(vec![Reply::After(
        Duration::from_millis(300),
        200,
        response_with_job(),
    )])
    .await;

    let started = Instant::now();
    let outcome = h.checkin.check_in().await.unwrap();
    let elapsed = started.elapsed();

    assert_eq!(h.sink.count.load(Ordering::SeqCst), 1);
    assert_eq!(h.sink.delivered.lock().unwrap()[0], "job_01J9ZD");
    // It waited for the job rather than giving up...
    assert!(elapsed >= Duration::from_millis(280), "returned too early");
    // ...and came back with it rather than sitting out the rest of the hold.
    assert!(
        elapsed < Duration::from_secs(5),
        "took {elapsed:?}; a job should return immediately, not at the end of the hold"
    );
    assert_eq!(outcome.next_checkin, Duration::ZERO);
}

/// The acceptance criterion, and the reason this module exists. A proxy that
/// hangs up on an idle long poll must not look like an outage: backing off
/// there makes the agent slow to reach for no reason at all.
#[tokio::test]
async fn a_proxy_hanging_up_mid_poll_is_not_treated_as_a_failure() {
    let h = harness(vec![Reply::HangUpAfter(Duration::from_secs(6))]).await;

    let outcome = h
        .checkin
        .check_in()
        .await
        .expect("a trimmed idle connection is not a check-in failure");

    assert_eq!(
        outcome.next_checkin,
        Duration::ZERO,
        "the agent should poll straight back, not back off"
    );
    assert!(!outcome.inventory_requested);
}

/// The observation is recorded so it can be reported, and the hold is left
/// alone. Shortening the agent's own timeout would only make it abandon polls
/// the gateway was about to answer — the gateway decides the hold, not us.
#[tokio::test]
async fn a_trimmed_poll_is_recorded_without_changing_the_hold() {
    let h = harness(vec![Reply::HangUpAfter(Duration::from_secs(6))]).await;
    assert_eq!(h.checkin.observed_idle_limit(), None);

    h.checkin.check_in().await.unwrap();

    let observed = h
        .checkin
        .observed_idle_limit()
        .expect("should have been recorded");
    assert!(
        observed >= Duration::from_secs(5) && observed < Duration::from_secs(20),
        "recorded a nonsensical idle limit: {observed:?}"
    );
    assert_eq!(
        h.checkin.hold(),
        Duration::from_secs(55),
        "the gateway decides the hold; the agent must not quietly give up sooner"
    );
}

/// A gateway that is genuinely unreachable fails fast, and that *is* a failure.
/// If this were also swallowed, an agent would spin against a dead gateway
/// forever instead of backing off.
#[tokio::test]
async fn a_gateway_that_fails_immediately_is_still_a_failure() {
    let ca = TestCa::new();
    let host = EnrolledHost::new(&ca, THIRTY_DAYS);
    // Nothing listening on this port.
    let transport = Arc::new(
        MtlsTransport::with_extra_root(
            "https://localhost:1",
            host.state.clone(),
            Some(ca.pem.clone().into_bytes()),
        )
        .unwrap(),
    );

    let fake = FakeHost::debian();
    let checkin = GatewayCheckIn::new(
        transport,
        host.state.clone(),
        SystemState::new(fake.root()).unwrap(),
        Arc::new(UnhandledJobs),
        updawg_protocol::LocalPolicy::default(),
    );

    let err = checkin.check_in().await.unwrap_err();
    assert!(
        err.to_string().contains("could not reach"),
        "expected a transport failure, got: {err}"
    );
    assert_eq!(
        checkin.observed_idle_limit(),
        None,
        "a fast failure says nothing about the network's idle timeout"
    );
}

/// Only the shortest observation is kept, so a network that trims every poll
/// produces one log line rather than a stream of them.
#[tokio::test]
async fn only_the_shortest_idle_limit_is_kept() {
    let h = harness(vec![]).await;
    h.checkin.record_idle_limit(Duration::from_secs(30));
    h.checkin.record_idle_limit(Duration::from_secs(40));
    assert_eq!(
        h.checkin.observed_idle_limit(),
        Some(Duration::from_secs(30))
    );
    h.checkin.record_idle_limit(Duration::from_secs(12));
    assert_eq!(
        h.checkin.observed_idle_limit(),
        Some(Duration::from_secs(12))
    );
}

/// A host that cannot read its own state still checks in. A heartbeat that
/// says less is worth much more than no heartbeat: a host that goes quiet is
/// indistinguishable from one that was switched off.
#[tokio::test]
async fn a_host_that_cannot_read_its_state_still_checks_in() {
    let ca = TestCa::new();
    let host = EnrolledHost::new(&ca, THIRTY_DAYS);
    let gateway = TestGateway::scripted(&ca, vec![Reply::Now(200, empty_response())]).await;
    let transport = Arc::new(transport(&host, &gateway, &ca));

    let bare = FakeHost::debian();
    std::fs::remove_file(bare.root().join("proc/meminfo")).unwrap();
    std::fs::remove_file(bare.root().join("proc/uptime")).unwrap();

    let checkin = GatewayCheckIn::new(
        transport,
        host.state.clone(),
        SystemState::new(bare.root()).unwrap(),
        Arc::new(UnhandledJobs),
        updawg_protocol::LocalPolicy::default(),
    );

    checkin
        .check_in()
        .await
        .expect("a degraded check-in is still a check-in");
    let seen = gateway.seen.lock().unwrap();
    let body: serde_json::Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(body["uptime_s"], 0);
    assert_eq!(body["boot_id"], "b81e5c7a-1f2d-4c3b-9a8e-0d1f2a3b4c5d");
}

/// The inventory hash rides on every check-in so the server can notice the two
/// have diverged. Before anything has been uploaded it is empty, which is
/// correct and is what makes the server ask.
#[tokio::test]
async fn the_inventory_hash_is_reported_and_survives_a_restart() {
    let h = harness(vec![
        Reply::Now(200, empty_response()),
        Reply::Now(200, empty_response()),
    ])
    .await;

    h.checkin.check_in().await.unwrap();
    h.host.state.set_inventory_hash("sha256:9f86d0").unwrap();
    h.checkin.check_in().await.unwrap();

    let seen = h.gateway.seen.lock().unwrap();
    let first: serde_json::Value = serde_json::from_str(&seen[0].body).unwrap();
    let second: serde_json::Value = serde_json::from_str(&seen[1].body).unwrap();
    assert_eq!(first["inventory_hash"], "");
    assert_eq!(second["inventory_hash"], "sha256:9f86d0");
}
