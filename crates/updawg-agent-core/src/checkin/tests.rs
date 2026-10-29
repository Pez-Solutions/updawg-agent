//! These run against a real TLS gateway that can hold a request and hang up
//! mid-poll. The behaviour under test depends on timing, which a mock that
//! fails instantly can't reproduce.

use super::*;
use crate::testing::{EnrolledHost, Reply, TestCa, TestGateway, transport};
use std::sync::atomic::{AtomicUsize, Ordering};
use updawg_collectors::testing::FakeHost;

const THIRTY_DAYS: Duration = Duration::from_secs(30 * 86_400);

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
    /// dropping it removes the fixture directory the collector reads
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

#[tokio::test]
async fn the_check_in_carries_what_the_collectors_found() {
    let h = harness(vec![Reply::Now(200, empty_response())]).await;
    h.checkin.check_in().await.unwrap();

    let seen = h.gateway.seen.lock().unwrap();
    let body: serde_json::Value = serde_json::from_str(&seen[0].body).unwrap();

    assert_eq!(seen[0].path, "/agent/v1/checkin");
    assert_eq!(body["boot_id"], "b81e5c7a-1f2d-4c3b-9a8e-0d1f2a3b4c5d");
    assert_eq!(body["uptime_s"], 864_000);
    // Debian fixture has no reboot-required flag file
    assert_eq!(body["state"]["reboot_required"], "no");
    // 16 GB total, 12 GB available.
    assert!((body["metrics"]["mem_used_pct"].as_f64().unwrap() - 25.0).abs() < 0.01);
}

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
    assert!(elapsed >= Duration::from_millis(280), "returned too early");
    assert!(
        elapsed < Duration::from_secs(5),
        "took {elapsed:?}; a job should return immediately, not at the end of the hold"
    );
    assert_eq!(outcome.next_checkin, Duration::ZERO);
}

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

/// One cut is not an idle limit: a gateway restart cuts every held poll at a
/// random point. The agent's own timeout is left alone too; the gateway
/// decides the hold.
#[tokio::test]
async fn one_trimmed_poll_is_not_taken_for_an_idle_limit() {
    let h = harness(vec![
        Reply::HangUpAfter(Duration::from_secs(6)),
        Reply::Now(200, empty_response()),
    ])
    .await;

    h.checkin.check_in().await.unwrap();
    h.checkin.check_in().await.unwrap();

    assert_eq!(h.checkin.observed_idle_limit(), None);
    assert_eq!(h.checkin.requested_hold(), None);
    let seen = h.gateway.seen.lock().unwrap();
    let body: serde_json::Value = serde_json::from_str(&seen[1].body).unwrap();
    assert!(
        body.get("max_hold_s").is_none(),
        "one cut should not change the hold asked for: {body}"
    );
    assert_eq!(
        h.checkin.hold(),
        Duration::from_secs(55),
        "the gateway decides the hold; the agent must not quietly give up sooner"
    );
}

/// A proxy that trims at 30s every time is believed after [`CONFIRM_CUTS`]
/// cuts and asked for 20s. A poll answered early in between doesn't reset the
/// count.
#[tokio::test]
async fn cuts_at_the_same_point_converge_on_two_thirds_of_it() {
    let h = harness(vec![]).await;
    h.checkin.record_idle_limit(Duration::from_secs(31));
    h.checkin.record_answered(Duration::from_secs(2));
    h.checkin.record_idle_limit(Duration::from_secs(30));
    assert_eq!(h.checkin.requested_hold(), None, "not after two");
    h.checkin.record_idle_limit(Duration::from_secs(32));
    assert_eq!(
        h.checkin.observed_idle_limit(),
        Some(Duration::from_secs(30)),
        "the shortest of the run"
    );
    assert_eq!(h.checkin.requested_hold(), Some(20));
}

/// Cuts at random points, as deploys cause, don't change what is asked for,
/// whether or not a limit has been learned.
#[tokio::test]
async fn cuts_at_random_points_do_not_change_the_hold() {
    let h = harness(vec![]).await;
    for after in [12, 41, 23, 7, 50] {
        h.checkin.record_idle_limit(Duration::from_secs(after));
    }
    assert_eq!(h.checkin.requested_hold(), None);

    for _ in 0..CONFIRM_CUTS {
        h.checkin.record_idle_limit(Duration::from_secs(30));
    }
    h.checkin.record_idle_limit(Duration::from_secs(7));
    assert_eq!(h.checkin.requested_hold(), Some(20));
    // The next poll, held for the 20s asked for, outlives the stray cut.
    h.checkin.record_answered(Duration::from_secs(20));
    h.checkin.record_idle_limit(Duration::from_secs(8));
    h.checkin.record_idle_limit(Duration::from_secs(7));
    assert_eq!(h.checkin.requested_hold(), Some(20));
}

/// After [`RELEARN_AFTER`] the full hold is retried; if it survives, the limit
/// is forgotten and has to be seen [`CONFIRM_CUTS`] times again.
#[test]
fn a_learned_limit_is_forgotten_when_the_full_hold_survives() {
    let start = Instant::now();
    let thirty = Duration::from_secs(30);
    let mut limit = IdleLimit::default();
    assert_eq!(limit.cut(thirty, start), Learned::Nothing);
    assert_eq!(limit.cut(thirty, start), Learned::Nothing);
    assert_eq!(limit.cut(thirty, start), Learned::New(thirty));

    let almost = start + RELEARN_AFTER.saturating_sub(Duration::from_secs(1));
    assert_eq!(limit.current(almost), Some(thirty));
    assert_eq!(limit.current(start + RELEARN_AFTER), None, "retried");

    limit.answered(Duration::from_secs(55));
    assert_eq!(limit.cut(thirty, start + RELEARN_AFTER), Learned::Nothing);
    assert_eq!(limit.current(start + RELEARN_AFTER), None);
}

/// A limit that still applies after the retry is believed again on the first
/// cut at the same point, so a network that really trims doesn't flap.
#[test]
fn a_limit_that_still_applies_is_believed_again_after_one_cut() {
    let start = Instant::now();
    let thirty = Duration::from_secs(30);
    let mut limit = IdleLimit::default();
    for _ in 0..CONFIRM_CUTS {
        limit.cut(thirty, start);
    }
    let retry = start + RELEARN_AFTER;
    assert_eq!(limit.current(retry), None);
    assert_eq!(
        limit.cut(Duration::from_secs(29), retry),
        Learned::Again(Duration::from_secs(29))
    );
    assert_eq!(limit.current(retry), Some(Duration::from_secs(29)));
    assert_eq!(
        limit.current(retry + RELEARN_AFTER.saturating_sub(Duration::from_secs(1))),
        Some(Duration::from_secs(29)),
        "and believed for another hour"
    );
}

/// Otherwise the agent would spin against a dead gateway instead of backing
/// off.
#[tokio::test]
async fn a_gateway_that_fails_immediately_is_still_a_failure() {
    let ca = TestCa::new();
    let host = EnrolledHost::new(&ca, THIRTY_DAYS);
    // nothing listens on port 1
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

/// The hash is empty until an inventory has been uploaded; that's what makes
/// the server ask for one.
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

#[test]
fn a_running_agent_looks_at_its_certificate_every_hour() {
    let start = Instant::now();
    let mut plan = RenewalPlan::new(start);
    assert_eq!(plan.step(start, false, false, 0.5), RenewalStep::Nothing);
    let later = start + RENEWAL_CHECK;
    assert_eq!(plan.step(later, false, false, 0.5), RenewalStep::Check);
    assert_eq!(
        plan.step(later, false, false, 0.5),
        RenewalStep::Nothing,
        "once an hour"
    );
}

#[test]
fn a_renewal_the_server_asks_for_is_spread_and_not_postponed() {
    let start = Instant::now();
    let mut plan = RenewalPlan::new(start);
    let at = start + RENEW_NOW_SPREAD.mul_f64(0.5);
    assert_eq!(plan.step(start, true, false, 0.5), RenewalStep::Nothing);
    assert_eq!(
        plan.step(start + RENEW_NOW_SPREAD.mul_f64(0.4), true, false, 0.5),
        RenewalStep::Nothing
    );
    assert_eq!(plan.step(at, true, false, 0.5), RenewalStep::Force);
    plan.renewed(at);
    assert_eq!(plan.step(at, false, false, 0.5), RenewalStep::Nothing);
}

/// Spread 0.0 puts the host at the start of the window, so the server's
/// request is immediate too.
#[test]
fn by_hand_is_now_and_a_failure_is_retried() {
    let start = Instant::now();
    let mut plan = RenewalPlan::new(start);
    assert_eq!(plan.step(start, true, false, 0.0), RenewalStep::Force);
    plan.failed(start);
    assert_eq!(
        plan.step(start, true, false, 0.0),
        RenewalStep::Nothing,
        "not straight away"
    );
    assert_eq!(
        plan.step(start + RENEW_NOW_RETRY, true, false, 0.0),
        RenewalStep::Force
    );

    let mut plan = RenewalPlan::new(start);
    assert_eq!(plan.step(start, false, true, 1.0), RenewalStep::Force);
}
