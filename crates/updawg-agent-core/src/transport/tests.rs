//! Tests for the authenticated transport.
//!
//! These run a real TLS server in-process, with a real CA, and require a client
//! certificate. Nothing here mocks the handshake, because the handshake is the
//! part that is easy to get subtly wrong: a client that builds fine, connects
//! fine, and quietly presents no certificate at all would pass any test that
//! stopped at the HTTP layer.

use super::*;
use crate::testing::{EnrolledHost, NEXT, TestCa, TestGateway, checkin_request, transport};
use std::{fs, sync::atomic::Ordering};

const THIRTY_DAYS: Duration = Duration::from_secs(30 * 86_400);
const LONG_POLL: Duration = Duration::from_secs(55);

/// The one that matters: the client really presents its certificate, and the
/// server really required it.
#[tokio::test]
async fn every_request_presents_the_client_certificate() {
    let ca = TestCa::new();
    let host = EnrolledHost::new(&ca, THIRTY_DAYS);
    let gateway = TestGateway::start(
        &ca,
        vec![(
            200,
            r#"{"next_checkin_s":0,"inventory_requested":false,"config_version":7}"#.into(),
        )],
    )
    .await;

    let transport = transport(&host, &gateway, &ca);
    let response = transport
        .check_in(&checkin_request(), LONG_POLL)
        .await
        .unwrap();

    assert_eq!(response.config_version, 7);
    let seen = gateway.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/agent/v1/checkin");
    assert!(
        seen[0]
            .client_subject
            .as_deref()
            .is_some_and(|s| s.contains("hst_01J9ZC6Q")),
        "the gateway saw no client certificate: {:?}",
        seen[0].client_subject
    );
    assert!(seen[0].body.contains("b81e"));
}

/// End-to-end rotation: renew, then prove the *new* certificate is what the
/// next request presents. Checking only that the file changed would miss a
/// client that was never rebuilt.
#[tokio::test]
async fn a_renewed_certificate_is_what_the_next_request_presents() {
    let ca = TestCa::new();
    // Twenty-five days into a thirty-day life, so renewal is due now.
    let host = EnrolledHost::aged(&ca, Duration::from_secs(25 * 86_400), THIRTY_DAYS);
    let renewed_pem = ca.issue_for(
        "hst_01J9ZC6Q_renewed",
        vec![],
        Duration::ZERO,
        THIRTY_DAYS,
        &host.key(),
    );

    let renewal = serde_json::json!({
        "certificate": renewed_pem,
        "ca_chain": [ca.pem],
    })
    .to_string();

    let gateway = TestGateway::start(
        &ca,
        vec![
            (200, renewal),
            (
                200,
                r#"{"next_checkin_s":0,"inventory_requested":false,"config_version":1}"#.into(),
            ),
        ],
    )
    .await;

    let transport = transport(&host, &gateway, &ca);
    let before = transport.certificate().serial().to_string();

    let outcome = transport.renew_if_due(SystemTime::now()).await.unwrap();
    assert!(
        matches!(outcome, Renewal::Renewed { .. }),
        "got {outcome:?}"
    );
    assert_ne!(transport.certificate().serial(), before);

    // Survives a restart, and is what the wire sees.
    let reloaded = host.state.identity().unwrap().unwrap();
    assert!(reloaded.certificate.contains("BEGIN CERTIFICATE"));
    assert_eq!(
        ClientCertificate::from_pem(&reloaded.certificate)
            .unwrap()
            .serial(),
        transport.certificate().serial()
    );

    transport
        .check_in(&checkin_request(), LONG_POLL)
        .await
        .unwrap();
    let seen = gateway.seen();
    assert_eq!(seen[0].path, "/agent/v1/cert/renew");
    assert!(
        seen[1]
            .client_subject
            .as_deref()
            .is_some_and(|s| s.contains("renewed")),
        "the rebuilt client did not present the new certificate: {:?}",
        seen[1].client_subject
    );
}

#[tokio::test]
async fn renewal_does_nothing_while_the_certificate_is_young() {
    let ca = TestCa::new();
    let host = EnrolledHost::new(&ca, THIRTY_DAYS);
    let gateway = TestGateway::start(&ca, vec![]).await;
    let transport = transport(&host, &gateway, &ca);

    let outcome = transport.renew_if_due(SystemTime::now()).await.unwrap();
    assert!(matches!(outcome, Renewal::NotDue { .. }), "got {outcome:?}");
    assert!(
        gateway.seen().is_empty(),
        "a certificate with a month left should not have contacted the gateway"
    );
}

/// The renewal response is validated before it is adopted, for the same reason
/// the enrollment response is: a certificate that cannot work must not replace
/// one that does.
#[tokio::test]
async fn a_certificate_for_the_wrong_key_is_refused_and_the_old_one_kept() {
    let ca = TestCa::new();
    let host = EnrolledHost::aged(&ca, Duration::from_secs(25 * 86_400), THIRTY_DAYS);
    // Issued for a key this host does not hold.
    let (wrong, _) = ca.issue("hst_01J9ZC6Q", THIRTY_DAYS);

    let gateway = TestGateway::start(
        &ca,
        std::iter::repeat_n(
            (
                200,
                serde_json::json!({ "certificate": wrong, "ca_chain": [ca.pem] }).to_string(),
            ),
            RENEW_ATTEMPTS as usize,
        )
        .collect(),
    )
    .await;

    let transport = transport(&host, &gateway, &ca);
    let before = transport.certificate().serial().to_string();

    let err = transport.renew_if_due(SystemTime::now()).await.unwrap_err();
    assert!(
        err.to_string().contains("different key"),
        "expected the key mismatch to be named, got: {err}"
    );
    assert_eq!(
        transport.certificate().serial(),
        before,
        "a refused renewal must leave the working certificate in place"
    );
}

#[tokio::test]
async fn a_rejected_certificate_says_what_to_do_about_it() {
    let ca = TestCa::new();
    let host = EnrolledHost::new(&ca, THIRTY_DAYS);
    let gateway = TestGateway::start(&ca, vec![(403, "{}".into())]).await;
    let transport = transport(&host, &gateway, &ca);

    let err = transport
        .check_in(&checkin_request(), LONG_POLL)
        .await
        .unwrap_err();
    assert!(
        matches!(err, TransportError::CertificateRejected { .. }),
        "got {err:?}"
    );
    let text = err.to_string();
    assert!(
        text.contains("hst_01J9ZC6Q"),
        "the subject should be named: {text}"
    );
    assert!(
        text.contains("--force"),
        "the recovery step should be named: {text}"
    );
}

/// A gateway refusing an expired certificate fails at the handshake, not with
/// a status code. The local expiry is a fact we already have, so say that
/// rather than reporting an opaque connection error.
#[tokio::test]
async fn an_expired_certificate_is_diagnosed_locally() {
    let ca = TestCa::new();
    let host = EnrolledHost::aged(&ca, Duration::from_secs(120), Duration::from_secs(60));
    let gateway = TestGateway::start(&ca, vec![(200, "{}".into())]).await;
    let transport = transport(&host, &gateway, &ca);

    let err = transport
        .check_in(&checkin_request(), LONG_POLL)
        .await
        .unwrap_err();

    assert!(
        matches!(err, TransportError::CertificateExpired { .. }),
        "got {err:?}"
    );
    assert!(err.to_string().contains("--force"));
}

#[tokio::test]
async fn a_server_error_is_reported_with_its_problem_detail() {
    let ca = TestCa::new();
    let host = EnrolledHost::new(&ca, THIRTY_DAYS);
    let gateway = TestGateway::start(
        &ca,
        vec![(
            503,
            r#"{"title":"Unavailable","detail":"The gateway is draining."}"#.into(),
        )],
    )
    .await;

    let err = transport(&host, &gateway, &ca)
        .check_in(&checkin_request(), LONG_POLL)
        .await
        .unwrap_err();
    assert!(
        matches!(err, TransportError::Server { status: 503, .. }),
        "got {err:?}"
    );
    assert!(err.to_string().contains("The gateway is draining."));
}

/// A 429 is a request to slow down, not a failure to report (DAWG-131). This
/// stub sends no `Retry-After`, so the agent waits the minute it assumes.
#[tokio::test]
async fn a_rate_limited_check_in_says_how_long_to_wait() {
    let ca = TestCa::new();
    let host = EnrolledHost::new(&ca, THIRTY_DAYS);
    let gateway = TestGateway::start(
        &ca,
        vec![(
            429,
            r#"{"code":"rate_limited","message":"slow down","retry_after_s":3}"#.into(),
        )],
    )
    .await;

    let err = transport(&host, &gateway, &ca)
        .check_in(&checkin_request(), LONG_POLL)
        .await
        .unwrap_err();
    assert_eq!(
        err.retry_after(),
        Some(Duration::from_secs(60)),
        "got {err:?}"
    );
}

#[test]
fn a_host_that_has_not_enrolled_says_so() {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("updawg-tp-bare-{}-{n}", std::process::id()));
    let state = LocalState::new(&dir);
    state.ensure().unwrap();

    let err = MtlsTransport::new("https://agents.updawg.net", state).unwrap_err();
    assert!(matches!(err, TransportError::NotEnrolled), "got {err:?}");
    fs::remove_dir_all(dir).ok();
}

#[test]
fn a_plain_http_gateway_is_refused() {
    let state = LocalState::new(std::env::temp_dir().join("updawg-tp-nothing"));
    let err = MtlsTransport::new("http://agents.updawg.net", state).unwrap_err();
    assert!(
        matches!(err, TransportError::NotHttps { .. }),
        "got {err:?}"
    );
}

/// The fleet-scale property. A thousand hosts enrolled together must not renew
/// together, and each one's offset must survive a restart.
#[test]
fn renewal_spread_is_stable_per_host_and_spread_across_the_fleet() {
    let one = spread_from("0a1b2c3d");
    assert!((0.0..1.0).contains(&one));
    assert!(
        (one - spread_from("0a1b2c3d")).abs() < f64::EPSILON,
        "the same certificate must always give the same offset"
    );

    let spread: Vec<f64> = (0..200).map(|i| spread_from(&format!("{i:08x}"))).collect();
    let low = spread.iter().filter(|s| **s < 0.5).count();
    assert!(
        (60..=140).contains(&low),
        "offsets clustered instead of spreading: {low} of 200 below the midpoint"
    );
}

#[test]
fn durations_are_described_in_units_an_operator_can_act_on() {
    assert_eq!(approximate(Duration::from_secs(30)), "30 seconds");
    assert_eq!(approximate(Duration::from_secs(600)), "10 minutes");
    assert_eq!(approximate(Duration::from_secs(7200)), "2 hours");
    assert_eq!(approximate(Duration::from_secs(10 * 86_400)), "10 days");
}

/* ------------------------------------------------------- inventory upload */

fn inventory_upload() -> updawg_protocol::InventoryUpload {
    updawg_protocol::InventoryUpload {
        kind: updawg_protocol::InventoryKind::Full,
        base_hash: None,
        hash: "sha256:aaa".into(),
        collected_at: chrono::Utc::now(),
        facts: None,
        removals: vec![],
        frozen: None,
        packages: updawg_protocol::PackageDelta {
            // Repetitive on purpose: a real package list is hundreds of similar
            // lines, which is the case zstd is best at, and a body that did not
            // actually shrink would make the assertion below meaningless.
            added: (0..200)
                .map(|i| updawg_protocol::InstalledPackage {
                    name: format!("package-{i}"),
                    version: "1.2.3-0ubuntu4".into(),
                    arch: "amd64".into(),
                    repo: Some("noble-updates".into()),
                    source: None,
                })
                .collect(),
            removed: vec![],
        },
        updates: vec![],
        repositories: vec![],
        held_packages: vec![],
    }
}

#[tokio::test]
async fn an_inventory_is_uploaded_compressed_and_arrives_intact() {
    let ca = TestCa::new();
    let host = EnrolledHost::new(&ca, THIRTY_DAYS);
    let gateway = TestGateway::start(&ca, vec![(200, r#"{"accepted":true}"#.into())]).await;

    let upload = inventory_upload();
    transport(&host, &gateway, &ca)
        .upload_inventory(&upload)
        .await
        .unwrap();

    let seen = gateway.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].method, "PUT",
        "inventory replaces a state, so it is a PUT"
    );
    assert_eq!(seen[0].path, "/agent/v1/inventory");
    assert_eq!(seen[0].header("content-encoding"), Some("zstd"));

    // The bytes on the wire are genuinely compressed, and genuinely smaller.
    // Sending the header without compressing, or compressing something that grew,
    // would both pass a test that only checked the header.
    let raw = serde_json::to_vec(&upload).unwrap();
    assert!(
        seen[0].body_bytes.len() < raw.len() / 2,
        "the body was {} bytes against {} uncompressed; it was not really compressed",
        seen[0].body_bytes.len(),
        raw.len()
    );

    // And it decompresses back to exactly what was sent — the agent compressing
    // something the gateway cannot read is the failure this is really for.
    let decoded = zstd::decode_all(seen[0].body_bytes.as_slice()).expect("the body is zstd");
    // DAWG-37: byte for byte what `updawgctl print-inventory --json` prints.
    assert_eq!(decoded, super::inventory_body(&upload).unwrap());
    let round_tripped: updawg_protocol::InventoryUpload =
        serde_json::from_slice(&decoded).expect("the body is the inventory JSON");
    assert_eq!(round_tripped.hash, upload.hash);
    assert_eq!(round_tripped.packages.added.len(), 200);
}

#[tokio::test]
async fn a_refused_delta_is_recognised_by_its_code() {
    let ca = TestCa::new();
    let host = EnrolledHost::new(&ca, THIRTY_DAYS);
    let gateway = TestGateway::start(
        &ca,
        vec![(
            409,
            r#"{"code":"inventory_base_mismatch","message":"send a full one"}"#.into(),
        )],
    )
    .await;

    let error = transport(&host, &gateway, &ca)
        .upload_inventory(&inventory_upload())
        .await
        .expect_err("a 409 is an error");

    // The agent answers this one case by sending a full inventory, so it has to
    // be told apart from every other server error — and told apart by the
    // *code*, which the protocol makes stable, rather than by the wording.
    assert!(
        error.is_inventory_base_mismatch(),
        "a base mismatch was not recognised: {error}"
    );
}

#[tokio::test]
async fn any_other_server_error_is_not_a_base_mismatch() {
    let ca = TestCa::new();
    let host = EnrolledHost::new(&ca, THIRTY_DAYS);
    // A 409 is the only status that carries the code, and a 500 that happened to
    // mention it must not send the agent down the re-upload path.
    let gateway = TestGateway::start(
        &ca,
        vec![(
            500,
            r#"{"code":"unavailable","message":"inventory_base_mismatch appears here by accident"}"#
                .into(),
        )],
    )
    .await;

    let error = transport(&host, &gateway, &ca)
        .upload_inventory(&inventory_upload())
        .await
        .expect_err("a 500 is an error");
    assert!(!error.is_inventory_base_mismatch(), "{error}");
}

#[tokio::test]
async fn a_rejected_certificate_is_reported_as_such_on_upload_too() {
    let ca = TestCa::new();
    let host = EnrolledHost::new(&ca, THIRTY_DAYS);
    let gateway =
        TestGateway::start(&ca, vec![(401, r#"{"code":"certificate_revoked"}"#.into())]).await;

    let error = transport(&host, &gateway, &ca)
        .upload_inventory(&inventory_upload())
        .await
        .expect_err("a 401 is an error");

    // "re-enroll this host", not "the inventory was bad". Every path to the
    // gateway has to say the same thing about a dead certificate, or an operator
    // gets a different diagnosis depending on which request happened to run.
    assert!(
        matches!(error, TransportError::CertificateRejected { .. }),
        "{error}"
    );
}

// ---- Following a rotation at renewal (DAWG-99) ----

/// A throwaway organization key that keeps its private half, so these can
/// endorse rather than assert against a fixture.
struct RotationKey {
    pair: aws_lc_rs::signature::Ed25519KeyPair,
    wire: String,
}

impl RotationKey {
    fn new() -> Self {
        use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
        use base64::Engine as _;

        let rng = aws_lc_rs::rand::SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let mut der = updawg_crypto::ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(pair.public_key().as_ref());
        Self {
            pair,
            wire: format!(
                "ed25519:{}",
                base64::engine::general_purpose::STANDARD.encode(der)
            ),
        }
    }

    fn offered(
        &self,
        id: &str,
        status: updawg_protocol::SigningKeyStatus,
    ) -> updawg_protocol::OrgSigningKey {
        updawg_protocol::OrgSigningKey {
            key_id: updawg_protocol::SigningKeyId::new(id),
            public_key: self.wire.clone(),
            status,
            endorsement: None,
        }
    }

    fn endorse(
        &self,
        my_id: &str,
        new_id: &str,
        new: &RotationKey,
    ) -> updawg_protocol::Endorsement {
        use base64::Engine as _;
        let statement = updawg_protocol::EndorsementStatement {
            org_id: updawg_protocol::OrgId::new("org_test"),
            issued_at: "2026-09-24T11:00:00Z".parse().unwrap(),
            previous_key: updawg_protocol::EndorsedKey {
                key_id: updawg_protocol::SigningKeyId::new(my_id),
                public_key: self.wire.clone(),
            },
            new_key: updawg_protocol::EndorsedKey {
                key_id: updawg_protocol::SigningKeyId::new(new_id),
                public_key: new.wire.clone(),
            },
        };
        let signature = self.pair.sign(&statement.signing_bytes().unwrap());
        updawg_protocol::Endorsement::new(
            &statement,
            base64::engine::general_purpose::STANDARD.encode(signature.as_ref()),
        )
        .unwrap()
    }
}

fn identity_with(keys: Vec<updawg_protocol::OrgSigningKey>) -> Identity {
    Identity {
        host_id: updawg_protocol::HostId::new("hst_01J9ZC6Q"),
        certificate: String::new(),
        ca_chain: Vec::new(),
        org_signing_keys: keys,
        enrolled_at: "2026-09-01T00:00:00Z".into(),
    }
}

fn renewal_offering(keys: Vec<updawg_protocol::OrgSigningKey>) -> CertRenewResponse {
    CertRenewResponse {
        certificate: String::new(),
        ca_chain: Vec::new(),
        org_signing_keys: keys,
    }
}

fn key_ids(keys: &[updawg_protocol::OrgSigningKey]) -> Vec<&str> {
    keys.iter().map(|k| k.key_id.as_str()).collect()
}

#[test]
fn a_renewal_that_offers_an_endorsed_key_rotates_the_host() {
    use updawg_protocol::SigningKeyStatus;
    let old = RotationKey::new();
    let new = RotationKey::new();

    let mut new_wire = new.offered("sk_new", SigningKeyStatus::Active);
    new_wire.endorsement = Some(old.endorse("sk_old", "sk_new", &new));

    let identity = identity_with(vec![old.offered("sk_old", SigningKeyStatus::Active)]);
    let merged = merge_org_keys(
        &identity,
        &renewal_offering(vec![
            old.offered("sk_old", SigningKeyStatus::Retiring),
            new_wire,
        ]),
    )
    .unwrap();

    assert_eq!(key_ids(&merged), vec!["sk_old", "sk_new"]);
}

/// ⚠️ The renewal path was the widest way to change a fleet's trusted keys
/// without anybody agreeing to it: no operator is present, and until DAWG-99
/// this adopted whatever arrived.
#[test]
fn a_renewal_that_offers_an_unendorsed_key_keeps_the_pinned_set() {
    use updawg_protocol::SigningKeyStatus;
    let old = RotationKey::new();
    let impostor = RotationKey::new();

    let identity = identity_with(vec![old.offered("sk_old", SigningKeyStatus::Active)]);
    let merged = merge_org_keys(
        &identity,
        &renewal_offering(vec![
            old.offered("sk_old", SigningKeyStatus::Retiring),
            impostor.offered("sk_impostor", SigningKeyStatus::Active),
        ]),
    )
    .unwrap();

    assert_eq!(
        key_ids(&merged),
        vec!["sk_old"],
        "an unendorsed key must not be pinned by a renewal"
    );
}

/// The renewal itself still succeeds. A certificate that cannot be renewed
/// takes the host off the air; a key set that was not adopted costs nothing
/// until somebody rotates for real.
#[test]
fn a_refused_key_set_does_not_fail_the_renewal() {
    use updawg_protocol::SigningKeyStatus;
    let old = RotationKey::new();
    let impostor = RotationKey::new();
    let identity = identity_with(vec![old.offered("sk_old", SigningKeyStatus::Active)]);

    assert!(
        merge_org_keys(
            &identity,
            &renewal_offering(vec![
                old.offered("sk_old", SigningKeyStatus::Active),
                impostor.offered("sk_impostor", SigningKeyStatus::Active),
            ]),
        )
        .is_ok()
    );
}

/// The other half, unchanged by DAWG-99 and worth keeping asserted beside it:
/// a renewal that drops a key this host relies on is refused too.
#[test]
fn a_renewal_that_drops_a_relied_on_key_keeps_the_pinned_set() {
    use updawg_protocol::SigningKeyStatus;
    let old = RotationKey::new();
    let replacement = RotationKey::new();
    let identity = identity_with(vec![old.offered("sk_old", SigningKeyStatus::Active)]);

    let merged = merge_org_keys(
        &identity,
        &renewal_offering(vec![
            replacement.offered("sk_replacement", SigningKeyStatus::Active),
        ]),
    )
    .unwrap();

    assert_eq!(key_ids(&merged), vec!["sk_old"]);
}
