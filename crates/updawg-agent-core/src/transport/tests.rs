//! Tests for the authenticated transport.
//!
//! These run a real TLS server in-process, with a real CA, and require a client
//! certificate. Nothing here mocks the handshake, because the handshake is the
//! part that is easy to get subtly wrong: a client that builds fine, connects
//! fine, and quietly presents no certificate at all would pass any test that
//! stopped at the HTTP layer.

use super::*;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_ED25519,
};
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use updawg_protocol::{HostId, HostMetrics, HostStateReport};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A throwaway certificate authority, so the tests exercise a real chain.
struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    pem: String,
}

impl TestCa {
    fn new() -> Self {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Updawg Test CA");
        params.distinguished_name = dn;

        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem();
        Self {
            issuer: Issuer::new(params, key),
            pem,
        }
    }

    /// Issue an end-entity certificate for a fresh Ed25519 key, as the gateway
    /// would for an agent.
    fn issue(&self, common_name: &str, valid_for: Duration) -> (String, KeyPair) {
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let pem = self.issue_for_eku(
            common_name,
            vec![],
            Duration::ZERO,
            valid_for,
            &key,
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        (pem, key)
    }

    /// The server's own certificate. ECDSA, because the platform verifier
    /// applies the operating system's algorithm policy to extra roots as well
    /// as built-in ones, and macOS will not accept Ed25519 for server
    /// authentication. A real gateway's certificate is ECDSA or RSA too.
    fn issue_server(&self) -> (String, KeyPair) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let pem = self.issue_for_eku(
            "localhost",
            vec!["localhost".into(), "127.0.0.1".into()],
            Duration::ZERO,
            Duration::from_secs(3600),
            &key,
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        (pem, key)
    }

    /// `aged` backdates `not_before`, so a certificate can start life already
    /// inside its renewal window.
    fn issue_for(
        &self,
        common_name: &str,
        sans: Vec<String>,
        aged: Duration,
        valid_for: Duration,
        key: &KeyPair,
    ) -> String {
        self.issue_for_eku(
            common_name,
            sans,
            aged,
            valid_for,
            key,
            ExtendedKeyUsagePurpose::ClientAuth,
        )
    }

    fn issue_for_eku(
        &self,
        common_name: &str,
        sans: Vec<String>,
        aged: Duration,
        valid_for: Duration,
        key: &KeyPair,
        eku: ExtendedKeyUsagePurpose,
    ) -> String {
        let mut params = CertificateParams::new(sans).unwrap();
        // Without an extended key usage the verifier refuses the chain, which
        // is the same rule a real gateway's certificate has to satisfy.
        params.extended_key_usages = vec![eku];
        // rcgen derives a default serial from the key, so a renewal for the
        // same key would otherwise be indistinguishable from the original.
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        params.serial_number = Some(rcgen::SerialNumber::from_slice(&n.to_be_bytes()));
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        let issued = SystemTime::now() - aged;
        params.not_before = issued.into();
        params.not_after = (issued + valid_for).into();

        params.signed_by(key, &self.issuer).unwrap().pem()
    }
}

/// An enrolled host on disk: state directory, key file, identity file.
struct EnrolledHost {
    dir: PathBuf,
    state: LocalState,
}

impl EnrolledHost {
    fn new(ca: &TestCa, valid_for: Duration) -> Self {
        Self::aged(ca, Duration::ZERO, valid_for)
    }

    /// An enrolled host whose certificate was issued `aged` ago.
    fn aged(ca: &TestCa, aged: Duration, valid_for: Duration) -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("updawg-tp-{}-{n}", std::process::id()));
        let state = LocalState::new(dir.join("state"));
        state.ensure().unwrap();

        // The host's own key, then a certificate issued for exactly that key —
        // the same relationship a real enrollment produces.
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        fs::write(state.root().join(KEY_FILE), key.serialize_pem()).unwrap();
        let cert = ca.issue_for("hst_01J9ZC6Q", vec![], aged, valid_for, &key);

        state
            .save_identity(&Identity {
                host_id: HostId::new("hst_01J9ZC6Q"),
                certificate: cert,
                ca_chain: vec![ca.pem.clone()],
                org_signing_keys: vec![],
                enrolled_at: "2026-09-19T00:00:00Z".into(),
            })
            .unwrap();

        Self { dir, state }
    }

    fn key(&self) -> KeyPair {
        KeyPair::from_pem(&fs::read_to_string(self.state.root().join(KEY_FILE)).unwrap()).unwrap()
    }
}

impl Drop for EnrolledHost {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.dir).ok();
    }
}

/// What one request looked like from the server's side.
#[derive(Debug, Clone)]
struct Seen {
    path: String,
    body: String,
    client_subject: Option<String>,
}

/// A TLS server that demands a client certificate and answers canned JSON.
///
/// Speaks just enough HTTP/1.1 to satisfy `reqwest`. Using a real HTTP server
/// crate would add a dependency to prove something this proves directly.
struct TestGateway {
    addr: std::net::SocketAddr,
    seen: Arc<std::sync::Mutex<Vec<Seen>>>,
}

impl TestGateway {
    /// `replies` is consumed one entry per request: (status, json body).
    async fn start(ca: &TestCa, replies: Vec<(u16, String)>) -> Self {
        use tokio_rustls::rustls::{
            RootCertStore, ServerConfig,
            pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
            server::WebPkiClientVerifier,
        };

        let (server_pem, server_key) = ca.issue_server();

        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(server_pem.as_bytes())
                .collect::<std::result::Result<_, _>>()
                .unwrap();
        let key = PrivateKeyDer::from_pem_slice(server_key.serialize_pem().as_bytes()).unwrap();

        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(ca.pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        // Client authentication is mandatory. That is the whole point: a client
        // presenting nothing gets refused at the handshake.
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();

        let mut config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));

        let recorded = Arc::clone(&seen);
        tokio::spawn(async move {
            let mut replies = replies.into_iter();
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let recorded = Arc::clone(&recorded);
                let reply = replies.next().unwrap_or((200, "{}".into()));
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };

                    let client_subject = tls
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|c| c.first().cloned())
                        .and_then(|der| {
                            use x509_parser::prelude::{FromDer, X509Certificate};
                            X509Certificate::from_der(der.as_ref())
                                .ok()
                                .map(|(_, c)| c.subject().to_string())
                        });

                    let mut buf = vec![0u8; 16 * 1024];
                    let n = tls.read(&mut buf).await.unwrap_or(0);
                    let raw = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = raw
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();
                    let body = raw.split("\r\n\r\n").nth(1).unwrap_or_default().to_string();

                    recorded.lock().unwrap().push(Seen {
                        path,
                        body,
                        client_subject,
                    });

                    let (status, json) = reply;
                    let response = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{json}",
                        json.len()
                    );
                    tls.write_all(response.as_bytes()).await.ok();
                    tls.shutdown().await.ok();
                });
            }
        });

        Self { addr, seen }
    }

    fn url(&self) -> String {
        format!("https://localhost:{}", self.addr.port())
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn transport(host: &EnrolledHost, gateway: &TestGateway, ca: &TestCa) -> MtlsTransport {
    MtlsTransport::with_extra_root(
        &gateway.url(),
        host.state.clone(),
        Some(ca.pem.clone().into_bytes()),
    )
    .unwrap()
}

fn checkin_request() -> CheckinRequest {
    CheckinRequest {
        boot_id: "b81e".into(),
        uptime_s: 864_000,
        inventory_hash: "sha256:9f86d0".into(),
        state: HostStateReport::default(),
        metrics: HostMetrics {
            load1: 0.1,
            mem_used_pct: 20.0,
            root_free_bytes: 1_000_000,
        },
        running_job_ids: vec![],
    }
}

const THIRTY_DAYS: Duration = Duration::from_secs(30 * 86_400);

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
    let response = transport.check_in(&checkin_request()).await.unwrap();

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

    transport.check_in(&checkin_request()).await.unwrap();
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

    let err = transport.check_in(&checkin_request()).await.unwrap_err();
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

    let err = transport.check_in(&checkin_request()).await.unwrap_err();

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
        .check_in(&checkin_request())
        .await
        .unwrap_err();
    assert!(
        matches!(err, TransportError::Server { status: 503, .. }),
        "got {err:?}"
    );
    assert!(err.to_string().contains("The gateway is draining."));
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
