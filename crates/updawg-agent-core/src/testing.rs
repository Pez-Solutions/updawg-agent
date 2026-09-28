//! Shared test scaffolding: a real CA, a real enrolled host, and a real TLS
//! gateway that demands a client certificate.
//!
//! This lives outside the test modules that use it because both the transport
//! and the check-in loop need the same thing, and the point of it is that
//! nothing is mocked: an agent that connects fine and quietly presents no
//! certificate would pass any test that stopped at the HTTP layer.
//!
//! The gateway speaks just enough HTTP/1.1 to satisfy `reqwest`. Bringing in a
//! real HTTP server crate would add a dependency to prove something this proves
//! directly — and, more to the point, would not let a test hang up mid-response
//! the way a corporate proxy does.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::{
    enroll::KEY_FILE,
    state::{Identity, LocalState},
    transport::MtlsTransport,
};
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
    time::{Duration, SystemTime},
};
use tokio::io::AsyncWriteExt;
use updawg_protocol::{CheckinRequest, HostId, HostMetrics, HostStateReport};

pub(crate) static NEXT: AtomicU64 = AtomicU64::new(0);

/// A throwaway certificate authority, so the tests exercise a real chain.
pub(crate) struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    pub(crate) pem: String,
}

impl TestCa {
    pub(crate) fn new() -> Self {
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
    pub(crate) fn issue(&self, common_name: &str, valid_for: Duration) -> (String, KeyPair) {
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
    pub(crate) fn issue_server(&self) -> (String, KeyPair) {
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
    pub(crate) fn issue_for(
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

    pub(crate) fn issue_for_eku(
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
pub(crate) struct EnrolledHost {
    dir: PathBuf,
    pub(crate) state: LocalState,
}

impl EnrolledHost {
    pub(crate) fn new(ca: &TestCa, valid_for: Duration) -> Self {
        Self::aged(ca, Duration::ZERO, valid_for)
    }

    /// An enrolled host whose certificate was issued `aged` ago.
    pub(crate) fn aged(ca: &TestCa, aged: Duration, valid_for: Duration) -> Self {
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

    pub(crate) fn key(&self) -> KeyPair {
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
pub(crate) struct Seen {
    pub(crate) path: String,
    pub(crate) method: String,
    pub(crate) body: String,
    /// The body before any lossy conversion.
    ///
    /// An inventory upload is zstd, so `body` is meaningless for it — a lossy
    /// UTF-8 conversion of compressed bytes is not the bytes.
    pub(crate) body_bytes: Vec<u8>,
    /// Lowercased header names to values, for the handful a test cares about.
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) client_subject: Option<String>,
}

impl Seen {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A TLS server that demands a client certificate and answers canned JSON.
///
/// Speaks just enough HTTP/1.1 to satisfy `reqwest`. Using a real HTTP server
/// crate would add a dependency to prove something this proves directly.
pub(crate) struct TestGateway {
    addr: std::net::SocketAddr,
    pub(crate) seen: Arc<std::sync::Mutex<Vec<Seen>>>,
}

/// What the gateway does with one request.
#[derive(Debug, Clone)]
pub(crate) enum Reply {
    /// Answer immediately.
    Now(u16, String),
    /// Hold the request open, then answer — a long poll with a job waiting at
    /// the end of it.
    After(Duration, u16, String),
    /// Hold the request open and then hang up without answering. This is what
    /// a proxy trimming an idle connection looks like from the agent's side,
    /// and it is indistinguishable from an outage unless you look at how long
    /// it took.
    HangUpAfter(Duration),
}

impl TestGateway {
    /// `replies` is consumed one entry per request: (status, json body).
    pub(crate) async fn start(ca: &TestCa, replies: Vec<(u16, String)>) -> Self {
        Self::scripted(
            ca,
            replies.into_iter().map(|(s, b)| Reply::Now(s, b)).collect(),
        )
        .await
    }

    /// As [`Self::start`], but each request gets a [`Reply`].
    pub(crate) async fn scripted(ca: &TestCa, replies: Vec<Reply>) -> Self {
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
                let reply = replies.next().unwrap_or(Reply::Now(200, "{}".into()));
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

                    let (method, path, headers, body_bytes) = read_request(&mut tls).await;

                    recorded.lock().unwrap().push(Seen {
                        path,
                        method,
                        body: String::from_utf8_lossy(&body_bytes).to_string(),
                        body_bytes,
                        headers,
                        client_subject,
                    });

                    let (status, json) = match reply {
                        Reply::Now(s, j) => (s, j),
                        Reply::After(delay, s, j) => {
                            tokio::time::sleep(delay).await;
                            (s, j)
                        }
                        // Drop the connection without writing anything. The
                        // agent sees a transport error, exactly as it would
                        // behind a proxy with an idle timeout.
                        Reply::HangUpAfter(delay) => {
                            tokio::time::sleep(delay).await;
                            drop(tls);
                            return;
                        }
                    };
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

    pub(crate) fn url(&self) -> String {
        format!("https://localhost:{}", self.addr.port())
    }

    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

pub(crate) fn transport(host: &EnrolledHost, gateway: &TestGateway, ca: &TestCa) -> MtlsTransport {
    MtlsTransport::with_extra_root(
        &gateway.url(),
        host.state.clone(),
        Some(ca.pem.clone().into_bytes()),
    )
    .unwrap()
}

pub(crate) fn checkin_request() -> CheckinRequest {
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
        max_hold_s: None,
        local_policy: None,
        snapshots: None,
    }
}

/// Read one HTTP/1.1 request: method, path, headers, body.
///
/// Reads until the headers are complete, then until `Content-Length` is
/// satisfied. A single `read` was enough while every body was small JSON; a
/// compressed inventory arrives in more than one TCP segment, and a harness that
/// read once would fail or pass depending on how the kernel happened to split it
/// — which is the kind of test failure nobody can reproduce.
async fn read_request<S>(tls: &mut S) -> (String, String, Vec<(String, String)>, Vec<u8>)
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;

    let mut raw: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    let head_end = loop {
        let n = tls.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break raw.windows(4).position(|w| w == b"\r\n\r\n");
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break Some(i);
        }
    };
    let head_end = head_end.map_or(raw.len(), |i| i + 4);
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let content_length: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);

    while raw.len() - head_end < content_length {
        let n = tls.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
    }

    let mut words = head.split_whitespace();
    let method = words.next().unwrap_or_default().to_string();
    let path = words.next().unwrap_or_default().to_string();
    (method, path, headers, raw[head_end..].to_vec())
}
