//! A stand-in for the Updawg gateway, for the distro matrix (DAWG-40):
//! enough of it that a real `updawgctl` enrolls against it and a real
//! `updawgd` checks in and uploads an inventory, and a record of what each
//! host did.
//!
//! ```text
//! cargo run -p updawg-agent-core --example fake_gateway -- <dir>
//! ```
//!
//! Writes `<dir>/ca.pem` at start — what the agent is given with
//! `--insecure-extra-root`, so it is only ever used with a build that has the
//! flag — and rewrites `<dir>/results.json` after every request: one entry
//! per host, keyed by the enrollment token it used, saying what it enrolled
//! as, how many times it checked in with its certificate, and what its first
//! inventory held.
//!
//! Listens on `0.0.0.0:8443` as `gateway.test`. A container reaches it with
//! `--add-host gateway.test:host-gateway`.
//!
//! Real TLS, and the real rules where they matter: enrollment needs no
//! client certificate, everything after it does, and must present the one
//! issued to that host. What it does not do is anything the server decides —
//! it accepts any token, stores nothing, and sends no jobs — because what is
//! under test is the agent on each distribution, not the server.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::{
    RootCertStore, ServerConfig as TlsConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use updawg_protocol::{
    CheckinResponse, EnrollRequest, EnrollResponse, HostId, OrgSigningKey, ServerConfig,
    SigningKeyId, SigningKeyStatus,
};

const NAME: &str = "gateway.test";
const LISTEN: &str = "0.0.0.0:8443";

/// What one host did, keyed by its token.
type Results = Arc<Mutex<BTreeMap<String, serde_json::Value>>>;

#[tokio::main]
async fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).expect("usage: fake_gateway <dir>"));
    std::fs::create_dir_all(&dir).unwrap();

    let (issuer, ca_pem) = ca();
    std::fs::write(dir.join("ca.pem"), &ca_pem).unwrap();
    let issuer = Arc::new(issuer);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls(&issuer, &ca_pem)));
    let org_key = org_signing_key();

    let results: Results = Arc::default();
    let listener = tokio::net::TcpListener::bind(LISTEN).await.unwrap();
    eprintln!(
        "fake gateway on {LISTEN} as {NAME}; CA in {}",
        dir.display()
    );
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let (acceptor, issuer, ca_pem, org_key, results, dir) = (
            acceptor.clone(),
            Arc::clone(&issuer),
            ca_pem.clone(),
            org_key.clone(),
            Arc::clone(&results),
            dir.clone(),
        );
        tokio::spawn(async move {
            let Ok(mut stream) = acceptor.accept(stream).await else {
                return;
            };
            let client_cn = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first().cloned())
                .and_then(|der| {
                    use x509_parser::prelude::{FromDer, X509Certificate};
                    let (_, cert) = X509Certificate::from_der(der.as_ref()).ok()?;
                    let cn = cert.subject().iter_common_name().next()?;
                    cn.as_str().ok().map(str::to_owned)
                });
            let Some((method, path, body)) = read_request(&mut stream).await else {
                return;
            };
            let (status, reply) = answer(
                &method,
                &path,
                &body,
                client_cn.as_deref(),
                &issuer,
                &ca_pem,
                &org_key,
                &results,
            );
            let reply = reply.to_string();
            let _ = stream
                .write_all(
                    format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                        reply.len()
                    )
                    .as_bytes(),
                )
                .await;
            let _ = stream.shutdown().await;
            let snapshot = serde_json::to_vec_pretty(&*results.lock().unwrap()).unwrap();
            let tmp = dir.join("results.json.tmp");
            std::fs::write(&tmp, snapshot).unwrap();
            std::fs::rename(tmp, dir.join("results.json")).unwrap();
        });
    }
}

/// The CA: signs the gateway's certificate and every host's.
fn ca() -> (Issuer<'static, KeyPair>, String) {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Updawg distro matrix CA");
    ca_params.distinguished_name = dn;
    let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
    (Issuer::new(ca_params, ca_key), ca_pem)
}

/// The listener's TLS: the gateway's own certificate, and client
/// certificates from the CA — optional at the handshake, because enrollment
/// has none yet; required per request in [`answer`] for everything else.
fn tls(issuer: &Issuer<'static, KeyPair>, ca_pem: &str) -> TlsConfig {
    // An end entity, never the CA itself: rustls refuses a CA certificate
    // presented as a server's.
    let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut server_params = CertificateParams::new(vec![NAME.to_owned()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, NAME);
    server_params.distinguished_name = dn;
    let server_pem = server_params.signed_by(&server_key, issuer).unwrap().pem();

    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
        .unwrap();
    let mut tls = TlsConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            CertificateDer::pem_slice_iter(server_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            PrivateKeyDer::from_pem_slice(server_key.serialize_pem().as_bytes()).unwrap(),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    tls
}

/// The organization's signing key the hosts pin. Nothing is ever signed with
/// it: no jobs are sent.
fn org_signing_key() -> OrgSigningKey {
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let mut spki = updawg_crypto::ED25519_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(key.public_key().as_ref());
    OrgSigningKey {
        key_id: SigningKeyId::new("sk_distromatrix"),
        public_key: format!("ed25519:{}", base64_encode(&spki)),
        status: SigningKeyStatus::Active,
        endorsement: None,
    }
}

/// One request's answer, and what it adds to the record.
#[allow(clippy::too_many_arguments)]
fn answer(
    method: &str,
    path: &str,
    body: &[u8],
    client_cn: Option<&str>,
    issuer: &Issuer<'static, KeyPair>,
    ca_pem: &str,
    org_key: &OrgSigningKey,
    results: &Results,
) -> (u16, serde_json::Value) {
    let refuse = |status: u16, why: &str| (status, serde_json::json!({ "detail": why }));
    if (method, path) == ("POST", "/agent/v1/enroll") {
        let Ok(request) = serde_json::from_slice::<EnrollRequest>(body) else {
            return refuse(400, "not an enrollment request");
        };
        let host_id = format!("hst_{}", sanitize(&request.token));
        let Ok(mut csr) = CertificateSigningRequestParams::from_pem(&request.csr) else {
            return refuse(400, "the CSR does not parse");
        };
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host_id.as_str());
        csr.params.distinguished_name = dn;
        csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        csr.params.not_before = SystemTime::now().into();
        csr.params.not_after = (SystemTime::now() + Duration::from_secs(30 * 86_400)).into();
        let Ok(cert) = csr.signed_by(issuer) else {
            return refuse(400, "the CSR could not be signed");
        };
        results.lock().unwrap().insert(
            request.token.clone(),
            serde_json::json!({
                "host_id": host_id,
                "hostname": request.hostname,
                "machine_id": request.machine_id,
                "facts": request.facts,
                "agent_version": request.agent_version,
                "checkins": 0,
            }),
        );
        let response = EnrollResponse {
            host_id: HostId::new(host_id),
            certificate: cert.pem(),
            ca_chain: vec![ca_pem.to_owned()],
            org_signing_keys: vec![org_key.clone()],
            config: ServerConfig {
                checkin_timeout_s: 5,
                inventory_interval_s: 21_600,
                refresh_metadata_interval_s: 21_600,
                config_version: 1,
                enabled_job_kinds: vec![],
            },
        };
        return (200, serde_json::to_value(response).unwrap());
    }

    // Everything else: only with the certificate issued at enrollment.
    let Some(cn) = client_cn else {
        return refuse(401, "no client certificate");
    };
    let mut results = results.lock().unwrap();
    let Some(host) = results
        .values_mut()
        .find(|h| h["host_id"].as_str() == Some(cn))
    else {
        return refuse(403, "a certificate for no host enrolled here");
    };
    match (method, path) {
        ("POST", "/agent/v1/checkin") => {
            host["checkins"] = (host["checkins"].as_u64().unwrap_or(0) + 1).into();
            let response = CheckinResponse {
                next_checkin_s: 2,
                inventory_requested: host.get("inventory").is_none(),
                config_version: 1,
                jobs: vec![],
                config: None,
            };
            (200, serde_json::to_value(response).unwrap())
        }
        ("PUT", "/agent/v1/inventory") => {
            let Ok(json) = zstd::decode_all(body) else {
                return refuse(400, "not zstd");
            };
            let Ok(upload) = serde_json::from_slice::<serde_json::Value>(&json) else {
                return refuse(400, "not JSON");
            };
            if host.get("inventory").is_none() {
                let count = |key: &str| upload[key].as_array().map_or(0, Vec::len);
                host["inventory"] = serde_json::json!({
                    "kind": upload["type"],
                    "packages": upload["packages"]["added"].as_array().map_or(0, Vec::len),
                    "updates": count("updates"),
                    "repositories": count("repositories"),
                    "facts": upload["facts"],
                    "sample": upload["packages"]["added"].get(0),
                });
            }
            (200, serde_json::json!({}))
        }
        ("GET", "/agent/v1/config") => (
            200,
            serde_json::json!({
                "checkin_timeout_s": 5,
                "inventory_interval_s": 21_600,
                "config_version": 1
            }),
        ),
        _ => (200, serde_json::json!({})),
    }
}

/// A token as the tail of a host id: letters and digits only.
fn sanitize(token: &str) -> String {
    token
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase()
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Method, path and body of one HTTP/1.1 request.
async fn read_request<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Option<(String, String, Vec<u8>)> {
    let mut raw = Vec::new();
    let mut buf = vec![0_u8; 16 * 1024];
    let head_end = loop {
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&buf[..n]);
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let mut lines = head.lines();
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_owned();
    let path = first.next()?.to_owned();
    let length: usize = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    while raw.len() < head_end + length {
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
    }
    Some((method, path, raw[head_end..].to_vec()))
}
