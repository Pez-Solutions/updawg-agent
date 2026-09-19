//! Enrollment: the moment this host decides what it will trust.
//!
//! The sequence is short and the order matters:
//!
//! 1. Generate a key pair. The private half is written to disk and never sent.
//! 2. Build a CSR naming the machine id, so the server can recognise a host it
//!    has seen before.
//! 3. `POST /agent/v1/enroll` with the enrollment token and the CSR.
//! 4. **Validate the response before believing any of it**, then write the key
//!    and the identity.
//!
//! Step 4 is the whole point of this module. The organization signing keys that
//! arrive in that response decide which jobs this host will execute for the
//! rest of its life, and a host that pins a malformed or unusable key discovers
//! the problem at the worst possible moment — when a job it cannot verify
//! arrives. So the response is parsed, checked and rejected here, before
//! anything is written.
//!
//! Two properties that fall out of writing nothing until the end:
//!
//! - **A failed enrollment leaves an existing identity intact.** An agent that
//!   is working keeps working, whatever the server said.
//! - **Re-enrolling is not automatic.** An already-enrolled host refuses a
//!   second enrollment unless told to replace itself, and refuses again if the
//!   organization key it would pin is not the one it pinned before. Silently
//!   following a key change is exactly the attack pinning exists to stop.

use crate::state::{Identity, LocalState};
use async_trait::async_trait;
use std::{
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};
use updawg_collectors::enrollment::{EnrollmentCollector, EnrollmentFacts};
use updawg_crypto::{AgentKey, PinnedKeys};
use updawg_protocol::{
    API_PATH, EnrollRequest, EnrollResponse, HostId, PROTOCOL_HEADER, PROTOCOL_VERSION,
};

/// Filename of the host's private key inside the state directory.
pub const KEY_FILE: &str = "agent.key";

/// How long to wait for the enrollment exchange.
///
/// Generous, because this happens once and often over a link that is being
/// configured at the same time. The check-in loop's timeouts are the ones that
/// need to be tight.
const ENROLL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EnrollError {
    #[error(
        "this host is already enrolled as {host_id}; pass --force to replace its identity, \
         which invalidates the current certificate"
    )]
    AlreadyEnrolled { host_id: HostId },

    #[error(
        "the organization signing key has changed since this host enrolled.\n  \
         pinned:  {pinned}\n  offered: {offered}\n\
         This is what key pinning exists to catch. If the organization really did rotate its \
         key, re-enroll with --accept-new-org-key; otherwise stop and find out why the server \
         is offering a different key."
    )]
    OrgKeyChanged { pinned: String, offered: String },

    #[error(
        "the enrollment token was rejected. Tokens expire, have a limited number of uses, and \
         are shown only once — generate a fresh one in the portal."
    )]
    TokenRejected,

    #[error("the server refused the enrollment ({status}): {detail}")]
    ServerRefused { status: u16, detail: String },

    #[error("could not reach {url}: {detail}")]
    Unreachable { url: String, detail: String },

    #[error(
        "the agent server address must be https; `{url}` is not. Enrollment carries a token and \
         a CSR, and the only endpoint without a client certificate is this one."
    )]
    NotHttps { url: String },

    #[error("the server's enrollment response is not usable: {0}")]
    BadResponse(String),

    #[error(transparent)]
    Crypto(#[from] updawg_crypto::CryptoError),
    #[error(transparent)]
    Facts(#[from] updawg_collectors::CollectorError),
    #[error(transparent)]
    State(#[from] crate::state::StateError),
}

pub type Result<T> = std::result::Result<T, EnrollError>;

/// The exchange with the gateway, behind a trait.
///
/// Enrollment is the one request that carries a secret and establishes trust,
/// so the logic around it is worth testing without a network. The HTTPS
/// implementation is below; the tests drive the same flow through a fake.
#[async_trait]
pub trait EnrollExchange: Send + Sync + fmt::Debug {
    async fn post_enroll(&self, request: &EnrollRequest) -> Result<EnrollResponse>;
}

/// What an enrollment attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enrolled {
    /// Nothing to do: this host already has an identity.
    Already { host_id: HostId },
    /// A new identity was established.
    New {
        host_id: HostId,
        org_keys: Vec<String>,
    },
    /// An existing identity was replaced.
    Replaced {
        previous: HostId,
        host_id: HostId,
        org_keys: Vec<String>,
    },
}

impl Enrolled {
    #[must_use]
    pub fn host_id(&self) -> &HostId {
        match self {
            Self::Already { host_id }
            | Self::New { host_id, .. }
            | Self::Replaced { host_id, .. } => host_id,
        }
    }
}

/// Caller's intent, kept explicit so neither choice can be made by accident.
#[derive(Debug, Clone, Copy, Default)]
pub struct EnrollOptions {
    /// Replace an existing identity rather than refusing.
    pub force: bool,
    /// Accept an organization signing key that differs from the pinned one.
    pub accept_new_org_key: bool,
}

/// Runs the enrollment sequence.
#[derive(Debug)]
pub struct Enroller<'a> {
    state: &'a LocalState,
    exchange: &'a dyn EnrollExchange,
    facts: EnrollmentCollector,
    agent_version: String,
}

impl<'a> Enroller<'a> {
    #[must_use]
    pub fn new(state: &'a LocalState, exchange: &'a dyn EnrollExchange) -> Self {
        Self {
            state,
            exchange,
            facts: EnrollmentCollector::default(),
            agent_version: crate::VERSION.to_string(),
        }
    }

    /// Point fact collection at a different filesystem root. For tests.
    #[must_use]
    pub fn with_fact_root(mut self, root: impl AsRef<Path>) -> Self {
        self.facts = EnrollmentCollector::new(root);
        self
    }

    #[must_use]
    pub fn key_path(&self) -> PathBuf {
        self.state.root().join(KEY_FILE)
    }

    /// Exchange a token for an identity.
    ///
    /// # Errors
    /// See [`EnrollError`]. Every failure leaves whatever identity the host
    /// already had untouched.
    pub async fn enroll(&self, token: &str, options: EnrollOptions) -> Result<Enrolled> {
        let existing = self.state.identity()?;
        if let Some(current) = &existing
            && !options.force
        {
            return Ok(Enrolled::Already {
                host_id: current.host_id.clone(),
            });
        }

        let facts = self.facts.gather()?;

        // A fresh key every time, including on re-enrollment: the old
        // certificate is being abandoned, and reusing the key it was issued for
        // means one compromise covers both identities. The key is held in
        // memory until the server has answered, so a failed enrollment does not
        // overwrite a working one.
        let key = AgentKey::generate()?;
        let csr = key.certificate_request(&facts.machine_id)?;

        let request = build_request(token, csr, &facts, &self.agent_version);
        let response = self.exchange.post_enroll(&request).await?;

        let pinned = validate(&response)?;

        if let Some(current) = &existing {
            check_key_continuity(current, &pinned, options)?;
        }

        // Written in this order on purpose: without the key the identity is
        // useless, and an identity file is what `is_enrolled` looks at. Key
        // first means there is no moment where the host looks enrolled but
        // cannot authenticate.
        key.save(self.key_path())?;
        self.state.save_identity(&Identity {
            host_id: response.host_id.clone(),
            certificate: response.certificate.clone(),
            ca_chain: response.ca_chain.clone(),
            org_signing_keys: response.org_signing_keys.clone(),
            enrolled_at: chrono::Utc::now().to_rfc3339(),
        })?;

        let org_keys = pinned.describe();
        Ok(match existing {
            None => Enrolled::New {
                host_id: response.host_id,
                org_keys,
            },
            Some(previous) => Enrolled::Replaced {
                previous: previous.host_id,
                host_id: response.host_id,
                org_keys,
            },
        })
    }
}

/// Refuse a re-enrollment that would quietly change what this host trusts.
///
/// The check is deliberately one-directional: the offered set must still
/// contain every key this host has pinned and not retired. Gaining a key is a
/// rotation, which is normal. *Losing* the key that has been signing this
/// host's jobs is either a revocation the operator should know about or a
/// server that is not the one we enrolled with.
fn check_key_continuity(
    current: &Identity,
    offered: &PinnedKeys,
    options: EnrollOptions,
) -> Result<()> {
    let previously = PinnedKeys::from_wire(&current.org_signing_keys)?;
    let mut missing = Vec::new();
    for (key_id, key) in previously.usable() {
        if !offered.contains(key_id, key) {
            missing.push(format!("{key_id} {}", key.fingerprint()));
        }
    }

    if missing.is_empty() || options.accept_new_org_key {
        if !missing.is_empty() {
            tracing::warn!(
                dropped = ?missing,
                "re-enrolling onto a different organization signing key at the operator's \
                 explicit instruction"
            );
        }
        return Ok(());
    }

    Err(EnrollError::OrgKeyChanged {
        pinned: missing.join(", "),
        offered: offered.describe().join(", "),
    })
}

fn build_request(
    token: &str,
    csr: String,
    facts: &EnrollmentFacts,
    agent_version: &str,
) -> EnrollRequest {
    EnrollRequest {
        token: token.to_string(),
        csr,
        machine_id: facts.machine_id.clone(),
        hostname: facts.hostname.clone(),
        facts: facts.facts.clone(),
        agent_version: agent_version.to_string(),
    }
}

/// Everything that has to be true before any of this is written down.
fn validate(response: &EnrollResponse) -> Result<PinnedKeys> {
    if !response.host_id.is_well_formed() {
        return Err(EnrollError::BadResponse(format!(
            "host id `{}` does not look like one ({}…)",
            response.host_id,
            HostId::PREFIX
        )));
    }
    if !response.certificate.contains("BEGIN CERTIFICATE") {
        return Err(EnrollError::BadResponse(
            "the certificate is not PEM".into(),
        ));
    }
    // An empty chain would mean trusting whatever the gateway presents later,
    // which is the opposite of what mTLS is for.
    if response.ca_chain.is_empty() {
        return Err(EnrollError::BadResponse(
            "no CA chain was returned; there would be nothing to verify the gateway against".into(),
        ));
    }
    if response.org_signing_keys.is_empty() {
        return Err(EnrollError::BadResponse(
            "no organization signing keys were returned; this host could never verify a job".into(),
        ));
    }
    Ok(PinnedKeys::from_wire(&response.org_signing_keys)?)
}

/* ------------------------------------------------------------------ HTTPS */

/// The real exchange: one `POST` to `{server}/agent/v1/enroll`.
///
/// This is the only agent request that does not present a client certificate —
/// there isn't one yet. It is also the only one that carries a bearer secret,
/// which is why the scheme is checked rather than assumed.
#[derive(Debug)]
pub struct HttpsEnrollExchange {
    url: String,
    client: reqwest::Client,
}

impl HttpsEnrollExchange {
    /// # Errors
    /// [`EnrollError::NotHttps`] if the configured server is not an https URL,
    /// and [`EnrollError::Unreachable`] if the HTTP client cannot be built.
    pub fn new(server: &str) -> Result<Self> {
        let server = server.trim_end_matches('/');
        if !server.starts_with("https://") {
            return Err(EnrollError::NotHttps {
                url: server.to_string(),
            });
        }

        let client = reqwest::Client::builder()
            .timeout(ENROLL_TIMEOUT)
            .user_agent(format!("updawg-agent/{}", crate::VERSION))
            .build()
            .map_err(|e| EnrollError::Unreachable {
                url: server.to_string(),
                detail: e.to_string(),
            })?;

        Ok(Self {
            url: format!("{server}{API_PATH}/enroll"),
            client,
        })
    }
}

#[async_trait]
impl EnrollExchange for HttpsEnrollExchange {
    async fn post_enroll(&self, request: &EnrollRequest) -> Result<EnrollResponse> {
        let response = self
            .client
            .post(&self.url)
            .header(PROTOCOL_HEADER, PROTOCOL_VERSION.to_string())
            .json(request)
            .send()
            .await
            .map_err(|e| EnrollError::Unreachable {
                url: self.url.clone(),
                detail: causes(&e),
            })?;

        let status = response.status();
        if !status.is_success() {
            // 401 and 403 both mean the token did not work. Saying so beats
            // making an operator read an RFC 9457 body to learn it.
            if status.as_u16() == 401 || status.as_u16() == 403 {
                return Err(EnrollError::TokenRejected);
            }
            let detail = response
                .text()
                .await
                .unwrap_or_else(|_| "no response body".into());
            return Err(EnrollError::ServerRefused {
                status: status.as_u16(),
                detail: problem_detail(&detail),
            });
        }

        response
            .json::<EnrollResponse>()
            .await
            .map_err(|e| EnrollError::BadResponse(e.to_string()))
    }
}

/// Flatten an error and everything under it into one line.
///
/// reqwest's own `Display` is "error sending request for url (…)" and nothing
/// else — the reason, a failed TLS handshake or a refused connection, is two or
/// three levels down the source chain. An operator reading a failed enrollment
/// needs the reason, not the URL they already typed.
fn causes(error: &dyn std::error::Error) -> String {
    let mut parts = vec![error.to_string()];
    let mut source = error.source();
    while let Some(e) = source {
        let text = e.to_string();
        // Each layer tends to quote the one below it; only add what is new.
        if !parts.iter().any(|p| p.contains(&text)) {
            parts.push(text);
        }
        source = e.source();
    }
    parts.join(": ")
}

/// Pull the human-readable part out of an RFC 9457 problem document.
fn problem_detail(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("detail")
                .or_else(|| v.get("title"))
                .and_then(|d| d.as_str().map(ToString::to_string))
        })
        .unwrap_or_else(|| body.chars().take(200).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::{Arc, Mutex},
    };
    use updawg_protocol::{OrgSigningKey, ServerConfig, SigningKeyId, SigningKeyStatus};

    static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    struct Fixture {
        dir: PathBuf,
        state: LocalState,
        fact_root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let n = NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("updawg-enroll-{}-{n}", std::process::id()));
            let state = LocalState::new(dir.join("state"));
            state.ensure().unwrap();

            let fact_root = dir.join("root");
            fs::create_dir_all(fact_root.join("etc")).unwrap();
            fs::create_dir_all(fact_root.join("proc/sys/kernel")).unwrap();
            fs::write(
                fact_root.join("etc/machine-id"),
                "3f2a9c1d4e5b6a7c8d9e0f1a2b3c4d5e\n",
            )
            .unwrap();
            fs::write(fact_root.join("proc/sys/kernel/hostname"), "web-03\n").unwrap();
            fs::write(
                fact_root.join("proc/sys/kernel/osrelease"),
                "6.12.0-amd64\n",
            )
            .unwrap();
            fs::write(
                fact_root.join("etc/os-release"),
                "ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\n",
            )
            .unwrap();

            Self {
                dir,
                state,
                fact_root,
            }
        }

        fn enroller<'a>(&'a self, exchange: &'a dyn EnrollExchange) -> Enroller<'a> {
            Enroller::new(&self.state, exchange).with_fact_root(&self.fact_root)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.dir).ok();
        }
    }

    /// A stand-in gateway. Records what it was asked and answers with whatever
    /// the test wants it to.
    #[derive(Debug)]
    struct FakeGateway {
        reply: Mutex<Vec<Result<EnrollResponse>>>,
        seen: Arc<Mutex<Vec<EnrollRequest>>>,
    }

    impl FakeGateway {
        fn answering(replies: Vec<Result<EnrollResponse>>) -> Self {
            Self {
                reply: Mutex::new(replies),
                seen: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn ok(response: EnrollResponse) -> Self {
            Self::answering(vec![Ok(response)])
        }
    }

    #[async_trait]
    impl EnrollExchange for FakeGateway {
        async fn post_enroll(&self, request: &EnrollRequest) -> Result<EnrollResponse> {
            self.seen.lock().unwrap().push(request.clone());
            let mut replies = self.reply.lock().unwrap();
            assert!(
                !replies.is_empty(),
                "the fake gateway was called more times than the test expected"
            );
            replies.remove(0)
        }
    }

    fn org_key(id: &str, status: SigningKeyStatus) -> OrgSigningKey {
        use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
        use base64::Engine as _;

        let rng = aws_lc_rs::rand::SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();

        let mut der = updawg_crypto::ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(pair.public_key().as_ref());

        OrgSigningKey {
            key_id: SigningKeyId::new(id),
            public_key: format!(
                "ed25519:{}",
                base64::engine::general_purpose::STANDARD.encode(der)
            ),
            status,
            endorsement: None,
        }
    }

    fn response_with(host_id: &str, keys: Vec<OrgSigningKey>) -> EnrollResponse {
        EnrollResponse {
            host_id: HostId::new(host_id),
            certificate: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".into(),
            ca_chain: vec!["-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n".into()],
            org_signing_keys: keys,
            config: ServerConfig::default(),
        }
    }

    fn good_response() -> EnrollResponse {
        response_with(
            "hst_01J9ZC6Q",
            vec![org_key("sk_01J8", SigningKeyStatus::Active)],
        )
    }

    #[tokio::test]
    async fn a_first_enrollment_writes_the_key_the_identity_and_the_pinned_keys() {
        let fx = Fixture::new();
        let gateway = FakeGateway::ok(good_response());
        let enroller = fx.enroller(&gateway);

        let outcome = enroller
            .enroll("enr_7Kq", EnrollOptions::default())
            .await
            .unwrap();

        assert!(matches!(outcome, Enrolled::New { .. }));
        assert_eq!(outcome.host_id().as_str(), "hst_01J9ZC6Q");
        assert!(fx.state.is_enrolled());
        assert!(
            enroller.key_path().exists(),
            "the private key was not written"
        );

        let identity = fx.state.identity().unwrap().unwrap();
        assert_eq!(identity.org_signing_keys.len(), 1);
        assert_eq!(identity.ca_chain.len(), 1);
    }

    #[tokio::test]
    async fn the_request_carries_the_machine_id_the_facts_and_a_csr() {
        let fx = Fixture::new();
        let gateway = FakeGateway::ok(good_response());
        fx.enroller(&gateway)
            .enroll("enr_7Kq", EnrollOptions::default())
            .await
            .unwrap();

        let seen = gateway.seen.lock().unwrap();
        let req = seen.first().expect("the gateway should have been called");
        assert_eq!(req.token, "enr_7Kq");
        assert_eq!(req.machine_id, "3f2a9c1d4e5b6a7c8d9e0f1a2b3c4d5e");
        assert_eq!(req.hostname, "web-03");
        assert_eq!(req.facts.distro, "debian");
        assert_eq!(req.facts.codename.as_deref(), Some("trixie"));
        assert!(req.csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert_eq!(req.agent_version, crate::VERSION);
    }

    /// The private key is the one thing that must never be on the wire. Worth a
    /// test rather than an assumption, since the request is built by hand.
    #[tokio::test]
    async fn the_private_key_is_never_part_of_the_request() {
        let fx = Fixture::new();
        let gateway = FakeGateway::ok(good_response());
        let enroller = fx.enroller(&gateway);
        enroller
            .enroll("enr_7Kq", EnrollOptions::default())
            .await
            .unwrap();

        let on_disk = fs::read_to_string(enroller.key_path()).unwrap();
        let body = serde_json::to_string(&gateway.seen.lock().unwrap()[0]).unwrap();
        assert!(!body.contains("PRIVATE KEY"));
        for line in on_disk.lines().filter(|l| !l.starts_with("-----")) {
            assert!(
                !body.contains(line),
                "private key material was sent to the server"
            );
        }
    }

    /// Running `updawgctl enroll` twice — by a person, or by a configuration
    /// manager that runs the same play again — must not churn the identity.
    #[tokio::test]
    async fn re_enrolling_without_force_is_a_no_op() {
        let fx = Fixture::new();
        let gateway = FakeGateway::ok(good_response());
        fx.enroller(&gateway)
            .enroll("enr_7Kq", EnrollOptions::default())
            .await
            .unwrap();
        let first = fs::read_to_string(fx.state.root().join(KEY_FILE)).unwrap();

        // The same token again. The fake would panic on a second call.
        let outcome = fx
            .enroller(&gateway)
            .enroll("enr_7Kq", EnrollOptions::default())
            .await
            .unwrap();

        assert!(matches!(outcome, Enrolled::Already { .. }));
        assert_eq!(outcome.host_id().as_str(), "hst_01J9ZC6Q");
        assert_eq!(
            first,
            fs::read_to_string(fx.state.root().join(KEY_FILE)).unwrap(),
            "a no-op enrollment must not replace the key"
        );
    }

    #[tokio::test]
    async fn forcing_a_re_enrollment_onto_the_same_org_key_replaces_the_identity() {
        let fx = Fixture::new();
        let key = org_key("sk_01J8", SigningKeyStatus::Active);
        let gateway = FakeGateway::answering(vec![
            Ok(response_with("hst_first", vec![key.clone()])),
            Ok(response_with("hst_first", vec![key])),
        ]);

        fx.enroller(&gateway)
            .enroll("enr_7Kq", EnrollOptions::default())
            .await
            .unwrap();
        let first_key = fs::read_to_string(fx.state.root().join(KEY_FILE)).unwrap();

        let outcome = fx
            .enroller(&gateway)
            .enroll(
                "enr_other",
                EnrollOptions {
                    force: true,
                    ..EnrollOptions::default()
                },
            )
            .await
            .unwrap();

        assert!(matches!(outcome, Enrolled::Replaced { .. }));
        assert_ne!(
            first_key,
            fs::read_to_string(fx.state.root().join(KEY_FILE)).unwrap(),
            "re-enrollment should abandon the old key rather than reuse it"
        );
    }

    /// The property pinning exists for. A server offering a different signing
    /// key must not be followed just because it asked.
    #[tokio::test]
    async fn a_forced_re_enrollment_refuses_a_different_org_key() {
        let fx = Fixture::new();
        let gateway = FakeGateway::answering(vec![
            Ok(response_with(
                "hst_first",
                vec![org_key("sk_original", SigningKeyStatus::Active)],
            )),
            Ok(response_with(
                "hst_first",
                vec![org_key("sk_impostor", SigningKeyStatus::Active)],
            )),
        ]);

        fx.enroller(&gateway)
            .enroll("enr_7Kq", EnrollOptions::default())
            .await
            .unwrap();
        let before = fx.state.identity().unwrap().unwrap();

        let err = fx
            .enroller(&gateway)
            .enroll(
                "enr_7Kq",
                EnrollOptions {
                    force: true,
                    ..EnrollOptions::default()
                },
            )
            .await
            .unwrap_err();

        assert!(
            matches!(err, EnrollError::OrgKeyChanged { .. }),
            "got {err:?}"
        );
        let after = fx.state.identity().unwrap().unwrap();
        assert_eq!(
            before.org_signing_keys[0].key_id.as_str(),
            after.org_signing_keys[0].key_id.as_str(),
            "a refused re-enrollment must not change what is pinned"
        );
    }

    #[tokio::test]
    async fn an_operator_can_accept_a_new_org_key_deliberately() {
        let fx = Fixture::new();
        let gateway = FakeGateway::answering(vec![
            Ok(response_with(
                "hst_first",
                vec![org_key("sk_original", SigningKeyStatus::Active)],
            )),
            Ok(response_with(
                "hst_first",
                vec![org_key("sk_replacement", SigningKeyStatus::Active)],
            )),
        ]);

        fx.enroller(&gateway)
            .enroll("t", EnrollOptions::default())
            .await
            .unwrap();
        fx.enroller(&gateway)
            .enroll(
                "t",
                EnrollOptions {
                    force: true,
                    accept_new_org_key: true,
                },
            )
            .await
            .unwrap();

        let identity = fx.state.identity().unwrap().unwrap();
        assert_eq!(
            identity.org_signing_keys[0].key_id.as_str(),
            "sk_replacement"
        );
    }

    /// Adding a key is a rotation, not a substitution: the key that has been
    /// signing this host's jobs is still there.
    #[tokio::test]
    async fn gaining_an_additional_org_key_is_allowed() {
        let fx = Fixture::new();
        let original = org_key("sk_original", SigningKeyStatus::Active);
        let gateway = FakeGateway::answering(vec![
            Ok(response_with("hst_first", vec![original.clone()])),
            Ok(response_with(
                "hst_first",
                vec![
                    OrgSigningKey {
                        status: SigningKeyStatus::Retiring,
                        ..original
                    },
                    org_key("sk_next", SigningKeyStatus::Active),
                ],
            )),
        ]);

        fx.enroller(&gateway)
            .enroll("t", EnrollOptions::default())
            .await
            .unwrap();
        fx.enroller(&gateway)
            .enroll(
                "t",
                EnrollOptions {
                    force: true,
                    ..EnrollOptions::default()
                },
            )
            .await
            .unwrap();

        let identity = fx.state.identity().unwrap().unwrap();
        assert_eq!(identity.org_signing_keys.len(), 2);
    }

    #[tokio::test]
    async fn a_rejected_token_says_what_to_do_about_it() {
        let fx = Fixture::new();
        let gateway = FakeGateway::answering(vec![Err(EnrollError::TokenRejected)]);
        let err = fx
            .enroller(&gateway)
            .enroll("enr_expired", EnrollOptions::default())
            .await
            .unwrap_err();

        assert!(matches!(err, EnrollError::TokenRejected));
        assert!(err.to_string().contains("shown only once"));
        assert!(
            !fx.state.is_enrolled(),
            "a rejected token must not enroll the host"
        );
    }

    /// The failure mode that matters operationally: a host that is working must
    /// not be broken by an enrollment attempt that fails.
    #[tokio::test]
    async fn a_failed_re_enrollment_leaves_the_working_identity_alone() {
        let fx = Fixture::new();
        let gateway = FakeGateway::answering(vec![
            Ok(good_response()),
            Err(EnrollError::Unreachable {
                url: "https://agents.updawg.net".into(),
                detail: "connection reset".into(),
            }),
        ]);

        fx.enroller(&gateway)
            .enroll("t", EnrollOptions::default())
            .await
            .unwrap();
        let key_before = fs::read_to_string(fx.state.root().join(KEY_FILE)).unwrap();
        let id_before = fx.state.identity().unwrap().unwrap();

        fx.enroller(&gateway)
            .enroll(
                "t",
                EnrollOptions {
                    force: true,
                    ..EnrollOptions::default()
                },
            )
            .await
            .unwrap_err();

        assert_eq!(
            key_before,
            fs::read_to_string(fx.state.root().join(KEY_FILE)).unwrap()
        );
        assert_eq!(
            id_before.host_id.as_str(),
            fx.state.identity().unwrap().unwrap().host_id.as_str()
        );
    }

    #[tokio::test]
    async fn a_response_that_cannot_be_trusted_is_never_pinned() {
        let cases: Vec<(EnrollResponse, &str)> = vec![
            (
                response_with(
                    "wrong_prefix",
                    vec![org_key("sk_1", SigningKeyStatus::Active)],
                ),
                "a host id with the wrong prefix",
            ),
            (
                EnrollResponse {
                    certificate: "not a certificate".into(),
                    ..good_response()
                },
                "a certificate that is not PEM",
            ),
            (
                EnrollResponse {
                    ca_chain: vec![],
                    ..good_response()
                },
                "an empty CA chain",
            ),
            (
                response_with("hst_ok", vec![]),
                "no organization signing keys",
            ),
            (
                response_with(
                    "hst_ok",
                    vec![OrgSigningKey {
                        public_key: "ed25519:not-base64!".into(),
                        ..org_key("sk_1", SigningKeyStatus::Active)
                    }],
                ),
                "a malformed organization key",
            ),
            (
                response_with("hst_ok", vec![org_key("sk_1", SigningKeyStatus::Retired)]),
                "only a retired key",
            ),
        ];

        for (response, why) in cases {
            let fx = Fixture::new();
            let gateway = FakeGateway::ok(response);
            let err = fx
                .enroller(&gateway)
                .enroll("t", EnrollOptions::default())
                .await
                .unwrap_err();
            assert!(
                matches!(err, EnrollError::BadResponse(_) | EnrollError::Crypto(_)),
                "{why}: expected a rejection, got {err:?}"
            );
            assert!(
                !fx.state.is_enrolled(),
                "{why}: the host was enrolled anyway"
            );
            assert!(
                !fx.state.root().join(KEY_FILE).exists(),
                "{why}: a key was written for an enrollment that failed"
            );
        }
    }

    /// The request body from section 5.2 of the design document, as JSON.
    /// If this stops matching, either the document or the wire format drifted.
    #[tokio::test]
    async fn the_request_matches_the_documented_shape() {
        let fx = Fixture::new();
        let gateway = FakeGateway::ok(good_response());
        fx.enroller(&gateway)
            .enroll("enr_7Kq", EnrollOptions::default())
            .await
            .unwrap();

        let seen = gateway.seen.lock().unwrap();
        let sent: serde_json::Value = serde_json::to_value(&seen[0]).unwrap();
        let documented = [
            "token",
            "csr",
            "machine_id",
            "hostname",
            "facts",
            "agent_version",
        ];
        for field in documented {
            assert!(
                sent.get(field).is_some(),
                "the request is missing `{field}`"
            );
        }
        let extra: Vec<_> = sent
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| !documented.contains(&k.as_str()))
            .collect();
        assert!(
            extra.is_empty(),
            "the request grew undocumented fields: {extra:?}"
        );

        for field in ["distro", "version", "kernel", "arch"] {
            assert!(
                sent["facts"].get(field).is_some(),
                "the facts are missing `{field}`"
            );
        }
    }

    /// The response body from section 5.2, deserialised and run through the
    /// same validation a real enrollment would.
    #[test]
    fn the_documented_response_deserialises_and_validates() {
        let key = org_key("sk_01J8", SigningKeyStatus::Active);
        let body = serde_json::json!({
            "host_id": "hst_01J9ZC6Q",
            "certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            "ca_chain": ["-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----"],
            "org_signing_keys": [
                { "key_id": "sk_01J8", "public_key": key.public_key, "status": "active" }
            ],
            "config": { "checkin_timeout_s": 55, "inventory_interval_s": 21600 }
        })
        .to_string();

        let response: EnrollResponse = serde_json::from_str(&body).unwrap();
        let pinned = validate(&response).expect("the documented response should validate");
        assert_eq!(pinned.describe().len(), 1);
        assert_eq!(response.config.checkin_timeout_s, 55);
        // Absent from the documented body, so the default has to fill it in or
        // every real response would fail to parse.
        assert_eq!(response.config.refresh_metadata_interval_s, 3600);
    }

    #[test]
    fn a_plain_http_server_address_is_refused() {
        let err = HttpsEnrollExchange::new("http://agents.updawg.net").unwrap_err();
        assert!(matches!(err, EnrollError::NotHttps { .. }), "got {err:?}");
    }

    #[test]
    fn the_enroll_url_is_built_from_the_protocol_crates_path() {
        let exchange = HttpsEnrollExchange::new("https://agents.updawg.net/").unwrap();
        assert_eq!(exchange.url, "https://agents.updawg.net/agent/v1/enroll");
    }

    /// The failure an operator is most likely to hit on day one: the gateway
    /// name resolves but has no usable certificate. `reqwest`'s own message
    /// names only the URL, so without this the log says nothing useful.
    #[test]
    fn an_unreachable_server_reports_the_underlying_reason() {
        #[derive(Debug)]
        struct Layer(&'static str, Option<Box<Layer>>);
        impl fmt::Display for Layer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.0)
            }
        }
        impl std::error::Error for Layer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.1
                    .as_deref()
                    .map(|l| l as &(dyn std::error::Error + 'static))
            }
        }

        let error = Layer(
            "error sending request",
            Some(Box::new(Layer(
                "tls handshake eof",
                Some(Box::new(Layer("received fatal alert: InternalError", None))),
            ))),
        );
        assert_eq!(
            causes(&error),
            "error sending request: tls handshake eof: received fatal alert: InternalError"
        );
    }

    #[test]
    fn a_problem_document_is_reported_by_its_detail_not_its_json() {
        let detail = problem_detail(
            r#"{"type":"https://updawg.net/errors/token","title":"Token expired","detail":"This enrollment token expired on 2026-09-01."}"#,
        );
        assert_eq!(detail, "This enrollment token expired on 2026-09-01.");
        assert_eq!(problem_detail("plain text"), "plain text");
    }
}
