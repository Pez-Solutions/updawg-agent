//! Outbound HTTPS transport, authenticated with the host's client certificate.
//!
//! The agent only ever makes outbound connections. There is no listener, no
//! inbound port and no SSH, which is what lets it work behind NAT and strict
//! egress firewalls.
//!
//! Every request after enrollment presents the client certificate issued at
//! enrollment. Those certificates are short-lived — thirty days — so a host
//! that is decommissioned or revoked drops out of the fleet on its own rather
//! than needing to be chased. The cost is that renewal has to work, which is
//! most of what this module is about.
//!
//! # Why the client lives behind a lock
//!
//! `reqwest` fixes the client certificate when the client is built, so rotating
//! a certificate means building a new client. Swapping it behind a lock keeps
//! rotation invisible to callers: a check-in in flight finishes on the old
//! connection pool and the next one uses the new certificate.
//!
//! Scope note: DAWG-31 implements this. DAWG-32 drives the check-in loop.

use crate::{
    enroll::KEY_FILE,
    state::{Identity, LocalState},
};
use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use std::{
    sync::RwLock,
    time::{Duration, SystemTime},
};
use updawg_crypto::{AgentKey, ClientCertificate, PinnedKeys};
use updawg_protocol::{
    API_PATH, CertRenewRequest, CertRenewResponse, CheckinRequest, CheckinResponse, Job,
    PROTOCOL_HEADER, PROTOCOL_VERSION,
};

/// How long any single request may take, other than a long-poll check-in.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Attempts made before giving up on one renewal pass.
///
/// Small, because the caller comes back. Renewal starts with a third of the
/// certificate's life left, so there is room for many passes before it matters.
const RENEW_ATTEMPTS: u32 = 3;

/// zstd level 3, its default.
///
/// The body is a few hundred kilobytes of repetitive text and the host is
/// somebody's production server. Higher levels cost noticeably more CPU for a few
/// percent less over the wire, and the agent's job is to be unnoticeable.
const COMPRESSION_LEVEL: i32 = 3;

/// Longer than a normal request: this one is a few hundred kilobytes and the
/// gateway writes several thousand rows before answering.
const INVENTORY_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    #[error("not enrolled; run `updawgctl enroll --token ...` first")]
    NotEnrolled,

    #[error(
        "the gateway rejected this host's client certificate ({subject}, serial {serial}, \
         expires in {expires}).\n\
         If this host was decommissioned or its certificate revoked, re-enroll it with \
         `updawgctl enroll --token <new token> --force`."
    )]
    CertificateRejected {
        subject: String,
        serial: String,
        expires: String,
    },

    #[error(
        "this host's client certificate expired {ago} ago, so the gateway will refuse it. \
         Renewal should have happened with ten days to spare — check whether the host was \
         powered off, or whether {url} has been reachable. Re-enroll with \
         `updawgctl enroll --token <new token> --force` to recover."
    )]
    CertificateExpired { ago: String, url: String },

    #[error("could not reach {url}: {detail}")]
    Unreachable { url: String, detail: String },

    #[error("{url} returned {status}: {detail}")]
    Server {
        url: String,
        status: u16,
        detail: String,
    },

    #[error("could not understand the response from {url}: {detail}")]
    BadResponse { url: String, detail: String },

    #[error("the agent server address must be https; `{url}` is not")]
    NotHttps { url: String },

    #[error(transparent)]
    Crypto(#[from] updawg_crypto::CryptoError),
    #[error(transparent)]
    State(#[from] crate::state::StateError),
}

impl TransportError {
    /// Whether the gateway refused an inventory delta because it does not hold
    /// the base it was computed against.
    ///
    /// Branching on the **code**, never the message: the protocol says so
    /// explicitly, so the gateway's wording can change without breaking hosts
    /// running older builds. The status is checked too, because a 409 is the only
    /// thing that carries this code and reading it from any other status would
    /// mean trusting a body we have not authenticated as meaning what we think.
    #[must_use]
    pub fn is_inventory_base_mismatch(&self) -> bool {
        matches!(
            self,
            Self::Server { status, detail, .. }
                if *status == 409
                    && detail.contains(updawg_protocol::ApiError::INVENTORY_BASE_MISMATCH)
        )
    }
}

pub type Result<T> = std::result::Result<T, TransportError>;

#[async_trait]
pub trait Transport: Send + Sync {
    /// Hold a long-poll open and return any job the server has for us.
    async fn check_in(&self) -> Result<Option<Job>>;
}

/// What a renewal pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Renewal {
    /// Not yet in the renewal window.
    NotDue { remaining: Duration },
    /// A new certificate was issued and is now in use.
    Renewed { expires_in: Duration },
}

/// The authenticated connection to the gateway.
#[derive(Debug)]
pub struct MtlsTransport {
    base: String,
    state: LocalState,
    /// Rebuilt whenever the certificate rotates. See the module docs.
    client: RwLock<reqwest::Client>,
    certificate: RwLock<ClientCertificate>,
    /// Per-host offset into the renewal window, so a fleet does not renew in
    /// lockstep. Derived from the certificate serial rather than a clock, so it
    /// is stable across restarts — a host that keeps rebooting should not keep
    /// drawing a new renewal time.
    spread: f64,
    extra_root: Option<Vec<u8>>,
}

impl MtlsTransport {
    /// Build a transport from the identity written at enrollment.
    ///
    /// # Errors
    /// [`TransportError::NotEnrolled`] if there is no identity yet, and
    /// [`TransportError::Crypto`] if the stored certificate or key is unusable.
    pub fn new(server: &str, state: LocalState) -> Result<Self> {
        Self::with_extra_root(server, state, None)
    }

    /// As [`Self::new`], additionally trusting a PEM CA for the server side.
    ///
    /// For a gateway behind an organization's own CA, and for the tests below.
    /// It adds to the platform trust store rather than replacing it.
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn with_extra_root(
        server: &str,
        state: LocalState,
        extra_root: Option<Vec<u8>>,
    ) -> Result<Self> {
        let base = server.trim_end_matches('/').to_string();
        if !base.starts_with("https://") {
            return Err(TransportError::NotHttps { url: base });
        }

        let identity = state.identity()?.ok_or(TransportError::NotEnrolled)?;
        let certificate = ClientCertificate::from_pem(&identity.certificate)?;
        let client = build_client(&state, &identity, extra_root.as_deref())?;

        Ok(Self {
            base,
            spread: spread_from(certificate.serial()),
            state,
            client: RwLock::new(client),
            certificate: RwLock::new(certificate),
            extra_root,
        })
    }

    #[must_use]
    pub fn certificate(&self) -> ClientCertificate {
        self.certificate
            .read()
            .map_or_else(|e| e.into_inner().clone(), |c| c.clone())
    }

    fn client(&self) -> reqwest::Client {
        self.client
            .read()
            .map_or_else(|e| e.into_inner().clone(), |c| c.clone())
    }

    fn url(&self, path: &str) -> String {
        format!("{}{API_PATH}{path}", self.base)
    }

    /// Check in, holding the long poll open for up to `hold`.
    ///
    /// The caller picks the hold rather than this taking the protocol constant,
    /// because on a network that trims idle connections the agent converges on
    /// something shorter than the gateway would allow (see
    /// [`crate::checkin`]). A margin is added so a poll that is working
    /// normally is never cut off by the client's own clock first.
    ///
    /// # Errors
    /// See [`TransportError`].
    pub async fn check_in(
        &self,
        request: &CheckinRequest,
        hold: Duration,
    ) -> Result<CheckinResponse> {
        self.post("/checkin", request, hold + Duration::from_secs(10))
            .await
    }

    /// Renew the client certificate if it is time, and start using the new one.
    ///
    /// The key is *not* rotated. A new key would mean writing two files that
    /// must both land or neither, and a crash between them leaves a host that
    /// cannot authenticate and cannot renew — recoverable only by hand. The
    /// certificate is the short-lived credential; keeping the key makes its
    /// replacement one atomic write. Rotating the key too would need an
    /// explicit two-file swap protocol, and is not worth it for this.
    ///
    /// # Errors
    /// See [`TransportError`]. A failure here leaves the current certificate in
    /// place and in use.
    pub async fn renew_if_due(&self, now: SystemTime) -> Result<Renewal> {
        let certificate = self.certificate();
        if !certificate.renewal_due(now, self.spread) {
            return Ok(Renewal::NotDue {
                remaining: certificate.remaining(now).unwrap_or(Duration::ZERO),
            });
        }

        let mut last = None;
        for attempt in 1..=RENEW_ATTEMPTS {
            match self.renew_once().await {
                Ok(renewal) => return Ok(renewal),
                Err(e) => {
                    tracing::warn!(
                        attempt,
                        of = RENEW_ATTEMPTS,
                        error = %e,
                        "certificate renewal failed"
                    );
                    last = Some(e);
                    if attempt < RENEW_ATTEMPTS {
                        tokio::time::sleep(Duration::from_secs(2u64.pow(attempt))).await;
                    }
                }
            }
        }
        Err(last.unwrap_or(TransportError::NotEnrolled))
    }

    async fn renew_once(&self) -> Result<Renewal> {
        let key = AgentKey::load(self.state.root().join(KEY_FILE))?;
        let identity = self.state.identity()?.ok_or(TransportError::NotEnrolled)?;

        let request = CertRenewRequest {
            csr: key.certificate_request(renewal_subject(&identity))?,
            agent_version: crate::VERSION.to_string(),
        };

        let response: CertRenewResponse =
            self.post("/cert/renew", &request, REQUEST_TIMEOUT).await?;

        self.adopt(&key, &identity, &response)
    }

    /// Validate a renewal response and put the new certificate into service.
    fn adopt(
        &self,
        key: &AgentKey,
        identity: &Identity,
        response: &CertRenewResponse,
    ) -> Result<Renewal> {
        let url = self.url("/cert/renew");
        let bad = |detail: String| TransportError::BadResponse {
            url: url.clone(),
            detail,
        };

        let certificate = ClientCertificate::from_pem(&response.certificate)?;
        if response.ca_chain.is_empty() {
            return Err(bad("the renewal returned no CA chain".into()));
        }
        // The check that matters: a certificate issued for someone else's key
        // would be accepted by the parser and then fail every handshake, which
        // is a miserable thing to debug at renewal time.
        if certificate.public_key_spki() != key.public_key_spki() {
            return Err(bad(
                "the renewed certificate is for a different key than this host holds".into(),
            ));
        }
        let now = SystemTime::now();
        let Some(expires_in) = certificate.remaining(now) else {
            return Err(bad("the renewed certificate has already expired".into()));
        };

        let org_signing_keys = merge_org_keys(identity, response)?;

        let renewed = Identity {
            certificate: response.certificate.clone(),
            ca_chain: response.ca_chain.clone(),
            org_signing_keys,
            ..identity.clone()
        };
        // Build the client before writing anything, for the same reason
        // enrollment holds the key back until the server has answered: if the
        // new certificate cannot actually be loaded into a TLS client, the
        // working one should still be on disk when the daemon next starts.
        let client = build_client(&self.state, &renewed, self.extra_root.as_deref())?;
        self.state.save_identity(&renewed)?;

        if let Ok(mut slot) = self.client.write() {
            *slot = client;
        }
        if let Ok(mut slot) = self.certificate.write() {
            *slot = certificate.clone();
        }

        tracing::info!(
            serial = certificate.serial(),
            expires_in_days = expires_in.as_secs() / 86_400,
            "client certificate renewed"
        );
        Ok(Renewal::Renewed { expires_in })
    }
}

/// Take organization signing keys offered at renewal, conservatively.
///
/// Adding a key is a rotation in progress and is adopted. *Dropping* one this
/// host still relies on is refused and left alone: following that blindly would
/// undo the pinning done at enrollment, and a renewal is not a moment an
/// operator is watching. Properly following an endorsed rotation is DAWG-99.
fn merge_org_keys(
    identity: &Identity,
    response: &CertRenewResponse,
) -> Result<Vec<updawg_protocol::OrgSigningKey>> {
    if response.org_signing_keys.is_empty() {
        return Ok(identity.org_signing_keys.clone());
    }

    let offered = PinnedKeys::from_wire(&response.org_signing_keys)?;
    let pinned = PinnedKeys::from_wire(&identity.org_signing_keys)?;
    let dropped: Vec<_> = pinned
        .usable()
        .into_iter()
        .filter(|(id, key)| !offered.contains(id, key))
        .map(|(id, key)| format!("{id} {}", key.fingerprint()))
        .collect();

    if dropped.is_empty() {
        tracing::info!(
            keys = ?offered.describe(),
            "adopted organization signing keys offered at renewal"
        );
        return Ok(response.org_signing_keys.clone());
    }

    tracing::error!(
        dropped = ?dropped,
        "the renewal dropped an organization signing key this host relies on; keeping the \
         pinned set. If the organization really rotated its key, re-enroll with \
         --accept-new-org-key (DAWG-99)"
    );
    Ok(identity.org_signing_keys.clone())
}

impl MtlsTransport {
    async fn post<B: Serialize + Sync, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        timeout: Duration,
    ) -> Result<R> {
        let url = self.url(path);
        let response = self
            .client()
            .post(&url)
            .header(PROTOCOL_HEADER, PROTOCOL_VERSION.to_string())
            .timeout(timeout)
            .json(body)
            .send()
            .await
            .map_err(|e| self.connection_error(&url, &e))?;

        let status = response.status();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return Err(self.certificate_rejected());
        }
        if !status.is_success() {
            let detail = response
                .text()
                .await
                .unwrap_or_else(|_| "no response body".into());
            return Err(TransportError::Server {
                url,
                status: status.as_u16(),
                detail: crate::enroll::problem_detail(&detail),
            });
        }

        response
            .json::<R>()
            .await
            .map_err(|e| TransportError::BadResponse {
                url,
                detail: e.to_string(),
            })
    }

    /// `PUT /agent/v1/inventory`, zstd-compressed.
    ///
    /// A full package list is 800–2,500 entries. Compressing it is not a
    /// micro-optimisation: across a fleet on a six-hourly cycle it is most of
    /// what the gateway receives, and the body is highly repetitive text, which
    /// is the case zstd is best at.
    ///
    /// The gateway decompresses by `Content-Encoding` and passes an unlabelled
    /// body through untouched, so this is safe to send at any point after the
    /// server side has shipped and needs no negotiation.
    ///
    /// Returns `()` — the gateway's answer carries nothing the agent acts on
    /// except its status, and [`TransportError::is_inventory_base_mismatch`] is
    /// how the one case that matters is recognised.
    pub async fn upload_inventory(&self, upload: &updawg_protocol::InventoryUpload) -> Result<()> {
        let url = self.url("/inventory");
        let json = serde_json::to_vec(upload).map_err(|e| TransportError::BadResponse {
            url: url.clone(),
            detail: format!("could not serialise the inventory: {e}"),
        })?;
        let body = zstd::encode_all(json.as_slice(), COMPRESSION_LEVEL).map_err(|e| {
            TransportError::BadResponse {
                url: url.clone(),
                detail: format!("could not compress the inventory: {e}"),
            }
        })?;

        let response = self
            .client()
            .put(&url)
            .header(PROTOCOL_HEADER, PROTOCOL_VERSION.to_string())
            .header("content-type", "application/json")
            .header("content-encoding", "zstd")
            .timeout(INVENTORY_TIMEOUT)
            .body(body)
            .send()
            .await
            .map_err(|e| self.connection_error(&url, &e))?;

        let status = response.status();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return Err(self.certificate_rejected());
        }
        if !status.is_success() {
            let detail = response
                .text()
                .await
                .unwrap_or_else(|_| "no response body".into());
            return Err(TransportError::Server {
                url,
                status: status.as_u16(),
                detail,
            });
        }
        Ok(())
    }

    /// Turn a connection failure into something worth reading.
    ///
    /// A gateway refusing an expired client certificate shows up as a TLS
    /// handshake failure, not as an HTTP status, and matching on alert strings
    /// to work out why is guesswork. The certificate's own expiry is a local
    /// fact, so check that first and say so plainly.
    fn connection_error(&self, url: &str, error: &reqwest::Error) -> TransportError {
        let certificate = self.certificate();
        let now = SystemTime::now();
        if certificate.is_expired(now) {
            let ago = now
                .duration_since(certificate.not_after())
                .unwrap_or(Duration::ZERO);
            return TransportError::CertificateExpired {
                ago: approximate(ago),
                url: url.to_string(),
            };
        }
        TransportError::Unreachable {
            url: url.to_string(),
            detail: crate::enroll::causes(error),
        }
    }

    fn certificate_rejected(&self) -> TransportError {
        let certificate = self.certificate();
        TransportError::CertificateRejected {
            subject: certificate.subject().to_string(),
            serial: certificate.serial().to_string(),
            expires: certificate
                .remaining(SystemTime::now())
                .map_or_else(|| "the past".into(), approximate),
        }
    }
}

/// Build a `reqwest` client that presents this host's certificate.
fn build_client(
    state: &LocalState,
    identity: &Identity,
    extra_root: Option<&[u8]>,
) -> Result<reqwest::Client> {
    let key = AgentKey::load(state.root().join(KEY_FILE))?;

    // reqwest wants one PEM document holding the key and the certificate
    // chain. Built in memory; the key is never written anywhere but its own
    // file.
    let mut bundle = key.private_key_pem();
    bundle.push_str(&identity.certificate);
    for ca in &identity.ca_chain {
        bundle.push_str(ca);
    }

    let client_identity = reqwest::Identity::from_pem(bundle.as_bytes()).map_err(|e| {
        TransportError::Crypto(updawg_crypto::CryptoError::MalformedCertificate(
            e.to_string(),
        ))
    })?;

    let mut builder = reqwest::Client::builder()
        .identity(client_identity)
        .timeout(REQUEST_TIMEOUT)
        .user_agent(format!("updawg-agent/{}", crate::VERSION));

    if let Some(pem) = extra_root {
        let root = reqwest::Certificate::from_pem(pem).map_err(|e| {
            TransportError::Crypto(updawg_crypto::CryptoError::MalformedCertificate(
                e.to_string(),
            ))
        })?;
        builder = builder.add_root_certificate(root);
    }

    builder.build().map_err(|e| TransportError::Unreachable {
        url: "the agent gateway".into(),
        detail: e.to_string(),
    })
}

/// The CSR subject to use when renewing.
///
/// The host id, not the machine id this host used at enrollment: by now the
/// server has named it, and that name is what the renewed certificate will
/// carry. Either way the subject is only a request — the gateway decides
/// identity from the certificate presented on the renewal call, not from what
/// the CSR asks for.
fn renewal_subject(identity: &Identity) -> &str {
    identity.host_id.as_str()
}

/// A stable per-host offset in `[0, 1)`, derived from the certificate serial.
///
/// Stable is the point. Drawing this from a clock would give a host that keeps
/// restarting a new renewal time each boot, which is the opposite of spreading
/// load.
fn spread_from(serial: &str) -> f64 {
    // FNV-1a. A simple `acc * 31 + b` fold leaves the low bits dominated by the
    // last byte, and certificate serials issued in sequence differ only there —
    // which clusters exactly the hosts this is meant to separate.
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x1000_0000_01b3;
    let hash = serial
        .bytes()
        .fold(OFFSET, |acc, b| (acc ^ u64::from(b)).wrapping_mul(PRIME));
    #[allow(clippy::cast_precision_loss)]
    {
        (hash % 10_000) as f64 / 10_000.0
    }
}

/// "3 days", "4 hours", "12 minutes" — enough for an operator to act on.
fn approximate(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..=90 => format!("{s} seconds"),
        91..=5400 => format!("{} minutes", s / 60),
        5401..=172_800 => format!("{} hours", s / 3600),
        _ => format!("{} days", s / 86_400),
    }
}

#[cfg(test)]
mod tests;
