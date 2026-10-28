//! Outbound HTTPS transport, authenticated with the host's client certificate.
//!
//! The agent only makes outbound connections (no listener, no SSH), so it
//! works behind NAT and strict egress firewalls.
//!
//! Client certificates are valid for 30 days, so a decommissioned or revoked
//! host drops out on its own. Most of this module is about renewing them.
//!
//! `reqwest` fixes the client certificate when the client is built, so the
//! client sits behind a lock and is swapped on renewal. Requests in flight
//! finish on the old connection pool.

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

/// Attempts per renewal pass. The caller retries later, and renewal starts
/// with a third of the certificate's life left.
const RENEW_ATTEMPTS: u32 = 3;

/// zstd's default level. Higher levels cost noticeably more CPU on the host
/// for a few percent smaller bodies.
const COMPRESSION_LEVEL: i32 = 3;

/// The upload is a few hundred KB and the gateway writes thousands of rows
/// before answering.
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
         Renewal should have happened with ten days to spare; check whether the host was \
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

    /// 429, with the wait the gateway asked for.
    #[error("{url} is rate limiting this host; waiting {}s before asking again", retry_after.as_secs())]
    RateLimited { url: String, retry_after: Duration },

    #[error("the agent server address must be https; `{url}` is not")]
    NotHttps { url: String },

    #[error(transparent)]
    Crypto(#[from] updawg_crypto::CryptoError),
    #[error(transparent)]
    State(#[from] crate::state::StateError),
}

impl TransportError {
    /// How long the gateway asked this host to wait, if it did.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after, .. } => Some(*retry_after),
            _ => None,
        }
    }

    /// Whether the gateway refused an inventory delta because it doesn't hold
    /// the base it was computed against.
    ///
    /// Matches on the error code rather than the message, which may change.
    /// Only a 409 carries this code, so the status is checked too.
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

/// Maps a 429 to [`TransportError::RateLimited`] using `Retry-After` (in
/// seconds). Falls back to a minute if the header is missing.
fn rate_limited(url: &str, response: &reqwest::Response) -> Option<TransportError> {
    if response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS {
        return None;
    }
    let seconds = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(60);
    Some(TransportError::RateLimited {
        url: url.to_owned(),
        retry_after: Duration::from_secs(seconds.clamp(1, 3600)),
    })
}

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
    client: RwLock<reqwest::Client>,
    certificate: RwLock<ClientCertificate>,
    /// Per-host offset into the renewal window, derived from the certificate
    /// serial so it stays the same across restarts.
    spread: f64,
    extra_root: Option<Vec<u8>>,
}

/// The bytes an inventory upload sends, before compression. Also used by
/// `updawgctl print-inventory --json` so it shows exactly what is sent.
pub fn inventory_body(upload: &updawg_protocol::InventoryUpload) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(upload)
}

impl MtlsTransport {
    /// Builds a transport from the identity written at enrollment.
    ///
    /// # Errors
    /// [`TransportError::NotEnrolled`] if there is no identity yet, and
    /// [`TransportError::Crypto`] if the stored certificate or key is unusable.
    pub fn new(server: &str, state: LocalState) -> Result<Self> {
        Self::with_extra_root(server, state, None)
    }

    /// As [`Self::new`], additionally trusting a PEM CA for the server side.
    /// Adds to the platform trust store rather than replacing it.
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

    /// Checks in, holding the long poll open for up to `hold`. Adds a margin
    /// so the client's timeout doesn't fire before the gateway answers.
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

    /// This host's offset into a window, between 0 and 1, stable across
    /// restarts. Also used to spread server-requested renewals.
    #[must_use]
    pub const fn spread(&self) -> f64 {
        self.spread
    }

    /// Renews the client certificate if it's due and starts using the new one.
    ///
    /// The key is not rotated. That would mean replacing two files atomically,
    /// and a crash in between would leave a host that can neither authenticate
    /// nor renew. Keeping the key makes renewal a single write.
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
        self.renew_now().await
    }

    /// Renews the client certificate regardless of age. Used when the server
    /// asks (the organization has a newer signing key than this host was
    /// offered) or an operator runs `updawgctl renew`.
    ///
    /// # Errors
    /// See [`Self::renew_if_due`].
    pub async fn renew_now(&self) -> Result<Renewal> {
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
        // a certificate for another key would parse fine and then fail every
        // handshake
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
        // Build the client before saving, so a certificate that can't be
        // loaded never replaces the working one on disk.
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

/// Merges organization signing keys offered at renewal.
///
/// A key missing from the offer is kept, since dropping it would undo the
/// pinning done at enrollment. A new key is adopted only if it is endorsed by
/// one this host already holds ([`PinnedKeys::adopt`]).
///
/// Nobody is watching during a renewal, so a rejected key set doesn't fail
/// the renewal. It keeps the current set and logs an error. There's no
/// `--accept-new-org-key` override here for the same reason.
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

    if !dropped.is_empty() {
        tracing::error!(
            dropped = ?dropped,
            "the renewal dropped an organization signing key this host relies on; keeping the \
             pinned set. If the organization really rotated its key, re-enroll with \
             --accept-new-org-key"
        );
        return Ok(identity.org_signing_keys.clone());
    }

    if let Err(e) = pinned.adopt(&response.org_signing_keys) {
        tracing::error!(
            reason = %e,
            "the renewal offered an organization signing key this host cannot follow; keeping \
             the pinned set. A new key has to be endorsed by one this host already trusts. If \
             the chain really is broken, re-enroll with --accept-new-org-key"
        );
        return Ok(identity.org_signing_keys.clone());
    }

    tracing::info!(
        keys = ?offered.describe(),
        "adopted organization signing keys offered at renewal"
    );
    Ok(response.org_signing_keys.clone())
}

const JOB_ANSWER_TIMEOUT: Duration = Duration::from_secs(30);

/// The gateway's reply to a job ack or completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobAnswer {
    Recorded,
    /// `409 job_out_of_order`: this answer or a later one already arrived.
    /// Not a failure and not worth retrying.
    AlreadyMoved,
}

impl MtlsTransport {
    /// `POST /agent/v1/jobs/{id}/ack`.
    ///
    /// # Errors
    /// Transport failures, and any refusal other than "already moved".
    pub async fn ack_job(
        &self,
        id: &updawg_protocol::JobId,
        ack: &updawg_protocol::JobAck,
    ) -> Result<JobAnswer> {
        self.answer(&format!("/jobs/{}/ack", id.as_str()), ack)
            .await
    }

    /// `POST /agent/v1/jobs/{id}/complete`.
    ///
    /// # Errors
    /// Transport failures, and any refusal other than "already moved".
    pub async fn complete_job(
        &self,
        id: &updawg_protocol::JobId,
        done: &updawg_protocol::JobComplete,
    ) -> Result<JobAnswer> {
        self.answer(&format!("/jobs/{}/complete", id.as_str()), done)
            .await
    }

    /// `POST /agent/v1/jobs/{id}/logs`: a batch of NDJSON lines.
    ///
    /// `Ok(false)` if the gateway will never accept this batch (malformed, or
    /// the job no longer takes logs) and the caller should drop it. `Err` is
    /// worth retrying.
    ///
    /// # Errors
    /// Transport failures and server errors.
    pub async fn upload_logs(&self, id: &updawg_protocol::JobId, ndjson: String) -> Result<bool> {
        let url = self.url(&format!("/jobs/{}/logs", id.as_str()));
        let response = self
            .client()
            .post(&url)
            .header(PROTOCOL_HEADER, PROTOCOL_VERSION.to_string())
            .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
            .timeout(JOB_ANSWER_TIMEOUT)
            .body(ndjson)
            .send()
            .await
            .map_err(|e| self.connection_error(&url, &e))?;
        if let Some(limited) = rate_limited(&url, &response) {
            return Err(limited);
        }
        let status = response.status().as_u16();
        match status {
            401 | 403 => Err(self.certificate_rejected()),
            200..=299 => Ok(true),
            // permanent refusals
            400 | 404 | 409 | 413 => Ok(false),
            _ => {
                let detail = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "no response body".into());
                Err(TransportError::Server {
                    url,
                    status,
                    detail: crate::enroll::problem_detail(&detail),
                })
            }
        }
    }

    /// A `POST` the gateway answers with `204` and no body.
    async fn answer<B: Serialize + Sync>(&self, path: &str, body: &B) -> Result<JobAnswer> {
        let url = self.url(path);
        let response = self
            .client()
            .post(&url)
            .header(PROTOCOL_HEADER, PROTOCOL_VERSION.to_string())
            .timeout(JOB_ANSWER_TIMEOUT)
            .json(body)
            .send()
            .await
            .map_err(|e| self.connection_error(&url, &e))?;
        let status = response.status();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return Err(self.certificate_rejected());
        }
        if let Some(limited) = rate_limited(&url, &response) {
            return Err(limited);
        }
        if status.as_u16() == 409 {
            return Ok(JobAnswer::AlreadyMoved);
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
        Ok(JobAnswer::Recorded)
    }

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
        if let Some(limited) = rate_limited(&url, &response) {
            return Err(limited);
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
    /// A full package list is typically 800 to 2,500 entries of repetitive
    /// text, and inventory is most of what the gateway receives, so it's worth
    /// compressing. The gateway decodes by `Content-Encoding`.
    ///
    /// Only the status matters. Use
    /// [`TransportError::is_inventory_base_mismatch`] to detect a stale delta.
    pub async fn upload_inventory(&self, upload: &updawg_protocol::InventoryUpload) -> Result<()> {
        let url = self.url("/inventory");
        let json = inventory_body(upload).map_err(|e| TransportError::BadResponse {
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
        if let Some(limited) = rate_limited(&url, &response) {
            return Err(limited);
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

    /// An expired client certificate shows up as a TLS handshake failure
    /// rather than an HTTP status, so check the local expiry first and report
    /// that if it applies.
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

fn build_client(
    state: &LocalState,
    identity: &Identity,
    extra_root: Option<&[u8]>,
) -> Result<reqwest::Client> {
    let key = AgentKey::load(state.root().join(KEY_FILE))?;

    // reqwest wants the key and chain in one PEM. Kept in memory only.
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

/// The CSR subject for a renewal: the server-assigned host id rather than the
/// machine id used at enrollment. The gateway takes identity from the
/// presented certificate, not the CSR, so this is only a request.
fn renewal_subject(identity: &Identity) -> &str {
    identity.host_id.as_str()
}

/// A stable per-host offset in `[0, 1)`, derived from the certificate serial.
fn spread_from(serial: &str) -> f64 {
    // FNV-1a. A simple `acc * 31 + b` fold leaves the low bits dominated by
    // the last byte, and sequential serials differ mostly there.
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

/// Rough human duration: "3 days", "4 hours", "12 minutes".
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
