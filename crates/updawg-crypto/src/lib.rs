//! Signature verification, key pinning and CSR generation.
//!
//! The agent generates its key pair locally and the private key never leaves
//! the host. The organization's signing key is pinned at enrollment, and every
//! job is verified against that pinned key rather than against whatever the
//! server currently claims.
//!
//! On rotation the old key endorses the new one, so the agent can follow a
//! rotation without trusting the server. See [`PinnedKeys::adopt`].

pub mod cert;
pub mod key;
pub mod org_key;

use std::fmt;
use updawg_protocol::{OrgSigningKey, SigningKeyStatus};

pub use cert::ClientCertificate;
pub use key::AgentKey;
pub use org_key::OrgKeyPair;

/// DER header of an Ed25519 `SubjectPublicKeyInfo`, ahead of the 32 key bytes:
/// `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING }`.
pub const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

const ED25519_KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("signature does not verify against the pinned organization key")]
    BadSignature,
    #[error("the job says {claimed} signed it, and it verifies under {signed_by}")]
    WrongKey { claimed: String, signed_by: String },
    #[error("no organization key is pinned; the host is not enrolled")]
    NotPinned,
    #[error(
        "organization key {key_id} carries no endorsement, and this host has already pinned a \
         key; a new key has to be endorsed by one this host already trusts"
    )]
    UnendorsedKey { key_id: String },
    #[error(
        "the endorsement offered for organization key {key_id} does not lead back to a key this \
         host trusts: {detail}"
    )]
    BrokenEndorsement { key_id: String, detail: String },
    #[error(
        "organization key {key_id} was offered with different key material than the one this \
         host has pinned under that id"
    )]
    KeyMaterialChanged { key_id: String },
    #[error(
        "organization key {key_id} was offered as {offered:?} after this host recorded it as \
         {pinned:?}; a key never becomes more trusted than it already was"
    )]
    KeyStatusRegressed {
        key_id: String,
        pinned: SigningKeyStatus,
        offered: SigningKeyStatus,
    },
    #[error("organization key {key_id} is malformed: {detail}")]
    MalformedOrgKey { key_id: String, detail: String },
    #[error(
        "organization key {key_id} has been retired and must not be trusted; the host needs to re-enroll"
    )]
    KeyRetired { key_id: String },
    #[error("the server offered no usable organization signing key")]
    NoUsableOrgKey,
    #[error(
        "the server did not offer the organization key this host is configured to trust \
         ({fingerprint}, `trusted_org_key` in agent.toml); refusing to pin anything else"
    )]
    AnchorNotOffered { fingerprint: String },
    #[error("could not generate a key pair: {0}")]
    KeyGeneration(String),
    #[error("could not build a certificate signing request: {0}")]
    Csr(String),
    #[error("could not read or write {path}")]
    KeyFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("the private key file is not a valid Ed25519 key: {0}")]
    MalformedKeyFile(String),
    #[error("the client certificate could not be parsed: {0}")]
    MalformedCertificate(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Colon-separated short fingerprint, for display and for logs.
#[must_use]
pub fn fingerprint_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// An organization's Ed25519 public key, as the raw 32 bytes. It is parsed
/// when pinned, so a malformed key never reaches local state.
#[derive(Clone, PartialEq, Eq)]
pub struct OrgPublicKey(Vec<u8>);

impl OrgPublicKey {
    /// Parse the wire form: `ed25519:` followed by base64 SPKI.
    ///
    /// # Errors
    /// [`CryptoError::MalformedOrgKey`] if the prefix, the base64 or the DER
    /// structure is wrong.
    pub fn parse(key_id: &str, encoded: &str) -> Result<Self> {
        use base64::Engine as _;

        let bad = |detail: &str| CryptoError::MalformedOrgKey {
            key_id: key_id.to_string(),
            detail: detail.to_string(),
        };

        let body = encoded
            .strip_prefix("ed25519:")
            .ok_or_else(|| bad("expected an `ed25519:` prefix"))?;

        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|e| bad(&format!("not valid base64: {e}")))?;

        if der.len() != ED25519_SPKI_PREFIX.len() + ED25519_KEY_LEN {
            return Err(bad(&format!(
                "expected a {}-byte SubjectPublicKeyInfo, got {}",
                ED25519_SPKI_PREFIX.len() + ED25519_KEY_LEN,
                der.len()
            )));
        }
        if !der.starts_with(ED25519_SPKI_PREFIX) {
            return Err(bad("not an Ed25519 SubjectPublicKeyInfo"));
        }

        Ok(Self(der[ED25519_SPKI_PREFIX.len()..].to_vec()))
    }

    /// Like [`OrgPublicKey::parse`], but also accepts the bare base64 SPKI
    /// that `updawgctl keygen` prints.
    ///
    /// # Errors
    /// [`CryptoError::MalformedOrgKey`], as for [`OrgPublicKey::parse`].
    pub fn parse_configured(name: &str, encoded: &str) -> Result<Self> {
        let encoded = encoded.trim();
        if encoded.starts_with("ed25519:") {
            Self::parse(name, encoded)
        } else {
            Self::parse(name, &format!("ed25519:{encoded}"))
        }
    }

    #[must_use]
    pub fn to_wire(&self) -> String {
        use base64::Engine as _;
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(&self.0);
        format!(
            "ed25519:{}",
            base64::engine::general_purpose::STANDARD.encode(der)
        )
    }

    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn fingerprint(&self) -> String {
        fingerprint_bytes(&self.0)
    }

    /// # Errors
    /// [`CryptoError::BadSignature`] if it does not verify.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
        UnparsedPublicKey::new(&ED25519, &self.0)
            .verify(message, signature)
            .map_err(|_| CryptoError::BadSignature)
    }
}

// fingerprint only, so key material never ends up in a log
impl fmt::Debug for OrgPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OrgPublicKey")
            .field(&self.fingerprint())
            .finish()
    }
}

/// Verifies signed payloads against the key pinned at enrollment.
pub trait Verifier: Send + Sync + fmt::Debug {
    /// # Errors
    /// [`CryptoError::BadSignature`] if the signature does not verify.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()>;
    fn pinned_key(&self) -> Result<OrgPublicKey>;
}

/// The organization keys this host has pinned.
///
/// `active` and `retiring` keys both verify, so jobs signed just before a
/// cut-over still run. `retired` keys are kept so a job signed by one fails
/// with [`CryptoError::KeyRetired`] instead of looking like an unknown key.
#[derive(Debug, Clone)]
pub struct PinnedKeys {
    keys: Vec<PinnedKey>,
}

#[derive(Debug, Clone)]
struct PinnedKey {
    key_id: String,
    key: OrgPublicKey,
    status: SigningKeyStatus,
}

impl PinnedKeys {
    /// # Errors
    /// Fails if any key is malformed, or if none of them is active.
    pub fn from_wire(offered: &[OrgSigningKey]) -> Result<Self> {
        let mut keys = Vec::with_capacity(offered.len());
        for k in offered {
            keys.push(PinnedKey {
                key_id: k.key_id.as_str().to_string(),
                key: OrgPublicKey::parse(k.key_id.as_str(), &k.public_key)?,
                status: k.status,
            });
        }
        if !keys
            .iter()
            .any(|k| matches!(k.status, SigningKeyStatus::Active))
        {
            return Err(CryptoError::NoUsableOrgKey);
        }
        Ok(Self { keys })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Fingerprints in `key_id status fingerprint` form, for `updawgctl status`.
    #[must_use]
    pub fn describe(&self) -> Vec<String> {
        self.keys
            .iter()
            .map(|k| format!("{} {:?} {}", k.key_id, k.status, k.key.fingerprint()))
            .collect()
    }

    /// Same id and same bytes.
    #[must_use]
    pub fn contains(&self, key_id: &str, key: &OrgPublicKey) -> bool {
        self.keys
            .iter()
            .any(|k| k.key_id == key_id && &k.key == key)
    }

    /// Same bytes, under any id and in any status.
    #[must_use]
    pub fn contains_material(&self, key: &OrgPublicKey) -> bool {
        self.keys.iter().any(|k| &k.key == key)
    }

    /// Active and retiring keys.
    #[must_use]
    pub fn usable(&self) -> Vec<(&str, &OrgPublicKey)> {
        self.keys
            .iter()
            .filter(|k| {
                matches!(
                    k.status,
                    SigningKeyStatus::Active | SigningKeyStatus::Retiring
                )
            })
            .map(|k| (k.key_id.as_str(), &k.key))
            .collect()
    }

    /// Follows a rotation: returns the offered set if it is acceptable given
    /// the keys this host already trusts.
    ///
    /// - A key already pinned with the same material is kept. Its status can
    ///   move from `active` to `retiring` to `retired` without an endorsement,
    ///   since each step narrows what the host accepts. It can't move back.
    /// - A new key needs an endorsement that verifies under a key this host
    ///   holds as `active` or `retiring`, and that names the new key by
    ///   material as well as by id.
    /// - A new key offered as `retired` needs no endorsement. It can't verify
    ///   or endorse anything, and a host anchored on a customer's key would
    ///   otherwise reject every renewal that still lists the Updawg key the
    ///   customer replaced.
    /// - If any offered key fails, the whole set is rejected and the caller
    ///   keeps what it had, so a host never trusts half a rotation.
    ///
    /// Chains of any length work as long as every link is offered.
    ///
    /// The statement's `org_id` isn't checked here. An endorsement from
    /// another organization is signed by a key this host doesn't hold, so it
    /// already fails the chain check; `org_id` only stops a signature being
    /// replayed where the chain would otherwise line up.
    ///
    /// # Errors
    /// Every error names the offending key.
    pub fn adopt(&self, offered: &[OrgSigningKey]) -> Result<Self> {
        let parsed = Self::from_wire(offered)?;

        let mut trusted: Vec<PinnedKey> = Vec::with_capacity(parsed.keys.len());
        let mut pending: Vec<(&PinnedKey, &OrgSigningKey)> = Vec::new();

        // Keys that may endorse. Already-pinned keys count at the status this
        // host holds them at, not the status in this message; otherwise the
        // result would depend on evaluation order. Keys adopted during this
        // call join at their offered status so chains work.
        let mut authority: Vec<PinnedKey> = self.keys.clone();

        for (key, wire) in parsed.keys.iter().zip(offered) {
            match self.keys.iter().find(|k| k.key_id == key.key_id) {
                Some(already) if already.key != key.key => {
                    return Err(CryptoError::KeyMaterialChanged {
                        key_id: key.key_id.clone(),
                    });
                }
                Some(already) => {
                    if trust_rank(key.status) < trust_rank(already.status) {
                        return Err(CryptoError::KeyStatusRegressed {
                            key_id: key.key_id.clone(),
                            pinned: already.status,
                            offered: key.status,
                        });
                    }
                    trusted.push(key.clone());
                }
                // not added to `authority`: a retired key endorses nothing
                None if matches!(key.status, SigningKeyStatus::Retired) => {
                    trusted.push(key.clone());
                }
                None => pending.push((key, wire)),
            }
        }

        // Loop to a fixed point, since a key may be endorsed by another new
        // key in the same set.
        while !pending.is_empty() {
            let before = pending.len();
            let mut still_pending = Vec::with_capacity(before);
            for (key, wire) in pending {
                match endorsed_by(&authority, key, wire) {
                    Ok(()) => {
                        trusted.push(key.clone());
                        authority.push(key.clone());
                    }
                    Err(_) => still_pending.push((key, wire)),
                }
            }
            if still_pending.len() == before {
                // no progress; re-run the first one to surface its error
                let (key, wire) = still_pending[0];
                endorsed_by(&authority, key, wire)?;
                unreachable!("endorsed_by returned Ok on a key that did not move");
            }
            pending = still_pending;
        }

        Ok(Self { keys: trusted })
    }

    /// Pins an enrollment's keys against a key the operator configured in
    /// advance (`trusted_org_key` in `agent.toml`).
    ///
    /// Without an anchor, enrollment trusts whatever the server offers on
    /// first use, so a compromised server could give a new host a key of its
    /// own. With one, the anchor must be among the offered keys (under any
    /// id) and [`PinnedKeys::adopt`] requires every other key to chain from
    /// it or be retired. The anchor counts as active for endorsing whatever
    /// status it is offered at, so a host provisioned after the customer
    /// rotated can still reach the successor.
    ///
    /// # Errors
    /// [`CryptoError::AnchorNotOffered`] if no offered key has the anchor's
    /// material, and every error [`PinnedKeys::adopt`] returns.
    pub fn anchored(anchor: &OrgPublicKey, offered: &[OrgSigningKey]) -> Result<Self> {
        let parsed = Self::from_wire(offered)?;
        let root = parsed
            .keys
            .iter()
            .find(|k| &k.key == anchor)
            .ok_or_else(|| CryptoError::AnchorNotOffered {
                fingerprint: anchor.fingerprint(),
            })?;
        let base = Self {
            keys: vec![PinnedKey {
                key_id: root.key_id.clone(),
                key: root.key.clone(),
                status: SigningKeyStatus::Active,
            }],
        };
        base.adopt(offered)
    }

    /// Checks the signature over [`updawg_protocol::Job::signing_bytes`]
    /// against a usable pinned key, and that the key is the one the job
    /// names.
    ///
    /// # Errors
    /// [`CryptoError::BadSignature`] if nothing pinned verifies it (including a
    /// signature that is not base64), [`CryptoError::KeyRetired`] if a retired
    /// key did, and [`CryptoError::WrongKey`] if it verified under a key other
    /// than the one it names.
    pub fn verify_job(&self, job: &updawg_protocol::Job) -> Result<()> {
        use base64::Engine as _;
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&job.signature)
            .map_err(|_| CryptoError::BadSignature)?;
        let bytes = job.signing_bytes().map_err(|_| CryptoError::BadSignature)?;
        let signed_by = self.verify(&bytes, &signature)?;
        if signed_by != job.key_id.as_str() {
            return Err(CryptoError::WrongKey {
                claimed: job.key_id.as_str().to_owned(),
                signed_by: signed_by.to_owned(),
            });
        }
        Ok(())
    }

    /// Returns the id of the key that verified the signature.
    ///
    /// # Errors
    /// [`CryptoError::KeyRetired`] if a retired key is what signed it, and
    /// [`CryptoError::BadSignature`] if nothing pinned verifies it.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<&str> {
        for k in &self.keys {
            if k.key.verify(message, signature).is_ok() {
                return match k.status {
                    SigningKeyStatus::Active | SigningKeyStatus::Retiring => Ok(&k.key_id),
                    SigningKeyStatus::Retired => Err(CryptoError::KeyRetired {
                        key_id: k.key_id.clone(),
                    }),
                };
            }
        }
        Err(CryptoError::BadSignature)
    }
}

/// Lower means more trusted. The server may move a key up this scale on its
/// own; moving down would widen trust and is refused.
const fn trust_rank(status: SigningKeyStatus) -> u8 {
    match status {
        SigningKeyStatus::Active => 0,
        SigningKeyStatus::Retiring => 1,
        SigningKeyStatus::Retired => 2,
    }
}

fn endorsed_by(trusted: &[PinnedKey], key: &PinnedKey, wire: &OrgSigningKey) -> Result<()> {
    use base64::Engine as _;

    let broken = |detail: String| CryptoError::BrokenEndorsement {
        key_id: key.key_id.clone(),
        detail,
    };

    let endorsement = wire
        .endorsement
        .as_ref()
        .ok_or_else(|| CryptoError::UnendorsedKey {
            key_id: key.key_id.clone(),
        })?;

    let statement = endorsement
        .statement()
        .map_err(|e| broken(format!("its statement does not parse: {e}")))?;

    // Match on material as well as id, or the server could pick which bytes
    // an endorsed id refers to.
    if statement.new_key.key_id.as_str() != key.key_id {
        return Err(broken(format!(
            "it endorses {} rather than this key",
            statement.new_key.key_id
        )));
    }
    let endorsed_material = OrgPublicKey::parse(key.key_id.as_str(), &statement.new_key.public_key)
        .map_err(|e| broken(format!("the key it endorses is malformed: {e}")))?;
    if endorsed_material != key.key {
        return Err(broken(
            "it endorses different key material under the same id".to_string(),
        ));
    }

    let previous = trusted
        .iter()
        .find(|k| {
            k.key_id == statement.previous_key.key_id.as_str()
                && matches!(
                    k.status,
                    SigningKeyStatus::Active | SigningKeyStatus::Retiring
                )
        })
        .ok_or_else(|| {
            broken(format!(
                "it is endorsed by {}, which this host does not hold as active or retiring",
                statement.previous_key.key_id
            ))
        })?;
    let claimed = OrgPublicKey::parse(
        statement.previous_key.key_id.as_str(),
        &statement.previous_key.public_key,
    )
    .map_err(|e| broken(format!("the endorsing key is malformed: {e}")))?;
    if claimed != previous.key {
        return Err(broken(format!(
            "it names {} with material this host has not pinned",
            statement.previous_key.key_id
        )));
    }

    let signature = base64::engine::general_purpose::STANDARD
        .decode(&endorsement.signature)
        .map_err(|e| broken(format!("its signature is not valid base64: {e}")))?;

    previous
        .key
        .verify(&endorsement.signing_bytes(), &signature)
        .map_err(|_| {
            broken(format!(
                "its signature does not verify under {}",
                previous.key_id
            ))
        })
}

impl Verifier for PinnedKeys {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        Self::verify(self, message, signature).map(|_| ())
    }

    fn pinned_key(&self) -> Result<OrgPublicKey> {
        self.keys
            .iter()
            .find(|k| matches!(k.status, SigningKeyStatus::Active))
            .map(|k| k.key.clone())
            .ok_or(CryptoError::NotPinned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use updawg_protocol::SigningKeyId;

    /* ---------------------------------------------------------- verify_job */

    fn signed_job(key: &TestOrgKey, key_id: &str) -> updawg_protocol::Job {
        use base64::Engine as _;
        use updawg_protocol::job::{ApplyUpdates, JobSpec, PackagePin};
        let mut job = updawg_protocol::Job {
            id: updawg_protocol::JobId::new("job_0190a0de000070008000000000000001"),
            host_id: updawg_protocol::HostId::new("hst_0190a0de000070008000000000000002"),
            spec: JobSpec::ApplyUpdates(ApplyUpdates {
                packages: vec![PackagePin {
                    name: "openssl".into(),
                    arch: "amd64".into(),
                    from: "3.5.1-1".into(),
                    to: "3.5.1-2".into(),
                }],
                ..ApplyUpdates::default()
            }),
            not_before: None,
            expires_at: "2099-01-01T00:00:00Z".parse().unwrap(),
            key_id: SigningKeyId::new(key_id),
            signature: String::new(),
        };
        job.signature = base64::engine::general_purpose::STANDARD
            .encode(key.sign(&job.signing_bytes().unwrap()));
        job
    }

    #[test]
    fn a_job_signed_by_a_pinned_key_that_it_names_verifies() {
        let key = TestOrgKey::new();
        let keys = pinned(&[("sk_a", &key, SigningKeyStatus::Active)]);
        keys.verify_job(&signed_job(&key, "sk_a"))
            .expect("verifies");
    }

    #[test]
    fn an_edited_job_does_not_verify() {
        let key = TestOrgKey::new();
        let keys = pinned(&[("sk_a", &key, SigningKeyStatus::Active)]);
        let mut job = signed_job(&key, "sk_a");
        if let updawg_protocol::job::JobSpec::ApplyUpdates(ref mut p) = job.spec {
            p.packages[0].to = "3.5.1-99".into();
        }
        assert!(matches!(
            keys.verify_job(&job),
            Err(CryptoError::BadSignature)
        ));
    }

    #[test]
    fn a_job_naming_another_key_than_the_one_that_signed_it_is_refused() {
        let (a, b) = (TestOrgKey::new(), TestOrgKey::new());
        let keys = pinned(&[
            ("sk_a", &a, SigningKeyStatus::Active),
            ("sk_b", &b, SigningKeyStatus::Retiring),
        ]);
        // key_id is in the signed bytes, so only a lying signer can get here
        let job = signed_job(&a, "sk_b");
        assert!(matches!(
            keys.verify_job(&job),
            Err(CryptoError::WrongKey { .. })
        ));
    }

    #[test]
    fn a_job_signed_by_a_retired_key_or_an_unknown_one_is_refused() {
        let (a, b, stranger) = (TestOrgKey::new(), TestOrgKey::new(), TestOrgKey::new());
        // a set with no active key can't be pinned
        let keys = pinned(&[
            ("sk_a", &a, SigningKeyStatus::Retired),
            ("sk_b", &b, SigningKeyStatus::Active),
        ]);
        assert!(matches!(
            keys.verify_job(&signed_job(&a, "sk_a")),
            Err(CryptoError::KeyRetired { .. })
        ));
        let keys = pinned(&[("sk_a", &a, SigningKeyStatus::Active)]);
        assert!(matches!(
            keys.verify_job(&signed_job(&stranger, "sk_a")),
            Err(CryptoError::BadSignature)
        ));
        let mut job = signed_job(&a, "sk_a");
        job.signature = "not base64!".into();
        assert!(matches!(
            keys.verify_job(&job),
            Err(CryptoError::BadSignature)
        ));
    }

    struct TestOrgKey {
        pair: aws_lc_rs::signature::Ed25519KeyPair,
        wire: String,
    }

    impl TestOrgKey {
        fn new() -> Self {
            use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
            use base64::Engine as _;

            let rng = aws_lc_rs::rand::SystemRandom::new();
            let doc = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();

            let mut der = ED25519_SPKI_PREFIX.to_vec();
            der.extend_from_slice(pair.public_key().as_ref());
            let wire = format!(
                "ed25519:{}",
                base64::engine::general_purpose::STANDARD.encode(der)
            );
            Self { pair, wire }
        }

        fn sign(&self, message: &[u8]) -> Vec<u8> {
            self.pair.sign(message).as_ref().to_vec()
        }

        fn endorse(
            &self,
            my_id: &str,
            new_id: &str,
            new_key: &TestOrgKey,
        ) -> updawg_protocol::Endorsement {
            use base64::Engine as _;
            let statement = updawg_protocol::EndorsementStatement {
                org_id: updawg_protocol::OrgId::new("org_test"),
                issued_at: "2026-09-24T11:00:00Z".parse().unwrap(),
                previous_key: updawg_protocol::EndorsedKey {
                    key_id: SigningKeyId::new(my_id),
                    public_key: self.wire.clone(),
                },
                new_key: updawg_protocol::EndorsedKey {
                    key_id: SigningKeyId::new(new_id),
                    public_key: new_key.wire.clone(),
                },
            };
            let signature = self.sign(&statement.signing_bytes().unwrap());
            updawg_protocol::Endorsement::new(
                &statement,
                base64::engine::general_purpose::STANDARD.encode(signature),
            )
            .unwrap()
        }
    }

    fn pinned(keys: &[(&str, &TestOrgKey, SigningKeyStatus)]) -> PinnedKeys {
        PinnedKeys::from_wire(
            &keys
                .iter()
                .map(|(id, k, status)| offered(id, &k.wire, *status))
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn offered(id: &str, wire: &str, status: SigningKeyStatus) -> OrgSigningKey {
        OrgSigningKey {
            key_id: SigningKeyId::new(id),
            public_key: wire.to_string(),
            status,
            endorsement: None,
        }
    }

    // ---- rotation ----

    #[test]
    fn an_endorsed_new_key_is_adopted() {
        let old = TestOrgKey::new();
        let new = TestOrgKey::new();
        let host = pinned(&[("sk_old", &old, SigningKeyStatus::Active)]);

        let mut new_wire = offered("sk_new", &new.wire, SigningKeyStatus::Active);
        new_wire.endorsement = Some(old.endorse("sk_old", "sk_new", &new));

        let adopted = host
            .adopt(&[
                offered("sk_old", &old.wire, SigningKeyStatus::Retiring),
                new_wire,
            ])
            .unwrap();

        assert_eq!(adopted.usable().len(), 2);
        assert!(adopted.contains("sk_new", &OrgPublicKey::parse("sk_new", &new.wire).unwrap()));
    }

    #[test]
    fn an_unendorsed_new_key_is_refused() {
        let old = TestOrgKey::new();
        let new = TestOrgKey::new();
        let host = pinned(&[("sk_old", &old, SigningKeyStatus::Active)]);

        let err = host
            .adopt(&[
                offered("sk_old", &old.wire, SigningKeyStatus::Active),
                offered("sk_new", &new.wire, SigningKeyStatus::Active),
            ])
            .unwrap_err();

        assert!(matches!(err, CryptoError::UnendorsedKey { ref key_id } if key_id == "sk_new"));
    }

    /// A compromised server endorsing its own key with another key it made.
    #[test]
    fn an_endorsement_by_a_key_this_host_does_not_hold_is_refused() {
        let old = TestOrgKey::new();
        let stranger = TestOrgKey::new();
        let new = TestOrgKey::new();
        let host = pinned(&[("sk_old", &old, SigningKeyStatus::Active)]);

        let mut new_wire = offered("sk_new", &new.wire, SigningKeyStatus::Active);
        new_wire.endorsement = Some(stranger.endorse("sk_stranger", "sk_new", &new));

        let err = host
            .adopt(&[
                offered("sk_old", &old.wire, SigningKeyStatus::Active),
                new_wire,
            ])
            .unwrap_err();
        assert!(matches!(err, CryptoError::BrokenEndorsement { .. }));
        assert!(err.to_string().contains("sk_stranger"));
    }

    /// Cross-tenant replay: a valid endorsement made by another org's key.
    #[test]
    fn an_endorsement_from_another_organization_does_not_transfer() {
        let ours = TestOrgKey::new();
        let theirs = TestOrgKey::new();
        let new = TestOrgKey::new();
        let host = pinned(&[("sk_ours", &ours, SigningKeyStatus::Active)]);

        let mut new_wire = offered("sk_new", &new.wire, SigningKeyStatus::Active);
        new_wire.endorsement = Some(theirs.endorse("sk_theirs", "sk_new", &new));

        assert!(
            host.adopt(&[
                offered("sk_ours", &ours.wire, SigningKeyStatus::Active),
                new_wire
            ])
            .is_err()
        );
    }

    /// Genuine endorsement of the right id, but different material offered
    /// under it.
    #[test]
    fn an_endorsement_of_a_different_key_than_the_one_offered_is_refused() {
        let old = TestOrgKey::new();
        let endorsed = TestOrgKey::new();
        let substituted = TestOrgKey::new();
        let host = pinned(&[("sk_old", &old, SigningKeyStatus::Active)]);

        let mut new_wire = offered("sk_new", &substituted.wire, SigningKeyStatus::Active);
        new_wire.endorsement = Some(old.endorse("sk_old", "sk_new", &endorsed));

        let err = host
            .adopt(&[
                offered("sk_old", &old.wire, SigningKeyStatus::Active),
                new_wire,
            ])
            .unwrap_err();
        assert!(err.to_string().contains("different key material"));
    }

    #[test]
    fn a_retired_key_cannot_endorse() {
        let retired = TestOrgKey::new();
        let active = TestOrgKey::new();
        let new = TestOrgKey::new();
        let host = pinned(&[
            ("sk_retired", &retired, SigningKeyStatus::Retired),
            ("sk_active", &active, SigningKeyStatus::Active),
        ]);

        let mut new_wire = offered("sk_new", &new.wire, SigningKeyStatus::Active);
        new_wire.endorsement = Some(retired.endorse("sk_retired", "sk_new", &new));

        let err = host
            .adopt(&[
                offered("sk_retired", &retired.wire, SigningKeyStatus::Retired),
                offered("sk_active", &active.wire, SigningKeyStatus::Active),
                new_wire,
            ])
            .unwrap_err();
        assert!(err.to_string().contains("active or retiring"));
    }

    #[test]
    fn a_pinned_key_may_be_narrowed_without_an_endorsement() {
        let key = TestOrgKey::new();
        let other = TestOrgKey::new();
        let host = pinned(&[
            ("sk_a", &key, SigningKeyStatus::Active),
            ("sk_b", &other, SigningKeyStatus::Active),
        ]);

        let adopted = host
            .adopt(&[
                offered("sk_a", &key.wire, SigningKeyStatus::Retiring),
                offered("sk_b", &other.wire, SigningKeyStatus::Active),
            ])
            .unwrap();
        assert_eq!(adopted.usable().len(), 2);

        let adopted = host
            .adopt(&[
                offered("sk_a", &key.wire, SigningKeyStatus::Retired),
                offered("sk_b", &other.wire, SigningKeyStatus::Active),
            ])
            .unwrap();
        assert_eq!(adopted.usable().len(), 1);
    }

    #[test]
    fn a_retired_key_cannot_be_promoted_back() {
        let key = TestOrgKey::new();
        let other = TestOrgKey::new();
        let host = pinned(&[
            ("sk_a", &key, SigningKeyStatus::Retired),
            ("sk_b", &other, SigningKeyStatus::Active),
        ]);

        let err = host
            .adopt(&[
                offered("sk_a", &key.wire, SigningKeyStatus::Active),
                offered("sk_b", &other.wire, SigningKeyStatus::Active),
            ])
            .unwrap_err();
        assert!(matches!(
            err,
            CryptoError::KeyStatusRegressed { ref key_id, .. } if key_id == "sk_a"
        ));
    }

    #[test]
    fn the_material_under_a_pinned_id_may_not_change() {
        let key = TestOrgKey::new();
        let impostor = TestOrgKey::new();
        let host = pinned(&[("sk_a", &key, SigningKeyStatus::Active)]);

        let err = host
            .adopt(&[offered("sk_a", &impostor.wire, SigningKeyStatus::Active)])
            .unwrap_err();
        assert!(matches!(
            err,
            CryptoError::KeyMaterialChanged { ref key_id } if key_id == "sk_a"
        ));
    }

    /// A host that missed two rotations. The links are deliberately out of
    /// order; nothing requires the server to sort them.
    #[test]
    fn a_chain_of_any_length_is_followed_whatever_order_it_arrives_in() {
        let a = TestOrgKey::new();
        let b = TestOrgKey::new();
        let c = TestOrgKey::new();
        let host = pinned(&[("sk_a", &a, SigningKeyStatus::Active)]);

        let mut c_wire = offered("sk_c", &c.wire, SigningKeyStatus::Active);
        c_wire.endorsement = Some(b.endorse("sk_b", "sk_c", &c));
        let mut b_wire = offered("sk_b", &b.wire, SigningKeyStatus::Retiring);
        b_wire.endorsement = Some(a.endorse("sk_a", "sk_b", &b));

        let adopted = host
            .adopt(&[
                c_wire,
                offered("sk_a", &a.wire, SigningKeyStatus::Retired),
                b_wire,
            ])
            .unwrap();
        assert_eq!(adopted.usable().len(), 2);
    }

    /// Endorsement rights come from the status this host already holds, not
    /// the one in the message. Using the offered status made the result
    /// depend on evaluation order.
    #[test]
    fn a_key_endorses_at_the_status_this_host_holds_it_at() {
        let old = TestOrgKey::new();
        let new = TestOrgKey::new();

        // retired in the same message it endorses in: still active here
        let host = pinned(&[("sk_old", &old, SigningKeyStatus::Active)]);
        let mut new_wire = offered("sk_new", &new.wire, SigningKeyStatus::Active);
        new_wire.endorsement = Some(old.endorse("sk_old", "sk_new", &new));
        assert!(
            host.adopt(&[
                offered("sk_old", &old.wire, SigningKeyStatus::Retired),
                new_wire,
            ])
            .is_ok()
        );

        // held as retired, offered as active: rejected as a promotion
        let other = TestOrgKey::new();
        let host = pinned(&[
            ("sk_old", &old, SigningKeyStatus::Retired),
            ("sk_live", &other, SigningKeyStatus::Active),
        ]);
        let mut new_wire = offered("sk_new", &new.wire, SigningKeyStatus::Active);
        new_wire.endorsement = Some(old.endorse("sk_old", "sk_new", &new));
        assert!(
            host.adopt(&[
                offered("sk_old", &old.wire, SigningKeyStatus::Active),
                offered("sk_live", &other.wire, SigningKeyStatus::Active),
                new_wire,
            ])
            .is_err()
        );
    }

    // ---- customer-held keys ----

    fn anchor(key: &TestOrgKey) -> OrgPublicKey {
        OrgPublicKey::parse("anchor", &key.wire).unwrap()
    }

    #[test]
    fn an_anchored_enrollment_pins_the_customers_key() {
        let updawg = TestOrgKey::new();
        let customer = TestOrgKey::new();
        let mut customer_wire = offered("sk_customer", &customer.wire, SigningKeyStatus::Active);
        customer_wire.endorsement = Some(updawg.endorse("sk_updawg", "sk_customer", &customer));

        let keys = PinnedKeys::anchored(
            &anchor(&customer),
            &[
                customer_wire,
                offered("sk_updawg", &updawg.wire, SigningKeyStatus::Retired),
            ],
        )
        .unwrap();

        assert_eq!(keys.usable().len(), 1);
        keys.verify_job(&signed_job(&customer, "sk_customer"))
            .expect("the customer's own signature verifies");
        assert!(matches!(
            keys.verify_job(&signed_job(&updawg, "sk_updawg")),
            Err(CryptoError::KeyRetired { .. })
        ));
    }

    #[test]
    fn an_anchored_enrollment_refuses_a_key_the_customer_did_not_endorse() {
        let customer = TestOrgKey::new();
        let server = TestOrgKey::new();

        let err = PinnedKeys::anchored(
            &anchor(&customer),
            &[offered("sk_server", &server.wire, SigningKeyStatus::Active)],
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::AnchorNotOffered { .. }), "{err}");

        // alongside the customer's key, as the active one
        let err = PinnedKeys::anchored(
            &anchor(&customer),
            &[
                offered("sk_customer", &customer.wire, SigningKeyStatus::Retiring),
                offered("sk_server", &server.wire, SigningKeyStatus::Active),
            ],
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::UnendorsedKey { .. }), "{err}");

        // self-endorsed
        let mut endorsed = offered("sk_server", &server.wire, SigningKeyStatus::Active);
        endorsed.endorsement = Some(server.endorse("sk_server", "sk_server", &server));
        assert!(
            PinnedKeys::anchored(
                &anchor(&customer),
                &[
                    offered("sk_customer", &customer.wire, SigningKeyStatus::Retiring),
                    endorsed,
                ],
            )
            .is_err()
        );
    }

    /// The customer rotated after this host's config was written.
    #[test]
    fn an_anchor_the_customer_rotated_away_from_still_leads_to_its_successor() {
        let first = TestOrgKey::new();
        let second = TestOrgKey::new();
        let mut second_wire = offered("sk_second", &second.wire, SigningKeyStatus::Active);
        second_wire.endorsement = Some(first.endorse("sk_first", "sk_second", &second));

        let keys = PinnedKeys::anchored(
            &anchor(&first),
            &[
                offered("sk_first", &first.wire, SigningKeyStatus::Retired),
                second_wire,
            ],
        )
        .unwrap();
        keys.verify_job(&signed_job(&second, "sk_second"))
            .expect("the successor verifies");
        assert!(matches!(
            keys.verify_job(&signed_job(&first, "sk_first")),
            Err(CryptoError::KeyRetired { .. })
        ));
    }

    #[test]
    fn an_unknown_retired_key_is_pinned_as_revoked_and_endorses_nothing() {
        let current = TestOrgKey::new();
        let old = TestOrgKey::new();
        let sneaky = TestOrgKey::new();
        let host = pinned(&[("sk_current", &current, SigningKeyStatus::Active)]);

        let keys = host
            .adopt(&[
                offered("sk_current", &current.wire, SigningKeyStatus::Active),
                offered("sk_old", &old.wire, SigningKeyStatus::Retired),
            ])
            .unwrap();
        assert!(matches!(
            keys.verify_job(&signed_job(&old, "sk_old")),
            Err(CryptoError::KeyRetired { .. })
        ));

        let mut sneaky_wire = offered("sk_sneaky", &sneaky.wire, SigningKeyStatus::Active);
        sneaky_wire.endorsement = Some(old.endorse("sk_old", "sk_sneaky", &sneaky));
        assert!(
            host.adopt(&[
                offered("sk_current", &current.wire, SigningKeyStatus::Active),
                offered("sk_old", &old.wire, SigningKeyStatus::Retired),
                sneaky_wire,
            ])
            .is_err(),
            "a retired key adopted in the same breath must not endorse"
        );
    }

    #[test]
    fn a_configured_key_parses_with_or_without_its_prefix() {
        let key = TestOrgKey::new();
        let bare = key.wire.strip_prefix("ed25519:").unwrap();
        assert_eq!(
            OrgPublicKey::parse_configured("trusted_org_key", bare).unwrap(),
            OrgPublicKey::parse_configured("trusted_org_key", &format!(" {} ", key.wire)).unwrap(),
        );
        assert!(OrgPublicKey::parse_configured("trusted_org_key", "bm90IGEga2V5").is_err());
    }

    #[test]
    fn one_bad_key_rejects_the_whole_set() {
        let old = TestOrgKey::new();
        let good = TestOrgKey::new();
        let bad = TestOrgKey::new();
        let host = pinned(&[("sk_old", &old, SigningKeyStatus::Active)]);

        let mut good_wire = offered("sk_good", &good.wire, SigningKeyStatus::Active);
        good_wire.endorsement = Some(old.endorse("sk_old", "sk_good", &good));

        assert!(
            host.adopt(&[
                offered("sk_old", &old.wire, SigningKeyStatus::Active),
                good_wire,
                offered("sk_bad", &bad.wire, SigningKeyStatus::Active),
            ])
            .is_err(),
            "the good key must not be adopted alongside a bad one"
        );
    }

    #[test]
    fn an_endorsement_signed_over_something_else_is_refused() {
        use base64::Engine as _;
        let old = TestOrgKey::new();
        let new = TestOrgKey::new();
        let host = pinned(&[("sk_old", &old, SigningKeyStatus::Active)]);

        let mut endorsement = old.endorse("sk_old", "sk_new", &new);
        endorsement.signature = base64::engine::general_purpose::STANDARD
            .encode(old.sign(b"updawg-endorsement-v1\0something else entirely"));

        let mut new_wire = offered("sk_new", &new.wire, SigningKeyStatus::Active);
        new_wire.endorsement = Some(endorsement);

        let err = host
            .adopt(&[
                offered("sk_old", &old.wire, SigningKeyStatus::Active),
                new_wire,
            ])
            .unwrap_err();
        assert!(err.to_string().contains("does not verify"));
    }

    /// Without the domain-separation prefix, any signature the signer made
    /// over attacker-chosen bytes could pass as an endorsement.
    #[test]
    fn an_endorsement_signed_without_the_purpose_label_is_refused() {
        use base64::Engine as _;
        let old = TestOrgKey::new();
        let new = TestOrgKey::new();
        let host = pinned(&[("sk_old", &old, SigningKeyStatus::Active)]);

        let mut endorsement = old.endorse("sk_old", "sk_new", &new);
        endorsement.signature = base64::engine::general_purpose::STANDARD
            .encode(old.sign(endorsement.statement.as_bytes()));

        let mut new_wire = offered("sk_new", &new.wire, SigningKeyStatus::Active);
        new_wire.endorsement = Some(endorsement);

        assert!(
            host.adopt(&[
                offered("sk_old", &old.wire, SigningKeyStatus::Active),
                new_wire
            ])
            .is_err()
        );
    }

    #[test]
    fn every_refusal_names_the_key_it_is_about() {
        let old = TestOrgKey::new();
        let new = TestOrgKey::new();
        let host = pinned(&[("sk_old", &old, SigningKeyStatus::Active)]);

        let err = host
            .adopt(&[
                offered("sk_old", &old.wire, SigningKeyStatus::Active),
                offered("sk_troublesome", &new.wire, SigningKeyStatus::Active),
            ])
            .unwrap_err();
        assert!(
            err.to_string().contains("sk_troublesome"),
            "unhelpful: {err}"
        );
    }

    #[test]
    fn debug_output_never_contains_raw_key_bytes() {
        let key = OrgPublicKey::from_bytes(vec![0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6]);
        let rendered = format!("{key:?}");
        assert!(rendered.contains("de:ad:be:ef"));
        assert!(
            !rendered.contains("[222"),
            "raw bytes leaked into Debug output"
        );
    }

    #[test]
    fn a_wire_key_round_trips() {
        let org = TestOrgKey::new();
        let parsed = OrgPublicKey::parse("sk_1", &org.wire).unwrap();
        assert_eq!(parsed.as_bytes().len(), ED25519_KEY_LEN);
        assert_eq!(parsed.to_wire(), org.wire);
    }

    #[test]
    fn a_real_signature_verifies_and_a_tampered_message_does_not() {
        let org = TestOrgKey::new();
        let key = OrgPublicKey::parse("sk_1", &org.wire).unwrap();
        let sig = org.sign(b"job envelope");

        key.verify(b"job envelope", &sig).unwrap();
        let err = key.verify(b"job envelopf", &sig).unwrap_err();
        assert!(matches!(err, CryptoError::BadSignature));
    }

    #[test]
    fn malformed_keys_are_rejected_with_the_reason() {
        let org = TestOrgKey::new();
        let body = org.wire.strip_prefix("ed25519:").unwrap();

        for (encoded, why) in [
            (body.to_string(), "missing algorithm prefix"),
            ("ed25519:not base64!!".to_string(), "not base64"),
            ("ed25519:AAAA".to_string(), "too short"),
            // right length, wrong algorithm OID
            (
                {
                    use base64::Engine as _;
                    let mut der = vec![
                        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x86, 0x48, 0x03, 0x21, 0x00,
                    ];
                    der.extend_from_slice(&[7u8; 32]);
                    format!(
                        "ed25519:{}",
                        base64::engine::general_purpose::STANDARD.encode(der)
                    )
                },
                "wrong algorithm OID",
            ),
        ] {
            let err = OrgPublicKey::parse("sk_1", &encoded).unwrap_err();
            assert!(
                matches!(err, CryptoError::MalformedOrgKey { .. }),
                "{why}: got {err:?}"
            );
        }
    }

    #[test]
    fn a_response_with_no_active_key_is_not_pinnable() {
        let org = TestOrgKey::new();
        let err = PinnedKeys::from_wire(&[offered("sk_1", &org.wire, SigningKeyStatus::Retiring)])
            .unwrap_err();
        assert!(matches!(err, CryptoError::NoUsableOrgKey), "got {err:?}");
    }

    #[test]
    fn one_malformed_key_rejects_the_whole_set() {
        let org = TestOrgKey::new();
        let err = PinnedKeys::from_wire(&[
            offered("sk_1", &org.wire, SigningKeyStatus::Active),
            offered("sk_2", "ed25519:zzzz", SigningKeyStatus::Active),
        ])
        .unwrap_err();
        assert!(
            matches!(err, CryptoError::MalformedOrgKey { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_retiring_key_still_verifies_during_a_rotation() {
        let old = TestOrgKey::new();
        let new = TestOrgKey::new();
        let pinned = PinnedKeys::from_wire(&[
            offered("sk_old", &old.wire, SigningKeyStatus::Retiring),
            offered("sk_new", &new.wire, SigningKeyStatus::Active),
        ])
        .unwrap();

        assert_eq!(pinned.verify(b"job", &old.sign(b"job")).unwrap(), "sk_old");
        assert_eq!(pinned.verify(b"job", &new.sign(b"job")).unwrap(), "sk_new");
    }

    #[test]
    fn a_retired_key_fails_as_revoked_rather_than_as_unknown() {
        let retired = TestOrgKey::new();
        let active = TestOrgKey::new();
        let pinned = PinnedKeys::from_wire(&[
            offered("sk_gone", &retired.wire, SigningKeyStatus::Retired),
            offered("sk_now", &active.wire, SigningKeyStatus::Active),
        ])
        .unwrap();

        let err = pinned.verify(b"job", &retired.sign(b"job")).unwrap_err();
        assert!(
            matches!(err, CryptoError::KeyRetired { ref key_id } if key_id == "sk_gone"),
            "got {err:?}"
        );
    }

    #[test]
    fn a_signature_from_an_unpinned_key_is_refused() {
        let pinned_org = TestOrgKey::new();
        let stranger = TestOrgKey::new();
        let pinned =
            PinnedKeys::from_wire(&[offered("sk_1", &pinned_org.wire, SigningKeyStatus::Active)])
                .unwrap();

        let err = pinned.verify(b"job", &stranger.sign(b"job")).unwrap_err();
        assert!(matches!(err, CryptoError::BadSignature), "got {err:?}");
    }
}

/// SHA-256 of `bytes` as `sha256:<hex>`. The prefix lets the algorithm change
/// later without ambiguity.
///
/// Uses `aws-lc-rs` so the binary has a single crypto backend.
#[must_use]
pub fn content_hash(bytes: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    let mut out = String::with_capacity(7 + digest.as_ref().len() * 2);
    out.push_str("sha256:");
    for b in digest.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod content_hash_tests {
    use super::content_hash;

    #[test]
    fn it_is_sha256_and_says_so() {
        assert_eq!(
            content_hash(b""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn different_content_hashes_differently() {
        assert_ne!(content_hash(b"a"), content_hash(b"b"));
        assert_eq!(content_hash(b"a"), content_hash(b"a"));
    }
}
