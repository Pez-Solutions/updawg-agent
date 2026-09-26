//! Signature verification, key pinning and CSR generation.
//!
//! The agent generates its key pair locally and the private key never leaves
//! the host. The organization's signing key is pinned at enrollment, and every
//! job is verified against that pinned key rather than against whatever the
//! server currently claims.
//!
//! Key rotation works by the old key endorsing the new one, so an agent can
//! follow a rotation without having to trust the server blindly. That is the
//! whole reason rotation is not simply "the server says use this key now", and
//! it is [`PinnedKeys::adopt`] that makes it so — until DAWG-99 the agent
//! pinned whatever the server offered, and the sentence above was true of the
//! design and of nothing in the code.
//!
//! Scope note: DAWG-19 defines the surface. DAWG-30 implements key generation,
//! CSRs and pinning, DAWG-31 the certificate lifecycle, DAWG-99 rotation
//! following.

pub mod cert;
pub mod key;

use std::fmt;
use updawg_protocol::{OrgSigningKey, SigningKeyStatus};

pub use cert::ClientCertificate;
pub use key::AgentKey;

/// DER header of an Ed25519 `SubjectPublicKeyInfo`, ahead of the 32 key bytes.
///
/// `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING }`. Checking it is how
/// a base64 blob that happens to decode to 44 bytes is told apart from an
/// actual Ed25519 key.
pub const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Length of a raw Ed25519 public key.
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

/// An Ed25519 public key belonging to an organization.
///
/// Held as the raw 32 bytes. Parsing happens once, at the moment the key is
/// pinned, so a malformed key is rejected before it reaches local state rather
/// than every time a job arrives.
#[derive(Clone, PartialEq, Eq)]
pub struct OrgPublicKey(Vec<u8>);

impl OrgPublicKey {
    /// Parse the wire form: `ed25519:` followed by base64 SPKI.
    ///
    /// # Errors
    /// [`CryptoError::MalformedOrgKey`] if the prefix, the base64 or the DER
    /// structure is wrong. Being strict here is the point — this value decides
    /// what the host will execute for the rest of its life.
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

    /// Encode back to the wire form, so what was pinned can be shown.
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

    /// Short fingerprint for display and for logs.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        fingerprint_bytes(&self.0)
    }

    /// Verify a detached signature over `message`.
    ///
    /// # Errors
    /// [`CryptoError::BadSignature`] if it does not verify.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
        UnparsedPublicKey::new(&ED25519, &self.0)
            .verify(message, signature)
            .map_err(|_| CryptoError::BadSignature)
    }
}

// Never print key material, even by accident in a debug log line.
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

/// The organization keys this host pinned, and what it will accept from them.
///
/// `active` and `retiring` both verify: a rotation is not instantaneous, and a
/// job signed moments before the cut-over must still be executable. `retired`
/// is kept rather than dropped so that a job signed by a revoked key fails as
/// *revoked* rather than as *unknown* — the two call for very different
/// reactions from whoever reads the log line.
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
    /// Parse and validate the set of keys the server offered.
    ///
    /// # Errors
    /// Fails if any key is malformed, or if none of them can sign anything.
    /// A response that pins nothing usable is a response to reject, not to
    /// store and discover at the first job.
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

    /// Whether this set still contains the given key with the same bytes.
    #[must_use]
    pub fn contains(&self, key_id: &str, key: &OrgPublicKey) -> bool {
        self.keys
            .iter()
            .any(|k| k.key_id == key_id && &k.key == key)
    }

    /// The keys that are still allowed to sign new work.
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

    /// Follow a rotation: take the offered set, given what this host already
    /// trusts.
    ///
    /// This is the method that makes *"an agent never has to take the server's
    /// word for a new key"* true rather than aspirational. Before DAWG-99 the
    /// agent pinned whatever arrived, which is exactly the blind trust the
    /// design says it does not require.
    ///
    /// The rules are [ADR 0002] §3:
    ///
    /// - A key **already pinned, with the same material**, is kept. Its status
    ///   may move `active` → `retiring` → `retired` without an endorsement,
    ///   because every step in that direction *reduces* what this host will
    ///   accept. It may never move back.
    /// - A key **not already pinned** needs an endorsement that verifies under
    ///   a key this host currently holds as `active` or `retiring`, and whose
    ///   statement names this key by **material as well as by id**.
    /// - ⚠️ If any offered key fails, **the whole set is rejected** and the
    ///   caller keeps what it had. Partially adopting a key set is how a host
    ///   ends up trusting half of a rotation, and a renewal is not a moment an
    ///   operator is watching.
    ///
    /// Chains of any length work, as long as every link is offered: a key
    /// adopted in one pass can endorse another in the next.
    ///
    /// # ⚠️ Where the cross-tenant check actually happens
    ///
    /// The statement binds `org_id`, and this method never reads it — because
    /// it does not have to and could not do better if it tried. An endorsement
    /// produced in another organization is signed by **that** organization's
    /// key, which this host does not hold, so it fails the chain check first.
    /// `org_id` is what stops the signature being *reused* somewhere the chain
    /// would otherwise line up; it is not a second check this host can make
    /// against an org id it was never told.
    ///
    /// # Errors
    /// Every failure names the key, because the operator reading it has a fleet
    /// that has just refused a key change and needs to know which one.
    ///
    /// [ADR 0002]: https://github.com/Pez-Solutions/updawg-docs/blob/main/decisions/0002-signing-key-rotation-endorsements.md
    pub fn adopt(&self, offered: &[OrgSigningKey]) -> Result<Self> {
        let parsed = Self::from_wire(offered)?;

        // What the result will be.
        let mut trusted: Vec<PinnedKey> = Vec::with_capacity(parsed.keys.len());
        let mut pending: Vec<(&PinnedKey, &OrgSigningKey)> = Vec::new();

        // ⚠️ Who may endorse, which is **not** the same list. A key already
        // pinned counts at the status this host currently holds it at, not at
        // the status the same message offers — otherwise a server could retire
        // a key and use it to endorse its successor in one breath, and whether
        // that worked would depend on the order the two were evaluated in.
        // Keys adopted during this call join at their offered status, which is
        // what makes a chain of any length work.
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
                None => pending.push((key, wire)),
            }
        }

        // Fixed point rather than one pass: an endorsement may chain from a key
        // that is itself new in this same set.
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
                // Nothing moved, so nothing ever will. Report the first
                // failure properly rather than "no progress".
                let (key, wire) = still_pending[0];
                endorsed_by(&authority, key, wire)?;
                unreachable!("endorsed_by returned Ok on a key that did not move");
            }
            pending = still_pending;
        }

        Ok(Self { keys: trusted })
    }

    /// Verify a job: its signature, over [`updawg_protocol::Job::signing_bytes`],
    /// under a pinned key that may still sign — **and** that key is the one the
    /// job names. A job naming one key and verifying under another is a job
    /// somebody has edited, and is refused as one.
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

    /// Verify a signature against the pinned set.
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

/// How much a status lets a key do. Lower is more.
///
/// The ordering is the whole rule: a status may only ever move *up* this scale.
/// `active` → `retiring` → `retired` each narrows what the host will accept, so
/// a server can do it unilaterally; going the other way widens it, which is a
/// thing only an endorsement may do.
const fn trust_rank(status: SigningKeyStatus) -> u8 {
    match status {
        SigningKeyStatus::Active => 0,
        SigningKeyStatus::Retiring => 1,
        SigningKeyStatus::Retired => 2,
    }
}

/// Whether `key`'s endorsement chains back to something in `trusted`.
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

    // The endorsement must be about *this* key, by material as well as by id.
    // An endorsement that named only an id would leave the server free to
    // choose which bytes that id refers to.
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

    // And it must be made by a key this host holds and still accepts, matched
    // by material and id together.
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

    /// ⚠️ The attack the signature exists for: one version edited in flight.
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
        // Signed with a's key, claiming b's id — with the id in the signed
        // bytes, so this is only reachable by a signer that lied.
        let job = signed_job(&a, "sk_b");
        assert!(matches!(
            keys.verify_job(&job),
            Err(CryptoError::WrongKey { .. })
        ));
    }

    #[test]
    fn a_job_signed_by_a_retired_key_or_an_unknown_one_is_refused() {
        let (a, b, stranger) = (TestOrgKey::new(), TestOrgKey::new(), TestOrgKey::new());
        // A set of only retired keys is refused when pinned, so pin a live one
        // beside it.
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

    /// A throwaway organization key pair, so the tests sign with real Ed25519
    /// rather than asserting against a fixture that could drift.
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

        /// Endorse `new_key`, the way the signer will.
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

    /// The set a host has already pinned.
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

    // ---- Following a rotation (DAWG-99, ADR 0002 §3) ----

    /// The happy path, and the sentence the design makes: a key this host has
    /// never seen is adopted **because** the key it already trusts vouched for
    /// it, not because the server sent it.
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

    /// ⚠️ The behaviour this ticket exists to change. Before DAWG-99 the agent
    /// pinned whatever arrived; an unendorsed new key is the whole attack.
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

    /// Attack (1): a compromised API mints a key and endorses it with a key of
    /// its own. It verifies perfectly — under a key this host has never held.
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

    /// Attack (2), the cross-tenant replay, from the agent's side: another
    /// organization's endorsement of this very key is a real endorsement,
    /// correctly signed, and fails because the key that made it is not one this
    /// host holds. `org_id` is what stops it being reusable; the chain is what
    /// this host checks.
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

    /// Attack (4): the endorsement is genuine, made by a key this host trusts,
    /// and names the right id — but the material offered under that id is
    /// somebody else's. An endorsement that covered only the id would accept
    /// this.
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

    /// Attack (3): an endorsement of a key since revoked must not re-verify for
    /// ever. A retired key cannot endorse, which is what breaks the loop.
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

    /// Narrowing needs no endorsement, because it only ever removes trust.
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

    /// ⚠️ And widening does not. A server that could promote a retired key back
    /// to active would have an undo button on a revocation, which is the one
    /// thing revocation must not have.
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

    /// Same id, different bytes. Not a rotation — a substitution, and it is
    /// caught before anything looks for an endorsement.
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

    /// A host that has been off for two rotations. Every link is offered, so
    /// the chain is followable however long it is — and the links arrive in the
    /// wrong order here on purpose, because a server has no reason to sort them.
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

    /// ⚠️ Found by the chain test above failing for the wrong reason. Who may
    /// endorse is decided by the status this host **currently holds**, not by
    /// the status the same message offers — so a key retired in this very
    /// message can still be the root of the chain, and a key *promoted* in this
    /// very message cannot. Reading the offered status instead would make the
    /// answer depend on the order the keys were evaluated in.
    #[test]
    fn a_key_endorses_at_the_status_this_host_holds_it_at() {
        let old = TestOrgKey::new();
        let new = TestOrgKey::new();

        // Retired in the same message it endorses in: still allowed, because
        // this host holds it as active until this set is applied.
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

        // And the other direction, which is the one that matters: a key this
        // host holds as retired does not become an endorser by being offered as
        // active. It is refused as a promotion before it gets that far.
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

    /// ⚠️ All or nothing. A host that adopted the keys that checked out and
    /// dropped the one that did not would be trusting half a rotation, silently.
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

    /// The signature has to be checked, not merely present and well-formed.
    /// This endorsement names all the right keys and is signed over the wrong
    /// bytes.
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

    /// ⚠️ The label, from the agent's side. An endorsement whose signature was
    /// made over the statement *without* the purpose prefix must not verify —
    /// otherwise anything that gets the signer to sign attacker-chosen bytes
    /// for some other purpose has produced an endorsement.
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

    /// The error is read by somebody whose fleet has just stopped following a
    /// rotation. It has to name the key.
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
            // Right length, wrong DER header: an RSA-ish blob of the same size.
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

    /// The distinction worth having: a job signed by a revoked key is a very
    /// different event from a job signed by a key nobody has heard of.
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

/// SHA-256 of `bytes`, rendered as `sha256:<hex>`.
///
/// Through `aws-lc-rs`, which is already the agent's one crypto backend. Pulling
/// in a `RustCrypto` `sha2` for this would put a second SHA-256 implementation in a
/// binary whose whole argument is that there is one set of primitives to audit —
/// and it would be there to hash a list of package names.
///
/// The prefix is part of the value, not decoration: it is what lets the algorithm
/// change later without the server having to guess which one produced a given
/// hash.
#[must_use]
pub fn content_hash(bytes: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    let mut out = String::with_capacity(7 + digest.as_ref().len() * 2);
    out.push_str("sha256:");
    for b in digest.as_ref() {
        use std::fmt::Write as _;
        // Infallible for a String.
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod content_hash_tests {
    use super::content_hash;

    #[test]
    fn it_is_sha256_and_says_so() {
        // The empty-input digest, which is the one SHA-256 value worth knowing by
        // sight: if this changes, the algorithm changed underneath us.
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
