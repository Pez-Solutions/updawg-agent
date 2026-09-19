//! Signature verification, key pinning and CSR generation.
//!
//! The agent generates its key pair locally and the private key never leaves
//! the host. The organization's signing key is pinned at enrollment, and every
//! job is verified against that pinned key rather than against whatever the
//! server currently claims.
//!
//! Key rotation works by the old key endorsing the new one, so an agent can
//! follow a rotation without having to trust the server blindly. That is the
//! whole reason rotation is not simply "the server says use this key now".
//!
//! Scope note: DAWG-19 defines the surface. DAWG-30 implements key generation,
//! CSRs and pinning; DAWG-68 implements rotation following.

pub mod key;

use std::fmt;
use updawg_protocol::{OrgSigningKey, SigningKeyStatus};

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
    #[error("no organization key is pinned; the host is not enrolled")]
    NotPinned,
    #[error("endorsement chain does not lead back to the pinned key")]
    BrokenEndorsement,
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
    }

    fn offered(id: &str, wire: &str, status: SigningKeyStatus) -> OrgSigningKey {
        OrgSigningKey {
            key_id: SigningKeyId::new(id),
            public_key: wire.to_string(),
            status,
            endorsement: None,
        }
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
