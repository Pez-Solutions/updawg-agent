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
//! Scope note: DAWG-19 defines the surface. DAWG-30 implements enrollment and
//! pinning; DAWG-68 implements rotation following.

use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("signature does not verify against the pinned organization key")]
    BadSignature,
    #[error("no organization key is pinned; the host is not enrolled")]
    NotPinned,
    #[error("endorsement chain does not lead back to the pinned key")]
    BrokenEndorsement,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// An Ed25519 public key belonging to an organization.
#[derive(Clone, PartialEq, Eq)]
pub struct OrgPublicKey(Vec<u8>);

impl OrgPublicKey {
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
        self.0
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
