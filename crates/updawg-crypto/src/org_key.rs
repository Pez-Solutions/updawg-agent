//! An organization signing key the **customer** holds (DAWG-157, ADR 0006).
//!
//! Everywhere else in the agent an organization key is a public half to pin
//! and verify against. This is the one place a private half exists, and it is
//! not on a managed host: it is `updawgctl keygen` and `updawgctl sign`, run
//! by the organization in its own environment, so that Updawg never holds a
//! key its agents accept.
//!
//! The file is an unencrypted PKCS#8 PEM (`BEGIN PRIVATE KEY`), the format
//! `openssl genpkey -algorithm ed25519` writes, so a customer can generate the
//! key with their own tools or import this one into an HSM. Protecting the
//! file is theirs to decide; it is written readable by its owner only.

use crate::{CryptoError, ED25519_SPKI_PREFIX, OrgPublicKey, Result};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use base64::Engine as _;
use std::{fmt, fs, io::Write as _, path::Path};

const PEM_LABEL: &str = "PRIVATE KEY";

/// A customer-held organization key pair.
pub struct OrgKeyPair {
    pair: Ed25519KeyPair,
    pkcs8: Vec<u8>,
}

// Never print the private half, even by accident in an error.
impl fmt::Debug for OrgKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrgKeyPair")
            .field("public_key", &self.public().fingerprint())
            .finish()
    }
}

impl OrgKeyPair {
    /// Generate a fresh key pair.
    ///
    /// # Errors
    /// Fails only if the platform's random source is unavailable.
    pub fn generate() -> Result<Self> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;
        Self::from_pkcs8(doc.as_ref())
    }

    fn from_pkcs8(pkcs8: &[u8]) -> Result<Self> {
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|e| CryptoError::MalformedKeyFile(e.to_string()))?;
        Ok(Self {
            pair,
            pkcs8: pkcs8.to_vec(),
        })
    }

    /// Read a PKCS#8 PEM file.
    ///
    /// # Errors
    /// Fails if the file cannot be read or is not an Ed25519 private key.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let pem = fs::read_to_string(path).map_err(|source| CryptoError::KeyFile {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_pkcs8(&decode_pem(&pem)?)
    }

    /// Write the key to `path`, readable only by its owner, refusing to
    /// replace a file that is already there.
    ///
    /// ⚠️ **Refusing is the point.** Overwriting an organization key is
    /// losing it, and losing it is the one thing nobody, including Updawg,
    /// can undo: every host would have to be re-enrolled.
    ///
    /// # Errors
    /// Fails if the file exists or cannot be written.
    pub fn save_new(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let failed = |source| CryptoError::KeyFile {
            path: path.display().to_string(),
            source,
        };
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(failed)?;
        file.write_all(encode_pem(&self.pkcs8).as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(failed)
    }

    /// The public half, as agents pin it.
    #[must_use]
    pub fn public(&self) -> OrgPublicKey {
        OrgPublicKey::from_bytes(self.pair.public_key().as_ref().to_vec())
    }

    /// The base64 SPKI, without the `ed25519:` prefix: what `trusted_org_key`
    /// and the installer's `UPDAWG_ORG_KEY` take, and what the portal asks for.
    #[must_use]
    pub fn public_spki_base64(&self) -> String {
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(self.pair.public_key().as_ref());
        base64::engine::general_purpose::STANDARD.encode(der)
    }

    /// Sign `message`, which must already be a purpose-labelled message —
    /// [`updawg_protocol::Job::signing_bytes`] or
    /// [`updawg_protocol::EndorsementStatement::signing_bytes`] — and never
    /// raw bytes from somewhere else. See [`updawg_protocol::SignaturePurpose`].
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.pair.sign(message).as_ref().to_vec()
    }
}

fn encode_pem(der: &[u8]) -> String {
    use fmt::Write as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {PEM_LABEL}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    let _ = writeln!(out, "-----END {PEM_LABEL}-----");
    out
}

fn decode_pem(pem: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {PEM_LABEL}-----");
    let end = format!("-----END {PEM_LABEL}-----");
    let body = pem
        .split_once(&begin)
        .and_then(|(_, rest)| rest.split_once(&end))
        .map(|(body, _)| body)
        .ok_or_else(|| {
            CryptoError::MalformedKeyFile(format!(
                "expected an unencrypted PKCS#8 key between `{begin}` and `{end}`"
            ))
        })?;
    let compact: String = body.split_whitespace().collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|e| CryptoError::MalformedKeyFile(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("updawg-org-key-{}-{name}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        dir.join("org.key")
    }

    #[test]
    fn a_saved_key_loads_back_and_signs_what_its_public_half_verifies() {
        let path = scratch("round-trip");
        let key = OrgKeyPair::generate().unwrap();
        key.save_new(&path).unwrap();
        let loaded = OrgKeyPair::load(&path).unwrap();

        assert_eq!(loaded.public(), key.public());
        let message = b"updawg-job-v1\0{}";
        key.public()
            .verify(message, &loaded.sign(message))
            .expect("verifies");
        assert_eq!(
            OrgPublicKey::parse_configured("k", &key.public_spki_base64()).unwrap(),
            key.public()
        );
    }

    #[test]
    fn an_existing_key_is_never_overwritten() {
        let path = scratch("no-overwrite");
        let first = OrgKeyPair::generate().unwrap();
        first.save_new(&path).unwrap();
        assert!(OrgKeyPair::generate().unwrap().save_new(&path).is_err());
        assert_eq!(OrgKeyPair::load(&path).unwrap().public(), first.public());
    }

    #[cfg(unix)]
    #[test]
    fn the_key_file_is_readable_by_its_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let path = scratch("mode");
        OrgKeyPair::generate().unwrap().save_new(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// What `openssl genpkey -algorithm ed25519` writes: PKCS#8 v1, with no
    /// public key inside. A customer who made their key with their own tools
    /// can sign with it.
    #[test]
    fn a_key_openssl_made_loads() {
        let path = scratch("openssl");
        fs::write(
            &path,
            "-----BEGIN PRIVATE KEY-----\n\
             MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n\
             -----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let key = OrgKeyPair::load(&path).unwrap();
        // RFC 8032 §7.1 test 1's public key, which is this seed's.
        assert_eq!(
            key.public().as_bytes(),
            [
                0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
                0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
                0xf7, 0x07, 0x51, 0x1a
            ]
        );
    }

    #[test]
    fn debug_output_never_contains_the_private_half() {
        let key = OrgKeyPair::generate().unwrap();
        let shown = format!("{key:?}");
        let pem = encode_pem(&key.pkcs8);
        assert!(!shown.contains(pem.lines().nth(1).unwrap()));
    }
}
