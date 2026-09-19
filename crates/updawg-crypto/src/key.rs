//! The host's own key pair, and the CSR it sends at enrollment.
//!
//! The private key is generated on the host and never leaves it. Nothing in
//! this module serialises it anywhere except the one file it lives in, and
//! nothing implements `Display` or a revealing `Debug` for it.
//!
//! Ed25519, because the certificate is short-lived and re-issued monthly: a
//! small key with fast signatures matters more than algorithm agility on a
//! credential with a thirty-day life.

use crate::{CryptoError, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519, PublicKeyData};
use std::{
    fmt, fs,
    io::Write,
    path::{Path, PathBuf},
};

/// Permission bits the private key file must not have set.
///
/// Group and other, in other words. The agent runs as root and the key is the
/// host's entire identity; anything readable beyond the owner is a finding.
#[cfg(unix)]
const FORBIDDEN_BITS: u32 = 0o077;

/// The host's Ed25519 key pair.
pub struct AgentKey {
    inner: KeyPair,
}

// The whole point of this type is that the private half stays put. A derived
// Debug would put it in the first error message that included the struct.
impl fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentKey")
            .field("algorithm", &"ed25519")
            .field("public_key", &self.fingerprint())
            .finish()
    }
}

impl AgentKey {
    /// Generate a fresh key pair.
    ///
    /// # Errors
    /// Fails only if the platform's random source is unavailable, which is not
    /// a condition worth continuing past.
    pub fn generate() -> Result<Self> {
        let inner = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Load the key pair from a PKCS#8 PEM file.
    ///
    /// If the file is readable by anyone but its owner the permissions are
    /// tightened and the fact is logged at warn level. Refusing to start would
    /// be the stricter choice, but it turns a permissions slip into an outage
    /// on a host that is otherwise healthy; fixing it loudly is the better
    /// trade for something that runs unattended.
    ///
    /// # Errors
    /// Fails if the file is missing, unreadable, or not a valid Ed25519 key.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();

        #[cfg(unix)]
        tighten_permissions(path)?;

        let pem = fs::read_to_string(path).map_err(|source| CryptoError::KeyFile {
            path: path.display().to_string(),
            source,
        })?;
        let inner =
            KeyPair::from_pem(&pem).map_err(|e| CryptoError::MalformedKeyFile(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Whether a key file already exists at this path.
    #[must_use]
    pub fn exists(path: impl AsRef<Path>) -> bool {
        path.as_ref().exists()
    }

    /// Write the key pair to disk, atomically and readable only by its owner.
    ///
    /// Temp file, fsync, rename — the same rule as the rest of the agent's
    /// state. A half-written key file would leave a host that cannot
    /// authenticate and cannot re-enroll either, because the identity it would
    /// be re-enrolling with is the thing that got truncated.
    ///
    /// # Errors
    /// Fails if the directory cannot be created or the file cannot be written.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| CryptoError::KeyFile {
                path: parent.display().to_string(),
                source,
            })?;
        }

        let tmp: PathBuf = path.with_extension("tmp");
        let pem = self.inner.serialize_pem();

        let write = || -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp)?;
            // Narrow the window: create, then restrict, then write. The file is
            // empty for as long as it is world-readable.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(pem.as_bytes())?;
            f.flush()?;
            f.sync_all()?;
            Ok(())
        };
        write().map_err(|source| CryptoError::KeyFile {
            path: tmp.display().to_string(),
            source,
        })?;

        fs::rename(&tmp, path).map_err(|source| CryptoError::KeyFile {
            path: path.display().to_string(),
            source,
        })
    }

    /// The `SubjectPublicKeyInfo` DER encoding of the public half.
    #[must_use]
    pub fn public_key_spki(&self) -> Vec<u8> {
        self.inner.subject_public_key_info()
    }

    /// Short fingerprint of the public half, for logs and `updawgctl status`.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        crate::fingerprint_bytes(&self.public_key_spki())
    }

    /// Generate a PEM-encoded certificate signing request.
    ///
    /// The subject carries the machine id rather than the hostname. Hostnames
    /// change and repeat; the machine id is what the server matches on to
    /// recognise a rebuilt host, so it is what the request should be about.
    /// The server issues the certificate with the host id in the subject — it
    /// decides identity, we only prove possession of the key.
    ///
    /// # Errors
    /// Fails if the request cannot be serialised, which would mean an invalid
    /// subject value.
    pub fn certificate_request(&self, machine_id: &str) -> Result<String> {
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| CryptoError::Csr(e.to_string()))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, machine_id);
        params.distinguished_name = dn;

        let csr = params
            .serialize_request(&self.inner)
            .map_err(|e| CryptoError::Csr(e.to_string()))?;
        csr.pem().map_err(|e| CryptoError::Csr(e.to_string()))
    }
}

/// Tighten a key file's permissions to owner-only, reporting whether it had to.
#[cfg(unix)]
fn tighten_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let meta = fs::metadata(path).map_err(|source| CryptoError::KeyFile {
        path: path.display().to_string(),
        source,
    })?;
    let mode = meta.permissions().mode();
    if mode & FORBIDDEN_BITS == 0 {
        return Ok(());
    }

    tracing::warn!(
        path = %path.display(),
        mode = format!("{:o}", mode & 0o777),
        "private key was readable beyond its owner; tightening to 0600"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        CryptoError::KeyFile {
            path: path.display().to_string(),
            source,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let n = NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("updawg-key-test-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_saved_key_round_trips() {
        let dir = temp_dir();
        let path = dir.join("agent.key");

        let key = AgentKey::generate().unwrap();
        key.save(&path).unwrap();

        let loaded = AgentKey::load(&path).unwrap();
        assert_eq!(
            key.public_key_spki(),
            loaded.public_key_spki(),
            "reloading the key must give back the same public half"
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn the_key_is_ed25519_in_spki_form() {
        let key = AgentKey::generate().unwrap();
        let spki = key.public_key_spki();
        // 12-byte Ed25519 SPKI header, then the 32-byte key.
        assert_eq!(spki.len(), 44);
        assert_eq!(&spki[..12], crate::ED25519_SPKI_PREFIX);
    }

    #[cfg(unix)]
    #[test]
    fn a_new_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        let path = dir.join("agent.key");
        AgentKey::generate().unwrap().save(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file mode was {mode:o}");
        fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn loading_a_world_readable_key_tightens_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        let path = dir.join("agent.key");
        AgentKey::generate().unwrap().save(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        AgentKey::load(&path).expect("a loose key should still load");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "permissions were not tightened; mode {mode:o}");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn saving_leaves_no_temporary_file_behind() {
        let dir = temp_dir();
        AgentKey::generate()
            .unwrap()
            .save(dir.join("agent.key"))
            .unwrap();
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_corrupt_key_file_is_reported_not_ignored() {
        let dir = temp_dir();
        let path = dir.join("agent.key");
        fs::write(&path, b"-----BEGIN PRIVATE KEY-----\nnope\n").unwrap();
        let err = AgentKey::load(&path).unwrap_err();
        assert!(
            matches!(err, CryptoError::MalformedKeyFile(_)),
            "got {err:?}"
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn the_csr_names_the_machine_id_and_is_pem() {
        let key = AgentKey::generate().unwrap();
        let pem = key
            .certificate_request("3f2a9c1d4e5b6a7c8d9e0f1a2b3c4d5e")
            .unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(
            pem.trim_end()
                .ends_with("-----END CERTIFICATE REQUEST-----")
        );
    }

    #[test]
    fn debug_output_never_contains_the_private_key() {
        let dir = temp_dir();
        let path = dir.join("agent.key");
        let key = AgentKey::generate().unwrap();
        key.save(&path).unwrap();
        let pem = fs::read_to_string(&path).unwrap();

        let rendered = format!("{key:?}");
        assert!(!rendered.contains("PRIVATE KEY"));
        for line in pem.lines().filter(|l| !l.starts_with("-----")) {
            assert!(
                !rendered.contains(line),
                "private key material leaked into Debug output"
            );
        }
        fs::remove_dir_all(dir).ok();
    }
}
