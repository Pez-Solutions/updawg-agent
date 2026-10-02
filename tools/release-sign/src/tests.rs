//! What apt and dnf will make of these signatures, asked of the tools that
//! verify them: `gpgv`, and Sequoia's `sqv` where it is installed (apt uses
//! it from Debian 13). A local RSA key stands in for KMS: the packets around
//! the signature are the part written here, and they are the same whoever
//! signs.
//!
//! CI sets `UPDAWG_REQUIRE_GPGV`, so a runner without `gpgv` fails rather
//! than passing having checked nothing.

use crate::der;
use crate::openpgp::{PublicKey, Signer, canonical_text};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA512};
use std::path::Path;
use std::process::Command;

struct Local(KeyPair);

impl Signer for Local {
    fn sign(&self, to_hash: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut sig = vec![0; self.0.public_modulus_len()];
        self.0
            .sign(&RSA_PKCS1_SHA512, &SystemRandom::new(), to_hash, &mut sig)
            .map_err(|_| anyhow::anyhow!("sign"))?;
        Ok(sig)
    }
}

fn local() -> (Local, PublicKey) {
    let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let (n, e) = der::rsa_public_key(pair.public_key().as_ref()).unwrap();
    (
        Local(pair),
        PublicKey {
            created: 1_790_000_000,
            n,
            e,
        },
    )
}

fn available(tool: &str) -> bool {
    let found = Command::new(tool).arg("--version").output().is_ok();
    if !found && tool == "gpgv" {
        assert!(
            std::env::var("UPDAWG_REQUIRE_GPGV").is_err(),
            "UPDAWG_REQUIRE_GPGV is set and gpgv is not installed"
        );
    }
    if !found {
        eprintln!("skipping: {tool} is not installed");
    }
    found
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("release-sign-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn gpgv(keyring: &Path, args: &[&Path]) -> std::process::Output {
    Command::new("gpgv")
        .arg("--keyring")
        .arg(keyring)
        .args(args)
        .output()
        .unwrap()
}

const RELEASE: &str = "Origin: Updawg\nLabel: Updawg\nSuite: stable\nCodename: stable\nDate: Wed, 30 Sep 2026 18:00:00 UTC\nArchitectures: amd64 arm64\nComponents: main\nSHA256:\n 0123456789abcdef 1234 main/binary-amd64/Packages\n";

#[test]
fn a_detached_signature_verifies_and_a_changed_file_does_not() {
    if !available("gpgv") {
        return;
    }
    let dir = scratch("detach");
    let (signer, key) = local();
    let keyring = dir.join("key.gpg");
    std::fs::write(
        &keyring,
        key.certificate("Test <t@example>", &signer, key.created)
            .unwrap(),
    )
    .unwrap();
    let data = dir.join("Release");
    std::fs::write(&data, RELEASE).unwrap();
    let sig = dir.join("Release.gpg");
    std::fs::write(
        &sig,
        key.detach_sign(RELEASE.as_bytes(), &signer, 1_790_000_100)
            .unwrap(),
    )
    .unwrap();

    let ok = gpgv(&keyring, &[&sig, &data]);
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );

    std::fs::write(&data, RELEASE.replace("stable", "beta")).unwrap();
    assert!(
        !gpgv(&keyring, &[&sig, &data]).status.success(),
        "a changed file verified"
    );
}

#[test]
fn a_cleartext_signature_verifies_as_inrelease() {
    if !available("gpgv") {
        return;
    }
    let dir = scratch("clear");
    let (signer, key) = local();
    let keyring = dir.join("key.gpg");
    std::fs::write(
        &keyring,
        key.certificate("Test <t@example>", &signer, key.created)
            .unwrap(),
    )
    .unwrap();
    let inrelease = dir.join("InRelease");
    // With a line that needs dash-escaping, and trailing space, which a text
    // signature ignores.
    let text = format!("{RELEASE}-dashed line  \n");
    let message = key.clear_sign(&text, &signer, 1_790_000_100).unwrap();
    assert!(message.contains("\n- -dashed line"), "{message}");
    std::fs::write(&inrelease, &message).unwrap();

    let ok = gpgv(&keyring, &[&inrelease]);
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );

    let tampered = message.replace("Suite: stable", "Suite: beta!");
    std::fs::write(&inrelease, tampered).unwrap();
    assert!(
        !gpgv(&keyring, &[&inrelease]).status.success(),
        "a changed InRelease verified"
    );
}

#[test]
fn sequoia_accepts_the_key_and_the_signature() {
    if !available("sqv") {
        return;
    }
    let dir = scratch("sqv");
    let (signer, key) = local();
    let keyring = dir.join("key.gpg");
    std::fs::write(
        &keyring,
        key.certificate("Test <t@example>", &signer, key.created)
            .unwrap(),
    )
    .unwrap();
    let data = dir.join("repomd.xml");
    std::fs::write(&data, "<repomd/>\n").unwrap();
    let sig = dir.join("repomd.xml.asc");
    std::fs::write(
        &sig,
        key.detach_sign(b"<repomd/>\n", &signer, 1_790_000_100)
            .unwrap(),
    )
    .unwrap();

    let out = Command::new("sqv")
        .arg("--keyring")
        .arg(&keyring)
        .arg(&sig)
        .arg(&data)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_export_is_the_same_bytes_every_time() {
    // The fingerprint and the self-signature both depend only on the key and
    // its creation time, so publishing the key twice cannot give two keys.
    let (signer, key) = local();
    let a = key
        .export("Test <t@example>", &signer, key.created)
        .unwrap();
    let b = key
        .export("Test <t@example>", &signer, key.created)
        .unwrap();
    assert_eq!(a, b);
    assert!(a.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"));
    assert_eq!(canonical_text("x\n"), b"x".to_vec());
}

#[test]
fn a_manifest_verifies_with_the_public_key_as_the_agent_holds_it() {
    use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA512, UnparsedPublicKey};
    use base64::Engine as _;
    let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
    // PKCS#1 DER, which is what the agent compiles in (self_update/release-key.der).
    let public = pair.public_key().as_ref().to_vec();
    let dir = scratch("manifest");
    for target in ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"] {
        std::fs::create_dir_all(dir.join(target)).unwrap();
        for name in ["updawgd", "updawgctl"] {
            std::fs::write(dir.join(target).join(name), format!("{target} {name}")).unwrap();
        }
    }
    let json = crate::manifest::build(
        &Local(pair),
        "beta",
        "0.1.0-20261002120000.gabcdef0",
        &dir,
        "https://pkg.updawg.net/bin/pool/0.1.0-20261002120000.gabcdef0/",
    )
    .unwrap();
    let manifest: updawg_protocol::ReleaseManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest.artifacts.len(), 4);
    let d = manifest
        .artifact("aarch64-unknown-linux-musl", "updawgd")
        .unwrap();
    assert_eq!(
        d.url,
        "https://pkg.updawg.net/bin/pool/0.1.0-20261002120000.gabcdef0/aarch64-unknown-linux-musl/updawgd"
    );
    assert_eq!(
        d.size_bytes,
        "aarch64-unknown-linux-musl updawgd".len() as u64
    );
    let signature = base64::engine::general_purpose::STANDARD
        .decode(&manifest.signature)
        .unwrap();
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, &public)
        .verify(&manifest.signing_bytes().unwrap(), &signature)
        .unwrap();
    assert!(
        crate::manifest::build(
            &Local(KeyPair::generate(KeySize::Rsa2048).unwrap()),
            "nightly",
            "1",
            &dir,
            "x"
        )
        .is_err()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
