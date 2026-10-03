#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use super::*;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA512};
use base64::Engine as _;
use updawg_protocol::ReleaseArtifact;

/// A key of our own, standing in for the release key, and its public half as
/// the agent embeds one (PKCS#1 DER).
fn key() -> (RsaKeyPair, Vec<u8>) {
    let pair = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let public = pair.public_key().as_ref().to_vec();
    (pair, public)
}

fn unsigned(channel: ReleaseChannel) -> ReleaseManifest {
    ReleaseManifest {
        channel,
        version: "0.1.0-20261002120000.gabcdef0".into(),
        released_at: "2026-10-02T12:00:00Z".parse().unwrap(),
        artifacts: vec![ReleaseArtifact {
            target: target().into(),
            name: "updawgd".into(),
            url: "https://pkg.updawg.net/bin/pool/x/updawgd".into(),
            sha256: sha256(b"updawgd"),
            size_bytes: 7,
        }],
        signature: String::new(),
        min_upgradable_from: None,
    }
}

fn sign(pair: &RsaKeyPair, mut manifest: ReleaseManifest) -> ReleaseManifest {
    let mut signature = vec![0; pair.public_modulus_len()];
    pair.sign(
        &RSA_PKCS1_SHA512,
        &SystemRandom::new(),
        &manifest.signing_bytes().unwrap(),
        &mut signature,
    )
    .unwrap();
    manifest.signature = base64::engine::general_purpose::STANDARD.encode(signature);
    manifest
}

fn body(manifest: &ReleaseManifest) -> Vec<u8> {
    serde_json::to_vec(manifest).unwrap()
}

#[test]
fn a_manifest_the_key_signed_is_read() {
    let (pair, public) = key();
    let signed = sign(&pair, unsigned(ReleaseChannel::Beta));
    let read = verify_manifest(&body(&signed), &public, ReleaseChannel::Beta).unwrap();
    assert_eq!(read, signed);
}

#[test]
fn a_manifest_changed_after_signing_is_refused() {
    let (pair, public) = key();
    let mut signed = sign(&pair, unsigned(ReleaseChannel::Beta));
    signed.artifacts[0].sha256 = sha256(b"something else");
    let error = verify_manifest(&body(&signed), &public, ReleaseChannel::Beta).unwrap_err();
    assert!(error.contains("does not verify"), "{error}");
}

#[test]
fn a_manifest_another_key_signed_is_refused() {
    let (pair, _) = key();
    let (_, other) = key();
    let signed = sign(&pair, unsigned(ReleaseChannel::Beta));
    assert!(verify_manifest(&body(&signed), &other, ReleaseChannel::Beta).is_err());
}

#[test]
fn a_genuine_manifest_for_the_other_channel_is_refused() {
    // Signed, and beta's: served where stable was asked for, it must not
    // move a stable host onto beta.
    let (pair, public) = key();
    let signed = sign(&pair, unsigned(ReleaseChannel::Beta));
    let error = verify_manifest(&body(&signed), &public, ReleaseChannel::Stable).unwrap_err();
    assert!(error.contains("stable"), "{error}");
}

#[test]
fn an_unsigned_manifest_is_refused() {
    let (_, public) = key();
    assert!(
        verify_manifest(
            &body(&unsigned(ReleaseChannel::Beta)),
            &public,
            ReleaseChannel::Beta
        )
        .is_err()
    );
}

#[test]
fn the_embedded_release_key_is_an_rsa_4096_public_key() {
    // PKCS#1 RSAPublicKey: a DER SEQUENCE, 526 bytes for a 4096-bit modulus
    // with exponent 65537.
    assert_eq!(RELEASE_KEY.len(), 526);
    assert_eq!(&RELEASE_KEY[..2], &[0x30, 0x82]);
    // And it is what the agent checks with: our own signature does not pass.
    let (pair, _) = key();
    let signed = sign(&pair, unsigned(ReleaseChannel::Stable));
    assert!(verify_manifest(&body(&signed), RELEASE_KEY, ReleaseChannel::Stable).is_err());
}

#[test]
fn how_the_agent_was_installed_decides_how_it_updates() {
    assert_eq!(
        method_for(Path::new("/usr/bin/updawgd"), true, true),
        Ok(Method::Apt)
    );
    assert_eq!(
        method_for(Path::new("/usr/bin/updawgd"), true, false),
        Ok(Method::Dnf)
    );
    assert_eq!(
        method_for(Path::new("/usr/local/bin/updawgd"), false, true),
        Ok(Method::Binary {
            dir: PathBuf::from("/usr/local/bin")
        })
    );
    // Anywhere else, unowned: somebody's own build, left alone.
    assert!(method_for(Path::new("/opt/updawg/updawgd"), false, true).is_err());
    assert!(method_for(Path::new("/usr/bin/updawgd"), false, true).is_err());
}

#[test]
fn apt_cache_madison_is_read() {
    let out = "updawg-agent | 0.1.0-20261002120000.gabcdef0 | https://pkg.updawg.net/apt beta/main amd64 Packages\n\
               updawg-agent | 0.1.0-20261001090000.g1234567 | https://pkg.updawg.net/apt beta/main amd64 Packages\n";
    assert_eq!(
        parse_madison(out),
        vec![
            "0.1.0-20261002120000.gabcdef0",
            "0.1.0-20261001090000.g1234567"
        ]
    );
    assert!(parse_madison("").is_empty());
}

#[test]
fn dnf_list_is_read_without_its_headings() {
    let out = "Installed Packages\n\
               updawg-agent.x86_64    0.1.0-20261001090000.g1234567    @updawg-beta\n\
               Available Packages\n\
               updawg-agent.x86_64    0.1.0-20261002120000.gabcdef0    updawg-beta\n\
               updawg-agent-extras.x86_64  9.9-1  elsewhere\n";
    assert_eq!(
        parse_dnf_list(out),
        vec![
            "0.1.0-20261001090000.g1234567",
            "0.1.0-20261002120000.gabcdef0"
        ]
    );
}

#[test]
fn only_a_package_version_is_passed_on() {
    assert!(plausible_version("0.1.0-20261002120000.gabcdef0"));
    assert!(plausible_version("0.2.0-1"));
    for bad in ["", "latest", "1.0; rm -rf /", "1.0 2.0", "../1.0", "-o"] {
        assert!(!plausible_version(bad), "{bad:?}");
    }
}

#[test]
fn sha256_is_spelled_as_the_manifest_spells_it() {
    assert_eq!(
        sha256(b"abc"),
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn a_pending_update_survives_the_restart_it_is_for() {
    let dir = std::env::temp_dir().join(format!("updawg-self-update-{}", std::process::id()));
    let state = LocalState::new(&dir);
    assert!(state.self_update().unwrap().is_none());
    let now = chrono::Utc::now();
    let job = Job {
        id: updawg_protocol::JobId::new("job_01"),
        host_id: updawg_protocol::HostId::new("hst_01"),
        spec: updawg_protocol::JobSpec::SelfUpdate(updawg_protocol::SelfUpdate {
            version: "0.1.0-2".into(),
            channel: ReleaseChannel::Beta,
        }),
        not_before: None,
        expires_at: now,
        key_id: updawg_protocol::SigningKeyId::new("sk_01"),
        signature: String::new(),
    };
    let pending = Pending {
        job,
        report: JobComplete {
            status: updawg_protocol::JobStatus::Succeeded,
            started_at: now,
            finished_at: now,
            snapshot_id: None,
            changes: vec![],
            health_checks: vec![],
            reboot_required: false,
            inventory_hash: None,
            error: None,
            preflight: vec![],
        },
        from: "0.1.0-1".into(),
        to: "0.1.0-2".into(),
        method: Method::Apt,
        started_at: now,
    };
    state.set_self_update(&pending).unwrap();
    state
        .set_self_update_outcome(&Outcome {
            rolled_back: true,
            detail: "did not check in".into(),
        })
        .unwrap();
    let (back, outcome) = state.take_self_update().unwrap().unwrap();
    assert_eq!(back.to, "0.1.0-2");
    assert_eq!(outcome.unwrap().detail, "did not check in");
    // Taken once: reported once.
    assert!(state.take_self_update().unwrap().is_none());
    assert!(state.self_update_outcome().unwrap().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_apt_channel_is_the_suite_of_the_updawg_line() {
    let list = "# written by install.sh\n\
                deb [signed-by=/etc/apt/keyrings/updawg.asc] https://pkg.updawg.net/apt beta main\n";
    assert_eq!(apt_channel(list).as_deref(), Some("beta"));
    assert_eq!(
        apt_channel("deb https://pkg.updawg.net/apt/ stable main").as_deref(),
        Some("stable")
    );
    assert_eq!(
        apt_channel("deb http://deb.debian.org/debian trixie main"),
        None
    );
    assert_eq!(
        apt_channel("# deb https://pkg.updawg.net/apt beta main"),
        None
    );
    assert_eq!(apt_channel(""), None);
}

#[test]
fn the_dnf_channel_is_the_last_segment_of_baseurl() {
    let repo =
        "[updawg]\nname=Updawg (stable)\nbaseurl=https://pkg.updawg.net/rpm/stable\nenabled=1\n";
    assert_eq!(dnf_channel(repo).as_deref(), Some("stable"));
    assert_eq!(
        dnf_channel("baseurl = https://pkg.updawg.net/rpm/beta/").as_deref(),
        Some("beta")
    );
    assert_eq!(
        dnf_channel("baseurl=https://pkg.updawg.net/rpm/$basearch?x"),
        None
    );
    assert_eq!(dnf_channel("[updawg]\n"), None);
}
