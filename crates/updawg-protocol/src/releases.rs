//! Agent releases: one manifest per channel, saying which build the channel
//! holds and where its binaries are.
//!
//! Served from `https://pkg.updawg.net/bin/<channel>.json`, next to the apt
//! and dnf repositories for the same builds.
//!
//! # Trust
//!
//! The manifest is signed by the release key, the same KMS-held
//! `RSA_SIGN_PKCS1_4096_SHA512` key that signs the package repositories. The
//! agent checks it against a public key compiled into the binary, so a
//! compromised gateway or bucket can't ship an agent build on its own.
//!
//! A self-update job (signed by the organization key) names the version, and
//! the manifest (signed by the release key) says what that version's binaries
//! are. Both have to agree.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    #[default]
    Stable,
    Beta,
}

impl ReleaseChannel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
        }
    }
}

/// One binary of one build, for one target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseArtifact {
    /// For example `x86_64-unknown-linux-musl`.
    pub target: String,
    /// `updawgd` or `updawgctl`.
    pub name: String,
    pub url: String,
    /// `sha256:` followed by the hex digest.
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub channel: ReleaseChannel,
    /// Full build version, as the packages and the agent report it:
    /// `0.1.0-20260930183310.g8c53d52`.
    pub version: String,
    pub released_at: DateTime<Utc>,
    pub artifacts: Vec<ReleaseArtifact>,
    /// Base64 `RSASSA-PKCS1-v1_5` with SHA-512, by the release key, over
    /// [`ReleaseManifest::signing_bytes`].
    pub signature: String,
    /// Minimum version that can self-update directly to this one, when a
    /// release needs an intermediate step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_upgradable_from: Option<String>,
}

impl ReleaseManifest {
    /// Domain separation label, so a manifest signature can't be reused for
    /// anything else the release key signs. Same `label || 0x00 || message`
    /// shape as [`crate::SignaturePurpose`].
    pub const LABEL: &'static str = "updawg-release-manifest-v1";

    /// The manifest without its signature, as canonical JSON (same rules as
    /// [`crate::Job::document`]).
    pub fn document(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        if let Some(obj) = value.as_object_mut() {
            obj.remove("signature");
        }
        serde_json::to_vec(&value)
    }

    /// The exact bytes the signature covers.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut out = Self::LABEL.as_bytes().to_vec();
        out.push(0);
        out.extend(self.document()?);
        Ok(out)
    }

    /// This target's binary called `name`, if the build has one.
    #[must_use]
    pub fn artifact(&self, target: &str, name: &str) -> Option<&ReleaseArtifact> {
        self.artifacts
            .iter()
            .find(|a| a.target == target && a.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> ReleaseManifest {
        ReleaseManifest {
            channel: ReleaseChannel::Beta,
            version: "0.1.0-20261002120000.gabcdef0".into(),
            released_at: "2026-10-02T12:00:00Z".parse().unwrap(),
            artifacts: vec![ReleaseArtifact {
                target: "x86_64-unknown-linux-musl".into(),
                name: "updawgd".into(),
                url: "https://pkg.updawg.net/bin/pool/0.1.0-20261002120000.gabcdef0/x86_64-unknown-linux-musl/updawgd".into(),
                sha256: format!("sha256:{}", "0".repeat(64)),
                size_bytes: 1,
            }],
            signature: "c2lnbmF0dXJl".into(),
            min_upgradable_from: None,
        }
    }

    #[test]
    fn the_signature_is_not_part_of_what_it_signs() {
        let mut a = manifest();
        let before = a.signing_bytes().unwrap();
        a.signature = "ZGlmZmVyZW50".into();
        assert_eq!(a.signing_bytes().unwrap(), before);
    }

    #[test]
    fn every_other_field_is() {
        let base = manifest().signing_bytes().unwrap();
        let mut m = manifest();
        m.version.push('1');
        assert_ne!(m.signing_bytes().unwrap(), base);
        let mut m = manifest();
        m.channel = ReleaseChannel::Stable;
        assert_ne!(
            m.signing_bytes().unwrap(),
            base,
            "a beta manifest must not pass as stable"
        );
        let mut m = manifest();
        m.artifacts[0].sha256 = format!("sha256:{}", "1".repeat(64));
        assert_ne!(m.signing_bytes().unwrap(), base);
    }

    #[test]
    fn the_label_comes_first_and_ends_at_the_first_nul() {
        let bytes = manifest().signing_bytes().unwrap();
        let nul = bytes.iter().position(|b| *b == 0).unwrap();
        assert_eq!(&bytes[..nul], ReleaseManifest::LABEL.as_bytes());
        assert_eq!(bytes[nul + 1], b'{');
    }

    #[test]
    fn an_artifact_is_found_by_target_and_name() {
        let m = manifest();
        assert!(m.artifact("x86_64-unknown-linux-musl", "updawgd").is_some());
        assert!(
            m.artifact("x86_64-unknown-linux-musl", "updawgctl")
                .is_none()
        );
        assert!(
            m.artifact("aarch64-unknown-linux-musl", "updawgd")
                .is_none()
        );
    }
}
