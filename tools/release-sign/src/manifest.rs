//! The agent's release manifest for one channel, in the
//! `updawg_protocol::ReleaseManifest` format.

use crate::openpgp::Signer;
use anyhow::{Context as _, bail};
use base64::Engine as _;
use std::fmt::Write as _;
use std::path::Path;
use updawg_protocol::{ReleaseArtifact, ReleaseChannel, ReleaseManifest};

const TARGETS: [&str; 2] = ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"];
const BINARIES: [&str; 2] = ["updawgd", "updawgctl"];

pub(crate) fn build(
    signer: &dyn Signer,
    channel: &str,
    version: &str,
    dir: &Path,
    base_url: &str,
) -> anyhow::Result<String> {
    let channel = match channel {
        "beta" => ReleaseChannel::Beta,
        "stable" => ReleaseChannel::Stable,
        other => bail!("the channel is beta or stable, not {other}"),
    };
    let mut manifest = unsigned(channel, version, dir, base_url)?;
    let signature = signer.sign(&manifest.signing_bytes()?)?;
    manifest.signature = base64::engine::general_purpose::STANDARD.encode(signature);
    Ok(format!("{}\n", serde_json::to_string_pretty(&manifest)?))
}

/// The manifest without its signature.
pub(crate) fn unsigned(
    channel: ReleaseChannel,
    version: &str,
    dir: &Path,
    base_url: &str,
) -> anyhow::Result<ReleaseManifest> {
    let base = base_url.trim_end_matches('/');
    let mut artifacts = Vec::new();
    for target in TARGETS {
        for name in BINARIES {
            let path = dir.join(target).join(name);
            let bytes = std::fs::read(&path).with_context(|| path.display().to_string())?;
            let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &bytes);
            let hex = digest.as_ref().iter().fold(String::new(), |mut hex, b| {
                let _ = write!(hex, "{b:02x}");
                hex
            });
            artifacts.push(ReleaseArtifact {
                target: target.into(),
                name: name.into(),
                url: format!("{base}/{target}/{name}"),
                sha256: format!("sha256:{hex}"),
                size_bytes: u64::try_from(bytes.len())?,
            });
        }
    }
    Ok(ReleaseManifest {
        channel,
        version: version.into(),
        released_at: chrono::Utc::now(),
        artifacts,
        signature: String::new(),
        min_upgradable_from: None,
    })
}
