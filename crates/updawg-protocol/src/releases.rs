//! Agent releases: `GET /agent/v1/releases/{channel}`.
//!
//! The manifest is signed independently of the transport. An agent verifies the
//! signature before acting on it, so compromising the gateway is not enough to
//! ship a malicious agent build — you would also need the manifest signing key.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    #[default]
    Stable,
    Beta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseArtifact {
    /// e.g. `x86_64-unknown-linux-musl`.
    pub target: String,
    pub url: String,
    /// `sha256:` followed by the hex digest.
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub channel: ReleaseChannel,
    pub version: String,
    pub released_at: DateTime<Utc>,
    pub artifacts: Vec<ReleaseArtifact>,
    /// Minisign signature over the manifest with `signature` removed.
    pub signature: String,
    /// Minimum version that can self-update directly to this one, when a
    /// release needs an intermediate step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_upgradable_from: Option<String>,
}
