//! Enrollment: `POST /agent/v1/enroll`.
//!
//! The only endpoint that does not require a client certificate. The agent
//! generates its key pair locally, sends a CSR, and receives a short-lived
//! certificate plus the organization's signing keys, which it pins.
//!
//! Re-enrolling with a `machine_id` the organization already knows reuses the
//! existing host record, so a rebuilt machine keeps its history.

use crate::{
    config::ServerConfig,
    endorsement::Endorsement,
    ids::{HostId, SigningKeyId},
};
use serde::{Deserialize, Serialize};

/// Facts gathered before the host has an identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostFacts {
    pub distro: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codename: Option<String>,
    pub kernel: String,
    pub arch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtualization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud: Option<CloudFacts>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudFacts {
    pub provider: String,
    pub instance_id: String,
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// Enrollment token, shown once in the portal.
    pub token: String,
    /// PEM-encoded certificate signing request.
    pub csr: String,
    pub machine_id: String,
    pub hostname: String,
    pub facts: HostFacts,
    pub agent_version: String,
}

/// One of the organization's job-signing keys.
///
/// The agent pins these at enrollment and verifies every job against them.
/// Rotation works by the outgoing key endorsing its replacement, so an agent
/// can follow a rotation without simply believing whatever the server sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgSigningKey {
    pub key_id: SigningKeyId,
    /// `ed25519:` followed by the base64 SPKI encoding.
    pub public_key: String,
    pub status: SigningKeyStatus,
    /// The outgoing key's statement about this one, and the signature over it.
    ///
    /// Absent is only acceptable on first use. An agent with no pinned keys
    /// accepts an unendorsed key at enrollment, anchored by the enrollment
    /// token. Once it has pinned keys, any new key needs an endorsement, or
    /// the agent would be trusting whatever the server sends.
    ///
    /// In 0.2 this was an `Option<String>` holding a bare signature, which
    /// couldn't be verified because the agent had no way to rebuild the exact
    /// statement (it includes an `issued_at`). See [`Endorsement`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endorsement: Option<Endorsement>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningKeyStatus {
    Active,
    /// Still accepted for verification, no longer used for new jobs.
    Retiring,
    /// No longer accepted. Kept so an agent can tell revoked from unknown and
    /// say so when it refuses.
    Retired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub host_id: HostId,
    /// PEM-encoded client certificate.
    pub certificate: String,
    pub ca_chain: Vec<String>,
    pub org_signing_keys: Vec<OrgSigningKey>,
    pub config: ServerConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_facts_are_omitted_rather_than_sent_as_null() {
        let facts = HostFacts {
            distro: "debian".into(),
            version: "13".into(),
            codename: None,
            kernel: "6.12.0-amd64".into(),
            arch: "x86_64".into(),
            virtualization: None,
            cloud: None,
        };
        let json = serde_json::to_string(&facts).unwrap();
        assert!(
            !json.contains("cloud"),
            "absent facts should not appear on the wire"
        );
        assert!(!json.contains("null"));
    }

    #[test]
    fn signing_key_status_round_trips() {
        for status in [
            SigningKeyStatus::Active,
            SigningKeyStatus::Retiring,
            SigningKeyStatus::Retired,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: SigningKeyStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, back);
        }
    }
}
