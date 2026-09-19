//! Certificate renewal: `POST /agent/v1/cert/renew`.
//!
//! Client certificates are short-lived. An agent renews well before expiry;
//! one that fails to renew falls out of the fleet and shows up as stale, which
//! is the intended failure mode — a host Updawg cannot authenticate is a host
//! Updawg should not claim to know the state of.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CertRenewRequest {
    /// PEM-encoded CSR, generated from the same key pair or a fresh one.
    pub csr: String,
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CertRenewResponse {
    pub certificate: String,
    pub ca_chain: Vec<String>,
    /// Present when the organization's signing keys have changed since
    /// enrollment, so a renewing agent picks up a rotation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub org_signing_keys: Vec<crate::enroll::OrgSigningKey>,
}
