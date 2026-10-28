//! Certificate renewal: `POST /agent/v1/cert/renew`.
//!
//! Client certificates are short-lived and the agent renews well before
//! expiry. An agent that fails to renew shows up as stale, since the server
//! can't vouch for the state of a host it can't authenticate.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRenewRequest {
    /// PEM-encoded CSR, generated from the same key pair or a fresh one.
    pub csr: String,
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRenewResponse {
    pub certificate: String,
    pub ca_chain: Vec<String>,
    /// Present when the organization's signing keys have changed since
    /// enrollment, so a renewing agent picks up a rotation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub org_signing_keys: Vec<crate::enroll::OrgSigningKey>,
}
