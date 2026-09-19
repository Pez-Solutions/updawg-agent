//! The error body the gateway returns.

use serde::{Deserialize, Serialize};

/// A structured error from the gateway.
///
/// The agent branches on `code`, never on `message`, so wording can change
/// without breaking behaviour on hosts running older builds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    /// Stable machine-readable code, e.g. `inventory_base_mismatch`.
    pub code: String,
    /// Human-readable detail. For logs and operators, not for control flow.
    pub message: String,
    /// Present when retrying later might succeed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u64>,
}

impl ApiError {
    /// The delta's `base_hash` did not match what the server holds, so the
    /// agent must send a full inventory. Returned with HTTP 409.
    pub const INVENTORY_BASE_MISMATCH: &'static str = "inventory_base_mismatch";
    /// The enrollment token is unknown, expired or exhausted.
    pub const ENROLLMENT_TOKEN_INVALID: &'static str = "enrollment_token_invalid";
    /// The client certificate has been revoked, usually by decommissioning.
    pub const CERTIFICATE_REVOKED: &'static str = "certificate_revoked";
    /// The agent is too old for this gateway.
    pub const PROTOCOL_UNSUPPORTED: &'static str = "protocol_unsupported";
}
