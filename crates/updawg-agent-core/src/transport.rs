//! Outbound HTTPS transport.
//!
//! The agent only ever makes outbound connections. There is no listener, no
//! inbound port and no SSH, which is what lets it work behind NAT and strict
//! egress firewalls.
//!
//! Scope note: DAWG-19 defines the surface, DAWG-31 implements mTLS with
//! rustls and certificate renewal.

use async_trait::async_trait;
use updawg_protocol::Job;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("not enrolled; run `updawgctl enroll --token ...` first")]
    NotEnrolled,
    #[error("server rejected the client certificate")]
    CertificateRejected,
    #[error("request failed: {0}")]
    Request(String),
}

pub type Result<T> = std::result::Result<T, TransportError>;

#[async_trait]
pub trait Transport: Send + Sync {
    /// Hold a long-poll open and return any job the server has for us.
    async fn check_in(&self) -> Result<Option<Job>>;
}
