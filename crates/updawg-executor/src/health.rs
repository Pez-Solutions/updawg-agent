//! Health checks, run after every mutating job.
//!
//! These are what halt a rollout, so a check that cannot run must report a
//! failure rather than quietly passing.

use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

/// The check types supported by `[[health_check]]` in `agent.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckKind {
    Systemd { unit: String },
    Http { url: String, expect_status: u16 },
    Command { argv: Vec<String> },
}

#[async_trait]
pub trait HealthCheck: Send + Sync {
    fn name(&self) -> &str;
    async fn run(&self) -> CheckResult;
}
