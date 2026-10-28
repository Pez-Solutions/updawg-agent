//! Wire types for the Updawg agent API.
//!
//! This crate defines the contract between the Updawg agent and the gateway.
//! It lives in the agent repository so that people auditing the agent can read
//! the format it speaks. `updawg-server` depends on it rather than redefining
//! the types, so the two sides can't drift.
//!
//! # Jobs are a closed set
//!
//! [`JobKind`] and [`JobSpec`] are closed enums. No variant carries a script,
//! a command line or an arbitrary string for the agent to execute. Every job is
//! a typed operation with explicit parameters, so even full control of the
//! control plane can't run arbitrary commands on a host.
//!
//! Adding a variant to either enum is a security decision. Anything that would
//! let the server describe how to do something, rather than what to do, does
//! not belong here.
//!
//! # Adding fields
//!
//! The structs are not `#[non_exhaustive]`. The agent builds requests and the
//! server builds responses, both outside this crate, and neither could use a
//! struct it can't construct with a literal. Adding a field is a minor version
//! bump, and new optional fields carry `#[serde(default)]` so an older peer
//! still parses. It does break every struct literal, but that shows up at
//! compile time rather than in a running fleet.
//!
//! [`PROTOCOL_VERSION`] does not change for a new field. It covers the shape of
//! the conversation (the endpoints, the mTLS identity, what a 409 means). 0.2.0
//! added four optional fields: a shorter check-in hold the agent may ask for,
//! what the local config permits, the advisory the package manager attributes
//! to an update, and the packages an upgrade would remove. Absent means unknown
//! in both directions, so a 0.1 agent and a 0.2 gateway still understand each
//! other.
//!
//! # Breaking changes in 0.3
//!
//! Both change what an organization signing key signs. They were made before
//! any organization outside ours had a key or any agent had pinned one.
//!
//! 1. [`Job::signing_bytes`] now prefixes the document with a purpose label,
//!    so a 0.2 signature over a job does not verify under 0.3 and vice versa.
//!    The document itself is unchanged and is now [`Job::document`], which is
//!    what the server stores and delivers.
//! 2. [`OrgSigningKey::endorsement`] is an [`Endorsement`] rather than a
//!    `String`. The old field was a bare signature that nothing produced or
//!    read, and the statement it covered couldn't be reconstructed from
//!    anything the agent holds.
//!
//! Mixing versions fails loudly: a 0.2 gateway and a 0.3 agent disagree at the
//! first signature or the first enrollment.
//!
//! # Transport
//!
//! Mutual TLS. The agent generates a key pair locally at enrollment, sends a
//! CSR, and receives a short-lived client certificate; the private key never
//! leaves the host. Every request carries a `Updawg-Protocol` header, and the
//! gateway accepts the current and previous version.
//!
//! # Identifiers
//!
//! Identifiers are `UUIDv7` with a three-letter type prefix: `hst_`, `job_`,
//! `org_`.

#![doc(html_root_url = "https://docs.rs/updawg-protocol/0.12.0")]
#![forbid(unsafe_code)]

pub mod cert;
pub mod checkin;
pub mod config;
pub mod endorsement;
pub mod enroll;
pub mod error;
pub mod ids;
pub mod inventory;
pub mod job;
pub mod logs;
pub mod releases;
pub mod sign;

pub use cert::{CertRenewRequest, CertRenewResponse};
pub use checkin::{
    AgentInstall, CheckinRequest, CheckinResponse, HostMetrics, HostStateReport, InstallMethod,
    RebootRequired, SnapshotSupport,
};
pub use config::{AgentMode, LocalPolicy, ServerConfig};
pub use endorsement::{EndorsedKey, Endorsement, EndorsementStatement};
pub use enroll::{
    CloudFacts, EnrollRequest, EnrollResponse, HostFacts, OrgSigningKey, SigningKeyStatus,
};
pub use error::ApiError;
pub use ids::{HostId, JobId, OrgId, SigningKeyId};
pub use inventory::{
    AdvisoryHint, AvailableUpdate, Ecosystem, Frozen, FrozenKind, InstalledPackage, InventoryKind,
    InventoryUpload, PackageDelta, PendingRemoval, RemovedPackage, Replacement, Repository,
    SourcePackage, SystemFacts, public_url,
};
pub use job::{
    ApplyUpdates, CheckStatus, DistUpgrade, HealthCheckReport, Job, JobAck, JobComplete, JobKind,
    JobSpec, JobStatus, PackageChange, PackagePin, Preflight, PreflightCheck, Reboot, RebootPolicy,
    Rollback, SelfUpdate, Snapshot, SnapshotPolicy,
};
pub use logs::{LogLine, LogStream};
pub use releases::{ReleaseArtifact, ReleaseChannel, ReleaseManifest};
pub use sign::SignaturePurpose;

/// The agent API path prefix.
pub const API_PATH: &str = "/agent/v1";

/// Value of the `Updawg-Protocol` header this crate speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Name of the protocol header.
pub const PROTOCOL_HEADER: &str = "Updawg-Protocol";

/// Longest a check-in is held open before the gateway replies with no jobs.
pub const CHECKIN_LONG_POLL_SECONDS: u64 = 55;

/// Floor on [`CheckinRequest::hold_seconds`]. Without it, an agent asking for
/// zero would reconnect in a tight loop.
pub const CHECKIN_MIN_HOLD_SECONDS: u64 = 5;

/// Lifetime of an issued client certificate.
pub const CLIENT_CERT_DAYS: u32 = 30;
