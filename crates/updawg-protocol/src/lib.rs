//! Wire types for the Updawg agent API.
//!
//! This crate is the single source of truth for the contract between the Updawg
//! agent and the gateway. It lives in the agent repository on purpose: the agent
//! is the thing customers audit, and the format it speaks should be defined
//! where they can read it. `updawg-server` depends on this crate rather than
//! redefining these types, so the two sides cannot drift apart.
//!
//! # The property this crate exists to preserve
//!
//! [`JobKind`] and [`JobSpec`] are **closed enums**. There is no variant that
//! carries a script, a command line, or an arbitrary string for the agent to
//! execute. Every job is one of a fixed set of typed operations with explicit
//! parameters, which is why full control of the Updawg control plane still
//! cannot run arbitrary commands on a customer's host.
//!
//! Adding a variant to either enum is a security decision, not a routine
//! change. Anything that would let the server describe *how* to do something,
//! rather than *what* to do, belongs somewhere else.
//!
//! # Adding fields
//!
//! These structs are deliberately **not** `#[non_exhaustive]`. Both ends of
//! this wire format are outside this crate — the agent builds requests, the
//! server builds responses — and a struct neither of them can construct with a
//! literal is a struct neither of them can use. Adding a field is therefore a
//! minor version bump, and new optional fields carry `#[serde(default)]` so an
//! older peer keeps parsing.
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
//! Identifiers are `UUIDv7` rendered with a three-letter type prefix — `hst_`,
//! `job_`, `org_`. The design document's illustrative examples used `host_` in
//! places; the three-letter form is what the implementation uses throughout the
//! agent, the server and the portal, and it is what this crate defines.

#![doc(html_root_url = "https://docs.rs/updawg-protocol/0.1.1")]
#![forbid(unsafe_code)]

pub mod cert;
pub mod checkin;
pub mod config;
pub mod enroll;
pub mod error;
pub mod ids;
pub mod inventory;
pub mod job;
pub mod logs;
pub mod releases;

pub use cert::{CertRenewRequest, CertRenewResponse};
pub use checkin::{CheckinRequest, CheckinResponse, HostMetrics, HostStateReport};
pub use config::ServerConfig;
pub use enroll::{
    CloudFacts, EnrollRequest, EnrollResponse, HostFacts, OrgSigningKey, SigningKeyStatus,
};
pub use error::ApiError;
pub use ids::{HostId, JobId, OrgId, SigningKeyId};
pub use inventory::{
    AvailableUpdate, Ecosystem, InstalledPackage, InventoryKind, InventoryUpload, PackageDelta,
    RemovedPackage, Repository, SystemFacts,
};
pub use job::{
    ApplyUpdates, DistUpgrade, HealthCheckReport, Job, JobAck, JobComplete, JobKind, JobSpec,
    JobStatus, PackageChange, PackagePin, Preflight, Reboot, RebootPolicy, Rollback, SelfUpdate,
    Snapshot, SnapshotPolicy,
};
pub use logs::{LogLine, LogStream};
pub use releases::{ReleaseChannel, ReleaseManifest};

/// The agent API path prefix.
pub const API_PATH: &str = "/agent/v1";

/// Value of the `Updawg-Protocol` header this crate speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Name of the protocol header.
pub const PROTOCOL_HEADER: &str = "Updawg-Protocol";

/// Longest a check-in is held open before the gateway replies with no jobs.
pub const CHECKIN_LONG_POLL_SECONDS: u64 = 55;

/// Lifetime of an issued client certificate.
pub const CLIENT_CERT_DAYS: u32 = 30;
