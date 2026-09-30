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
//! It also means adding one is a **breaking change to every struct literal**,
//! which is the price of the property above and is paid at compile time in two
//! repositories rather than at runtime in a customer's fleet.
//!
//! [`PROTOCOL_VERSION`] does **not** move for a field. It names the shape of
//! the conversation — the endpoints, the mTLS identity, what a 409 means — and
//! 0.2.0 added four optional fields to it: a shorter check-in hold the agent may
//! ask for (DAWG-205), what the local config permits (DAWG-223), the advisory
//! its package manager attributes to an update (DAWG-231), and the packages an
//! upgrade would remove rather than upgrade (DAWG-232). Every one of them is
//! absent-means-unknown in both directions, so a 0.1 agent and a 0.2 gateway
//! understand each other exactly as well as they did before.
//!
//! # ⚠️ What 0.3 breaks
//!
//! Two changes, both to what an organization signing key signs, both decided in
//! [ADR 0002] and both taken now because **there is no installed base**: no
//! organization outside ours has a key, nothing has signed a job in anger, and
//! no agent has pinned anything. That stops being true with the first enrolled
//! fleet, which is the reason to do it now rather than then.
//!
//! 1. **[`Job::signing_bytes`] now prefixes the document with a purpose label.**
//!    A 0.2 signature over a job does not verify under 0.3 and vice versa. The
//!    document itself is unchanged and is now [`Job::document`], which is what
//!    the server stores and delivers.
//! 2. **[`OrgSigningKey::endorsement`] is an [`Endorsement`], not a `String`.**
//!    It was a bare signature that nothing produced and nothing read — and
//!    could not have been read, because the statement it covered was not
//!    recoverable from anything the agent holds.
//!
//! Neither is a silent break at a peer: a 0.2 gateway and a 0.3 agent fail at
//! the first signature and the first enrollment respectively, loudly. There is
//! no version of this where one side quietly accepts the other.
//!
//! [ADR 0002]: https://github.com/Pez-Solutions/updawg-docs/blob/main/decisions/0002-signing-key-rotation-endorsements.md
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

#![doc(html_root_url = "https://docs.rs/updawg-protocol/0.3.0")]
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
    CheckinRequest, CheckinResponse, HostMetrics, HostStateReport, RebootRequired, SnapshotSupport,
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
pub use releases::{ReleaseChannel, ReleaseManifest};
pub use sign::SignaturePurpose;

/// The agent API path prefix.
pub const API_PATH: &str = "/agent/v1";

/// Value of the `Updawg-Protocol` header this crate speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Name of the protocol header.
pub const PROTOCOL_HEADER: &str = "Updawg-Protocol";

/// Longest a check-in is held open before the gateway replies with no jobs.
pub const CHECKIN_LONG_POLL_SECONDS: u64 = 55;

/// Shortest a check-in is held open, whatever the agent asks for.
///
/// The floor on [`CheckinRequest::hold_seconds`]. An agent that asked for zero
/// and was given zero would reconnect as fast as the network allows, for ever,
/// and the graph would look like a busy fleet rather than a bug.
pub const CHECKIN_MIN_HOLD_SECONDS: u64 = 5;

/// Lifetime of an issued client certificate.
pub const CLIENT_CERT_DAYS: u32 = 30;
