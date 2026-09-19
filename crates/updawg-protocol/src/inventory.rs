//! Inventory: `PUT /agent/v1/inventory`.
//!
//! The list of what the agent reports is exhaustive by design. It never
//! collects file contents, environment variables, process arguments, user data
//! or credentials, and `updawgctl --print-inventory` prints exactly what these
//! types serialise to.
//!
//! Uploads are full or delta. A delta names the hash it was computed against;
//! if that does not match what the server holds, the server answers 409 with
//! [`ApiError::INVENTORY_BASE_MISMATCH`](crate::ApiError::INVENTORY_BASE_MISMATCH)
//! and the agent sends a full inventory instead. Blindly applying a delta to an
//! unknown base is how an inventory drifts silently.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    Deb,
    Rpm,
}

/// Platform facts, refreshed when they change rather than on a schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemFacts {
    pub hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fqdn: Option<String>,
    pub machine_id: String,
    pub distro: String,
    pub version_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codename: Option<String>,
    pub kernel: String,
    pub arch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtualization: Option<String>,
    pub ecosystem: Ecosystem,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub arch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
}

/// Enough to identify a package being removed, without repeating everything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovedPackage {
    pub name: String,
    pub version: String,
    pub arch: String,
}

/// A newer candidate version the package manager is offering.
///
/// Whether this counts as a security update, and how severe it is, is decided
/// server-side against advisory data. The agent's view is incomplete and
/// inconsistent between distros, so it reports what it sees and does not
/// editorialise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailableUpdate {
    pub name: String,
    pub arch: String,
    pub installed: String,
    pub candidate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Repository {
    pub id: String,
    pub kind: String,
    /// Not from the distro. These are what break a dist-upgrade when they have
    /// no packages for the target release.
    pub third_party: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PackageDelta {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added: Vec<InstalledPackage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<RemovedPackage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryKind {
    Full,
    Delta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryUpload {
    #[serde(rename = "type")]
    pub kind: InventoryKind,
    /// Hash this delta was computed against. Required for `Delta`, absent for
    /// `Full`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_hash: Option<String>,
    /// Hash of the resulting state.
    pub hash: String,
    pub collected_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facts: Option<SystemFacts>,
    /// For `Full`, `added` carries everything installed and `removed` is empty.
    #[serde(default)]
    pub packages: PackageDelta,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub updates: Vec<AvailableUpdate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repositories: Vec<Repository>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub held_packages: Vec<String>,
}

impl InventoryUpload {
    /// Whether this upload is internally consistent.
    ///
    /// A delta without a base hash cannot be applied safely, and a full
    /// inventory claiming a base is confused about what it is.
    #[must_use]
    pub fn is_coherent(&self) -> bool {
        match self.kind {
            InventoryKind::Full => self.base_hash.is_none() && self.packages.removed.is_empty(),
            InventoryKind::Delta => self.base_hash.is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upload(kind: InventoryKind, base: Option<&str>) -> InventoryUpload {
        InventoryUpload {
            kind,
            base_hash: base.map(Into::into),
            hash: "sha256:1b4f0e".into(),
            collected_at: Utc::now(),
            facts: None,
            packages: PackageDelta::default(),
            updates: vec![],
            repositories: vec![],
            held_packages: vec![],
        }
    }

    #[test]
    fn a_delta_without_a_base_hash_is_incoherent() {
        assert!(!upload(InventoryKind::Delta, None).is_coherent());
        assert!(upload(InventoryKind::Delta, Some("sha256:9f86d0")).is_coherent());
    }

    #[test]
    fn a_full_inventory_claiming_a_base_is_incoherent() {
        assert!(!upload(InventoryKind::Full, Some("sha256:9f86d0")).is_coherent());
        assert!(upload(InventoryKind::Full, None).is_coherent());
    }

    #[test]
    fn the_type_field_is_named_type_on_the_wire() {
        let json = serde_json::to_value(upload(InventoryKind::Delta, Some("x"))).unwrap();
        assert_eq!(json["type"], "delta");
    }
}
