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
    /// What the host's own package manager says this update fixes (DAWG-231).
    ///
    /// A **hint**, in the strict sense: it is what the vendor's metadata on
    /// this host happens to say, and the authoritative classification stays the
    /// server's, against advisory feeds. The server must not start reading this
    /// instead — a host's own metadata is exactly as incomplete as its vendor
    /// chose to make it, and a hint that became the answer would make the
    /// product's coverage depend on which mirror a customer happens to use.
    ///
    /// It is here because on the RHEL family there is nothing else. Debian and
    /// Ubuntu publish security fixes to a `-security` pocket, which [`repo`]
    /// already carries; Red Hat and its rebuilds publish a fix and a routine
    /// rebuild to the same `baseos`, so `repo` carries no signal at all and
    /// `dnf updateinfo` is the only local thing that does.
    ///
    /// A list rather than one, because a package can be behind several
    /// advisories at once — `dnf updateinfo` lists one per version, including
    /// versions between the installed one and the candidate, and all of them
    /// are fixed by taking the candidate.
    ///
    /// [`repo`]: AvailableUpdate::repo
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advisories: Vec<AdvisoryHint>,
}

/// One advisory the host's package manager attributes to an update.
///
/// Every field is **verbatim**. Normalising here would be a guess made on the
/// host, and a guess made on the host cannot be corrected later: Red Hat's
/// rebuilds say `Moderate` where Amazon Linux says `Medium` for the same band,
/// and deciding they are the same is the server's call against a feed it can
/// re-read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryHint {
    /// The vendor's advisory id: `RLSA-2026:60226`, `ALAS2023-2025-1194`.
    pub id: String,
    /// The vendor's severity word, unnormalised, and absent when there is none.
    ///
    /// **A bugfix has no severity at all.** Inventing one puts every routine
    /// rebuild on the same scale as a remote code execution, which is the exact
    /// noise that makes an operator stop reading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// `security`, `bugfix`, `enhancement`, or whatever else the package
    /// manager printed. A type nobody has seen before is worth reporting as
    /// itself rather than folded into one of the three.
    pub kind: String,
    /// The version this advisory fixes the package at, when the package manager
    /// names one. It may be **below** the candidate: several advisories can sit
    /// between what is installed and what would be installed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_in: Option<String>,
}

/// A package an upgrade would **remove** rather than move to a new version
/// (DAWG-232).
///
/// Its own list, not a shape of [`AvailableUpdate`], because an update has one
/// name and two versions and this is a removal and possibly an install. Folding
/// it into an update would put a name and two versions on a row that describes
/// neither, and it would be believed.
///
/// The invisible state is the dangerous one. A host with an obsoleted package
/// installed is a host where applying updates will take something away, and the
/// proposal carrying it should say so before anybody approves it rather than
/// after the job has run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRemoval {
    pub name: String,
    pub arch: String,
    /// The version installed now, which is what would go away.
    pub installed: String,
    /// What takes its place, **when the package manager names one**.
    ///
    /// dnf does: `check-update` prints the obsoleting package above the one it
    /// obsoletes. apt does not — a simulated `dist-upgrade` prints
    /// `Remv barpkg [1.0]` and nothing about what caused it, which is why this
    /// is an `Option` and not two more required fields. Captured from both
    /// families rather than assumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_by: Option<Replacement>,
}

/// The package that would be installed in place of a removed one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Replacement {
    pub name: String,
    pub arch: String,
    pub version: String,
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
    /// Packages an upgrade would remove rather than upgrade (DAWG-232).
    ///
    /// Current state, like [`updates`](InventoryUpload::updates), and sent in
    /// full on a delta as well as on a full inventory: it describes what the
    /// package manager would do now, not what changed since last time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removals: Vec<PendingRemoval>,
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
            removals: vec![],
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

#[cfg(test)]
mod wire_tests {
    use super::*;

    fn update() -> AvailableUpdate {
        AvailableUpdate {
            name: "attr".into(),
            arch: "aarch64".into(),
            installed: "2.5.1-3.el9".into(),
            candidate: "2.6.0-1.el9_8".into(),
            repo: Some("baseos".into()),
            advisories: vec![],
        }
    }

    #[test]
    fn an_update_with_no_advisory_hint_is_the_same_five_fields_as_before() {
        let json = serde_json::to_string(&update()).unwrap();
        assert!(!json.contains("advisories"), "{json}");
    }

    #[test]
    fn an_older_agent_sending_no_hints_parses_as_none_rather_than_failing() {
        let json = r#"{"name":"less","arch":"amd64","installed":"1","candidate":"2"}"#;
        let update: AvailableUpdate = serde_json::from_str(json).unwrap();
        assert!(update.advisories.is_empty());
        assert!(update.repo.is_none());
    }

    #[test]
    fn a_bugfix_carries_no_severity() {
        let hint = AdvisoryHint {
            id: "RLBA-2026:12345".into(),
            severity: None,
            kind: "bugfix".into(),
            fixed_in: Some("590-5.el9".into()),
        };
        let json = serde_json::to_string(&hint).unwrap();
        assert!(!json.contains("severity"), "{json}");
    }

    #[test]
    fn a_severity_word_is_not_normalised_on_the_way_past() {
        // Red Hat's rebuilds say Moderate where Amazon Linux says Medium for the
        // same band. Deciding they are the same is the server's job, against a
        // feed it can re-read; a guess made on the host cannot be corrected.
        for word in ["Moderate", "Medium", "Important", "Critical"] {
            let hint = AdvisoryHint {
                id: "X".into(),
                severity: Some(word.into()),
                kind: "security".into(),
                fixed_in: None,
            };
            let back: AdvisoryHint =
                serde_json::from_str(&serde_json::to_string(&hint).unwrap()).unwrap();
            assert_eq!(back.severity.as_deref(), Some(word));
        }
    }

    #[test]
    fn a_removal_can_name_no_replacement_because_apt_names_none() {
        let removal = PendingRemoval {
            name: "barpkg".into(),
            arch: "all".into(),
            installed: "1.0".into(),
            replaced_by: None,
        };
        let json = serde_json::to_string(&removal).unwrap();
        assert!(!json.contains("replaced_by"), "{json}");
        let back: PendingRemoval = serde_json::from_str(&json).unwrap();
        assert_eq!(back, removal);
    }

    #[test]
    fn a_removal_round_trips_with_its_replacement() {
        let removal = PendingRemoval {
            name: "oldthing".into(),
            arch: "noarch".into(),
            installed: "1.0-1.el9".into(),
            replaced_by: Some(Replacement {
                name: "newthing".into(),
                arch: "noarch".into(),
                version: "2.0-1.el9".into(),
                repo: Some("local".into()),
            }),
        };
        let back: PendingRemoval =
            serde_json::from_str(&serde_json::to_string(&removal).unwrap()).unwrap();
        assert_eq!(back, removal);
    }
}
