//! Inventory: what the agent reports about a host.
//!
//! The list here is exhaustive by design. The agent never collects file
//! contents, environment variables, process arguments, user data or
//! credentials, and `updawgctl --print-inventory` must print exactly what these
//! types serialise to. See DAWG-37 for the test that keeps that honest.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Which package manager family a host belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    Deb,
    Rpm,
}

/// Facts about the platform, collected at enrollment and refreshed on change.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SystemFacts {
    pub hostname: String,
    pub fqdn: Option<String>,
    pub machine_id: String,
    pub distro: String,
    pub version_id: String,
    pub codename: Option<String>,
    pub kernel: String,
    pub arch: String,
    pub virtualization: Option<String>,
    pub ecosystem: Ecosystem,
    pub collected_at: DateTime<Utc>,
}

/// One package currently installed on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub repository: Option<String>,
}

/// A newer candidate version available for an installed package.
///
/// The agent reports what the package manager offers. Whether it counts as a
/// security update, and how severe, is decided server-side against advisory
/// data, because the agent's view is incomplete and inconsistent across distros.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AvailableUpdate {
    pub name: String,
    pub current_version: String,
    pub candidate_version: String,
    pub arch: String,
    pub repository: Option<String>,
    /// e.g. the `-security` pocket on Debian-family hosts.
    pub origin: Option<String>,
}

/// A configured package repository, including third-party ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Repository {
    pub id: String,
    pub uri: String,
    pub enabled: bool,
    pub gpg_verified: bool,
}
