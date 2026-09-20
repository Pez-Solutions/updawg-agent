//! RHEL-family backend.
//!
//! Installed packages come from `rpm -qa --qf`, candidates from `dnf
//! check-update`, and advisory hints from `dnf updateinfo`.

//!
//! Implemented by DAWG-35.

use crate::{ApplyOutcome, ApplyPlan, BackendError, LogSink, PackageBackend, Result};
use async_trait::async_trait;
use updawg_protocol::{AvailableUpdate, Ecosystem, InstalledPackage, Repository};

#[derive(Debug, Default, Clone)]
pub struct DnfBackend {
    _private: (),
}

impl DnfBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PackageBackend for DnfBackend {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Rpm
    }

    async fn installed(&self) -> Result<Vec<InstalledPackage>> {
        Err(BackendError::ToolMissing {
            tool: "rpm (DAWG-35)",
        })
    }

    async fn refresh_metadata(&self) -> Result<()> {
        Err(BackendError::ToolMissing {
            tool: "dnf (DAWG-35)",
        })
    }

    async fn available_updates(&self) -> Result<Vec<AvailableUpdate>> {
        Err(BackendError::ToolMissing {
            tool: "dnf (DAWG-35)",
        })
    }

    async fn held_packages(&self) -> Result<Vec<String>> {
        // `dnf versionlock list`, once DAWG-35 lands. Reporting an empty list
        // here would be a lie with consequences: the server would plan an upgrade
        // for a package that is locked, the job would report success, and the
        // version would not move.
        Err(BackendError::ToolMissing {
            tool: "dnf versionlock (DAWG-35)",
        })
    }

    async fn repositories(&self) -> Result<Vec<Repository>> {
        Err(BackendError::ToolMissing {
            tool: "dnf (DAWG-35)",
        })
    }

    async fn apply(&self, _plan: &ApplyPlan, _log: &dyn LogSink) -> Result<ApplyOutcome> {
        Err(BackendError::ToolMissing {
            tool: "dnf (DAWG-35)",
        })
    }
}
