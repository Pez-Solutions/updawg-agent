//! Debian-family backend.
//!
//! Installed packages come from `dpkg-query -W` with a tab-separated format
//! string, candidates from a simulated `apt-get -s dist-upgrade`, and
//! repository origin from `apt-cache policy`.
//!
//! Implemented by DAWG-34.

use crate::{ApplyOutcome, ApplyPlan, BackendError, LogSink, PackageBackend, Result};
use async_trait::async_trait;
use updawg_protocol::{AvailableUpdate, Ecosystem, InstalledPackage, Repository};

#[derive(Debug, Default, Clone)]
pub struct AptBackend {
    _private: (),
}

impl AptBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PackageBackend for AptBackend {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Deb
    }

    async fn installed(&self) -> Result<Vec<InstalledPackage>> {
        Err(BackendError::ToolMissing {
            tool: "dpkg-query (DAWG-34)",
        })
    }

    async fn refresh_metadata(&self) -> Result<()> {
        Err(BackendError::ToolMissing {
            tool: "apt-get (DAWG-34)",
        })
    }

    async fn available_updates(&self) -> Result<Vec<AvailableUpdate>> {
        Err(BackendError::ToolMissing {
            tool: "apt-get (DAWG-34)",
        })
    }

    async fn repositories(&self) -> Result<Vec<Repository>> {
        Err(BackendError::ToolMissing {
            tool: "apt-cache (DAWG-34)",
        })
    }

    async fn apply(&self, _plan: &ApplyPlan, _log: &dyn LogSink) -> Result<ApplyOutcome> {
        Err(BackendError::ToolMissing {
            tool: "apt-get (DAWG-34)",
        })
    }
}
