//! The facts needed to enroll, gathered before the host has an identity.
//!
//! Deliberately smaller than the full inventory. Enrollment needs just enough
//! to create the host record and tell one machine from another; everything else
//! arrives on the first inventory upload, after the host has a certificate and
//! the operator has had a chance to look at what is being sent.
//!
//! It reads the same sources as [`crate::facts`] through the same
//! [`platform`] module — one place that knows where `/etc/os-release` lives,
//! not two that can disagree.

use crate::{Result, platform};
use platform::Root;
use updawg_protocol::HostFacts;

/// What identifies this machine, before the server has named it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentFacts {
    /// `/etc/machine-id`. The server matches on this to recognise a host it has
    /// seen before, so a rebuilt machine keeps its history.
    pub machine_id: String,
    pub hostname: String,
    pub facts: HostFacts,
}

/// Reads the handful of files enrollment needs.
#[derive(Debug, Clone, Default)]
pub struct EnrollmentCollector {
    root: Root,
}

impl EnrollmentCollector {
    #[must_use]
    pub fn new(root: impl AsRef<std::path::Path>) -> Self {
        Self {
            root: Root::new(root),
        }
    }

    /// Gather everything `POST /enroll` needs.
    ///
    /// # Errors
    /// Fails if the machine id, hostname, kernel or distribution cannot be
    /// determined. All are required: enrolling a host whose identity or
    /// platform is unknown would create a record nobody can act on.
    pub fn gather(&self) -> Result<EnrollmentFacts> {
        let os = platform::os_release(&self.root)?;

        Ok(EnrollmentFacts {
            machine_id: platform::machine_id(&self.root)?,
            hostname: platform::hostname(&self.root)?,
            facts: HostFacts {
                distro: os.id,
                version: os.version_id,
                codename: os.codename,
                kernel: platform::kernel(&self.root)?,
                arch: platform::arch(),
                virtualization: platform::virtualization(&self.root),
                // Cloud metadata means talking to a link-local endpoint before
                // the host has enrolled. It belongs with the rest of the fact
                // collectors, where it can be disabled.
                cloud: None,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CollectorError, testing::FakeHost};

    #[test]
    fn a_debian_host_reports_the_facts_the_design_document_shows() {
        let host = FakeHost::debian();
        let got = EnrollmentCollector::new(host.path()).gather().unwrap();

        assert_eq!(got.machine_id, "3f2a9c1d4e5b6a7c8d9e0f1a2b3c4d5e");
        assert_eq!(got.hostname, "web-03");
        assert_eq!(got.facts.distro, "debian");
        assert_eq!(got.facts.version, "13");
        assert_eq!(got.facts.codename.as_deref(), Some("trixie"));
        assert_eq!(got.facts.kernel, "6.12.0-amd64");
        assert!(!got.facts.arch.is_empty());
    }

    /// A cloned golden image is the case this guards. systemd leaves
    /// `/etc/machine-id` empty on purpose so first boot fills it in; enrolling
    /// before that gives every clone the same identity.
    #[test]
    fn an_empty_machine_id_refuses_to_enroll() {
        let host = FakeHost::debian();
        host.write("etc/machine-id", "\n");
        let err = EnrollmentCollector::new(host.path()).gather().unwrap_err();
        assert!(
            matches!(err, CollectorError::SourceUnavailable { input } if input == "/etc/machine-id"),
            "got {err:?}"
        );
    }

    #[test]
    fn a_missing_machine_id_falls_back_to_the_dbus_copy() {
        let host = FakeHost::debian();
        std::fs::remove_file(host.root().join("etc/machine-id")).unwrap();
        host.write(
            "var/lib/dbus/machine-id",
            "aaaabbbbccccddddeeeeffff00001111",
        );

        let got = EnrollmentCollector::new(host.path()).gather().unwrap();
        assert_eq!(got.machine_id, "aaaabbbbccccddddeeeeffff00001111");
    }

    #[test]
    fn a_host_with_no_os_release_is_reported_clearly() {
        let host = FakeHost::debian();
        std::fs::remove_file(host.root().join("etc/os-release")).unwrap();
        let err = EnrollmentCollector::new(host.path()).gather().unwrap_err();
        assert!(
            matches!(err, CollectorError::SourceUnavailable { input } if input == "/etc/os-release"),
            "got {err:?}"
        );
    }

    /// Enrollment and the full inventory must agree about what this host is.
    /// They read the same sources through the same module; this is the test
    /// that keeps it that way.
    #[test]
    fn enrollment_facts_match_the_platform_facts_for_the_same_host() {
        let host = FakeHost::ubuntu();
        let enrolling = EnrollmentCollector::new(host.path()).gather().unwrap();
        let full = crate::PlatformFacts::new(host.root()).gather().unwrap();

        assert_eq!(enrolling.machine_id, full.machine_id);
        assert_eq!(enrolling.hostname, full.hostname);
        assert_eq!(enrolling.facts.distro, full.distro);
        assert_eq!(enrolling.facts.version, full.version_id);
        assert_eq!(enrolling.facts.codename, full.codename);
        assert_eq!(enrolling.facts.kernel, full.kernel);
        assert_eq!(enrolling.facts.arch, full.arch);
    }
}
