//! Platform facts: what this machine is.
//!
//! Sent with a full inventory rather than on every check-in, because these
//! change on the order of never. The exhaustive list of what is collected lives
//! in [`SystemFacts`]; anything not represented there is not gathered, and that
//! is a promise `updawgctl --print-inventory` exists to make checkable.
//!
//! What is deliberately absent is as much the point as what is present: no file
//! contents, no environment, no process arguments, no user data. A host's
//! operator should be able to read this module in a few minutes and be
//! satisfied.

use crate::{Collector, FactCollector, Result, platform};
use async_trait::async_trait;
use platform::Root;
use updawg_protocol::SystemFacts;

/// Reads the platform facts.
#[derive(Debug, Clone, Default)]
pub struct PlatformFacts {
    root: Root,
}

impl PlatformFacts {
    #[must_use]
    pub fn new(root: Root) -> Self {
        Self { root }
    }

    /// Gather everything, synchronously.
    ///
    /// # Errors
    /// Fails only on the facts nothing downstream works without: the machine
    /// id, the distribution, the kernel and the package ecosystem. Everything
    /// optional degrades to absent.
    pub fn gather(&self) -> Result<SystemFacts> {
        let os = platform::os_release(&self.root)?;

        let virtualization = platform::virtualization(&self.root);
        if virtualization.is_none() {
            // Not an error and not "bare metal" — we could not tell. Worth a
            // line, because it is the sort of gap that gets noticed much later.
            tracing::debug!("could not determine virtualization for this host");
        }

        Ok(SystemFacts {
            hostname: platform::hostname(&self.root)?,
            fqdn: platform::fqdn(&self.root),
            machine_id: platform::machine_id(&self.root)?,
            distro: os.id,
            version_id: os.version_id,
            codename: os.codename,
            kernel: platform::kernel(&self.root)?,
            arch: platform::arch(),
            virtualization,
            ecosystem: platform::ecosystem(&self.root)?,
        })
    }
}

#[async_trait]
impl Collector for PlatformFacts {
    fn name(&self) -> &'static str {
        "platform-facts"
    }

    async fn is_available(&self) -> bool {
        platform::os_release(&self.root).is_ok()
    }
}

#[async_trait]
impl FactCollector for PlatformFacts {
    async fn facts(&self) -> Result<SystemFacts> {
        self.gather()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CollectorError;
    use crate::testing::FakeHost;
    use updawg_protocol::Ecosystem;

    #[tokio::test]
    async fn a_debian_host_reports_every_platform_fact() {
        let host = FakeHost::debian();
        let facts = PlatformFacts::new(host.root()).facts().await.unwrap();

        assert_eq!(facts.hostname, "web-03");
        assert_eq!(facts.machine_id, "3f2a9c1d4e5b6a7c8d9e0f1a2b3c4d5e");
        assert_eq!(facts.distro, "debian");
        assert_eq!(facts.version_id, "13");
        assert_eq!(facts.codename.as_deref(), Some("trixie"));
        assert_eq!(facts.kernel, "6.12.0-amd64");
        assert_eq!(facts.ecosystem, Ecosystem::Deb);
        assert!(!facts.arch.is_empty());
    }

    #[tokio::test]
    async fn a_rhel_family_host_reports_the_rpm_ecosystem() {
        let host = FakeHost::rocky();
        let facts = PlatformFacts::new(host.root()).facts().await.unwrap();

        assert_eq!(facts.distro, "rocky");
        assert_eq!(facts.version_id, "9.4");
        assert_eq!(facts.ecosystem, Ecosystem::Rpm);
    }

    #[tokio::test]
    async fn amazon_linux_is_collected_like_any_other_rpm_host() {
        let host = FakeHost::amazon();
        let facts = PlatformFacts::new(host.root()).facts().await.unwrap();

        assert_eq!(facts.distro, "amzn");
        assert_eq!(facts.version_id, "2023");
        assert_eq!(facts.ecosystem, Ecosystem::Rpm);
        // Amazon Linux has no VERSION_CODENAME, which is absence, not failure.
        assert_eq!(facts.codename, None);
    }

    #[tokio::test]
    async fn virtualization_is_read_from_sys_when_there_is_no_systemd() {
        let host = FakeHost::debian();
        host.write("sys/class/dmi/id/product_name", "KVM\n");
        let facts = PlatformFacts::new(host.root()).facts().await.unwrap();
        assert_eq!(facts.virtualization.as_deref(), Some("kvm"));
    }

    /// Bare metal and "could not tell" are both `None` on the wire, but the
    /// collector must not invent a hypervisor for a machine that has none.
    #[tokio::test]
    async fn bare_metal_reports_no_virtualization_rather_than_guessing() {
        let host = FakeHost::debian();
        host.write("sys/class/dmi/id/product_name", "PowerEdge R640\n");
        let facts = PlatformFacts::new(host.root()).facts().await.unwrap();
        assert_eq!(facts.virtualization, None);
    }

    #[tokio::test]
    async fn an_fqdn_is_optional() {
        let host = FakeHost::debian();
        let facts = PlatformFacts::new(host.root()).facts().await.unwrap();
        // The fixture root never shells out, so there is no FQDN to find.
        assert_eq!(facts.fqdn, None);
    }

    #[tokio::test]
    async fn a_host_with_neither_dpkg_nor_rpm_is_reported_clearly() {
        let host = FakeHost::debian();
        std::fs::remove_file(host.root().join("usr/bin/dpkg")).unwrap();
        let err = PlatformFacts::new(host.root()).facts().await.unwrap_err();
        assert!(
            matches!(err, CollectorError::SourceUnavailable { input } if input == "dpkg or rpm"),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn availability_is_reported_without_collecting() {
        let host = FakeHost::debian();
        assert!(PlatformFacts::new(host.root()).is_available().await);

        let bare = FakeHost::empty();
        assert!(!PlatformFacts::new(bare.root()).is_available().await);
    }

    /// The cloned-golden-image case. systemd leaves this file empty on purpose
    /// so first boot fills it in; collecting before that gives every clone the
    /// same identity.
    #[tokio::test]
    async fn an_empty_machine_id_is_refused() {
        let host = FakeHost::debian();
        host.write("etc/machine-id", "\n");
        let err = PlatformFacts::new(host.root()).facts().await.unwrap_err();
        assert!(
            matches!(err, CollectorError::SourceUnavailable { .. }),
            "got {err:?}"
        );
    }
}
