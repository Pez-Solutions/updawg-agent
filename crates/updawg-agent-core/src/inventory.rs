//! Collecting the host's package inventory and uploading it to the gateway.
//!
//! # Full or delta
//!
//! A full package list is 800 to 2,500 entries, and most of the gateway's
//! traffic would be full lists if every host sent one every six hours. After
//! the first upload the agent sends only the changes, along with the hash of
//! the inventory it diffed against.
//!
//! If the server holds a different base hash it answers 409 and the agent
//! sends a full inventory. Applying a delta to the wrong base would leave a
//! package list that is wrong in ways nobody would notice.
//!
//! # `updawgctl print-inventory`
//!
//! [`Collected::upload`] builds what leaves the host, and both the uploader
//! and `print-inventory` use it, so the command shows exactly what is sent.

use crate::{
    scheduler::Inventory,
    state::{InventorySnapshot, LocalState},
    transport::MtlsTransport,
};
use async_trait::async_trait;
use std::{collections::BTreeSet, sync::Arc};
use updawg_backends::PackageBackend;
use updawg_collectors::FactCollector;
use updawg_protocol::{
    InstalledPackage, InventoryKind, InventoryUpload, PackageDelta, PendingRemoval, RemovedPackage,
    SystemFacts,
};

/// Everything one collection pass gathered.
#[derive(Debug, Clone)]
pub struct Collected {
    pub facts: SystemFacts,
    pub packages: Vec<InstalledPackage>,
    pub updates: Vec<updawg_protocol::AvailableUpdate>,
    /// Packages an upgrade would remove. Usually empty.
    pub removals: Vec<PendingRemoval>,
    pub repositories: Vec<updawg_protocol::Repository>,
    pub held: Vec<String>,
    /// Names of the updates the host's package manager marks as security
    /// fixes (see [`updawg_backends::PackageBackend::security_updates`]).
    ///
    /// Not uploaded. It only feeds the count on the heartbeat; the server
    /// classifies updates itself from advisory data.
    pub security: BTreeSet<String>,
    /// Set if the host's sources are pinned to a point in time.
    pub frozen: Option<updawg_protocol::Frozen>,
    /// The backend's [`reports_modules`](PackageBackend::reports_modules).
    pub modules_reported: bool,
}

impl Collected {
    /// Runs one collection pass. Shared by the uploader and
    /// `updawgctl print-inventory` so the two can't drift apart.
    ///
    /// # Errors
    /// Whatever the backend or the fact collector could not answer.
    pub async fn from_host(
        backend: &dyn PackageBackend,
        facts: &dyn FactCollector,
    ) -> anyhow::Result<Self> {
        // security status is derived from the pending list on both families
        let changes = backend.pending_changes().await?;
        let security = backend.security_updates(&changes.updates).await?;
        Ok(Self {
            facts: facts.facts().await?,
            packages: backend.installed().await?,
            updates: changes.updates,
            removals: changes.removals,
            security,
            repositories: backend.repositories().await?,
            held: backend.held_packages().await?,
            // only a hint, so don't fail the inventory over it
            frozen: backend.frozen().await.unwrap_or_else(|e| {
                tracing::warn!(error = %e, "could not tell whether the package sources are pinned");
                None
            }),
            modules_reported: backend.reports_modules(),
        })
    }

    /// Hash of the package list, which deltas are computed against.
    ///
    /// Updates and repositories are left out. They are replaced on every upload
    /// anyway, and including them would change the hash whenever a mirror
    /// published something, forcing a full upload from every host.
    #[must_use]
    pub fn hash(&self) -> String {
        updawg_crypto::content_hash(canonical(&self.packages).as_bytes())
    }

    /// Pending updates, and how many of them the package manager marks as
    /// security fixes.
    ///
    /// The security count is a hint for the heartbeat. Distro metadata is
    /// incomplete and differs between families, so the server classifies
    /// updates itself from advisory data.
    ///
    /// Uses [`Collected::security`] from the backend instead of checking each
    /// update's pocket here: only apt has security pockets, and RHEL-family
    /// repos mix security fixes in with everything else, so a pocket filter
    /// would always give 0 there. Counting only names in `updates` keeps the
    /// result at or below `pending`.
    #[must_use]
    pub fn counts(&self) -> (u32, u32) {
        let pending = u32::try_from(self.updates.len()).unwrap_or(u32::MAX);
        let security = self
            .updates
            .iter()
            .filter(|u| self.security.contains(&u.name))
            .count();
        (pending, u32::try_from(security).unwrap_or(u32::MAX))
    }

    /// Builds the upload. With `previous` set to `None` (first run, or the
    /// server rejected the last delta) it is a full inventory.
    #[must_use]
    pub fn upload(&self, previous: Option<&InventorySnapshot>) -> InventoryUpload {
        let hash = self.hash();
        let collected_at = chrono::Utc::now();

        let packages = match previous {
            Some(previous) => {
                let before: BTreeSet<Key> = previous.packages.iter().map(Key::of).collect();
                let now: BTreeSet<Key> = self.packages.iter().map(Key::of).collect();

                PackageDelta {
                    added: self
                        .packages
                        .iter()
                        .filter(|p| !before.contains(&Key::of(p)))
                        .cloned()
                        .collect(),
                    removed: previous
                        .packages
                        .iter()
                        .filter(|p| !now.contains(&Key::of(p)))
                        .map(|p| RemovedPackage {
                            name: p.name.clone(),
                            version: p.version.clone(),
                            arch: p.arch.clone(),
                        })
                        .collect(),
                }
            }
            None => PackageDelta {
                added: self.packages.clone(),
                removed: Vec::new(),
            },
        };

        InventoryUpload {
            kind: if previous.is_some() {
                InventoryKind::Delta
            } else {
                InventoryKind::Full
            },
            base_hash: previous.map(|p| p.hash.clone()),
            hash,
            collected_at,
            // always sent: they're small, and they're how the server notices
            // a host was reinstalled with a different release
            facts: Some(self.facts.clone()),
            packages,
            updates: self.updates.clone(),
            repositories: self.repositories.clone(),
            held_packages: self.held.clone(),
            // removals and frozen are current state, sent on deltas too
            removals: self.removals.clone(),
            frozen: self.frozen.clone(),
            // module streams aren't part of a package's identity, so a delta
            // won't carry them; the server asks for a full inventory the first
            // time a host reports this
            modules_reported: self.modules_reported,
        }
    }
}

/// Package identity for diffing: name, version and arch. An upgrade shows up
/// as a removal plus an addition, which matches how the server stores them.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key<'a>(&'a str, &'a str, &'a str);

impl<'a> Key<'a> {
    fn of(p: &'a InstalledPackage) -> Self {
        Self(&p.name, &p.version, &p.arch)
    }
}

/// Input to the inventory hash: one tab-separated line per package, sorted
/// (`dpkg-query` output order isn't stable), with a trailing newline. Fields
/// can't contain tabs or newlines, so nothing needs escaping.
fn canonical(packages: &[InstalledPackage]) -> String {
    let mut lines: Vec<String> = packages
        .iter()
        .map(|p| format!("{}\t{}\t{}", p.name, p.version, p.arch))
        .collect();
    lines.sort_unstable();
    lines.dedup();
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Collects from the package backend and uploads to the gateway.
pub struct GatewayInventory {
    transport: Arc<MtlsTransport>,
    state: LocalState,
    backend: Arc<dyn PackageBackend>,
    facts: Arc<dyn FactCollector>,
}

impl std::fmt::Debug for GatewayInventory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayInventory").finish_non_exhaustive()
    }
}

impl GatewayInventory {
    #[must_use]
    pub fn new(
        transport: Arc<MtlsTransport>,
        state: LocalState,
        backend: Arc<dyn PackageBackend>,
        facts: Arc<dyn FactCollector>,
    ) -> Self {
        Self {
            transport,
            state,
            backend,
            facts,
        }
    }

    /// Collects without uploading, via [`Collected::from_host`].
    pub async fn collect(&self) -> anyhow::Result<Collected> {
        Collected::from_host(self.backend.as_ref(), self.facts.as_ref()).await
    }
}

#[async_trait]
impl Inventory for GatewayInventory {
    async fn collect_and_upload(&self) -> anyhow::Result<()> {
        let collected = self.collect().await?;
        let previous = self.state.inventory_snapshot()?;

        let upload = collected.upload(previous.as_ref());
        let mut sent_delta = upload.base_hash.is_some();

        match self.transport.upload_inventory(&upload).await {
            Ok(()) => {}
            // retrying the delta would fail forever; resync with a full one
            Err(e) if e.is_inventory_base_mismatch() => {
                tracing::warn!(
                    "the gateway does not hold the inventory this delta was computed against; \
                     sending a full one"
                );
                self.state.clear_inventory_snapshot()?;
                let full = collected.upload(None);
                self.transport.upload_inventory(&full).await?;
                sent_delta = false;
            }
            Err(e) => return Err(e.into()),
        }

        let (pending_updates, security_updates) = collected.counts();
        let hash = collected.hash();

        // only after the gateway accepted it, or the next delta would be
        // computed against something the server never got
        self.state.set_inventory_snapshot(&InventorySnapshot {
            hash: hash.clone(),
            packages: collected.packages,
            pending_updates,
            security_updates,
        })?;
        self.state.set_inventory_hash(&hash)?;

        tracing::info!(
            delta = sent_delta,
            packages = self
                .state
                .inventory_snapshot()?
                .map_or(0, |s| s.packages.len()),
            pending_updates,
            security_updates,
            "inventory uploaded"
        );
        Ok(())
    }

    async fn refresh_metadata(&self) -> anyhow::Result<()> {
        self.backend.refresh_metadata().await?;
        Ok(())
    }
}
