//! Collecting what a host has installed, and telling the gateway (DAWG-36).
//!
//! # Full or delta
//!
//! A full package list is 800–2,500 entries. Sending all of it every six hours,
//! from every host in a fleet, is most of what the gateway would receive — so
//! after the first upload the agent sends only what changed, naming the hash it
//! computed the change against.
//!
//! That base hash is the whole safety mechanism. If the server holds a different
//! one, it refuses with 409 and the agent sends a full inventory instead.
//! Applying a delta to an unknown base produces a package list that is subtly
//! wrong and stays wrong — and an inventory that is quietly wrong is worse than
//! one that is obviously missing, because a fleet dashboard built on it looks
//! exactly as convincing either way.
//!
//! # What is uploaded is what `updawgctl print-inventory` prints
//!
//! Not approximately. [`Collected::upload`] is the single description of what
//! leaves the host, and both the uploader and the command print the same value.
//! A customer who wants to know what Updawg collects can read it, and that
//! answer is only worth anything if it cannot drift from the truth.

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
    /// Packages an upgrade would remove rather than upgrade (DAWG-232).
    ///
    /// Almost always empty, and the times it is not are the times it matters:
    /// this is the difference between a proposal that installs something and
    /// one that takes something away.
    pub removals: Vec<PendingRemoval>,
    pub repositories: Vec<updawg_protocol::Repository>,
    pub held: Vec<String>,
    /// The packages the host's own package manager calls a security fix.
    ///
    /// Names rather than updates, because the two families answer the question in
    /// different places and only the backend knows which one applies — see
    /// [`updawg_backends::PackageBackend::security_updates`]. Not uploaded: it is
    /// a count on the heartbeat, and the server decides what a security update
    /// really is against advisory data.
    pub security: BTreeSet<String>,
    /// What pins the host's sources in time, if anything does (DAWG-233).
    pub frozen: Option<updawg_protocol::Frozen>,
}

impl Collected {
    /// Ask a host what it has, through a backend and a fact collector.
    ///
    /// The **one** description of what a collection pass is, called by the
    /// uploader and by `updawgctl print-inventory` alike. Building it in two
    /// places is how the command that answers "what does Updawg collect about my
    /// servers?" starts answering it about a slightly different collection — and
    /// that answer is only worth something if it cannot drift.
    ///
    /// # Errors
    /// Whatever the backend or the fact collector could not answer.
    pub async fn from_host(
        backend: &dyn PackageBackend,
        facts: &dyn FactCollector,
    ) -> anyhow::Result<Self> {
        // The updates first: which of them the package manager calls security is
        // a question about that list, and on both families it is answered from
        // the list rather than by asking again.
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
            // A hint about the updates, like an update's source: failing to
            // read it costs the hint, not the inventory.
            frozen: backend.frozen().await.unwrap_or_else(|e| {
                tracing::warn!(error = %e, "could not tell whether the package sources are pinned");
                None
            }),
        })
    }

    /// Hash of the package list, which is what a delta applies to.
    ///
    /// Only the packages. The updates and repositories are replaced wholesale on
    /// every upload, so including them would change the hash whenever a mirror
    /// published anything — and every host in the fleet would send a full
    /// inventory the next morning for no reason.
    #[must_use]
    pub fn hash(&self) -> String {
        updawg_crypto::content_hash(canonical(&self.packages).as_bytes())
    }

    /// How many updates are outstanding, and how many the package manager itself
    /// calls security.
    ///
    /// The second is a local hint for the heartbeat, not a classification: the
    /// authoritative answer is the server's, against advisory data. The
    /// distribution's own metadata is incomplete and inconsistent between
    /// families, which is why the server does not take this as the truth.
    ///
    /// Counted from [`Collected::security`], which the backend filled in, rather
    /// than by reading the pocket off each update here. Reading the pocket is
    /// apt's answer and **only** apt's: the RHEL family publishes security fixes
    /// to the same repository as everything else, so the same filter returns zero
    /// on every RHEL host, for ever, with nothing to notice. `security` is
    /// intersected with `updates` by the backend, so an advisory for something not
    /// upgradable here cannot push the count above `pending`.
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

    /// The upload to send, given what the host last sent.
    ///
    /// `None` for `previous` — first run, or the server refused our last delta —
    /// means a full inventory.
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
            // Sent every time, delta or not. They are a handful of short strings
            // and they are how the server notices a host was re-imaged into a
            // different release — the one change that matters most and the one a
            // package delta describes worst.
            facts: Some(self.facts.clone()),
            packages,
            updates: self.updates.clone(),
            repositories: self.repositories.clone(),
            held_packages: self.held.clone(),
            // Current state, like the updates, and sent on a delta as well: it
            // describes what the package manager would do now rather than what
            // changed since the last pass.
            removals: self.removals.clone(),
            // Current state too: a pin is lifted by editing a file, which no
            // package delta would show.
            frozen: self.frozen.clone(),
        }
    }
}

/// A package's identity for comparison: name, version and architecture.
///
/// All three. Two architectures of one package at one version are two installed
/// things, and an upgrade is a removal plus an addition rather than a change —
/// which is exactly how the server stores them.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key<'a>(&'a str, &'a str, &'a str);

impl<'a> Key<'a> {
    fn of(p: &'a InstalledPackage) -> Self {
        Self(&p.name, &p.version, &p.arch)
    }
}

/// The bytes the hash is taken over.
///
/// Sorted, because `dpkg-query` makes no promise about order and a hash that
/// changed when the order did would have every host sending a full inventory at
/// random. One line per package, tab-separated, with a trailing newline — no
/// field can contain a tab or a newline, so there is nothing to escape.
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

    /// Ask the host what it has, without sending anything.
    ///
    /// The same [`Collected::from_host`] that `updawgctl print-inventory` calls,
    /// so what it prints is what would be uploaded rather than a description of
    /// it.
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
        // What was sent in the end, for the log: a delta the gateway could
        // not apply is followed by a full inventory.
        let mut sent_delta = upload.base_hash.is_some();

        match self.transport.upload_inventory(&upload).await {
            Ok(()) => {}
            // The server holds a different base than we computed against. The
            // only way back into step is to send everything — retrying the delta
            // would fail the same way for ever.
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

        // Written only after the gateway has accepted it. If this is stored
        // first and the upload then fails, the next run computes a delta against
        // a state the server never received, and the two drift apart silently.
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
