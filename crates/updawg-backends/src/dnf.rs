//! RHEL-family backend.
//!
//! Installed packages come from `rpm -qa` with a format string, candidates from
//! `dnf repoquery --upgrades`, repository origin from `dnf repolist -v`, advisory
//! hints from `dnf updateinfo`, obsoletions from `dnf check-update --obsoletes`,
//! and holds from `dnf versionlock list`.
//!
//! As in [`crate::apt`], parsing is done by plain functions over `&str`, tested
//! against output captured from Rocky 8, Rocky 9 and Amazon Linux 2023
//! containers (`tests/fixtures/dnf/`).
//!
//! # Why `repoquery --upgrades` and not `check-update`
//!
//! `dnf check-update` prints a padded table for terminals, and it wraps. A
//! package whose `name.arch` is wider than the first column gets its own line,
//! with the version and repository indented on the next:
//!
//! ```text
//! elfutils-default-yama-scope.noarch
//!                                   0.188-3.amzn2023.0.3   amazonlinux
//! ```
//!
//! A three-fields-per-line parser silently drops those. `repoquery --qf`
//! prints exactly the requested fields, one record per line.
//!
//! `--latest-limit=1` is required. Without it `repoquery --upgrades` returns
//! every newer version in the repositories, not just the one `dnf upgrade`
//! would install: 77 records for 38 packages on a stock Rocky 9 container
//! (three for `glib2`). With it the set matches `check-update` exactly;
//! `tests/dnf.rs` and `tests/dnf_live.rs` check this.
//!
//! dnf deduplicates identical output lines, so counting with
//! `--qf '%{name}.%{arch}'` gives 38 either way. The duplicates only show up
//! once the version is in the format.
//!
//! # Obsoletes
//!
//! `repoquery --upgrades` doesn't report obsoletes, and no `--qf` names both
//! sides of one. `check-update --obsoletes` does, under an
//! `Obsoleting Packages` heading, so [`parse_obsoletes`] reads that (and
//! handles the wrapping by not parsing line by line).
//!
//! `dnf check-update` exits 100 when there are updates, hence [`run_ok`].
//!
//! # Security classification
//!
//! The security flag is only what dnf's `updateinfo` says; the server makes
//! the real call from advisory data. The RHEL family has no security pocket
//! (fixes and bugfixes both go to `baseos`), so [`AvailableUpdate::repo`]
//! says nothing about it and `updateinfo` is the only local signal.

use crate::{
    ApplyOutcome, ApplyPlan, BackendError, Change, LogSink, PackageBackend, PendingChanges, Pin,
    Result, apt::Ran,
};
use async_trait::async_trait;
use std::collections::{BTreeMap, BTreeSet};
use updawg_protocol::{
    AdvisoryHint, AvailableUpdate, Ecosystem, InstalledPackage, PendingRemoval, Replacement,
    Repository,
};

#[derive(Debug, Default, Clone)]
pub struct DnfBackend {
    /// The distribution's name from `/etc/os-release` (`Rocky Linux`,
    /// `Amazon Linux`, `Red Hat Enterprise Linux`). Repositories not named
    /// after it are third-party.
    distro: Option<String>,
}

impl DnfBackend {
    #[must_use]
    pub fn new() -> Self {
        Self {
            distro: distro_name(&std::fs::read_to_string("/etc/os-release").unwrap_or_default()),
        }
    }
}

#[async_trait]
impl PackageBackend for DnfBackend {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Rpm
    }

    async fn installed(&self) -> Result<Vec<InstalledPackage>> {
        let out = run("rpm", &["-qa", "--qf", RPM_QF]).await?;
        Ok(parse_installed(&out))
    }

    fn reports_modules(&self) -> bool {
        true
    }

    async fn refresh_metadata(&self) -> Result<()> {
        run("dnf", &["-q", "makecache"]).await.map(|_| ())
    }

    async fn pending_changes(&self) -> Result<PendingChanges> {
        // repoquery doesn't report the installed version, so read it here.
        // `rpm -qa` is local and cheap.
        let installed = self.installed().await?;
        let out = run(
            "dnf",
            &[
                "-q",
                "repoquery",
                "--upgrades",
                "--latest-limit=1",
                "--qf",
                REPOQUERY_QF,
            ],
        )
        .await?;
        let mut updates = parse_upgrades(&out, &installed);

        // Skip updateinfo when there's nothing to upgrade, the usual case
        // (and permanently so on an Amazon Linux host pinned to a release).
        if !updates.is_empty() {
            let out = run("dnf", &["-q", "updateinfo", "list", "--available"]).await?;
            attach_advisories(&mut updates, &parse_updateinfo(&out));
        }

        let out = run_ok(
            "dnf",
            &["-q", "check-update", "--obsoletes"],
            // 100 means updates are available
            &[100],
        )
        .await?;
        Ok(PendingChanges {
            removals: parse_obsoletes(&out, &installed),
            updates,
        })
    }

    async fn repositories(&self) -> Result<Vec<Repository>> {
        let out = run("dnf", &["-q", "repolist", "--all", "-v"]).await?;
        Ok(parse_repositories(&out, self.distro.as_deref()))
    }

    /// Pinned by `/etc/dnf/vars/releasever` if set. On Amazon Linux 2023
    /// hosts are pinned to the installed release unless set to `latest`, and
    /// `dnf check-release-update` gives the newest available.
    async fn frozen(&self) -> Result<Option<updawg_protocol::Frozen>> {
        let file = std::fs::read_to_string(RELEASEVER)
            .ok()
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty());
        if file.as_deref() == Some("latest") {
            return Ok(None);
        }
        let amazon = crate::release::this_host()
            .is_ok_and(|h| h.id == "amzn" && h.version.starts_with("2023"));
        if !amazon {
            return Ok(file.map(|pinned| updawg_protocol::Frozen {
                kind: updawg_protocol::FrozenKind::Releasever,
                pinned,
                latest: None,
            }));
        }
        let pinned = match file {
            Some(pinned) => pinned,
            None => run("rpm", &["-q", "--qf", "%{VERSION}", "system-release"])
                .await?
                .trim()
                .to_owned(),
        };
        // If this fails, still report the pin, just without `latest`.
        let asked = run_status("dnf", &["check-release-update".to_owned()]).await?;
        let latest = (asked.code == 0).then(|| {
            newest_release(&format!("{}{}", asked.stdout, asked.stderr))
                .map_or_else(|| pinned.clone(), str::to_owned)
        });
        Ok(Some(updawg_protocol::Frozen {
            kind: updawg_protocol::FrozenKind::Releasever,
            pinned,
            latest,
        }))
    }

    async fn held_packages(&self) -> Result<Vec<String>> {
        match run("dnf", &["-q", "versionlock", "list"]).await {
            Ok(out) => Ok(parse_holds(&out)),
            // versionlock is an optional plugin. Without it nothing can be
            // locked, so an empty list is correct.
            Err(BackendError::CommandFailed { ref stderr, .. })
                if stderr.contains("No such command: versionlock") =>
            {
                Ok(Vec::new())
            }
            Err(e) => Err(e),
        }
    }

    async fn security_updates(&self, updates: &[AvailableUpdate]) -> Result<BTreeSet<String>> {
        // Use the advisories `pending_changes` already attached. Asking
        // updateinfo again could disagree if a repository published in
        // between.
        Ok(updates
            .iter()
            .filter(|u| u.advisories.iter().any(|a| a.kind == SECURITY))
            .map(|u| u.name.clone())
            .collect())
    }

    /// Leapp: see [`crate::leapp_upgrade`].
    fn upgrade_finishes_at_reboot(&self) -> bool {
        true
    }

    async fn release_upgrade_blockers(&self, target: &str) -> Result<Vec<String>> {
        let host = crate::release::this_host()?;
        crate::leapp_upgrade::blockers(self, &host, target).await
    }

    async fn dist_upgrade(&self, target: &str, log: &dyn LogSink) -> Result<ApplyOutcome> {
        crate::leapp_upgrade::upgrade(self, target, log).await
    }

    async fn check_pins(&self, pins: &[Pin]) -> Result<Vec<String>> {
        let before = installed_versions(pins).await?;
        let todo = still_to_do(pins, &before)?;
        if todo.is_empty() {
            return Ok(vec![]);
        }
        let simulated = run_status("dnf", &simulate_args(&todo)).await?;
        check_transaction(&todo, &simulated)?;
        Ok(vec![])
    }

    /// Installs exactly the approved versions, or nothing. Same steps as
    /// [`crate::apt`]:
    ///
    /// 1. Each pin must be at `from` (or already at `to`, which is skipped),
    ///    per `rpm -q`.
    /// 2. `dnf install --assumeno` with the exact command line must upgrade
    ///    only the remaining pins, to exactly their versions. On Rocky 9,
    ///    asking for `openssl-libs` alone also upgrades `openssl` and
    ///    `openssl-fips-provider`, which gets refused.
    /// 3. Run it with `-y`. Weak dependencies are off in both runs.
    /// 4. Each pin must now be at `to`.
    async fn apply(&self, plan: &ApplyPlan, log: &dyn LogSink) -> Result<ApplyOutcome> {
        let before = installed_versions(&plan.packages).await?;
        let todo = still_to_do(&plan.packages, &before)?;
        if todo.is_empty() {
            log.line("every approved version is already installed; nothing to do");
            return Ok(ApplyOutcome {
                changed: vec![],
                reboot_required: reboot_required().await,
                after_reboot: None,
            });
        }

        let simulated = run_status("dnf", &simulate_args(&todo)).await?;
        check_transaction(&todo, &simulated)?;

        log.line(&format!(
            "installing {} package(s) at their approved versions",
            todo.len()
        ));
        let installed = run_status("dnf", &install_args(&todo)).await?;
        for line in crate::apt::as_shown(&installed.stdout) {
            log.line(line);
        }
        if installed.code != 0 {
            if is_locked(&installed.stderr) {
                return Err(BackendError::Locked);
            }
            return Err(BackendError::CommandFailed {
                tool: "dnf",
                status: installed.code,
                stderr: installed.stderr,
            });
        }

        let after = installed_versions(&plan.packages).await?;
        let changed = changes(&todo, &after)?;
        Ok(ApplyOutcome {
            changed,
            reboot_required: reboot_required().await,
            after_reboot: None,
        })
    }
}

/// `rpm -qa` format: name, `[epoch:]version-release`, architecture, module.
///
/// `%|EPOCH?{...}|` prints the epoch only when there is one, which matches
/// dnf's `%{evr}`, so installed and candidate versions compare cleanly.
const RPM_QF: &str =
    "%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{ARCH}\t%{MODULARITYLABEL}\n";

/// `dnf repoquery` format: name, `[epoch:]version-release`, architecture, repo.
///
/// No trailing newline: `repoquery` adds one itself.
const REPOQUERY_QF: &str = "%{name}\t%{evr}\t%{arch}\t%{reponame}";

/// `rpm -qa --qf` output: name, EVR, architecture, modularity label.
///
/// Entries with arch `(none)` are skipped. That's how rpm lists imported
/// signing keys (`gpg-pubkey`) and similar pseudo-packages.
#[must_use]
pub fn parse_installed(out: &str) -> Vec<InstalledPackage> {
    out.lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let name = fields.next()?;
            let version = fields.next()?;
            let arch = fields.next()?;
            let label = fields.next().unwrap_or_default();
            if name.is_empty() || version.is_empty() || arch == "(none)" {
                return None;
            }
            Some(InstalledPackage {
                name: name.to_owned(),
                version: version.to_owned(),
                arch: arch.to_owned(),
                // rpm only knows the repo if dnf installed it, so leave it
                // out as with dpkg.
                repo: None,
                // SOURCERPM is a file name, not name and version
                source: None,
                module: module_stream(label),
            })
        })
        .collect()
}

/// `name:stream` from rpm's `MODULARITYLABEL` (`name:stream:version:context`).
/// `(none)`, rpm's value for a missing tag, means not modular.
fn module_stream(label: &str) -> Option<String> {
    let mut parts = label.split(':');
    let (Some(name), Some(stream)) = (parts.next(), parts.next()) else {
        return None;
    };
    if name.is_empty() || stream.is_empty() || name == "(none)" {
        return None;
    }
    Some(format!("{name}:{stream}"))
}

/// `dnf repoquery --upgrades --latest-limit=1 --qf` output, joined to what is
/// installed.
///
/// Candidates for packages that aren't installed are dropped (`--upgrades`
/// shouldn't produce any). Keyed on name and arch, since on a multilib host
/// `glibc.i686` and `glibc.x86_64` upgrade independently.
#[must_use]
pub fn parse_upgrades(out: &str, installed: &[InstalledPackage]) -> Vec<AvailableUpdate> {
    let have: BTreeMap<(&str, &str), &str> = installed
        .iter()
        .map(|p| ((p.name.as_str(), p.arch.as_str()), p.version.as_str()))
        .collect();

    out.lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let name = fields.next()?;
            let candidate = fields.next()?;
            let arch = fields.next()?;
            let repo = fields.next().unwrap_or_default();
            if name.is_empty() || candidate.is_empty() {
                return None;
            }
            let current = have.get(&(name, arch))?;
            Some(AvailableUpdate {
                name: name.to_owned(),
                arch: arch.to_owned(),
                installed: (*current).to_owned(),
                candidate: candidate.to_owned(),
                repo: (!repo.is_empty()).then(|| repo.to_owned()),
                // filled in by `attach_advisories`
                advisories: Vec::new(),
                source: None,
            })
        })
        .collect()
}

/// One row of `dnf updateinfo list`. [`attach_advisories`] turns these into
/// [`updawg_protocol::AdvisoryHint`]s on the matching update.
///
/// Severity is the vendor's word, passed through as is. Red Hat and rebuilds
/// use `Moderate` where Amazon Linux uses `Medium`; the server normalises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateinfoRow {
    pub advisory: String,
    pub severity: Option<String>,
    pub kind: AdvisoryKind,
    pub package: String,
    pub version: String,
    pub arch: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvisoryKind {
    Security,
    Bugfix,
    Enhancement,
    /// Any other type, kept verbatim.
    Other(String),
}

/// What [`AdvisoryKind::as_str`] returns for a security advisory.
pub const SECURITY: &str = "security";

impl AdvisoryKind {
    /// Wire spelling: lowercase, as `updateinfo` printed it. The server does
    /// any normalising.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Security => SECURITY,
            Self::Bugfix => "bugfix",
            Self::Enhancement => "enhancement",
            Self::Other(other) => other,
        }
    }
}

/// `dnf updateinfo list --available` output.
///
/// Three whitespace-separated fields: the advisory, its type, and the NEVRA it
/// applies to.
///
/// ```text
/// RLSA-2026:60226 Moderate/Sec.  attr-2.6.0-1.el9_8.aarch64
/// RLBA-2026:12345 bugfix         less-590-5.el9.aarch64
/// ```
///
/// The type column is `Severity/Sec.` for security advisories and a bare word
/// otherwise. Non-security advisories have no severity.
///
/// A package appears once per advisory, including ones for versions between
/// installed and candidate. [`security_packages`] collapses them.
#[must_use]
pub fn parse_updateinfo(out: &str) -> Vec<UpdateinfoRow> {
    out.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let advisory = fields.next()?;
            let kind = fields.next()?;
            let nevra = fields.next()?;
            // extra columns mean a different format (`--summary` etc.)
            if fields.next().is_some() {
                return None;
            }
            let (package, version, arch) = split_nevra(nevra)?;

            let (severity, kind) = match kind.strip_suffix("/Sec.") {
                Some(severity) => (Some(severity.to_owned()), AdvisoryKind::Security),
                None => (
                    None,
                    match kind {
                        "bugfix" => AdvisoryKind::Bugfix,
                        "enhancement" => AdvisoryKind::Enhancement,
                        other => AdvisoryKind::Other(other.to_owned()),
                    },
                ),
            };

            Some(UpdateinfoRow {
                advisory: advisory.to_owned(),
                severity,
                kind,
                package: package.to_owned(),
                version: version.to_owned(),
                arch: arch.to_owned(),
            })
        })
        .collect()
}

/// Names of packages with at least one security advisory.
#[must_use]
pub fn security_packages(out: &str) -> BTreeSet<String> {
    parse_updateinfo(out)
        .into_iter()
        .filter(|h| h.kind == AdvisoryKind::Security)
        .map(|h| h.package)
        .collect()
}

/// Attaches each `updateinfo` row to its update, keyed on name and arch.
///
/// Rows without a pending update are dropped. `updateinfo` describes the
/// repositories, so it can name packages that aren't installed or are
/// already current.
pub fn attach_advisories(updates: &mut [AvailableUpdate], rows: &[UpdateinfoRow]) {
    let mut by_package: BTreeMap<(&str, &str), Vec<AdvisoryHint>> = BTreeMap::new();
    for row in rows {
        by_package
            .entry((row.package.as_str(), row.arch.as_str()))
            .or_default()
            .push(AdvisoryHint {
                id: row.advisory.clone(),
                severity: row.severity.clone(),
                kind: row.kind.as_str().to_owned(),
                fixed_in: Some(row.version.clone()),
            });
    }

    for update in updates {
        let Some(hints) = by_package.get(&(update.name.as_str(), update.arch.as_str())) else {
            continue;
        };
        update.advisories.clone_from(hints);
        // sort so the upload is stable and the server doesn't see churn
        update
            .advisories
            .sort_by(|a, b| (&a.id, &a.fixed_in, &a.kind).cmp(&(&b.id, &b.fixed_in, &b.kind)));
        update.advisories.dedup();
    }
}

/// The `Obsoleting Packages` section of `dnf check-update --obsoletes`.
///
/// ```text
/// Obsoleting Packages
/// newthing.noarch                        2.0-1.el9      local
///     oldthing.noarch                    1.0-1.el9      @System
/// ```
///
/// The table can wrap, so it's read as a stream of tokens rather than lines:
/// every entry is exactly three fields with no spaces in them. Indentation
/// can't be trusted (wrapped lines are indented too), but an `@` prefix on
/// the repository marks the installed, obsoleted package.
///
/// A malformed triple ends parsing, since skipping it would misalign every
/// entry after it.
#[must_use]
pub fn parse_obsoletes(out: &str, installed: &[InstalledPackage]) -> Vec<PendingRemoval> {
    let have: BTreeMap<(&str, &str), &str> = installed
        .iter()
        .map(|p| ((p.name.as_str(), p.arch.as_str()), p.version.as_str()))
        .collect();

    let tokens: Vec<&str> = out
        .lines()
        .skip_while(|l| l.trim() != OBSOLETING)
        .skip(1)
        .flat_map(str::split_whitespace)
        .collect();

    let mut removals: Vec<PendingRemoval> = Vec::new();
    let mut obsoleter: Option<Replacement> = None;

    for entry in tokens.chunks(3) {
        let [name_arch, evr, repo] = entry else { break };
        let Some((name, arch)) = name_arch.rsplit_once('.') else {
            break;
        };
        // an EVR always has a release, so no hyphen means we're misaligned
        if name.is_empty() || arch.is_empty() || !evr.contains('-') || repo.is_empty() {
            break;
        }

        match repo.strip_prefix('@') {
            // installed, so this is the one being obsoleted
            Some(_) => {
                // Use rpm's version string so it matches the inventory.
                let Some(version) = have.get(&(name, arch)) else {
                    continue;
                };
                removals.push(PendingRemoval {
                    name: name.to_owned(),
                    arch: arch.to_owned(),
                    installed: (*version).to_owned(),
                    replaced_by: obsoleter.clone(),
                });
            }
            None => {
                obsoleter = Some(Replacement {
                    name: name.to_owned(),
                    arch: arch.to_owned(),
                    version: (*evr).to_owned(),
                    repo: Some((*repo).to_owned()),
                });
            }
        }
    }

    removals
}

const OBSOLETING: &str = "Obsoleting Packages";

/// Splits `name-version-release.arch`. Version and release can't contain
/// hyphens, so the last two hyphens are always the separators.
fn split_nevra(nevra: &str) -> Option<(&str, &str, &str)> {
    let (rest, arch) = nevra.rsplit_once('.')?;
    let (rest, release) = rest.rsplit_once('-')?;
    let (name, version) = rest.rsplit_once('-')?;
    if name.is_empty() || version.is_empty() || release.is_empty() || arch.is_empty() {
        return None;
    }
    let start = name.len() + 1;
    let evr = nevra.get(start..nevra.len() - arch.len() - 1)?;
    Some((name, evr, arch))
}

/// `dnf repolist --all -v` output.
///
/// Uses the verbose `Key : value` form because the plain table truncates
/// names to the terminal width. Lines other than `Repo-*` (progress, cache
/// messages) are ignored.
#[must_use]
pub fn parse_repositories(out: &str, distro: Option<&str>) -> Vec<Repository> {
    struct Block {
        id: String,
        name: String,
        enabled: bool,
    }

    let mut blocks: Vec<Block> = Vec::new();
    for line in out.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "Repo-id" => blocks.push(Block {
                id: value.to_owned(),
                name: String::new(),
                // dnf always prints `Repo-status`; if it's ever missing, err
                // towards showing the repo as enabled.
                enabled: true,
            }),
            "Repo-name" => {
                if let Some(b) = blocks.last_mut() {
                    value.clone_into(&mut b.name);
                }
            }
            "Repo-status" => {
                if let Some(b) = blocks.last_mut() {
                    b.enabled = value == "enabled";
                }
            }
            _ => {}
        }
    }

    blocks
        .into_iter()
        .map(|b| Repository {
            id: b.id,
            kind: "rpm".to_owned(),
            third_party: !distro.is_some_and(|d| repo_is_distro(&b.name, d)),
            enabled: b.enabled,
            // not sent for dnf; leapp checks repositories itself
            url: None,
        })
        .collect()
}

/// Whether a repository belongs to the host's distribution, matched on the
/// repository name. It's the only field every vendor fills in recognisably:
/// `Rocky Linux 9 - BaseOS`, `Amazon Linux 2023 repository` and
/// `Red Hat Enterprise Linux 9 for x86_64 - BaseOS (RPMs)` all start with
/// their distribution's `NAME`, and EPEL doesn't.
///
/// The first-word fallback is for Oracle (`NAME` is `Oracle Linux Server`,
/// repositories are `Oracle Linux 9 BaseOS Latest`). Unrecognised names count
/// as third-party.
#[must_use]
pub fn repo_is_distro(repo_name: &str, distro: &str) -> bool {
    let repo = repo_name.trim().to_ascii_lowercase();
    let distro = distro.trim().to_ascii_lowercase();
    if distro.is_empty() || repo.is_empty() {
        return false;
    }
    if repo.starts_with(&distro) {
        return true;
    }
    match (
        repo.split_whitespace().next(),
        distro.split_whitespace().next(),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// `NAME` from `/etc/os-release`. Uses `NAME` rather than `ID` because it's
/// matched against repository names: `ID=amzn` doesn't match
/// `Amazon Linux 2023 repository`, `NAME="Amazon Linux"` does. With `None`,
/// every repository counts as third-party.
#[must_use]
pub fn distro_name(os_release: &str) -> Option<String> {
    let name = os_release.lines().find_map(|line| {
        line.strip_prefix("NAME=")
            .map(|v| v.trim().trim_matches('"').to_owned())
    })?;
    (!name.is_empty()).then_some(name)
}

/// `dnf versionlock list` output.
///
/// Entries look like `name-epoch:version-release.*`, and dnf may add several
/// per package (one per known version), so they're collapsed to names in
/// first-seen order.
///
/// ```text
/// zlib-0:1.2.11-40.el9.*
/// tar-2:1.34-11.el9.*
/// ```
#[must_use]
pub fn parse_holds(out: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut holds = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(name) = hold_name(line) else {
            continue;
        };
        if seen.insert(name.clone()) {
            holds.push(name);
        }
    }
    holds
}

/// dnf always writes the epoch, so the name is everything before the last
/// hyphen preceding the colon. The file can be hand-edited, so entries
/// without a colon fall back to the text before the first `*`.
fn hold_name(entry: &str) -> Option<String> {
    let name = match entry.split_once(':') {
        Some((head, _)) => head.rsplit_once('-').map(|(name, _)| name)?,
        None => entry.split('*').next()?.trim_end_matches(['-', '.']),
    };
    (!name.is_empty()).then(|| name.to_owned())
}

/// Used for both the simulation and the install. Weak dependencies are off
/// because on Rocky 8 upgrading `openssl-libs` otherwise pulls in
/// `openssl-pkcs11`.
const DNF_OPTIONS: &[&str] = &["--setopt=install_weak_deps=False"];

fn key(name: &str, arch: &str) -> String {
    format!("{name}.{arch}")
}

/// `openssl-libs-1:3.5.5-5.el9_8.aarch64`
#[must_use]
pub fn nevra(pin: &Pin) -> String {
    format!("{}-{}.{}", pin.name, pin.to, pin.arch)
}

#[must_use]
pub fn install_args(todo: &[&Pin]) -> Vec<String> {
    let mut args = vec!["install".to_owned(), "-y".to_owned()];
    args.extend(DNF_OPTIONS.iter().map(|&o| o.to_owned()));
    args.extend(todo.iter().map(|p| nevra(p)));
    args
}

/// The install command with `--assumeno`: dnf resolves and prints the
/// transaction, then stops. It always exits 1, so only the output matters.
#[must_use]
pub fn simulate_args(todo: &[&Pin]) -> Vec<String> {
    let mut args = install_args(todo);
    "--assumeno".clone_into(&mut args[1]);
    args
}

/// Keyed `name.arch`, versions formatted as in [`RPM_QF`].
const RPM_Q_QF: &str = "%{NAME}.%{ARCH}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\n";

/// Every installed version of each package (install-only packages like
/// `kernel` have several).
#[must_use]
pub fn parse_versions(out: &str) -> BTreeMap<String, Vec<String>> {
    let mut versions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // lines without a tab are "package x is not installed"
    for (name, version) in out.lines().filter_map(|l| l.split_once('\t')) {
        versions
            .entry(name.to_owned())
            .or_default()
            .push(version.trim().to_owned());
    }
    versions
}

/// The pins not yet at their approved version.
///
/// # Errors
/// [`BackendError::Refused`] when a package moved since the approval.
pub fn still_to_do<'a>(
    pins: &'a [Pin],
    installed: &BTreeMap<String, Vec<String>>,
) -> Result<Vec<&'a Pin>> {
    let mut todo = Vec::new();
    for pin in pins {
        let have = installed.get(&key(&pin.name, &pin.arch));
        match have {
            Some(v) if v.contains(&pin.to) => {}
            Some(v) if v.contains(&pin.from) => todo.push(pin),
            Some(v) => {
                return Err(BackendError::Refused(format!(
                    "{} is at {}, and the job was approved for {} to {}",
                    pin.name,
                    v.join(", "),
                    pin.from,
                    pin.to
                )));
            }
            None => {
                return Err(BackendError::Refused(format!(
                    "{} is not installed, and the job was approved to upgrade it from {}",
                    pin.name, pin.from
                )));
            }
        }
    }
    Ok(todo)
}

/// One row of a dnf transaction table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRow {
    /// The heading without the colon (`Upgrading`, `Installing dependencies`,
    /// `Removing`, ...), or `Replacing` for `replacing` lines under an
    /// obsoletion.
    pub section: String,
    pub name: String,
    pub arch: String,
    pub version: String,
}

/// The table `dnf install --assumeno` prints.
///
/// Unlike `check-update`, this table has widened rather than wrapped in every
/// capture so far (`tests/fixtures/dnf/transaction/rocky9-long-names.txt` is
/// 87 columns). A wrapped row is still handled, though no real capture
/// exercises that path.
#[must_use]
pub fn parse_transaction(out: &str) -> Vec<TransactionRow> {
    let mut rows = Vec::new();
    let mut section: Option<String> = None;
    let mut wrapped: Option<String> = None;
    for line in out.lines() {
        if line.starts_with("Transaction Summary") {
            break;
        }
        if !line.starts_with(' ') {
            // a heading, or the table frame and column titles
            section = line.strip_suffix(':').map(str::to_owned);
            wrapped = None;
            continue;
        }
        let Some(current) = section.as_deref() else {
            continue;
        };
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.first() == Some(&"replacing") {
            // `     replacing  name.arch  version`
            if let (Some(nevr), Some(version)) = (words.get(1), words.get(2))
                && let Some((name, arch)) = nevr.rsplit_once('.')
            {
                rows.push(TransactionRow {
                    section: "Replacing".to_owned(),
                    name: name.to_owned(),
                    arch: arch.to_owned(),
                    version: (*version).to_owned(),
                });
            }
            continue;
        }
        let words: Vec<&str> = match (wrapped.take(), words.as_slice()) {
            (None, [name]) => {
                wrapped = Some((*name).to_owned());
                continue;
            }
            (Some(name), rest) => {
                let mut joined = vec![name];
                joined.extend(rest.iter().map(|w| (*w).to_owned()));
                rows.extend(row(
                    current,
                    &joined.iter().map(String::as_str).collect::<Vec<_>>(),
                ));
                continue;
            }
            (None, words) => words.to_vec(),
        };
        rows.extend(row(current, &words));
    }
    rows
}

fn row(section: &str, words: &[&str]) -> Option<TransactionRow> {
    let [name, arch, version, ..] = words else {
        return None;
    };
    Some(TransactionRow {
        section: section.to_owned(),
        name: (*name).to_owned(),
        arch: (*arch).to_owned(),
        version: (*version).to_owned(),
    })
}

/// Whether dnf's plan is exactly the approved pins and nothing else.
///
/// # Errors
/// [`BackendError::Refused`] naming what differs.
pub fn check_transaction(todo: &[&Pin], simulated: &Ran) -> Result<()> {
    // `--assumeno` always exits 1, so look for an error line. Usually the
    // approved version is gone from the repositories.
    if let Some(error) = simulated
        .stderr
        .lines()
        .chain(simulated.stdout.lines())
        .find(|l| l.starts_with("Error:"))
    {
        return Err(BackendError::Refused(format!(
            "the approved versions cannot be installed: {}",
            error.trim_start_matches("Error:").trim()
        )));
    }
    let wanted: BTreeMap<String, &str> = todo
        .iter()
        .map(|p| (key(&p.name, &p.arch), p.to.as_str()))
        .collect();
    let mut seen = BTreeSet::new();
    for row in parse_transaction(&simulated.stdout) {
        let k = key(&row.name, &row.arch);
        // install-only packages like `kernel` show up as `Installing`
        let approved = matches!(row.section.as_str(), "Upgrading" | "Installing")
            && wanted.get(&k) == Some(&row.version.as_str());
        if !approved {
            return Err(BackendError::Refused(format!(
                "installing the approved versions would also mean {} {} {}, which nobody approved",
                row.section.to_lowercase(),
                row.name,
                row.version
            )));
        }
        seen.insert(k);
    }
    if let Some(pin) = todo.iter().find(|p| !seen.contains(&key(&p.name, &p.arch))) {
        return Err(BackendError::Refused(format!(
            "dnf would not upgrade {} to {}",
            pin.name, pin.to
        )));
    }
    Ok(())
}

/// What changed, according to rpm afterwards.
///
/// # Errors
/// [`BackendError::CommandFailed`] when dnf said it worked and rpm disagrees.
pub fn changes(todo: &[&Pin], after: &BTreeMap<String, Vec<String>>) -> Result<Vec<Change>> {
    let mut changed = Vec::new();
    for pin in todo {
        let now = after.get(&key(&pin.name, &pin.arch));
        if !now.is_some_and(|v| v.contains(&pin.to)) {
            return Err(BackendError::CommandFailed {
                tool: "dnf",
                status: 0,
                stderr: format!(
                    "{} is at {} after installing, not {}",
                    pin.name,
                    now.map(|v| v.join(", ")).unwrap_or_default(),
                    pin.to
                ),
            });
        }
        changed.push(Change {
            name: pin.name.clone(),
            arch: pin.arch.clone(),
            from: pin.from.clone(),
            to: pin.to.clone(),
        });
    }
    Ok(changed)
}

/// `rpm -q` arguments for the pins' installed versions; see
/// [`parse_versions`].
#[must_use]
pub fn query_args(pins: &[Pin]) -> Vec<String> {
    let mut args = vec!["-q".to_owned(), "--qf".to_owned(), RPM_Q_QF.to_owned()];
    args.extend(pins.iter().map(|p| key(&p.name, &p.arch)));
    args
}

async fn installed_versions(pins: &[Pin]) -> Result<BTreeMap<String, Vec<String>>> {
    // exit 1 just means one of them isn't installed
    let ran = run_status("rpm", &query_args(pins)).await?;
    Ok(parse_versions(&ran.stdout))
}

/// `needs-restarting -r` exits 1 when a reboot is needed. Anything else,
/// including the tool missing, counts as no; the post-job inventory has the
/// collector's more thorough answer.
async fn reboot_required() -> bool {
    tokio::process::Command::new("needs-restarting")
        .arg("-r")
        .output()
        .await
        .is_ok_and(|o| o.status.code() == Some(1))
}

fn is_locked(stderr: &str) -> bool {
    stderr.contains("Failed to obtain the transaction lock") || stderr.contains("to finish.")
}

async fn run_status(tool: &'static str, args: &[String]) -> Result<Ran> {
    let output = tokio::process::Command::new(tool)
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BackendError::ToolMissing { tool }
            } else {
                BackendError::Io(e)
            }
        })?;
    Ok(Ran {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

const RELEASEVER: &str = "/etc/dnf/vars/releasever";

/// The newest release in `dnf check-release-update` output
/// (`Version 2023.6.20241010:` lines). `None` if the host is current.
#[must_use]
pub fn newest_release(out: &str) -> Option<&str> {
    let numeric = |v: &str| -> Vec<u64> { v.split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    out.lines()
        .filter_map(|l| l.trim().strip_prefix("Version "))
        .map(|v| v.trim_end_matches(':').trim())
        .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
        .max_by_key(|v| numeric(v))
}

async fn run(tool: &'static str, args: &[&str]) -> Result<String> {
    run_ok(tool, args, &[]).await
}

/// As [`run`], but treating the exit codes in `also_ok` as success
/// (`dnf check-update` exits 100 when there are updates).
async fn run_ok(tool: &'static str, args: &[&str], also_ok: &[i32]) -> Result<String> {
    let output = tokio::process::Command::new(tool)
        .args(args)
        // The parsers match English output (`enabled`, `bugfix`,
        // `No such command`); other locales would silently parse as empty.
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BackendError::ToolMissing { tool }
            } else {
                BackendError::Io(e)
            }
        })?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    let accepted = output.status.success()
        || output
            .status
            .code()
            .is_some_and(|code| also_ok.contains(&code));
    if !accepted {
        // the caller retries later; forcing the lock corrupts the database
        if stderr.contains("Failed to obtain the transaction lock") || stderr.contains("to finish.")
        {
            return Err(BackendError::Locked);
        }
        return Err(BackendError::CommandFailed {
            tool,
            status: output.status.code().unwrap_or(-1),
            stderr: stderr.trim().to_owned(),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
