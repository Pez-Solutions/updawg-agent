//! RHEL-family backend (DAWG-35).
//!
//! Installed packages come from `rpm -qa` with a format string, candidates from
//! `dnf repoquery --upgrades`, repository origin from `dnf repolist -v`, advisory
//! hints from `dnf updateinfo`, obsoletions from `dnf check-update --obsoletes`,
//! and holds from `dnf versionlock list`.
//!
//! Shelling out rather than linking `libdnf` is what keeps the binary statically
//! linked against musl, so one build per architecture runs on every supported
//! distribution.
//!
//! # Where the logic lives
//!
//! Every function that interprets output is a **pure function over `&str`**, and
//! every one of them is tested against output captured from real containers —
//! Rocky 8, Rocky 9 and Amazon Linux 2023, in `tests/fixtures/dnf/`. The methods
//! below are a shell invocation and a call to one of those, exactly as in
//! [`crate::apt`].
//!
//! # Why `repoquery --upgrades` and not `check-update`
//!
//! `dnf check-update` is the command a person runs, and its output is a padded
//! table meant for a terminal. **It wraps.** A package whose `name.arch` is wider
//! than the first column is printed alone on its line and its version and
//! repository follow on the next, indented:
//!
//! ```text
//! elfutils-default-yama-scope.noarch
//!                                   0.188-3.amzn2023.0.3   amazonlinux
//! ```
//!
//! A parser that takes three whitespace-separated fields per line drops that
//! package silently, which is the worst possible way to be wrong about an
//! outstanding update. `repoquery --qf` emits exactly the fields asked for, one
//! record per line, and never wraps.
//!
//! **`--latest-limit=1` is load-bearing.** Without it `repoquery --upgrades`
//! returns *every* newer version in the repositories rather than the one `dnf
//! upgrade` would install — on a stock Rocky 9 container that is 77 records for
//! 38 upgradable packages, three of them `glib2`. Reporting those would invent
//! two updates that will never be applied. With it, the set matches
//! `check-update` package for package, which is what `tests/dnf.rs` asserts
//! against the captured table and `tests/dnf_live.rs` asserts against a live one.
//!
//! ⚠️ A measuring trap that cost me twenty minutes: **dnf deduplicates identical
//! formatted output lines**. Counting `--qf '%{name}.%{arch}'` gives 38 either
//! way and makes the problem invisible; the duplicates only appear once the
//! version is in the format string.
//!
//! # The one thing `check-update` is still needed for
//!
//! `repoquery --upgrades` does not report **obsoletes** — an obsoletion is not
//! an upgrade — and no `--qf` names both sides of one. `check-update
//! --obsoletes` does, under an `Obsoleting Packages` heading, so that is where
//! [`parse_obsoletes`] reads them from despite everything above. It survives the
//! wrapping by not reading lines at all: see that function.
//!
//! ⚠️ **`dnf check-update` exits 100 when there are updates.** Treating a
//! non-zero status as a failure means it never answers on a host that has
//! anything to do, which is every host worth asking. [`run_ok`] is why.
//!
//! # What the agent does not decide
//!
//! Whether an update is *security* is reported here only as what dnf itself says
//! in `updateinfo`. That is a local hint for the heartbeat, not a
//! classification: the authoritative answer is the server's, against advisory
//! data. It matters more here than on Debian, because **the RHEL family has no
//! security pocket** — a security fix and a bugfix are published to the same
//! `baseos`, so [`AvailableUpdate::repo`] carries no signal at all and
//! `updateinfo` is the only thing that does.

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
    /// The distribution's own name, as `/etc/os-release` spells it — `Rocky
    /// Linux`, `Amazon Linux`, `Red Hat Enterprise Linux`. Everything whose
    /// repository does not announce itself under that name is third-party.
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
        // `repoquery` reports the candidate and the repository it comes from but
        // not what is installed, so the installed set is read again here rather
        // than threaded through the trait. `rpm -qa` is local and reads the same
        // database `repoquery` just consulted; the alternative is a trait that
        // makes every backend accept an argument only one of them wants.
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

        // Three commands, because dnf keeps the three answers in three places:
        // the candidate in `repoquery`, the advisory in `updateinfo`, and the
        // obsoletion in `check-update`. Skipped entirely when there is nothing
        // to upgrade, which is the common steady state and the one where an
        // Amazon Linux host pinned to a snapshot sits for ever (DAWG-233).
        if !updates.is_empty() {
            let out = run("dnf", &["-q", "updateinfo", "list", "--available"]).await?;
            attach_advisories(&mut updates, &parse_updateinfo(&out));
        }

        let out = run_ok(
            "dnf",
            &["-q", "check-update", "--obsoletes"],
            // 100 is `check-update` saying there are updates, which is the
            // interesting case and not an error. Reading it as one is how this
            // returns nothing on every host that has anything to do.
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

    /// `/etc/dnf/vars/releasever`, where it fixes the release; on Amazon
    /// Linux 2023 the installed release otherwise, which is where every host
    /// is pinned unless told `latest`, and `dnf check-release-update` for
    /// what it could move to (DAWG-233).
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
        // Metadata for releases other than the pinned one, read and not
        // installed. Unanswered, the pin is still reported: that it is pinned
        // is known, how far behind is not.
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
            // versionlock is a plugin and is not installed by default. Its
            // absence is not a failure to answer: with no plugin there is
            // nothing enforcing a lock, so no package is held and an empty list
            // is the truth rather than a guess. This is the one place where
            // "none" and "I cannot tell you" genuinely are the same answer.
            Err(BackendError::CommandFailed { ref stderr, .. })
                if stderr.contains("No such command: versionlock") =>
            {
                Ok(Vec::new())
            }
            Err(e) => Err(e),
        }
    }

    async fn security_updates(&self, updates: &[AvailableUpdate]) -> Result<BTreeSet<String>> {
        // Answered from the updates rather than by asking `updateinfo` again:
        // `pending_changes` already attached what it said (DAWG-231), and a
        // second call could only disagree with the first. That disagreement
        // would be a repository that published between the two commands, and
        // resolving it in favour of the newer half would make the count on the
        // heartbeat describe a different set of updates from the one uploaded.
        Ok(updates
            .iter()
            .filter(|u| u.advisories.iter().any(|a| a.kind == SECURITY))
            .map(|u| u.name.clone())
            .collect())
    }

    /// Install exactly the approved versions, or nothing (DAWG-102).
    ///
    /// The same four steps as [`crate::apt`], and the first three change
    /// nothing:
    ///
    /// 1. **What is installed now**, from `rpm -q`. Each pin must be at its
    ///    `from` — or already at its `to`, which is done and skipped.
    /// 2. **What dnf would do**, from `dnf install --assumeno` with the exact
    ///    command line. It must upgrade exactly the remaining pins to exactly
    ///    their versions and nothing else. On Rocky 9 asking for
    ///    `openssl-libs` alone upgrades `openssl` and `openssl-fips-provider`
    ///    too, and that is refused: nobody approved them.
    /// 3. **Do it**, with the same command line and `-y`. Weak dependencies
    ///    are off on both, so a recommended package is never pulled in.
    /// 4. **What is installed after.** Each pin must now be at its `to`.
    /// Leapp (DAWG-152): see [`crate::leapp_upgrade`].
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

/// `rpm -qa` format: name, `[epoch:]version-release`, architecture.
///
/// The `%|EPOCH?{…}|` conditional prints the epoch only when the package has
/// one, which is exactly the `[epoch:]version[-release]` that the server's
/// `rpmvercmp` parses — and it is what `dnf`'s own `%{evr}` produces, so the
/// installed version and the candidate are spelled the same way on both sides of
/// a comparison.
const RPM_QF: &str =
    "%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{ARCH}\t%{MODULARITYLABEL}\n";

/// `dnf repoquery` format: name, `[epoch:]version-release`, architecture, repo.
///
/// No trailing newline: `repoquery` ends every record with one of its own, and
/// adding a second gives a blank line between records — which makes every line
/// count twice and is how I first convinced myself `--upgrades` was returning
/// duplicates.
const REPOQUERY_QF: &str = "%{name}\t%{evr}\t%{arch}\t%{reponame}";

/* ------------------------------------------------------------- the parsers */

/// `rpm -qa --qf` output: name, EVR, architecture, modularity label.
///
/// **`gpg-pubkey` is not a package.** rpm keeps imported signing keys in the same
/// database and `rpm -qa` lists them, with `(none)` for the architecture. Sending
/// them as installed software would have the server matching advisories against a
/// key fingerprint and, worse, proposing to upgrade one. Filtering on the
/// architecture catches every such pseudo-entry rather than just the one name.
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
                // rpm records where a package came from only when dnf put it
                // there, and it is empty on anything installed by rpm itself or
                // baked into an image. Left absent rather than guessed, as with
                // dpkg.
                repo: None,
                // rpm's SOURCERPM is a file name, not a name and version; not
                // needed until the RHEL family has unfixed advisories too.
                source: None,
                module: module_stream(label),
            })
        })
        .collect()
}

/// `name:stream` from rpm's `MODULARITYLABEL`, `name:stream:version:context`
/// (DAWG-236). The build version and context say which build of the stream a
/// package is, which no advisory is about. `(none)` — rpm's word for a tag a
/// package does not have — and anything without a stream are not modular.
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
/// **A candidate for something not installed is dropped**, which is the same rule
/// as apt's bracket test and exists for the same reason: an "update" to a package
/// the host does not have is an invention. `--upgrades` should never produce one,
/// so this is a guard rather than a filter — but the alternative to guarding is
/// an `AvailableUpdate` with an empty `installed`, and nothing downstream would
/// notice.
///
/// Keyed on **name and architecture together**, because a multilib host has
/// `glibc.i686` and `glibc.x86_64` installed at once and they upgrade
/// independently.
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
                // The RHEL family has no security pocket, so this is `baseos` or
                // `appstream` and carries no severity of its own. It is reported
                // because the server wants to know which repository an update
                // came from, not because it means anything about urgency.
                repo: (!repo.is_empty()).then(|| repo.to_owned()),
                // Filled in by `attach_advisories` from `dnf updateinfo`, which
                // is a separate command and a separate parse. Empty here rather
                // than absent from the type, so the one place that joins them is
                // the one place that can get it wrong.
                advisories: Vec::new(),
                // dnf names no source upload per update; the server does
                // not need one for the RHEL family, which has no changelogs to
                // look up by it.
                source: None,
            })
        })
        .collect()
}

/// One row of `dnf updateinfo list`.
///
/// Not [`updawg_protocol::AdvisoryHint`], which is what goes on the wire: this
/// carries the package and architecture the row named, and the wire type hangs
/// off the update those identify. [`attach_advisories`] is the join.
///
/// The severity is the vendor's word — `Critical`, `Important`, `Moderate`, `Low`
/// on Red Hat and its rebuilds, and `Critical`, `Important`, `Medium`, `Low` on
/// Amazon Linux, which uses `Medium` where Red Hat uses `Moderate`. Normalising
/// those onto one scale is the server's job (DAWG-65); the agent reports the word
/// it was given.
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
    /// Anything dnf printed that is none of the above, kept verbatim rather than
    /// folded into one of them. A type nobody has seen before is worth reporting
    /// as itself.
    Other(String),
}

/// What [`AdvisoryKind::as_str`] returns for a security advisory, and the only
/// value any of this code compares against.
pub const SECURITY: &str = "security";

impl AdvisoryKind {
    /// How this type is spelled on the wire.
    ///
    /// Lowercase and verbatim, matching what `updateinfo` printed. The server
    /// decides what the word means; normalising it here would be a guess made
    /// on the host, and a guess made on the host cannot be corrected later.
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
/// The type column is either `Severity/Sec.` for a security advisory or a bare
/// word for anything else — **a bugfix has no severity at all**, and inventing
/// one for it would put every routine rebuild on the same scale as a remote code
/// execution.
///
/// The same package appears once per advisory, including advisories for versions
/// between the installed one and the candidate. That is dnf being complete rather
/// than repetitive, and [`security_packages`] collapses it.
#[must_use]
pub fn parse_updateinfo(out: &str) -> Vec<UpdateinfoRow> {
    out.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let advisory = fields.next()?;
            let kind = fields.next()?;
            let nevra = fields.next()?;
            // A fourth field means this is not the row shape we understand —
            // `updateinfo` grows columns under `--summary` and friends.
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

/// The packages `dnf updateinfo` attributes a security advisory to.
///
/// Names only. A package with three outstanding security advisories is one
/// package with a security update available, and the count on the heartbeat is a
/// count of updates rather than of advisories.
#[must_use]
pub fn security_packages(out: &str) -> BTreeSet<String> {
    parse_updateinfo(out)
        .into_iter()
        .filter(|h| h.kind == AdvisoryKind::Security)
        .map(|h| h.package)
        .collect()
}

/// Hang each `updateinfo` row on the update it is about (DAWG-231).
///
/// Keyed on **name and architecture together**, as everything else here is: a
/// multilib host has `glibc.i686` and `glibc.x86_64` installed at once, they
/// upgrade independently, and an advisory names one of them.
///
/// A row for a package with no pending update is dropped. `updateinfo` answers
/// about the repositories rather than about this host, so it can name a package
/// that is not installed or is already current — and an advisory hung on
/// nothing would be a claim the host cannot act on.
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
        // dnf prints one row per advisory per version and its order is its own.
        // Sorting makes the upload stable, which matters because the server
        // stores it and a list that reshuffles every six hours looks like a
        // change every six hours.
        update
            .advisories
            .sort_by(|a, b| (&a.id, &a.fixed_in, &a.kind).cmp(&(&b.id, &b.fixed_in, &b.kind)));
        update.advisories.dedup();
    }
}

/// The `Obsoleting Packages` section of `dnf check-update --obsoletes`
/// (DAWG-232).
///
/// ```text
/// Obsoleting Packages
/// newthing.noarch                        2.0-1.el9      local
///     oldthing.noarch                    1.0-1.el9      @System
/// ```
///
/// **This is the one place `check-update` is the right command**, against the
/// rule at the top of this file, because `repoquery --upgrades` does not report
/// obsoletes at all — an obsoletion is not an upgrade — and no `--qf` names
/// both sides of one. Verified against a real Rocky 9 container with two
/// obsoleting packages built into a local repository; `repoquery --upgrades`
/// listed neither.
///
/// The table still wraps, and the answer to that is to **stop reading it as
/// lines**. Every entry is exactly three whitespace-separated fields and none of
/// them can contain a space, so the section is one token stream and wrapping is
/// invisible to it. An indented line is not a reliable marker of anything — a
/// wrapped continuation is indented too — but the repository is: dnf prints an
/// installed package's repository with an `@` prefix, so `@` is what tells the
/// obsoleted package from the thing obsoleting it.
///
/// A triple that is not shaped like one ends the section rather than being
/// skipped, because skipping it would shift every following entry by a field
/// and produce a list of confident nonsense.
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
        // An EVR always carries a release, so a middle field with no hyphen in
        // it means the columns are not where this parser thinks they are.
        if name.is_empty() || arch.is_empty() || !evr.contains('-') || repo.is_empty() {
            break;
        }

        match repo.strip_prefix('@') {
            // Installed, so this is the package being obsoleted.
            Some(_) => {
                // Reported with rpm's own version rather than the table's, so
                // the removal names the same string the inventory reported as
                // installed. A package the host does not actually have is
                // dropped, as an upgrade for one is in `parse_upgrades`.
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

/// The heading `dnf check-update` prints above the obsoletions, under `LC_ALL=C`.
const OBSOLETING: &str = "Obsoleting Packages";

/// Split `name-version-release.arch` into its name, its `version-release` and its
/// architecture.
///
/// Neither the version nor the release may contain a hyphen, which is what makes
/// this decidable: the last two hyphens are always the separators, whatever the
/// name contains. `elfutils-default-yama-scope-0.188-3.amzn2023.0.3.noarch` is
/// one package, not four.
fn split_nevra(nevra: &str) -> Option<(&str, &str, &str)> {
    let (rest, arch) = nevra.rsplit_once('.')?;
    let (rest, release) = rest.rsplit_once('-')?;
    let (name, version) = rest.rsplit_once('-')?;
    if name.is_empty() || version.is_empty() || release.is_empty() || arch.is_empty() {
        return None;
    }
    // The version and release are contiguous in the input, so the slice covering
    // both is the EVR without having to rebuild it.
    let start = name.len() + 1;
    let evr = nevra.get(start..nevra.len() - arch.len() - 1)?;
    Some((name, evr, arch))
}

/// `dnf repolist --all -v` output.
///
/// The verbose form prints one `Key : value` line per attribute, which is the
/// reason to use it. **The table `dnf repolist` prints without `-v` is truncated
/// to the terminal width** — `Rocky Linux 9 - Devel WARNING! FOR BUILDROOT ONLY
/// DO NOT LEAVE ENABLED` arrives as `Rocky Linux 9 - Devel WARNING! FOR BUILDROOT`
/// — and a name cut off mid-word is a name that cannot be matched against
/// anything.
///
/// dnf prints its own progress and cache chatter to the same stream, so
/// everything that is not a `Repo-` line is ignored rather than counted on being
/// absent.
#[must_use]
pub fn parse_repositories(out: &str, distro: Option<&str>) -> Vec<Repository> {
    /// One repository as the verbose listing spells it, before it becomes a
    /// [`Repository`].
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
                // dnf prints `Repo-status` for every repository, so this default
                // is never what is reported. It is `true` rather than `false`
                // because a repository whose status line went missing is one the
                // host is probably using, and a disabled repository reported as
                // enabled is a smaller lie than the reverse — the reverse hides a
                // source of packages entirely.
                enabled: true,
            }),
            // Only inside a block. A `Repo-name` with no `Repo-id` before it
            // cannot happen in dnf's output, and if it ever does the name belongs
            // to nothing and is better dropped than attached to the wrong repo.
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
            // Not sent from dnf yet (DAWG-149): leapp checks its own.
            url: None,
        })
        .collect()
}

/// Whether a repository belongs to the distribution the host is running.
///
/// Matched on the repository's **name** rather than on its id or its `.repo`
/// file, because the name is the only field every vendor fills in with something
/// recognisable. `Rocky Linux 9 - BaseOS`, `Amazon Linux 2023 repository` and
/// `Red Hat Enterprise Linux 9 for x86_64 - BaseOS (RPMs)` all begin with the
/// `NAME` in their own `/etc/os-release`; `Extra Packages for Enterprise Linux 9`
/// does not begin with any of them.
///
/// The first-word fallback is for Oracle, whose `NAME` is `Oracle Linux Server`
/// while its repositories are named `Oracle Linux 9 BaseOS Latest`. It is looser
/// than the prefix test and deliberately so — the direction that costs something
/// is calling a third-party repository the distribution's, and `Oracle` is not a
/// word another vendor's repository starts with.
///
/// An unrecognised name counts as third-party, as it does on apt: an unsigned or
/// hand-rolled repository often has a name nobody would recognise, and those are
/// exactly the ones that break a release upgrade.
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

/// The distribution's own name, from `/etc/os-release`.
///
/// `NAME`, not `ID`: the apt backend matches an apt *origin*, which is spelled
/// like an id, while dnf has no origin field and the closest thing is the
/// human-readable repository name. `ID=amzn` matches nothing in `Amazon Linux
/// 2023 repository`; `NAME="Amazon Linux"` matches it exactly.
///
/// Returns `None` when the file says nothing useful, and then every repository
/// reads as third-party — the safe direction.
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
/// Entries are written as `name-epoch:version-release.*`, and dnf adds **one per
/// version it knows about** — `dnf versionlock add tar` on Amazon Linux produced
/// three lines for one package. The name is what a held package is, so they are
/// collapsed to it, in the order first seen.
///
/// ```text
/// zlib-0:1.2.11-40.el9.*
/// tar-2:1.34-11.el9.*
/// ```
///
/// A held package will not be upgraded no matter what a proposal says, so a plan
/// that ignores these is a plan that silently does nothing.
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

/// The package name out of one versionlock entry.
///
/// The epoch's colon is the anchor: everything before it is `name-epoch`, so the
/// name is what precedes its last hyphen. dnf always writes the epoch, even a
/// zero one, which is what makes this reliable — but the list is a plain file a
/// person can edit, so an entry with no colon falls back to the text before the
/// first glob character.
fn hold_name(entry: &str) -> Option<String> {
    let name = match entry.split_once(':') {
        Some((head, _)) => head.rsplit_once('-').map(|(name, _)| name)?,
        None => entry.split('*').next()?.trim_end_matches(['-', '.']),
    };
    (!name.is_empty()).then(|| name.to_owned())
}

/* ------------------------------------------------------------- applying */

/// On the simulation and the install alike, so the one checked is the one run.
///
/// Weak dependencies off: on Rocky 8, upgrading `openssl-libs` otherwise
/// installs `openssl-pkcs11` because something recommends it.
const DNF_OPTIONS: &[&str] = &["--setopt=install_weak_deps=False"];

/// `name.arch`, which is how `rpm -q` and a transaction table both key a
/// package, and which keeps two architectures of one package apart.
fn key(name: &str, arch: &str) -> String {
    format!("{name}.{arch}")
}

/// `openssl-libs-1:3.5.5-5.el9_8.aarch64`: the exact package dnf is asked for.
#[must_use]
pub fn nevra(pin: &Pin) -> String {
    format!("{}-{}.{}", pin.name, pin.to, pin.arch)
}

/// The exact `dnf install` command line for these pins.
#[must_use]
pub fn install_args(todo: &[&Pin]) -> Vec<String> {
    let mut args = vec!["install".to_owned(), "-y".to_owned()];
    args.extend(DNF_OPTIONS.iter().map(|&o| o.to_owned()));
    args.extend(todo.iter().map(|p| nevra(p)));
    args
}

/// The same command line, answered "no" at the prompt: dnf resolves the
/// transaction, prints it, and stops. It exits 1 whatever it decided, so the
/// output is the only answer.
#[must_use]
pub fn simulate_args(todo: &[&Pin]) -> Vec<String> {
    let mut args = install_args(todo);
    "--assumeno".clone_into(&mut args[1]);
    args
}

/// `rpm -q --qf` for the installed versions of these packages, keyed
/// `name.arch`, spelled as [`RPM_QF`] spells them so they compare equal to
/// what the server was sent.
const RPM_Q_QF: &str = "%{NAME}.%{ARCH}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\n";

/// Every installed version of each package. More than one is normal for an
/// install-only package such as `kernel`.
#[must_use]
pub fn parse_versions(out: &str) -> BTreeMap<String, Vec<String>> {
    let mut versions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // Lines without a tab are rpm's "package x is not installed".
    for (name, version) in out.lines().filter_map(|l| l.split_once('\t')) {
        versions
            .entry(name.to_owned())
            .or_default()
            .push(version.trim().to_owned());
    }
    versions
}

/// The pins not already at their approved version, or a refusal naming the
/// first one at neither end.
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
    /// The heading it sits under, without the colon: `Upgrading`,
    /// `Installing dependencies`, `Downgrading`, `Removing`, … — or
    /// `Replacing` for the indented `replacing` lines under an obsoletion.
    pub section: String,
    pub name: String,
    pub arch: String,
    pub version: String,
}

/// The table `dnf install --assumeno` prints.
///
/// `check-update`'s table wraps a long name onto its own line (see the module
/// docs). This one, with output piped, **widened instead** in every capture —
/// `tests/fixtures/dnf/transaction/rocky9-long-names.txt` is 87 columns. A
/// lone name followed by the rest of its row is still read as one row, in
/// case some dnf does wrap it; that path has no real capture behind it.
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
            // A heading, or the table's own frame and column titles.
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
    // `--assumeno` exits 1 whether it resolved or not; an error says so in
    // words. Almost always a version the repositories no longer carry.
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
        // `Installing` rather than `Upgrading` is how an install-only package
        // such as `kernel` arrives: alongside, not in place.
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

/// What changed, as rpm reports it afterwards. Each pin must be at its `to`.
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

/// The `rpm -q` command line for these pins' installed versions, read by
/// [`parse_versions`].
#[must_use]
pub fn query_args(pins: &[Pin]) -> Vec<String> {
    let mut args = vec!["-q".to_owned(), "--qf".to_owned(), RPM_Q_QF.to_owned()];
    args.extend(pins.iter().map(|p| key(&p.name, &p.arch)));
    args
}

async fn installed_versions(pins: &[Pin]) -> Result<BTreeMap<String, Vec<String>>> {
    // Exit 1 means one of them is not installed, which is an answer.
    let ran = run_status("rpm", &query_args(pins)).await?;
    Ok(parse_versions(&ran.stdout))
}

/// `needs-restarting -r`: exit 1 means a reboot is needed. Missing or
/// anything else is "no"; the inventory uploaded after every job carries the
/// collector's fuller answer.
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

/// A command and what it said, whatever its exit status.
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

/// Where dnf's `$releasever` is fixed, when something fixes it.
const RELEASEVER: &str = "/etc/dnf/vars/releasever";

/// The newest release `dnf check-release-update` offers, from its
/// `Version 2023.6.20241010:` lines. `None` when it offers none, which is
/// what it prints for a host that is current.
#[must_use]
pub fn newest_release(out: &str) -> Option<&str> {
    let numeric = |v: &str| -> Vec<u64> { v.split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    out.lines()
        .filter_map(|l| l.trim().strip_prefix("Version "))
        .map(|v| v.trim_end_matches(':').trim())
        .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
        .max_by_key(|v| numeric(v))
}

/* ------------------------------------------------------------- the shelling */

async fn run(tool: &'static str, args: &[&str]) -> Result<String> {
    run_ok(tool, args, &[]).await
}

/// As [`run`], but treating some non-zero exit codes as success.
///
/// `dnf check-update` exits **100** when there are updates — the useful case,
/// and the one where reading a non-zero status as a failure means the command
/// never answers on any host that has anything to do.
async fn run_ok(tool: &'static str, args: &[&str], also_ok: &[i32]) -> Result<String> {
    let output = tokio::process::Command::new(tool)
        .args(args)
        // Parsing depends on the exact words dnf prints — `enabled`, `bugfix`,
        // `No such command` — and every one of them is translated. A host with
        // LANG set to anything else would report no repositories and no holds,
        // with no error anywhere.
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
        // Another transaction holds the rpm database. Waiting and retrying is the
        // only safe answer: forcing it corrupts the database, and the caller
        // decides when to come back.
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
