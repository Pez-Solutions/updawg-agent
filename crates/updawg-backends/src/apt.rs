//! Debian-family backend.
//!
//! Installed packages come from `dpkg-query -W` with a tab-separated format
//! string, candidates and pending removals from one simulated
//! `apt-get -s dist-upgrade`, repository origin from `apt-cache policy`, and
//! holds from `apt-mark showhold`.
//!
//! All output parsing is done by plain functions over `&str`, tested against
//! output captured from Ubuntu 20.04, 22.04, 24.04 and Debian 11 and 12
//! containers (`tests/fixtures/apt/`). The trait methods just run a command
//! and call one of them.
//!
//! The security flag is only apt's view (the candidate comes from a
//! `-security` pocket). The server makes the real classification from
//! advisory data.

use crate::{
    ApplyOutcome, ApplyPlan, BackendError, Change, LogSink, PackageBackend, PendingChanges, Pin,
    Result,
};
use async_trait::async_trait;
use updawg_protocol::{AvailableUpdate, Ecosystem, InstalledPackage, PendingRemoval, Repository};

#[derive(Debug, Default, Clone)]
pub struct AptBackend {
    /// The distribution's origin as `apt-cache policy` spells it (`Ubuntu`,
    /// `Debian`, `Raspbian`). Anything else is third-party. Read from
    /// `/etc/os-release` so derivatives are handled correctly.
    origin: Option<String>,
}

impl AptBackend {
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: distro_origin(&std::fs::read_to_string("/etc/os-release").unwrap_or_default()),
        }
    }
}

#[async_trait]
impl PackageBackend for AptBackend {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Deb
    }

    async fn installed(&self) -> Result<Vec<InstalledPackage>> {
        let out = run(
            "dpkg-query",
            &[
                "-W",
                "-f",
                // Source name and version go last so output without them
                // (the older fixtures) still parses. Both fields exist as far
                // back as dpkg 1.19.7 (Ubuntu 20.04).
                "${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\t${source:Package}\t${source:Version}\n",
            ],
        )
        .await?;
        Ok(parse_installed(&out))
    }

    async fn refresh_metadata(&self) -> Result<()> {
        run("apt-get", &["update", "-qq"]).await.map(|_| ())
    }

    async fn pending_changes(&self) -> Result<PendingChanges> {
        // `-s` implies Debug::NoLocking, so this works while
        // unattended-upgrades holds the lock.
        let installed = self.installed().await?;
        let out = run("apt-get", &["-s", "dist-upgrade"]).await?;
        let mut updates = parse_updates(&out);
        candidate_sources(&mut updates).await;
        Ok(PendingChanges {
            updates,
            removals: parse_removals(&out, &installed),
        })
    }

    async fn repositories(&self) -> Result<Vec<Repository>> {
        let out = run("apt-cache", &["policy"]).await?;
        Ok(parse_repositories(&out, self.origin.as_deref()))
    }

    async fn release_sources(&self) -> Result<Vec<crate::RepoSource>> {
        let out = run("apt-cache", &["policy"]).await?;
        let mut sources = parse_sources(&out, self.origin.as_deref());
        let names = run("dpkg-query", &["-W", "-f", "${Package}\n"]).await?;
        let names: Vec<&str> = names.lines().filter(|l| !l.is_empty()).collect();
        if names.is_empty() {
            return Ok(sources);
        }
        let mut args = vec!["policy"];
        args.extend(names);
        let per_package = run("apt-cache", &args).await?;
        for (package, uri, suite) in parse_installed_from(&per_package) {
            if let Some(s) = sources
                .iter_mut()
                .find(|s| s.uri == uri && s.suite == suite)
                && !s.packages.contains(&package)
            {
                s.packages.push(package);
            }
        }
        Ok(sources)
    }

    async fn frozen(&self) -> Result<Option<updawg_protocol::Frozen>> {
        let out = run("apt-cache", &["policy"]).await?;
        Ok(frozen_sources(&parse_sources(&out, self.origin.as_deref())))
    }

    async fn held_packages(&self) -> Result<Vec<String>> {
        let out = run("apt-mark", &["showhold"]).await?;
        Ok(parse_holds(&out))
    }

    async fn security_updates(
        &self,
        updates: &[AvailableUpdate],
    ) -> Result<std::collections::BTreeSet<String>> {
        Ok(updates
            .iter()
            .filter(|u| u.repo.as_deref().is_some_and(is_security_archive))
            .map(|u| u.name.clone())
            .collect())
    }

    async fn dist_upgrade(&self, target: &str, log: &dyn LogSink) -> Result<ApplyOutcome> {
        if crate::release::this_host()?.id == "ubuntu" {
            crate::ubuntu_upgrade::upgrade(self, target, log).await
        } else {
            crate::debian_upgrade::upgrade(self, target, log).await
        }
    }

    async fn release_upgrade_blockers(&self, target: &str) -> Result<Vec<String>> {
        let host = crate::release::this_host()?;
        if host.id == "ubuntu" {
            crate::ubuntu_upgrade::blockers(self, &host, target).await
        } else {
            crate::debian_upgrade::blockers(self, &host, target).await
        }
    }

    async fn check_pins(&self, pins: &[Pin]) -> Result<Vec<String>> {
        let before = installed_versions(pins).await?;
        let todo = still_to_do(pins, &before)?;
        if todo.is_empty() {
            return Ok(vec![]);
        }
        simulate(&todo).await
    }

    /// Installs exactly the approved versions, or nothing.
    ///
    /// 1. Each pin must be at its `from` version (or already at `to`, which
    ///    is skipped). Otherwise the host has moved since approval: refuse.
    /// 2. Simulate the exact command line. It must upgrade only the remaining
    ///    pins, to exactly their versions. Removals, unapproved new packages,
    ///    or an approved version apt can no longer find are refused.
    /// 3. Run it for real: non-interactive, keeping local config files, and
    ///    waiting for the dpkg lock instead of fighting `unattended-upgrades`.
    /// 4. Each pin must now be at `to`. The reported changes come from dpkg,
    ///    not from the plan.
    async fn apply(&self, plan: &ApplyPlan, log: &dyn LogSink) -> Result<ApplyOutcome> {
        let before = installed_versions(&plan.packages).await?;
        let todo = still_to_do(&plan.packages, &before)?;
        if todo.is_empty() {
            log.line("every approved version is already installed; nothing to do");
            return Ok(ApplyOutcome {
                changed: vec![],
                reboot_required: reboot_required(),
                after_reboot: None,
            });
        }

        for extra in simulate(&todo).await? {
            log.line(&format!(
                "also installing {extra}, from the same source upload as an approved package"
            ));
        }

        log.line(&format!(
            "installing {} package(s) at their approved versions",
            todo.len()
        ));
        let installed = run_status("apt-get", &install_args(&todo)).await?;
        for line in as_shown(&installed.stdout) {
            log.line(line);
        }
        if installed.code != 0 {
            return Err(BackendError::CommandFailed {
                tool: "apt-get",
                status: installed.code,
                stderr: installed.stderr,
            });
        }

        let after = installed_versions(&plan.packages).await?;
        let changed = changes(&todo, &after)?;
        Ok(ApplyOutcome {
            changed,
            reboot_required: reboot_required(),
            after_reboot: None,
        })
    }
}

/// `dpkg-query -W` output: name, version, architecture, status, and
/// optionally the source package's name and version.
///
/// Only status `installed` counts. Other states (`config-files`,
/// `half-configured`, `unpacked`, ...) don't have the package's files on
/// disk, so matching advisories against them would be wrong.
#[must_use]
pub fn parse_installed(out: &str) -> Vec<InstalledPackage> {
    out.lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let name = fields.next()?;
            let version = fields.next()?;
            let arch = fields.next()?;
            let status = fields.next()?;
            if status.trim() != "installed" || name.is_empty() || version.is_empty() {
                return None;
            }
            let source = match (fields.next(), fields.next()) {
                (Some(n), Some(v)) if !n.trim().is_empty() && !v.trim().is_empty() => {
                    Some(updawg_protocol::SourcePackage {
                        name: n.trim().to_owned(),
                        version: v.trim().to_owned(),
                    })
                }
                _ => None,
            };
            Some(InstalledPackage {
                name: name.to_owned(),
                version: version.to_owned(),
                arch: arch.to_owned(),
                // dpkg doesn't know the repository, and apt only knows it
                // for packages still available.
                repo: None,
                source,
                module: None,
            })
        })
        .collect()
}

/// `apt-get -s dist-upgrade` output.
///
/// The lines that matter look like:
///
/// ```text
/// Inst perl-base [5.38.2-3.2ubuntu0.4] (5.38.2-3.2ubuntu0.6 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [arm64])
/// Inst libbrotli1 (1.0.9-2+b6 Debian:12.15/oldstable [arm64])
/// ```
///
/// The bracketed version before `(` means the package is installed and has
/// an upgrade. Without it, apt is installing something new (a dependency),
/// which isn't an update.
#[must_use]
pub fn parse_updates(out: &str) -> Vec<AvailableUpdate> {
    out.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("Inst ")?;
            let (name, rest) = rest.split_once(' ')?;

            // no `[installed]` means a new install
            let rest = rest.strip_prefix('[')?;
            let (installed, rest) = rest.split_once(']')?;

            // Candidate, origins and arch are inside the parentheses. apt may
            // append `[]` after them for a dependency pull-in
            // (`Inst libgcc-s1:armhf (... [armhf]) []`), which this skips.
            let open = rest.find('(')?;
            let close = rest.rfind(')')?;
            let inner = rest.get(open + 1..close)?;

            let (candidate, origins) = inner.split_once(' ').unwrap_or((inner, ""));

            Some(AvailableUpdate {
                // apt says `libc6:armhf` for foreign arches; dpkg-query says
                // `libc6` with the arch in its own field.
                name: name.split(':').next().unwrap_or(name).to_owned(),
                arch: architecture(inner).unwrap_or_default(),
                installed: installed.to_owned(),
                candidate: candidate.to_owned(),
                repo: pocket(origins),
                advisories: Vec::new(),
                // filled in by `candidate_sources`
                source: None,
            })
        })
        .collect()
}

/// The `Remv` lines of `apt-get -s dist-upgrade`.
///
/// ```text
/// Remv barpkg [1.0]
/// Inst foopkg [1.0] (2.0 localhost [all])
/// ```
///
/// apt doesn't say what replaces a removed package; nothing links the `Remv`
/// line to the `Inst` that caused it. So [`PendingRemoval::replaced_by`] is
/// always `None` here (dnf does fill it in).
///
/// The architecture is taken from the installed set, since apt only writes
/// `name:arch` for foreign architectures. Packages not installed are dropped.
#[must_use]
pub fn parse_removals(out: &str, installed: &[InstalledPackage]) -> Vec<PendingRemoval> {
    out.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("Remv ")?;
            let (name, _) = rest.split_once(' ').unwrap_or((rest, ""));
            let name = name.split(':').next().unwrap_or(name);
            let package = installed.iter().find(|p| p.name == name)?;
            Some(PendingRemoval {
                name: package.name.clone(),
                arch: package.arch.clone(),
                installed: package.version.clone(),
                replaced_by: None,
            })
        })
        .collect()
}

/// The architecture in the trailing `[arm64]`. `inner` is just the
/// parenthesised group, so a trailing `[]` after it doesn't interfere.
fn architecture(inner: &str) -> Option<String> {
    let open = inner.rfind('[')?;
    let close = inner[open..].find(']')? + open;
    let arch = inner.get(open + 1..close)?;
    (!arch.is_empty()).then(|| arch.to_owned())
}

/// The pocket a candidate comes from, such as `noble-security`.
///
/// apt lists origins as `Origin:version/archive`, comma-separated when a
/// version is in several: `Ubuntu:24.04/noble-updates,
/// Ubuntu:24.04/noble-security`. A security pocket anywhere in the list wins,
/// since Ubuntu publishes every security fix to `-updates` too.
fn pocket(origins: &str) -> Option<String> {
    let archives: Vec<&str> = origins
        .split(',')
        .filter_map(|o| o.trim().split('/').nth(1))
        // The last origin has the arch appended
        // (`Ubuntu:24.04/noble-security [arm64]`), so cut at whitespace or the
        // `-security` suffix check misses it.
        .map(|a| a.split_whitespace().next().unwrap_or(a))
        .filter(|a| !a.is_empty())
        .collect();

    archives
        .iter()
        .find(|a| is_security_archive(a))
        .or_else(|| archives.first())
        .map(|a| (*a).to_owned())
}

/// Whether an archive name is a security pocket. Checked on the archive
/// because Ubuntu and Debian differ in origin and label but both use the
/// `-security` suffix.
#[must_use]
pub fn is_security_archive(archive: &str) -> bool {
    archive.ends_with("-security") || archive == "security"
}

/// `apt-cache policy` output.
///
/// Repositories appear as a priority line followed by a `release` line of
/// comma-separated `key=value` pairs:
///
/// ```text
///  500 http://ports.ubuntu.com/ubuntu-ports noble-security/main arm64 Packages
///      release v=24.04,o=Ubuntu,a=noble-security,n=noble,l=Ubuntu,c=main,b=arm64
/// ```
///
/// `a=now` is dpkg's own status file rather than a repository, and is skipped.
#[must_use]
pub fn parse_repositories(out: &str, distro_origin: Option<&str>) -> Vec<Repository> {
    let mut repos: Vec<Repository> = Vec::new();
    // from the priority line above each `release` line
    let mut uri: Option<String> = None;

    for line in out.lines() {
        let Some(fields) = line.trim().strip_prefix("release ") else {
            if let Some((location, _)) = source_line(line.trim()) {
                uri = Some(location);
            }
            continue;
        };
        let location = uri.take();
        let mut origin = None;
        let mut archive = None;
        let mut component = None;
        for pair in fields.split(',') {
            match pair.trim().split_once('=') {
                Some(("o", v)) => origin = Some(v),
                Some(("a", v)) => archive = Some(v),
                Some(("c", v)) => component = Some(v),
                _ => {}
            }
        }

        if archive == Some("now") {
            continue;
        }
        let Some(archive) = archive else { continue };

        // `noble-security/main`, as apt shows it
        let id = component.map_or_else(
            || archive.to_owned(),
            |component| format!("{archive}/{component}"),
        );
        if repos.iter().any(|r| r.id == id) {
            continue;
        }

        // No origin counts as third-party. Hand-rolled repositories often
        // have none, and they're the ones likely to break a dist-upgrade.
        let third_party =
            !matches!((origin, distro_origin), (Some(o), Some(d)) if origin_is_distro(o, d));
        repos.push(Repository {
            id,
            kind: "deb".to_owned(),
            third_party,
            enabled: true,
            // third-party only, credentials stripped
            url: location
                .filter(|_| third_party)
                .and_then(|u| updawg_protocol::public_url(&u)),
        });
    }

    repos
}

/// Repositories with their locations, from `apt-cache policy`.
///
/// The priority line has the base URL and `suite/component`; the `release`
/// line under it has the origin, used for third-party the same way as
/// [`parse_repositories`]. One entry per URL and suite, since a suite's
/// components are published together.
///
/// ```text
///  500 https://packages.cloud.google.com/apt cloud-sdk-trixie/main amd64 Packages
///      release o=cloud-sdk-trixie,a=cloud-sdk-trixie,n=cloud-sdk-trixie,c=main,b=amd64
/// ```
#[must_use]
pub fn parse_sources(out: &str, distro_origin: Option<&str>) -> Vec<crate::RepoSource> {
    let mut sources: Vec<crate::RepoSource> = Vec::new();
    let mut pending: Option<(String, String)> = None;
    for line in out.lines() {
        let trimmed = line.trim();
        if let Some(fields) = trimmed.strip_prefix("release ") {
            let Some((uri, suite)) = pending.take() else {
                continue;
            };
            let origin = fields
                .split(',')
                .find_map(|pair| pair.trim().strip_prefix("o="));
            if sources.iter().any(|s| s.uri == uri && s.suite == suite) {
                continue;
            }
            sources.push(crate::RepoSource {
                uri,
                suite,
                third_party: !matches!((origin, distro_origin), (Some(o), Some(d)) if origin_is_distro(o, d)),
                packages: vec![],
            });
        } else if let Some(location) = source_line(trimmed) {
            pending = Some(location);
        }
    }
    sources
}

/// Frozen when every distribution source is a dated snapshot, pinned at the
/// oldest. A single live source (say a security pocket still on the mirror)
/// means updates still arrive, so the host isn't frozen. Third-party
/// repositories are ignored.
#[must_use]
pub fn frozen_sources(sources: &[crate::RepoSource]) -> Option<updawg_protocol::Frozen> {
    let distro: Vec<&crate::RepoSource> = sources.iter().filter(|s| !s.third_party).collect();
    if distro.is_empty() {
        return None;
    }
    let mut stamps = Vec::new();
    for source in distro {
        stamps.push(snapshot_stamp(&source.uri)?);
    }
    stamps.sort_unstable();
    Some(updawg_protocol::Frozen {
        kind: updawg_protocol::FrozenKind::Snapshot,
        pinned: (*stamps.first()?).to_owned(),
        latest: None,
    })
}

/// The timestamp in a snapshot.debian.org or snapshot.ubuntu.com URL, so
/// `https://snapshot.debian.org/archive/debian/20240101T000000Z` gives
/// `20240101T000000Z`. apt's `Snapshot` option uses the same services.
fn snapshot_stamp(uri: &str) -> Option<&str> {
    let (_, rest) = uri.split_once("://")?;
    let (host, path) = rest.split_once('/')?;
    if !matches!(host, "snapshot.debian.org" | "snapshot.ubuntu.com") {
        return None;
    }
    let stamp = path.trim_end_matches('/').rsplit('/').next()?;
    let b = stamp.as_bytes();
    let well_formed = b.len() == 16
        && b[8] == b'T'
        && b[15] == b'Z'
        && b[..8].iter().chain(&b[9..15]).all(u8::is_ascii_digit);
    well_formed.then_some(stamp)
}

/// `500 https://host/path suite/component arch Packages` to (URL, suite).
fn source_line(line: &str) -> Option<(String, String)> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 4 || tokens.last() != Some(&"Packages") || tokens[0].parse::<i32>().is_err() {
        return None;
    }
    let suite = tokens[2].split('/').next().unwrap_or(tokens[2]);
    Some((tokens[1].trim_end_matches('/').to_owned(), suite.to_owned()))
}

/// Which repository each package's installed version came from, from
/// `apt-cache policy <package>...` (the source lines under the `***`
/// version). A version only in `/var/lib/dpkg/status` gives nothing.
///
/// ```text
/// google-cloud-cli:
///   Installed: 586.0.0-0
///   Version table:
///  *** 586.0.0-0 500
///         500 https://packages.cloud.google.com/apt cloud-sdk-trixie/main amd64 Packages
///         100 /var/lib/dpkg/status
/// ```
#[must_use]
pub fn parse_installed_from(out: &str) -> Vec<(String, String, String)> {
    let mut found = Vec::new();
    let mut package: Option<String> = None;
    let mut installed = false;
    for line in out.lines() {
        if !line.starts_with(' ') && line.ends_with(':') {
            package = Some(line.trim_end_matches(':').to_owned());
            installed = false;
            continue;
        }
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("*** ") {
            installed = rest.split_whitespace().count() == 2;
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        // another version of the same package: `1:9.20.26-1~deb13u1 500`
        if tokens.len() == 2 && tokens[1].parse::<i32>().is_ok() && !trimmed.contains('/') {
            installed = false;
            continue;
        }
        if installed && let (Some(p), Some((uri, suite))) = (&package, source_line(trimmed)) {
            found.push((p.clone(), uri, suite));
        }
    }
    found
}

/// Prefix match, since some derivatives use a suffixed origin.
fn origin_is_distro(origin: &str, distro: &str) -> bool {
    origin.eq_ignore_ascii_case(distro)
        || origin
            .to_ascii_lowercase()
            .starts_with(&distro.to_ascii_lowercase())
}

/// The apt origin for the distribution in `/etc/os-release`: `ID=ubuntu`
/// becomes `Ubuntu`. With `None`, every repository counts as third-party.
#[must_use]
pub fn distro_origin(os_release: &str) -> Option<String> {
    let id = os_release.lines().find_map(|line| {
        line.strip_prefix("ID=")
            .map(|v| v.trim().trim_matches('"').to_owned())
    })?;
    if id.is_empty() {
        return None;
    }
    let mut chars = id.chars();
    let first = chars.next()?;
    Some(first.to_uppercase().collect::<String>() + chars.as_str())
}

/// `apt-mark showhold` output: one package name per line.
#[must_use]
pub fn parse_holds(out: &str) -> Vec<String> {
    out.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// `name:arch`. Omitted for `all`, which older apt rejects as a qualifier.
fn qualified(pin: &Pin) -> String {
    if pin.arch == "all" || pin.arch.is_empty() {
        pin.name.clone()
    } else {
        format!("{}:{}", pin.name, pin.arch)
    }
}

/// The pins not yet at their approved version.
///
/// `installed` maps [`qualified`] names to the version dpkg reports.
///
/// # Errors
/// [`BackendError::Refused`] when a package moved since the approval.
pub fn still_to_do<'a>(
    pins: &'a [Pin],
    installed: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<&'a Pin>> {
    let mut todo = Vec::new();
    for pin in pins {
        match installed.get(&qualified(pin)).map(String::as_str) {
            Some(v) if v == pin.to => {}
            Some(v) if v == pin.from => todo.push(pin),
            Some(v) => {
                return Err(BackendError::Refused(format!(
                    "{} is at {v}, and the job was approved for {} to {}",
                    pin.name, pin.from, pin.to
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

const APT_OPTIONS: &[&str] = &[
    "-y",
    "--only-upgrade",
    "--no-install-recommends",
    // wait for unattended-upgrades to release the lock
    "-o",
    "DPkg::Lock::Timeout=600",
    // keep local config; the package's version is left as `.dpkg-dist`
    "-o",
    "Dpkg::Options::=--force-confdef",
    "-o",
    "Dpkg::Options::=--force-confold",
];

#[must_use]
pub fn install_args(todo: &[&Pin]) -> Vec<String> {
    let mut args = vec!["install".to_owned()];
    args.extend(APT_OPTIONS.iter().map(|&o| o.to_owned()));
    args.extend(todo.iter().map(|p| format!("{}={}", qualified(p), p.to)));
    args
}

/// Output as it would look on a terminal. dpkg redraws progress lines
/// ("Reading database ... 45%") with `\r`, so keep only the last redraw of
/// each line and drop blank ones.
pub fn as_shown(output: &str) -> impl Iterator<Item = &str> {
    output
        .lines()
        .map(|line| {
            line.rsplit('\r')
                .find(|s| !s.trim().is_empty())
                .unwrap_or("")
        })
        .filter(|line| !line.trim().is_empty())
}

#[must_use]
pub fn simulate_args(todo: &[&Pin]) -> Vec<String> {
    let mut args = install_args(todo);
    args.insert(1, "-s".to_owned());
    args
}

/// Output of a command, whatever its exit status.
#[derive(Debug, Clone)]
pub struct Ran {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// `(package, version)` to `(source package, source version)`.
pub type Sources = std::collections::BTreeMap<(String, String), (String, String)>;

/// New, unpinned packages the simulation would install
/// (`Inst name (version ...)` with no `[old]`).
#[must_use]
pub fn unpinned_new_installs(todo: &[&Pin], simulated: &Ran) -> Vec<(String, String)> {
    simulated
        .stdout
        .lines()
        .filter_map(inst)
        .filter(|(name, old, _)| {
            old.is_none()
                && !todo
                    .iter()
                    .any(|p| &p.name == name || &qualified(p) == name)
        })
        .map(|(name, _, new)| (name, new))
        .collect()
}

/// `Inst openssl [3.5.1-1] (3.5.1-2 Debian-Security:13/stable-security [amd64])`
/// as name, old version, new version.
fn inst(line: &str) -> Option<(String, Option<String>, String)> {
    let rest = line.strip_prefix("Inst ")?;
    let name = rest.split_whitespace().next()?.to_owned();
    let old = rest
        .split_whitespace()
        .nth(1)
        .and_then(|w| w.strip_prefix('['))
        .and_then(|w| w.strip_suffix(']'))
        .map(str::to_owned);
    let new = line
        .split('(')
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .unwrap_or("")
        .to_owned();
    Some((name, old, new))
}

/// Checks the simulation does exactly what was approved, except that it may
/// also install new packages built from the same source upload as an
/// approved one.
///
/// That exception exists for kernels: upgrading `linux-image-cloud-amd64` to
/// 6.12.111-1 installs `linux-image-6.12.111+deb13-cloud-amd64`, whose name
/// changes with every ABI, so it never shows up as an upgrade. Both come from
/// the same `linux-signed-amd64` upload. Any other new package, any removal,
/// or any unapproved version is refused.
///
/// `sources` comes from [`parse_uploads`]. Returns the extra packages as
/// `name version`.
///
/// # Errors
/// [`BackendError::Refused`] naming what differs.
pub fn check_simulation(todo: &[&Pin], simulated: &Ran, sources: &Sources) -> Result<Vec<String>> {
    if simulated.code != 0 {
        // usually "Version 'x' for 'y' was not found": the approved version
        // has left the archive
        let why = simulated
            .stderr
            .lines()
            .chain(simulated.stdout.lines())
            .find(|l| l.starts_with("E:"))
            .unwrap_or("apt refused the simulation")
            .trim_start_matches("E: ");
        return Err(BackendError::Refused(format!(
            "the approved versions cannot be installed: {why}"
        )));
    }
    let mut upgraded = std::collections::BTreeMap::new();
    for line in simulated.stdout.lines() {
        if let Some(name) = line.strip_prefix("Remv ") {
            let name = name.split_whitespace().next().unwrap_or("?");
            return Err(BackendError::Refused(format!(
                "installing the approved versions would remove {name}, which nobody approved"
            )));
        }
        if let Some((name, old, new)) = inst(line) {
            upgraded.insert(name, (old, new));
        }
    }
    let upload = |name: &str, version: &str| sources.get(&(name.to_owned(), version.to_owned()));
    let mut alongside = Vec::new();
    for (name, (old, version)) in &upgraded {
        let approved = todo
            .iter()
            .find(|p| &p.name == name || &qualified(p) == name);
        match approved {
            Some(p) if &p.to == version => {}
            Some(p) => {
                return Err(BackendError::Refused(format!(
                    "apt would install {name} {version}, and {} was approved",
                    p.to
                )));
            }
            None if old.is_none()
                && upload(name, version).is_some_and(|built| {
                    todo.iter().any(|p| upload(&p.name, &p.to) == Some(built))
                }) =>
            {
                alongside.push(format!("{name} {version}"));
            }
            None => {
                return Err(BackendError::Refused(format!(
                    "installing the approved versions would also install {name} {version}, which nobody approved"
                )));
            }
        }
    }
    if let Some(missing) = todo
        .iter()
        .find(|p| !upgraded.contains_key(&p.name) && !upgraded.contains_key(&qualified(p)))
    {
        return Err(BackendError::Refused(format!(
            "apt would not upgrade {}; is it held?",
            missing.name
        )));
    }
    Ok(alongside)
}

/// `apt-cache show name=version ...`: the source upload for each stanza.
/// `Source:` is absent when the source has the binary's name, and only has a
/// `(version)` when that differs from the binary's.
#[must_use]
pub fn parse_uploads(show: &str) -> Sources {
    let mut out = Sources::new();
    for stanza in show.split("\n\n") {
        let field = |key: &str| {
            stanza
                .lines()
                .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_owned()))
        };
        let (Some(package), Some(version)) = (field("Package:"), field("Version:")) else {
            continue;
        };
        let (source, source_version) = match field("Source:") {
            Some(src) => match src.split_once(' ') {
                Some((name, v)) => (
                    name.to_owned(),
                    v.trim_start_matches('(').trim_end_matches(')').to_owned(),
                ),
                None => (src, version.clone()),
            },
            None => (package.clone(), version.clone()),
        };
        out.entry((package, version))
            .or_insert((source, source_version));
    }
    out
}

/// Fills in each candidate's source package from `apt-cache show`, 200 at a
/// time. The server uses it to look up changelogs; it can differ from the
/// installed package's source (kernels, for instance). Best effort: on
/// failure the update is sent without it.
async fn candidate_sources(updates: &mut [AvailableUpdate]) {
    for chunk in updates.chunks_mut(200) {
        let mut args = vec!["show".to_owned()];
        args.extend(chunk.iter().map(|u| format!("{}={}", u.name, u.candidate)));
        // exits 100 if any are missing; the rest is still usable
        let Ok(shown) = run_status("apt-cache", &args).await else {
            continue;
        };
        let sources = parse_uploads(&shown.stdout);
        for update in chunk.iter_mut() {
            if let Some((name, version)) =
                sources.get(&(update.name.clone(), update.candidate.clone()))
            {
                update.source = Some(updawg_protocol::SourcePackage {
                    name: name.clone(),
                    version: version.clone(),
                });
            }
        }
    }
}

/// Source uploads for the new packages and the pinned targets. Only queried
/// when there's a new package.
async fn sources_for(todo: &[&Pin], simulated: &Ran) -> Result<Sources> {
    let new = unpinned_new_installs(todo, simulated);
    if new.is_empty() {
        return Ok(Sources::new());
    }
    let mut args = vec!["show".to_owned()];
    args.extend(todo.iter().map(|p| format!("{}={}", p.name, p.to)));
    args.extend(new.iter().map(|(name, version)| {
        let bare = name.split(':').next().unwrap_or(name);
        format!("{bare}={version}")
    }));
    // exits 100 if any are missing; those get refused by the check
    let shown = run_status("apt-cache", &args).await?;
    let mut sources = parse_uploads(&shown.stdout);
    // the simulation may say `name:arch`, so key it both ways
    for (name, version) in &new {
        let bare = name.split(':').next().unwrap_or(name).to_owned();
        if let Some(built) = sources.get(&(bare, version.clone())).cloned() {
            sources.insert((name.clone(), version.clone()), built);
        }
    }
    Ok(sources)
}

/// The read-only first half of [`AptBackend::apply`], also used by the
/// preflight.
async fn simulate(todo: &[&Pin]) -> Result<Vec<String>> {
    let simulated = run_status("apt-get", &simulate_args(todo)).await?;
    let sources = sources_for(todo, &simulated).await?;
    check_simulation(todo, &simulated, &sources)
}

/// What changed, according to dpkg afterwards.
///
/// # Errors
/// [`BackendError::CommandFailed`] when apt exited cleanly but a package
/// still isn't at its approved version.
pub fn changes(
    todo: &[&Pin],
    after: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<Change>> {
    let mut changed = Vec::new();
    for pin in todo {
        let now = after.get(&qualified(pin)).cloned().unwrap_or_default();
        if now != pin.to {
            return Err(BackendError::CommandFailed {
                tool: "apt-get",
                status: 0,
                stderr: format!("{} is at {now} after installing, not {}", pin.name, pin.to),
            });
        }
        changed.push(Change {
            name: pin.name.clone(),
            arch: pin.arch.clone(),
            from: pin.from.clone(),
            to: now,
        });
    }
    Ok(changed)
}

fn reboot_required() -> bool {
    std::path::Path::new("/var/run/reboot-required").exists()
}

async fn installed_versions(pins: &[Pin]) -> Result<std::collections::BTreeMap<String, String>> {
    let names: Vec<String> = pins.iter().map(qualified).collect();
    let mut args = vec![
        "-W".to_owned(),
        "-f=${Package}:${Architecture}\t${Version}\t${db:Status-Status}\n".to_owned(),
    ];
    args.extend(names);
    // exit 1 just means one of them isn't installed
    let ran = run_status("dpkg-query", &args).await?;
    Ok(parse_versions(&ran.stdout))
}

/// `dpkg-query -W -f='${Package}:${Architecture}\t${Version}\t${db:Status-Status}\n'`,
/// installed packages only, keyed the way [`qualified`] spells them.
#[must_use]
pub fn parse_versions(out: &str) -> std::collections::BTreeMap<String, String> {
    out.lines()
        .filter_map(|line| {
            let mut f = line.split('\t');
            let (name, version, status) = (f.next()?, f.next()?, f.next()?);
            (status.trim() == "installed").then(|| {
                let key = name.strip_suffix(":all").unwrap_or(name).to_owned();
                (key, version.to_owned())
            })
        })
        .collect()
}

async fn run_status(tool: &'static str, args: &[String]) -> Result<Ran> {
    let output = tokio::process::Command::new(tool)
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        // stop needrestart restarting services on its own; `l` only lists
        .env("NEEDRESTART_MODE", "l")
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

async fn run(tool: &'static str, args: &[&str]) -> Result<String> {
    let output = tokio::process::Command::new(tool)
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        // The parsers match apt's English output. Under another locale they'd
        // silently find no updates.
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
    if !output.status.success() {
        // the caller retries later; forcing the lock corrupts the database
        if stderr.contains("Could not get lock") || stderr.contains("Unable to acquire the dpkg") {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn source(uri: &str, third_party: bool) -> crate::RepoSource {
        crate::RepoSource {
            uri: uri.into(),
            suite: "bookworm".into(),
            third_party,
            packages: vec![],
        }
    }

    #[test]
    fn a_host_is_frozen_only_when_every_distribution_source_is_a_snapshot() {
        let main = source(
            "http://snapshot.debian.org/archive/debian/20240315T000000Z",
            false,
        );
        let security = source(
            "http://snapshot.debian.org/archive/debian-security/20240101T120000Z",
            false,
        );
        let docker = source("https://download.docker.com/linux/debian", true);

        let frozen = frozen_sources(&[main.clone(), security, docker.clone()]).unwrap();
        assert_eq!(frozen.kind, updawg_protocol::FrozenKind::Snapshot);
        assert_eq!(frozen.pinned, "20240101T120000Z", "the oldest pins it");
        assert_eq!(frozen.latest, None);

        let live = source("http://deb.debian.org/debian-security", false);
        assert_eq!(frozen_sources(&[main, live]), None);
        assert_eq!(frozen_sources(&[docker]), None, "third-party only");
        assert_eq!(frozen_sources(&[]), None);

        let ubuntu = source("https://snapshot.ubuntu.com/ubuntu/20240301T030400Z", false);
        assert_eq!(
            frozen_sources(&[ubuntu]).unwrap().pinned,
            "20240301T030400Z"
        );
        let not_a_stamp = source("http://snapshot.debian.org/archive/debian/latest", false);
        assert_eq!(frozen_sources(&[not_a_stamp]), None);
    }
}
