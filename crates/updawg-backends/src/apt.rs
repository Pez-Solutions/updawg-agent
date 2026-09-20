//! Debian-family backend (DAWG-34).
//!
//! Installed packages come from `dpkg-query -W` with a tab-separated format
//! string, candidates from a simulated `apt-get -s dist-upgrade`, repository
//! origin from `apt-cache policy`, and holds from `apt-mark showhold`.
//!
//! Shelling out rather than linking `libapt` is what keeps the binary statically
//! linked against musl, so one build per architecture runs on every supported
//! distribution.
//!
//! # Where the logic lives
//!
//! Every function that interprets output is a **pure function over `&str`**, and
//! every one of them is tested against output captured from real containers —
//! Ubuntu 20.04, 22.04, 24.04 and Debian 11, 12, in `tests/fixtures/apt/`. The
//! methods below are a shell invocation and a call to one of those. That split is
//! deliberate: the parsing is where the bugs are, and it is the part that can be
//! tested without a package manager present.
//!
//! # What the agent does not decide
//!
//! Whether an update is *security* is reported here only as what apt itself says
//! — the candidate comes from a pocket whose archive ends in `-security`. That is
//! a local hint for the heartbeat, not a classification: the authoritative answer
//! is the server's, against advisory data, because the distribution's own
//! metadata is incomplete and inconsistent between families.

use crate::{ApplyOutcome, ApplyPlan, BackendError, LogSink, PackageBackend, Result};
use async_trait::async_trait;
use updawg_protocol::{AvailableUpdate, Ecosystem, InstalledPackage, Repository};

#[derive(Debug, Default, Clone)]
pub struct AptBackend {
    /// The distribution's own origin, as `apt-cache policy` spells it — `Ubuntu`,
    /// `Debian`, `Raspbian`. Everything else is third-party.
    ///
    /// Read from `/etc/os-release` rather than hard-coded, so a derivative
    /// reports its own archives as its own rather than as somebody else's.
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
                "${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n",
            ],
        )
        .await?;
        Ok(parse_installed(&out))
    }

    async fn refresh_metadata(&self) -> Result<()> {
        run("apt-get", &["update", "-qq"]).await.map(|_| ())
    }

    async fn available_updates(&self) -> Result<Vec<AvailableUpdate>> {
        // Simulated, so it takes no locks and changes nothing. `-s` implies
        // Debug::NoLocking, which is what lets this run while unattended-upgrades
        // holds the real lock — an agent that could only report when nothing else
        // was working would be silent exactly when it mattered.
        let out = run("apt-get", &["-s", "dist-upgrade"]).await?;
        Ok(parse_updates(&out))
    }

    async fn repositories(&self) -> Result<Vec<Repository>> {
        let out = run("apt-cache", &["policy"]).await?;
        Ok(parse_repositories(&out, self.origin.as_deref()))
    }

    async fn held_packages(&self) -> Result<Vec<String>> {
        let out = run("apt-mark", &["showhold"]).await?;
        Ok(parse_holds(&out))
    }

    async fn apply(&self, _plan: &ApplyPlan, _log: &dyn LogSink) -> Result<ApplyOutcome> {
        // Deliberately still a stub. Applying updates is the mutating half and
        // belongs with job execution and its permission checks (DAWG-38); DAWG-34
        // is the reporting half. A backend that could report and not act is a
        // useful thing to ship on its own.
        Err(BackendError::ToolMissing {
            tool: "apt-get install (DAWG-38)",
        })
    }
}

/* ------------------------------------------------------------- the parsers */

/// `dpkg-query -W` output: name, version, architecture, status.
///
/// **Only `installed` counts.** dpkg also knows `config-files` (purged but
/// configuration left behind), `half-configured`, `unpacked` and several others.
/// Reporting those as installed would have the server matching advisories against
/// packages whose files are not on disk, and proposing upgrades for them.
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
            Some(InstalledPackage {
                name: name.to_owned(),
                version: version.to_owned(),
                arch: arch.to_owned(),
                // dpkg does not know which repository a package came from; that
                // is apt's view, and it is only true for packages still
                // available. Left absent rather than guessed.
                repo: None,
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
/// **The bracket before `(` is the whole distinction.** With it, the package is
/// installed at that version and an upgrade is available. Without it, apt is
/// proposing to install something new — a dependency being pulled in — and
/// reporting that as an available update would invent an upgrade for a package
/// the host does not have.
#[must_use]
pub fn parse_updates(out: &str) -> Vec<AvailableUpdate> {
    out.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("Inst ")?;
            let (name, rest) = rest.split_once(' ')?;

            // A new install, not an upgrade.
            let rest = rest.strip_prefix('[')?;
            let (installed, rest) = rest.split_once(']')?;

            // Everything that matters — the candidate version, the origins and
            // the architecture — is inside the parentheses. Anything after them
            // is not: apt appends `[]` to mark a package pulled in as a
            // dependency (`Inst libgcc-s1:armhf (… [armhf]) []`), and taking the
            // parenthesised group is the whole of what excludes it. There is only
            // ever one such group, so `find` and `rfind` are interchangeable here
            // and neither is load-bearing.
            let open = rest.find('(')?;
            let close = rest.rfind(')')?;
            let inner = rest.get(open + 1..close)?;

            let (candidate, origins) = inner.split_once(' ').unwrap_or((inner, ""));

            Some(AvailableUpdate {
                // Foreign-architecture packages are named `libc6:armhf` here and
                // plain `libc6` in dpkg-query, where the architecture is its own
                // field. Stripping it keeps one package one name.
                name: name.split(':').next().unwrap_or(name).to_owned(),
                arch: architecture(inner).unwrap_or_default(),
                installed: installed.to_owned(),
                candidate: candidate.to_owned(),
                repo: pocket(origins),
            })
        })
        .collect()
}

/// The architecture apt printed in the trailing `[arm64]`.
///
/// `inner` is already the parenthesised group, so the `[]` apt appends after it
/// for a dependency pull-in is not in scope here. Verified by mutation rather
/// than assumed: `a_foreign_architecture_package_keeps_one_name` parses a line
/// carrying that `[]` and still reads `armhf`.
fn architecture(inner: &str) -> Option<String> {
    let open = inner.rfind('[')?;
    let close = inner[open..].find(']')? + open;
    let arch = inner.get(open + 1..close)?;
    (!arch.is_empty()).then(|| arch.to_owned())
}

/// The pocket a candidate comes from, e.g. `noble-security`.
///
/// apt renders origins as `Origin:version/archive`, comma-separated when a
/// version is in more than one: `Ubuntu:24.04/noble-updates,
/// Ubuntu:24.04/noble-security`. **A security pocket anywhere in that list wins**,
/// because that is what it means for an update to be available from security —
/// taking the first would report the noble-updates copy of a security fix as an
/// ordinary update, and every Ubuntu security update is published to both.
fn pocket(origins: &str) -> Option<String> {
    let archives: Vec<&str> = origins
        .split(',')
        .filter_map(|o| o.trim().split('/').nth(1))
        // The architecture group rides on the end of the last origin —
        // `Ubuntu:24.04/noble-security [arm64]` — so the archive has to be cut at
        // whitespace. Without this the suffix test never matches the last origin,
        // and since Ubuntu lists -updates first and publishes every security
        // update to both, *every* Ubuntu security update would be reported as an
        // ordinary one.
        .map(|a| a.split_whitespace().next().unwrap_or(a))
        .filter(|a| !a.is_empty())
        .collect();

    archives
        .iter()
        .find(|a| is_security_archive(a))
        .or_else(|| archives.first())
        .map(|a| (*a).to_owned())
}

/// Whether an archive name is a security pocket.
///
/// One rule covers both families, which is why it is done on the archive rather
/// than the origin or the label: Ubuntu publishes to `noble-security` with
/// `o=Ubuntu`, and Debian to `bookworm-security` with `o=Debian` and
/// `l=Debian-Security`. The suffix is the only part they agree on.
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

    for line in out.lines() {
        let Some(fields) = line.trim().strip_prefix("release ") else {
            continue;
        };
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

        // The local dpkg status file, which is not a repository.
        if archive == Some("now") {
            continue;
        }
        let Some(archive) = archive else { continue };

        // `noble-security/main`, matching how apt names it to a human.
        let id = component.map_or_else(
            || archive.to_owned(),
            |component| format!("{archive}/{component}"),
        );
        if repos.iter().any(|r| r.id == id) {
            continue;
        }

        repos.push(Repository {
            id,
            kind: "deb".to_owned(),
            // Absent origin counts as third-party: an unsigned or hand-rolled
            // repository often has none, and those are exactly the ones that
            // break a dist-upgrade. Unknown provenance is not the distribution's.
            third_party: !matches!((origin, distro_origin), (Some(o), Some(d)) if origin_is_distro(o, d)),
            enabled: true,
        });
    }

    repos
}

/// Whether an apt origin belongs to the distribution the host is running.
///
/// Debian publishes security updates under the origin `Debian` but some
/// derivatives use a suffixed form, so this is a prefix match on the
/// distribution's own name rather than equality.
fn origin_is_distro(origin: &str, distro: &str) -> bool {
    origin.eq_ignore_ascii_case(distro)
        || origin
            .to_ascii_lowercase()
            .starts_with(&distro.to_ascii_lowercase())
}

/// The apt origin for the distribution described by `/etc/os-release`.
///
/// `ID=ubuntu` becomes `Ubuntu`, which is how apt spells it. Returns `None` when
/// the file says nothing useful, and then every repository reads as third-party —
/// the safe direction, because a third-party repository is reported and reviewed
/// rather than silently trusted.
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
///
/// A held package will not be upgraded no matter what a proposal says, so a plan
/// that ignores these is a plan that silently does nothing.
#[must_use]
pub fn parse_holds(out: &str) -> Vec<String> {
    out.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/* ------------------------------------------------------------- the shelling */

async fn run(tool: &'static str, args: &[&str]) -> Result<String> {
    let output = tokio::process::Command::new(tool)
        .args(args)
        // Non-interactive and predictable. Without these apt will occasionally
        // try to open a pager or ask a question, and an agent has nobody to ask.
        .env("DEBIAN_FRONTEND", "noninteractive")
        // Parsing depends on the exact words apt prints. A host with LANG set to
        // anything else would parse as an empty upgrade list — no error, no
        // updates, and a fleet that looks perfectly patched.
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
        // A lock is a wait-and-retry, not a failure to report: forcing it
        // corrupts the package database, and the caller decides when to come back.
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
