//! Debian-family backend (DAWG-34).
//!
//! Installed packages come from `dpkg-query -W` with a tab-separated format
//! string, candidates and pending removals from one simulated
//! `apt-get -s dist-upgrade`, repository origin from `apt-cache policy`, and
//! holds from `apt-mark showhold`.
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

use crate::{
    ApplyOutcome, ApplyPlan, BackendError, Change, LogSink, PackageBackend, PendingChanges, Pin,
    Result,
};
use async_trait::async_trait;
use updawg_protocol::{AvailableUpdate, Ecosystem, InstalledPackage, PendingRemoval, Repository};

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

    async fn pending_changes(&self) -> Result<PendingChanges> {
        // Simulated, so it takes no locks and changes nothing. `-s` implies
        // Debug::NoLocking, which is what lets this run while unattended-upgrades
        // holds the real lock — an agent that could only report when nothing else
        // was working would be silent exactly when it mattered.
        //
        // One simulation answers both halves: apt prints `Inst` and `Remv` lines
        // from the same run, and this is the expensive call in a collection pass.
        let installed = self.installed().await?;
        let out = run("apt-get", &["-s", "dist-upgrade"]).await?;
        Ok(PendingChanges {
            updates: parse_updates(&out),
            removals: parse_removals(&out, &installed),
        })
    }

    async fn repositories(&self) -> Result<Vec<Repository>> {
        let out = run("apt-cache", &["policy"]).await?;
        Ok(parse_repositories(&out, self.origin.as_deref()))
    }

    async fn held_packages(&self) -> Result<Vec<String>> {
        let out = run("apt-mark", &["showhold"]).await?;
        Ok(parse_holds(&out))
    }

    async fn security_updates(
        &self,
        updates: &[AvailableUpdate],
    ) -> Result<std::collections::BTreeSet<String>> {
        // Already answered by the collection that produced `updates`: apt names
        // the pocket a candidate comes from, and `-security` is the whole signal.
        Ok(updates
            .iter()
            .filter(|u| u.repo.as_deref().is_some_and(is_security_archive))
            .map(|u| u.name.clone())
            .collect())
    }

    /// Install exactly the approved versions, or nothing (DAWG-102).
    ///
    /// Four steps, and the first three change nothing:
    ///
    /// 1. **What is installed now.** Each pin must be at its `from` version —
    ///    or already at its `to`, which is done and skipped. Anything else is
    ///    a host that moved since the approval, and is refused.
    /// 2. **What apt would do**, by simulation with the exact command line.
    ///    It must upgrade exactly the pins that remain, to exactly their
    ///    versions, and nothing else: a removal, or a package pulled in that
    ///    nobody approved, is refused. So is an approved version apt can no
    ///    longer find — the candidate moved on.
    /// 3. **Do it**, with the same command line: non-interactive, keeping
    ///    local configuration files, waiting for the dpkg lock rather than
    ///    fighting `unattended-upgrades` for it.
    /// 4. **What is installed after.** Each pin must now be at its `to`. The
    ///    changes reported are what dpkg says, not what was asked for.
    async fn apply(&self, plan: &ApplyPlan, log: &dyn LogSink) -> Result<ApplyOutcome> {
        let before = installed_versions(&plan.packages).await?;
        let todo = still_to_do(&plan.packages, &before)?;
        if todo.is_empty() {
            log.line("every approved version is already installed; nothing to do");
            return Ok(ApplyOutcome {
                changed: vec![],
                reboot_required: reboot_required(),
            });
        }

        let simulated = run_status("apt-get", &simulate_args(&todo)).await?;
        check_simulation(&todo, &simulated)?;

        log.line(&format!(
            "installing {} package(s) at their approved versions",
            todo.len()
        ));
        let installed = run_status("apt-get", &install_args(&todo)).await?;
        for line in installed.stdout.lines() {
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
                // apt has no `updateinfo`. The pocket on `repo` is the whole of
                // what it says about an update, and it is already there.
                advisories: Vec::new(),
            })
        })
        .collect()
}

/// The `Remv` lines of `apt-get -s dist-upgrade` (DAWG-232).
///
/// ```text
/// Remv barpkg [1.0]
/// Inst foopkg [1.0] (2.0 localhost [all])
/// ```
///
/// **apt says that a package will be removed and never what replaces it.**
/// Captured from a Debian 12 container with a package built to `Replaces` and
/// `Conflicts` another: the `Remv` line carries a name and the installed
/// version, and nothing links it to the `Inst` line that caused it. That is why
/// [`PendingRemoval::replaced_by`] is an `Option` — dnf names the obsoleting
/// package and apt does not, and inventing one here would be a lie with a name
/// and a version in it.
///
/// The architecture comes from the installed set rather than from the line, for
/// the same reason `parse_updates` strips `:armhf` from a name: apt writes
/// `name:arch` only for a foreign architecture, and dpkg keeps the architecture
/// in its own field. A package the host does not have is dropped, which is the
/// same guard as everywhere else here — apt should never propose removing one,
/// and an entry with an invented architecture would be indistinguishable from a
/// real one downstream.
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

/* ------------------------------------------------------ applying, decided */

/// `name:arch` as apt and dpkg spell a package on one architecture.
///
/// `all` is left off: an architecture-independent package has one version for
/// every architecture, and older apt refuses the qualifier.
fn qualified(pin: &Pin) -> String {
    if pin.arch == "all" || pin.arch.is_empty() {
        pin.name.clone()
    } else {
        format!("{}:{}", pin.name, pin.arch)
    }
}

/// The pins not already at their approved version, or a refusal naming the
/// first one that is at neither end.
///
/// `installed` maps [`qualified`] names to the version dpkg reports; a package
/// that is not installed at all is absent.
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
    // Wait for the lock rather than fight unattended-upgrades for it. Ten
    // minutes is longer than it ever holds it.
    "-o",
    "DPkg::Lock::Timeout=600",
    // A changed configuration file keeps the local version. The package's
    // new one is left beside it as `.dpkg-dist`, for a person to read.
    "-o",
    "Dpkg::Options::=--force-confdef",
    "-o",
    "Dpkg::Options::=--force-confold",
];

/// The exact `apt-get install` command line for these pins.
#[must_use]
pub fn install_args(todo: &[&Pin]) -> Vec<String> {
    let mut args = vec!["install".to_owned()];
    args.extend(APT_OPTIONS.iter().map(|&o| o.to_owned()));
    args.extend(todo.iter().map(|p| format!("{}={}", qualified(p), p.to)));
    args
}

/// The same command line, simulated.
#[must_use]
pub fn simulate_args(todo: &[&Pin]) -> Vec<String> {
    let mut args = install_args(todo);
    args.insert(1, "-s".to_owned());
    args
}

/// What an `apt-get` run said, whatever its exit status.
#[derive(Debug, Clone)]
pub struct Ran {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Whether apt's simulation does exactly what was approved and nothing else.
///
/// # Errors
/// [`BackendError::Refused`] naming what differs.
pub fn check_simulation(todo: &[&Pin], simulated: &Ran) -> Result<()> {
    if simulated.code != 0 {
        // Almost always "Version 'x' for 'y' was not found": the archive moved
        // on and the approved version is gone.
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
        let mut words = line.split_whitespace();
        match words.next() {
            Some("Remv") => {
                let name = words.next().unwrap_or("?");
                return Err(BackendError::Refused(format!(
                    "installing the approved versions would remove {name}, which nobody approved"
                )));
            }
            Some("Inst") => {
                let name = words.next().unwrap_or("?").to_owned();
                // `Inst openssl [3.5.1-1] (3.5.1-2 Debian-Security:13/stable-security [amd64])`
                let new = line
                    .split('(')
                    .nth(1)
                    .and_then(|rest| rest.split_whitespace().next())
                    .unwrap_or("")
                    .to_owned();
                upgraded.insert(name, new);
            }
            _ => {}
        }
    }
    for (name, version) in &upgraded {
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
            "apt would not upgrade {} — is it held?",
            missing.name
        )));
    }
    Ok(())
}

/// What changed, from dpkg's own account afterwards.
///
/// # Errors
/// [`BackendError::CommandFailed`] when apt exited cleanly and a package is
/// still not at its approved version — which would otherwise be reported as a
/// success that patched nothing.
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

/// `/var/run/reboot-required`, which Debian and Ubuntu's packages touch.
fn reboot_required() -> bool {
    std::path::Path::new("/var/run/reboot-required").exists()
}

/// The version dpkg reports for each pin's package, where installed.
async fn installed_versions(pins: &[Pin]) -> Result<std::collections::BTreeMap<String, String>> {
    let names: Vec<String> = pins.iter().map(qualified).collect();
    let mut args = vec![
        "-W".to_owned(),
        "-f=${Package}:${Architecture}\t${Version}\t${db:Status-Status}\n".to_owned(),
    ];
    args.extend(names);
    // Exit 1 means "one of these is not installed", which is an answer.
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

/* ------------------------------------- running apt, whatever it answers */

async fn run_status(tool: &'static str, args: &[String]) -> Result<Ran> {
    let output = tokio::process::Command::new(tool)
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        // Ubuntu's needrestart would otherwise restart services by itself,
        // which is a decision this job was not approved to make. `l` lists.
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
