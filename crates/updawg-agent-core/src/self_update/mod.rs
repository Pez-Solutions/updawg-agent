//! The `self_update` job: the agent updating itself.
//!
//! There are two install methods, and each updates its own way:
//!
//! - A package install (the .deb or .rpm from pkg.updawg.net): apt or dnf
//!   installs the requested version from the host's configured repository and
//!   checks its signature against the release key.
//! - install.sh's binaries in `/usr/local/bin`: the agent fetches the
//!   channel's manifest, verifies it against the compiled-in [`RELEASE_KEY`],
//!   and replaces the binaries with the ones it lists, checked by sha256.
//!
//! # The helper unit
//!
//! The agent can't replace itself. Anything it spawns lives in its own
//! cgroup, so restarting `updawgd` would kill the package manager or the
//! binary swap halfway through. Instead the agent does the checks
//! ([`start`]), records a [`Pending`] update, and starts
//! `updawgctl self-update-run` in a transient systemd unit ([`helper`]),
//! which:
//!
//! 1. installs or swaps, and restarts `updawgd`;
//! 2. waits for the new version to check in successfully (it watches
//!    `last-checkin.json`, which the agent writes after every check-in);
//! 3. if that doesn't happen in time, restores the previous version,
//!    restarts it, and records an [`Outcome`].
//!
//! Whichever agent is running at the end reports the job
//! ([`crate::jobs::Executor::resume_after_self_update`]), the same way a job
//! that reboots the host is reported.

pub mod helper;

use crate::state::LocalState;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;
use updawg_protocol::{Job, JobComplete, ReleaseChannel, ReleaseManifest};

/// Public half of the release signing key (PKCS#1 `RSAPublicKey`, DER), the
/// same key that signs pkg.updawg.net. SHA-256 of the file:
/// `05ac56cc6b856b5df464feacc66dc239dfc598f942af5577702a729c0081028c`; the
/// modulus begins `cd5007d5`, matching `updawg.asc`.
///
/// Agents built before 2026-10-07 trust an older key (modulus `8b4906e6`)
/// and have to be reinstalled from get.updawg.net.
///
/// Not configurable and never fetched: whoever could change it could ship an
/// agent.
pub const RELEASE_KEY: &[u8] = include_bytes!("release-key.der");

/// Where the manifests are: `<base>/bin/<channel>.json`.
pub const RELEASE_BASE: &str = "https://pkg.updawg.net";

/// The helper's transient unit. A fixed name means systemd refuses to start
/// a second update while one is running.
pub const UNIT: &str = "updawg-self-update";

/// How long the helper waits for the new agent to check in before rolling
/// back. The agent checks in right after starting, so this mostly covers a
/// slow gateway.
pub const CONFIRM_WITHIN: Duration = Duration::from_secs(300);

pub const PACKAGE: &str = "updawg-agent";

/// This build's target, as the manifest names binaries.
#[must_use]
pub const fn target() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64-unknown-linux-musl"
    } else {
        "x86_64-unknown-linux-musl"
    }
}

/// How this agent was installed, and so how it updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Method {
    Apt,
    Dnf,
    /// install.sh's binaries, in `dir`.
    Binary {
        dir: PathBuf,
    },
}

/// Picks the method for an agent running from `exe`, given whether the
/// package database owns the file and whether the host uses dpkg.
///
/// # Errors
/// If the agent was installed some other way.
pub fn method_for(exe: &Path, packaged: bool, dpkg: bool) -> Result<Method, String> {
    if packaged {
        return Ok(if dpkg { Method::Apt } else { Method::Dnf });
    }
    match exe.parent() {
        Some(dir) if dir == Path::new("/usr/local/bin") => Ok(Method::Binary {
            dir: dir.to_path_buf(),
        }),
        _ => Err(format!(
            "this agent runs from {}, which no package owns and install.sh did not put there; update it the way it was installed",
            exe.display()
        )),
    }
}

/// Where install.sh writes the package repository (`packaging/install.sh`).
pub const APT_SOURCE: &str = "/etc/apt/sources.list.d/updawg.list";
/// The dnf equivalent of [`APT_SOURCE`].
pub const DNF_REPO: &str = "/etc/yum.repos.d/updawg.repo";

/// Install method and, for package installs, the repository's channel, as
/// reported in the check-in. Called once at startup. An agent that can't
/// update itself reports `other`.
#[must_use]
pub fn install() -> updawg_protocol::AgentInstall {
    use updawg_protocol::{AgentInstall, InstallMethod};
    let read = |path: &str| std::fs::read_to_string(path).ok();
    match detect() {
        Ok(Method::Apt) => AgentInstall {
            method: InstallMethod::Apt,
            channel: read(APT_SOURCE).as_deref().and_then(apt_channel),
        },
        Ok(Method::Dnf) => AgentInstall {
            method: InstallMethod::Dnf,
            channel: read(DNF_REPO).as_deref().and_then(dnf_channel),
        },
        Ok(Method::Binary { .. }) => AgentInstall {
            method: InstallMethod::Binary,
            channel: None,
        },
        Err(_) => AgentInstall {
            method: InstallMethod::Other,
            channel: None,
        },
    }
}

/// Suite of the `.../apt` line in install.sh's source file:
/// `deb [signed-by=/etc/apt/keyrings/updawg.asc] https://pkg.updawg.net/apt stable main`.
#[must_use]
pub fn apt_channel(list: &str) -> Option<String> {
    list.lines()
        .map(str::trim)
        .filter(|line| line.starts_with("deb ") || line.starts_with("deb\t"))
        .find_map(|line| {
            let mut words = line.split_whitespace().skip(1);
            let uri = words.find(|w| !w.starts_with('['))?;
            uri.trim_end_matches('/')
                .ends_with("/apt")
                .then(|| words.next())
                .flatten()
                .and_then(channel_name)
        })
}

/// Last path segment of the repo's `baseurl`:
/// `baseurl=https://pkg.updawg.net/rpm/stable`.
#[must_use]
pub fn dnf_channel(repo: &str) -> Option<String> {
    repo.lines()
        .filter_map(|line| line.trim().strip_prefix("baseurl"))
        .filter_map(|rest| rest.trim_start().strip_prefix('='))
        .find_map(|url| {
            url.trim()
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .and_then(channel_name)
        })
}

// The value comes from a file root can edit and ends up on the wire, so only
// accept something that looks like a channel name.
fn channel_name(word: &str) -> Option<String> {
    (!word.is_empty()
        && word.len() <= 32
        && word
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
    .then(|| word.to_owned())
}

/// Detects the install method of the running agent.
///
/// # Errors
/// As [`method_for`], or when the executable cannot be found.
pub fn detect() -> Result<Method, String> {
    let exe =
        std::env::current_exe().map_err(|e| format!("finding the agent's executable: {e}"))?;
    // after a package upgrade `/proc/self/exe` ends in ` (deleted)`; the
    // path itself is still right.
    let exe = PathBuf::from(
        exe.to_string_lossy()
            .trim_end_matches(" (deleted)")
            .to_owned(),
    );
    let dpkg = Path::new("/usr/bin/dpkg").exists();
    let owner = if dpkg {
        std::process::Command::new("dpkg-query")
            .arg("-S")
            .arg(&exe)
            .output()
    } else {
        std::process::Command::new("rpm")
            .arg("-qf")
            .arg(&exe)
            .output()
    };
    let packaged = owner.is_ok_and(|o| o.status.success());
    method_for(&exe, packaged, dpkg)
}

/// An in-progress self-update. Written by the agent that starts it, read by
/// the helper and by whichever agent runs afterwards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    pub job: Job,
    /// The job report, minus the final result.
    pub report: JobComplete,
    pub from: String,
    pub to: String,
    pub method: Method,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

/// Written by the helper only when the update failed and the old agent is
/// the one running afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    pub rolled_back: bool,
    pub detail: String,
}

#[derive(Debug)]
pub enum Started {
    /// Already on the requested version; the job succeeded.
    AlreadyThere,
    /// The helper has it; the job is reported after the restart.
    Handed,
}

/// Parses a manifest and verifies its signature against `key`.
///
/// # Errors
/// If it doesn't parse, the signature doesn't verify, or it is for a
/// different channel.
pub fn verify_manifest(
    body: &[u8],
    key: &[u8],
    channel: ReleaseChannel,
) -> Result<ReleaseManifest, String> {
    use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA512, UnparsedPublicKey};
    use base64::Engine as _;
    let manifest: ReleaseManifest =
        serde_json::from_slice(body).map_err(|e| format!("the manifest does not parse: {e}"))?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(&manifest.signature)
        .map_err(|e| format!("the manifest's signature is not base64: {e}"))?;
    let signed = manifest
        .signing_bytes()
        .map_err(|e| format!("the manifest cannot be serialised: {e}"))?;
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, key)
        .verify(&signed, &signature)
        .map_err(|_| {
            "the manifest's signature does not verify against the release key".to_owned()
        })?;
    // a validly signed beta manifest served for stable is still wrong
    if manifest.channel != channel {
        return Err(format!(
            "asked for the {} manifest and got {}'s",
            channel.as_str(),
            manifest.channel.as_str()
        ));
    }
    Ok(manifest)
}

/// Whether `version` only has characters a package version can have, so it
/// is safe to pass to apt, dnf, or put in a URL.
#[must_use]
pub fn plausible_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '~'))
        && version.starts_with(|c: char| c.is_ascii_digit())
}

/// `sha256:<hex>` of `bytes`.
#[must_use]
pub fn sha256(bytes: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    let mut out = String::from("sha256:");
    for b in digest.as_ref() {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Versions of [`PACKAGE`] available from the host's repositories.
///
/// # Errors
/// When the package manager cannot be asked.
pub async fn offered(method: &Method) -> Result<Vec<String>, String> {
    let (tool, args): (&str, &[&str]) = match method {
        Method::Apt => ("apt-cache", &["madison", PACKAGE]),
        Method::Dnf => ("dnf", &["-q", "--showduplicates", "list", PACKAGE]),
        Method::Binary { .. } => return Ok(Vec::new()),
    };
    let out = tokio::process::Command::new(tool)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("running {tool}: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(match method {
        Method::Apt => parse_madison(&text),
        _ => parse_dnf_list(&text),
    })
}

/// Runs `apt-get update` or `dnf makecache`.
///
/// # Errors
/// When the package manager cannot be run or says it failed.
pub async fn refresh(method: &Method) -> Result<(), String> {
    let (tool, args): (&str, &[&str]) = match method {
        Method::Apt => ("apt-get", &["update", "-qq"]),
        Method::Dnf => ("dnf", &["-y", "-q", "makecache"]),
        Method::Binary { .. } => return Ok(()),
    };
    let out = tokio::process::Command::new(tool)
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output()
        .await
        .map_err(|e| format!("running {tool}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "refreshing the package lists: {tool} said {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Parses `apt-cache madison` output:
/// `updawg-agent | 0.1.0-... | https://... beta/main amd64 Packages`.
#[must_use]
pub fn parse_madison(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split('|').map(str::trim);
            (fields.next() == Some(PACKAGE)).then(|| fields.next().map(str::to_owned))?
        })
        .collect()
}

/// Parses `dnf list --showduplicates` output, skipping the headings:
/// `updawg-agent.x86_64  0.1.0-...  updawg-beta`.
#[must_use]
pub fn parse_dnf_list(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let version = fields.next()?;
            name.strip_prefix(PACKAGE)
                .is_some_and(|rest| rest.starts_with('.'))
                .then(|| version.to_owned())
        })
        .collect()
}

/// Prepares a self-update and hands it to the helper.
///
/// All the checks that can fail happen here, before anything is changed: the
/// version string, the install method, that both the target version and the
/// running one (for rollback) are available, and the binaries' signatures.
///
/// # Errors
/// If any check fails. Nothing has been changed at that point.
pub async fn start(
    job: &Job,
    spec: &updawg_protocol::SelfUpdate,
    report: JobComplete,
    state: &LocalState,
    log: &crate::joblog::JobLog,
) -> Result<Started, String> {
    let to = spec.version.as_str();
    if !plausible_version(to) {
        return Err(format!("{to:?} is not a version"));
    }
    let from = crate::VERSION;
    if to == from {
        log.agent(format!("already {to}"));
        return Ok(Started::AlreadyThere);
    }
    if from.ends_with("-dev") {
        return Err(format!(
            "this agent ({from}) is a development build, which updates the way it was built"
        ));
    }
    if !Path::new("/run/systemd/system").exists() {
        return Err(
            "the host is not running systemd, which the update needs to restart the agent".into(),
        );
    }
    let method = detect()?;
    log.agent(format!("updating {from} -> {to} ({})", describe(&method)));

    match &method {
        Method::Apt | Method::Dnf => {
            // stale package lists would miss a recently promoted build
            refresh(&method).await?;
            let offered = offered(&method).await?;
            if !offered.iter().any(|v| v == to) {
                return Err(format!(
                    "{to} is not in this host's {PACKAGE} repository, which offers {}",
                    if offered.is_empty() {
                        "nothing".to_owned()
                    } else {
                        offered.join(", ")
                    }
                ));
            }
            // needed for rollback
            if !offered.iter().any(|v| v == from) {
                return Err(format!(
                    "{from}, the version running, is no longer in this host's repository, so the update could not be undone if it failed"
                ));
            }
        }
        Method::Binary { dir } => stage(spec.channel, to, dir, log).await?,
    }

    state
        .set_self_update(&Pending {
            job: job.clone(),
            report,
            from: from.to_owned(),
            to: to.to_owned(),
            method,
            started_at: chrono::Utc::now(),
        })
        .map_err(|e| format!("recording the update: {e}"))?;

    let ctl = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|d| d.join("updawgctl")))
        .filter(|p| p.exists())
        .ok_or("cannot find updawgctl beside updawgd")?;
    let launched = tokio::process::Command::new("systemd-run")
        .arg(format!("--unit={UNIT}"))
        .arg("--collect")
        .arg("--description=Updawg agent self-update")
        .arg(ctl)
        .arg("--state-dir")
        .arg(state.root())
        .arg("self-update-run")
        .output()
        .await
        .map_err(|e| format!("starting the update: {e}"))?;
    if !launched.status.success() {
        let _ = state.take_self_update();
        return Err(format!(
            "systemd would not start the update: {}",
            String::from_utf8_lossy(&launched.stderr).trim()
        ));
    }
    log.agent("handed to the update helper; the agent restarts as the new version");
    Ok(Started::Handed)
}

pub async fn helper_running() -> bool {
    tokio::process::Command::new("systemctl")
        .args(["is-active", "--quiet", &format!("{UNIT}.service")])
        .status()
        .await
        .is_ok_and(|s| s.success())
}

fn describe(method: &Method) -> String {
    match method {
        Method::Apt => "apt".into(),
        Method::Dnf => "dnf".into(),
        Method::Binary { dir } => format!("binaries in {}", dir.display()),
    }
}

/// Staging path for `name`. It sits next to the binary it replaces so the
/// swap is a rename on the same filesystem.
#[must_use]
pub fn staged(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!(".{name}.new"))
}

/// Where the previous binary is kept for rollback.
#[must_use]
pub fn previous(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!(".{name}.prev"))
}

async fn stage(
    channel: ReleaseChannel,
    to: &str,
    dir: &Path,
    log: &crate::joblog::JobLog,
) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| format!("preparing an HTTP client: {e}"))?;
    let url = format!("{RELEASE_BASE}/bin/{}.json", channel.as_str());
    let body = fetch(&client, &url).await?;
    let manifest = verify_manifest(&body, RELEASE_KEY, channel)?;
    if manifest.version != to {
        return Err(format!(
            "the {} channel holds {}, not {to}",
            channel.as_str(),
            manifest.version
        ));
    }
    log.agent(format!(
        "the {} manifest is signed and names {to}",
        channel.as_str()
    ));
    for name in ["updawgd", "updawgctl"] {
        let artifact = manifest
            .artifact(target(), name)
            .ok_or_else(|| format!("{to} has no {name} for {}", target()))?;
        let bytes = fetch(&client, &artifact.url).await?;
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if size != artifact.size_bytes || sha256(&bytes) != artifact.sha256 {
            return Err(format!(
                "{name} downloaded from {} is not what the manifest says",
                artifact.url
            ));
        }
        let path = staged(dir, name);
        write_executable(&path, &bytes).map_err(|e| format!("staging {}: {e}", path.display()))?;
    }
    // make sure it runs on this host and reports the right version
    let ran = tokio::process::Command::new(staged(dir, "updawgctl"))
        .arg("--version")
        .output()
        .await
        .map_err(|e| format!("the new updawgctl does not run: {e}"))?;
    let said = String::from_utf8_lossy(&ran.stdout);
    if !said.contains(to) {
        return Err(format!(
            "the new updawgctl says {:?}, not {to}",
            said.trim()
        ));
    }
    log.agent("both binaries downloaded, checked and staged");
    Ok(())
}

async fn fetch(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("fetching {url}: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("fetching {url}: {}", response.status()));
    }
    Ok(response
        .bytes()
        .await
        .map_err(|e| format!("reading {url}: {e}"))?
        .to_vec())
}

fn write_executable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut file = std::fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
