//! The agent updating itself: a `self_update` job (DAWG-46).
//!
//! # Two ways in, decided by Pez 2026-10-02
//!
//! - **A package install** (the .deb or .rpm from pkg.updawg.net): apt or dnf
//!   installs the version the job names, from the host's own configured
//!   repository, whose signature they check against the same release key.
//! - **install.sh's binaries** in `/usr/local/bin`: the agent fetches the
//!   channel's manifest, checks its signature against the release key compiled
//!   in here ([`RELEASE_KEY`]), and swaps the binaries for the ones it names,
//!   by sha256.
//!
//! # Why a helper, in its own unit
//!
//! The agent cannot replace itself from inside itself. Anything it runs is in
//! its own control group, so restarting `updawgd` kills it — the package
//! manager mid-install, or the swap mid-rename. So the agent only *prepares*
//! ([`start`]), writes down what it is doing ([`Pending`]), and hands the rest
//! to `updawgctl self-update-run` in a transient systemd unit of its own
//! ([`helper`]), which:
//!
//! 1. installs (or swaps), and restarts `updawgd`;
//! 2. waits for a successful check-in **by the new version**
//!    (`last-checkin.json`, which the agent writes after every check-in);
//! 3. and, if none comes in time, puts the previous version back, restarts,
//!    and writes down why ([`Outcome`]).
//!
//! The job is reported by whichever agent is running at the end
//! ([`crate::jobs::Executor::resume_after_self_update`]): the new one once it
//! has checked in, or the old one, put back, with the reason. The same shape
//! as a job that reboots the host.

pub mod helper;

use crate::state::LocalState;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;
use updawg_protocol::{Job, JobComplete, ReleaseChannel, ReleaseManifest};

/// The release key's public half (PKCS#1 `RSAPublicKey`, DER): the Cloud KMS
/// key `release-signing/packages` version 1 in **`updawg-prod`**, which also
/// signs pkg.updawg.net. SHA-256 of this file:
/// `05ac56cc6b856b5df464feacc66dc239dfc598f942af5577702a729c0081028c`; its
/// modulus begins `cd5007d5`, as `updawg.asc`'s does.
///
/// Production's key since 2026-10-07 (DAWG-184). Agents built before then
/// trust `updawg-dev`'s key (modulus `8b4906e6`) and cannot follow on their
/// own: they are reinstalled from get.updawg.net.
///
/// ⚠️ Compiled in, never configurable and never fetched: anything that could
/// change it could ship an agent.
pub const RELEASE_KEY: &[u8] = include_bytes!("release-key.der");

/// Where the manifests are: `<base>/bin/<channel>.json`.
pub const RELEASE_BASE: &str = "https://pkg.updawg.net";

/// The transient unit the helper runs in. One name, so two updates cannot run
/// at once: systemd refuses a second unit by the same name.
pub const UNIT: &str = "updawg-self-update";

/// How long the helper waits for the new agent to check in before putting the
/// old one back. The agent checks in as soon as it starts; this is for a slow
/// gateway, not for a slow agent.
pub const CONFIRM_WITHIN: Duration = Duration::from_secs(300);

/// The package, in both families.
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

/// How this agent was installed, which decides how it updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Method {
    /// The .deb, through apt.
    Apt,
    /// The .rpm, through dnf.
    Dnf,
    /// install.sh's binaries, in this directory.
    Binary { dir: PathBuf },
}

/// The method for an agent running from `exe`, given whether the package
/// database owns that file and which family the host has.
///
/// # Errors
/// An agent installed some third way, which this does not touch.
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

/// How this agent was installed, for the check-in (protocol 0.9): the method
/// and, for a package install, the channel its repository follows.
///
/// Run once at start, like snapshot detection. An agent installed some way it
/// cannot update itself still checks in, as `other`.
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

/// The suite of the `…/apt` line in install.sh's source file:
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

/// The last path segment of the repository's `baseurl`:
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

/// A channel name as a repository could spell one, or nothing: what goes on
/// the wire is read from a file anyone with root can edit.
fn channel_name(word: &str) -> Option<String> {
    (!word.is_empty()
        && word.len() <= 32
        && word
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
    .then(|| word.to_owned())
}

/// Look at the running agent and decide.
///
/// # Errors
/// As [`method_for`], or when the executable cannot be found.
pub fn detect() -> Result<Method, String> {
    let exe =
        std::env::current_exe().map_err(|e| format!("finding the agent's executable: {e}"))?;
    // `/proc/self/exe` after an upgrade reads `… (deleted)`; the path is what
    // matters here and it is still the path.
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

/// A self-update under way: written by the agent that starts it, read by the
/// helper and by whichever agent runs afterwards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    pub job: Job,
    /// Everything but the ending.
    pub report: JobComplete,
    pub from: String,
    pub to: String,
    pub method: Method,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

/// What the helper found, when it was not a success: written only when the
/// old agent is what runs afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    /// Whether the previous version is back.
    pub rolled_back: bool,
    pub detail: String,
}

/// What [`start`] did.
#[derive(Debug)]
pub enum Started {
    /// Already on that version: nothing to do, and the job succeeded.
    AlreadyThere,
    /// Handed to the helper. The job is reported after the restart.
    Handed,
}

/// Check a manifest's signature with `key` and read it.
///
/// # Errors
/// Anything short of a manifest the key signed, for the channel asked for.
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
    // Checked after the signature, and still checked: a genuine beta
    // manifest served where stable was asked for is a downgrade of trust.
    if manifest.channel != channel {
        return Err(format!(
            "asked for the {} manifest and got {}'s",
            channel.as_str(),
            manifest.channel.as_str()
        ));
    }
    Ok(manifest)
}

/// Whether `version` is safe to pass to apt, dnf and a URL: a package
/// version's characters and nothing else.
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

/// The versions of [`PACKAGE`] the host's repositories offer.
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

/// `apt-get update` / `dnf makecache`: the package lists as the
/// repositories have them now.
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

/// `apt-cache madison`: `updawg-agent | 0.1.0-… | https://… beta/main amd64 Packages`.
#[must_use]
pub fn parse_madison(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split('|').map(str::trim);
            (fields.next() == Some(PACKAGE)).then(|| fields.next().map(str::to_owned))?
        })
        .collect()
}

/// `dnf list --showduplicates`: `updawg-agent.x86_64  0.1.0-…  updawg-beta`,
/// under headings that are not packages.
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

/// Prepare a self-update to `to` and hand it to the helper.
///
/// Everything that can refuse does so here, before anything changes: the
/// version, the way the agent was installed, whether the version (and the one
/// running, to come back to) can be had, and the binaries' signatures.
///
/// # Errors
/// Why it will not, with nothing changed.
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
    log.agent(format!("updating {from} → {to} ({})", describe(&method)));

    match &method {
        Method::Apt | Method::Dnf => {
            // The lists first: a build promoted an hour ago is not in lists
            // read yesterday, and the update would be refused for no reason
            // but the host's cache. Found on the first real hosts.
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
            // The way back. Without it a failed update could not be undone.
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

/// Whether the helper's unit is still running.
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

/// The staged binary for `name`, beside the one it replaces, so that putting
/// it in place is a rename on one filesystem.
#[must_use]
pub fn staged(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!(".{name}.new"))
}

/// The previous binary, kept for putting back.
#[must_use]
pub fn previous(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!(".{name}.prev"))
}

/// Fetch and check the channel's manifest, then download, check and stage
/// both binaries of `to` for this target.
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
    // It has to run here, and say it is what it is meant to be.
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
