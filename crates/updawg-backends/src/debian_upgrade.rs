//! A Debian release upgrade (DAWG-151): the sources rewritten, then
//! `apt full-upgrade`, as Debian's release notes lay it out.
//!
//! 1. **Refuse what the release notes say not to do** ([`blockers`], which
//!    a preflight asks too). Debian only (Ubuntu has its own tool:
//!    [`crate::ubuntu_upgrade`]); one release at a time, 12 to 13 and never
//!    12 to 14; nothing held; nothing half-installed (`dpkg --audit`).
//! 2. **Rewrite the sources.** Every suite that names this release —
//!    `bookworm`, `bookworm-updates`, `bookworm-security`,
//!    `cloud-sdk-bookworm` — is renamed to the target's, in
//!    `/etc/apt/sources.list` and every `.list` and deb822 `.sources` file
//!    under `sources.list.d`. Suites that name no release (`stable`) are left
//!    as they are. The files are copied to `/var/backups` first. Moving to 12
//!    or later, a Debian line with `non-free` gains `non-free-firmware`, where
//!    the firmware went in 12.
//! 3. **`apt-get update`.** If it fails — a repository with nothing for the
//!    target, which the preflight's `third_party_repos` check is there to
//!    catch first — the sources are put back and nothing else has changed:
//!    refused, not failed.
//! 4. **`upgrade --without-new-pkgs`, then `full-upgrade`**, non-interactive,
//!    keeping every configuration file edited on the host (`--force-confold`,
//!    `--force-confdef` for the ones nobody edited). The release notes' two
//!    steps: the minimal upgrade first, so the full one has less to solve.
//!    Output goes to the job's log line by line; it takes minutes.
//! 5. **It says it is the target now**: `/etc/os-release` from the new
//!    `base-files`. Otherwise the job failed, whatever apt said.
//!
//! From step 4 on there is no undoing it by putting files back: a failure
//! there is a half-upgraded host, which is what the snapshot taken before the
//! job is for (the executor's, as for an install).

pub use crate::release::{Host, read_os_release};
use crate::{BackendError, Change, LogSink, Result, release};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, BufReader};
use updawg_protocol::InstalledPackage;

/// Where the sources are kept before they are rewritten.
const BACKUPS: &str = "/var/backups";

/// The first release with a `non-free-firmware` component.
const FIRMWARE_FROM: u32 = 12;

/// Whether this host may be upgraded to `target`, and the target's
/// codename.
///
/// # Errors
/// [`BackendError::Refused`] saying why not.
pub fn plan(host: &Host, target: &str) -> Result<String> {
    if host.id != "debian" {
        return Err(BackendError::Refused(format!(
            "release upgrades are built for Debian so far, and this host is {}",
            host.id
        )));
    }
    let (Ok(now), Ok(to)) = (host.version.parse::<u32>(), target.trim().parse::<u32>()) else {
        return Err(BackendError::Refused(format!(
            "cannot tell how {} relates to {target}",
            host.version
        )));
    };
    if to != now + 1 {
        return Err(BackendError::Refused(format!(
            "Debian upgrades one release at a time, and this host is on {now}, so the next is {}, not {to}",
            now + 1
        )));
    }
    release::codename_for(target)
        .filter(|c| !c.chars().all(|ch| ch.is_ascii_digit()))
        .ok_or_else(|| {
            BackendError::Refused(format!("this agent does not know Debian {to}'s codename"))
        })
}

/// What rewriting changed in one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewrite {
    pub text: String,
    /// Each suite renamed, `old → new`, once each.
    pub renamed: Vec<String>,
}

/// A one-line-style sources file (`sources.list`, `*.list`), rewritten.
#[must_use]
pub fn rewrite_list(text: &str, current: &str, target: &str, firmware: bool) -> Rewrite {
    let mut renamed = Vec::new();
    let lines: Vec<String> = text
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if !(trimmed.starts_with("deb ") || trimmed.starts_with("deb-src ")) {
                return line.to_owned();
            }
            // `deb [opt=a opt=b] uri suite component...`, the options optional.
            let words: Vec<&str> = trimmed.split_whitespace().collect();
            let mut at = 1;
            if words.get(1).is_some_and(|w| w.starts_with('[')) {
                while at < words.len() && !words[at].ends_with(']') {
                    at += 1;
                }
                at += 1;
            }
            // `at` is the URI; the suite follows it.
            let suite_at = at + 1;
            let Some(suite) = words.get(suite_at) else {
                return line.to_owned();
            };
            let Some(new) = release::target_suite(suite, current, target) else {
                return line.to_owned();
            };
            note(&mut renamed, suite, &new);
            let mut out: Vec<String> = words.iter().map(|w| (*w).to_owned()).collect();
            out[suite_at] = new;
            if firmware
                && out[suite_at + 1..].iter().any(|c| c == "non-free")
                && !out[suite_at + 1..].iter().any(|c| c == "non-free-firmware")
            {
                out.push("non-free-firmware".to_owned());
            }
            out.join(" ")
        })
        .collect();
    Rewrite {
        text: rejoin(text, &lines),
        renamed,
    }
}

/// A deb822 sources file (`*.sources`), rewritten stanza by stanza.
#[must_use]
pub fn rewrite_sources(text: &str, current: &str, target: &str, firmware: bool) -> Rewrite {
    let mut renamed = Vec::new();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let mut start = 0;
    while start < lines.len() {
        let end = (start..lines.len())
            .find(|i| lines[*i].trim().is_empty())
            .unwrap_or(lines.len());
        let mut renamed_here = false;
        for line in &mut lines[start..end] {
            let Some(value) = field(line, "Suites") else {
                continue;
            };
            let suites: Vec<String> = value
                .split_whitespace()
                .map(|s| match release::target_suite(s, current, target) {
                    Some(new) => {
                        note(&mut renamed, s, &new);
                        renamed_here = true;
                        new
                    }
                    None => s.to_owned(),
                })
                .collect();
            *line = format!("Suites: {}", suites.join(" "));
        }
        if firmware && renamed_here {
            for line in &mut lines[start..end] {
                let Some(value) = field(line, "Components") else {
                    continue;
                };
                let components: Vec<&str> = value.split_whitespace().collect();
                if components.contains(&"non-free") && !components.contains(&"non-free-firmware") {
                    *line = format!("Components: {} non-free-firmware", components.join(" "));
                }
            }
        }
        start = end + 1;
    }
    Rewrite {
        text: rejoin(text, &lines),
        renamed,
    }
}

/// A deb822 field's value, when `line` is that field.
fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let (key, value) = line.split_once(':')?;
    key.trim().eq_ignore_ascii_case(name).then_some(value)
}

fn note(renamed: &mut Vec<String>, from: &str, to: &str) {
    let entry = format!("{from} → {to}");
    if !renamed.contains(&entry) {
        renamed.push(entry);
    }
}

/// `lines` joined as `original` was, trailing newline included.
fn rejoin(original: &str, lines: &[String]) -> String {
    let mut out = lines.join("\n");
    if original.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Every package that moved, arrived or left between two inventories.
#[must_use]
pub fn changes(before: &[InstalledPackage], after: &[InstalledPackage]) -> Vec<Change> {
    let index = |list: &[InstalledPackage]| -> BTreeMap<(String, String), String> {
        list.iter()
            .map(|p| ((p.name.clone(), p.arch.clone()), p.version.clone()))
            .collect()
    };
    let (was, now) = (index(before), index(after));
    let mut out = Vec::new();
    for ((name, arch), from) in &was {
        let to = now
            .get(&(name.clone(), arch.clone()))
            .cloned()
            .unwrap_or_default();
        if &to != from {
            out.push(Change {
                name: name.clone(),
                arch: arch.clone(),
                from: from.clone(),
                to,
            });
        }
    }
    for ((name, arch), to) in &now {
        if !was.contains_key(&(name.clone(), arch.clone())) {
            out.push(Change {
                name: name.clone(),
                arch: arch.clone(),
                from: String::new(),
                to: to.clone(),
            });
        }
    }
    out
}

/* ------------------------------------------------------------ doing it */

/// The sources files apt reads.
fn source_files() -> Vec<PathBuf> {
    let mut files = vec![PathBuf::from("/etc/apt/sources.list")];
    if let Ok(dir) = std::fs::read_dir("/etc/apt/sources.list.d") {
        let mut more: Vec<PathBuf> = dir
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "list" || e == "sources"))
            .collect();
        more.sort();
        files.extend(more);
    }
    files.into_iter().filter(|p| p.is_file()).collect()
}

/// A file as it was before the rewrite, to put back.
struct Kept {
    path: PathBuf,
    text: String,
}

/// Why this host would refuse to be upgraded to `target`, found without
/// changing anything: [`plan`], held packages, `dpkg --audit`. What
/// [`upgrade`] checks before it begins, and what a preflight asks ahead of
/// time. Empty when nothing stands in the way.
///
/// # Errors
/// When the package manager could not be asked.
pub async fn blockers(
    backend: &dyn crate::PackageBackend,
    host: &Host,
    target: &str,
) -> Result<Vec<String>> {
    if let Err(BackendError::Refused(why)) = plan(host, target) {
        return Ok(vec![why]);
    }
    let mut out = Vec::new();
    out.extend(held(backend).await?);
    out.extend(half_installed().await?);
    Ok(out)
}

/// Held packages, as a refusal.
pub(crate) async fn held(backend: &dyn crate::PackageBackend) -> Result<Option<String>> {
    let held = backend.held_packages().await?;
    Ok((!held.is_empty()).then(|| {
        format!(
            "held packages stay behind in a release upgrade and can break it; release them first: {}",
            held.join(", ")
        )
    }))
}

/// Anything `dpkg --audit` reports, as a refusal.
pub(crate) async fn half_installed() -> Result<Option<String>> {
    let audit = tokio::process::Command::new("dpkg")
        .arg("--audit")
        .env("LC_ALL", "C")
        .output()
        .await?;
    let audit = String::from_utf8_lossy(&audit.stdout);
    Ok((!audit.trim().is_empty()).then(|| {
        format!(
            "dpkg reports packages half-installed or half-configured; sort those out first: {}",
            audit.lines().next().unwrap_or_default()
        )
    }))
}

/// Rewrite every sources file, keeping copies in `/var/backups`. Returns the
/// originals of the files it changed.
fn rewrite_all(host: &Host, target: &str, codename: &str, log: &dyn LogSink) -> Result<Vec<Kept>> {
    let backup =
        Path::new(BACKUPS).join(format!("updawg-dist-upgrade-{}-to-{target}", host.version));
    std::fs::create_dir_all(&backup)?;
    let firmware = target.parse::<u32>().is_ok_and(|t| t >= FIRMWARE_FROM);
    let mut kept = Vec::new();
    for path in source_files() {
        let text = std::fs::read_to_string(&path)?;
        let rewrite = if path.extension().is_some_and(|e| e == "sources") {
            rewrite_sources(&text, &host.codename, codename, firmware)
        } else {
            rewrite_list(&text, &host.codename, codename, firmware)
        };
        if rewrite.text == text {
            continue;
        }
        let name = path
            .file_name()
            .map_or_else(|| "sources".into(), |n| n.to_string_lossy().into_owned());
        std::fs::write(backup.join(&name), &text)?;
        std::fs::write(&path, &rewrite.text)?;
        log.line(&format!(
            "rewrote {}: {}",
            path.display(),
            rewrite.renamed.join(", ")
        ));
        kept.push(Kept { path, text });
    }
    log.line(&format!(
        "the sources as they were are in {}",
        backup.display()
    ));
    Ok(kept)
}

fn put_back(kept: &[Kept], log: &dyn LogSink) {
    for k in kept {
        match std::fs::write(&k.path, &k.text) {
            Ok(()) => log.line(&format!("put back {}", k.path.display())),
            Err(e) => log.line(&format!("could not put back {}: {e}", k.path.display())),
        }
    }
}

/// `apt-get` with the options every step takes, streaming its output.
pub(crate) async fn apt(args: &[&str], log: &dyn LogSink) -> Result<i32> {
    let mut all: Vec<&str> = vec![
        "-y",
        "-q",
        "-o",
        "Dpkg::Options::=--force-confdef",
        "-o",
        "Dpkg::Options::=--force-confold",
        "-o",
        "DPkg::Lock::Timeout=600",
    ];
    all.extend_from_slice(args);
    streamed("apt-get", &all, log).await
}

/// Run `tool`, sending each line it prints to `log` as it prints it.
///
/// The environment is every release upgrade's: nothing asks a question, and
/// Ubuntu's upgrader neither buffers its output nor moves into `screen`,
/// where the job could no longer hear it.
pub(crate) async fn streamed(tool: &'static str, args: &[&str], log: &dyn LogSink) -> Result<i32> {
    log.line(&format!("$ {tool} {}", args.join(" ")));
    let mut child = tokio::process::Command::new(tool)
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("APT_LISTCHANGES_FRONTEND", "none")
        .env("UCF_FORCE_CONFFOLD", "1")
        .env("NEEDRESTART_MODE", "l")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("PYTHONUNBUFFERED", "1")
        .env("RELEASE_UPGRADER_NO_SCREEN", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BackendError::ToolMissing { tool }
            } else {
                BackendError::Io(e)
            }
        })?;
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(BackendError::Io(std::io::Error::other("no output pipes")));
    };
    tokio::join!(pump(stdout, log), pump(stderr, log));
    let status = child.wait().await?;
    Ok(status.code().unwrap_or(-1))
}

/// Each line `r` gives, to `log`, as it comes.
async fn pump<R: tokio::io::AsyncRead + Unpin>(r: R, log: &dyn LogSink) {
    let mut lines = BufReader::new(r).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        for part in crate::apt::as_shown(&line) {
            log.line(part);
        }
    }
}

fn failed(step: &'static str, status: i32) -> BackendError {
    BackendError::CommandFailed {
        tool: "apt-get",
        status,
        stderr: format!("{step} failed; the job log has apt's output"),
    }
}

/// Upgrade this host to Debian `target`. See the module note.
///
/// # Errors
/// [`BackendError::Refused`] when nothing was changed (not Debian, not one
/// release on, held or half-installed packages, `apt-get update` failing
/// with the sources put back); any other error once the upgrade has begun.
pub async fn upgrade(
    backend: &dyn crate::PackageBackend,
    target: &str,
    log: &dyn LogSink,
) -> Result<crate::ApplyOutcome> {
    let host = release::this_host()?;
    let codename = plan(&host, target)?;
    let refused = blockers(backend, &host, target).await?;
    if !refused.is_empty() {
        return Err(BackendError::Refused(refused.join("; ")));
    }
    log.line(&format!(
        "upgrading Debian {} ({}) to {target} ({codename})",
        host.version, host.codename
    ));

    let before = backend.installed().await?;
    let kept = rewrite_all(&host, target, &codename, log)?;
    if kept.is_empty() {
        return Err(BackendError::Refused(format!(
            "no apt source names {}, so there was nothing to move to {codename}",
            host.codename
        )));
    }

    let updated = apt(&["update"], log).await?;
    if updated != 0 {
        put_back(&kept, log);
        let _ = apt(&["update"], log).await;
        return Err(BackendError::Refused(format!(
            "apt-get update failed against {codename}'s sources, so they were put back and nothing else was changed (a repository with nothing for {codename}?)"
        )));
    }

    log.line("the minimal upgrade first: nothing new installed, nothing removed");
    let minimal = apt(&["upgrade", "--without-new-pkgs"], log).await?;
    if minimal != 0 {
        return Err(failed("apt-get upgrade --without-new-pkgs", minimal));
    }
    log.line("then the full upgrade");
    let full = apt(&["full-upgrade"], log).await?;
    if full != 0 {
        return Err(failed("apt-get full-upgrade", full));
    }

    let now = read_os_release(&std::fs::read_to_string("/etc/os-release")?);
    if now.as_ref().map(|h| h.version.as_str()) != Some(target) {
        return Err(BackendError::CommandFailed {
            tool: "apt-get",
            status: 0,
            stderr: format!(
                "apt finished, and /etc/os-release still says {}",
                now.map_or_else(|| "nothing it can read".into(), |h| h.version)
            ),
        });
    }
    let after = backend.installed().await?;
    let changed = changes(&before, &after);
    log.line(&format!(
        "now Debian {target} ({codename}): {} package(s) changed; the new kernel is in use after a reboot",
        changed.len()
    ));
    Ok(crate::ApplyOutcome {
        changed,
        reboot_required: true,
        after_reboot: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GCE_12_LIST: &str = "deb https://packages.cloud.google.com/apt google-compute-engine-bookworm-stable main\ndeb https://packages.cloud.google.com/apt cloud-sdk-bookworm main\n";

    const GCE_12_SOURCES: &str = "Types: deb deb-src\nURIs: mirror+file:///etc/apt/mirrors/debian.list\nSuites: bookworm bookworm-updates bookworm-backports\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb deb-src\nURIs: mirror+file:///etc/apt/mirrors/debian-security.list\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n";

    #[test]
    fn a_one_line_file_has_every_suite_naming_the_release_renamed() {
        let r = rewrite_list(GCE_12_LIST, "bookworm", "trixie", true);
        assert_eq!(
            r.text,
            "deb https://packages.cloud.google.com/apt google-compute-engine-trixie-stable main\ndeb https://packages.cloud.google.com/apt cloud-sdk-trixie main\n"
        );
        assert_eq!(r.renamed.len(), 2);
    }

    #[test]
    fn options_comments_and_suites_naming_no_release_are_left_alone() {
        let text = "# deb http://deb.debian.org/debian bullseye main\ndeb [arch=amd64 signed-by=/usr/share/keyrings/x.gpg] https://example.test/apt bullseye-security main contrib non-free\ndeb https://repo.example.test/ stable main\n";
        let r = rewrite_list(text, "bullseye", "bookworm", true);
        let lines: Vec<&str> = r.text.lines().collect();
        assert_eq!(lines[0], "# deb http://deb.debian.org/debian bullseye main");
        assert_eq!(
            lines[1],
            "deb [arch=amd64 signed-by=/usr/share/keyrings/x.gpg] https://example.test/apt bookworm-security main contrib non-free non-free-firmware"
        );
        assert_eq!(lines[2], "deb https://repo.example.test/ stable main");
        assert_eq!(r.renamed, ["bullseye-security → bookworm-security"]);
    }

    #[test]
    fn a_deb822_file_has_its_suites_renamed_stanza_by_stanza() {
        let r = rewrite_sources(GCE_12_SOURCES, "bookworm", "trixie", true);
        assert!(
            r.text
                .contains("Suites: trixie trixie-updates trixie-backports\n")
        );
        assert!(r.text.contains("Suites: trixie-security\n"));
        assert!(
            r.text.contains("Components: main\n"),
            "no non-free, no firmware"
        );
        assert!(r.text.ends_with('\n'));
        assert_eq!(r.renamed.len(), 4);

        let with_non_free = GCE_12_SOURCES.replace("Components: main", "Components: main non-free");
        let r = rewrite_sources(&with_non_free, "bookworm", "trixie", true);
        assert!(
            r.text
                .contains("Components: main non-free non-free-firmware")
        );
        let r = rewrite_sources(&with_non_free, "bookworm", "trixie", false);
        assert!(!r.text.contains("non-free-firmware"));
    }

    #[test]
    fn only_debian_and_only_the_next_release() {
        let host = |id: &str, v: &str| Host {
            id: id.into(),
            version: v.into(),
            codename: "bookworm".into(),
        };
        assert_eq!(plan(&host("debian", "12"), "13").unwrap(), "trixie");
        assert_eq!(plan(&host("debian", "11"), "12").unwrap(), "bookworm");
        for (h, target, says) in [
            (host("debian", "12"), "14", "one release at a time"),
            (host("debian", "12"), "12", "one release at a time"),
            (host("ubuntu", "22.04"), "24.04", "built for Debian"),
            (host("debian", "12"), "trixie", "cannot tell"),
        ] {
            match plan(&h, target) {
                Err(BackendError::Refused(why)) => assert!(why.contains(says), "{why}"),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn os_release_is_read_for_its_id_version_and_codename() {
        let text = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\nID=debian\n";
        assert_eq!(
            read_os_release(text),
            Some(Host {
                id: "debian".into(),
                version: "12".into(),
                codename: "bookworm".into()
            })
        );
    }

    #[test]
    fn changes_are_every_package_that_moved_arrived_or_left() {
        let p = |n: &str, v: &str| InstalledPackage {
            name: n.into(),
            version: v.into(),
            arch: "amd64".into(),
            repo: None,
            source: None,
        };
        let changed = changes(
            &[p("bash", "5.2"), p("libold", "1"), p("tzdata", "a")],
            &[p("bash", "5.3"), p("libnew", "2"), p("tzdata", "a")],
        );
        let seen: Vec<(&str, &str, &str)> = changed
            .iter()
            .map(|c| (c.name.as_str(), c.from.as_str(), c.to.as_str()))
            .collect();
        assert_eq!(
            seen,
            [
                ("bash", "5.2", "5.3"),
                ("libold", "1", ""),
                ("libnew", "", "2")
            ]
        );
    }
}
