//! Release names: codenames, renaming suites between releases, and the
//! host's current release ([`Host`]). Shared by the release-upgrade preflight
//! in `updawg-agent-core` and [`crate::debian_upgrade`], so the preflight
//! checks the same suite the upgrade writes.

/// The codename of a release named by version (`13`, `24.04`) or already by
/// codename (`forky`). `None` for a version this build does not know.
#[must_use]
pub fn codename_for(target: &str) -> Option<String> {
    let target = target.trim().to_ascii_lowercase();
    if !target.is_empty() && target.chars().all(|c| c.is_ascii_lowercase()) {
        return Some(target);
    }
    let known = [
        // Debian.
        ("10", "buster"),
        ("11", "bullseye"),
        ("12", "bookworm"),
        ("13", "trixie"),
        ("14", "forky"),
        ("15", "duke"),
        // Ubuntu.
        ("20.04", "focal"),
        ("22.04", "jammy"),
        ("24.04", "noble"),
        ("24.10", "oracular"),
        ("25.04", "plucky"),
        ("25.10", "questing"),
        ("26.04", "resolute"),
    ];
    known
        .iter()
        .find(|(version, _)| *version == target)
        .map(|(_, codename)| (*codename).to_owned())
}

/// `suite` with the `current` release renamed to `target`, matching whole
/// `-`-separated words. `None` if the suite isn't tied to `current`.
#[must_use]
pub fn target_suite(suite: &str, current: &str, target: &str) -> Option<String> {
    let mut renamed = false;
    let words: Vec<&str> = suite
        .split('-')
        .map(|w| {
            if w == current {
                renamed = true;
                target
            } else {
                w
            }
        })
        .collect();
    renamed.then(|| words.join("-"))
}

/// This host's release, from `/etc/os-release`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub id: String,
    pub version: String,
    pub codename: String,
}

/// Requires `ID` and `VERSION_ID`. `VERSION_CODENAME` is empty if absent.
#[must_use]
pub fn read_os_release(text: &str) -> Option<Host> {
    let value = |key: &str| {
        text.lines().find_map(|l| {
            l.strip_prefix(key)
                .and_then(|v| v.strip_prefix('='))
                .map(|v| v.trim().trim_matches('"').to_owned())
                .filter(|v| !v.is_empty())
        })
    };
    Some(Host {
        id: value("ID")?,
        version: value("VERSION_ID")?,
        // The RHEL family names no codename.
        codename: value("VERSION_CODENAME").unwrap_or_default(),
    })
}

/// # Errors
/// Reading the file, or [`crate::BackendError::Refused`] when it does not
/// say which release this is.
pub fn this_host() -> crate::Result<Host> {
    let text = std::fs::read_to_string("/etc/os-release")?;
    read_os_release(&text).ok_or_else(|| {
        crate::BackendError::Refused("/etc/os-release does not say which release this is".into())
    })
}
