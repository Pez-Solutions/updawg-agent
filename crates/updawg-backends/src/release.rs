//! Releases by name: a version's codename, and a suite renamed from one
//! release to the next. Shared by the release-upgrade preflight
//! (`updawg-agent-core`'s readiness, DAWG-149) and the Debian upgrade itself
//! ([`crate::debian_upgrade`], DAWG-151), so the suite a preflight asks a
//! repository about is the suite the upgrade writes.

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

/// `suite` renamed from the `current` release to `target`, where it names
/// the current release as one of its `-`-separated words. `None` when it
/// names none, and so is not tied to a release.
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
