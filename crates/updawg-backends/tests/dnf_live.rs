//! The dnf parsers against live containers, not checked-in fixtures (DAWG-35).
//!
//! `tests/dnf.rs` runs against captured output and is fast, hermetic and always
//! green. That is exactly its weakness: it proves the parsers still handle what
//! dnf printed on the day the fixtures were taken, and says nothing about what
//! dnf prints today. This file is the canary for that drift.
//!
//! Ignored by default because it needs Docker and pulls three images. Run it when
//! touching a parser, when a new distribution is added, or when dnf has moved:
//!
//! ```text
//! cargo test -p updawg-backends --test dnf_live -- --ignored --nocapture
//! ```
//!
//! Set `UPDAWG_REQUIRE_DOCKER=1` to turn "no Docker, so this quietly did nothing"
//! into a failure — the same guard the server uses for its database tests, and
//! for the same reason: a test suite that silently shrinks stays green.

// clippy.toml allows unwrap and expect in `#[cfg(test)]` modules, but that does
// not reach an integration test in `tests/` — the whole file is the test. In here
// a panic *is* the assertion.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    unreachable_pub
)]

use std::collections::BTreeSet;
use updawg_backends::dnf::{
    distro_name, parse_holds, parse_installed, parse_repositories, parse_upgrades,
    security_packages,
};

/// The image, and whether a stock one should have any updates.
///
/// Amazon Linux 2023 pins `$releasever` to the snapshot its image was built from
/// and genuinely has none, which is the thing worth asserting about it: a fleet
/// of those hosts reports itself fully patched and is telling the truth about a
/// state somebody still has to decide about.
const IMAGES: &[(&str, bool)] = &[
    ("rockylinux/rockylinux:8", true),
    ("rockylinux/rockylinux:9", true),
    ("amazonlinux:2023", false),
];

/// Exactly what `tests/fixtures/dnf/*.txt` was captured with. Kept here so the
/// fixtures can be regenerated from the one source of truth.
///
/// `RELEASEVER` is set only for the `amazonlinux2023-latest` fixture, where it
/// reproduces `dnf upgrade --releasever=latest` — how an Amazon Linux host moves
/// off the snapshot it is pinned to.
const CAPTURE: &str = r#"
set -u
DNFARGS=""
if [ -n "${RELEASEVER:-}" ]; then DNFARGS="--releasever=$RELEASEVER"; fi
dnf -q $DNFARGS makecache >/dev/null 2>&1
echo "===OS_RELEASE==="
cat /etc/os-release
echo "===RPM_QA==="
rpm -qa --qf '%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{ARCH}\n'
echo "===UPGRADES==="
dnf -q $DNFARGS repoquery --upgrades --latest-limit=1 --qf '%{name}\t%{evr}\t%{arch}\t%{reponame}' 2>/dev/null
echo "===CHECK_UPDATE==="
dnf -q $DNFARGS check-update 2>/dev/null
echo "===UPDATEINFO==="
dnf -q $DNFARGS updateinfo list --available 2>/dev/null
echo "===REPOLIST==="
dnf -q $DNFARGS repolist --all -v 2>/dev/null
dnf install -y -q $DNFARGS 'dnf-command(versionlock)' >/dev/null 2>&1
dnf versionlock add zlib >/dev/null 2>&1
dnf versionlock add tar >/dev/null 2>&1
echo "===HOLDS==="
dnf -q versionlock list 2>&1
"#;

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn capture(image: &str) -> String {
    let mut child = std::process::Command::new("docker")
        .args(["run", "--rm", "-i", image, "bash", "-s"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn docker");
    {
        use std::io::Write as _;
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(CAPTURE.as_bytes())
            .expect("write the capture script");
    }
    let out = child.wait_with_output().expect("run docker");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn section(fixture: &str, name: &str) -> String {
    let start = format!("==={name}===");
    let mut out = String::new();
    let mut inside = false;
    for line in fixture.lines() {
        if line.starts_with("===") && line.ends_with("===") {
            inside = line.trim() == start;
            continue;
        }
        if inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// `name.arch` for every row of a `check-update` table. See `tests/dnf.rs` for
/// why this lives in the tests and not in the backend.
fn check_update_names(table: &str) -> BTreeSet<String> {
    table
        .lines()
        .filter(|l| !l.starts_with(char::is_whitespace))
        .filter_map(|l| l.split_whitespace().next())
        .filter(|f| f.contains('.'))
        .map(ToOwned::to_owned)
        .collect()
}

#[test]
#[ignore = "needs Docker and pulls three distribution images"]
fn the_parsers_still_understand_what_dnf_prints_today() {
    if !docker_available() {
        assert!(
            std::env::var("UPDAWG_REQUIRE_DOCKER").is_err(),
            "UPDAWG_REQUIRE_DOCKER is set but Docker is not usable"
        );
        eprintln!("skipping: no Docker");
        return;
    }

    for (image, has_updates) in IMAGES {
        let out = capture(image);
        assert!(
            out.contains("===RPM_QA==="),
            "{image}: captured nothing — is the image pullable?"
        );

        let distro = distro_name(&section(&out, "OS_RELEASE"))
            .unwrap_or_else(|| panic!("{image}: /etc/os-release carries no NAME"));

        let installed = parse_installed(&section(&out, "RPM_QA"));
        assert!(
            installed.len() > 50,
            "{image}: only {} packages — rpm's format string has moved",
            installed.len()
        );
        assert!(
            !installed.iter().any(|p| p.name == "gpg-pubkey"),
            "{image}: an imported signing key was reported as a package"
        );
        assert!(
            installed
                .iter()
                .all(|p| !p.version.is_empty() && !p.arch.is_empty()),
            "{image}: a package parsed with no version or no architecture"
        );

        let updates = parse_upgrades(&section(&out, "UPGRADES"), &installed);
        assert_eq!(
            !updates.is_empty(),
            *has_updates,
            "{image}: {} updates, expected {}",
            updates.len(),
            if *has_updates { "some" } else { "none" }
        );
        for u in &updates {
            assert_ne!(
                u.installed, u.candidate,
                "{image}: {} is reported as an update to itself",
                u.name
            );
            assert!(
                !u.installed.is_empty(),
                "{image}: {} has a candidate but no installed version",
                u.name
            );
        }

        // The assertion most likely to catch a real regression: `--latest-limit=1`
        // still means one candidate per package, and `repoquery` still answers the
        // same question as the table a person would read.
        let queried: BTreeSet<String> = updates
            .iter()
            .map(|u| format!("{}.{}", u.name, u.arch))
            .collect();
        assert_eq!(
            queried,
            check_update_names(&section(&out, "CHECK_UPDATE")),
            "{image}: repoquery and check-update disagree about what is upgradable"
        );

        let repos = parse_repositories(&section(&out, "REPOLIST"), Some(&distro));
        assert!(
            !repos.is_empty(),
            "{image}: no repositories — dnf repolist -v's format has moved"
        );
        assert!(
            repos.iter().all(|r| !r.third_party),
            "{image}: a stock image reported a third-party repository, so name matching has moved"
        );

        let holds = parse_holds(&section(&out, "HOLDS"));
        assert_eq!(
            holds,
            vec!["zlib".to_string(), "tar".to_string()],
            "{image}: dnf versionlock list's output has moved"
        );

        let security = security_packages(&section(&out, "UPDATEINFO"));
        let named: BTreeSet<&str> = updates.iter().map(|u| u.name.as_str()).collect();
        let counted = security
            .iter()
            .filter(|p| named.contains(p.as_str()))
            .count();
        assert!(
            counted > 0 || !*has_updates,
            "{image}: {} updates and not one security advisory — updateinfo's format has moved",
            updates.len()
        );

        eprintln!(
            "{image}: {} installed, {} updates ({counted} security), {} repositories, {} held",
            installed.len(),
            updates.len(),
            repos.len(),
            holds.len(),
        );
    }
}
