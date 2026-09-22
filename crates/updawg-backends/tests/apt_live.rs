//! The apt parsers against live containers, not checked-in fixtures (DAWG-34).
//!
//! `tests/apt.rs` runs against captured output and is fast, hermetic and always
//! green. That is exactly its weakness: it proves the parsers still handle what
//! apt printed on the day the fixtures were taken, and says nothing about what
//! apt prints today. This file is the canary for that drift.
//!
//! Ignored by default because it needs Docker and pulls five images. Run it when
//! touching a parser, when a new distribution is added, or when apt has moved:
//!
//! ```text
//! cargo test -p updawg-backends --test apt_live -- --ignored --nocapture
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

use updawg_backends::apt::{
    parse_holds, parse_installed, parse_removals, parse_repositories, parse_updates,
};

const IMAGES: &[(&str, &str)] = &[
    ("ubuntu:20.04", "Ubuntu"),
    ("ubuntu:22.04", "Ubuntu"),
    ("ubuntu:24.04", "Ubuntu"),
    ("debian:11", "Debian"),
    ("debian:12", "Debian"),
];

/// Exactly what `tests/fixtures/apt/*.txt` was captured with. Kept here so the
/// fixtures can be regenerated from the one source of truth.
const CAPTURE: &str = r#"
set -uo pipefail
apt-get update -qq >/dev/null 2>&1
echo "===DPKG_QUERY==="
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n' 2>/dev/null
echo "===DIST_UPGRADE==="
apt-get -s dist-upgrade 2>&1
echo "===POLICY==="
apt-cache policy 2>&1
victim=$(apt-get -s dist-upgrade 2>/dev/null | awk '/^Inst /{print $2; exit}')
[ -n "${victim:-}" ] && apt-mark hold "$victim" >/dev/null 2>&1
apt-mark hold perl-base >/dev/null 2>&1
echo "===HOLDS==="
apt-mark showhold 2>/dev/null
echo "===INSTALL_SIM==="
apt-get -s install --no-install-recommends curl 2>&1
"#;

/// Builds the state `tests/fixtures/apt/debian12-removals.txt` was captured
/// from, because no official image has an upgrade that removes something.
///
/// Three packages built with `dpkg-deb`, one of which `Replaces` and
/// `Conflicts` the other two and is then offered as an upgrade. The packages
/// are made up; what `apt` prints about them is not, and what it prints is a
/// `Remv` line that does not name the package that caused it.
const REMOVALS_CAPTURE: &str = r#"
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq dpkg-dev >/dev/null 2>&1
mk() {
  d=/tmp/build/$1-$2
  rm -rf "$d"; mkdir -p "$d/DEBIAN"
  { echo "Package: $1"; echo "Version: $2"; echo "Architecture: all"
    echo "Maintainer: t <t@example.com>"; echo "Description: t"
    shift 2; for l in "$@"; do echo "$l"; done
  } > "$d/DEBIAN/control"
  dpkg-deb -b "$d" /tmp/repo/$(basename $d).deb >/dev/null
}
mkdir -p /tmp/repo /tmp/build
mk barpkg 1.0
mk quxpkg 1.0
mk foopkg 1.0
mk foopkg 2.0 "Replaces: barpkg, quxpkg" "Conflicts: barpkg, quxpkg" "Provides: barpkg, quxpkg"
dpkg -i /tmp/repo/barpkg-1.0.deb /tmp/repo/quxpkg-1.0.deb /tmp/repo/foopkg-1.0.deb >/dev/null 2>&1
cd /tmp/repo
rm -f barpkg-1.0.deb quxpkg-1.0.deb foopkg-1.0.deb
dpkg-scanpackages . /dev/null > Packages 2>/dev/null
echo "deb [trusted=yes] file:/tmp/repo ./" > /etc/apt/sources.list.d/local.list
apt-get update -qq >/dev/null 2>&1
echo "===DPKG_QUERY==="
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n' 2>/dev/null
echo "===DIST_UPGRADE==="
apt-get -s dist-upgrade 2>&1
"#;

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn capture(image: &str) -> String {
    capture_with(image, CAPTURE)
}

fn capture_with(image: &str, script: &str) -> String {
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
            .write_all(script.as_bytes())
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

#[test]
#[ignore = "needs Docker and pulls five distribution images"]
fn the_parsers_still_understand_what_apt_prints_today() {
    if !docker_available() {
        assert!(
            std::env::var("UPDAWG_REQUIRE_DOCKER").is_err(),
            "UPDAWG_REQUIRE_DOCKER is set but Docker is not usable"
        );
        eprintln!("skipping: no Docker");
        return;
    }

    for (image, origin) in IMAGES {
        let out = capture(image);
        assert!(
            out.contains("===DPKG_QUERY==="),
            "{image}: captured nothing — is the image pullable?"
        );

        let installed = parse_installed(&section(&out, "DPKG_QUERY"));
        assert!(
            installed.len() > 50,
            "{image}: only {} packages — dpkg-query's format has moved",
            installed.len()
        );
        assert!(
            installed
                .iter()
                .all(|p| !p.name.contains(':') && !p.version.is_empty()),
            "{image}: a package parsed with an architecture in its name or no version"
        );

        let repos = parse_repositories(&section(&out, "POLICY"), Some(origin));
        assert!(
            !repos.is_empty(),
            "{image}: no repositories — apt-cache policy's format has moved"
        );
        assert!(
            repos.iter().all(|r| !r.third_party),
            "{image}: a stock image reported a third-party repository, so origin matching has moved"
        );

        let holds = parse_holds(&section(&out, "HOLDS"));
        assert!(
            holds.iter().any(|h| h == "perl-base"),
            "{image}: apt-mark showhold's output has moved, got {holds:?}"
        );

        // A newly-installed dependency must never read as an available update.
        // This is the assertion most likely to catch a real regression, because
        // it depends on apt's exact bracket placement.
        let sim = section(&out, "INSTALL_SIM");
        assert!(
            sim.contains("Inst "),
            "{image}: the install simulation printed no Inst lines"
        );
        assert!(
            parse_updates(&sim).is_empty(),
            "{image}: a package being newly installed was reported as an available update"
        );

        let updates = parse_updates(&section(&out, "DIST_UPGRADE"));
        assert!(
            parse_removals(&section(&out, "DIST_UPGRADE"), &installed).is_empty(),
            "{image}: a stock image's upgrade would remove a package"
        );
        for u in &updates {
            assert_ne!(
                u.installed, u.candidate,
                "{image}: {} is reported as an update to itself",
                u.name
            );
            assert!(
                !u.arch.is_empty(),
                "{image}: {} parsed with no architecture",
                u.name
            );
        }

        eprintln!(
            "{image}: {} installed, {} updates ({} from security), {} repositories, {} held",
            installed.len(),
            updates.len(),
            updates
                .iter()
                .filter(|u| u
                    .repo
                    .as_deref()
                    .is_some_and(updawg_backends::apt::is_security_archive))
                .count(),
            repos.len(),
            holds.len(),
        );
    }
}

#[test]
#[ignore = "needs Docker, and builds three .debs inside the container"]
fn an_upgrade_that_removes_a_package_still_says_so_the_same_way() {
    if !docker_available() {
        assert!(
            std::env::var("UPDAWG_REQUIRE_DOCKER").is_err(),
            "UPDAWG_REQUIRE_DOCKER is set but Docker is not usable"
        );
        eprintln!("skipping: no Docker");
        return;
    }

    let out = capture_with("debian:12", REMOVALS_CAPTURE);
    assert!(
        out.contains("===DPKG_QUERY==="),
        "captured nothing — is dpkg-dev still installable?"
    );

    let installed = parse_installed(&section(&out, "DPKG_QUERY"));
    let sim = section(&out, "DIST_UPGRADE");
    let removals = parse_removals(&sim, &installed);
    assert_eq!(
        removals
            .iter()
            .map(|r| (r.name.as_str(), r.installed.as_str()))
            .collect::<Vec<_>>(),
        vec![("barpkg", "1.0"), ("quxpkg", "1.0")],
        "apt's Remv line has moved"
    );

    // The fact the wire shape rests on: apt still names nothing that replaced
    // them. If this ever fails, `PendingRemoval::replaced_by` can be filled in
    // on this family too.
    assert!(
        removals.iter().all(|r| r.replaced_by.is_none()),
        "apt now names the replacement; parse_removals can report it"
    );

    // And a removal is never also reported as an update.
    let updates = parse_updates(&sim);
    assert!(updates.iter().any(|u| u.name == "foopkg"));
    assert!(!updates.iter().any(|u| u.name == "barpkg"));

    eprintln!("debian12 synthetic: {} removals", removals.len());
}
