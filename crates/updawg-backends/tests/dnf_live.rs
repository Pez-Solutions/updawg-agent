//! The dnf parsers against live containers.
//!
//! `tests/dnf.rs` uses captured fixtures, so it can't notice dnf's output
//! changing after they were taken. This can.
//!
//! Ignored by default because it needs Docker and pulls three images. Run it
//! after touching a parser, adding a distribution, or a dnf release:
//!
//! ```text
//! cargo test -p updawg-backends --test dnf_live -- --ignored --nocapture
//! ```
//!
//! Set `UPDAWG_REQUIRE_DOCKER=1` to fail rather than skip when Docker is
//! missing.

// clippy.toml's test allowances don't apply to integration tests.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    unreachable_pub
)]

use std::collections::BTreeSet;
use updawg_backends::dnf::{
    attach_advisories, distro_name, parse_holds, parse_installed, parse_obsoletes,
    parse_repositories, parse_updateinfo, parse_upgrades, security_packages,
};

/// The image, and whether a stock one should have any updates.
///
/// Amazon Linux 2023 pins `$releasever` to the snapshot the image was built
/// from, so it has none.
const IMAGES: &[(&str, bool)] = &[
    ("rockylinux/rockylinux:8", true),
    ("rockylinux/rockylinux:9", true),
    ("amazonlinux:2023", false),
];

/// The script `tests/fixtures/dnf/*.txt` were captured with, kept so they can
/// be regenerated.
///
/// `RELEASEVER` is only set for the `amazonlinux2023-latest` fixture. It
/// mirrors `dnf upgrade --releasever=latest`, which is how an Amazon Linux host
/// moves off its pinned snapshot.
const CAPTURE: &str = r#"
set -u
DNFARGS=""
if [ -n "${RELEASEVER:-}" ]; then DNFARGS="--releasever=$RELEASEVER"; fi
dnf -q $DNFARGS makecache >/dev/null 2>&1
echo "===OS_RELEASE==="
cat /etc/os-release
echo "===RPM_QA==="
rpm -qa --qf '%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{ARCH}\t%{MODULARITYLABEL}\n'
echo "===UPGRADES==="
dnf -q $DNFARGS repoquery --upgrades --latest-limit=1 --qf '%{name}\t%{evr}\t%{arch}\t%{reponame}' 2>/dev/null
echo "===CHECK_UPDATE==="
dnf -q $DNFARGS check-update 2>/dev/null
echo "===CHECK_UPDATE_OBSOLETES==="
dnf -q $DNFARGS check-update --obsoletes 2>/dev/null
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

/// Builds the state `tests/fixtures/dnf/rocky9-obsoletes.txt` was captured
/// from, since no official image has an obsoletion in it.
///
/// Three packages from a local repository: one that only obsoletes an
/// installed package, one that is an upgrade and also obsoletes something, and
/// one with a long name to check column padding in the table.
const OBSOLETES_CAPTURE: &str = r#"
set -u
dnf -q install -y rpm-build createrepo_c >/dev/null 2>&1
mkdir -p /root/rpmbuild/SPECS /tmp/repo
spec() {
cat > /root/rpmbuild/SPECS/$1.spec <<SPEC
Name: $1
Version: $2
Release: 1.el9
Summary: t
License: MIT
BuildArch: noarch
${3:-}
%description
t
%files
%changelog
SPEC
rpmbuild -bb --quiet /root/rpmbuild/SPECS/$1.spec >/dev/null 2>&1
}
spec oldthing 1.0
spec gonepkg 1.0
spec keeper 1.0
spec newthing 2.0 "Obsoletes: oldthing < 2.0"
spec keeper 2.0 "Obsoletes: gonepkg < 2.0"
spec updawg-replacement-with-a-very-long-package-name 2.0 "Obsoletes: keeper-legacy < 2.0"
spec keeper-legacy 1.0
rpm -i /root/rpmbuild/RPMS/noarch/oldthing-1.0-1.el9.noarch.rpm \
       /root/rpmbuild/RPMS/noarch/gonepkg-1.0-1.el9.noarch.rpm \
       /root/rpmbuild/RPMS/noarch/keeper-legacy-1.0-1.el9.noarch.rpm \
       /root/rpmbuild/RPMS/noarch/keeper-1.0-1.el9.noarch.rpm 2>/dev/null
cp /root/rpmbuild/RPMS/noarch/newthing-2.0-1.el9.noarch.rpm \
   /root/rpmbuild/RPMS/noarch/keeper-2.0-1.el9.noarch.rpm \
   /root/rpmbuild/RPMS/noarch/updawg-replacement-with-a-very-long-package-name-2.0-1.el9.noarch.rpm /tmp/repo/
createrepo_c -q /tmp/repo
printf '[local]\nname=local\nbaseurl=file:///tmp/repo\nenabled=1\ngpgcheck=0\n' > /etc/yum.repos.d/local.repo
dnf -q makecache >/dev/null 2>&1
echo "===RPM_QA==="
rpm -qa --qf '%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{ARCH}\t%{MODULARITYLABEL}\n'
echo "===UPGRADES==="
dnf -q repoquery --upgrades --latest-limit=1 --qf '%{name}\t%{evr}\t%{arch}\t%{reponame}' 2>/dev/null
echo "===CHECK_UPDATE_OBSOLETES==="
dnf -q check-update --obsoletes 2>/dev/null
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

/// `name.arch` for every row of a `check-update` table.
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
            "{image}: captured nothing; is the image pullable?"
        );

        let distro = distro_name(&section(&out, "OS_RELEASE"))
            .unwrap_or_else(|| panic!("{image}: /etc/os-release carries no NAME"));

        let installed = parse_installed(&section(&out, "RPM_QA"));
        assert!(
            installed.len() > 50,
            "{image}: only {} packages; rpm's format string has moved",
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

        // `--latest-limit=1` should still give one candidate per package, and
        // repoquery should agree with the check-update table.
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
            "{image}: no repositories; dnf repolist -v's format has moved"
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
            "{image}: {} updates and not one security advisory; updateinfo's format has moved",
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

#[test]
#[ignore = "needs Docker, and builds three RPMs inside the container"]
fn an_obsoletion_is_still_reported_the_way_the_fixture_was_captured() {
    if !docker_available() {
        assert!(
            std::env::var("UPDAWG_REQUIRE_DOCKER").is_err(),
            "UPDAWG_REQUIRE_DOCKER is set but Docker is not usable"
        );
        eprintln!("skipping: no Docker");
        return;
    }

    let out = capture_with("rockylinux/rockylinux:9", OBSOLETES_CAPTURE);
    assert!(
        out.contains("===RPM_QA==="),
        "captured nothing; is rpmbuild still in the Rocky 9 repositories?"
    );

    let installed = parse_installed(&section(&out, "RPM_QA"));
    let removals = parse_obsoletes(&section(&out, "CHECK_UPDATE_OBSOLETES"), &installed);
    let named: Vec<(&str, &str)> = removals
        .iter()
        .map(|r| {
            (
                r.name.as_str(),
                r.replaced_by.as_ref().map_or("", |p| p.name.as_str()),
            )
        })
        .collect();
    assert_eq!(
        named,
        vec![
            ("gonepkg", "keeper"),
            ("oldthing", "newthing"),
            (
                "keeper-legacy",
                "updawg-replacement-with-a-very-long-package-name"
            ),
        ],
        "the `Obsoleting Packages` section has moved"
    );

    // repoquery --upgrades doesn't report obsoletions, which is why the backend
    // reads check-update at all. If that changes, this fails.
    let updates = parse_upgrades(&section(&out, "UPGRADES"), &installed);
    assert!(
        !updates.iter().any(|u| u.name == "newthing"),
        "repoquery --upgrades now reports obsoletes; parse_obsoletes may be redundant"
    );

    eprintln!("rocky9 synthetic: {} obsoletions", removals.len());
}

#[test]
#[ignore = "needs Docker and pulls three distribution images"]
fn an_update_still_carries_the_advisory_dnf_names_for_it() {
    if !docker_available() {
        assert!(
            std::env::var("UPDAWG_REQUIRE_DOCKER").is_err(),
            "UPDAWG_REQUIRE_DOCKER is set but Docker is not usable"
        );
        eprintln!("skipping: no Docker");
        return;
    }

    for (image, has_updates) in IMAGES {
        if !has_updates {
            continue;
        }
        let out = capture(image);
        let installed = parse_installed(&section(&out, "RPM_QA"));
        let mut updates = parse_upgrades(&section(&out, "UPGRADES"), &installed);
        attach_advisories(
            &mut updates,
            &parse_updateinfo(&section(&out, "UPDATEINFO")),
        );

        let rated = updates.iter().filter(|u| !u.advisories.is_empty()).count();
        assert!(
            rated > 0,
            "{image}: {} updates and not one advisory attached; updateinfo's package names no longer line up with repoquery's",
            updates.len()
        );
        for update in &updates {
            for hint in &update.advisories {
                assert!(!hint.id.is_empty(), "{image}: an advisory with no id");
                assert_eq!(
                    hint.kind,
                    hint.kind.to_ascii_lowercase(),
                    "{image}: {} is spelled {}",
                    hint.id,
                    hint.kind
                );
            }
        }

        assert!(
            parse_obsoletes(&section(&out, "CHECK_UPDATE_OBSOLETES"), &installed).is_empty(),
            "{image}: a stock image reported an obsoletion"
        );
        eprintln!(
            "{image}: {rated} of {} updates carry an advisory",
            updates.len()
        );
    }
}
