//! The dnf parsers, against output captured from real distributions (DAWG-35).
//!
//! Every fixture in `tests/fixtures/dnf/` is the literal output of running `rpm
//! -qa`, `dnf repoquery --upgrades`, `dnf check-update`, `dnf updateinfo list`,
//! `dnf repolist -v` and `dnf versionlock list` inside that distribution's
//! official container image. Nothing here is hand-written, because hand-written
//! fixtures test what I believed dnf prints rather than what it prints.
//!
//! The distributions are the ones DAWG-35 names: Rocky 8 (dnf 4.7), Rocky 9 (dnf
//! 4.14) and Amazon Linux 2023 (dnf 4.14). `tests/dnf_live.rs` re-captures them
//! from live containers and is the canary for the format drifting.
//!
//! # Why Amazon Linux is here twice
//!
//! Amazon Linux 2023 does **deterministic upgrades**: `$releasever` is pinned to
//! a dated snapshot and `dnf check-update` reports nothing at all until somebody
//! moves it. `amazonlinux2023` is a stock image and has *zero* updates — which is
//! the truth about that host, and a state a fleet dashboard will show as fully
//! patched. `amazonlinux2023-latest` is the same distribution after
//! `--releasever=latest`, which is how such a host actually moves, and is where
//! the ALAS advisories and the wrapped `check-update` line come from.
//!
//! # And why there is a fifth fixture
//!
//! `rocky9-obsoletes` is a Rocky 9 container with three obsoleting packages
//! built with `rpmbuild` into a local repository, because **no stock image has
//! an obsoletion in it** — I checked Rocky 8, Rocky 9 and Amazon Linux 2023 and
//! none of them do. The packages are synthetic; the `dnf` output is not, and it
//! is the only way to have captured output for a state that matters (DAWG-232)
//! and that no official image reaches. `tests/dnf_live.rs` rebuilds it.

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
use updawg_backends::dnf;
use updawg_backends::dnf::{
    AdvisoryKind, attach_advisories, distro_name, parse_holds, parse_installed, parse_obsoletes,
    parse_repositories, parse_updateinfo, parse_upgrades, repo_is_distro, security_packages,
};

/// The four fixtures, the `NAME` each one's `/etc/os-release` carries, and
/// whether it should have any updates at all.
const DISTROS: &[(&str, &str, bool)] = &[
    ("rocky8", "Rocky Linux", true),
    ("rocky9", "Rocky Linux", true),
    ("amazonlinux2023", "Amazon Linux", false),
    ("amazonlinux2023-latest", "Amazon Linux", true),
];

fn fixture(name: &str) -> String {
    let path = format!(
        "{}/tests/fixtures/dnf/{name}.txt",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// One `===SECTION===` out of a fixture.
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

/* --------------------------------------------------------------- installed */

#[test]
fn every_distribution_reports_its_installed_packages() {
    for (distro, _, _) in DISTROS {
        let f = fixture(distro);
        let packages = parse_installed(&section(&f, "RPM_QA"));

        // A base image has 100-200 packages. An empty list would mean the format
        // string changed and the agent now reports a host with nothing installed
        // — which reads as a host with nothing to patch.
        assert!(
            packages.len() > 50,
            "{distro}: only {} packages parsed",
            packages.len()
        );
        for p in &packages {
            assert!(!p.name.is_empty(), "{distro}: a package with no name");
            assert!(
                !p.version.is_empty(),
                "{distro}: {} parsed with no version",
                p.name
            );
            assert!(
                !p.arch.is_empty(),
                "{distro}: {} parsed with no architecture",
                p.name
            );
            assert!(
                p.repo.is_none(),
                "{distro}: {} claims a repository rpm does not know",
                p.name
            );
        }
    }
}

#[test]
fn an_imported_signing_key_is_not_an_installed_package() {
    // rpm keeps imported GPG keys in the package database and `rpm -qa` lists
    // them, with `(none)` for the architecture. Reported as packages, the server
    // would match advisories against a key fingerprint and offer to upgrade one.
    //
    // Three of the four fixtures carry one. Rocky 8's does not — its image has
    // never installed a signed package, so no key has been imported — which is
    // why this counts the fixtures that prove something rather than requiring all
    // of them to.
    let mut proven = 0;
    for (distro, _, _) in DISTROS {
        let f = fixture(distro);
        let raw = section(&f, "RPM_QA");
        if !raw.contains("gpg-pubkey") {
            continue;
        }
        proven += 1;
        assert!(
            !parse_installed(&raw).iter().any(|p| p.name == "gpg-pubkey"),
            "{distro}: gpg-pubkey was reported as an installed package"
        );
    }
    assert!(
        proven >= 3,
        "only {proven} fixtures have a gpg-pubkey row; this test proves almost nothing"
    );
}

#[test]
fn an_epoch_survives_into_the_version() {
    // The server's rpm comparison parses `[epoch:]version[-release]`, and an
    // epoch dropped here makes `2:1.34-13` look older than `1.35`, which reverses
    // the only thing an epoch exists to do.
    let packages = parse_installed(&section(&fixture("rocky9"), "RPM_QA"));
    let tar = packages
        .iter()
        .find(|p| p.name == "tar")
        .expect("rocky9 has tar installed");
    assert!(
        tar.version.starts_with("2:"),
        "tar parsed as {} with its epoch dropped",
        tar.version
    );

    // And a package without one does not acquire `0:`, because the two spellings
    // compare equal but only one of them is what rpm prints.
    let zlib = packages
        .iter()
        .find(|p| p.name == "zlib")
        .expect("rocky9 has zlib installed");
    assert!(
        !zlib.version.contains(':'),
        "zlib parsed as {} with an epoch invented",
        zlib.version
    );
}

/* ----------------------------------------------------------------- updates */

#[test]
fn every_distribution_reports_its_available_updates() {
    for (distro, _, has_updates) in DISTROS {
        let f = fixture(distro);
        let installed = parse_installed(&section(&f, "RPM_QA"));
        let updates = parse_upgrades(&section(&f, "UPGRADES"), &installed);

        assert_eq!(
            !updates.is_empty(),
            *has_updates,
            "{distro}: {} updates, expected {}",
            updates.len(),
            if *has_updates { "some" } else { "none" }
        );

        for u in &updates {
            assert!(
                !u.installed.is_empty(),
                "{distro}: {} has a candidate but no installed version",
                u.name
            );
            assert_ne!(
                u.installed, u.candidate,
                "{distro}: {} is reported as an update to itself",
                u.name
            );
            assert!(
                !u.arch.is_empty(),
                "{distro}: {} parsed with no architecture",
                u.name
            );
            assert!(
                u.repo.is_some(),
                "{distro}: {} came from no repository",
                u.name
            );
        }
    }
}

#[test]
fn one_package_gets_one_candidate() {
    // `repoquery --upgrades` without `--latest-limit=1` returns every newer
    // version in the repositories — 77 records for 38 upgradable packages on a
    // stock Rocky 9, three of them glib2. The captured fixture has the flag, and
    // this is what would notice if it were ever dropped.
    for (distro, _, _) in DISTROS {
        let f = fixture(distro);
        let installed = parse_installed(&section(&f, "RPM_QA"));
        let updates = parse_upgrades(&section(&f, "UPGRADES"), &installed);

        let mut seen = BTreeSet::new();
        for u in &updates {
            assert!(
                seen.insert((u.name.clone(), u.arch.clone())),
                "{distro}: {}.{} has more than one candidate",
                u.name,
                u.arch
            );
        }
    }
}

#[test]
fn the_machine_readable_query_agrees_with_the_table_dnf_prints() {
    // The two are different commands answering the same question, and the whole
    // reason for preferring `repoquery` is that `check-update` is a padded table
    // that wraps. If they ever stop agreeing, the flag or the query has moved.
    for (distro, _, _) in DISTROS {
        let f = fixture(distro);
        let installed = parse_installed(&section(&f, "RPM_QA"));

        let queried: BTreeSet<String> = parse_upgrades(&section(&f, "UPGRADES"), &installed)
            .iter()
            .map(|u| format!("{}.{}", u.name, u.arch))
            .collect();
        let tabled = check_update_names(&section(&f, "CHECK_UPDATE"));

        assert_eq!(queried, tabled, "{distro}: the two disagree");
    }
}

#[test]
fn a_package_whose_name_overflows_the_column_is_not_lost() {
    // The reason `check-update` is not what the backend parses. `scrape` here is
    // the crude version a production parser would be, minus the wrap handling,
    // and this asserts the fixture really does contain the case that breaks it.
    let table = section(&fixture("amazonlinux2023-latest"), "CHECK_UPDATE");
    assert!(
        table
            .lines()
            .any(|l| l.trim() == "elfutils-default-yama-scope.noarch"),
        "the fixture no longer has a wrapped line, so this proves nothing"
    );

    let naive: BTreeSet<&str> = table
        .lines()
        .filter(|l| l.split_whitespace().count() == 3)
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    assert!(
        !naive.contains("elfutils-default-yama-scope.noarch"),
        "the naive three-field parse now handles the wrap, so the fixture changed"
    );
    assert!(
        check_update_names(&table).contains("elfutils-default-yama-scope.noarch"),
        "the wrap-aware scrape lost the package too"
    );
}

/// `name.arch` for every row of a `check-update` table, test-side.
///
/// Deliberately not production code: nothing in the backend parses this table,
/// precisely because getting it right means knowing that **a row whose
/// `name.arch` overflows the first column is printed alone and its version and
/// repository follow on the next line, indented**. Taking the first field of
/// every line that does not start with whitespace handles both shapes.
fn check_update_names(table: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in table.lines() {
        // A continuation, or the indented half of an obsoletes pair.
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        let Some(first) = line.split_whitespace().next() else {
            continue;
        };
        // `Obsoleting Packages`, and anything else dnf says in prose. Every real
        // row's first field is `name.arch`.
        if !first.contains('.') {
            continue;
        }
        names.insert(first.to_owned());
    }
    names
}

/* ------------------------------------------------------------- updateinfo */

#[test]
fn a_security_advisory_carries_a_severity_and_a_bugfix_does_not() {
    for (distro, _, has_updates) in DISTROS {
        if !has_updates {
            continue;
        }
        let hints = parse_updateinfo(&section(&fixture(distro), "UPDATEINFO"));
        assert!(!hints.is_empty(), "{distro}: no advisories parsed");

        for h in &hints {
            assert!(!h.advisory.is_empty(), "{distro}: an advisory with no id");
            assert!(
                !h.package.is_empty(),
                "{distro}: an advisory with no package"
            );
            assert!(
                !h.version.is_empty(),
                "{distro}: {} has no version",
                h.package
            );
            assert!(
                !h.arch.is_empty(),
                "{distro}: {} has no architecture",
                h.package
            );
            match h.kind {
                AdvisoryKind::Security => assert!(
                    h.severity.is_some(),
                    "{distro}: security advisory {} has no severity",
                    h.advisory
                ),
                // Inventing a severity for a routine rebuild would put it on the
                // same scale as a remote code execution.
                _ => assert!(
                    h.severity.is_none(),
                    "{distro}: {:?} advisory {} acquired a severity",
                    h.kind,
                    h.advisory
                ),
            }
        }
    }
}

#[test]
fn the_vendors_own_words_are_reported_rather_than_normalised() {
    // Red Hat's rebuilds say `Moderate`; Amazon says `Medium` for the same band.
    // Mapping one onto the other is the server's job (DAWG-65) — the agent would
    // be guessing, and a guess made here cannot be corrected later.
    let rocky: BTreeSet<String> = parse_updateinfo(&section(&fixture("rocky9"), "UPDATEINFO"))
        .into_iter()
        .filter_map(|h| h.severity)
        .collect();
    let amazon: BTreeSet<String> =
        parse_updateinfo(&section(&fixture("amazonlinux2023-latest"), "UPDATEINFO"))
            .into_iter()
            .filter_map(|h| h.severity)
            .collect();

    assert!(rocky.contains("Moderate"), "rocky9 severities: {rocky:?}");
    assert!(amazon.contains("Medium"), "amazon severities: {amazon:?}");
    assert!(
        !amazon.contains("Moderate"),
        "an Amazon severity was rewritten into Red Hat's vocabulary"
    );
}

#[test]
fn a_package_with_several_advisories_is_one_security_update() {
    // dnf lists an advisory per version, including versions between the installed
    // one and the candidate: glibc on a stock Rocky 9 has three. The heartbeat
    // counts updates, not advisories.
    let f = fixture("rocky9");
    let hints = parse_updateinfo(&section(&f, "UPDATEINFO"));
    let glibc = hints.iter().filter(|h| h.package == "glibc").count();
    assert!(
        glibc > 1,
        "the fixture no longer has a package with several advisories, so this proves nothing"
    );

    let security = security_packages(&section(&f, "UPDATEINFO"));
    assert!(security.contains("glibc"));
    assert!(
        security.len() < hints.len(),
        "collapsing to names changed nothing"
    );
}

#[test]
fn a_hyphenated_package_name_survives_the_nevra() {
    // `elfutils-default-yama-scope-0.188-3.amzn2023.0.3.noarch` is one package.
    // Splitting on the first hyphen makes it `elfutils`, which exists, so the
    // mistake looks like a correct answer.
    let hints = parse_updateinfo(&section(&fixture("amazonlinux2023-latest"), "UPDATEINFO"));
    let long = hints
        .iter()
        .find(|h| h.package.matches('-').count() >= 2)
        .expect("the fixture has a package with hyphens in its name");
    assert!(
        !long.version.is_empty() && !long.version.contains('/'),
        "{} parsed a version of {}",
        long.package,
        long.version
    );
    assert!(
        matches!(long.arch.as_str(), "noarch" | "aarch64" | "x86_64" | "i686"),
        "{} parsed an architecture of {}",
        long.package,
        long.arch
    );
}

#[test]
fn only_updates_that_are_actually_available_count_as_security() {
    // What `DnfBackend::security_updates` does with the two lists. An advisory
    // naming a package that is not upgradable — because it is held, or because
    // the advisory is for a version already installed — must not be counted.
    let f = fixture("rocky9");
    let installed = parse_installed(&section(&f, "RPM_QA"));
    let updates = parse_upgrades(&section(&f, "UPGRADES"), &installed);
    let named: BTreeSet<&str> = updates.iter().map(|u| u.name.as_str()).collect();

    let security = security_packages(&section(&f, "UPDATEINFO"));
    assert!(!security.is_empty(), "rocky9 has security advisories");

    let counted = security
        .iter()
        .filter(|p| named.contains(p.as_str()))
        .count();
    assert!(counted > 0, "none of the advisories matched an update");
    assert!(
        counted <= updates.len(),
        "more security updates ({counted}) than updates ({})",
        updates.len()
    );
}

/* ----------------------------------------------------------- repositories */

#[test]
fn every_distribution_reports_its_repositories() {
    for (distro, name, _) in DISTROS {
        let f = fixture(distro);
        let repos = parse_repositories(&section(&f, "REPOLIST"), Some(name));

        assert!(
            !repos.is_empty(),
            "{distro}: no repositories — dnf repolist -v has moved"
        );
        assert!(
            repos.iter().any(|r| r.enabled),
            "{distro}: every repository parsed as disabled"
        );
        assert!(
            repos.iter().any(|r| !r.enabled),
            "{distro}: every repository parsed as enabled — the source and debuginfo ones are not"
        );
        for r in &repos {
            assert!(!r.id.is_empty(), "{distro}: a repository with no id");
            assert_eq!(r.kind, "rpm");
            assert!(
                !r.third_party,
                "{distro}: a stock image reported {} as third-party",
                r.id
            );
        }

        let mut ids: Vec<&str> = repos.iter().map(|r| r.id.as_str()).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "{distro}: a repository was parsed twice");
    }
}

#[test]
fn a_repository_name_too_wide_for_the_terminal_is_read_in_full() {
    // Why `-v`. The plain table truncates to the terminal width and turns
    // `Rocky Linux 9 - Devel WARNING! FOR BUILDROOT ONLY DO NOT LEAVE ENABLED`
    // into something ending mid-word — and a name cut off mid-word matches
    // nothing.
    let raw = section(&fixture("rocky9"), "REPOLIST");
    assert!(
        raw.contains("DO NOT LEAVE ENABLED"),
        "the fixture no longer has a long repository name, so this proves nothing"
    );
    let repos = parse_repositories(&raw, Some("Rocky Linux"));
    let devel = repos
        .iter()
        .find(|r| r.id == "devel")
        .expect("rocky9 has a devel repository");
    assert!(!devel.enabled, "the buildroot repository parsed as enabled");
    assert!(!devel.third_party);
}

#[test]
fn a_repository_the_distribution_does_not_publish_is_third_party() {
    for (repo, distro) in [
        ("Rocky Linux 9 - BaseOS", "Rocky Linux"),
        ("Amazon Linux 2023 repository", "Amazon Linux"),
        (
            "Red Hat Enterprise Linux 9 for x86_64 - BaseOS (RPMs)",
            "Red Hat Enterprise Linux",
        ),
        ("CentOS Stream 9 - BaseOS", "CentOS Stream"),
        // Oracle names its repositories after the distribution and its
        // `/etc/os-release` after the product, so only the first word agrees.
        (
            "Oracle Linux 9 BaseOS Latest (aarch64)",
            "Oracle Linux Server",
        ),
    ] {
        assert!(repo_is_distro(repo, distro), "{repo} under {distro}");
    }

    for (repo, distro) in [
        (
            "Extra Packages for Enterprise Linux 9 - aarch64",
            "Rocky Linux",
        ),
        (
            "Extra Packages for Enterprise Linux 9 - x86_64",
            "Red Hat Enterprise Linux",
        ),
        ("Docker CE Stable - x86_64", "Rocky Linux"),
        ("Some Vendor", "Amazon Linux"),
        ("", "Rocky Linux"),
    ] {
        assert!(!repo_is_distro(repo, distro), "{repo} under {distro}");
    }
}

#[test]
fn a_host_that_will_not_say_what_it_is_has_no_repositories_of_its_own() {
    // The safe direction: an unsigned or hand-rolled repository often has a name
    // nobody would recognise, and those are the ones that break a release
    // upgrade.
    let repos = parse_repositories(&section(&fixture("rocky9"), "REPOLIST"), None);
    assert!(!repos.is_empty());
    assert!(repos.iter().all(|r| r.third_party));
}

#[test]
fn the_distribution_name_comes_from_os_release() {
    for (distro, name, _) in DISTROS {
        assert_eq!(
            distro_name(&section(&fixture(distro), "OS_RELEASE")).as_deref(),
            Some(*name),
            "{distro}"
        );
    }
    assert_eq!(distro_name(""), None);
    assert_eq!(distro_name("ID=rocky\n"), None);
    assert_eq!(distro_name("NAME=\"\"\n"), None);
}

/* ------------------------------------------------------------------ holds */

#[test]
fn every_distribution_reports_what_it_has_locked() {
    for (distro, _, _) in DISTROS {
        let holds = parse_holds(&section(&fixture(distro), "HOLDS"));
        assert_eq!(
            holds,
            vec!["zlib".to_string(), "tar".to_string()],
            "{distro}"
        );
    }
}

#[test]
fn a_package_locked_at_several_versions_is_held_once() {
    // `dnf versionlock add tar` writes one entry per version it knows about —
    // three on Amazon Linux. Three entries is still one held package.
    let raw = section(&fixture("amazonlinux2023"), "HOLDS");
    assert!(
        raw.lines().filter(|l| l.starts_with("tar-")).count() > 1,
        "the fixture no longer has a package locked twice, so this proves nothing"
    );
    assert_eq!(parse_holds(&raw).iter().filter(|h| *h == "tar").count(), 1);
}

#[test]
fn nothing_in_the_lock_file_that_is_not_a_lock_becomes_one() {
    // The list is a plain file a person can edit, and dnf writes a dated comment
    // above each entry when it adds one.
    let holds = parse_holds(
        "\n# Added lock on Mon Sep 21 19:05:31 2026\nzlib-0:1.2.11-40.el9.*\n\nkernel*\n",
    );
    assert_eq!(holds, vec!["zlib".to_string(), "kernel".to_string()]);
}

/* ------------------------------ obsoletions and hints (DAWG-231, DAWG-232) */

#[test]
fn a_stock_host_has_no_obsoletions() {
    // The normal answer, and worth asserting: `parse_obsoletes` reads a table
    // that on most hosts does not contain the section it is looking for, and
    // "found nothing" must not be reachable by finding the wrong thing.
    for (distro, _, _) in DISTROS {
        let f = fixture(distro);
        let installed = parse_installed(&section(&f, "RPM_QA"));
        assert!(
            parse_obsoletes(&section(&f, "CHECK_UPDATE"), &installed).is_empty(),
            "{distro} reported an obsoletion"
        );
    }
}

#[test]
fn an_obsoleted_package_is_reported_with_what_replaces_it() {
    let f = fixture("rocky9-obsoletes");
    let installed = parse_installed(&section(&f, "RPM_QA"));
    let removals = parse_obsoletes(&section(&f, "CHECK_UPDATE_OBSOLETES"), &installed);

    let named: Vec<(&str, Option<&str>)> = removals
        .iter()
        .map(|r| {
            (
                r.name.as_str(),
                r.replaced_by.as_ref().map(|p| p.name.as_str()),
            )
        })
        .collect();
    assert_eq!(
        named,
        vec![
            ("gonepkg", Some("keeper")),
            ("oldthing", Some("newthing")),
            (
                "keeper-legacy",
                Some("updawg-replacement-with-a-very-long-package-name")
            ),
        ]
    );

    let gone = &removals[0];
    assert_eq!(gone.arch, "noarch");
    assert_eq!(gone.installed, "1.0-1.el9");
    let by = gone.replaced_by.as_ref().unwrap();
    assert_eq!(by.version, "2.0-1.el9");
    assert_eq!(by.repo.as_deref(), Some("local"));
}

#[test]
fn an_obsoleter_that_is_also_an_upgrade_appears_on_both_lists() {
    // `keeper` 2.0 upgrades `keeper` 1.0 *and* obsoletes `gonepkg`. Both are
    // true and they are different statements: one moves a version, the other
    // takes a package away.
    let f = fixture("rocky9-obsoletes");
    let installed = parse_installed(&section(&f, "RPM_QA"));
    let updates = parse_upgrades(&section(&f, "UPGRADES"), &installed);
    let removals = parse_obsoletes(&section(&f, "CHECK_UPDATE_OBSOLETES"), &installed);

    assert!(updates.iter().any(|u| u.name == "keeper"));
    assert!(removals.iter().any(|r| r.name == "gonepkg"));
    // And the package that only obsoletes is on neither list as an update:
    // `repoquery --upgrades` does not report it, which is the whole reason
    // `check-update` is read at all.
    assert!(!updates.iter().any(|u| u.name == "newthing"));
}

#[test]
fn a_wrapped_obsoleting_table_is_read_the_same_way() {
    // The same entries as the fixture, re-flowed the way `check-update` wraps a
    // name too wide for its column — the `CHECK_UPDATE` section of
    // `amazonlinux2023-latest.txt` is the real thing. Reading this as lines
    // loses entries; reading it as a token stream cannot.
    let wrapped = "Obsoleting Packages
keeper.noarch
                                  2.0-1.el9      local
    gonepkg.noarch                1.0-1.el9      @System
updawg-replacement-with-a-very-long-package-name.noarch
                                  2.0-1.el9      local
    keeper-legacy.noarch
                                  1.0-1.el9      @System
";
    let f = fixture("rocky9-obsoletes");
    let installed = parse_installed(&section(&f, "RPM_QA"));
    let removals = parse_obsoletes(wrapped, &installed);
    assert_eq!(
        removals
            .iter()
            .map(|r| (
                r.name.as_str(),
                r.replaced_by.as_ref().unwrap().name.as_str()
            ))
            .collect::<Vec<_>>(),
        vec![
            ("gonepkg", "keeper"),
            (
                "keeper-legacy",
                "updawg-replacement-with-a-very-long-package-name"
            ),
        ]
    );
}

#[test]
fn a_table_that_stops_making_sense_ends_the_section_rather_than_shifting() {
    // A field lost mid-table would put every following entry one column out and
    // produce a list of confident nonsense. Stopping under-reports, which is the
    // direction somebody can notice.
    let f = fixture("rocky9-obsoletes");
    let installed = parse_installed(&section(&f, "RPM_QA"));
    let truncated = "Obsoleting Packages
keeper.noarch 2.0-1.el9 local
    gonepkg.noarch 1.0-1.el9 @System
newthing.noarch
";
    let removals = parse_obsoletes(truncated, &installed);
    assert_eq!(removals.len(), 1);
    assert_eq!(removals[0].name, "gonepkg");
}

#[test]
fn an_obsoletion_of_something_this_host_does_not_have_is_dropped() {
    let table = "Obsoleting Packages
keeper.noarch 2.0-1.el9 local
    nothing-here.noarch 1.0-1.el9 @System
";
    assert!(parse_obsoletes(table, &[]).is_empty());
}

#[test]
fn an_update_carries_the_advisory_its_package_manager_named() {
    let f = fixture("rocky9");
    let installed = parse_installed(&section(&f, "RPM_QA"));
    let mut updates = parse_upgrades(&section(&f, "UPGRADES"), &installed);
    attach_advisories(&mut updates, &parse_updateinfo(&section(&f, "UPDATEINFO")));

    let openssl = updates
        .iter()
        .find(|u| u.name == "openssl")
        .expect("openssl is upgradable on the rocky9 fixture");
    let hint = openssl
        .advisories
        .iter()
        .find(|a| a.kind == "security")
        .expect("openssl's update is a security fix on this host");
    assert!(hint.id.starts_with("RLSA-"), "{}", hint.id);
    assert!(hint.severity.is_some());
    assert!(hint.fixed_in.is_some());
}

#[test]
fn a_severity_word_reaches_the_wire_exactly_as_the_vendor_wrote_it() {
    // Rocky says `Moderate` where Amazon Linux says `Medium` for the same band.
    // Both survive the trip; deciding they are the same is the server's job.
    let mut words = BTreeSet::new();
    for distro in ["rocky9", "amazonlinux2023-latest"] {
        let f = fixture(distro);
        let installed = parse_installed(&section(&f, "RPM_QA"));
        let mut updates = parse_upgrades(&section(&f, "UPGRADES"), &installed);
        attach_advisories(&mut updates, &parse_updateinfo(&section(&f, "UPDATEINFO")));
        words.extend(
            updates
                .iter()
                .flat_map(|u| &u.advisories)
                .filter_map(|a| a.severity.clone()),
        );
    }
    assert!(words.contains("Moderate"), "{words:?}");
    assert!(words.contains("Medium"), "{words:?}");
}

#[test]
fn a_bugfix_advisory_reaches_the_wire_without_a_severity() {
    let f = fixture("rocky9");
    let installed = parse_installed(&section(&f, "RPM_QA"));
    let mut updates = parse_upgrades(&section(&f, "UPGRADES"), &installed);
    attach_advisories(&mut updates, &parse_updateinfo(&section(&f, "UPDATEINFO")));

    let non_security: Vec<_> = updates
        .iter()
        .flat_map(|u| &u.advisories)
        .filter(|a| a.kind != "security")
        .collect();
    assert!(
        !non_security.is_empty(),
        "the rocky9 fixture has bugfix advisories in it"
    );
    for hint in non_security {
        assert!(
            hint.severity.is_none(),
            "{} is a {} and carries a severity",
            hint.id,
            hint.kind
        );
    }
}

#[test]
fn every_attached_advisory_is_about_a_package_that_has_an_update() {
    let f = fixture("rocky9");
    let installed = parse_installed(&section(&f, "RPM_QA"));
    let mut updates = parse_upgrades(&section(&f, "UPGRADES"), &installed);
    attach_advisories(&mut updates, &parse_updateinfo(&section(&f, "UPDATEINFO")));

    let upgradable: BTreeSet<&str> = updates.iter().map(|u| u.name.as_str()).collect();
    // And the reverse: every security row about something upgradable found a
    // home, so the count on the heartbeat and the list on the upload agree.
    let security: BTreeSet<String> = security_packages(&section(&f, "UPDATEINFO"))
        .into_iter()
        .filter(|p| upgradable.contains(p.as_str()))
        .collect();
    let attached: BTreeSet<String> = updates
        .iter()
        .filter(|u| u.advisories.iter().any(|a| a.kind == "security"))
        .map(|u| u.name.clone())
        .collect();
    assert!(!security.is_empty());
    assert_eq!(security, attached);
}

#[test]
fn attaching_advisories_twice_changes_nothing() {
    // A join that appended would grow the list on every pass and change the
    // upload every time without anything on the host changing.
    let f = fixture("rocky9");
    let installed = parse_installed(&section(&f, "RPM_QA"));
    let mut once = parse_upgrades(&section(&f, "UPGRADES"), &installed);
    let rows = parse_updateinfo(&section(&f, "UPDATEINFO"));
    attach_advisories(&mut once, &rows);
    let mut twice = once.clone();
    attach_advisories(&mut twice, &rows);
    assert_eq!(once, twice);
}

#[test]
fn the_kind_of_an_advisory_is_lowercase_and_verbatim() {
    let rows = parse_updateinfo(&section(&fixture("rocky9"), "UPDATEINFO"));
    assert!(!rows.is_empty());
    for row in &rows {
        let spelled = row.kind.as_str();
        assert_eq!(spelled, spelled.to_ascii_lowercase(), "{spelled}");
        if let AdvisoryKind::Other(other) = &row.kind {
            assert_eq!(spelled, other);
        }
    }
}

/* ----------------------------------------- applying: the transaction check */

// `dnf install --assumeno <exact nevras>`, captured from rockylinux:9,
// rockylinux:8 and amazonlinux:2023 on 2026-09-27 with LC_ALL=C and stdout
// piped, which is how the agent runs it. `--assumeno` exits 1 every time.

fn transaction(name: &str) -> &'static str {
    match name {
        "rocky9-openssl-libs" => include_str!("fixtures/dnf/transaction/rocky9-openssl-libs.txt"),
        "rocky9-missing" => include_str!("fixtures/dnf/transaction/rocky9-missing.txt"),
        "rocky9-missing.stderr" => {
            include_str!("fixtures/dnf/transaction/rocky9-missing.stderr.txt")
        }
        "rocky8-weak-deps" => include_str!("fixtures/dnf/transaction/rocky8-weak-deps.txt"),
        "amazonlinux2023-downgrade" => {
            include_str!("fixtures/dnf/transaction/amazonlinux2023-downgrade.txt")
        }
        "rocky9-long-names" => include_str!("fixtures/dnf/transaction/rocky9-long-names.txt"),
        other => panic!("no fixture {other}"),
    }
}

fn ran(stdout: &str, stderr: &str) -> updawg_backends::apt::Ran {
    updawg_backends::apt::Ran {
        code: 1,
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
    }
}

fn pin(name: &str, arch: &str, from: &str, to: &str) -> updawg_backends::Pin {
    updawg_backends::Pin {
        name: name.into(),
        arch: arch.into(),
        from: from.into(),
        to: to.into(),
    }
}

fn refusal(result: updawg_backends::Result<()>) -> String {
    match result {
        Err(updawg_backends::BackendError::Refused(why)) => why,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn openssl(name: &str) -> updawg_backends::Pin {
    pin(name, "aarch64", "1:3.5.5-2.el9_8", "1:3.5.5-5.el9_8")
}

#[test]
fn a_transaction_that_is_exactly_the_pins_passes() {
    let pins = [
        openssl("openssl"),
        openssl("openssl-fips-provider"),
        openssl("openssl-libs"),
    ];
    let todo: Vec<&updawg_backends::Pin> = pins.iter().collect();
    dnf::check_transaction(
        &todo,
        &ran(transaction("rocky9-openssl-libs"), "Operation aborted.\n"),
    )
    .expect("exactly what was approved");
}

#[test]
fn asking_for_one_package_and_getting_three_is_refused() {
    // The real Rocky 9 behaviour: openssl-libs at this version needs openssl
    // and openssl-fips-provider at it too. Nobody approved those.
    let pins = [openssl("openssl-libs")];
    let todo: Vec<&updawg_backends::Pin> = pins.iter().collect();
    let why = refusal(dnf::check_transaction(
        &todo,
        &ran(transaction("rocky9-openssl-libs"), ""),
    ));
    assert!(why.contains("upgrading openssl "), "{why}");
    assert!(why.contains("nobody approved"), "{why}");
}

#[test]
fn a_version_the_repositories_no_longer_carry_is_refused_with_dnfs_reason() {
    let pins = [pin(
        "openssl-libs",
        "aarch64",
        "1:3.5.5-2.el9_8",
        "1:3.5.5-99.el9_8",
    )];
    let todo: Vec<&updawg_backends::Pin> = pins.iter().collect();
    let why = refusal(dnf::check_transaction(
        &todo,
        &ran(
            transaction("rocky9-missing"),
            transaction("rocky9-missing.stderr"),
        ),
    ));
    assert!(why.contains("Unable to find a match"), "{why}");
}

#[test]
fn a_dependency_or_a_weak_dependency_is_refused() {
    let pins = [pin(
        "openssl-libs",
        "aarch64",
        "1:1.1.1k-12.el8_9",
        "1:1.1.1k-16.el8_10",
    )];
    let todo: Vec<&updawg_backends::Pin> = pins.iter().collect();
    let why = refusal(dnf::check_transaction(
        &todo,
        &ran(transaction("rocky8-weak-deps"), ""),
    ));
    assert!(why.contains("installing dependencies openssl "), "{why}");
}

#[test]
fn a_downgrade_is_refused() {
    let pins = [pin(
        "openssl-libs",
        "aarch64",
        "1:3.5.7-2.amzn2023.0.2",
        "1:3.5.7-2.amzn2023.0.1",
    )];
    let todo: Vec<&updawg_backends::Pin> = pins.iter().collect();
    let why = refusal(dnf::check_transaction(
        &todo,
        &ran(transaction("amazonlinux2023-downgrade"), ""),
    ));
    assert!(
        why.starts_with("installing the approved versions would also mean downgrading"),
        "{why}"
    );
}

#[test]
fn every_section_and_row_is_read_including_long_names() {
    let rows = dnf::parse_transaction(transaction("rocky9-long-names"));
    let got: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|r| (r.section.as_str(), r.name.as_str(), r.version.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            (
                "Installing",
                "NetworkManager-config-connectivity-redhat",
                "1:1.54.3-5.el9_8"
            ),
            (
                "Installing",
                "NetworkManager-dispatcher-routing-rules",
                "1:1.54.3-5.el9_8"
            ),
            (
                "Installing",
                "ansible-collection-redhat-rhel_mgmt",
                "1.1.0-2.el9"
            ),
            ("Installing dependencies", "ipcalc", "1.0.0-5.el9"),
        ]
    );
    // Rocky 8's three sections, one row each.
    let sections: Vec<String> = dnf::parse_transaction(transaction("rocky8-weak-deps"))
        .into_iter()
        .map(|r| r.section)
        .collect();
    assert_eq!(
        sections,
        [
            "Upgrading",
            "Installing dependencies",
            "Installing weak dependencies"
        ]
    );
}

#[test]
fn installed_versions_keep_every_install_of_an_install_only_package() {
    let versions = dnf::parse_versions(
        "kernel.x86_64\t5.14.0-570.12.1.el9_6\nkernel.x86_64\t5.14.0-611.5.1.el9_7\n\
         package jq.x86_64 is not installed\nopenssl-libs.aarch64\t1:3.5.5-2.el9_8\n",
    );
    assert_eq!(versions["kernel.x86_64"].len(), 2);
    assert_eq!(versions["openssl-libs.aarch64"], ["1:3.5.5-2.el9_8"]);
    assert!(!versions.contains_key("jq.x86_64"));
}

/// `dnf check-release-update` in `amazonlinux:2023.5.20240805.0`, captured
/// 2026-09-30 (DAWG-233), after installing the plugin that provides it — the
/// container image leaves it out, where AWS's machine images have it. It
/// offers releases up to 2023.10.20260330 while the newest image is 2023.12:
/// what it offers is "newer than this", not always "the newest".
#[test]
fn the_newest_release_amazon_linux_offers_is_read_from_check_release_update() {
    let out = include_str!("fixtures/dnf/check-release-update/amazonlinux2023.5.20240805.txt");
    assert_eq!(dnf::newest_release(out), Some("2023.10.20260330"));
    // A current host: the command prints nothing.
    assert_eq!(dnf::newest_release(""), None);
    // Ordered by number, not by text: 2023.10 is newer than 2023.9.
    assert_eq!(
        dnf::newest_release("  Version 2023.9.20250101:\n  Version 2023.10.20250101:\n"),
        Some("2023.10.20250101")
    );
}
