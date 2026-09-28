//! The apt parsers, against output captured from real distributions (DAWG-34).
//!
//! Every fixture in `tests/fixtures/apt/` is the literal output of running
//! `dpkg-query`, `apt-get -s dist-upgrade`, `apt-cache policy` and `apt-mark
//! showhold` inside that distribution's official container image. Nothing here is
//! hand-written, because hand-written fixtures test what I believed apt prints
//! rather than what it prints.
//!
//! The five are the ones DAWG-34 names: Ubuntu 20.04, 22.04 and 24.04 (apt 2.0,
//! 2.4 and 2.8), and Debian 11 and 12. `tests/apt_live.rs` re-captures them from
//! live containers and is the canary for the format drifting.
//!
//! # And why there is a sixth fixture
//!
//! `debian12-removals` is a Debian 12 container with three packages built by
//! `dpkg-deb` into a local repository, one of which `Replaces` and `Conflicts`
//! the other two, because **no stock image has an upgrade that removes
//! something** and that is the state DAWG-232 exists for. The packages are
//! synthetic; the `apt` output is not, and it is what settled the shape of
//! `PendingRemoval`: apt says a package will be removed and never what
//! replaced it. `tests/apt_live.rs` rebuilds it.

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
    distro_origin, is_security_archive, parse_holds, parse_installed, parse_removals,
    parse_repositories, parse_updates,
};

/// The five distributions, and the origin each one's own repositories carry.
const DISTROS: &[(&str, &str)] = &[
    ("ubuntu2004", "Ubuntu"),
    ("ubuntu2204", "Ubuntu"),
    ("ubuntu2404", "Ubuntu"),
    ("debian11", "Debian"),
    ("debian12", "Debian"),
];

fn fixture(name: &str) -> String {
    let path = format!(
        "{}/tests/fixtures/apt/{name}.txt",
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
    assert!(!out.is_empty(), "fixture section {name} is empty");
    out
}

/* --------------------------------------------------------------- installed */

#[test]
fn every_distribution_reports_its_installed_packages() {
    for (distro, _) in DISTROS {
        let f = fixture(distro);
        let packages = parse_installed(&section(&f, "DPKG_QUERY"));

        // A base image has 80-120 packages. An empty list would mean the format
        // string changed and the agent now reports a host with nothing installed
        // — which reads as a host with nothing to patch.
        assert!(
            packages.len() > 50,
            "{distro}: only {} packages parsed",
            packages.len()
        );
        for p in &packages {
            assert!(!p.name.is_empty(), "{distro}: a package with no name");
            assert!(!p.version.is_empty(), "{distro}: {} has no version", p.name);
            assert!(!p.arch.is_empty(), "{distro}: {} has no arch", p.name);
            // dpkg does not know where a package came from; apt does, and only
            // for packages still available. Guessing would be worse than absent.
            assert!(p.repo.is_none(), "{distro}: dpkg-query invented a repo");
            assert!(
                !p.name.contains(':'),
                "{distro}: {} carries an architecture in its name",
                p.name
            );
        }

        // dpkg is always in a base image, and always installed.
        assert!(
            packages.iter().any(|p| p.name == "dpkg"),
            "{distro}: dpkg itself is missing from the installed list"
        );
    }
}

#[test]
fn only_fully_installed_packages_count() {
    // dpkg also knows config-files (purged, configuration left behind),
    // half-configured, unpacked and several others. Reporting those would have
    // the server matching advisories against packages whose files are not on
    // disk, and proposing upgrades for things that are not there.
    let out = "\
installed-pkg\t1.0\tamd64\tinstalled
removed-pkg\t2.0\tamd64\tconfig-files
broken-pkg\t3.0\tamd64\thalf-configured
unpacked-pkg\t4.0\tamd64\tunpacked
";
    let packages = parse_installed(out);
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "installed-pkg");
}

#[test]
fn a_multi_arch_package_appears_once_per_architecture() {
    // Two rows, one name, two architectures — which is what the server interns
    // as two distinct (name, version, arch) rows. Collapsing them would lose one.
    let out =
        "libc6\t2.39-0ubuntu8.9\tarm64\tinstalled\nlibc6\t2.39-0ubuntu8.9\tarmhf\tinstalled\n";
    let packages = parse_installed(out);
    assert_eq!(packages.len(), 2);
    assert_eq!(packages[0].name, "libc6");
    assert_eq!(packages[1].name, "libc6");
    assert_ne!(packages[0].arch, packages[1].arch);
}

#[test]
fn a_truncated_line_is_skipped_rather_than_guessed() {
    let out = "good\t1.0\tamd64\tinstalled\nbad-no-status\t1.0\tamd64\n\nalso-good\t2.0\tall\tinstalled\n";
    let parsed = parse_installed(out);
    let names: Vec<&str> = parsed.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["good", "also-good"]);
}

/* ----------------------------------------------------------------- updates */

#[test]
fn available_updates_are_parsed_where_a_distribution_had_any() {
    // Ubuntu's images ship behind their own archives, so these have real
    // upgrades. Debian's are fully patched — an empty list there is correct, and
    // the Debian-origin parsing is covered by the install simulation below.
    for distro in ["ubuntu2004", "ubuntu2204", "ubuntu2404"] {
        let f = fixture(distro);
        let updates = parse_updates(&section(&f, "DIST_UPGRADE"));
        assert!(!updates.is_empty(), "{distro}: no upgrades parsed");

        for u in &updates {
            assert!(!u.name.is_empty(), "{distro}: update with no name");
            assert!(
                !u.installed.is_empty(),
                "{distro}: {} has no installed version",
                u.name
            );
            assert!(
                !u.candidate.is_empty(),
                "{distro}: {} has no candidate",
                u.name
            );
            assert_ne!(
                u.installed, u.candidate,
                "{distro}: {} is reported as an update to itself",
                u.name
            );
            assert!(
                !u.arch.is_empty(),
                "{distro}: {} has no architecture",
                u.name
            );
        }
    }
}

#[test]
fn a_package_being_newly_installed_is_not_an_available_update() {
    // The whole distinction is the `[current-version]` bracket. `Inst libbrotli1
    // (1.0.9-2+b6 …)` is apt proposing to pull in a dependency; reporting it
    // would invent an upgrade for a package the host does not have, and the
    // server would then propose "upgrading" it.
    for (distro, _) in DISTROS {
        let f = fixture(distro);
        let sim = section(&f, "INSTALL_SIM");
        assert!(
            sim.contains("Inst "),
            "{distro}: the install simulation captured no Inst lines"
        );
        assert!(
            parse_updates(&sim).is_empty(),
            "{distro}: a newly-installed dependency was reported as an available update"
        );
    }
}

#[test]
fn the_security_pocket_is_identified_on_both_families() {
    // Ubuntu publishes every security update to both -updates and -security, and
    // apt lists both origins. Taking the first would report a security fix as an
    // ordinary update on every Ubuntu host there is.
    let line = "Inst perl-base [5.38.2-3.2ubuntu0.4] (5.38.2-3.2ubuntu0.6 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [arm64])";
    let updates = parse_updates(line);
    assert_eq!(updates[0].repo.as_deref(), Some("noble-security"));

    // Debian spells it differently — origin `Debian-Security`, archive
    // `oldstable-security` — which is why the rule is on the archive suffix
    // rather than on the origin or the label.
    let line = "Inst libssl3 [3.0.20-1~deb12u1] (3.0.20-1~deb12u2 Debian:12.15/oldstable, Debian-Security:12/oldstable-security [arm64])";
    let updates = parse_updates(line);
    assert_eq!(updates[0].repo.as_deref(), Some("oldstable-security"));

    // And an ordinary update keeps its own pocket.
    let line = "Inst libapt-pkg6.0 [2.0.10] (2.0.11 Ubuntu:20.04/focal-updates [arm64])";
    let updates = parse_updates(line);
    assert_eq!(updates[0].repo.as_deref(), Some("focal-updates"));
}

#[test]
fn security_archives_are_recognised_across_families() {
    for archive in [
        "noble-security",
        "oldstable-security",
        "bookworm-security",
        "security",
    ] {
        assert!(is_security_archive(archive), "{archive} not recognised");
    }
    for archive in ["noble-updates", "noble", "stable", "noble-backports", ""] {
        assert!(
            !is_security_archive(archive),
            "{archive} wrongly recognised"
        );
    }
}

#[test]
fn a_foreign_architecture_package_keeps_one_name() {
    // apt names these `libc6:armhf` and dpkg-query names them `libc6` with the
    // architecture in its own field. If they disagree, the server sees two
    // packages and an update that never matches an installed version.
    let line =
        "Inst libgcc-s1:armhf (14.2.0-4ubuntu2~24.04.1 Ubuntu:24.04/noble-updates [armhf]) []";
    assert!(
        parse_updates(line).is_empty(),
        "a new install was reported as an update"
    );

    let line = "Inst libc6:armhf [2.39-0ubuntu8.8] (2.39-0ubuntu8.9 Ubuntu:24.04/noble-updates [armhf]) []";
    let updates = parse_updates(line);
    assert_eq!(updates.len(), 1);
    assert_eq!(
        updates[0].name, "libc6",
        "the architecture stayed in the name"
    );
    // The trailing `[]` marks a dependency pull-in and must not be mistaken for
    // the architecture group.
    assert_eq!(updates[0].arch, "armhf");
}

#[test]
fn held_packages_do_not_appear_as_available_updates() {
    // apt keeps a held package back, so its upgrade simply stops being offered.
    // The fixture captures a dist-upgrade taken after holding the first
    // upgradable package, so this is apt's real behaviour rather than an
    // assumption about it.
    for distro in ["ubuntu2004", "ubuntu2204", "ubuntu2404"] {
        let f = fixture(distro);
        let holds = parse_holds(&section(&f, "HOLDS"));
        let after = parse_updates(&section(&f, "DIST_UPGRADE_WITH_HOLDS"));
        for held in &holds {
            assert!(
                !after.iter().any(|u| &u.name == held),
                "{distro}: {held} is held but still offered as an update"
            );
        }
    }
}

#[test]
fn noise_and_prose_around_the_inst_lines_is_ignored() {
    // apt prints several paragraphs of prose, and `Conf` lines that mirror every
    // `Inst`. Counting a Conf line would double every update.
    let out = "\
Reading package lists...
Building dependency tree...
The following packages will be upgraded:
  perl-base
1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst perl-base [5.38.2-3.2ubuntu0.4] (5.38.2-3.2ubuntu0.6 Ubuntu:24.04/noble-updates [arm64])
Conf perl-base (5.38.2-3.2ubuntu0.6 Ubuntu:24.04/noble-updates [arm64])
Remv obsolete-thing [1.0]
";
    let updates = parse_updates(out);
    assert_eq!(
        updates.len(),
        1,
        "expected exactly one update, got {updates:?}"
    );
    assert_eq!(updates[0].name, "perl-base");
}

/* ------------------------------------------------------------ repositories */

#[test]
fn every_distribution_reports_its_repositories() {
    for (distro, origin) in DISTROS {
        let f = fixture(distro);
        let repos = parse_repositories(&section(&f, "POLICY"), Some(origin));

        assert!(!repos.is_empty(), "{distro}: no repositories parsed");
        for r in &repos {
            assert!(!r.id.is_empty(), "{distro}: repository with no id");
            assert_eq!(r.kind, "deb");
            // Everything in a stock image comes from the distribution itself.
            assert!(
                !r.third_party,
                "{distro}: {} read as third-party in a stock image",
                r.id
            );
        }

        // The local dpkg status file is `a=now`, and is not a repository.
        assert!(
            !repos.iter().any(|r| r.id == "now"),
            "{distro}: the dpkg status file was reported as a repository"
        );
    }
}

#[test]
fn a_repository_that_is_not_the_distributions_is_third_party() {
    // These are the ones that break a dist-upgrade, because they have no
    // packages for the target release.
    let policy = "\
Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 https://download.docker.com/linux/ubuntu noble/stable arm64 Packages
     release o=Docker,a=noble,l=Docker CE,c=stable,b=arm64
     origin download.docker.com
 500 http://ports.ubuntu.com/ubuntu-ports noble/main arm64 Packages
     release v=24.04,o=Ubuntu,a=noble,n=noble,l=Ubuntu,c=main,b=arm64
     origin ports.ubuntu.com
";
    let repos = parse_repositories(policy, Some("Ubuntu"));
    let docker = repos
        .iter()
        .find(|r| r.id == "noble/stable")
        .expect("docker repo");
    assert!(
        docker.third_party,
        "a Docker repository read as Ubuntu's own"
    );
    let ubuntu = repos
        .iter()
        .find(|r| r.id == "noble/main")
        .expect("ubuntu repo");
    assert!(
        !ubuntu.third_party,
        "Ubuntu's own repository read as third-party"
    );
}

#[test]
fn an_unknown_distribution_treats_everything_as_third_party() {
    // Failing this direction is the safe one: a third-party repository is
    // reported and looked at, where a missed one silently breaks a dist-upgrade.
    let policy = "\
 500 http://example.test/ stable/main arm64 Packages
     release o=Ubuntu,a=stable,c=main,b=arm64
";
    let repos = parse_repositories(policy, None);
    assert!(repos[0].third_party);
}

#[test]
fn a_repository_with_no_origin_is_third_party() {
    // An unsigned or hand-rolled repository often has no origin at all, and those
    // are exactly the ones worth knowing about. Unknown provenance is not the
    // distribution's.
    let policy = " 500 http://example.test/ ./ Packages\n     release a=unstable,c=main\n";
    let repos = parse_repositories(policy, Some("Debian"));
    assert_eq!(repos.len(), 1);
    assert!(repos[0].third_party);
}

#[test]
fn debian_security_is_debians_own_repository() {
    // Debian publishes security under origin `Debian` with label
    // `Debian-Security`. Reading the label instead of the origin would mark every
    // Debian host's security repository as third-party — and a third-party
    // security repo is the sort of finding that gets acted on.
    let policy = "     release v=12,o=Debian,a=oldstable-security,n=bookworm-security,l=Debian-Security,c=main,b=arm64\n";
    let repos = parse_repositories(policy, Some("Debian"));
    assert_eq!(repos.len(), 1);
    assert!(
        !repos[0].third_party,
        "Debian's own security archive read as third-party"
    );
    assert!(is_security_archive("oldstable-security"));
}

#[test]
fn the_same_repository_is_not_reported_twice() {
    let policy = "\
     release v=24.04,o=Ubuntu,a=noble,c=main,b=arm64
     release v=24.04,o=Ubuntu,a=noble,c=main,b=arm64
";
    assert_eq!(parse_repositories(policy, Some("Ubuntu")).len(), 1);
}

/* -------------------------------------------------------- holds and origin */

#[test]
fn every_distribution_reports_its_holds() {
    for (distro, _) in DISTROS {
        let f = fixture(distro);
        let holds = parse_holds(&section(&f, "HOLDS"));
        // The capture holds perl-base on every image.
        assert!(
            holds.iter().any(|h| h == "perl-base"),
            "{distro}: the held package is missing, got {holds:?}"
        );
    }
}

#[test]
fn no_holds_is_an_empty_list_rather_than_a_blank_entry() {
    assert!(parse_holds("").is_empty());
    assert!(parse_holds("\n\n").is_empty());
    assert_eq!(
        parse_holds("a\n\nb\n"),
        vec!["a".to_string(), "b".to_string()]
    );
}

#[test]
fn the_distribution_origin_comes_from_os_release() {
    assert_eq!(
        distro_origin("ID=ubuntu\nVERSION_ID=\"24.04\"\n").as_deref(),
        Some("Ubuntu")
    );
    assert_eq!(distro_origin("ID=debian\n").as_deref(), Some("Debian"));
    // Quoted, as some distributions write it.
    assert_eq!(
        distro_origin("ID=\"raspbian\"\n").as_deref(),
        Some("Raspbian")
    );
    // And nothing usable yields nothing, so everything reads as third-party.
    assert_eq!(distro_origin(""), None);
    assert_eq!(distro_origin("NAME=Whatever\n"), None);
    assert_eq!(distro_origin("ID=\n"), None);
}

#[test]
fn os_release_id_is_not_confused_with_id_like() {
    // `ID_LIKE=debian` on Ubuntu. Matching the wrong key would make Ubuntu's own
    // repositories read as Debian's and every one of them third-party.
    let os_release = "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID_LIKE=debian\nID=ubuntu\n";
    assert_eq!(distro_origin(os_release).as_deref(), Some("Ubuntu"));
}

/* ------------------------------------------- packages an upgrade removes */

#[test]
fn a_stock_upgrade_removes_nothing() {
    // The normal answer on every official image, and the reason the fixture
    // below had to be built: a removal is rare, and rare is exactly what gets
    // shipped untested.
    for (distro, _) in DISTROS {
        let f = fixture(distro);
        let installed = parse_installed(&section(&f, "DPKG_QUERY"));
        assert!(
            parse_removals(&section(&f, "DIST_UPGRADE"), &installed).is_empty(),
            "{distro} reported a removal"
        );
    }
}

#[test]
fn a_package_an_upgrade_would_remove_is_reported() {
    let f = fixture("debian12-removals");
    let installed = parse_installed(&section(&f, "DPKG_QUERY"));
    let removals = parse_removals(&section(&f, "DIST_UPGRADE"), &installed);

    assert_eq!(
        removals
            .iter()
            .map(|r| (r.name.as_str(), r.installed.as_str(), r.arch.as_str()))
            .collect::<Vec<_>>(),
        vec![("barpkg", "1.0", "all"), ("quxpkg", "1.0", "all")]
    );
}

#[test]
fn apt_never_says_what_replaced_the_package_it_removes() {
    // The fact that decided the wire shape. `Remv barpkg [1.0]` carries a name
    // and a version and nothing else — the `Inst foopkg` line that caused it is
    // in the same output with nothing linking the two. dnf names the obsoleting
    // package; apt does not, and inventing one here would be a lie with a name
    // and a version in it.
    let f = fixture("debian12-removals");
    let installed = parse_installed(&section(&f, "DPKG_QUERY"));
    for removal in parse_removals(&section(&f, "DIST_UPGRADE"), &installed) {
        assert!(removal.replaced_by.is_none(), "{}", removal.name);
    }
}

#[test]
fn the_package_causing_the_removal_is_still_an_ordinary_update() {
    let f = fixture("debian12-removals");
    let updates = parse_updates(&section(&f, "DIST_UPGRADE"));
    let foopkg = updates
        .iter()
        .find(|u| u.name == "foopkg")
        .expect("foopkg is the upgrade that removes the other two");
    assert_eq!(foopkg.installed, "1.0");
    assert_eq!(foopkg.candidate, "2.0");
    // And nothing it removed is reported as an update, which is the lie the
    // separate list exists to avoid.
    assert!(!updates.iter().any(|u| u.name == "barpkg"));
}

#[test]
fn a_removal_of_something_this_host_does_not_have_is_dropped() {
    // apt should never propose removing one, and an entry whose architecture
    // had to be invented would be indistinguishable from a real one downstream.
    assert!(parse_removals("Remv ghost [1.0]\n", &[]).is_empty());
}

#[test]
fn a_foreign_architecture_removal_keeps_one_name() {
    let installed = parse_installed("libc6\t2.36-9\tarmhf\tinstalled\n");
    let removals = parse_removals("Remv libc6:armhf [2.36-9]\n", &installed);
    assert_eq!(removals.len(), 1);
    assert_eq!(removals[0].name, "libc6");
    assert_eq!(removals[0].arch, "armhf");
}

/* ---------------------------------------------- applying exactly (DAWG-102) */

mod apply {
    use std::collections::BTreeMap;
    use updawg_backends::{
        BackendError, Pin,
        apt::{
            Ran, changes, check_simulation, install_args, parse_versions, simulate_args,
            still_to_do,
        },
    };

    fn pin(name: &str, from: &str, to: &str) -> Pin {
        Pin {
            name: name.into(),
            arch: "amd64".into(),
            from: from.into(),
            to: to.into(),
        }
    }

    fn installed(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(n, v)| (format!("{n}:amd64"), (*v).to_owned()))
            .collect()
    }

    #[track_caller]
    fn refused<T: std::fmt::Debug>(r: Result<T, BackendError>) -> String {
        match r {
            Err(BackendError::Refused(why)) => why,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_pin_at_its_from_is_to_do_and_one_at_its_to_is_done() {
        let pins = [
            pin("openssl", "3.5.1-1", "3.5.1-2"),
            pin("curl", "8.14-1", "8.14-2"),
        ];
        let todo = still_to_do(
            &pins,
            &installed(&[("openssl", "3.5.1-1"), ("curl", "8.14-2")]),
        )
        .unwrap();
        assert_eq!(
            todo.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["openssl"]
        );
    }

    /// ⚠️ The host moved since the approval — somebody upgraded by hand, or
    /// downgraded. Installing now would be a change nobody reviewed.
    #[test]
    fn a_pin_at_neither_end_is_refused() {
        let pins = [pin("openssl", "3.5.1-1", "3.5.1-2")];
        let why = refused(still_to_do(&pins, &installed(&[("openssl", "3.5.0-9")])));
        assert!(why.contains("3.5.0-9"), "{why}");
        let why = refused(still_to_do(&pins, &installed(&[])));
        assert!(why.contains("not installed"), "{why}");
    }

    #[test]
    fn the_command_line_names_exact_versions_and_keeps_local_config() {
        let pins = [pin("openssl", "3.5.1-1", "3.5.1-2")];
        let todo: Vec<&Pin> = pins.iter().collect();
        let args = install_args(&todo);
        assert_eq!(args[0], "install");
        assert!(
            args.contains(&"openssl:amd64=3.5.1-2".to_owned()),
            "{args:?}"
        );
        assert!(args.contains(&"--only-upgrade".to_owned()));
        assert!(args.contains(&"Dpkg::Options::=--force-confold".to_owned()));
        assert!(args.contains(&"DPkg::Lock::Timeout=600".to_owned()));
        assert_eq!(simulate_args(&todo)[1], "-s");
        // An architecture-independent package is named bare.
        let all = [Pin {
            arch: "all".into(),
            ..pin("tzdata", "2025a-1", "2025b-1")
        }];
        let todo: Vec<&Pin> = all.iter().collect();
        assert!(install_args(&todo).contains(&"tzdata=2025b-1".to_owned()));
    }

    fn sim(stdout: &str) -> Ran {
        Ran {
            code: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    #[test]
    fn a_simulation_doing_exactly_the_plan_passes() {
        let pins = [pin("openssl", "3.5.1-1", "3.5.1-2")];
        let todo: Vec<&Pin> = pins.iter().collect();
        let out = "Inst openssl [3.5.1-1] (3.5.1-2 Debian-Security:13/stable-security [amd64])\nConf openssl (3.5.1-2 Debian-Security:13/stable-security [amd64])\n";
        check_simulation(&todo, &sim(out)).unwrap();
    }

    /// Each of these is a change nobody approved, and refused before anything
    /// is touched.
    #[test]
    fn a_simulation_doing_anything_else_is_refused() {
        let pins = [pin("openssl", "3.5.1-1", "3.5.1-2")];
        let todo: Vec<&Pin> = pins.iter().collect();
        let ok = "Inst openssl [3.5.1-1] (3.5.1-2 Debian-Security:13/stable-security [amd64])\n";

        let why = refused(check_simulation(
            &todo,
            &sim(&format!("Remv libfoo [1.0]\n{ok}")),
        ));
        assert!(why.contains("remove libfoo"), "{why}");
        let why = refused(check_simulation(
            &todo,
            &sim(&format!("{ok}Inst libnew (2.0 Debian:13/stable [amd64])\n")),
        ));
        assert!(why.contains("also install libnew"), "{why}");
        let why = refused(check_simulation(
            &todo,
            &sim("Inst openssl [3.5.1-1] (3.5.1-3 Debian:13/stable [amd64])\n"),
        ));
        assert!(why.contains("3.5.1-3"), "{why}");
        let why = refused(check_simulation(&todo, &sim("")));
        assert!(why.contains("held"), "{why}");
        // The archive moved on and the approved version is gone.
        let gone = Ran {
            code: 100,
            stdout: String::new(),
            stderr: "E: Version '3.5.1-2' for 'openssl' was not found\n".into(),
        };
        let why = refused(check_simulation(&todo, &gone));
        assert!(why.contains("was not found"), "{why}");
    }

    #[test]
    fn changes_are_what_dpkg_says_and_a_pin_left_behind_is_a_failure() {
        let pins = [pin("openssl", "3.5.1-1", "3.5.1-2")];
        let todo: Vec<&Pin> = pins.iter().collect();
        let changed = changes(&todo, &installed(&[("openssl", "3.5.1-2")])).unwrap();
        assert_eq!(changed[0].to, "3.5.1-2");
        assert!(matches!(
            changes(&todo, &installed(&[("openssl", "3.5.1-1")])),
            Err(BackendError::CommandFailed { .. })
        ));
    }

    #[test]
    fn dpkg_query_output_is_keyed_like_the_command_line() {
        let out = "openssl:amd64\t3.5.1-2\tinstalled\ntzdata:all\t2025b-1\tinstalled\nold:amd64\t1.0\tconfig-files\n";
        let v = parse_versions(out);
        assert_eq!(v.get("openssl:amd64").map(String::as_str), Some("3.5.1-2"));
        assert_eq!(v.get("tzdata").map(String::as_str), Some("2025b-1"));
        assert!(!v.contains_key("old:amd64"));
    }
}

/* ----------------------------------------------------- output, as shown */

#[test]
fn a_line_redrawn_with_carriage_returns_is_logged_as_its_last_redraw() {
    // `apt-get install jq` in debian:13, stdout piped as the agent pipes it.
    // dpkg ends every line `\r\n` and redraws "Reading database" with bare
    // `\r`, which is what reached the log as one long line.
    let out = include_str!("fixtures/apt/debian13-install.txt");
    let shown: Vec<&str> = updawg_backends::apt::as_shown(out).collect();
    assert!(shown.iter().all(|l| !l.contains('\r')), "{shown:#?}");
    let database: Vec<&&str> = shown
        .iter()
        .filter(|l| l.contains("Reading database"))
        .collect();
    assert_eq!(
        database,
        [&"(Reading database ... 4948 files and directories currently installed.)"],
        "{shown:#?}"
    );
    assert!(
        shown.contains(&"Setting up jq (1.7.1-6+deb13u4) ..."),
        "{shown:#?}"
    );
}

#[test]
fn a_line_that_ends_in_a_carriage_return_keeps_what_came_before_it() {
    let shown: Vec<&str> = updawg_backends::apt::as_shown("Progress: [ 50%]\r\n").collect();
    assert_eq!(shown, ["Progress: [ 50%]"]);
}

/// DAWG-212: the source package's name and version, from `dpkg-query` on
/// Debian 13 (captured 2026-09-28). `bash` is a binNMU — its source version is
/// not its own — and `login` is built from `util-linux`, not `shadow`: neither
/// could be worked out from the binary.
#[test]
fn the_source_package_comes_with_its_own_version() {
    use updawg_protocol::SourcePackage;
    let out = "bash\t5.2.37-2+b10\tamd64\tinstalled\tbash\t5.2.37-2\n\
               login\t1:4.16.0-2+really2.41.5-0+deb13u1\tamd64\tinstalled\tutil-linux\t2.41.5-0+deb13u1\n\
               libc6\t2.41-12+deb13u4\tamd64\tinstalled\tglibc\t2.41-12+deb13u4\n\
               old\t1.0\tamd64\tinstalled\n";
    let packages = parse_installed(out);
    let source = |name: &str| {
        packages
            .iter()
            .find(|p| p.name == name)
            .unwrap()
            .source
            .clone()
    };
    assert_eq!(
        source("bash"),
        Some(SourcePackage {
            name: "bash".into(),
            version: "5.2.37-2".into()
        })
    );
    assert_eq!(source("login").unwrap().name, "util-linux");
    assert_eq!(source("libc6").unwrap().name, "glibc");
    // Output without the fields, as the fixtures were captured.
    assert_eq!(source("old"), None);
}
