//! Deciding what to upload (DAWG-36).
//!
//! The delta is the part worth testing hard. Getting it wrong does not fail
//! loudly — it leaves the server holding a package list that is subtly wrong and
//! stays wrong, and a fleet dashboard built on it looks exactly as convincing as
//! a correct one.

// clippy.toml allows unwrap and expect in `#[cfg(test)]` modules, but that does
// not reach an integration test in `tests/` — the whole file is the test. In here
// a panic *is* the assertion.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    unreachable_pub
)]

use updawg_agent_core::{inventory::Collected, state::InventorySnapshot};
use updawg_protocol::{
    AvailableUpdate, Ecosystem, InstalledPackage, InventoryKind, Repository, SystemFacts,
};

fn facts() -> SystemFacts {
    SystemFacts {
        hostname: "web-03".into(),
        fqdn: None,
        machine_id: "3f2a9c".into(),
        distro: "ubuntu".into(),
        version_id: "24.04".into(),
        codename: Some("noble".into()),
        kernel: "6.8.0-45-generic".into(),
        arch: "x86_64".into(),
        virtualization: None,
        ecosystem: Ecosystem::Deb,
    }
}

fn pkg(name: &str, version: &str) -> InstalledPackage {
    InstalledPackage {
        name: name.into(),
        version: version.into(),
        arch: "amd64".into(),
        repo: None,
        source: None,
    }
}

fn update(name: &str, repo: Option<&str>) -> AvailableUpdate {
    AvailableUpdate {
        name: name.into(),
        arch: "amd64".into(),
        installed: "1".into(),
        candidate: "2".into(),
        repo: repo.map(Into::into),
        advisories: vec![],
    }
}

fn collected(packages: Vec<InstalledPackage>) -> Collected {
    Collected {
        facts: facts(),
        packages,
        updates: vec![],
        removals: vec![],
        security: std::collections::BTreeSet::new(),
        repositories: vec![],
        held: vec![],
    }
}

fn snapshot(c: &Collected) -> InventorySnapshot {
    InventorySnapshot {
        hash: c.hash(),
        packages: c.packages.clone(),
        pending_updates: 0,
        security_updates: 0,
    }
}

/* -------------------------------------------------------------- the hash */

#[test]
fn the_hash_does_not_depend_on_the_order_packages_came_back_in() {
    // `dpkg-query` makes no promise about order. A hash that moved when the
    // order did would have every host in the fleet sending a full inventory at
    // random, for ever.
    let a = collected(vec![pkg("curl", "8.5.0"), pkg("jq", "1.7")]);
    let b = collected(vec![pkg("jq", "1.7"), pkg("curl", "8.5.0")]);
    assert_eq!(a.hash(), b.hash());
}

#[test]
fn the_hash_moves_when_a_version_moves() {
    assert_ne!(
        collected(vec![pkg("curl", "8.5.0")]).hash(),
        collected(vec![pkg("curl", "8.6.0")]).hash()
    );
}

#[test]
fn the_hash_distinguishes_architectures() {
    // Two architectures of one package at one version are two installed things,
    // and the server stores them as two rows.
    let mut armhf = pkg("libc6", "2.39");
    armhf.arch = "armhf".into();
    assert_ne!(
        collected(vec![pkg("libc6", "2.39")]).hash(),
        collected(vec![pkg("libc6", "2.39"), armhf]).hash()
    );
}

#[test]
fn the_hash_ignores_everything_except_packages() {
    // Updates and repositories are replaced wholesale on every upload. Folding
    // them into the hash would change it whenever a mirror published anything,
    // and every host would send a full inventory the next morning for nothing.
    let mut a = collected(vec![pkg("curl", "8.5.0")]);
    let b = collected(vec![pkg("curl", "8.5.0")]);
    a.updates = vec![update("curl", Some("noble-security"))];
    a.repositories = vec![Repository {
        id: "noble/main".into(),
        kind: "deb".into(),
        third_party: false,
        enabled: true,
        url: None,
    }];
    a.held = vec!["linux-image-generic".into()];
    assert_eq!(a.hash(), b.hash());
}

#[test]
fn the_hash_says_which_algorithm_made_it() {
    // The prefix is part of the value: it is what lets the algorithm change
    // later without the server having to guess what produced a given hash.
    assert!(collected(vec![]).hash().starts_with("sha256:"));
}

/* ------------------------------------------------------------ full upload */

#[test]
fn the_first_upload_is_full_and_carries_everything() {
    let c = collected(vec![pkg("curl", "8.5.0"), pkg("jq", "1.7")]);
    let upload = c.upload(None);

    assert_eq!(upload.kind, InventoryKind::Full);
    assert_eq!(upload.base_hash, None);
    assert_eq!(upload.packages.added.len(), 2);
    assert!(upload.packages.removed.is_empty());
    // The server rejects an incoherent upload outright, so this is the shape the
    // agent must never get wrong.
    assert!(upload.is_coherent());
}

/* ----------------------------------------------------------------- deltas */

#[test]
fn a_delta_names_the_hash_it_was_computed_against() {
    // This is the whole safety mechanism: the server checks it against what it
    // holds and refuses with 409 if they disagree.
    let before = collected(vec![pkg("curl", "8.5.0")]);
    let previous = snapshot(&before);
    let after = collected(vec![pkg("curl", "8.5.0"), pkg("jq", "1.7")]);

    let upload = after.upload(Some(&previous));
    assert_eq!(upload.kind, InventoryKind::Delta);
    assert_eq!(upload.base_hash.as_deref(), Some(previous.hash.as_str()));
    assert_eq!(upload.hash, after.hash());
    assert!(upload.is_coherent());
}

#[test]
fn an_upgrade_is_a_removal_and_an_addition() {
    // Which is exactly how the server stores it: (name, version, arch) rows, so
    // an upgrade replaces one row with another. A delta that only added the new
    // version would leave the host holding both, and the old one is the
    // vulnerable one.
    let before = collected(vec![pkg("openssl", "3.0.13-0ubuntu3.3")]);
    let previous = snapshot(&before);
    let after = collected(vec![pkg("openssl", "3.0.13-0ubuntu3.4")]);

    let upload = after.upload(Some(&previous));
    assert_eq!(upload.packages.added.len(), 1);
    assert_eq!(upload.packages.added[0].version, "3.0.13-0ubuntu3.4");
    assert_eq!(upload.packages.removed.len(), 1);
    assert_eq!(upload.packages.removed[0].version, "3.0.13-0ubuntu3.3");
}

#[test]
fn a_package_that_did_not_change_is_not_in_the_delta() {
    // The entire point. If untouched packages rode along, the delta would be the
    // full inventory with extra steps.
    let before = collected(vec![pkg("curl", "8.5.0"), pkg("jq", "1.7")]);
    let previous = snapshot(&before);
    let after = collected(vec![
        pkg("curl", "8.5.0"),
        pkg("jq", "1.7"),
        pkg("git", "2.43"),
    ]);

    let upload = after.upload(Some(&previous));
    assert_eq!(upload.packages.added.len(), 1);
    assert_eq!(upload.packages.added[0].name, "git");
    assert!(upload.packages.removed.is_empty());
}

#[test]
fn a_removal_is_reported_as_a_removal() {
    let before = collected(vec![pkg("curl", "8.5.0"), pkg("jq", "1.7")]);
    let previous = snapshot(&before);
    let after = collected(vec![pkg("curl", "8.5.0")]);

    let upload = after.upload(Some(&previous));
    assert!(upload.packages.added.is_empty());
    assert_eq!(upload.packages.removed.len(), 1);
    assert_eq!(upload.packages.removed[0].name, "jq");
}

#[test]
fn nothing_changing_produces_an_empty_delta_that_is_still_valid() {
    // A host that has not changed in six hours still uploads: the updates and
    // repositories are refreshed wholesale on every upload, and a mirror can
    // publish without the host changing at all. The package half is then empty,
    // which is correct and tiny.
    let before = collected(vec![pkg("curl", "8.5.0")]);
    let previous = snapshot(&before);
    let after = collected(vec![pkg("curl", "8.5.0")]);

    let upload = after.upload(Some(&previous));
    assert!(upload.packages.added.is_empty());
    assert!(upload.packages.removed.is_empty());
    assert_eq!(
        upload.hash, previous.hash,
        "an unchanged host changed its hash"
    );
    assert!(upload.is_coherent());
}

#[test]
fn a_delta_only_moves_the_architecture_that_changed() {
    // Both architectures of one package at one version. Upgrading one must not
    // report the other as removed — the server would delete a package that is
    // still installed and then propose reinstalling it.
    let mut armhf = pkg("libc6", "2.39");
    armhf.arch = "armhf".into();
    let before = collected(vec![pkg("libc6", "2.39"), armhf.clone()]);
    let previous = snapshot(&before);

    let upload = collected(vec![pkg("libc6", "2.40"), armhf]).upload(Some(&previous));

    assert_eq!(upload.packages.added.len(), 1);
    assert_eq!(upload.packages.added[0].arch, "amd64");
    assert_eq!(upload.packages.removed.len(), 1);
    assert_eq!(upload.packages.removed[0].arch, "amd64");
}

#[test]
fn facts_ride_on_every_upload_including_a_delta() {
    // A re-imaged host is the change that matters most and the one a package
    // delta describes worst — it would read as a few thousand removals and a few
    // thousand additions with no hint that the release moved.
    let before = collected(vec![pkg("curl", "8.5.0")]);
    let previous = snapshot(&before);
    let upload = collected(vec![pkg("curl", "8.5.0")]).upload(Some(&previous));
    assert!(upload.facts.is_some(), "a delta dropped the platform facts");
}

/* ----------------------------------------------------------------- counts */

#[test]
fn security_updates_are_counted_from_what_the_backend_named() {
    let mut c = collected(vec![]);
    c.updates = vec![
        update("openssl", Some("noble-security")),
        update("jq", Some("noble-updates")),
        update("mystery", None),
    ];
    // What `AptBackend::security_updates` would return for those three.
    c.security = ["openssl".to_string()].into_iter().collect();

    let (pending, security) = c.counts();
    assert_eq!(pending, 3);
    // An update the backend did not name is not counted as security. This is a
    // hint for the heartbeat; the authoritative answer is the server's, against
    // advisory data.
    assert_eq!(security, 1);
}

#[test]
fn an_advisory_for_something_not_upgradable_does_not_inflate_the_count() {
    // dnf's `updateinfo` lists an advisory per *version*, including ones between
    // the installed package and the candidate, and a backend that returned those
    // names without intersecting them could report more security updates than
    // there are updates. The count is over `updates`, so it cannot.
    let mut c = collected(vec![]);
    c.updates = vec![update("openssl", None)];
    c.security = ["openssl", "glibc", "curl"]
        .into_iter()
        .map(ToString::to_string)
        .collect();

    assert_eq!(c.counts(), (1, 1));
}

#[test]
fn a_host_with_nothing_to_do_counts_zero() {
    assert_eq!(collected(vec![pkg("curl", "8.5.0")]).counts(), (0, 0));
}
