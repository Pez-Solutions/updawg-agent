//! The ZFS parsers, against captured output (see `fixtures/zfs/README.md`).
//! `zfs_live.rs` runs the same commands against a real `OpenZFS`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    unreachable_pub
)]

use updawg_snapshots::{
    Restored, SnapshotError,
    zfs::{parse_diff, parse_findmnt, parse_id, parse_list},
};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/zfs/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn the_root_dataset_is_what_findmnt_says_is_mounted() {
    assert_eq!(
        parse_findmnt(&fixture("findmnt.txt")),
        Some(("tank/ROOT/ubuntu".into(), "zfs".into()))
    );
    assert_eq!(parse_findmnt(""), None);
}

// the administrator's snapshot has `-` for the unset property
#[test]
fn only_the_agents_own_snapshots_are_listed() {
    let ours = parse_list(&fixture("list.txt"));
    assert_eq!(ours.len(), 1, "{ours:?}");
    assert_eq!(ours[0].id, "zfs:tank/ROOT/ubuntu@updawg-job_x");
    assert_eq!(ours[0].job, "job_x");
    assert_eq!(ours[0].created, "1790609289");
}

#[test]
fn a_diff_says_what_a_rollback_puts_back_and_which_kernels_it_takes() {
    let (root, kernels) = parse_diff(&fixture("diff-root.txt"), "/srv/zroot/sys");
    assert_eq!(
        root,
        Restored {
            created: 1,
            modified: 2,
            deleted: 2,
            ..Restored::default()
        }
    );
    assert_eq!(kernels, vec!["6.8.0-2".to_owned()]);
    let (varlib, kernels) = parse_diff(&fixture("diff-varlib.txt"), "/srv/zroot/sys");
    assert_eq!(varlib.modified, 1);
    assert!(kernels.is_empty());
    // on a real root the mountpoint is /
    let (_, kernels) = parse_diff("+\t/usr/lib/modules/6.8.0-2\n", "/");
    assert_eq!(kernels, vec!["6.8.0-2".to_owned()]);
}

#[test]
fn an_id_is_a_dataset_and_one_of_our_snapshot_names() {
    assert_eq!(
        parse_id("zfs:rpool/ROOT/debian@updawg-job_x").unwrap(),
        ("rpool/ROOT/debian", "updawg-job_x")
    );
    for foreign in [
        "zfs:rpool/ROOT/debian@admins-own",
        "zfs:@updawg-job_x",
        "zfs:rpool/ROOT/debian",
        "snapper:4:job_x",
    ] {
        assert!(
            matches!(parse_id(foreign), Err(SnapshotError::ForeignId { .. })),
            "{foreign}"
        );
    }
}
