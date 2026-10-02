//! The LVM parsers, against output captured from a real LVM (DAWG-118). See
//! `fixtures/lvm/README.md`, and `lvm_live.rs` for the round run for real.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    unreachable_pub
)]

use updawg_snapshots::{
    SnapshotError,
    lvm::{parse_deferred, parse_id, parse_ours, parse_pool_free, parse_volumes},
};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/lvm/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// The root is found by the device findmnt names, and must be thin.
#[test]
fn volumes_say_which_is_thin() {
    let volumes = parse_volumes(&fixture("lvs-all.json")).unwrap();
    let root = volumes
        .iter()
        .find(|v| v.dm_path == "/dev/mapper/testvg-root")
        .unwrap();
    assert_eq!((root.vg.as_str(), root.lv.as_str()), ("testvg", "root"));
    assert_eq!(root.segtype, "thin");
    let pool = volumes.iter().find(|v| v.lv == "pool").unwrap();
    assert_eq!(pool.segtype, "thin-pool");
}

#[test]
fn only_the_agents_own_snapshots_of_this_volume_are_listed() {
    let ours = parse_ours(&fixture("lvs-ours.json"), "root").unwrap();
    assert_eq!(ours.len(), 1, "{ours:?}");
    assert_eq!(ours[0].id, "lvm:testvg/updawg_job_x");
    assert_eq!(ours[0].job, "job_x");
    // Of another volume: not this one's.
    let home = parse_ours(&fixture("lvs-ours.json"), "home").unwrap();
    assert!(matches!(home.as_slice(), []), "{home:?}");
}

/// 1 GiB, 6.32% used.
#[test]
fn the_pools_free_space_is_its_size_less_what_is_used() {
    let free = parse_pool_free(&fixture("pool.json")).unwrap();
    let expected = 1_073_741_824.0 * (100.0 - 6.32) / 100.0;
    #[allow(clippy::cast_precision_loss)]
    let got = free as f64;
    assert!((got - expected).abs() < 2.0, "{free}");
}

/// A mounted root cannot merge now; LVM says it will at the next boot.
#[test]
fn a_merge_into_a_mounted_volume_is_put_off_to_its_next_activation() {
    assert!(parse_deferred(&fixture("merge-deferred.txt")));
    assert!(!parse_deferred(
        "  Merged snapshot testvg/updawg_job_x into testvg/root.\n"
    ));
}

#[test]
fn an_id_is_a_volume_group_and_one_of_our_snapshot_names() {
    assert_eq!(
        parse_id("lvm:rhel/updawg_job_x").unwrap(),
        ("rhel", "updawg_job_x")
    );
    for foreign in [
        "lvm:rhel/root",
        "lvm:/updawg_job_x",
        "lvm:rhel/sub/updawg_job_x",
        "zfs:rpool/ROOT/x@updawg-job_x",
    ] {
        assert!(
            matches!(parse_id(foreign), Err(SnapshotError::ForeignId { .. })),
            "{foreign}"
        );
    }
}
