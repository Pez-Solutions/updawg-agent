//! The snapper provider against a real snapper on a real btrfs (DAWG-116).
//!
//! Ignored by default: it needs root, snapper, and a snapper configuration it
//! may write to, which must **not** be `root`. On a scratch host:
//!
//! ```text
//! truncate -s 2G /var/tmp/bt.img && mkfs.btrfs /var/tmp/bt.img
//! mkdir -p /srv/bt && mount -o loop /var/tmp/bt.img /srv/bt
//! snapper -c updawg-test create-config /srv/bt
//! UPDAWG_SNAPPER_CONFIG=updawg-test UPDAWG_SNAPPER_DIR=/srv/bt \
//!   cargo test -p updawg-snapshots --test snapper_live -- --ignored --nocapture
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    unreachable_pub
)]

use std::path::PathBuf;
use updawg_snapshots::{SnapshotError, SnapshotProvider, snapper::Snapper};

fn scratch() -> (Snapper, PathBuf) {
    let config = std::env::var("UPDAWG_SNAPPER_CONFIG").expect("UPDAWG_SNAPPER_CONFIG");
    assert_ne!(config, "root", "never the real root filesystem");
    let dir = std::env::var("UPDAWG_SNAPPER_DIR").expect("UPDAWG_SNAPPER_DIR");
    (Snapper::with_config(&config), PathBuf::from(dir))
}

#[tokio::test]
#[ignore = "needs root, snapper and a scratch btrfs configuration"]
async fn take_change_roll_back_and_prune() {
    let (snapper, dir) = scratch();
    snapper.available().await.unwrap();
    snapper.prune(0).await.unwrap();
    let free = snapper.free_bytes().await.unwrap();
    assert!(free > 1024 * 1024, "{free}");

    let file = dir.join("openssl.version");
    std::fs::write(&file, "3.5.1-1\n").unwrap();
    let before = snapper
        .create("before job_live_1", "job_live_1")
        .await
        .unwrap();
    assert!(before.id.ends_with(":job_live_1"), "{}", before.id);

    // The "install": one file changes, one appears.
    std::fs::write(&file, "3.5.1-2\n").unwrap();
    std::fs::write(dir.join("new.conf"), "x\n").unwrap();
    std::fs::create_dir_all(dir.join("usr/lib/modules/6.8.0-9/kernel")).unwrap();
    assert_eq!(
        snapper.kernels_rolled_away(&before.id).await.unwrap(),
        vec!["6.8.0-9".to_owned()]
    );

    // Somebody else's snapshot is neither listed nor pruned.
    let admin = std::process::Command::new("snapper")
        .args(["-c", &std::env::var("UPDAWG_SNAPPER_CONFIG").unwrap()])
        .args(["create", "--description", "an administrator's"])
        .status()
        .unwrap();
    assert!(admin.success());

    let listed = snapper.list().await.unwrap();
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(listed[0].id, before.id);

    let restored = snapper.rollback(&before.id).await.unwrap();
    println!("restored: {restored}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "3.5.1-1\n");
    assert!(!dir.join("new.conf").exists());
    assert!(!dir.join("usr/lib/modules/6.8.0-9").exists());
    assert_eq!(restored.modified, 1);

    // Again, with nothing to put back.
    let again = snapper.rollback(&before.id).await.unwrap();
    assert_eq!((again.created, again.modified, again.deleted), (0, 0, 0));

    // The same number with another job is not this snapshot.
    let (number, _) = updawg_snapshots::snapper::parse_id(&before.id).unwrap();
    let wrong = format!("snapper:{number}:job_somebody_else");
    assert!(matches!(
        snapper.rollback(&wrong).await,
        Err(SnapshotError::NotFound { .. })
    ));

    for n in 2..=4 {
        snapper
            .create(&format!("before job_live_{n}"), &format!("job_live_{n}"))
            .await
            .unwrap();
    }
    let pruned = snapper.prune(2).await.unwrap();
    assert_eq!(pruned.len(), 2, "{pruned:?}");
    assert!(pruned.contains(&before.id));
    let left: Vec<String> = snapper
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.job)
        .collect();
    assert_eq!(left, ["job_live_3", "job_live_4"]);
    snapper.prune(0).await.unwrap();
}
