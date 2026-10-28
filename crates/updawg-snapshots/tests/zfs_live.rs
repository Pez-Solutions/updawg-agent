//! The ZFS provider against a real `OpenZFS`.
//!
//! Ignored by default: it needs root, ZFS, and a writable dataset other than
//! the one mounted at `/`. On a scratch host:
//!
//! ```text
//! truncate -s 1G /var/tmp/z.img && zpool create -m none tank /var/tmp/z.img
//! zfs create -o mountpoint=/srv/zroot tank/ROOT
//! zfs create -o mountpoint=/srv/zroot/sys tank/ROOT/test
//! zfs create tank/ROOT/test/var && zfs create tank/ROOT/test/var/lib
//! UPDAWG_ZFS_DATASET=tank/ROOT/test \
//!   cargo test -p updawg-snapshots --test zfs_live -- --ignored --nocapture
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    unreachable_pub
)]

use std::path::PathBuf;
use updawg_snapshots::{SnapshotError, SnapshotProvider, zfs::Zfs};

fn mountpoint(dataset: &str) -> PathBuf {
    let out = std::process::Command::new("zfs")
        .args(["get", "-H", "-o", "value", "mountpoint", dataset])
        .output()
        .unwrap();
    PathBuf::from(String::from_utf8(out.stdout).unwrap().trim())
}

#[tokio::test]
#[ignore = "needs root, ZFS and a scratch dataset"]
async fn take_change_roll_back_and_prune_across_child_datasets() {
    let dataset = std::env::var("UPDAWG_ZFS_DATASET").expect("UPDAWG_ZFS_DATASET");
    assert!(
        mountpoint(&dataset) != std::path::Path::new("/"),
        "never the real root"
    );
    let zfs = Zfs::with_dataset(&dataset);
    zfs.available().await.unwrap();
    zfs.prune(0).await.unwrap();
    assert!(zfs.free_bytes().await.unwrap() > 1024 * 1024);

    let root = mountpoint(&dataset);
    let child = mountpoint(&format!("{dataset}/var/lib"));
    std::fs::create_dir_all(root.join("usr/lib/modules/6.8.0-1")).unwrap();
    std::fs::write(child.join("openssl.version"), "3.5.1-1\n").unwrap();
    let before = zfs.create("before job_live_1", "job_live_1").await.unwrap();

    // simulate an install: a file in a child dataset, and a new kernel
    std::fs::write(child.join("openssl.version"), "3.5.1-2\n").unwrap();
    std::fs::create_dir_all(root.join("usr/lib/modules/6.8.0-2")).unwrap();

    // a newer admin snapshot; `zfs rollback -r` will destroy it
    let admin = std::process::Command::new("zfs")
        .args(["snapshot", &format!("{dataset}@admins-own")])
        .status()
        .unwrap();
    assert!(admin.success());
    assert_eq!(zfs.list().await.unwrap().len(), 1);

    assert_eq!(
        zfs.kernels_rolled_away(&before.id).await.unwrap(),
        vec!["6.8.0-2".to_owned()]
    );
    let restored = zfs.rollback(&before.id).await.unwrap();
    println!("restored: {restored}");
    assert_eq!(
        std::fs::read_to_string(child.join("openssl.version")).unwrap(),
        "3.5.1-1\n",
        "the child dataset went back too"
    );
    assert!(!root.join("usr/lib/modules/6.8.0-2").exists());

    assert!(matches!(
        zfs.rollback(&format!("zfs:{dataset}@updawg-job_nobody"))
            .await,
        Err(SnapshotError::NotFound { .. })
    ));

    for n in 2..=4 {
        zfs.create(&format!("before job_live_{n}"), &format!("job_live_{n}"))
            .await
            .unwrap();
    }
    let pruned = zfs.prune(2).await.unwrap();
    assert_eq!(pruned.len(), 2, "{pruned:?}");
    let left: Vec<String> = zfs
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.job)
        .collect();
    assert_eq!(left, ["job_live_3", "job_live_4"]);
    zfs.prune(0).await.unwrap();
}
