//! The LVM provider against a real thin pool.
//!
//! Ignored by default: it needs root, LVM and a writable thin volume mounted
//! somewhere other than `/`. On a scratch host:
//!
//! ```text
//! truncate -s 2G /var/tmp/lv.img && LOOP=$(losetup --show -f /var/tmp/lv.img)
//! pvcreate $LOOP && vgcreate scratchvg $LOOP
//! lvcreate -L 1G -T scratchvg/pool && lvcreate -V 800M -T scratchvg/pool -n root
//! mkfs.xfs /dev/scratchvg/root && mkdir -p /srv/lvtest && mount /dev/scratchvg/root /srv/lvtest
//! UPDAWG_LVM_MOUNT=/srv/lvtest \
//!   cargo test -p updawg-snapshots --test lvm_live -- --ignored --nocapture
//! ```
//!
//! The merge is deferred while the volume is mounted, as it is for a real
//! root, so the test unmounts, deactivates, reactivates and remounts it to
//! simulate a boot.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    unreachable_pub
)]

use std::{path::PathBuf, process::Command};
use updawg_snapshots::{SnapshotProvider, lvm::Lvm};

fn sh(args: &[&str]) {
    let status = Command::new(args[0]).args(&args[1..]).status().unwrap();
    assert!(status.success(), "{args:?}");
}

#[tokio::test]
#[ignore = "needs root, LVM and a scratch thin volume"]
async fn take_change_roll_back_at_the_next_activation_and_prune() {
    let mount = PathBuf::from(std::env::var("UPDAWG_LVM_MOUNT").expect("UPDAWG_LVM_MOUNT"));
    assert_ne!(mount, PathBuf::from("/"), "never the real root");
    let lvm = Lvm::mounted_at(&mount).await.unwrap();
    lvm.available().await.unwrap();
    lvm.prune(0).await.unwrap();
    assert!(lvm.free_bytes().await.unwrap() > 1024 * 1024);

    let state = mount.join("var/lib/updawg");
    std::fs::create_dir_all(mount.join("usr/lib/modules/5.14.0-1")).unwrap();
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(mount.join("openssl.version"), "3.5.1-1\n").unwrap();
    std::fs::write(state.join("seen-jobs.json"), "before\n").unwrap();
    std::fs::write(state.join("pending-reboot.json"), "stale\n").unwrap();
    let before = lvm.create("before job_live_1", "job_live_1").await.unwrap();

    // simulate an install: a changed file, a new kernel, updated agent state
    std::fs::write(mount.join("openssl.version"), "3.5.1-2\n").unwrap();
    std::fs::create_dir_all(mount.join("usr/lib/modules/5.14.0-2")).unwrap();
    std::fs::write(state.join("seen-jobs.json"), "after\n").unwrap();
    std::fs::remove_file(state.join("pending-reboot.json")).unwrap();
    assert_eq!(lvm.list().await.unwrap().len(), 1);

    assert_eq!(
        lvm.kernels_rolled_away(&before.id).await.unwrap(),
        vec!["5.14.0-2".to_owned()]
    );
    lvm.carry_into(&before.id, &state).await.unwrap();
    let restored = lvm.rollback(&before.id).await.unwrap();
    println!("restored: {restored}");
    assert!(restored.at_next_boot, "a mounted volume merges later");
    // not merged yet
    assert_eq!(
        std::fs::read_to_string(mount.join("openssl.version")).unwrap(),
        "3.5.1-2\n"
    );

    // simulate a boot
    let lv = String::from_utf8(
        Command::new("findmnt")
            .args(["-n", "-o", "SOURCE"])
            .arg(&mount)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    sh(&["umount", mount.to_str().unwrap()]);
    sh(&["lvchange", "-an", &lv]);
    sh(&["lvchange", "-ay", &lv]);
    sh(&["mount", &lv, mount.to_str().unwrap()]);

    assert_eq!(
        std::fs::read_to_string(mount.join("openssl.version")).unwrap(),
        "3.5.1-1\n",
        "the volume went back"
    );
    assert!(!mount.join("usr/lib/modules/5.14.0-2").exists());
    assert_eq!(
        std::fs::read_to_string(state.join("seen-jobs.json")).unwrap(),
        "after\n",
        "the agent's state is what it was when the rollback was asked for"
    );
    assert!(!state.join("pending-reboot.json").exists());

    for n in 2..=4 {
        lvm.create(&format!("before job_live_{n}"), &format!("job_live_{n}"))
            .await
            .unwrap();
    }
    // the merged snapshot is gone, so three are left and keeping two prunes one
    let pruned = lvm.prune(2).await.unwrap();
    assert_eq!(pruned.len(), 1, "{pruned:?}");
    assert!(pruned[0].ends_with("/updawg_job_live_2"), "{pruned:?}");
    let left: Vec<String> = lvm
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.job)
        .collect();
    assert_eq!(left, ["job_live_3", "job_live_4"]);
    lvm.prune(0).await.unwrap();
}
