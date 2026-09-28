//! The snapper parsers, against output captured from a real snapper
//! (DAWG-116). See `fixtures/snapper/README.md` for where each came from, and
//! `snapper_live.rs` for the same commands run for real.

// The whole file is the test: a panic is the assertion.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    unreachable_pub
)]

use updawg_snapshots::{
    Restored, SnapshotError,
    snapper::{
        parse_configs, parse_df, parse_id, parse_list, parse_number, parse_status_kernels,
        parse_undo,
    },
};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/snapper/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn configurations_and_their_subvolumes() {
    assert_eq!(
        parse_configs(&fixture("list-configs.json")).unwrap(),
        vec![("data".to_owned(), "/srv/bt".to_owned())]
    );
}

/// Snapper's number 0 is the live filesystem, and number 2 is an
/// administrator's: neither is the agent's to restore or prune.
#[test]
fn only_the_agents_own_snapshots_are_listed() {
    let ours = parse_list(&fixture("list.json")).unwrap();
    assert_eq!(ours.len(), 1, "{ours:?}");
    assert_eq!(ours[0].id, "snapper:1:job_x");
    assert_eq!(ours[0].job, "job_x");
    // A comma in a description is why this is JSON and not CSV.
    assert_eq!(ours[0].description, "updawg job_x before, with, commas");
    assert_eq!(ours[0].created, "2026-09-28 13:46:27");
}

#[test]
fn they_are_listed_oldest_first_whatever_order_snapper_prints() {
    let mut value: serde_json::Value = serde_json::from_str(&fixture("list.json")).unwrap();
    let entries = value["data"].as_array_mut().unwrap();
    let mut newer = entries[1].clone();
    newer["number"] = 7.into();
    newer["userdata"]["updawg"] = "job_y".into();
    entries.insert(0, newer);
    let ours = parse_list(&value.to_string()).unwrap();
    let ids: Vec<_> = ours.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, ["snapper:1:job_x", "snapper:7:job_y"]);
}

/// `df -P /srv/bt` on the same host.
#[test]
fn free_space_is_df_s_available_column() {
    assert_eq!(
        parse_df(&fixture("df.txt")),
        Some(1_870_080 * 1024),
        "{}",
        fixture("df.txt")
    );
    assert_eq!(parse_df(""), None);
}

#[test]
fn create_prints_the_number() {
    assert_eq!(parse_number(&fixture("create.txt")).unwrap(), 1);
    assert!(matches!(
        parse_number("Creating snapshot failed."),
        Err(SnapshotError::Unparseable { .. })
    ));
}

#[test]
fn undochange_says_what_it_put_back() {
    assert_eq!(
        parse_undo(&fixture("undochange.txt")).unwrap(),
        Restored {
            created: 0,
            modified: 1,
            deleted: 1,
            ..Restored::default()
        }
    );
    assert_eq!(
        parse_undo(&fixture("undochange-nothing.txt")).unwrap(),
        Restored::default()
    );
    assert!(parse_undo("").is_err());
}

/// The number alone is not an identity, because snapper reuses them: the id
/// has to carry the job, and anything else is somebody else's id.
#[test]
fn an_id_is_the_number_and_the_job() {
    assert_eq!(parse_id("snapper:412:job_abc").unwrap(), (412, "job_abc"));
    for foreign in [
        "snapper:412",
        "snapper:0:job_abc",
        "snapper::job_abc",
        "snapper:412:",
        "zfs:rpool/ROOT@x",
        "412",
    ] {
        assert!(
            matches!(parse_id(foreign), Err(SnapshotError::ForeignId { .. })),
            "{foreign}"
        );
    }
}

/// A kernel installed since the snapshot is what a rollback would take away:
/// only its module directory counts, not what is inside it.
#[test]
fn a_kernel_installed_since_the_snapshot_is_found_by_its_modules_directory() {
    assert_eq!(
        parse_status_kernels(&fixture("status-kernel.txt"), "/srv/bt5"),
        vec!["6.8.0-2".to_owned()]
    );
    // On a real root the subvolume is `/`.
    assert_eq!(
        parse_status_kernels("+..... /lib/modules/6.12.48+deb13-amd64\n", "/"),
        vec!["6.12.48+deb13-amd64".to_owned()]
    );
    // Removed since, and so put back by a rollback: harmless.
    assert!(parse_status_kernels("-..... /usr/lib/modules/6.8.0-1\n", "/").is_empty());
}

#[test]
fn only_a_modules_directory_itself_names_a_kernel() {
    use updawg_snapshots::kernel_dir;
    assert_eq!(
        kernel_dir("/usr/lib/modules/6.8.0-2"),
        Some("6.8.0-2".into())
    );
    assert_eq!(kernel_dir("lib/modules/6.8.0-2/"), Some("6.8.0-2".into()));
    assert_eq!(kernel_dir("/usr/lib/modules/6.8.0-2/kernel"), None);
    assert_eq!(kernel_dir("/usr/lib/modules"), None);
    assert_eq!(kernel_dir("/opt/lib/modules/x"), None);
}
