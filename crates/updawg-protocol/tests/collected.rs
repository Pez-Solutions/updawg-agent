//! Everything the agent sends, field by field (DAWG-187).
//!
//! docs.updawg.net/agent/collected-data/ promises the whole list of what an
//! agent tells the service. This builds every message the agent sends with
//! every field filled in, collects the JSON paths, and compares them with
//! `collected-fields.txt`. The docs site vendors that file and fails its build
//! when the page doesn't describe a field in it, so a field added here reaches
//! the page or nothing ships.
//!
//! Struct literals, never `..Default::default()`: a field added to a message
//! doesn't compile here until somebody fills it in, and filled in it shows up
//! in the list.
//!
//! After changing a message, regenerate the file and read its diff:
//!
//! ```sh
//! UPDAWG_WRITE_COLLECTED=1 cargo test -p updawg-protocol --test collected
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    unreachable_pub
)]

use chrono::{DateTime, TimeZone, Utc};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use updawg_protocol::{
    AdvisoryHint, AgentInstall, AgentMode, AvailableUpdate, CertRenewRequest, CheckStatus,
    CheckinRequest, CloudFacts, Ecosystem, EnrollRequest, Frozen, FrozenKind, HealthCheckReport,
    HostFacts, HostMetrics, HostStateReport, InstallMethod, InstalledPackage, InventoryKind,
    InventoryUpload, JobAck, JobComplete, JobId, JobKind, JobStatus, LocalPolicy, LogLine,
    LogStream, PackageChange, PackageDelta, PendingRemoval, PreflightCheck, RebootRequired,
    RemovedPackage, Replacement, Repository, SnapshotSupport, SourcePackage, SystemFacts,
};

const FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/collected-fields.txt");

fn at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 3, 9, 0, 0).unwrap()
}

/// Every leaf under `value`, as `message.field.field`, with `[]` for a list.
fn walk(path: &str, value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                walk(&format!("{path}.{key}"), inner, out);
            }
        }
        Value::Array(items) => {
            let path = format!("{path}[]");
            assert!(
                !items.is_empty(),
                "{path} is empty in the fixture, which hides what its items carry"
            );
            for item in items {
                walk(&path, item, out);
            }
        }
        _ => {
            out.insert(path.to_owned());
        }
    }
}

fn fields(name: &str, message: &impl Serialize, out: &mut BTreeSet<String>) {
    walk(name, &serde_json::to_value(message).unwrap(), out);
}

fn enroll() -> EnrollRequest {
    EnrollRequest {
        token: "enr_x".into(),
        csr: "-----BEGIN CERTIFICATE REQUEST-----".into(),
        machine_id: "3f2a9c".into(),
        hostname: "web-03".into(),
        facts: HostFacts {
            distro: "ubuntu".into(),
            version: "24.04".into(),
            codename: Some("noble".into()),
            kernel: "6.8.0-45-generic".into(),
            arch: "x86_64".into(),
            virtualization: Some("kvm".into()),
            cloud: Some(CloudFacts {
                provider: "gcp".into(),
                instance_id: "1234".into(),
                region: "europe-west3".into(),
            }),
        },
        agent_version: "0.2.0".into(),
    }
}

fn checkin() -> CheckinRequest {
    CheckinRequest {
        boot_id: "b1".into(),
        uptime_s: 60,
        inventory_hash: "sha256:x".into(),
        state: HostStateReport {
            reboot_required: RebootRequired::Yes,
            services_need_restart: vec!["nginx".into()],
            pending_updates: 3,
            security_updates: 1,
            package_lock_held: false,
        },
        metrics: HostMetrics {
            load1: 0.5,
            mem_used_pct: 40.0,
            root_free_bytes: 1 << 30,
        },
        running_job_ids: vec![JobId::new("job_x")],
        max_hold_s: Some(60),
        local_policy: Some(LocalPolicy {
            mode: AgentMode::Managed,
            permitted_job_kinds: vec![JobKind::ApplyUpdates],
        }),
        snapshots: Some(SnapshotSupport {
            provider: Some("zfs".into()),
            reason: Some("why not".into()),
        }),
        agent_version: Some("0.2.0-20261003083653.gdd21454".into()),
        install: Some(AgentInstall {
            method: InstallMethod::Apt,
            channel: Some("stable".into()),
        }),
    }
}

fn source() -> SourcePackage {
    SourcePackage {
        name: "openssl".into(),
        version: "3.0.13-0ubuntu3".into(),
    }
}

fn inventory() -> InventoryUpload {
    InventoryUpload {
        kind: InventoryKind::Delta,
        base_hash: Some("sha256:a".into()),
        hash: "sha256:b".into(),
        collected_at: at(),
        facts: Some(SystemFacts {
            hostname: "web-03".into(),
            fqdn: Some("web-03.example.com".into()),
            machine_id: "3f2a9c".into(),
            distro: "ubuntu".into(),
            version_id: "24.04".into(),
            codename: Some("noble".into()),
            kernel: "6.8.0-45-generic".into(),
            arch: "x86_64".into(),
            virtualization: Some("kvm".into()),
            ecosystem: Ecosystem::Deb,
        }),
        packages: PackageDelta {
            added: vec![InstalledPackage {
                name: "libssl3t64".into(),
                version: "3.0.13-0ubuntu3".into(),
                arch: "amd64".into(),
                repo: Some("noble-updates".into()),
                source: Some(source()),
                module: Some("nodejs:20".into()),
            }],
            removed: vec![RemovedPackage {
                name: "libssl3".into(),
                version: "3.0.10".into(),
                arch: "amd64".into(),
            }],
        },
        updates: vec![AvailableUpdate {
            name: "libssl3t64".into(),
            arch: "amd64".into(),
            installed: "3.0.13-0ubuntu3".into(),
            candidate: "3.0.13-0ubuntu3.1".into(),
            repo: Some("noble-security".into()),
            advisories: vec![AdvisoryHint {
                id: "USN-7000-1".into(),
                severity: Some("high".into()),
                kind: "security".into(),
                fixed_in: Some("3.0.13-0ubuntu3.1".into()),
            }],
            source: Some(source()),
        }],
        repositories: vec![Repository {
            id: "noble-security".into(),
            kind: "deb".into(),
            third_party: true,
            enabled: true,
            url: Some("https://example.com/apt".into()),
        }],
        held_packages: vec!["postgresql-16".into()],
        removals: vec![PendingRemoval {
            name: "python3-old".into(),
            arch: "amd64".into(),
            installed: "1.0".into(),
            replaced_by: Some(Replacement {
                name: "python3-new".into(),
                arch: "amd64".into(),
                version: "2.0".into(),
                repo: Some("noble-updates".into()),
            }),
        }],
        frozen: Some(Frozen {
            kind: FrozenKind::Snapshot,
            pinned: "20240101T000000Z".into(),
            latest: Some("20240201T000000Z".into()),
        }),
        modules_reported: true,
    }
}

fn complete() -> JobComplete {
    JobComplete {
        status: JobStatus::Succeeded,
        started_at: at(),
        finished_at: at(),
        snapshot_id: Some("updawg-job_x".into()),
        changes: vec![PackageChange {
            name: "libssl3t64".into(),
            arch: "amd64".into(),
            from: "3.0.13-0ubuntu3".into(),
            to: "3.0.13-0ubuntu3.1".into(),
        }],
        health_checks: vec![HealthCheckReport {
            name: "nginx".into(),
            passed: true,
            duration_ms: 12,
            detail: Some("200".into()),
        }],
        reboot_required: false,
        inventory_hash: Some("sha256:c".into()),
        error: Some("none".into()),
        preflight: vec![PreflightCheck {
            name: "disk".into(),
            status: CheckStatus::Pass,
            summary: "enough room".into(),
            items: vec!["/".into()],
        }],
    }
}

fn everything() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    fields("enroll", &enroll(), &mut out);
    fields(
        "cert_renew",
        &CertRenewRequest {
            csr: "-----BEGIN CERTIFICATE REQUEST-----".into(),
            agent_version: "0.2.0".into(),
        },
        &mut out,
    );
    fields("checkin", &checkin(), &mut out);
    fields("inventory", &inventory(), &mut out);
    fields(
        "job_ack",
        &JobAck {
            accepted: false,
            rejection_reason: Some("not permitted".into()),
            at: at(),
        },
        &mut out,
    );
    fields("job_complete", &complete(), &mut out);
    fields(
        "job_log",
        &LogLine {
            at: at(),
            stream: LogStream::Stdout,
            line: "Reading package lists...".into(),
            seq: 1,
        },
        &mut out,
    );
    out
}

#[test]
fn the_published_list_is_every_field_the_agent_sends() {
    let actual: String = everything().into_iter().map(|f| f + "\n").collect();
    if std::env::var_os("UPDAWG_WRITE_COLLECTED").is_some() {
        std::fs::write(FILE, &actual).unwrap();
        return;
    }
    let published = std::fs::read_to_string(FILE).unwrap();
    assert!(
        published == actual,
        "collected-fields.txt is not what the agent sends. Regenerate it with\n\n    \
         UPDAWG_WRITE_COLLECTED=1 cargo test -p updawg-protocol --test collected\n\n\
         read the diff, and describe any new field on the docs site.\n\nWhat it sends:\n{actual}"
    );
}
