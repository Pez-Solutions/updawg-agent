//! Durable local state under `/var/lib/updawg`.
//!
//! Three things have to survive a restart, and each for a different reason:
//!
//! - **Identity** — the host id, its certificate, and the organization signing
//!   keys pinned at enrollment. Lose this and the host has to re-enroll.
//! - **Seen job ids** — replay protection. A job must not execute twice, and
//!   "twice" includes "once before a reboot and once after".
//! - **Pending reboot context** — a job that reboots the machine cannot report
//!   its own result. The agent writes down what it was doing, reboots, and
//!   finishes reporting on the way back up.
//!
//! Every write goes to a temporary file and is renamed into place. A half-written
//! identity file on a host that lost power mid-write would be worse than no file
//! at all: the agent would refuse to start rather than simply re-enrolling.

use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use updawg_protocol::{HostId, JobId, OrgSigningKey};

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("could not create state directory {path}")]
    CreateDir {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("could not read {path}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("could not write {path}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is corrupt")]
    Corrupt {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

pub type Result<T> = std::result::Result<T, StateError>;

/// Who this host is, established at enrollment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub host_id: HostId,
    /// PEM client certificate.
    pub certificate: String,
    pub ca_chain: Vec<String>,
    /// Keys pinned at enrollment. Every job is verified against these, not
    /// against whatever the server currently claims.
    pub org_signing_keys: Vec<OrgSigningKey>,
    pub enrolled_at: String,
}

/// What the agent was doing when it rebooted, so it can finish the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingReboot {
    pub job_id: JobId,
    pub started_at: String,
    pub boot_id_before: String,
}

/// Replay protection. Bounded: an agent running for years must not accumulate
/// an unbounded file of job ids.
const SEEN_JOBS_CAPACITY: usize = 2048;

// Small enough to stay a cheap file, large enough that a busy host cannot cycle
// through it between reboots and quietly lose replay protection. Enforced at
// compile time rather than by a test, because it is a property of the constant.
const _: () = assert!(SEEN_JOBS_CAPACITY >= 1024);

/// The inventory this host last uploaded, as it was sent.
///
/// Persisted rather than held in memory: a restart must not look like an
/// inventory change, and it must not lose the base a delta is computed against.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InventorySnapshot {
    /// Hash of `packages`, and what the server holds against this host.
    pub hash: String,
    /// Exactly what was uploaded, so the next run can say what changed.
    pub packages: Vec<updawg_protocol::InstalledPackage>,
    /// Cheap counts, answered on every check-in without touching the package
    /// manager. See [`LocalState::inventory_snapshot`].
    #[serde(default)]
    pub pending_updates: u32,
    #[serde(default)]
    pub security_updates: u32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SeenJobs {
    ids: VecDeque<String>,
}

#[derive(Debug, Clone)]
pub struct LocalState {
    root: PathBuf,
}

impl LocalState {
    #[must_use]
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    /// Create the state directory if it does not exist.
    pub fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.root).map_err(|source| StateError::CreateDir {
            path: self.root.display().to_string(),
            source,
        })?;
        // The identity file and pinned keys live here. Other users on the host
        // have no business reading them.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// Write a file atomically: temp file, flush, fsync, rename.
    ///
    /// The rename is what makes it atomic. Without it a power loss mid-write
    /// leaves a truncated file that parses as neither valid nor absent.
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.ensure()?;
        let final_path = self.path(name);
        let tmp_path = self.path(&format!(".{name}.tmp"));

        let write = || -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp_path)?;
            f.write_all(bytes)?;
            f.flush()?;
            f.sync_all()?;
            Ok(())
        };
        write().map_err(|source| StateError::Write {
            path: tmp_path.display().to_string(),
            source,
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
        }

        fs::rename(&tmp_path, &final_path).map_err(|source| StateError::Write {
            path: final_path.display().to_string(),
            source,
        })
    }

    fn read_json<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let path = self.path(name);
        match fs::read(&path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes)
                    .map(Some)
                    .map_err(|source| StateError::Corrupt {
                        path: path.display().to_string(),
                        source,
                    })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(StateError::Read {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    /* ----------------------------------------------------------- identity */

    #[must_use]
    pub fn is_enrolled(&self) -> bool {
        self.path("identity.json").exists()
    }

    pub fn identity(&self) -> Result<Option<Identity>> {
        self.read_json("identity.json")
    }

    pub fn save_identity(&self, identity: &Identity) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(identity).map_err(|source| StateError::Corrupt {
            path: "identity.json".into(),
            source,
        })?;
        self.write_atomic("identity.json", &bytes)
    }

    /* -------------------------------------------------- inventory hash */

    /// Hash of the inventory this host last uploaded.
    ///
    /// Sent on every check-in so the server can notice the two have diverged
    /// and ask for a fresh one. Kept next to the identity rather than held in
    /// memory because a restart must not silently look like a change.
    pub fn inventory_hash(&self) -> Result<Option<String>> {
        self.read_json::<String>("inventory-hash.json")
    }

    pub fn set_inventory_hash(&self, hash: &str) -> Result<()> {
        let bytes = serde_json::to_vec(hash).map_err(|source| StateError::Corrupt {
            path: "inventory-hash.json".into(),
            source,
        })?;
        self.write_atomic("inventory-hash.json", &bytes)
    }

    /* ----------------------------------------------- inventory snapshot */

    /// What this host last uploaded, and the cheap counts taken with it.
    ///
    /// The package list is here because **a delta is meaningless without it**: to
    /// say what changed, the agent has to know what it said last time. The
    /// alternative is uploading everything every six hours, which is what the
    /// delta exists to avoid.
    ///
    /// The counts are here for a different reason. A check-in carries
    /// `pending_updates` and `security_updates` and runs every fifty-five
    /// seconds; asking the package manager for them means `apt-get -s
    /// dist-upgrade`, which takes seconds and reads the whole package database.
    /// Answering a heartbeat from the last collection is the difference between a
    /// heartbeat that costs nothing and one that hammers the host all day.
    pub fn inventory_snapshot(&self) -> Result<Option<InventorySnapshot>> {
        self.read_json::<InventorySnapshot>("inventory.json")
    }

    pub fn set_inventory_snapshot(&self, snapshot: &InventorySnapshot) -> Result<()> {
        let bytes = serde_json::to_vec(snapshot).map_err(|source| StateError::Corrupt {
            path: "inventory.json".into(),
            source,
        })?;
        self.write_atomic("inventory.json", &bytes)
    }

    /// Forget what we believe the server holds.
    ///
    /// Called when the server refuses a delta: the two disagree about the base,
    /// and the only way back into step is a full upload. Clearing this rather
    /// than retrying is what stops a host re-sending a delta that can never
    /// apply.
    pub fn clear_inventory_snapshot(&self) -> Result<()> {
        let path = self.root.join("inventory.json");
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(StateError::Write {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    /* --------------------------------------------------------- seen jobs */

    /// Whether this job has already been handled.
    pub fn has_seen_job(&self, id: &JobId) -> Result<bool> {
        let seen: SeenJobs = self.read_json("seen-jobs.json")?.unwrap_or_default();
        Ok(seen.ids.iter().any(|s| s == id.as_str()))
    }

    /// Record a job as handled. Oldest entries fall off once the list is full.
    pub fn record_job(&self, id: &JobId) -> Result<()> {
        self.record_job_bounded(id, SEEN_JOBS_CAPACITY)
    }

    fn record_job_bounded(&self, id: &JobId, capacity: usize) -> Result<()> {
        let mut seen: SeenJobs = self.read_json("seen-jobs.json")?.unwrap_or_default();
        if seen.ids.iter().any(|s| s == id.as_str()) {
            return Ok(());
        }
        seen.ids.push_back(id.as_str().to_string());
        while seen.ids.len() > capacity {
            seen.ids.pop_front();
        }
        let bytes = serde_json::to_vec(&seen).map_err(|source| StateError::Corrupt {
            path: "seen-jobs.json".into(),
            source,
        })?;
        self.write_atomic("seen-jobs.json", &bytes)
    }

    /* ---------------------------------------------------- pending reboot */

    pub fn set_pending_reboot(&self, pending: &PendingReboot) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(pending).map_err(|source| StateError::Corrupt {
            path: "pending-reboot.json".into(),
            source,
        })?;
        self.write_atomic("pending-reboot.json", &bytes)
    }

    /// Read and clear the pending reboot record.
    ///
    /// Taking rather than reading, because it must only be reported once.
    pub fn take_pending_reboot(&self) -> Result<Option<PendingReboot>> {
        let pending: Option<PendingReboot> = self.read_json("pending-reboot.json")?;
        if pending.is_some() {
            let path = self.path("pending-reboot.json");
            fs::remove_file(&path).map_err(|source| StateError::Write {
                path: path.display().to_string(),
                source,
            })?;
        }
        Ok(pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests run in parallel in one process, so a timestamp alone is not a
    /// unique directory name. The counter is what makes it one.
    static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn temp_state() -> (LocalState, PathBuf) {
        let n = NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("updawg-state-test-{}-{n}", std::process::id()));
        let state = LocalState::new(&dir);
        state.ensure().unwrap();
        (state, dir)
    }

    fn identity() -> Identity {
        Identity {
            host_id: HostId::new("hst_webprod01"),
            certificate: "-----BEGIN CERTIFICATE-----".into(),
            ca_chain: vec![],
            org_signing_keys: vec![],
            enrolled_at: "2026-09-19T00:00:00Z".into(),
        }
    }

    #[test]
    fn identity_survives_being_written_and_read_back() {
        let (state, dir) = temp_state();
        assert!(!state.is_enrolled());
        state.save_identity(&identity()).unwrap();
        assert!(state.is_enrolled());

        // A fresh handle, as though the process had restarted.
        let reopened = LocalState::new(&dir);
        let loaded = reopened
            .identity()
            .unwrap()
            .expect("identity should persist across a restart");
        assert_eq!(loaded.host_id.as_str(), "hst_webprod01");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn missing_state_reads_as_absent_rather_than_failing() {
        let (state, dir) = temp_state();
        assert!(state.identity().unwrap().is_none());
        assert!(state.take_pending_reboot().unwrap().is_none());
        assert!(!state.has_seen_job(&JobId::new("job_x")).unwrap());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_corrupt_file_is_reported_rather_than_silently_ignored() {
        let (state, dir) = temp_state();
        fs::write(dir.join("identity.json"), b"{ not json").unwrap();
        let err = state.identity().unwrap_err();
        assert!(matches!(err, StateError::Corrupt { .. }), "got {err:?}");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_job_is_only_seen_once_and_the_record_survives_a_restart() {
        let (state, dir) = temp_state();
        let id = JobId::new("job_01J9ZD");
        assert!(!state.has_seen_job(&id).unwrap());
        state.record_job(&id).unwrap();
        assert!(state.has_seen_job(&id).unwrap());

        let reopened = LocalState::new(&dir);
        assert!(
            reopened.has_seen_job(&id).unwrap(),
            "replay protection must survive a restart"
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn recording_the_same_job_twice_is_harmless() {
        let (state, dir) = temp_state();
        let id = JobId::new("job_dup");
        state.record_job(&id).unwrap();
        state.record_job(&id).unwrap();
        fs::remove_dir_all(dir).ok();
    }

    /// Tested against a small capacity rather than the real one: each record
    /// is an fsync, and proving the ring works does not need two thousand of
    /// them. The production capacity is asserted separately.
    #[test]
    fn seen_jobs_stay_bounded() {
        let (state, dir) = temp_state();
        for i in 0..12 {
            state
                .record_job_bounded(&JobId::new(format!("job_{i}")), 8)
                .unwrap();
        }
        // The oldest have fallen off; the newest are still there.
        assert!(!state.has_seen_job(&JobId::new("job_0")).unwrap());
        assert!(!state.has_seen_job(&JobId::new("job_3")).unwrap());
        assert!(state.has_seen_job(&JobId::new("job_11")).unwrap());
        assert!(state.has_seen_job(&JobId::new("job_4")).unwrap());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_pending_reboot_is_reported_once_and_then_forgotten() {
        let (state, dir) = temp_state();
        state
            .set_pending_reboot(&PendingReboot {
                job_id: JobId::new("job_reboot"),
                started_at: "2026-09-19T01:00:00Z".into(),
                boot_id_before: "b81e".into(),
            })
            .unwrap();

        let reopened = LocalState::new(&dir);
        let taken = reopened
            .take_pending_reboot()
            .unwrap()
            .expect("should survive the reboot");
        assert_eq!(taken.job_id.as_str(), "job_reboot");
        // Taken, not read: a second call finds nothing.
        assert!(reopened.take_pending_reboot().unwrap().is_none());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn the_inventory_hash_survives_a_restart() {
        let (state, dir) = temp_state();
        assert!(state.inventory_hash().unwrap().is_none());
        state.set_inventory_hash("sha256:9f86d0").unwrap();

        let reopened = LocalState::new(&dir);
        assert_eq!(
            reopened.inventory_hash().unwrap().as_deref(),
            Some("sha256:9f86d0"),
            "a restart must not look like the inventory changed"
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn writes_leave_no_temporary_files_behind() {
        let (state, dir) = temp_state();
        state.save_identity(&identity()).unwrap();
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "atomic write left a temp file behind");
        fs::remove_dir_all(dir).ok();
    }
}
