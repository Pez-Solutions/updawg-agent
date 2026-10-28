//! Durable local state under `/var/lib/updawg`.
//!
//! The main things kept here:
//!
//! - Identity: host id, certificate, and the organization signing keys pinned
//!   at enrollment. Losing it means re-enrolling.
//! - Seen job ids, for replay protection across restarts and reboots.
//! - Pending reboot context. A job that reboots the machine can't report its
//!   result before it goes down, so the agent records it and reports after
//!   boot.
//!
//! Writes go to a temp file that is renamed into place. A truncated identity
//! file after a power loss would stop the agent from starting at all.

use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use updawg_protocol::{HostId, JobId, OrgSigningKey};

/// The file `updawgctl renew` leaves for `updawgd`.
const RENEWAL_REQUEST: &str = "renew-requested";

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
    /// Keys pinned at enrollment. Jobs are verified against these.
    pub org_signing_keys: Vec<OrgSigningKey>,
    pub enrolled_at: String,
}

/// What the agent was doing when it rebooted, so it can finish the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingReboot {
    /// The job as signed.
    pub job: updawg_protocol::Job,
    /// The report so far: changes, pre-reboot checks, start time.
    pub report: updawg_protocol::JobComplete,
    /// `/proc/sys/kernel/random/boot_id` when the reboot was requested. A
    /// different value afterwards means the reboot happened.
    pub boot_id_before: String,
}

/// A release upgrade that completes during the reboot (leapp), and what to
/// check once the host is back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseCheck {
    pub job: JobId,
    /// The major release the host should be on now (`9`).
    pub release: String,
    /// Installed packages before the upgrade, for the change report.
    pub before: Vec<updawg_protocol::InstalledPackage>,
}

/// A self-update in progress, and the helper's result.
const SELF_UPDATE: &str = "self-update.json";
const SELF_UPDATE_OUTCOME: &str = "self-update-outcome.json";

/// Bounded so the file doesn't grow forever on a long-lived agent.
const SEEN_JOBS_CAPACITY: usize = 2048;

// Large enough that a busy host can't cycle through it and lose replay
// protection.
const _: () = assert!(SEEN_JOBS_CAPACITY >= 1024);

/// The inventory this host last uploaded, as it was sent.
///
/// Persisted so a restart doesn't look like an inventory change and the next
/// delta still has a base.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InventorySnapshot {
    /// Hash of `packages`; should match what the server has for this host.
    pub hash: String,
    pub packages: Vec<updawg_protocol::InstalledPackage>,
    /// Reported on every check-in without asking the package manager. See
    /// [`LocalState::inventory_snapshot`].
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

    pub fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.root).map_err(|source| StateError::CreateDir {
            path: self.root.display().to_string(),
            source,
        })?;
        // holds the identity and pinned keys
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

    /// Temp file, fsync, rename.
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

    /// Hash of the inventory this host last uploaded. Sent on every check-in
    /// so the server can ask for a fresh upload if they differ.
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

    /// What this host last uploaded, and the update counts taken with it.
    ///
    /// The package list is the base for the next delta upload. The counts are
    /// cached because every check-in (roughly once a minute) reports them, and
    /// computing them means something like `apt-get -s dist-upgrade`, which
    /// takes seconds and reads the whole package database.
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

    /// Called when the server rejects a delta. The next upload is then a full
    /// one instead of a retry of a delta that can't apply.
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

    /// Record what to check after the reboot that finishes a release
    /// upgrade.
    pub fn set_release_check(&self, check: &ReleaseCheck) -> Result<()> {
        let bytes = serde_json::to_vec(check).map_err(|source| StateError::Corrupt {
            path: "release-check.json".into(),
            source,
        })?;
        self.write_atomic("release-check.json", &bytes)
    }

    /// Read and clear it: it is checked once, after the reboot.
    pub fn take_release_check(&self) -> Result<Option<ReleaseCheck>> {
        let check: Option<ReleaseCheck> = self.read_json("release-check.json")?;
        if check.is_some() {
            let path = self.path("release-check.json");
            fs::remove_file(&path).map_err(|source| StateError::Write {
                path: path.display().to_string(),
                source,
            })?;
        }
        Ok(check)
    }

    /// Read and clear the pending reboot record, so it is reported once.
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

    /// The pending reboot, without clearing it. For `updawgctl status`.
    pub fn pending_reboot(&self) -> Result<Option<PendingReboot>> {
        self.read_json("pending-reboot.json")
    }

    /* ----------------------------------------------------- self-update */

    /// Record a self-update under way (see `crate::self_update`).
    pub fn set_self_update(&self, pending: &crate::self_update::Pending) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(pending).map_err(|source| StateError::Corrupt {
            path: SELF_UPDATE.into(),
            source,
        })?;
        self.write_atomic(SELF_UPDATE, &bytes)
    }

    /// The self-update under way, without taking it: the helper reads it, and
    /// an agent that finds the helper still running leaves it.
    pub fn self_update(&self) -> Result<Option<crate::self_update::Pending>> {
        self.read_json(SELF_UPDATE)
    }

    /// Read and clear it, with the helper's outcome if it wrote one. Used once
    /// the job is reported.
    pub fn take_self_update(
        &self,
    ) -> Result<
        Option<(
            crate::self_update::Pending,
            Option<crate::self_update::Outcome>,
        )>,
    > {
        let Some(pending) = self.self_update()? else {
            return Ok(None);
        };
        let outcome = self.read_json(SELF_UPDATE_OUTCOME)?;
        for name in [SELF_UPDATE, SELF_UPDATE_OUTCOME] {
            let path = self.path(name);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(StateError::Write {
                        path: path.display().to_string(),
                        source,
                    });
                }
            }
        }
        Ok(Some((pending, outcome)))
    }

    /// Written by the helper when the old agent ends up running afterwards.
    pub fn set_self_update_outcome(&self, outcome: &crate::self_update::Outcome) -> Result<()> {
        let bytes = serde_json::to_vec(outcome).map_err(|source| StateError::Corrupt {
            path: SELF_UPDATE_OUTCOME.into(),
            source,
        })?;
        self.write_atomic(SELF_UPDATE_OUTCOME, &bytes)
    }

    pub fn self_update_outcome(&self) -> Result<Option<crate::self_update::Outcome>> {
        self.read_json(SELF_UPDATE_OUTCOME)
    }

    /* ---------------------------------------------------- manual renewal */

    /// Asks the running agent to renew its certificate at the next check-in
    /// (`updawgctl renew`), e.g. after a key rotation.
    pub fn request_renewal(&self) -> Result<()> {
        self.write_atomic(RENEWAL_REQUEST, b"")
    }

    /// Whether a renewal was requested. Clears the request.
    #[must_use]
    pub fn take_renewal_request(&self) -> bool {
        fs::remove_file(self.root().join(RENEWAL_REQUEST)).is_ok()
    }

    /* --------------------------------------------- shown by updawgctl */

    /// How the last check-in went. Local only, for `updawgctl status`.
    pub fn last_checkin(&self) -> Result<Option<LastCheckin>> {
        self.read_json("last-checkin.json")
    }

    pub fn set_last_checkin(&self, last: &LastCheckin) -> Result<()> {
        let bytes = serde_json::to_vec(last).map_err(|source| StateError::Corrupt {
            path: "last-checkin.json".into(),
            source,
        })?;
        self.write_atomic("last-checkin.json", &bytes)
    }

    /// The jobs this host has seen lately, newest last.
    pub fn job_history(&self) -> Result<Vec<JobRecord>> {
        Ok(self.read_json("job-history.json")?.unwrap_or_default())
    }

    /// Records a job's latest status, replacing any earlier entry for it.
    /// Keeps at most [`JOB_HISTORY`] jobs.
    pub fn record_job_status(&self, record: &JobRecord) -> Result<()> {
        let mut history = self.job_history()?;
        history.retain(|r| r.id != record.id);
        history.push(record.clone());
        let excess = history.len().saturating_sub(JOB_HISTORY);
        history.drain(..excess);
        let bytes = serde_json::to_vec(&history).map_err(|source| StateError::Corrupt {
            path: "job-history.json".into(),
            source,
        })?;
        self.write_atomic("job-history.json", &bytes)
    }

    /* ------------------------------------------------ across a rollback */

    /// Reads the whole state directory into memory so it can be restored
    /// after a filesystem rollback.
    ///
    /// The rollback would otherwise revert this directory too, forgetting
    /// jobs run since the snapshot (including the install being rolled back,
    /// which could then be replayed) and keys pinned by a rotation since.
    pub fn carry(&self) -> Result<Carried> {
        let entries = fs::read_dir(&self.root).map_err(|source| StateError::Read {
            path: self.root.display().to_string(),
            source,
        })?;
        let mut files = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| StateError::Read {
                path: self.root.display().to_string(),
                source,
            })?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // skip temp files and directories
            if name.starts_with('.') || !entry.path().is_file() {
                continue;
            }
            let bytes = fs::read(entry.path()).map_err(|source| StateError::Read {
                path: entry.path().display().to_string(),
                source,
            })?;
            files.push((name, bytes));
        }
        Ok(Carried { files })
    }

    /// Restores what [`LocalState::carry`] read and removes anything else, such
    /// as an old `pending-reboot.json` the rollback brought back.
    pub fn put_back(&self, carried: &Carried) -> Result<()> {
        for (name, bytes) in &carried.files {
            self.write_atomic(name, bytes)?;
        }
        let entries = fs::read_dir(&self.root).map_err(|source| StateError::Read {
            path: self.root.display().to_string(),
            source,
        })?;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.path().is_file() && !carried.files.iter().any(|(n, _)| *n == name) {
                fs::remove_file(entry.path()).map_err(|source| StateError::Write {
                    path: entry.path().display().to_string(),
                    source,
                })?;
            }
        }
        Ok(())
    }
}

/// How many jobs [`LocalState::job_history`] keeps.
pub const JOB_HISTORY: usize = 50;

/// How the last check-in went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastCheckin {
    pub at: chrono::DateTime<chrono::Utc>,
    /// The gateway answered.
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Agent version. The self-update helper uses it to tell the new version
    /// is up. Missing in records from older agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
}

/// One job, as `updawgctl jobs` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    pub id: String,
    /// `apply_updates`, `reboot`, ...
    pub kind: String,
    /// `running`, `rebooting`, `succeeded`, `failed`, `refused`.
    pub status: String,
    pub at: chrono::DateTime<chrono::Utc>,
    /// Why it was refused or failed, or what it changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The state directory's files, as [`LocalState::carry`] found them.
#[derive(Clone)]
pub struct Carried {
    files: Vec<(String, Vec<u8>)>,
}

impl std::fmt::Debug for Carried {
    // Names only: the identity is in here.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.files.iter().map(|(n, _)| n))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // tests run in parallel in one process; the counter keeps dirs unique
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

    // Small capacity: each record is an fsync.
    #[test]
    fn seen_jobs_stay_bounded() {
        let (state, dir) = temp_state();
        for i in 0..12 {
            state
                .record_job_bounded(&JobId::new(format!("job_{i}")), 8)
                .unwrap();
        }
        assert!(!state.has_seen_job(&JobId::new("job_0")).unwrap());
        assert!(!state.has_seen_job(&JobId::new("job_3")).unwrap());
        assert!(state.has_seen_job(&JobId::new("job_11")).unwrap());
        assert!(state.has_seen_job(&JobId::new("job_4")).unwrap());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn what_was_carried_across_a_rollback_is_put_back_exactly() {
        let (state, dir) = temp_state();
        state.save_identity(&identity()).unwrap();
        state
            .record_job(&JobId::new("job_before_snapshot"))
            .unwrap();
        let at_snapshot = fs::read(dir.join("seen-jobs.json")).unwrap();

        state.record_job(&JobId::new("job_install")).unwrap();
        state.record_job(&JobId::new("job_rollback")).unwrap();
        let carried = state.carry().unwrap();
        assert!(!format!("{carried:?}").contains("BEGIN"), "{carried:?}");

        // simulate the rollback: old seen-jobs, and a file that existed at
        // snapshot time
        fs::write(dir.join("seen-jobs.json"), &at_snapshot).unwrap();
        fs::write(dir.join("pending-reboot.json"), b"{}").unwrap();

        state.put_back(&carried).unwrap();
        assert!(state.has_seen_job(&JobId::new("job_install")).unwrap());
        assert!(state.has_seen_job(&JobId::new("job_rollback")).unwrap());
        assert!(!dir.join("pending-reboot.json").exists());
        assert_eq!(
            state.identity().unwrap().unwrap().host_id.as_str(),
            "hst_webprod01"
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn the_job_history_keeps_the_newest_and_one_line_per_job() {
        let (state, dir) = temp_state();
        let at = chrono::Utc::now();
        let rec = |id: &str, status: &str| JobRecord {
            id: id.into(),
            kind: "apply_updates".into(),
            status: status.into(),
            at,
            detail: None,
        };
        state.record_job_status(&rec("job_a", "running")).unwrap();
        state.record_job_status(&rec("job_a", "succeeded")).unwrap();
        let history = state.job_history().unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, "succeeded");
        for i in 0..JOB_HISTORY + 5 {
            state
                .record_job_status(&rec(&format!("job_{i}"), "succeeded"))
                .unwrap();
        }
        let history = state.job_history().unwrap();
        assert_eq!(history.len(), JOB_HISTORY);
        assert_eq!(
            history.last().unwrap().id,
            format!("job_{}", JOB_HISTORY + 4)
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn reading_a_pending_reboot_for_status_leaves_it_pending() {
        let (state, dir) = temp_state();
        assert!(state.pending_reboot().unwrap().is_none());
        fs::write(dir.join("pending-reboot.json"), b"{ not json").unwrap();
        assert!(state.pending_reboot().is_err());
        assert!(dir.join("pending-reboot.json").exists());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_pending_reboot_is_reported_once_and_then_forgotten() {
        let (state, dir) = temp_state();
        state
            .set_pending_reboot(&PendingReboot {
                job: updawg_protocol::Job {
                    id: JobId::new("job_reboot"),
                    host_id: HostId::new("hst_a"),
                    spec: updawg_protocol::JobSpec::RefreshInventory,
                    not_before: None,
                    expires_at: chrono::Utc::now(),
                    key_id: updawg_protocol::SigningKeyId::new("sk_a"),
                    signature: String::new(),
                },
                report: updawg_protocol::JobComplete {
                    status: updawg_protocol::JobStatus::Succeeded,
                    started_at: chrono::Utc::now(),
                    finished_at: chrono::Utc::now(),
                    snapshot_id: None,
                    changes: vec![],
                    health_checks: vec![],
                    reboot_required: true,
                    inventory_hash: None,
                    error: None,
                    preflight: vec![],
                },
                boot_id_before: "b81e".into(),
            })
            .unwrap();

        let reopened = LocalState::new(&dir);
        let taken = reopened
            .take_pending_reboot()
            .unwrap()
            .expect("should survive the reboot");
        assert_eq!(taken.job.id.as_str(), "job_reboot");
        assert!(taken.report.reboot_required);
        assert_eq!(taken.boot_id_before, "b81e");
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
