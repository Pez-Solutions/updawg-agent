//! LVM thin snapshots, for a root on a thin-provisioned logical volume.
//!
//! # Thin only
//!
//! A thin snapshot needs no space reserved up front. A classic (thick)
//! snapshot needs reserved space in the volume group and becomes invalid if an
//! install writes more than that. RHEL installs default to thick LVM, so most
//! RHEL hosts get no snapshots, and the host reports why.
//!
//! # Rollback happens at the next boot
//!
//! `lvconvert --merge` can't merge into a mounted root; LVM defers it to the
//! next activation, which for `/` is the next boot. The rollback job reports
//! that a reboot is needed, and nothing changes until then.
//!
//! After that boot `/` is the snapshot, including the agent's state
//! directory, so [`Lvm::carry_into`] first copies the current state into the
//! snapshot. Files written into a thin snapshot before a deferred merge do end
//! up on the origin after it (verified on a real host).
//!
//! # Ownership
//!
//! Snapshots are named `updawg_<job>` and tagged `updawg` and
//! `updawg_job_<job>`. Only those are listed, restored or pruned. LVM names
//! are unique within a volume group, so `lvm:<vg>/updawg_<job>` identifies
//! one snapshot.

use crate::{Provider, Restored, Result, Snapshot, SnapshotError, SnapshotProvider};
use async_trait::async_trait;
use std::path::{Path, PathBuf};

const MARK: &str = "updawg";

const MOUNT_AT: &str = "/run/updawg-snapshot";

/// Snapshots one thin volume.
#[derive(Debug, Clone)]
pub struct Lvm {
    vg: String,
    lv: String,
    mountpoint: PathBuf,
    /// XFS won't mount two filesystems with the same UUID, and a snapshot
    /// shares its origin's, so XFS needs `nouuid`.
    fstype: String,
}

impl Lvm {
    /// The thin volume mounted at `/`, or why there is none.
    ///
    /// # Errors
    /// `/` is not on LVM, or not on a thin volume, or the tools could not say.
    pub async fn root() -> std::result::Result<Self, String> {
        Self::mounted_at(Path::new("/")).await
    }

    /// The thin volume mounted at `mountpoint`.
    ///
    /// # Errors
    /// As [`Lvm::root`].
    pub async fn mounted_at(mountpoint: &Path) -> std::result::Result<Self, String> {
        let out = tokio::process::Command::new("findmnt")
            .args(["-n", "-o", "SOURCE,FSTYPE"])
            .arg(mountpoint)
            .env("LC_ALL", "C")
            .output()
            .await
            .map_err(|e| format!("findmnt: {e}"))?;
        let (source, fstype) = crate::zfs::parse_findmnt(&String::from_utf8_lossy(&out.stdout))
            .ok_or_else(|| format!("findmnt did not say what {} is", mountpoint.display()))?;
        if !source.starts_with("/dev/mapper/") {
            return Err(format!("{} is not on LVM", mountpoint.display()));
        }
        let lvs = run(&[
            "lvs",
            "--reportformat",
            "json",
            "-o",
            "vg_name,lv_name,segtype,pool_lv,lv_dm_path",
        ])
        .await
        .map_err(|e| e.to_string())?;
        let volumes = parse_volumes(&lvs).map_err(|e| e.to_string())?;
        let Some(volume) = volumes.into_iter().find(|v| v.dm_path == source) else {
            return Err(format!("no logical volume is {source}"));
        };
        if volume.segtype != "thin" {
            return Err(format!(
                "{}/{} is {}, not thin-provisioned; only thin volumes are snapshotted",
                volume.vg, volume.lv, volume.segtype
            ));
        }
        Ok(Self {
            vg: volume.vg,
            lv: volume.lv,
            mountpoint: mountpoint.to_path_buf(),
            fstype,
        })
    }

    fn name(job: &str) -> String {
        format!("updawg_{job}")
    }

    /// The snapshot name for `id`, if it is one of ours.
    async fn ours(&self, id: &str) -> Result<String> {
        let (vg, name) = parse_id(id)?;
        if vg != self.vg || !self.list().await?.iter().any(|s| s.id == id) {
            return Err(SnapshotError::NotFound { id: id.to_owned() });
        }
        Ok(name.to_owned())
    }

    /// Activates and mounts a snapshot, runs `f` on the mount point, then
    /// unmounts and deactivates it even if `f` failed.
    async fn with_mounted<T>(
        &self,
        name: &str,
        writable: bool,
        f: impl AsyncFnOnce(&Path) -> Result<T>,
    ) -> Result<T> {
        let lv = format!("{}/{name}", self.vg);
        let at = PathBuf::from(format!("{MOUNT_AT}-{name}"));
        // thin snapshots have the activation-skip flag; -K overrides it
        run(&["lvchange", "-ay", "-K", &lv]).await?;
        tokio::fs::create_dir_all(&at).await?;
        let mut options = vec![if writable { "rw" } else { "ro" }];
        if self.fstype == "xfs" {
            options.push("nouuid");
        }
        let device = format!("/dev/{lv}");
        let mounted = run(&[
            "mount",
            "-o",
            &options.join(","),
            &device,
            &at.to_string_lossy(),
        ])
        .await;
        let result = match mounted {
            Ok(_) => {
                let result = f(&at).await;
                let unmounted = run(&["umount", &at.to_string_lossy()]).await;
                result.and_then(|t| unmounted.map(|_| t))
            }
            Err(e) => Err(e),
        };
        let _ = tokio::fs::remove_dir(&at).await;
        let deactivated = run(&["lvchange", "-an", &lv]).await;
        result.and_then(|t| deactivated.map(|_| t))
    }
}

#[async_trait]
impl SnapshotProvider for Lvm {
    fn provider(&self) -> Provider {
        Provider::Lvm
    }

    async fn available(&self) -> std::result::Result<(), String> {
        run(&["lvs", &format!("{}/{}", self.vg, self.lv)])
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn free_bytes(&self) -> Result<u64> {
        let out = run(&[
            "lvs",
            "--reportformat",
            "json",
            "--units",
            "b",
            "--nosuffix",
            "-o",
            "pool_lv",
            &format!("{}/{}", self.vg, self.lv),
        ])
        .await?;
        let pool = report(&out)?
            .first()
            .and_then(|v| v.get("pool_lv"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| unparseable("the volume names no thin pool"))?;
        parse_pool_free(
            &run(&[
                "lvs",
                "--reportformat",
                "json",
                "--units",
                "b",
                "--nosuffix",
                "-o",
                "lv_size,data_percent",
                &format!("{}/{pool}", self.vg),
            ])
            .await?,
        )
    }

    async fn create(&self, description: &str, job: &str) -> Result<Snapshot> {
        let name = Self::name(job);
        run(&[
            "lvcreate",
            "-s",
            "-n",
            &name,
            "--addtag",
            MARK,
            "--addtag",
            &format!("{MARK}_job_{job}"),
            &format!("{}/{}", self.vg, self.lv),
        ])
        .await?;
        Ok(Snapshot {
            id: format!("lvm:{}/{name}", self.vg),
            description: description.to_owned(),
            job: job.to_owned(),
            created: String::new(),
        })
    }

    async fn list(&self) -> Result<Vec<Snapshot>> {
        let out = run(&[
            "lvs",
            "--reportformat",
            "json",
            "-o",
            "vg_name,lv_name,origin,lv_tags,lv_time",
            "-S",
            &format!("lv_tags={MARK}"),
            &self.vg,
        ])
        .await?;
        parse_ours(&out, &self.lv)
    }

    async fn rollback(&self, id: &str) -> Result<Restored> {
        let name = self.ours(id).await?;
        let (out, err) =
            run_both(&["lvconvert", "--merge", &format!("{}/{name}", self.vg)]).await?;
        Ok(Restored {
            at_next_boot: parse_deferred(&format!("{out}{err}")),
            ..Restored::default()
        })
    }

    async fn prune(&self, keep: usize) -> Result<Vec<String>> {
        let ours = self.list().await?;
        let excess = ours.len().saturating_sub(keep);
        let mut gone = Vec::new();
        for snapshot in ours.into_iter().take(excess) {
            let (vg, name) = parse_id(&snapshot.id)?;
            run(&["lvremove", "-y", &format!("{vg}/{name}")]).await?;
            gone.push(snapshot.id);
        }
        Ok(gone)
    }

    async fn kernels_rolled_away(&self, id: &str) -> Result<Vec<String>> {
        let name = self.ours(id).await?;
        let now = kernels_in(&self.mountpoint).await;
        let then = self
            .with_mounted(&name, false, async |at| Ok(kernels_in(at).await))
            .await?;
        let mut gone: Vec<String> = now.into_iter().filter(|k| !then.contains(k)).collect();
        gone.sort();
        Ok(gone)
    }

    fn restores_at_next_boot(&self) -> bool {
        true
    }

    async fn carry_into(&self, id: &str, dir: &Path) -> Result<()> {
        let name = self.ours(id).await?;
        let relative = dir
            .strip_prefix(&self.mountpoint)
            .map_err(|_| unparseable("the directory to carry is not on the snapshotted volume"))?
            .to_path_buf();
        let from = dir.to_path_buf();
        self.with_mounted(&name, true, async move |at| {
            let into = at.join(&relative);
            tokio::fs::create_dir_all(&into).await?;
            // Mirror the live directory, so files that no longer exist (a
            // finished pending reboot, say) are removed from the snapshot too.
            let mut stale = tokio::fs::read_dir(&into).await?;
            while let Some(entry) = stale.next_entry().await? {
                if entry.file_type().await?.is_file() {
                    tokio::fs::remove_file(entry.path()).await?;
                }
            }
            let mut live = tokio::fs::read_dir(&from).await?;
            while let Some(entry) = live.next_entry().await? {
                if entry.file_type().await?.is_file() {
                    tokio::fs::copy(entry.path(), into.join(entry.file_name())).await?;
                }
            }
            Ok(())
        })
        .await
    }
}

async fn kernels_in(root: &Path) -> Vec<String> {
    let mut kernels = Vec::new();
    for dir in ["usr/lib/modules", "lib/modules"] {
        let Ok(mut entries) = tokio::fs::read_dir(root.join(dir)).await else {
            continue;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry.file_type().await.is_ok_and(|t| t.is_dir()) {
                kernels.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    kernels.sort();
    kernels.dedup();
    kernels
}

/// One logical volume, as `lvs` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    pub vg: String,
    pub lv: String,
    pub segtype: String,
    pub dm_path: String,
}

/// Splits `lvm:<vg>/updawg_<job>` into volume group and snapshot name.
///
/// # Errors
/// [`SnapshotError::ForeignId`] for anything else.
pub fn parse_id(id: &str) -> Result<(&str, &str)> {
    id.strip_prefix("lvm:")
        .and_then(|rest| rest.split_once('/'))
        .filter(|(vg, name)| !vg.is_empty() && name.starts_with("updawg_") && !name.contains('/'))
        .ok_or_else(|| SnapshotError::ForeignId {
            id: id.to_owned(),
            provider: "lvm",
        })
}

/// Parses `lvs --reportformat json -o vg_name,lv_name,segtype,pool_lv,lv_dm_path`.
///
/// # Errors
/// [`SnapshotError::Unparseable`] if the JSON has an unexpected shape.
pub fn parse_volumes(out: &str) -> Result<Vec<Volume>> {
    report(out)?
        .iter()
        .map(|v| {
            let field = |k: &str| {
                v.get(k)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| unparseable(&format!("a volume without {k}")))
            };
            Ok(Volume {
                vg: field("vg_name")?,
                lv: field("lv_name")?,
                segtype: field("segtype")?,
                dm_path: field("lv_dm_path")?,
            })
        })
        .collect()
}

/// Parses `lvs -o vg_name,lv_name,origin,lv_tags,lv_time -S lv_tags=updawg`
/// into the agent's snapshots of `origin`, oldest first.
///
/// # Errors
/// [`SnapshotError::Unparseable`] if the JSON has an unexpected shape.
pub fn parse_ours(out: &str, origin: &str) -> Result<Vec<Snapshot>> {
    let mut ours: Vec<Snapshot> = report(out)?
        .iter()
        .filter_map(|v| {
            let text = |k: &str| {
                v.get(k)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
            };
            if text("origin") != origin {
                return None;
            }
            let tags: Vec<&str> = text("lv_tags").split(',').collect();
            if !tags.contains(&MARK) {
                return None;
            }
            // the job comes from the name; tags only mark ownership
            let job = text("lv_name").strip_prefix("updawg_")?.to_owned();
            Some(Snapshot {
                id: format!("lvm:{}/{}", text("vg_name"), text("lv_name")),
                description: String::new(),
                job,
                created: text("lv_time").to_owned(),
            })
        })
        .collect();
    // lv_time is `YYYY-MM-DD HH:MM:SS +ZZZZ`, which sorts as text
    ours.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)));
    Ok(ours)
}

/// The thin pool's free bytes: its size minus the used data percentage.
///
/// # Errors
/// [`SnapshotError::Unparseable`] if the JSON has an unexpected shape.
pub fn parse_pool_free(out: &str) -> Result<u64> {
    let pool = report(out)?
        .into_iter()
        .next()
        .ok_or_else(|| unparseable("no thin pool in the report"))?;
    let number = |k: &str| -> Result<f64> {
        pool.get(k)
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| unparseable(&format!("the pool's {k} is not a number")))
    };
    let (size, used) = (number("lv_size")?, number("data_percent")?);
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a byte count from a size and a percentage, rounded down"
    )]
    Ok((size * (100.0 - used).clamp(0.0, 100.0) / 100.0) as u64)
}

/// Whether `lvconvert --merge` deferred the merge to the next activation.
#[must_use]
pub fn parse_deferred(out: &str) -> bool {
    out.contains("will occur on next activation")
}

fn report(out: &str) -> Result<Vec<serde_json::Value>> {
    let value: serde_json::Value =
        serde_json::from_str(out).map_err(|e| unparseable(&format!("not JSON: {e}")))?;
    value
        .get("report")
        .and_then(|r| r.get(0))
        .and_then(|r| r.get("lv"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .ok_or_else(|| unparseable("no report[0].lv array"))
}

fn unparseable(detail: &str) -> SnapshotError {
    SnapshotError::Unparseable {
        tool: "lvs",
        detail: detail.to_owned(),
    }
}

/// Runs an LVM tool (or `mount`) and returns stdout. LVM writes warnings to
/// stderr even on success, so stderr is not parsed.
async fn run(args: &[&str]) -> Result<String> {
    Ok(run_both(args).await?.0)
}

/// Like [`run`], but also returns stderr, where `lvconvert` reports a
/// deferred merge.
async fn run_both(args: &[&str]) -> Result<(String, String)> {
    let (tool, rest) = args
        .split_first()
        .ok_or_else(|| unparseable("no command"))?;
    let tool: &'static str = match *tool {
        "lvs" => "lvs",
        "lvcreate" => "lvcreate",
        "lvconvert" => "lvconvert",
        "lvremove" => "lvremove",
        "lvchange" => "lvchange",
        "mount" => "mount",
        "umount" => "umount",
        _ => return Err(unparseable("not a tool this provider runs")),
    };
    let output = tokio::process::Command::new(tool)
        .args(rest)
        .env("LC_ALL", "C")
        .kill_on_drop(true)
        .output()
        .await?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        if stderr.contains("Failed to find logical volume") {
            return Err(SnapshotError::NotFound {
                id: rest.last().copied().unwrap_or_default().to_owned(),
            });
        }
        return Err(SnapshotError::CommandFailed {
            tool,
            status: output.status.code().unwrap_or(-1),
            stderr: stderr.trim().to_owned(),
        });
    }
    Ok((stdout, stderr))
}
