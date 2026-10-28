//! ZFS, for a root filesystem on a ZFS dataset.
//!
//! # What is snapshotted
//!
//! The dataset mounted at `/` and every dataset below it, atomically
//! (`zfs snapshot -r`). Ubuntu puts `var`, `var/lib`, `var/lib/dpkg` and
//! others in child datasets, so snapshotting only the root would restore files
//! without the matching package database. Datasets outside the root
//! (`rpool/USERDATA`, `bpool` for `/boot`) are left alone, which is why the
//! executor refuses a rollback that would remove a kernel.
//!
//! # Rollback destroys newer snapshots
//!
//! `zfs rollback` can only go back to a dataset's newest snapshot, so `-r`
//! destroys every snapshot newer than the target, including an
//! administrator's. The only alternative on ZFS is cloning.
//!
//! # Ownership
//!
//! Snapshots are named `@updawg-<job>` and carry the user property
//! `updawg:job`. Only those are listed, restored or pruned. ZFS names are
//! unique, so `zfs:<dataset>@updawg-<job>` identifies exactly one snapshot.

use crate::{Provider, Restored, Result, Snapshot, SnapshotError, SnapshotProvider};
use async_trait::async_trait;

const TOOL: &str = "zfs";
const MARK: &str = "updawg:job";
const DESCRIPTION: &str = "updawg:description";

/// Snapshots one dataset and everything below it.
#[derive(Debug, Clone)]
pub struct Zfs {
    dataset: String,
}

impl Zfs {
    /// The dataset mounted at `/`, or why there is none.
    ///
    /// # Errors
    /// `/` is not ZFS, or `findmnt` could not say.
    pub async fn root() -> std::result::Result<Self, String> {
        let out = tokio::process::Command::new("findmnt")
            .args(["-n", "-o", "SOURCE,FSTYPE", "/"])
            .env("LC_ALL", "C")
            .output()
            .await
            .map_err(|e| format!("findmnt: {e}"))?;
        match parse_findmnt(&String::from_utf8_lossy(&out.stdout)) {
            Some((dataset, fstype)) if fstype == "zfs" => Ok(Self { dataset }),
            Some((_, fstype)) => Err(format!("/ is {fstype}, not zfs")),
            None => Err("findmnt did not say what / is".into()),
        }
    }

    /// Uses a specific dataset instead of `/`. For tests.
    #[must_use]
    pub fn with_dataset(dataset: &str) -> Self {
        Self {
            dataset: dataset.to_owned(),
        }
    }

    fn snapshot_name(job: &str) -> String {
        format!("updawg-{job}")
    }

    /// Every dataset at or below ours that has this snapshot, ours first.
    async fn with_snapshot(&self, name: &str) -> Result<Vec<String>> {
        let out = run(&[
            "list",
            "-H",
            "-t",
            "snapshot",
            "-r",
            "-o",
            "name",
            &self.dataset,
        ])
        .await?;
        let suffix = format!("@{name}");
        Ok(out
            .lines()
            .filter_map(|l| l.trim().strip_suffix(&suffix))
            .map(str::to_owned)
            .collect())
    }

    async fn mountpoint(&self) -> Result<String> {
        Ok(
            run(&["get", "-H", "-o", "value", "mountpoint", &self.dataset])
                .await?
                .trim()
                .to_owned(),
        )
    }

    /// The snapshot name for `id`, if it is one of ours.
    async fn ours(&self, id: &str) -> Result<String> {
        let (dataset, name) = parse_id(id)?;
        if dataset != self.dataset || !self.list().await?.iter().any(|s| s.id == id) {
            return Err(SnapshotError::NotFound { id: id.to_owned() });
        }
        Ok(name.to_owned())
    }
}

#[async_trait]
impl SnapshotProvider for Zfs {
    fn provider(&self) -> Provider {
        Provider::Zfs
    }

    async fn available(&self) -> std::result::Result<(), String> {
        match run(&["list", "-H", "-o", "name", &self.dataset]).await {
            Ok(_) => Ok(()),
            Err(SnapshotError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Err("zfs is not installed".into())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    async fn free_bytes(&self) -> Result<u64> {
        let out = run(&["get", "-H", "-p", "-o", "value", "available", &self.dataset]).await?;
        out.trim().parse().map_err(|_| SnapshotError::Unparseable {
            tool: TOOL,
            detail: format!("available is not a number: {out:?}"),
        })
    }

    async fn create(&self, description: &str, job: &str) -> Result<Snapshot> {
        let name = Self::snapshot_name(job);
        let target = format!("{}@{name}", self.dataset);
        run(&[
            "snapshot",
            "-r",
            "-o",
            &format!("{MARK}={job}"),
            "-o",
            &format!("{DESCRIPTION}={description}"),
            &target,
        ])
        .await?;
        Ok(Snapshot {
            id: format!("zfs:{target}"),
            description: description.to_owned(),
            job: job.to_owned(),
            created: String::new(),
        })
    }

    async fn list(&self) -> Result<Vec<Snapshot>> {
        let out = run(&[
            "list",
            "-H",
            "-p",
            "-t",
            "snapshot",
            "-d",
            "1",
            "-o",
            &format!("name,creation,{MARK},{DESCRIPTION}"),
            "-s",
            "creation",
            &self.dataset,
        ])
        .await?;
        Ok(parse_list(&out))
    }

    async fn rollback(&self, id: &str) -> Result<Restored> {
        let name = self.ours(id).await?;
        let mut restored = Restored::default();
        for dataset in self.with_snapshot(&name).await? {
            let target = format!("{dataset}@{name}");
            let (these, _) = parse_diff(&run(&["diff", "-H", &target]).await?, "/");
            restored.created += these.created;
            restored.modified += these.modified;
            restored.deleted += these.deleted;
            run(&["rollback", "-r", &target]).await?;
        }
        Ok(restored)
    }

    async fn prune(&self, keep: usize) -> Result<Vec<String>> {
        let ours = self.list().await?;
        let excess = ours.len().saturating_sub(keep);
        let mut gone = Vec::new();
        for snapshot in ours.into_iter().take(excess) {
            let (_, name) = parse_id(&snapshot.id)?;
            run(&["destroy", "-r", &format!("{}@{name}", self.dataset)]).await?;
            gone.push(snapshot.id);
        }
        Ok(gone)
    }

    async fn kernels_rolled_away(&self, id: &str) -> Result<Vec<String>> {
        let name = self.ours(id).await?;
        let mountpoint = self.mountpoint().await?;
        let mut kernels = Vec::new();
        for dataset in self.with_snapshot(&name).await? {
            let (_, added) = parse_diff(
                &run(&["diff", "-H", &format!("{dataset}@{name}")]).await?,
                &mountpoint,
            );
            kernels.extend(added);
        }
        kernels.sort();
        kernels.dedup();
        Ok(kernels)
    }
}

/// Splits `zfs:<dataset>@<snapshot>` into dataset and snapshot name.
///
/// # Errors
/// [`SnapshotError::ForeignId`] for anything else, including a snapshot name
/// without the `updawg-` prefix.
pub fn parse_id(id: &str) -> Result<(&str, &str)> {
    id.strip_prefix("zfs:")
        .and_then(|rest| rest.split_once('@'))
        .filter(|(dataset, name)| !dataset.is_empty() && name.starts_with("updawg-"))
        .ok_or_else(|| SnapshotError::ForeignId {
            id: id.to_owned(),
            provider: "zfs",
        })
}

/// Parses `findmnt -n -o SOURCE,FSTYPE`.
#[must_use]
pub fn parse_findmnt(out: &str) -> Option<(String, String)> {
    let mut words = out.split_whitespace();
    Some((words.next()?.to_owned(), words.next()?.to_owned()))
}

/// Parses `zfs list -H -p -t snapshot -o name,creation,updawg:job[,updawg:description]`,
/// keeping only the agent's snapshots, in ZFS order. ZFS prints `-` for an
/// unset property, which filters out everyone else's.
#[must_use]
pub fn parse_list(out: &str) -> Vec<Snapshot> {
    out.lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let name = fields.next()?.trim();
            let created = fields.next()?.trim();
            let job = fields.next()?.trim();
            if job == "-" || job.is_empty() {
                return None;
            }
            let description = fields.next().map(str::trim).filter(|d| *d != "-");
            Some(Snapshot {
                id: format!("zfs:{name}"),
                description: description.unwrap_or_default().to_owned(),
                job: job.to_owned(),
                created: created.to_owned(),
            })
        })
        .collect()
}

/// Parses `zfs diff -H <snapshot>` into what a rollback would restore and the
/// kernel module directories it would remove.
///
/// The first column describes changes since the snapshot, so a rollback
/// inverts them: `+` gets removed, `-` gets put back, `M` and `R` are
/// restored. Paths are absolute on the live system; `mountpoint` is where the
/// snapshotted tree is mounted.
#[must_use]
pub fn parse_diff(out: &str, mountpoint: &str) -> (Restored, Vec<String>) {
    let mut restored = Restored::default();
    let mut kernels = Vec::new();
    for line in out.lines() {
        let mut fields = line.split('\t');
        let (Some(change), Some(path)) = (fields.next(), fields.next()) else {
            continue;
        };
        match change {
            "+" => {
                restored.deleted += 1;
                let relative = path
                    .strip_prefix(mountpoint.trim_end_matches('/'))
                    .unwrap_or(path);
                kernels.extend(crate::kernel_dir(relative));
            }
            "-" => restored.created += 1,
            "M" | "R" => restored.modified += 1,
            _ => {}
        }
    }
    (restored, kernels)
}

async fn run(args: &[&str]) -> Result<String> {
    let output = tokio::process::Command::new(TOOL)
        .args(args)
        .env("LC_ALL", "C")
        .kill_on_drop(true)
        .output()
        .await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        if stderr.contains("dataset does not exist") {
            return Err(SnapshotError::NotFound {
                id: args.last().copied().unwrap_or_default().to_owned(),
            });
        }
        return Err(SnapshotError::CommandFailed {
            tool: TOOL,
            status: output.status.code().unwrap_or(-1),
            stderr,
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
