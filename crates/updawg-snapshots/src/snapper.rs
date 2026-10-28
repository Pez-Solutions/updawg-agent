//! Snapper, for btrfs.
//!
//! Shells out to `snapper --jsonout`, the same way the package backends use
//! apt and dnf, so the agent stays a single static binary.
//!
//! # `undochange` instead of `snapper rollback`
//!
//! `snapper rollback` changes the default subvolume and expects a reboot.
//! That works on openSUSE, but Fedora and Ubuntu mount `subvol=root` or
//! `subvol=@` by name from fstab and the kernel command line, so the new
//! default is never mounted and the host comes back unchanged.
//! `undochange N..0` copies the snapshot's files back over the live
//! filesystem: it works on any layout, needs no reboot, and reports what it
//! changed. Running processes keep the old code until restarted, as after any
//! package change; health checks run afterwards.
//!
//! # Ownership
//!
//! The agent's snapshots carry `updawg=<job id>` as userdata, and only those
//! are listed, restored or pruned. Administrator snapshots and the pre/post
//! pairs from package-manager plugins are ignored.

use crate::{Provider, Restored, Result, Snapshot, SnapshotError, SnapshotProvider};
use async_trait::async_trait;

const TOOL: &str = "snapper";
const MARK: &str = "updawg";

/// Snapper, using one configuration.
#[derive(Debug, Clone)]
pub struct Snapper {
    config: String,
}

impl Snapper {
    /// The `root` configuration, snapper's convention for `/`.
    #[must_use]
    pub fn root() -> Self {
        Self::with_config("root")
    }

    /// Uses another configuration. For tests.
    #[must_use]
    pub fn with_config(config: &str) -> Self {
        Self {
            config: config.to_owned(),
        }
    }

    async fn snapper(&self, args: &[&str]) -> Result<String> {
        let mut all = vec!["--jsonout", "-c", &self.config];
        all.extend_from_slice(args);
        run(&all).await
    }
}

#[async_trait]
impl SnapshotProvider for Snapper {
    fn provider(&self) -> Provider {
        Provider::Snapper
    }

    async fn available(&self) -> std::result::Result<(), String> {
        let out = match run(&["--jsonout", "list-configs"]).await {
            Ok(out) => out,
            Err(SnapshotError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err("snapper is not installed".into());
            }
            Err(e) => return Err(e.to_string()),
        };
        let configs = parse_configs(&out).map_err(|e| e.to_string())?;
        if configs.iter().any(|(name, _)| *name == self.config) {
            Ok(())
        } else {
            Err(format!(
                "snapper has no `{}` configuration (it has: {})",
                self.config,
                if configs.is_empty() {
                    "none".to_owned()
                } else {
                    configs
                        .iter()
                        .map(|(n, s)| format!("{n} on {s}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ))
        }
    }

    async fn free_bytes(&self) -> Result<u64> {
        let configs = parse_configs(&run(&["--jsonout", "list-configs"]).await?)?;
        let Some((_, subvolume)) = configs.into_iter().find(|(name, _)| *name == self.config)
        else {
            return Err(SnapshotError::Unavailable(format!(
                "snapper has no `{}` configuration",
                self.config
            )));
        };
        let out = tokio::process::Command::new("df")
            .args(["-P", &subvolume])
            .env("LC_ALL", "C")
            .output()
            .await?;
        parse_df(&String::from_utf8_lossy(&out.stdout)).ok_or_else(|| SnapshotError::Unparseable {
            tool: "df",
            detail: String::from_utf8_lossy(&out.stdout).into_owned(),
        })
    }

    async fn create(&self, description: &str, job: &str) -> Result<Snapshot> {
        let userdata = format!("{MARK}={job}");
        // No cleanup algorithm, so snapper's timers can't delete a snapshot
        // a rollout still needs. `prune` bounds them instead.
        let out = self
            .snapper(&[
                "create",
                "--type",
                "single",
                "--description",
                description,
                "--userdata",
                &userdata,
                "--print-number",
            ])
            .await?;
        let number = parse_number(&out)?;
        Ok(Snapshot {
            id: id(number, job),
            description: description.to_owned(),
            job: job.to_owned(),
            created: String::new(),
        })
    }

    async fn list(&self) -> Result<Vec<Snapshot>> {
        parse_list(&self.snapper(&["list"]).await?)
    }

    async fn rollback(&self, snapshot: &str) -> Result<Restored> {
        let (number, _) = parse_id(snapshot)?;
        // compare the whole id, job included (see `id`)
        if !self.list().await?.iter().any(|s| s.id == snapshot) {
            return Err(SnapshotError::NotFound {
                id: snapshot.to_owned(),
            });
        }
        let range = format!("{number}..0");
        parse_undo(&self.snapper(&["undochange", &range]).await?)
    }

    async fn kernels_rolled_away(&self, id: &str) -> Result<Vec<String>> {
        let (number, _) = parse_id(id)?;
        if !self.list().await?.iter().any(|s| s.id == id) {
            return Err(SnapshotError::NotFound { id: id.to_owned() });
        }
        let configs = parse_configs(&run(&["--jsonout", "list-configs"]).await?)?;
        let subvolume = configs
            .into_iter()
            .find(|(name, _)| *name == self.config)
            .map_or_else(|| "/".to_owned(), |(_, s)| s);
        // no --jsonout; plain status output is one change per line
        let range = format!("{number}..0");
        let out = run(&["-c", &self.config, "status", &range]).await?;
        Ok(parse_status_kernels(&out, &subvolume))
    }

    async fn prune(&self, keep: usize) -> Result<Vec<String>> {
        let ours = self.list().await?;
        let excess = ours.len().saturating_sub(keep);
        let doomed: Vec<Snapshot> = ours.into_iter().take(excess).collect();
        if doomed.is_empty() {
            return Ok(vec![]);
        }
        let numbers: Vec<String> = doomed
            .iter()
            .map(|s| parse_id(&s.id).map(|(n, _)| n.to_string()))
            .collect::<Result<_>>()?;
        let mut args = vec!["delete"];
        args.extend(numbers.iter().map(String::as_str));
        self.snapper(&args).await?;
        Ok(doomed.into_iter().map(|s| s.id).collect())
    }
}

/// `snapper:<number>:<job>`.
///
/// The job is part of the id because snapper reuses numbers: delete the newest
/// snapshot and the next one gets the same number (seen on snapper 0.10.6).
/// Without the job, a rollback could restore a snapshot taken for a different
/// job.
fn id(number: u64, job: &str) -> String {
    format!("{}:{number}:{job}", Provider::Snapper.name())
}

/// The snapper number and job in `snapper:412:job_abc`.
///
/// # Errors
/// [`SnapshotError::ForeignId`] for anything else, including snapshot 0,
/// which is snapper's name for the live filesystem.
pub fn parse_id(id: &str) -> Result<(u64, &str)> {
    id.strip_prefix("snapper:")
        .and_then(|rest| rest.split_once(':'))
        .and_then(|(n, job)| Some((n.parse::<u64>().ok()?, job)))
        .filter(|(n, job)| *n > 0 && !job.is_empty())
        .ok_or_else(|| SnapshotError::ForeignId {
            id: id.to_owned(),
            provider: "snapper",
        })
}

/// Parses the output of `snapper create --print-number`.
///
/// # Errors
/// [`SnapshotError::Unparseable`] if it isn't a number.
pub fn parse_number(out: &str) -> Result<u64> {
    out.trim().parse().map_err(|_| SnapshotError::Unparseable {
        tool: TOOL,
        detail: format!("expected a snapshot number from create, got {out:?}"),
    })
}

/// Parses `snapper --jsonout list-configs` into (config, subvolume) pairs.
///
/// # Errors
/// [`SnapshotError::Unparseable`] if the JSON has an unexpected shape.
pub fn parse_configs(out: &str) -> Result<Vec<(String, String)>> {
    let value: serde_json::Value = json(out)?;
    let configs = value
        .get("configs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| unparseable("list-configs has no `configs` array"))?;
    configs
        .iter()
        .map(|c| {
            let field = |k: &str| c.get(k).and_then(serde_json::Value::as_str);
            match (field("config"), field("subvolume")) {
                (Some(name), Some(subvolume)) => Ok((name.to_owned(), subvolume.to_owned())),
                _ => Err(unparseable("a configuration without a name or subvolume")),
            }
        })
        .collect()
}

/// Parses `snapper --jsonout -c <config> list`, returning the agent's
/// snapshots oldest first.
///
/// The output has a single key (the config name) holding every snapshot,
/// including number 0 (the live filesystem). Only those with `updawg=`
/// userdata are kept.
///
/// # Errors
/// [`SnapshotError::Unparseable`] if the JSON has an unexpected shape.
pub fn parse_list(out: &str) -> Result<Vec<Snapshot>> {
    let value: serde_json::Value = json(out)?;
    let entries = value
        .as_object()
        .and_then(|o| o.values().next())
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| unparseable("list is not one configuration's array of snapshots"))?;
    let mut ours: Vec<(u64, Snapshot)> = entries
        .iter()
        .filter_map(|e| {
            let job = e.get("userdata")?.get(MARK)?.as_str()?;
            let number = e.get("number")?.as_u64().filter(|n| *n > 0)?;
            let text = |k: &str| {
                e.get(k)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            Some((
                number,
                Snapshot {
                    id: id(number, job),
                    description: text("description"),
                    job: job.to_owned(),
                    created: text("date"),
                },
            ))
        })
        .collect();
    ours.sort_by_key(|(n, _)| *n);
    Ok(ours.into_iter().map(|(_, s)| s).collect())
}

/// Parses `snapper undochange N..0`, which ends with
/// `create:C modify:M delete:D` or prints `nothing to do`.
///
/// # Errors
/// [`SnapshotError::Unparseable`] if neither is found.
pub fn parse_undo(out: &str) -> Result<Restored> {
    if out.trim() == "nothing to do" {
        return Ok(Restored::default());
    }
    for line in out.lines().rev() {
        let mut restored = Restored::default();
        let mut seen = 0;
        for word in line.split_whitespace() {
            let Some((key, n)) = word.split_once(':') else {
                continue;
            };
            let Ok(n) = n.parse::<u64>() else { continue };
            match key {
                "create" => restored.created = n,
                "modify" => restored.modified = n,
                "delete" => restored.deleted = n,
                _ => continue,
            }
            seen += 1;
        }
        if seen == 3 {
            return Ok(restored);
        }
    }
    Err(unparseable(&format!(
        "undochange printed no `create: modify: delete:` summary: {out:?}"
    )))
}

/// Kernels a rollback would remove, from `snapper status N..0`: module
/// directories created since snapshot N (flags starting with `+`). Paths are
/// absolute on the live system, under `subvolume`.
#[must_use]
pub fn parse_status_kernels(out: &str, subvolume: &str) -> Vec<String> {
    let mut kernels: Vec<String> = out
        .lines()
        .filter_map(|line| {
            let (flags, path) = line.split_once(' ')?;
            if !flags.starts_with('+') {
                return None;
            }
            let path = path.trim();
            let relative = path
                .strip_prefix(subvolume.trim_end_matches('/'))
                .unwrap_or(path);
            crate::kernel_dir(relative)
        })
        .collect();
    kernels.sort();
    kernels.dedup();
    kernels
}

/// The `Available` column of `df -P`, converted to bytes. We use `df` because
/// `statvfs` would need `unsafe`.
#[must_use]
pub fn parse_df(out: &str) -> Option<u64> {
    let line = out.lines().nth(1)?;
    let blocks: u64 = line.split_whitespace().nth(3)?.parse().ok()?;
    Some(blocks.saturating_mul(1024))
}

fn json(out: &str) -> Result<serde_json::Value> {
    serde_json::from_str(out).map_err(|e| unparseable(&format!("not JSON: {e}")))
}

fn unparseable(detail: &str) -> SnapshotError {
    SnapshotError::Unparseable {
        tool: TOOL,
        detail: detail.to_owned(),
    }
}

async fn run(args: &[&str]) -> Result<String> {
    let output = tokio::process::Command::new(TOOL)
        .args(args)
        // output is parsed, so force the C locale
        .env("LC_ALL", "C")
        .kill_on_drop(true)
        .output()
        .await?;
    if !output.status.success() {
        return Err(SnapshotError::CommandFailed {
            tool: TOOL,
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
