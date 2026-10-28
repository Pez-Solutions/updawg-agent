//! `updawgctl self-update-run`, the part of a self-update that runs outside
//! the agent in the transient unit [`super::UNIT`].
//!
//! Kept synchronous and simple. It must not leave the host without an agent:
//! unless the new version checks in, the old one is restored and restarted
//! and an [`super::Outcome`] records why.

use super::{Method, Outcome, PACKAGE, Pending, previous, staged};
use crate::state::LocalState;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

/// Runs the update recorded in `state`.
///
/// # Errors
/// Only if there is no pending update or it can't be read. Failures of the
/// update itself are recorded as an [`Outcome`].
pub fn run(state: &LocalState) -> anyhow::Result<()> {
    let pending = state.self_update()?.ok_or_else(|| {
        anyhow::anyhow!("no self-update is recorded in {}", state.root().display())
    })?;
    say(&format!(
        "updating the agent {} -> {} for job {}",
        pending.from, pending.to, pending.job.id
    ));
    let began = chrono::Utc::now();

    if let Err(why) = install(&pending.method, &pending.to) {
        say(&format!("the update did not install: {why}"));
        // may be half done (one of two binaries swapped), so roll back
        return give_up(
            state,
            &pending,
            &format!("the update did not install: {why}"),
        );
    }
    restart();

    let deadline = Instant::now() + super::CONFIRM_WITHIN;
    while Instant::now() < deadline {
        if confirmed(state, &pending.to, began) {
            say(&format!("{} checked in; done", pending.to));
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    give_up(
        state,
        &pending,
        &format!(
            "{} did not check in within {} s of starting",
            pending.to,
            super::CONFIRM_WITHIN.as_secs()
        ),
    )
}

fn give_up(state: &LocalState, pending: &Pending, why: &str) -> anyhow::Result<()> {
    say(&format!("putting {} back: {why}", pending.from));
    let outcome = match roll_back(&pending.method, &pending.from) {
        Ok(()) => Outcome {
            rolled_back: true,
            detail: format!("{why}; {} is back", pending.from),
        },
        Err(error) => Outcome {
            rolled_back: false,
            detail: format!(
                "{why}; and putting {} back failed too: {error}",
                pending.from
            ),
        },
    };
    say(&outcome.detail);
    // must be written before the restart, the next agent reads it
    state.set_self_update_outcome(&outcome)?;
    restart();
    Ok(())
}

fn confirmed(state: &LocalState, version: &str, began: chrono::DateTime<chrono::Utc>) -> bool {
    matches!(
        state.last_checkin(),
        Ok(Some(last)) if last.ok && last.at > began && last.agent.as_deref() == Some(version)
    )
}

fn install(method: &Method, version: &str) -> Result<(), String> {
    match method {
        Method::Apt | Method::Dnf => package(method, version),
        Method::Binary { dir } => swap(dir),
    }
}

fn roll_back(method: &Method, version: &str) -> Result<(), String> {
    match method {
        Method::Apt | Method::Dnf => package(method, version),
        Method::Binary { dir } => put_back(dir),
    }
}

/// Installs exactly `version` (upgrade or downgrade) and checks the result.
///
/// The package's postinstall already restarts `updawgd` (see
/// packaging/nfpm/postinstall.sh); the extra [`restart`] is harmless.
fn package(method: &Method, version: &str) -> Result<(), String> {
    match method {
        Method::Apt => {
            let pin = format!("{PACKAGE}={version}");
            exec(
                Command::new("apt-get")
                    .env("DEBIAN_FRONTEND", "noninteractive")
                    .args([
                        "install",
                        "-y",
                        "--allow-downgrades",
                        "-o",
                        "Dpkg::Options::=--force-confdef",
                        "-o",
                        "Dpkg::Options::=--force-confold",
                    ])
                    .arg(&pin),
            )?;
        }
        Method::Dnf => {
            let spec = format!("{PACKAGE}-{version}");
            // `dnf install` of an older version is a successful no-op, so
            // fall back to `downgrade`
            exec(Command::new("dnf").args(["-y", "install"]).arg(&spec))?;
            if installed(method).as_deref() != Some(version) {
                exec(Command::new("dnf").args(["-y", "downgrade"]).arg(&spec))?;
            }
        }
        Method::Binary { .. } => return Err("not a package install".into()),
    }
    match installed(method) {
        Some(now) if now == version => Ok(()),
        Some(now) => Err(format!("{PACKAGE} is {now} afterwards, not {version}")),
        None => Err(format!("{PACKAGE} is not installed afterwards")),
    }
}

fn installed(method: &Method) -> Option<String> {
    let out = match method {
        Method::Apt => Command::new("dpkg-query")
            .args(["-W", "-f", "${Version}", PACKAGE])
            .output(),
        Method::Dnf => Command::new("rpm")
            .args(["-q", "--qf", "%{VERSION}-%{RELEASE}", PACKAGE])
            .output(),
        Method::Binary { .. } => return None,
    }
    .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Hard-links each binary to `.prev`, then renames the staged one over it.
/// Each rename is atomic but the pair isn't; [`put_back`] handles that.
fn swap(dir: &Path) -> Result<(), String> {
    for name in ["updawgd", "updawgctl"] {
        let live = dir.join(name);
        let (new, prev) = (staged(dir, name), previous(dir, name));
        if !new.exists() {
            return Err(format!("{} is not staged", new.display()));
        }
        let _ = std::fs::remove_file(&prev);
        std::fs::hard_link(&live, &prev)
            .map_err(|e| format!("keeping {} as {}: {e}", live.display(), prev.display()))?;
        std::fs::rename(&new, &live)
            .map_err(|e| format!("putting {} in place: {e}", live.display()))?;
    }
    Ok(())
}

fn put_back(dir: &Path) -> Result<(), String> {
    let mut failed = Vec::new();
    for name in ["updawgd", "updawgctl"] {
        let prev = previous(dir, name);
        if prev.exists()
            && let Err(e) = std::fs::rename(&prev, dir.join(name))
        {
            failed.push(format!("{name}: {e}"));
        }
        let _ = std::fs::remove_file(staged(dir, name));
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("; "))
    }
}

fn restart() {
    if let Err(why) = exec(Command::new("systemctl").args(["restart", "updawgd.service"])) {
        say(&format!("restarting updawgd: {why}"));
    }
}

/// Output goes to the unit's journal.
fn exec(command: &mut Command) -> Result<(), String> {
    let shown = format!("{command:?}");
    say(&format!("running {shown}"));
    let status = command
        .status()
        .map_err(|e| format!("{shown} did not start: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{shown} exited {status}"))
    }
}

#[allow(clippy::print_stdout)]
fn say(line: &str) {
    println!("{line}");
}
