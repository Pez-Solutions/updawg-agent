//! `updawgctl self-update-run`: the half of a self-update that runs outside
//! the agent, in the transient unit [`super::UNIT`] (see the module above).
//!
//! Synchronous and plain on purpose: it is a short script in Rust, run once,
//! and the thing it must never do is leave the host without an agent. Every
//! path that does not end with the new agent checked in ends with the old one
//! put back and restarted, and [`super::Outcome`] saying why.

use super::{Method, Outcome, PACKAGE, Pending, previous, staged};
use crate::state::LocalState;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

/// Run the update recorded in `state`.
///
/// # Errors
/// Only when there is nothing to run, or the record cannot be read. Every
/// failure of the update itself is written down as an [`Outcome`] instead.
pub fn run(state: &LocalState) -> anyhow::Result<()> {
    let pending = state.self_update()?.ok_or_else(|| {
        anyhow::anyhow!("no self-update is recorded in {}", state.root().display())
    })?;
    say(&format!(
        "updating the agent {} → {} for job {}",
        pending.from, pending.to, pending.job.id
    ));
    let began = chrono::Utc::now();

    if let Err(why) = install(&pending.method, &pending.to) {
        say(&format!("the update did not install: {why}"));
        // Possibly half-done (a swap that renamed one binary of two), so put
        // the old one back the same way a failed start would.
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

/// Put `pending.from` back, restart, and write down why.
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
    // Written before the restart: the agent that starts reads it.
    state.set_self_update_outcome(&outcome)?;
    restart();
    Ok(())
}

/// Whether the agent has checked in as `version` since `began`.
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

/// Install exactly `version` of the package, up or down, and check that it is
/// what is installed afterwards.
///
/// The package's postinstall restarts `updawgd` (this helper is not under it,
/// see packaging/nfpm/postinstall.sh); [`restart`] after it does no harm.
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
            // `install` of an older version than the one installed does
            // nothing and succeeds, so: install, look, and downgrade if it is
            // still not there.
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

/// The installed version of the package, as the package manager says it.
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

/// Keep each binary as `.prev`, then rename the staged one over it. Both
/// renames are within one directory, so each is atomic; the pair is not, which
/// is what [`put_back`] is for.
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

/// Put back whatever [`swap`] kept.
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

/// Run it; its output goes to the unit's journal.
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

/// To the journal, through the unit's stdout.
#[allow(clippy::print_stdout)]
fn say(line: &str) {
    println!("{line}");
}
