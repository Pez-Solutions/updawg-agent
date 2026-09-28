//! `updawgctl` — the local tool for people who are about to trust this thing.
//!
//! `--print-inventory` is the important one. It shows exactly what would be
//! uploaded, and that output is a promise to the customer: a test asserts it is
//! byte-identical to what the agent actually sends (DAWG-37).
//!
//! Scope note: DAWG-19 wires up the command surface, DAWG-30 implements
//! `enroll`. The rest are implemented alongside the features they expose.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::{fmt::Write as _, sync::Arc, time::SystemTime};
use updawg_agent_core::{
    CONFIG_PATH, STATE_DIR, VERSION,
    config::AgentConfig,
    enroll::{EnrollOptions, Enrolled, Enroller, HttpsEnrollExchange, KEY_FILE},
    inventory::Collected,
    state::LocalState,
};
use updawg_collectors::{PlatformFacts, Root};
use updawg_crypto::{ClientCertificate, PinnedKeys};

#[derive(Debug, Parser)]
#[command(
    name = "updawgctl",
    version = VERSION,
    about = "Local control and inspection for the Updawg agent"
)]
struct Cli {
    #[arg(long, default_value = CONFIG_PATH, env = "UPDAWG_CONFIG")]
    config: String,

    #[arg(long, default_value = STATE_DIR, env = "UPDAWG_STATE_DIR")]
    state_dir: String,

    #[command(flatten)]
    extra_root: extra_root::ExtraRoot,

    #[command(subcommand)]
    command: Command,
}

/// The `--insecure-extra-root` flag, which exists only in a build that asked
/// for it.
///
/// Two definitions of one struct, chosen by feature. The disabled one has no
/// fields, so clap has never heard of the flag and `--insecure-extra-root
/// ca.pem` comes back as "unexpected argument". That is what DAWG-206 asked
/// for: not a flag that refuses, a flag that is not there.
///
/// Flattening it means the rest of this binary calls `load()` once and carries
/// no `#[cfg]` anywhere.
mod extra_root {
    #[cfg(feature = "insecure-extra-root")]
    #[derive(Debug, clap::Args)]
    pub(super) struct ExtraRoot {
        /// PEM certificate authority to trust in addition to the system store.
        ///
        /// For running against a gateway you started yourself. Deliberately
        /// accepts no environment variable: every other option here does, and
        /// this is the one that should not be settable by something inherited.
        #[arg(long = "insecure-extra-root", value_name = "PEM")]
        path: Option<std::path::PathBuf>,
    }

    #[cfg(not(feature = "insecure-extra-root"))]
    #[derive(Debug, clap::Args)]
    pub(super) struct ExtraRoot {}

    impl ExtraRoot {
        /// The PEM to trust, if this build can be told to trust one and was.
        ///
        /// Returns `Ok(None)` in a release build without looking at anything,
        /// because there is nothing to look at.
        #[cfg(feature = "insecure-extra-root")]
        pub(super) fn load(&self) -> anyhow::Result<Option<Vec<u8>>> {
            use anyhow::Context as _;
            let Some(path) = &self.path else {
                return Ok(None);
            };
            let pem = updawg_agent_core::insecure::load_root(path)
                .with_context(|| format!("reading {}", path.display()))?;
            eprintln!("{}", updawg_agent_core::insecure::WARNING);
            eprintln!("!! Trusting: {}", path.display());
            Ok(Some(pem))
        }

        #[cfg(not(feature = "insecure-extra-root"))]
        #[expect(
            clippy::unnecessary_wraps,
            clippy::unused_self,
            reason = "same signature as the build that can be told to trust one"
        )]
        pub(super) fn load(&self) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(None)
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Enroll this host with an organization.
    Enroll {
        /// Enrollment token, shown once in the portal.
        #[arg(long, env = "UPDAWG_TOKEN")]
        token: String,

        /// Replace an existing identity. The current certificate stops working.
        #[arg(long)]
        force: bool,

        /// Accept an organization signing key different from the pinned one.
        ///
        /// Only meaningful with --force, and only correct if you know the
        /// organization rotated its key.
        #[arg(long)]
        accept_new_org_key: bool,
    },
    /// Show enrollment, last check-in and pending jobs.
    Status,
    /// Print exactly what would be uploaded, and upload nothing.
    PrintInventory {
        /// Emit the exact JSON the agent uploads, rather than a summary.
        #[arg(long)]
        json: bool,
    },
    /// Show recent jobs recorded on this host.
    Jobs,
    /// Sign an approved job with a customer-held key (Enterprise).
    Sign {
        /// Path to the job envelope to sign.
        #[arg(long)]
        job: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let state = LocalState::new(&cli.state_dir);

    match cli.command {
        Command::Enroll {
            token,
            force,
            accept_new_org_key,
        } => {
            // Deliberately never echo the token back, not even truncated.
            enroll(
                &cli.config,
                &state,
                &token,
                EnrollOptions {
                    force,
                    accept_new_org_key,
                },
                cli.extra_root.load()?,
            )
            .await?;
        }
        Command::Status => status(&cli, &state)?,
        Command::PrintInventory { json } => print_inventory(&cli.config, json).await?,
        Command::Jobs => jobs(&state)?,
        Command::Sign { .. } => println!("sign: not implemented yet (DAWG-148)"),
    }
    Ok(())
}

async fn enroll(
    config_path: &str,
    state: &LocalState,
    token: &str,
    options: EnrollOptions,
    extra_root: Option<Vec<u8>>,
) -> Result<()> {
    let config = AgentConfig::load(config_path)
        .with_context(|| format!("reading {config_path} for the server address"))?;
    state.ensure().context("preparing the state directory")?;

    let exchange = HttpsEnrollExchange::with_extra_root(&config.server, extra_root)?;
    let enroller = Enroller::new(state, &exchange);

    match enroller.enroll(token, options).await? {
        Enrolled::Already { host_id } => {
            println!("Already enrolled as {host_id}. Nothing to do.");
            println!("Pass --force to replace this host's identity.");
        }
        Enrolled::New { host_id, org_keys } => {
            println!("Enrolled as {host_id}.");
            print_pinned(&org_keys);
        }
        Enrolled::Replaced {
            previous,
            host_id,
            org_keys,
        } => {
            println!("Re-enrolled as {host_id} (was {previous}).");
            println!("The previous certificate is no longer valid.");
            print_pinned(&org_keys);
        }
    }
    Ok(())
}

/// Show what got pinned. This is the line an operator should be able to compare
/// against what the portal shows, which is the only way pinning is checkable by
/// the person it protects.
fn print_pinned(org_keys: &[String]) {
    println!("Pinned organization signing keys:");
    for key in org_keys {
        println!("  {key}");
    }
}

fn status(cli: &Cli, state: &LocalState) -> Result<()> {
    println!("updawgctl {VERSION}");
    println!("config:    {}", cli.config);
    println!("state dir: {}", state.root().display());

    match state.identity().context("reading identity")? {
        None => {
            println!("enrolled:  no");
            println!("           run `updawgctl enroll --token ...`");
        }
        Some(identity) => {
            println!("enrolled:  yes");
            println!("host id:   {}", identity.host_id);
            println!("since:     {}", identity.enrolled_at);
            println!("key file:  {}", state.root().join(KEY_FILE).display());
            match ClientCertificate::from_pem(&identity.certificate) {
                Ok(cert) => {
                    println!("cert:      {} (serial {})", cert.subject(), cert.serial());
                    match cert.remaining(SystemTime::now()) {
                        Some(left) => println!("expires:   in {} days", left.as_secs() / 86_400),
                        // Not a footnote: an expired certificate means every
                        // request is already being refused.
                        None => println!("expires:   EXPIRED — re-enroll with --force"),
                    }
                }
                Err(e) => println!("cert:      UNREADABLE — {e}"),
            }
            match PinnedKeys::from_wire(&identity.org_signing_keys) {
                Ok(pinned) => print_pinned(&pinned.describe()),
                // Worth surfacing rather than hiding: an identity whose pinned
                // keys no longer parse cannot verify a job, and the host would
                // otherwise look healthy until one arrived.
                Err(e) => println!("org keys:  UNUSABLE — {e}"),
            }
        }
    }

    let now = chrono::Utc::now();
    match state.last_checkin() {
        Ok(Some(last)) => println!("{}", describe_checkin(&last, now)),
        Ok(None) => println!("check-in:  none recorded yet (is updawgd running?)"),
        Err(e) => println!("check-in:  UNREADABLE — {e}"),
    }
    match state.pending_reboot() {
        Ok(Some(pending)) => println!(
            "reboot:    pending for job {}, asked for by this agent; it finishes the job when the host is back",
            pending.job.id
        ),
        Ok(None) => {}
        Err(e) => println!("reboot:    record UNREADABLE — {e}"),
    }
    let running: Vec<_> = state
        .job_history()
        .unwrap_or_default()
        .into_iter()
        .filter(|j| j.status == "running" || j.status == "rebooting")
        .collect();
    if running.is_empty() {
        println!("jobs:      none running");
    } else {
        for job in running {
            println!("job:       {} {} ({})", job.id, job.kind, job.status);
        }
    }
    Ok(())
}

/// One line about the last check-in, for a person: when, and whether the
/// gateway answered.
fn describe_checkin(
    last: &updawg_agent_core::state::LastCheckin,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let ago = ago(now - last.at);
    if last.ok {
        format!(
            "check-in:  ok, {ago} ({})",
            last.at.format("%Y-%m-%d %H:%M:%S UTC")
        )
    } else {
        format!(
            "check-in:  FAILED {ago}: {}",
            last.error.as_deref().unwrap_or("no detail")
        )
    }
}

fn ago(d: chrono::Duration) -> String {
    let s = d.num_seconds().max(0);
    match s {
        0..=59 => format!("{s} s ago"),
        60..=3599 => format!("{} min ago", s / 60),
        3600..=86_399 => format!("{} h ago", s / 3600),
        _ => format!("{} days ago", s / 86_400),
    }
}

/// `updawgctl jobs`: the jobs this host has seen lately, newest first.
fn jobs(state: &LocalState) -> Result<()> {
    let history = state.job_history().context("reading the job history")?;
    if history.is_empty() {
        println!("no jobs recorded on this host yet");
        return Ok(());
    }
    for job in history.iter().rev() {
        println!("{}", describe_job(job));
    }
    Ok(())
}

fn describe_job(job: &updawg_agent_core::state::JobRecord) -> String {
    let mut line = format!(
        "{}  {:<10} {:<16} {}",
        job.at.format("%Y-%m-%d %H:%M"),
        job.status,
        job.kind,
        job.id
    );
    if let Some(detail) = &job.detail {
        let _ = write!(line, "\n    {detail}");
    }
    line
}

/// Print exactly what an inventory upload would send, and send nothing.
///
/// **The point is that this is the same value.** It builds the very
/// `InventoryUpload` the agent would PUT and prints that, rather than describing
/// it — an answer to "what does Updawg collect about my servers?" is only worth
/// something if it cannot drift from what is actually collected.
///
/// It deliberately shows the **full** inventory rather than the delta that would
/// really go out, because the question is what Updawg knows, not what changed
/// since Tuesday.
async fn print_inventory(config_path: &str, json: bool) -> Result<()> {
    let backend = updawg_backends::detect().context("finding a package manager on this host")?;
    let facts = Arc::new(PlatformFacts::new(Root::default()));

    // Collection only — no transport, so this works on a host that has never
    // enrolled. Someone evaluating Updawg should be able to see what it would
    // collect before letting it talk to anything.
    let collected = Collected::from_host(backend.as_ref(), facts.as_ref())
        .await
        .context("asking this host what it has")?;
    let upload = collected.upload(None);

    if json {
        // The very bytes the agent sends, not a pretty-printed copy of them
        // (DAWG-37): pipe to `jq` to read it.
        let body = updawg_agent_core::transport::inventory_body(&upload)?;
        return emit(&format!("{}\n", String::from_utf8(body)?));
    }

    let mut out = String::new();
    let server = AgentConfig::load(config_path)
        .map_or_else(|_| "<no configuration>".to_string(), |c| c.server);
    let _ = writeln!(
        out,
        "host      {} (uploads to {server})",
        upload.facts.as_ref().map_or("?", |f| f.hostname.as_str())
    );
    if let Some(f) = &upload.facts {
        let _ = writeln!(
            out,
            "release   {} {} ({})",
            f.distro, f.version_id, f.kernel
        );
        let _ = writeln!(out, "arch      {}", f.arch);
    }
    let _ = writeln!(out, "hash      {}", upload.hash);
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{}",
        plural(upload.packages.added.len(), "package", "installed")
    );
    let _ = writeln!(
        out,
        "{}",
        plural(upload.updates.len(), "update", "available")
    );
    let (_, security) = collected.counts();
    let _ = writeln!(
        out,
        "  {security} of them are a security fix, as this host's package manager sees it"
    );
    let _ = writeln!(
        out,
        "  (what actually counts as a security update is decided server-side, against advisory data)"
    );
    let _ = writeln!(
        out,
        "{}",
        plural(upload.repositories.len(), "repository", "configured")
    );
    let third_party = upload.repositories.iter().filter(|r| r.third_party).count();
    if third_party > 0 {
        let _ = writeln!(
            out,
            "  {third_party} of {} not this distribution's",
            if third_party == 1 {
                "them is"
            } else {
                "them are"
            }
        );
    }
    let _ = writeln!(
        out,
        "{}",
        plural(upload.held_packages.len(), "package", "held")
    );
    for held in &upload.held_packages {
        let _ = writeln!(out, "  {held}");
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Nothing else is collected. `--json` prints the exact request body."
    );
    emit(&out)
}

/// `1 package held`, `2 packages held`, `0 packages held`.
///
/// English, because this output is for a person. "1 packages held" in a tool
/// somebody is reading to decide whether to trust it with their servers is a
/// small thing that reads as carelessness.
fn plural(n: usize, noun: &str, verb: &str) -> String {
    if n == 1 {
        format!("{n} {noun} {verb}")
    } else if let Some(stem) = noun.strip_suffix('y') {
        format!("{n} {stem}ies {verb}")
    } else {
        format!("{n} {noun}s {verb}")
    }
}

/// Write to stdout, and stop quietly if whoever was reading has stopped.
///
/// Rust sets `SIGPIPE` to ignore, so `println!` into a closed pipe **panics** —
/// and `updawgctl print-inventory --json | head` is exactly how somebody will
/// read this. A backtrace where `head` should simply have ended is alarming
/// about nothing.
///
/// The usual fix is to restore the default `SIGPIPE` disposition, which needs
/// `unsafe`. This workspace forbids `unsafe`, and that is worth more than the
/// tidiness — this is the binary a customer audits. So the output is built up
/// and written once, and a broken pipe ends the process the way the signal would
/// have.
fn emit(text: &str) -> Result<()> {
    use std::io::Write as _;
    match std::io::stdout().write_all(text.as_bytes()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => std::process::exit(0),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{describe_checkin, describe_job, plural};

    #[test]
    fn a_check_in_says_when_and_whether_it_worked() {
        use updawg_agent_core::state::LastCheckin;
        let now = chrono::Utc::now();
        let ok = LastCheckin {
            at: now - chrono::Duration::seconds(42),
            ok: true,
            error: None,
        };
        assert!(describe_checkin(&ok, now).starts_with("check-in:  ok, 42 s ago"));
        let failed = LastCheckin {
            at: now - chrono::Duration::minutes(3),
            ok: false,
            error: Some("could not reach https://agents.updawg.net".into()),
        };
        assert_eq!(
            describe_checkin(&failed, now),
            "check-in:  FAILED 3 min ago: could not reach https://agents.updawg.net"
        );
    }

    #[test]
    fn a_refused_job_says_why_under_it() {
        use updawg_agent_core::state::JobRecord;
        let line = describe_job(&JobRecord {
            id: "job_01".into(),
            kind: "apply_updates".into(),
            status: "refused".into(),
            at: chrono::DateTime::parse_from_rfc3339("2026-09-28T18:00:31Z")
                .unwrap()
                .into(),
            detail: Some("this agent is in observe mode".into()),
        });
        assert_eq!(
            line,
            "2026-09-28 18:00  refused    apply_updates    job_01\n    this agent is in observe mode"
        );
    }

    #[test]
    fn counts_read_as_english() {
        // This output exists to be read by somebody deciding whether to trust
        // Updawg with their servers. "1 packages held" reads as carelessness.
        assert_eq!(plural(1, "package", "held"), "1 package held");
        assert_eq!(plural(2, "package", "held"), "2 packages held");
        assert_eq!(plural(0, "package", "held"), "0 packages held");
    }

    #[test]
    fn a_noun_ending_in_y_pluralises_properly() {
        assert_eq!(
            plural(1, "repository", "configured"),
            "1 repository configured"
        );
        assert_eq!(
            plural(3, "repository", "configured"),
            "3 repositories configured"
        );
    }
}
