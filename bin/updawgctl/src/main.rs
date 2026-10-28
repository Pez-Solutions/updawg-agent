//! `updawgctl`, the local command-line tool for the agent.
//!
//! `print-inventory` shows exactly what would be uploaded; it goes through the
//! same code path as the agent's own upload.

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

mod policy;
mod server;
mod sign;

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

/// The `--insecure-extra-root` flag, only present in builds with the
/// `insecure-extra-root` feature. Same arrangement as in `updawgd`.
mod extra_root {
    #[cfg(feature = "insecure-extra-root")]
    #[derive(Debug, clap::Args)]
    pub(super) struct ExtraRoot {
        /// PEM certificate authority to trust in addition to the system store.
        ///
        /// For running against a gateway you started yourself. Unlike the other
        /// options, this can't be set from the environment.
        #[arg(long = "insecure-extra-root", value_name = "PEM")]
        path: Option<std::path::PathBuf>,
    }

    #[cfg(not(feature = "insecure-extra-root"))]
    #[derive(Debug, clap::Args)]
    pub(super) struct ExtraRoot {}

    impl ExtraRoot {
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

        /// The gateway to report to, for an organization outside the EU.
        /// Written to the config as `server` before enrolling. The portal's
        /// install command sets it when needed.
        #[arg(long, env = "UPDAWG_SERVER")]
        server: Option<String>,

        /// Replace an existing identity. The current certificate stops working.
        /// With --server, also move a host that reports somewhere else.
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
    /// Run the preflight checks here, and change nothing.
    ///
    /// Without --release it checks the host as a package change would; with
    /// it, as an upgrade to that release (`14`, `24.04` or a codename),
    /// including whether each third-party repository publishes for it.
    Preflight {
        /// The release to check an upgrade to.
        #[arg(long)]
        release: Option<String>,
    },
    /// Make an organization signing key for your organization to hold
    /// itself (Enterprise).
    ///
    /// Run this where the key will live, not on a managed host. It writes the
    /// private key to --out, readable only by you, and prints the public half:
    /// give that to the portal, and to each host as `trusted_org_key` in
    /// `/etc/updawg/agent.toml` (or `UPDAWG_ORG_KEY` for the installer). Updawg
    /// never sees the private key, so it cannot be recovered if lost.
    Keygen {
        /// Where to write the private key. Never overwritten.
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Renew this host's certificate at the agent's next check-in, picking up
    /// any signing key the organization has rotated to. The gateway already
    /// asks hosts to do this after a rotation; this skips the wait.
    Renew,
    /// Prove you hold an organization key, for handing signing over to it
    /// in the portal (Enterprise). Prints one line to paste.
    ProveKey {
        /// Your organization's id, `org_...`, as the portal shows it.
        #[arg(long)]
        org: String,
        #[command(flatten)]
        source: sign::KeySource,
    },
    /// Endorse the next key with your active one, to rotate a key your
    /// organization holds (Enterprise). Prints one line to paste, along with
    /// the output of `prove-key` for the next key.
    Endorse {
        /// Your organization's id, `org_...`, as the portal shows it.
        #[arg(long)]
        org: String,
        /// Your active key's id, `sk_...`, as the portal lists it.
        #[arg(long)]
        from: String,
        /// The next key's public half, as `keygen` printed it.
        #[arg(long)]
        next_public_key: String,
        /// Where your active key is.
        #[command(flatten)]
        source: sign::KeySource,
    },
    /// Sign the jobs waiting for your organization's own key (Enterprise).
    ///
    /// Shows what each job will do, decoded from the bytes being signed, and
    /// asks before signing it. Needs an API token with the `read` and
    /// `approve` scopes in `UPDAWG_API_TOKEN`. Run it by hand, or on a
    /// schedule with --yes.
    Sign {
        /// Your organization's slug.
        #[arg(long, env = "UPDAWG_ORG")]
        org: String,
        /// The Updawg API.
        #[arg(long, env = "UPDAWG_API", default_value = "https://api.updawg.net")]
        api: String,
        /// The API token. Prefer the environment: an argument is visible to
        /// every user on this machine in `ps`.
        #[arg(long, env = "UPDAWG_API_TOKEN", hide_env_values = true)]
        token: String,
        /// Sign every waiting job without asking.
        #[arg(long)]
        yes: bool,
        /// Sign only what this policy file allows; anything else is left for a
        /// person. Meant for --yes on a schedule.
        #[arg(long)]
        policy: Option<std::path::PathBuf>,
        #[command(flatten)]
        source: sign::KeySource,
    },
    /// Carry out the self-update the agent prepared. The agent starts this in
    /// its own transient systemd unit; not for running by hand.
    #[command(hide = true)]
    SelfUpdateRun,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let state = LocalState::new(&cli.state_dir);

    match cli.command {
        Command::Enroll {
            token,
            server,
            force,
            accept_new_org_key,
        } => {
            if let Some(server) = server {
                let current = AgentConfig::load(&cli.config)
                    .with_context(|| format!("reading {}", cli.config))?
                    .server;
                if server::point_at(&cli.config, &current, &server, force)? {
                    println!(
                        "This host reports to {} from now on.",
                        server::origin(&server)?
                    );
                }
            }
            // never echo the token, not even truncated
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
        Command::Preflight { release } => preflight(&cli.config, release).await?,
        Command::Keygen { out } => keygen(&out)?,
        Command::Renew => {
            if !state.is_enrolled() {
                anyhow::bail!("this host is not enrolled");
            }
            state
                .request_renewal()
                .context("asking the agent to renew (run as root)")?;
            println!(
                "updawgd renews this host's certificate at its next check-in, within about a minute. \
                 `updawgctl status` shows the keys it pins afterwards."
            );
        }
        Command::ProveKey { org, source } => sign::prove_key(&org, &source)?,
        Command::Endorse {
            org,
            from,
            next_public_key,
            source,
        } => sign::endorse(&org, &from, &next_public_key, &source)?,
        Command::Sign {
            org,
            api,
            token,
            yes,
            policy,
            source,
        } => {
            let policy = policy
                .as_deref()
                .map(policy::SignPolicy::load)
                .transpose()?;
            sign::sign(
                sign::SignOptions {
                    api,
                    org,
                    token,
                    yes,
                    policy,
                },
                &source,
            )
            .await?;
        }
        Command::SelfUpdateRun => updawg_agent_core::self_update::helper::run(&state)?,
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

    let trusted = config
        .trusted_org_key()
        .with_context(|| format!("reading trusted_org_key from {config_path}"))?;

    let exchange = HttpsEnrollExchange::with_extra_root(&config.server, extra_root)?;
    let enroller = Enroller::new(state, &exchange).with_trusted_org_key(trusted);

    match enroller.enroll(token, options).await? {
        Enrolled::Already { host_id } => {
            println!("Already enrolled as {host_id}. Nothing to do.");
            println!("Pass --force to replace this host's identity.");
        }
        Enrolled::New { host_id, org_keys } => {
            println!("Enrolled as {host_id}.");
            print_pinned(&org_keys);
            restart_daemon();
        }
        Enrolled::Replaced {
            previous,
            host_id,
            org_keys,
        } => {
            println!("Re-enrolled as {host_id} (was {previous}).");
            println!("The previous certificate is no longer valid.");
            print_pinned(&org_keys);
            restart_daemon();
        }
    }
    Ok(())
}

fn keygen(out: &std::path::Path) -> Result<()> {
    let key = updawg_crypto::OrgKeyPair::generate().context("generating a key")?;
    key.save_new(out)
        .with_context(|| format!("writing {}", out.display()))?;
    println!("Wrote the private key to {} (mode 0600).", out.display());
    println!("Keep it safe and keep a copy: if it is lost, every host has to be re-enrolled.");
    println!();
    println!("Public key (for the portal, and trusted_org_key on each host):");
    println!("  {}", key.public_spki_base64());
    println!("Fingerprint: {}", key.public().fingerprint());
    Ok(())
}

/// Restarts updawgd so it picks up the new identity.
///
/// The daemon reads its identity only at startup, and one that started
/// unenrolled keeps running without checking in, so a host installed from a
/// package and then enrolled would otherwise never check in. Only restarts a
/// daemon systemd is running; a stopped one stays stopped.
fn restart_daemon() {
    const UNIT: &str = "updawgd.service";
    let running = std::path::Path::new("/run/systemd/system").exists()
        && std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", UNIT])
            .status()
            .is_ok_and(|s| s.success());
    if !running {
        println!("updawgd is not running here; it uses this identity when it next starts.");
        return;
    }
    match std::process::Command::new("systemctl")
        .args(["restart", UNIT])
        .status()
    {
        Ok(s) if s.success() => println!("Restarted updawgd, which now checks in as this host."),
        _ => println!(
            "Could not restart updawgd: run `systemctl restart updawgd` to use this identity."
        ),
    }
}

/// Printed so the operator can compare the pinned keys with the portal.
fn print_pinned(org_keys: &[String]) {
    println!("Pinned organization signing keys:");
    for key in org_keys {
        println!("  {key}");
    }
}

/// One line into a buffer that is emitted whole (see [`emit`]).
macro_rules! say {
    ($out:ident, $($arg:tt)*) => {{
        let _ = writeln!($out, $($arg)*);
    }};
}

fn status(cli: &Cli, state: &LocalState) -> Result<()> {
    // buffered so `updawgctl status | head` doesn't panic on the closed pipe
    let mut out = String::new();
    say!(out, "updawgctl {VERSION}");
    say!(out, "config:    {}", cli.config);
    say!(out, "state dir: {}", state.root().display());

    match state.identity().context("reading identity")? {
        None => {
            say!(out, "enrolled:  no");
            say!(out, "           run `updawgctl enroll --token ...`");
        }
        Some(identity) => {
            say!(out, "enrolled:  yes");
            say!(out, "host id:   {}", identity.host_id);
            say!(out, "since:     {}", identity.enrolled_at);
            say!(out, "key file:  {}", state.root().join(KEY_FILE).display());
            match ClientCertificate::from_pem(&identity.certificate) {
                Ok(cert) => {
                    say!(
                        out,
                        "cert:      {} (serial {})",
                        cert.subject(),
                        cert.serial()
                    );
                    match cert.remaining(SystemTime::now()) {
                        Some(left) => say!(out, "expires:   in {} days", left.as_secs() / 86_400),
                        None => say!(out, "expires:   EXPIRED, re-enroll with --force"),
                    }
                }
                Err(e) => say!(out, "cert:      UNREADABLE: {e}"),
            }
            let trusted = AgentConfig::load(&cli.config)
                .ok()
                .and_then(|c| c.trusted_org_key().ok().flatten());
            match PinnedKeys::from_wire(&identity.org_signing_keys) {
                Ok(pinned) => {
                    say!(out, "Pinned organization signing keys:");
                    for key in pinned.describe() {
                        say!(out, "  {key}");
                    }
                    // Configured but not pinned means the host enrolled before
                    // trusted_org_key was set. It picks the key up at its next
                    // renewal once the organization has taken over signing.
                    if let Some(trusted) = trusted {
                        if pinned.contains_material(&trusted) {
                            say!(out, "trusted:   {} (pinned)", trusted.fingerprint());
                        } else {
                            say!(
                                out,
                                "trusted:   {} NOT PINNED YET: this host enrolled before \
                                 trusted_org_key was set. It follows the key at its next \
                                 certificate renewal once your organization has taken over \
                                 signing; `updawgctl enroll --force` pins it now",
                                trusted.fingerprint()
                            );
                        }
                    }
                }
                // no job can verify, and the host would otherwise look healthy
                Err(e) => say!(out, "org keys:  UNUSABLE: {e}"),
            }
        }
    }

    let now = chrono::Utc::now();
    match state.last_checkin() {
        Ok(Some(last)) => say!(out, "{}", describe_checkin(&last, now)),
        Ok(None) if !state.is_enrolled() => say!(out, "check-in:  none: this host is not enrolled"),
        Ok(None) => say!(out, "check-in:  none recorded yet (is updawgd running?)"),
        Err(e) => say!(out, "check-in:  UNREADABLE: {e}"),
    }
    match state.pending_reboot() {
        Ok(Some(pending)) => say!(
            out,
            "reboot:    pending for job {}, asked for by this agent; it finishes the job when the host is back",
            pending.job.id
        ),
        Ok(None) => {}
        Err(e) => say!(out, "reboot:    record UNREADABLE: {e}"),
    }
    let running: Vec<_> = state
        .job_history()
        .unwrap_or_default()
        .into_iter()
        .filter(|j| j.status == "running" || j.status == "rebooting")
        .collect();
    if running.is_empty() {
        say!(out, "jobs:      none running");
    } else {
        for job in running {
            say!(out, "job:       {} {} ({})", job.id, job.kind, job.status);
        }
    }
    emit(&out)
}

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

/// Newest first.
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

/// Prints what an inventory upload would send, and sends nothing.
///
/// Builds the same `InventoryUpload` the agent would PUT, so the output can't
/// drift from what is actually collected. Always the full inventory rather
/// than a delta.
async fn print_inventory(config_path: &str, json: bool) -> Result<()> {
    let backend = updawg_backends::detect().context("finding a package manager on this host")?;
    let facts = Arc::new(PlatformFacts::new(Root::default()));

    // no transport, so this works on a host that has never enrolled
    let collected = Collected::from_host(backend.as_ref(), facts.as_ref())
        .await
        .context("asking this host what it has")?;
    let upload = collected.upload(None);

    if json {
        // the exact bytes the agent sends, not pretty-printed
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
fn plural(n: usize, noun: &str, verb: &str) -> String {
    if n == 1 {
        format!("{n} {noun} {verb}")
    } else if let Some(stem) = noun.strip_suffix('y') {
        format!("{n} {stem}ies {verb}")
    } else {
        format!("{n} {noun}s {verb}")
    }
}

/// The checks a `run_preflight` job would report, run here and printed.
async fn preflight(config_path: &str, release: Option<String>) -> Result<()> {
    let backend = updawg_backends::detect().ok();
    let wanted = AgentConfig::load(config_path).map_or(updawg_snapshots::Provider::Auto, |c| {
        c.snapshots.provider.provider()
    });
    let snapshots = updawg_snapshots::detect(wanted)
        .await
        .map(|p| p.provider().name().to_owned());
    // only Debian and Ubuntu have a file for this
    let reboot_now = if std::path::Path::new("/run/reboot-required").exists() {
        updawg_protocol::RebootRequired::Yes
    } else {
        updawg_protocol::RebootRequired::Unknown
    };
    let job = updawg_protocol::job::Preflight {
        target_release: release,
        packages: vec![],
    };
    let facts =
        updawg_agent_core::preflight::gather(&job, backend.as_deref(), snapshots, reboot_now).await;
    let mut out = String::new();
    for c in updawg_agent_core::preflight::evaluate(&facts) {
        let status = match c.status {
            updawg_protocol::CheckStatus::Pass => "pass",
            updawg_protocol::CheckStatus::Warn => "WARN",
            updawg_protocol::CheckStatus::Fail => "FAIL",
        };
        let _ = writeln!(out, "{status:<5} {:<19} {}", c.name, c.summary);
        for item in &c.items {
            let _ = writeln!(out, "      {:<19} {item}", "");
        }
    }
    emit(&out)
}

/// Writes to stdout, exiting quietly on a broken pipe.
///
/// Rust ignores `SIGPIPE`, so `println!` into a closed pipe panics (think
/// `print-inventory --json | head`). Restoring the default disposition needs
/// `unsafe`, which the workspace forbids, so output is buffered and written
/// once here instead.
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
            agent: None,
        };
        assert!(describe_checkin(&ok, now).starts_with("check-in:  ok, 42 s ago"));
        let failed = LastCheckin {
            at: now - chrono::Duration::minutes(3),
            ok: false,
            error: Some("could not reach https://agents.updawg.net".into()),
            agent: None,
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
