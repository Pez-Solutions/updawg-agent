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
use std::time::SystemTime;
use updawg_agent_core::{
    CONFIG_PATH, STATE_DIR, VERSION,
    config::AgentConfig,
    enroll::{EnrollOptions, Enrolled, Enroller, HttpsEnrollExchange, KEY_FILE},
    state::LocalState,
};
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

    #[command(subcommand)]
    command: Command,
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
        /// Emit JSON rather than a human-readable summary.
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
            )
            .await?;
        }
        Command::Status => status(&cli, &state)?,
        Command::PrintInventory { json } => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "error": "not implemented yet (DAWG-36)" })
                );
            } else {
                println!("print-inventory: not implemented yet (DAWG-36)");
            }
        }
        Command::Jobs => println!("jobs: not implemented yet (DAWG-29)"),
        Command::Sign { .. } => println!("sign: not implemented yet (DAWG-148)"),
    }
    Ok(())
}

async fn enroll(
    config_path: &str,
    state: &LocalState,
    token: &str,
    options: EnrollOptions,
) -> Result<()> {
    let config = AgentConfig::load(config_path)
        .with_context(|| format!("reading {config_path} for the server address"))?;
    state.ensure().context("preparing the state directory")?;

    let exchange = HttpsEnrollExchange::new(&config.server)?;
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

    println!("status:    check-in state not implemented yet (DAWG-32)");
    Ok(())
}
