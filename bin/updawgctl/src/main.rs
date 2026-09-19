//! `updawgctl` — the local tool for people who are about to trust this thing.
//!
//! `--print-inventory` is the important one. It shows exactly what would be
//! uploaded, and that output is a promise to the customer: a test asserts it is
//! byte-identical to what the agent actually sends (DAWG-37).
//!
//! Scope note: DAWG-19 wires up the command surface. The subcommands are
//! implemented alongside the features they expose.

use anyhow::Result;
use clap::{Parser, Subcommand};
use updawg_agent_core::{CONFIG_PATH, STATE_DIR, VERSION, state::LocalState};

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

// Returns Result because the subcommands will fail for real once they are
// implemented; today none of them can.
#[allow(clippy::unnecessary_wraps)]
fn main() -> Result<()> {
    let cli = Cli::parse();
    let state = LocalState::new(&cli.state_dir);

    match cli.command {
        Command::Enroll { .. } => {
            // Deliberately never echo the token back, not even truncated.
            println!("enroll: not implemented yet (DAWG-30)");
        }
        Command::Status => {
            println!("updawgctl {VERSION}");
            println!("config:    {}", cli.config);
            println!("state dir: {}", state.root().display());
            println!(
                "enrolled:  {}",
                if state.is_enrolled() { "yes" } else { "no" }
            );
            println!("status:    not implemented yet (DAWG-29)");
        }
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
