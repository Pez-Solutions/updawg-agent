//! `updawg-release-sign`: OpenPGP signatures for pkg.updawg.net's apt and dnf
//! repositories, made by a Cloud KMS key (DAWG-45, decided 2026-09-30).
//!
//! The key never leaves KMS. Release CI holds an hour-long credential that
//! may ask it for signatures, and nothing else: not the key, and not another
//! key. See `openpgp` for why this is not an OpenPGP library.
//!
//! ```text
//! updawg-release-sign --key <version> public-key --user-id "…" > updawg.asc
//! updawg-release-sign --key <version> detach Release > Release.gpg
//! updawg-release-sign --key <version> clear Release > InRelease
//! ```

mod der;
mod kms;
mod openpgp;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
struct Args {
    /// The Cloud KMS key version:
    /// `projects/…/locations/…/keyRings/…/cryptoKeys/…/cryptoKeyVersions/N`.
    #[arg(long, env = "UPDAWG_RELEASE_KEY")]
    key: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// The public key, armored, certified at the key's creation time.
    PublicKey {
        #[arg(long, default_value = "Updawg packages <packages@updawg.net>")]
        user_id: String,
    },
    /// An armored detached signature of FILE: Release.gpg, repomd.xml.asc.
    Detach { file: PathBuf },
    /// FILE as a cleartext-signed message: InRelease.
    Clear { file: PathBuf },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let kms = kms::Kms::new(args.key)?;
    let key = kms.public_key()?;
    let now = u32::try_from(chrono::Utc::now().timestamp())?;
    let out = match args.command {
        Command::PublicKey { user_id } => key.export(&user_id, &kms, key.created)?,
        Command::Detach { file } => {
            let data = std::fs::read(&file).with_context(|| file.display().to_string())?;
            key.detach_sign(&data, &kms, now)?
        }
        Command::Clear { file } => {
            let text =
                std::fs::read_to_string(&file).with_context(|| file.display().to_string())?;
            key.clear_sign(&text, &kms, now)?
        }
    };
    print!("{out}");
    Ok(())
}

#[cfg(test)]
mod tests;
