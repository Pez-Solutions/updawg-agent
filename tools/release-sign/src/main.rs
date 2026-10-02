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
//! updawg-release-sign --key <version> manifest --channel beta --version 0.1.0-… \
//!     --dir bin/ --base-url https://pkg.updawg.net/bin/pool/0.1.0-… > beta.json
//! ```

mod der;
mod kms;
mod manifest;
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
    /// A channel's signed release manifest (DAWG-46): the agent's binaries in
    /// DIR, as `<target>/updawgd` and `<target>/updawgctl`, served from
    /// `<base-url>/<target>/<name>`. Signed as raw `RSASSA-PKCS1-v1_5`
    /// rather than OpenPGP: the agent verifies it with the key compiled into
    /// it, and has no OpenPGP parser to want.
    Manifest {
        #[arg(long)]
        channel: String,
        /// The build, as its packages name it.
        #[arg(long)]
        version: String,
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        base_url: String,
    },
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
        Command::Manifest {
            channel,
            version,
            dir,
            base_url,
        } => manifest::build(&kms, &channel, &version, &dir, &base_url)?,
    };
    print!("{out}");
    Ok(())
}

#[cfg(test)]
mod tests;
