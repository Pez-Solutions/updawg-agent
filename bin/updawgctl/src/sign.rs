//! `updawgctl prove-key` and `updawgctl sign`: the organization's side of a
//! customer-held signing key (DAWG-157, ADR 0006).
//!
//! Run where the key lives — a workstation, a CI job, a box in front of an
//! HSM — never on a managed host. Neither command needs an enrolled agent.
//!
//! # What `sign` shows is decoded from what it signs
//!
//! Each job is described from its own document, parsed with the same
//! protocol crate an agent uses, and the signature covers
//! [`Job::signing_bytes`] of that same parse — exactly what every host will
//! verify. Nothing the server says *about* a job (a proposal title, a host's
//! name) decides what gets signed; the hostname is shown for orientation and
//! labelled as the server's.

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use std::{
    io::{BufRead as _, Write as _},
    path::PathBuf,
    process::{Command, Stdio},
};
use updawg_crypto::{OrgKeyPair, OrgPublicKey};
use updawg_protocol::{
    EndorsedKey, Endorsement, EndorsementStatement, Job, OrgId, SigningKeyId,
    job::{JobSpec, PackagePin},
};

/// Where the signature comes from.
#[derive(Debug, clap::Args)]
pub(crate) struct KeySource {
    /// The private key file `updawgctl keygen` wrote.
    #[arg(long, conflicts_with = "command")]
    key: Option<PathBuf>,

    /// Sign with your own HSM or KMS instead: run through `sh -c`, given the
    /// exact bytes to sign on stdin, and expected to print the Ed25519
    /// signature on stdout (64 raw bytes, or base64). Needs --public-key.
    #[arg(long, requires = "public_key")]
    command: Option<String>,

    /// The public half of the key --command signs with, as `keygen` prints
    /// it. Every signature is checked against it before it leaves here.
    #[arg(long)]
    public_key: Option<String>,
}

impl KeySource {
    fn signer(&self) -> Result<Signer> {
        match (&self.key, &self.command) {
            (Some(path), None) => {
                let key = OrgKeyPair::load(path)
                    .with_context(|| format!("reading the key in {}", path.display()))?;
                Ok(Signer {
                    public: key.public(),
                    how: How::File(Box::new(key)),
                })
            }
            (None, Some(command)) => {
                let public = self
                    .public_key
                    .as_deref()
                    .context("--public-key is required")?;
                Ok(Signer {
                    public: OrgPublicKey::parse_configured("--public-key", public)?,
                    how: How::Command(command.clone()),
                })
            }
            _ => bail!("say where the key is: --key FILE, or --command CMD --public-key KEY"),
        }
    }
}

#[derive(Debug)]
enum How {
    File(Box<OrgKeyPair>),
    Command(String),
}

#[derive(Debug)]
struct Signer {
    public: OrgPublicKey,
    how: How,
}

impl Signer {
    /// Sign `message` and check the result against the public half, so a
    /// misbehaving `--command` fails here rather than on every host.
    fn sign(&self, message: &[u8]) -> Result<String> {
        let signature = match &self.how {
            How::File(key) => key.sign(message),
            How::Command(command) => run_signer(command, message)?,
        };
        self.public
            .verify(message, &signature)
            .context("the signature does not verify under the key's public half")?;
        Ok(base64::engine::general_purpose::STANDARD.encode(signature))
    }
}

fn run_signer(command: &str, message: &[u8]) -> Result<Vec<u8>> {
    let mut child = Command::new("sh")
        .args(["-c", command])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("running `{command}`"))?;
    child
        .stdin
        .take()
        .context("no stdin")?
        .write_all(message)
        .context("handing the bytes to the signing command")?;
    let output = child
        .wait_with_output()
        .context("waiting for the signing command")?;
    if !output.status.success() {
        bail!("`{command}` failed: {}", output.status);
    }
    if output.stdout.len() == 64 {
        return Ok(output.stdout);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .context("the signing command printed neither 64 raw bytes nor base64")?;
    if decoded.len() != 64 {
        bail!(
            "the signing command printed {} bytes; an Ed25519 signature is 64",
            decoded.len()
        );
    }
    Ok(decoded)
}

/* ------------------------------------------------------------- prove-key */

/// `updawgctl prove-key --org org_… (--key FILE | --command … --public-key …)`.
///
/// Prints the proof the portal asks for before it hands signing over to this
/// key: the key endorsing **itself**, for this organization, now. It shows the
/// key's holder can sign with it — a hand-over to a key nobody holds cannot be
/// undone — and it is useless as an endorsement, because an agent only
/// follows one from a key it already trusts.
pub(crate) fn prove_key(org: &str, source: &KeySource) -> Result<()> {
    if !org.starts_with("org_") {
        bail!("--org is your organization's id, `org_…`, as the portal shows it");
    }
    let signer = source.signer()?;
    let me = EndorsedKey {
        key_id: SigningKeyId::new("sk_proposed"),
        public_key: signer.public.to_wire(),
    };
    let statement = EndorsementStatement {
        org_id: OrgId::new(org),
        issued_at: chrono::Utc::now(),
        previous_key: me.clone(),
        new_key: me,
    };
    let signature = signer.sign(&statement.signing_bytes()?)?;
    let proof = Endorsement::new(&statement, signature)?;
    println!("{}", serde_json::to_string(&proof)?);
    eprintln!(
        "Paste the line above into the portal (Settings → Signing keys) within 24 hours. \
         Key fingerprint: {}",
        signer.public.fingerprint()
    );
    Ok(())
}

/* ------------------------------------------------------------------ sign */

#[derive(Debug, serde::Deserialize)]
struct Unsigned {
    jobs: Vec<UnsignedJob>,
}

#[derive(Debug, serde::Deserialize)]
struct UnsignedJob {
    id: String,
    host: ListedHost,
    #[serde(default)]
    proposal_number: Option<i64>,
    document: String,
}

#[derive(Debug, serde::Deserialize)]
struct ListedHost {
    hostname: String,
}

#[derive(Debug, serde::Deserialize)]
struct ListedKey {
    id: String,
    public_key: String,
}

#[derive(Debug)]
pub(crate) struct SignOptions {
    pub(crate) api: String,
    pub(crate) org: String,
    pub(crate) token: String,
    pub(crate) yes: bool,
}

/// `updawgctl sign`: every job waiting for this key, shown, confirmed,
/// signed and handed back.
pub(crate) async fn sign(options: SignOptions, source: &KeySource) -> Result<()> {
    let signer = source.signer()?;
    let api = Api::new(&options)?;

    // Which id the organization knows this key by. A job naming another key
    // is for another key: signing it with this one is a signature every host
    // refuses.
    let keys: Vec<ListedKey> = api.get("signing-keys").await?;
    let mine = keys
        .iter()
        .find(|k| OrgPublicKey::parse(&k.id, &k.public_key).is_ok_and(|key| key == signer.public))
        .map(|k| k.id.clone())
        .with_context(|| {
            format!(
                "{} is not one of {}'s signing keys; hand signing over to it in the portal first",
                signer.public.fingerprint(),
                options.org
            )
        })?;

    let unsigned: Unsigned = api.get("jobs/unsigned").await?;
    if unsigned.jobs.is_empty() {
        println!("Nothing is waiting for a signature.");
        return Ok(());
    }

    let (mut done, mut skipped) = (0, 0);
    for listed in &unsigned.jobs {
        let job: Job = serde_json::from_str(&listed.document)
            .with_context(|| format!("{} is not a job this build can read", listed.id))?;
        if job.id.as_str() != listed.id {
            bail!(
                "the server listed {} with a document for {}; stopping",
                listed.id,
                job.id
            );
        }
        println!();
        print!(
            "{}",
            describe(&job, &listed.host.hostname, listed.proposal_number)
        );
        if job.key_id.as_str() != mine {
            println!("  skipped: it names {}, not this key ({mine})", job.key_id);
            skipped += 1;
            continue;
        }
        if !options.yes && !confirm("Sign this job?")? {
            skipped += 1;
            continue;
        }
        let signature = signer.sign(&job.signing_bytes()?)?;
        api.post_signature(&listed.id, &signature).await?;
        println!("  signed: queued for its host");
        done += 1;
    }
    println!();
    println!("{done} signed, {skipped} left waiting.");
    Ok(())
}

/// What a job will do, from its document.
fn describe(job: &Job, hostname: &str, proposal: Option<i64>) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "{} for {}", job.id, job.host_id);
    let _ = writeln!(out, "  host (as the server names it): {hostname}");
    if let Some(number) = proposal {
        let _ = writeln!(out, "  proposal: #{number}");
    }
    match &job.spec {
        JobSpec::RefreshInventory => {
            let _ = writeln!(out, "  refresh the inventory");
        }
        JobSpec::RunPreflight(p) => {
            let _ = writeln!(out, "  run preflight checks, changing nothing");
            if let Some(release) = &p.target_release {
                let _ = writeln!(out, "    for an upgrade to {release}");
            }
            pins(&mut out, &p.packages);
        }
        JobSpec::ApplyUpdates(a) => {
            let _ = writeln!(
                out,
                "  install exactly these versions (snapshot: {}, reboot: {}):",
                word(&a.snapshot),
                word(&a.reboot)
            );
            pins(&mut out, &a.packages);
        }
        JobSpec::DistUpgrade(d) => {
            let _ = writeln!(
                out,
                "  upgrade the distribution to {} (snapshot: {}, reboot: {})",
                d.target_release,
                word(&d.snapshot),
                word(&d.reboot)
            );
        }
        JobSpec::Reboot(r) => {
            let _ = writeln!(out, "  reboot ({})", word(&r.policy));
        }
        JobSpec::Snapshot(_) => {
            let _ = writeln!(out, "  take a snapshot");
        }
        JobSpec::Rollback(r) => {
            let _ = writeln!(out, "  roll back to snapshot {}", r.snapshot_id);
        }
        JobSpec::SelfUpdate(s) => {
            let _ = writeln!(
                out,
                "  update the agent to {} ({} channel)",
                s.version,
                word(&s.channel)
            );
        }
    }
    if let Some(not_before) = job.not_before {
        let _ = writeln!(out, "  not before {not_before}");
    }
    let _ = writeln!(out, "  expires {}", job.expires_at);
    out
}

fn pins(out: &mut String, packages: &[PackagePin]) {
    use std::fmt::Write as _;
    for p in packages {
        let _ = writeln!(out, "    {} ({}) {} -> {}", p.name, p.arch, p.from, p.to);
    }
}

/// An enum's wire spelling, which is what the portal shows too.
fn word<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "?".to_owned())
}

fn confirm(question: &str) -> Result<bool> {
    print!("{question} [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

#[derive(Debug)]
struct Api {
    base: String,
    token: String,
    client: reqwest::Client,
}

impl Api {
    fn new(options: &SignOptions) -> Result<Self> {
        if !options.api.starts_with("https://") && !options.api.starts_with("http://127.0.0.1") {
            bail!("--api must be https");
        }
        Ok(Self {
            base: format!(
                "{}/v1/orgs/{}",
                options.api.trim_end_matches('/'),
                options.org
            ),
            token: options.token.clone(),
            client: reqwest::Client::builder()
                .user_agent(concat!("updawgctl/", env!("CARGO_PKG_VERSION")))
                .build()?,
        })
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let response = self
            .client
            .get(format!("{}/{path}", self.base))
            .bearer_auth(&self.token)
            .send()
            .await
            .with_context(|| format!("asking for {path}"))?;
        let status = response.status();
        if !status.is_success() {
            bail!(
                "{path}: {status}: {}",
                response.text().await.unwrap_or_default()
            );
        }
        response
            .json()
            .await
            .with_context(|| format!("reading {path}"))
    }

    async fn post_signature(&self, job: &str, signature: &str) -> Result<()> {
        let response = self
            .client
            .post(format!("{}/jobs/{job}/signature", self.base))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "signature": signature }))
            .send()
            .await
            .with_context(|| format!("handing back {job}'s signature"))?;
        let status = response.status();
        if !status.is_success() {
            bail!(
                "{job}: the server refused the signature ({status}): {}",
                response.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use updawg_protocol::job::ApplyUpdates;

    fn job() -> Job {
        Job {
            id: updawg_protocol::JobId::new("job_1"),
            host_id: updawg_protocol::HostId::new("hst_1"),
            spec: JobSpec::ApplyUpdates(ApplyUpdates {
                packages: vec![PackagePin {
                    name: "openssl".into(),
                    arch: "amd64".into(),
                    from: "3.5.1-1".into(),
                    to: "3.5.1-2".into(),
                }],
                ..ApplyUpdates::default()
            }),
            not_before: None,
            expires_at: "2099-01-01T00:00:00Z".parse().unwrap(),
            key_id: SigningKeyId::new("sk_customer"),
            signature: String::new(),
        }
    }

    #[test]
    fn a_job_is_described_from_its_document() {
        let shown = describe(&job(), "web-03", Some(142));
        assert!(
            shown.contains("openssl (amd64) 3.5.1-1 -> 3.5.1-2"),
            "{shown}"
        );
        assert!(shown.contains("reboot: never"), "{shown}");
        assert!(shown.contains("#142"), "{shown}");
    }

    /// What `sign` produces is what a host checks: a signature over
    /// `signing_bytes` that the pinned key verifies.
    #[test]
    fn a_signature_from_a_key_file_verifies_as_a_host_checks_it() {
        let key = OrgKeyPair::generate().unwrap();
        let signer = Signer {
            public: key.public(),
            how: How::File(Box::new(key)),
        };
        let mut job = job();
        job.signature = signer.sign(&job.signing_bytes().unwrap()).unwrap();

        let pinned = updawg_crypto::PinnedKeys::from_wire(&[updawg_protocol::OrgSigningKey {
            key_id: SigningKeyId::new("sk_customer"),
            public_key: signer.public.to_wire(),
            status: updawg_protocol::SigningKeyStatus::Active,
            endorsement: None,
        }])
        .unwrap();
        pinned.verify_job(&job).expect("a host accepts it");
    }

    /// A signing command that signs with some other key is caught here.
    #[test]
    fn a_command_signing_with_the_wrong_key_is_refused() {
        let signer = Signer {
            public: OrgKeyPair::generate().unwrap().public(),
            how: How::Command("printf '%064d' 0".to_owned()),
        };
        assert!(signer.sign(b"updawg-job-v1\0{}").is_err());
    }
}
