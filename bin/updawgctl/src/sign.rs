//! `updawgctl prove-key`, `endorse` and `sign`: the organization's side of a
//! customer-held signing key.
//!
//! Run these where the key lives (a workstation, a CI job, a machine in front
//! of an HSM), not on a managed host. None of them need an enrolled agent.
//!
//! `sign` describes each job from its own document, parsed with the same
//! protocol crate the agent uses, and signs [`Job::signing_bytes`] of that
//! same parse. Metadata from the server, like the proposal or hostname, is
//! shown for context only and labelled as the server's.

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
    /// Verifies the result against the public half, so a misbehaving
    /// `--command` fails here rather than on every host.
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

/// Prints the proof the portal asks for before handing signing over to this
/// key: the key endorsing itself, for this organization, now. It shows the
/// holder can actually sign with it, since a hand-over to a key nobody holds
/// can't be undone. It's useless as a real endorsement because agents only
/// follow endorsements from a key they already trust.
pub(crate) fn prove_key(org: &str, source: &KeySource) -> Result<()> {
    if !org.starts_with("org_") {
        bail!("--org is your organization's id, `org_...`, as the portal shows it");
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
        "Paste the line above into the portal (Settings > Signing keys) within 24 hours. \
         Key fingerprint: {}",
        signer.public.fingerprint()
    );
    Ok(())
}

/* --------------------------------------------------------------- endorse */

/// The active key endorsing the next one, for rotating a key the organization
/// holds. Hosts follow it at their next certificate renewal. The portal also
/// wants a `prove-key` proof from the next key, so nobody can rotate to a key
/// that isn't held.
pub(crate) fn endorse(org: &str, from: &str, next: &str, source: &KeySource) -> Result<()> {
    let signer = source.signer()?;
    let next = OrgPublicKey::parse_configured("--next-public-key", next)?;
    let endorsement = endorsement(org, from, &next, &signer, chrono::Utc::now())?;
    let statement = endorsement.statement()?;
    println!("{}", serde_json::to_string(&endorsement)?);
    eprintln!(
        "Paste the line above into the portal (Settings > Signing keys > Rotate your key) \
         within 24 hours, with the output of `updawgctl prove-key --org {org}` run with the \
         next key. The next key will be {} (fingerprint {}).",
        statement.new_key.key_id.as_str(),
        next.fingerprint()
    );
    Ok(())
}

/// The next key's id is minted here, because the statement names it and is
/// signed before the server knows about the key.
fn endorsement(
    org: &str,
    from: &str,
    next: &OrgPublicKey,
    signer: &Signer,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Endorsement> {
    if !org.starts_with("org_") {
        bail!("--org is your organization's id, `org_...`, as the portal shows it");
    }
    if !from.starts_with("sk_") {
        bail!("--from is your active key's id, `sk_...`, as the portal lists it");
    }
    if *next == signer.public {
        bail!("the next key is the key you are rotating away from");
    }
    let millis = u64::try_from(now.timestamp_millis()).context("a clock before 1970")?;
    let statement = EndorsementStatement {
        org_id: OrgId::new(org),
        issued_at: now,
        previous_key: EndorsedKey {
            key_id: SigningKeyId::new(from),
            public_key: signer.public.to_wire(),
        },
        new_key: EndorsedKey {
            key_id: SigningKeyId::new(updawg_crypto::org_key::new_signing_key_id(millis)?),
            public_key: next.to_wire(),
        },
    };
    let signature = signer.sign(&statement.signing_bytes()?)?;
    Ok(Endorsement::new(&statement, signature)?)
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
    /// What unattended signing may sign. `None` signs everything waiting for
    /// this key.
    pub(crate) policy: Option<crate::policy::SignPolicy>,
}

/// Shows, confirms, signs and uploads every job waiting for this key.
pub(crate) async fn sign(options: SignOptions, source: &KeySource) -> Result<()> {
    let signer = source.signer()?;
    let api = Api::new(&options)?;

    // The id the organization knows this key by. Jobs naming a different key
    // are skipped, since hosts would reject the signature.
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
        if let Some(why) = options.policy.as_ref().and_then(|p| p.refuses(&job)) {
            println!("  left waiting: {why}");
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

/// An enum's wire spelling, which the portal also uses.
pub(crate) fn word<T: serde::Serialize>(value: &T) -> String {
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

    fn file_signer(key: OrgKeyPair) -> Signer {
        Signer {
            public: key.public(),
            how: How::File(Box::new(key)),
        }
    }

    #[test]
    fn an_endorsement_is_the_active_key_vouching_for_the_next() {
        let active = OrgKeyPair::generate().unwrap();
        let active_public = active.public();
        let next = OrgKeyPair::generate().unwrap().public();
        let signer = file_signer(active);

        let e = endorsement("org_1", "sk_active", &next, &signer, chrono::Utc::now()).unwrap();
        let statement = e.statement().unwrap();
        assert_eq!(statement.org_id.as_str(), "org_1");
        assert_eq!(statement.previous_key.key_id.as_str(), "sk_active");
        assert_eq!(statement.previous_key.public_key, active_public.to_wire());
        assert_eq!(statement.new_key.public_key, next.to_wire());
        assert!(statement.new_key.key_id.as_str().starts_with("sk_"));
        assert_ne!(statement.new_key.key_id.as_str(), "sk_active");
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&e.signature)
            .unwrap();
        active_public
            .verify(&e.signing_bytes(), &signature)
            .expect("verifies under the active key");

        assert!(
            endorsement(
                "org_1",
                "sk_active",
                &active_public,
                &signer,
                chrono::Utc::now()
            )
            .is_err(),
            "a key is not its own successor"
        );
    }

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

    #[test]
    fn a_command_signing_with_the_wrong_key_is_refused() {
        let signer = Signer {
            public: OrgKeyPair::generate().unwrap().public(),
            how: How::Command("printf '%064d' 0".to_owned()),
        };
        assert!(signer.sign(b"updawg-job-v1\0{}").is_err());
    }
}
