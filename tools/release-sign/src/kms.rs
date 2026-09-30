//! The signer that holds no key: Cloud KMS signs, and this sends it a digest.
//!
//! Authenticated with an OAuth access token from the environment
//! (`GOOGLE_OAUTH_ACCESS_TOKEN`), which in CI comes from Workload Identity
//! Federation: an hour-long credential for one workflow, granted `useToSign`
//! on this one key and nothing else.

use crate::openpgp::{PublicKey, Signer};
use anyhow::{Context as _, bail};
use aws_lc_rs::digest;
use base64::Engine as _;

const API: &str = "https://cloudkms.googleapis.com/v1";
/// The only algorithm this signs with: see [`crate::openpgp`].
const ALGORITHM: &str = "RSA_SIGN_PKCS1_4096_SHA512";

pub(crate) struct Kms {
    /// `projects/…/cryptoKeys/…/cryptoKeyVersions/N`.
    version: String,
    token: String,
    http: reqwest::blocking::Client,
}

/// Without the token, which is a credential.
impl std::fmt::Debug for Kms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kms")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl Kms {
    pub(crate) fn new(version: String) -> anyhow::Result<Self> {
        let token = std::env::var("GOOGLE_OAUTH_ACCESS_TOKEN")
            .context("GOOGLE_OAUTH_ACCESS_TOKEN is not set: this signs through Cloud KMS")?;
        Ok(Self {
            version,
            token,
            http: reqwest::blocking::Client::new(),
        })
    }

    fn get(&self, url: &str) -> anyhow::Result<serde_json::Value> {
        let response = self.http.get(url).bearer_auth(&self.token).send()?;
        let status = response.status();
        let body: serde_json::Value = response.json()?;
        if !status.is_success() {
            bail!("Cloud KMS answered {status}: {body}");
        }
        Ok(body)
    }

    /// The key's public half, with the key version's creation time as the
    /// OpenPGP key's, so every export has the same fingerprint.
    pub(crate) fn public_key(&self) -> anyhow::Result<PublicKey> {
        let version = self.get(&format!("{API}/{}", self.version))?;
        let created = version["createTime"]
            .as_str()
            .context("the key version has no createTime")?;
        let created = chrono::DateTime::parse_from_rfc3339(created)?.timestamp();

        let public = self.get(&format!("{API}/{}/publicKey", self.version))?;
        if public["algorithm"] != ALGORITHM {
            bail!(
                "the key is {}, and this signs only with {ALGORITHM}",
                public["algorithm"]
            );
        }
        let pem = public["pem"].as_str().context("no PEM in the answer")?;
        let (n, e) = crate::der::rsa_spki(&pem_der(pem)?)?;
        Ok(PublicKey {
            created: u32::try_from(created)?,
            n,
            e,
        })
    }
}

impl Signer for Kms {
    fn sign(&self, to_hash: &[u8]) -> anyhow::Result<Vec<u8>> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let digest = digest::digest(&digest::SHA512, to_hash);
        let response = self
            .http
            .post(format!("{API}/{}:asymmetricSign", self.version))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({"digest": {"sha512": b64.encode(digest.as_ref())}}))
            .send()?;
        let status = response.status();
        let body: serde_json::Value = response.json()?;
        if !status.is_success() {
            bail!("Cloud KMS refused to sign ({status}): {body}");
        }
        let signature = body["signature"]
            .as_str()
            .context("no signature in the answer")?;
        Ok(b64.decode(signature)?)
    }
}

fn pem_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    Ok(base64::engine::general_purpose::STANDARD.decode(body)?)
}
