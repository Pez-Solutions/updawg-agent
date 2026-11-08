//! Which certificate authorities may vouch for the gateway.
//!
//! The gateway's own certificate is a public one from Let's Encrypt. By
//! default the agent trusts only Let's Encrypt's roots, compiled in here, not
//! the hundred-odd the host trusts for everything else: any of those could
//! otherwise issue a certificate for the gateway's name and read what the
//! agent sends. A network that inspects TLS with its own CA needs `system`.
//!
//! The agent CA from enrollment is a different thing: it issues hosts'
//! client certificates, and renewals are checked against it.

use serde::{Deserialize, Serialize};

/// `gateway_trust` in `agent.toml`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayTrust {
    /// Let's Encrypt's roots only: ISRG Root X1, X2, YE and YR.
    #[default]
    LetsEncrypt,
    /// The host's own trust store, for a network that inspects TLS.
    System,
}

/// From letsencrypt.org/certificates, 2026-11-08. X1 and X2 match the macOS
/// system roots; YE and YR match the keys X2 and X1 cross-signed. SHA-256
/// fingerprints are checked in the tests.
const LETS_ENCRYPT_ROOTS: [&str; 4] = [
    include_str!("roots/isrg-root-x1.pem"),
    include_str!("roots/isrg-root-x2.pem"),
    include_str!("roots/isrg-root-ye.pem"),
    include_str!("roots/isrg-root-yr.pem"),
];

/// Sets the roots on a client that talks to the gateway. `extra_root` is the
/// `insecure-extra-root` build's, added either way.
///
/// # Errors
/// A root that does not parse, as text for the caller's own error.
pub(crate) fn configure(
    builder: reqwest::ClientBuilder,
    trust: GatewayTrust,
    extra_root: Option<&[u8]>,
) -> Result<reqwest::ClientBuilder, String> {
    let parse = |pem: &[u8]| {
        reqwest::Certificate::from_pem(pem).map_err(|e| format!("a root certificate: {e}"))
    };
    let extra = extra_root.map(parse).transpose()?;
    Ok(match trust {
        GatewayTrust::LetsEncrypt => {
            let mut roots = LETS_ENCRYPT_ROOTS
                .iter()
                .map(|pem| parse(pem.as_bytes()))
                .collect::<Result<Vec<_>, _>>()?;
            roots.extend(extra);
            builder.tls_certs_only(roots)
        }
        GatewayTrust::System => builder.tls_certs_merge(extra),
    })
}

/// `detail`, with what to change when it looks like the gateway's certificate
/// was refused for not chaining to Let's Encrypt.
#[must_use]
pub(crate) fn explain(trust: GatewayTrust, detail: String) -> String {
    if trust == GatewayTrust::LetsEncrypt && detail.contains("invalid peer certificate") {
        format!(
            "{detail}. This agent trusts only Let's Encrypt for the gateway; on a network \
             that inspects TLS with its own CA, set gateway_trust = \"system\" in agent.toml"
        )
    } else {
        detail
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use std::fmt::Write as _;

    fn sha256_of_der(pem: &str) -> String {
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap();
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &der);
        digest.as_ref().iter().fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        })
    }

    #[test]
    fn the_compiled_in_roots_are_lets_encrypts() {
        let got: Vec<String> = LETS_ENCRYPT_ROOTS
            .iter()
            .copied()
            .map(sha256_of_der)
            .collect();
        assert_eq!(
            got,
            [
                // ISRG Root X1
                "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6",
                // ISRG Root X2
                "69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470",
                // ISRG Root YE
                "e14ffcad5b0025731006caa43a121a22d8e9700f4fb9cf852f02a708aa5d5666",
                // ISRG Root YR
                "e57b7e6f150c419102e8d5c055729ff967b9d1a829bf00cec89ca604ebf4a86f",
            ]
        );
    }

    #[test]
    fn both_settings_build_a_client() {
        for trust in [GatewayTrust::LetsEncrypt, GatewayTrust::System] {
            configure(reqwest::Client::builder(), trust, None)
                .unwrap()
                .build()
                .unwrap();
        }
    }

    #[test]
    fn a_refused_gateway_certificate_says_what_to_change() {
        let refused = "invalid peer certificate: UnknownIssuer".to_owned();
        assert!(explain(GatewayTrust::LetsEncrypt, refused.clone()).contains("gateway_trust"));
        assert_eq!(explain(GatewayTrust::System, refused.clone()), refused);
        let timeout = "operation timed out".to_owned();
        assert_eq!(explain(GatewayTrust::LetsEncrypt, timeout.clone()), timeout);
    }
}
