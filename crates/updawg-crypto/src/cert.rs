//! The client certificate and its renewal schedule.
//!
//! Certificates last thirty days, so a decommissioned or compromised host
//! drops out of the fleet by itself. A host that fails to renew goes stale,
//! so renewal starts well before expiry.

use crate::{CryptoError, Result};
use std::{
    fmt,
    time::{Duration, SystemTime},
};

/// Renew once this fraction of the certificate's life remains. Ten days of a
/// thirty-day certificate covers a host being off for a week plus an outage
/// and retries.
const RENEW_AT_REMAINING_FRACTION: f64 = 1.0 / 3.0;

/// The parts of a client certificate needed to manage its renewal.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientCertificate {
    not_before: SystemTime,
    not_after: SystemTime,
    subject: String,
    serial: String,
    public_key_spki: Vec<u8>,
}

// keep the DER out of error messages
impl fmt::Debug for ClientCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCertificate")
            .field("subject", &self.subject)
            .field("serial", &self.serial)
            .field("not_before", &humantime(self.not_before))
            .field("not_after", &humantime(self.not_after))
            .finish_non_exhaustive()
    }
}

impl ClientCertificate {
    /// Parses the first (leaf) certificate in a PEM document.
    ///
    /// # Errors
    /// [`CryptoError::MalformedCertificate`] if there is no certificate in the
    /// PEM, or it does not parse as X.509.
    pub fn from_pem(pem: &str) -> Result<Self> {
        use x509_parser::prelude::{FromDer, X509Certificate};

        let der = first_pem_block(pem, "CERTIFICATE")
            .ok_or_else(|| CryptoError::MalformedCertificate("no CERTIFICATE block".into()))?;

        let (_, cert) = X509Certificate::from_der(&der)
            .map_err(|e| CryptoError::MalformedCertificate(e.to_string()))?;

        let validity = cert.validity();
        Ok(Self {
            not_before: unix(validity.not_before.timestamp()),
            not_after: unix(validity.not_after.timestamp()),
            subject: cert.subject().to_string(),
            serial: cert.raw_serial_as_string(),
            public_key_spki: cert.public_key().raw.to_vec(),
        })
    }

    #[must_use]
    pub fn not_after(&self) -> SystemTime {
        self.not_after
    }

    #[must_use]
    pub fn not_before(&self) -> SystemTime {
        self.not_before
    }

    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    #[must_use]
    pub fn serial(&self) -> &str {
        &self.serial
    }

    /// Checked against the host's key at renewal. A certificate for a different
    /// key parses fine and then fails every handshake.
    #[must_use]
    pub fn public_key_spki(&self) -> &[u8] {
        &self.public_key_spki
    }

    /// `None` once expired.
    #[must_use]
    pub fn remaining(&self, now: SystemTime) -> Option<Duration> {
        self.not_after.duration_since(now).ok()
    }

    #[must_use]
    pub fn is_expired(&self, now: SystemTime) -> bool {
        self.remaining(now).is_none()
    }

    /// When renewal should start. Computed from the certificate's lifetime, not
    /// a fixed number of days, so it adapts if the server changes the
    /// validity period.
    #[must_use]
    pub fn renew_after(&self) -> SystemTime {
        let lifetime = self
            .not_after
            .duration_since(self.not_before)
            .unwrap_or(Duration::ZERO);
        let window = lifetime.mul_f64(RENEW_AT_REMAINING_FRACTION);
        self.not_after
            .checked_sub(window)
            .unwrap_or(self.not_before)
    }

    /// `spread` (0.0 to 1.0) moves this host's renewal earlier by up to one
    /// renewal window, so hosts enrolled together don't all renew at once.
    #[must_use]
    pub fn renewal_due(&self, now: SystemTime, spread: f64) -> bool {
        let lifetime = self
            .not_after
            .duration_since(self.not_before)
            .unwrap_or(Duration::ZERO);
        let jitter = lifetime.mul_f64(RENEW_AT_REMAINING_FRACTION * spread.clamp(0.0, 1.0));
        let due = self
            .renew_after()
            .checked_sub(jitter)
            .unwrap_or(self.not_before);
        now >= due
    }
}

/// Hand-rolled to avoid another dependency in a binary that runs as root.
fn first_pem_block(pem: &str, label: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;

    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");

    let start = pem.find(&begin)? + begin.len();
    let finish = pem[start..].find(&end)? + start;
    let body: String = pem[start..finish]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

fn unix(seconds: i64) -> SystemTime {
    if seconds >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds.unsigned_abs())
    } else {
        SystemTime::UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs())
    }
}

fn humantime(t: SystemTime) -> String {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or_else(|_| "before 1970".into(), |d| format!("{}", d.as_secs()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519};

    /// Generated rather than a fixture, which would eventually expire.
    fn certificate(valid_for: Duration) -> (String, SystemTime, SystemTime) {
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();

        let not_before = SystemTime::now();
        let not_after = not_before + valid_for;
        params.not_before = not_before.into();
        params.not_after = not_after.into();

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "hst_01J9ZC6Q");
        params.distinguished_name = dn;

        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), not_before, not_after)
    }

    /// Certificate times have one-second resolution.
    fn about_equal(a: SystemTime, b: SystemTime) -> bool {
        a.duration_since(b)
            .or_else(|_| b.duration_since(a))
            .unwrap_or(Duration::ZERO)
            <= Duration::from_secs(2)
    }

    const THIRTY_DAYS: Duration = Duration::from_secs(30 * 86_400);

    #[test]
    fn a_real_certificate_parses_into_its_subject_and_validity() {
        let (pem, before, after) = certificate(THIRTY_DAYS);
        let cert = ClientCertificate::from_pem(&pem).unwrap();

        assert!(cert.subject().contains("hst_01J9ZC6Q"));
        assert!(!cert.serial().is_empty());
        assert!(about_equal(cert.not_before(), before));
        assert!(about_equal(cert.not_after(), after));
    }

    #[test]
    fn the_leaf_is_taken_when_a_chain_is_present() {
        let (leaf, _, after) = certificate(THIRTY_DAYS);
        let (ca, _, _) = certificate(Duration::from_secs(365 * 86_400));
        let bundle = format!("{leaf}{ca}");

        let cert = ClientCertificate::from_pem(&bundle).unwrap();
        assert!(
            about_equal(cert.not_after(), after),
            "the second certificate in the bundle was parsed instead of the leaf"
        );
    }

    #[test]
    fn anything_that_is_not_a_certificate_is_refused() {
        for input in ["", "-----BEGIN CERTIFICATE-----\nnot base64 !\n", "hello"] {
            assert!(
                ClientCertificate::from_pem(input).is_err(),
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn a_thirty_day_certificate_renews_with_ten_days_left() {
        let (pem, before, _) = certificate(THIRTY_DAYS);
        let cert = ClientCertificate::from_pem(&pem).unwrap();

        let expected = before + Duration::from_secs(20 * 86_400);
        assert!(
            about_equal(cert.renew_after(), expected),
            "renewal should begin on day 20 of 30"
        );
    }

    #[test]
    fn renewal_is_not_due_early_in_the_certificates_life() {
        let (pem, before, _) = certificate(THIRTY_DAYS);
        let cert = ClientCertificate::from_pem(&pem).unwrap();

        assert!(!cert.renewal_due(before + Duration::from_secs(5 * 86_400), 0.0));
        assert!(!cert.renewal_due(before + Duration::from_secs(19 * 86_400), 0.0));
        assert!(cert.renewal_due(before + Duration::from_secs(21 * 86_400), 0.0));
    }

    #[test]
    fn spread_moves_renewal_earlier_but_never_outside_the_window() {
        let (pem, before, _) = certificate(THIRTY_DAYS);
        let cert = ClientCertificate::from_pem(&pem).unwrap();

        // full spread: day 10
        assert!(cert.renewal_due(before + Duration::from_secs(11 * 86_400), 1.0));
        assert!(!cert.renewal_due(before + Duration::from_secs(9 * 86_400), 1.0));

        assert!(!cert.renewal_due(before - Duration::from_secs(60), 1.0));
    }

    #[test]
    fn an_expired_certificate_says_so_rather_than_reporting_a_huge_remaining() {
        let (pem, before, _) = certificate(Duration::from_secs(60));
        let cert = ClientCertificate::from_pem(&pem).unwrap();

        let later = before + Duration::from_secs(3600);
        assert!(cert.is_expired(later));
        assert_eq!(cert.remaining(later), None);
        assert!(cert.renewal_due(later, 0.0));
    }

    #[test]
    fn debug_output_carries_the_subject_and_not_the_whole_certificate() {
        let (pem, _, _) = certificate(THIRTY_DAYS);
        let cert = ClientCertificate::from_pem(&pem).unwrap();
        let rendered = format!("{cert:?}");
        assert!(rendered.contains("hst_01J9ZC6Q"));
        assert!(!rendered.contains("BEGIN CERTIFICATE"));
    }
}
