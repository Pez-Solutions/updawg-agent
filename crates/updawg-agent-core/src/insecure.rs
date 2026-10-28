//! Trusting a certificate authority the platform does not.
//!
//! For running the agent against a gateway you started yourself: a local one
//! for development, or one behind an organization's own CA. It is behind the
//! `insecure-extra-root` feature, which release builds do not enable.
//!
//! # What this gives away
//!
//! The extra root is added to the platform trust store, not swapped in for it.
//! Anyone holding the CA's private key can impersonate the Updawg gateway to
//! this host: answer its check-ins and read what it reports. They can't make
//! it install anything, because jobs are signed by the organization key pinned
//! at enrollment, which is not this CA.
//!
//! # Why a flag and not an environment variable
//!
//! Environment variables get inherited from parent processes or left behind in
//! unit files. Every other option on these binaries accepts one; this one
//! deliberately doesn't.

use std::{io, path::Path};

/// Printed in full on every use; it cannot be suppressed.
///
/// Every line is prefixed so it stays readable when interleaved with
/// structured logs.
pub const WARNING: &str = "\
!! This build trusts an extra certificate authority, from --insecure-extra-root.
!! It was compiled with the `insecure-extra-root` feature, which a release is
!! not. Anyone holding that CA's private key can impersonate the Updawg gateway
!! to this host: answer its check-ins, and read what it reports.
!! They cannot make it install anything: jobs are signed by the organization
!! key pinned at enrollment, which is not this CA.";

/// Reads a PEM certificate authority from disk.
///
/// Checks for a PEM header up front. Otherwise a wrong path surfaces later as
/// a generic TLS builder error from `reqwest`.
///
/// # Errors
/// If the file cannot be read, or does not look like PEM.
pub fn load_root(path: &Path) -> io::Result<Vec<u8>> {
    let pem = std::fs::read(path)?;

    if !pem
        .windows(BEGIN.len())
        .any(|window| window == BEGIN.as_bytes())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} does not contain a PEM certificate (no `{}` line). A DER \
                 certificate needs converting first: \
                 `openssl x509 -inform der -in cert.der -out cert.pem`",
                path.display(),
                BEGIN.trim()
            ),
        ));
    }

    Ok(pem)
}

const BEGIN: &str = "-----BEGIN CERTIFICATE-----";

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn temp(contents: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "updawg-root-{}-{:?}.pem",
            std::process::id(),
            std::thread::current().id()
        ));
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(contents).expect("write");
        path
    }

    #[test]
    fn a_pem_certificate_is_read_verbatim() {
        // rustls parses the whole document, so we pass it through untouched.
        let pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        let path = temp(pem);
        assert_eq!(load_root(&path).expect("reads"), pem);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn something_that_is_not_pem_says_so_rather_than_failing_inside_tls() {
        let path = temp(b"\x30\x82\x01\x0a not pem at all");
        let err = load_root(&path).expect_err("should be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let message = err.to_string();
        assert!(message.contains("BEGIN CERTIFICATE"), "{message}");
        assert!(message.contains("openssl x509"), "{message}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_missing_file_is_a_missing_file() {
        let err =
            load_root(std::path::Path::new("/nonexistent/updawg/ca.pem")).expect_err("should fail");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn the_warning_says_what_is_given_away_and_what_is_not() {
        assert!(WARNING.contains("impersonate"));
        assert!(WARNING.contains("cannot make it install anything"));
        assert!(WARNING.lines().all(|l| l.starts_with("!!")));
    }
}
