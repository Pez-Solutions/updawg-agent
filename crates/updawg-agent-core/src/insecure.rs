//! Trusting a certificate authority the platform does not.
//!
//! This module exists so the agent can be run against a gateway you started
//! yourself — a local one for development (DAWG-27), or an organization's own
//! CA. It is behind the `insecure-extra-root` feature and **a release build
//! does not have it**, which is the point: in the one component whose entire
//! argument is that it cannot be told what to trust, the ability to be told
//! what to trust should not be present in the binary people install.
//!
//! # What this actually gives away
//!
//! An extra root is *added* to the platform trust store rather than replacing
//! it, so nothing that already worked stops working. What changes is that
//! anybody holding the private key of the CA named here can impersonate the
//! Updawg gateway to this host: they can answer its check-ins, and hand it
//! whatever the gateway would have handed it.
//!
//! That is not as bad as it sounds, and it is worth knowing exactly why,
//! because the reason is the product's own argument. A gateway cannot make this
//! host *do* anything by impersonation alone — jobs are signed by the
//! organization's key, which was pinned at enrollment and is not in this CA. An
//! attacker with this root can lie to the host about what is available and can
//! read what it reports. They cannot install anything.
//!
//! # Why a flag and not an environment variable
//!
//! Because an environment variable is something that can be set by accident,
//! inherited from a parent process, or left in a unit file by somebody
//! debugging at two in the morning. Every other option on these binaries
//! accepts one. This one does not, and that asymmetry is deliberate.

use std::{io, path::Path};

/// Printed on every use, in full, with no way to suppress it.
///
/// Every line is prefixed so it survives being interleaved with structured
/// logs, and the reason is spelled out rather than left as "insecure" —
/// a warning nobody can act on is a warning people learn to scroll past.
pub const WARNING: &str = "\
!! This build trusts an extra certificate authority, from --insecure-extra-root.
!! It was compiled with the `insecure-extra-root` feature, which a release is
!! not. Anyone holding that CA's private key can impersonate the Updawg gateway
!! to this host: answer its check-ins, and read what it reports.
!! They cannot make it install anything — jobs are signed by the organization
!! key pinned at enrollment, which is not this CA.";

/// Read a PEM certificate authority from disk.
///
/// The contents are checked for a PEM header here rather than left to fail
/// inside `reqwest`, because the error that comes back from there is a generic
/// TLS builder error and the mistake being made is almost always a path that
/// points at the wrong file.
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
        // Verbatim matters: this is handed to rustls, which parses the whole
        // document. Trimming or re-encoding it here would be a second opinion
        // about a format we do not own.
        let pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        let path = temp(pem);
        assert_eq!(load_root(&path).expect("reads"), pem);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn something_that_is_not_pem_says_so_rather_than_failing_inside_tls() {
        // The mistake this catches is a path pointing at the wrong file, and
        // the error rustls gives for it names neither the file nor the format.
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
        // A warning nobody can act on is one people learn to scroll past, so
        // this asserts it still contains the two facts that make it actionable.
        assert!(WARNING.contains("impersonate"));
        assert!(WARNING.contains("cannot make it install anything"));
        // And every line is prefixed, so it survives interleaving with
        // structured logs.
        assert!(WARNING.lines().all(|l| l.starts_with("!!")));
    }
}
