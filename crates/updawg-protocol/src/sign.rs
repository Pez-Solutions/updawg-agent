//! Domain separation for signatures made by an organization key.
//!
//! An organization's Ed25519 key signs two things: job documents and
//! endorsements of its successor. Signer and agent have to agree on the exact
//! bytes, so the rule is defined once, here.

/// What a signature made by an organization key is for.
///
/// Without separation, a signature over attacker-influenced bytes for one
/// purpose could be replayed as a valid signature for the other. Before 0.3
/// the only thing telling them apart was that a job document is JSON and
/// starts with `{`.
///
/// The signed bytes are `label || 0x00 || message`, where labels are ASCII
/// with no NUL, so the label always ends at the first `0x00` and a message
/// under one label can never parse as one under another. A length prefix
/// would work too; NUL keeps the label readable in a hexdump when debugging a
/// signature that won't verify.
///
/// [Ed25519ctx] does this at the primitive level, but `aws-lc-rs` only
/// exposes pure Ed25519 and the agent sticks to one crypto backend.
///
/// [Ed25519ctx]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignaturePurpose {
    /// A job document, as [`crate::Job::document`] produces it.
    Job,
    /// A statement by an organization key endorsing its successor, as
    /// [`crate::EndorsementStatement::to_document`] produces it.
    Endorsement,
}

impl SignaturePurpose {
    /// Never appears in a label.
    pub const SEPARATOR: u8 = 0x00;

    /// Every purpose, for tests.
    pub const ALL: [Self; 2] = [Self::Job, Self::Endorsement];

    /// The label, which is ASCII and contains no NUL.
    ///
    /// Versioned: changing what a purpose's message contains means a new label,
    /// so old signatures aren't reinterpreted.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Job => "updawg-job-v1",
            Self::Endorsement => "updawg-endorsement-v1",
        }
    }

    /// `label || 0x00`, the prefix every message of this purpose carries.
    #[must_use]
    pub fn prefix(self) -> Vec<u8> {
        let mut out = self.label().as_bytes().to_vec();
        out.push(Self::SEPARATOR);
        out
    }

    /// The exact bytes a signature covers. The signer and the agent both call
    /// this so they can't drift apart.
    #[must_use]
    pub fn bytes_to_sign(self, message: &[u8]) -> Vec<u8> {
        let mut out = self.prefix();
        out.extend_from_slice(message);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_message_of_one_purpose_can_be_read_as_a_message_of_another() {
        for a in SignaturePurpose::ALL {
            for b in SignaturePurpose::ALL {
                if a == b {
                    continue;
                }
                for message in [
                    b"".to_vec(),
                    b"{}".to_vec(),
                    b.prefix(),
                    b.bytes_to_sign(b"nested"),
                ] {
                    let signed = a.bytes_to_sign(&message);
                    assert!(
                        !signed.starts_with(&b.prefix()),
                        "{a:?} over {message:?} reads as {b:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn labels_are_nul_free_ascii() {
        for purpose in SignaturePurpose::ALL {
            let label = purpose.label();
            assert!(!label.is_empty());
            assert!(label.is_ascii(), "{label} is not ASCII");
            assert!(
                !label.as_bytes().contains(&SignaturePurpose::SEPARATOR),
                "{label} contains the separator"
            );
        }
    }

    #[test]
    fn labels_are_distinct() {
        let mut seen = Vec::new();
        for purpose in SignaturePurpose::ALL {
            assert!(
                !seen.contains(&purpose.label()),
                "two purposes share a label"
            );
            seen.push(purpose.label());
        }
    }

    /// Pinned as literals: changing a label invalidates every signature made
    /// under the old one.
    #[test]
    fn the_signing_labels_are_stable() {
        assert_eq!(SignaturePurpose::Job.label(), "updawg-job-v1");
        assert_eq!(
            SignaturePurpose::Endorsement.label(),
            "updawg-endorsement-v1"
        );
    }

    #[test]
    fn the_message_follows_the_prefix_unchanged() {
        let signed = SignaturePurpose::Job.bytes_to_sign(b"{\"id\":\"job_1\"}");
        assert_eq!(signed, b"updawg-job-v1\0{\"id\":\"job_1\"}");
    }
}
