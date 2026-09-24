//! What an organization key signs, and how the two kinds of message are kept
//! apart.
//!
//! An organization's Ed25519 key signs two different things: job documents, and
//! endorsements of its own successor. Both sides of the wire have to agree on
//! the bytes exactly, so the rule lives here rather than in the signer and the
//! agent separately — see [ADR 0002].
//!
//! [ADR 0002]: https://github.com/Pez-Solutions/updawg-docs/blob/main/decisions/0002-signing-key-rotation-endorsements.md

/// What a signature made by an organization key is *for*.
///
/// # The attack this prevents
///
/// One key signs jobs and endorsements of its successor. Without separation,
/// **a message of one kind can be presented as a message of the other**:
/// anything that persuades the signer to produce a signature over
/// attacker-chosen bytes for one purpose has produced a valid signature for the
/// other. An endorsement is four short fields, and a job is a document whose
/// payload the control plane chooses.
///
/// Before 0.3 the two were told apart only by the fact that a job document is
/// JSON and starts with `{`. That is a property of an encoding nobody promised
/// to keep, not a separation.
///
/// # The shape
///
/// `label || 0x00 || message`, with labels that are ASCII and contain no NUL.
/// That makes the prefix **unambiguous** rather than merely present: a reader
/// finds the label by scanning to the first `0x00`, there is exactly one place
/// it can be, and no message under one label can be read as a message under
/// another whatever either encoding becomes later.
///
/// A length prefix would give the same property. A NUL terminator was chosen
/// because the label stays human-readable in a hexdump, which is what matters
/// when somebody is looking at a signature that will not verify.
///
/// ⚠️ **[Ed25519ctx] is exactly this at the primitive level** and would be the
/// better answer if it were available. `aws-lc-rs` exposes pure Ed25519 only,
/// and the agent has one crypto backend on purpose. A prefix in the message is
/// the same property built out of what we have.
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
    /// The separator. A byte that cannot appear in a label is what makes the
    /// prefix unambiguous rather than merely present.
    pub const SEPARATOR: u8 = 0x00;

    /// Every purpose, so a test can assert across all of them rather than
    /// across the ones somebody remembered to list.
    pub const ALL: [Self; 2] = [Self::Job, Self::Endorsement];

    /// The label, which is ASCII and contains no NUL.
    ///
    /// Versioned, so that changing what a purpose's message *contains* is a new
    /// label rather than a silent reinterpretation of signatures made under the
    /// old meaning.
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

    /// The exact bytes a signature covers.
    ///
    /// Both sides call this — the signer to sign, the agent to verify — so that
    /// "what is signed" is one function rather than two descriptions of it that
    /// can drift. DAWG-209 paid for the same lesson on the job document itself:
    /// a rebuilt document is not a byte-identical document, and "nearly
    /// identical" verifies as forged.
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

    /// The property the whole mechanism rests on. Not "the labels differ" —
    /// that is trivially true and not what protects anything.
    #[test]
    fn no_message_of_one_purpose_can_be_read_as_a_message_of_another() {
        for a in SignaturePurpose::ALL {
            for b in SignaturePurpose::ALL {
                if a == b {
                    continue;
                }
                // Whatever an attacker chooses as the message under `a`, the
                // result never begins with `b`'s prefix.
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

    /// The separator has to be absent from the labels or the prefix is not a
    /// prefix, it is a guess about where the label ends.
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

    /// ⚠️ These strings are on the wire in every signature ever made. Changing
    /// one invalidates every signature made under the old spelling, which is a
    /// silent failure at the far end — so they are pinned here as literals
    /// rather than derived from the variant name.
    #[test]
    fn the_labels_are_the_ones_adr_0002_names() {
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
