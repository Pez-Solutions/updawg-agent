//! Key rotation: the outgoing organization key endorsing its replacement.
//!
//! An agent pins an organization's signing keys at enrollment and verifies
//! every job against them. Rotation changes that material, and the design's
//! claim is that **an agent never has to take the server's word for a new
//! key**: the outgoing key signs a statement about the incoming one, and the
//! agent follows the chain from a key it already trusts.
//!
//! [ADR 0002] decides the bytes. This module is where they live, so that the
//! signer and the agent cannot produce two slightly different answers to "what
//! was signed".
//!
//! [ADR 0002]: https://github.com/Pez-Solutions/updawg-docs/blob/main/decisions/0002-signing-key-rotation-endorsements.md

use crate::{
    ids::{OrgId, SigningKeyId},
    sign::SignaturePurpose,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One end of an endorsement: a key named by both its id and its material.
///
/// ⚠️ **The material is here on purpose.** An endorsement that named a key only
/// by `key_id` would leave the server free to choose which bytes that id refers
/// to, and would therefore cover nothing the agent cares about. `public_key` is
/// what the agent is about to pin, or what it already has pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndorsedKey {
    pub key_id: SigningKeyId,
    /// `ed25519:` followed by the base64 SPKI encoding, exactly as
    /// [`crate::OrgSigningKey::public_key`] carries it.
    pub public_key: String,
}

/// What an endorsement says.
///
/// Every field answers an attack from [ADR 0002] and none is decorative:
///
/// - `org_id` — an endorsement legitimately produced in one tenant is not a
///   valid endorsement of that same key in another.
/// - `previous_key` — the agent checks that the endorsing key is one it holds
///   as `active` or `retiring`, **by material and id together**, so an
///   endorsement chains from a specific key rather than from a name. Without
///   it, an endorsement of a key since revoked re-verifies for ever.
/// - `new_key` — the endorsement covers the bytes about to be pinned.
/// - `issued_at` — *not* a freshness check. An agent that has been off for a
///   month must still be able to follow a rotation that happened while it was
///   off. It is there so that the audit trail and the agent's log agree on
///   which rotation this was when there have been several.
///
/// [ADR 0002]: https://github.com/Pez-Solutions/updawg-docs/blob/main/decisions/0002-signing-key-rotation-endorsements.md
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndorsementStatement {
    pub org_id: OrgId,
    pub issued_at: DateTime<Utc>,
    /// The key making the endorsement — one the agent should already hold.
    pub previous_key: EndorsedKey,
    /// The key being endorsed.
    pub new_key: EndorsedKey,
}

impl EndorsementStatement {
    /// The canonical document: this statement's JSON, which is the string an
    /// [`Endorsement`] carries verbatim.
    ///
    /// `serde_json` orders object keys deterministically and emits no
    /// insignificant whitespace, which is what makes this canonical. It is the
    /// same rule [`crate::Job::document`] uses.
    pub fn to_document(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// The exact bytes the previous key signs: the document under
    /// [`SignaturePurpose::Endorsement`].
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        Ok(SignaturePurpose::Endorsement.bytes_to_sign(self.to_document()?.as_bytes()))
    }
}

/// A statement and the signature over it, as they travel on
/// [`crate::OrgSigningKey::endorsement`].
///
/// # ⚠️ Why the statement is carried rather than rebuilt
///
/// The obvious wire format is a bare signature, with the agent reconstructing
/// the statement from what it knows. It cannot. `issued_at` is not derivable
/// from anything the agent holds, and even if it were, **a rebuilt document is
/// not a byte-identical document** — that is what DAWG-209 cost on the job
/// document, where "nearly identical" verified as forged. An agent that had to
/// guess the bytes would be an agent that fails a rotation for a reason nobody
/// can see.
///
/// So the signed bytes travel with the signature, and verification never
/// re-serialises anything. The statement is the **string that was signed**, not
/// an object to be parsed and re-encoded: an agent whose build predates a field
/// added later would drop that field on the round trip and compute a document
/// the signature does not cover. Parsing it (via [`Endorsement::statement`]) is
/// for deciding whether to *accept* the endorsement; it is never how the bytes
/// are recovered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endorsement {
    /// The canonical JSON of an [`EndorsementStatement`], verbatim.
    pub statement: String,
    /// Base64 Ed25519 signature by `previous_key` over
    /// [`Endorsement::signing_bytes`].
    pub signature: String,
}

impl Endorsement {
    /// Build one from a statement and the signature its previous key produced.
    ///
    /// The signature must have been made over [`EndorsementStatement::signing_bytes`]
    /// for the same statement — this serialises the statement once and hands
    /// back the pair, so the document that is signed and the document that is
    /// sent cannot differ.
    pub fn new(
        statement: &EndorsementStatement,
        signature_base64: impl Into<String>,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self {
            statement: statement.to_document()?,
            signature: signature_base64.into(),
        })
    }

    /// The exact bytes the signature covers.
    ///
    /// Infallible, and deliberately so: it reads the string that arrived rather
    /// than re-deriving it, so there is no encoding step here that can fail or
    /// disagree with the signer's.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        SignaturePurpose::Endorsement.bytes_to_sign(self.statement.as_bytes())
    }

    /// What the endorsement claims.
    ///
    /// ⚠️ For **deciding** whether to accept it — which organization, which
    /// previous key, which material. Never for recovering the signed bytes; use
    /// [`Endorsement::signing_bytes`] for that.
    pub fn statement(&self) -> Result<EndorsementStatement, serde_json::Error> {
        serde_json::from_str(&self.statement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str, material: &str) -> EndorsedKey {
        EndorsedKey {
            key_id: SigningKeyId::new(id),
            public_key: format!("ed25519:{material}"),
        }
    }

    fn statement() -> EndorsementStatement {
        EndorsementStatement {
            org_id: OrgId::new("org_01J9ZD"),
            issued_at: "2026-09-24T11:00:00Z".parse().unwrap(),
            previous_key: key("sk_old", "AAAAold"),
            new_key: key("sk_new", "AAAAnew"),
        }
    }

    #[test]
    fn the_document_is_stable_across_calls() {
        let s = statement();
        assert_eq!(s.to_document().unwrap(), s.to_document().unwrap());
    }

    #[test]
    fn the_signed_bytes_carry_the_endorsement_label() {
        let bytes = statement().signing_bytes().unwrap();
        assert!(bytes.starts_with(b"updawg-endorsement-v1\0"));
    }

    /// The reason the statement travels as a string. A verifier that parsed and
    /// re-serialised would be computing its own document; this asserts that the
    /// one it verifies is the one that arrived, byte for byte.
    #[test]
    fn verification_reads_the_bytes_that_arrived_rather_than_rebuilding_them() {
        let wire = Endorsement {
            // Key order and spacing a re-serialisation would not reproduce, and
            // a field this build does not know about.
            statement: "{\"new_key\":{\"key_id\":\"sk_new\",\"public_key\":\"ed25519:AAAAnew\"} , \"org_id\":\"org_1\",\"issued_at\":\"2026-09-24T11:00:00Z\",\"previous_key\":{\"key_id\":\"sk_old\",\"public_key\":\"ed25519:AAAAold\"},\"note\":\"from a later build\"}".into(),
            signature: "c2ln".into(),
        };
        assert_eq!(
            wire.signing_bytes(),
            SignaturePurpose::Endorsement.bytes_to_sign(wire.statement.as_bytes())
        );
        // And it still parses into something this build can make a decision on.
        let parsed = wire.statement().unwrap();
        assert_eq!(parsed.new_key.key_id.as_str(), "sk_new");
        assert_ne!(
            parsed.to_document().unwrap().as_bytes(),
            wire.statement.as_bytes(),
            "the fixture must actually differ from a re-serialisation, or this \
             test proves nothing"
        );
    }

    #[test]
    fn what_is_sent_is_what_was_signed() {
        let s = statement();
        let endorsement = Endorsement::new(&s, "c2ln").unwrap();
        assert_eq!(endorsement.signing_bytes(), s.signing_bytes().unwrap());
    }

    #[test]
    fn a_statement_round_trips() {
        let s = statement();
        let back: EndorsementStatement = serde_json::from_str(&s.to_document().unwrap()).unwrap();
        assert_eq!(s, back);
    }

    /// Both ends name the key by material as well as by id. An endorsement that
    /// dropped `public_key` would still deserialise into something plausible if
    /// the field were optional, so it is required and this says why.
    #[test]
    fn a_statement_missing_a_key_material_is_rejected() {
        let json = "{\"org_id\":\"org_1\",\"issued_at\":\"2026-09-24T11:00:00Z\",\
                    \"previous_key\":{\"key_id\":\"sk_old\"},\
                    \"new_key\":{\"key_id\":\"sk_new\",\"public_key\":\"ed25519:x\"}}";
        assert!(serde_json::from_str::<EndorsementStatement>(json).is_err());
    }
}
