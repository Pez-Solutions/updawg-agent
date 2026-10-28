//! Key rotation: the outgoing organization key endorsing its replacement.
//!
//! An agent pins an organization's signing keys at enrollment and verifies
//! every job against them. On rotation the agent doesn't take the server's
//! word for a new key: the outgoing key signs a statement about the incoming
//! one, and the agent follows the chain from a key it already trusts.
//!
//! The signer and the agent both use the definitions here, so they agree on
//! exactly what was signed.

use crate::{
    ids::{OrgId, SigningKeyId},
    sign::SignaturePurpose,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One end of an endorsement: a key named by both its id and its material.
///
/// The material is included because an id alone would let the server decide
/// which key bytes it refers to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndorsedKey {
    pub key_id: SigningKeyId,
    /// `ed25519:` followed by the base64 SPKI encoding, exactly as
    /// [`crate::OrgSigningKey::public_key`] carries it.
    pub public_key: String,
}

/// What an endorsement says.
///
/// - `org_id`: an endorsement from one tenant isn't valid in another.
/// - `previous_key`: the agent checks the endorsing key against the keys it
///   holds as `active` or `retiring`, by material and id together. Without
///   this, an endorsement by a since-revoked key would keep verifying.
/// - `new_key`: covers the bytes about to be pinned.
/// - `issued_at`: not a freshness check, since an agent that was off for a
///   month still needs to follow a rotation. It lets the audit trail and the
///   agent's log agree on which rotation this was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndorsementStatement {
    pub org_id: OrgId,
    pub issued_at: DateTime<Utc>,
    /// The key making the endorsement, which the agent should already hold.
    pub previous_key: EndorsedKey,
    /// The key being endorsed.
    pub new_key: EndorsedKey,
}

impl EndorsementStatement {
    /// The canonical document, which [`Endorsement`] carries verbatim.
    ///
    /// `serde_json` orders keys deterministically and emits no extra
    /// whitespace. Same rule as [`crate::Job::document`].
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
/// The statement travels as the exact string that was signed. The agent can't
/// rebuild it: `issued_at` isn't derivable from anything it holds, and
/// re-serialising a parsed statement would drop any field added in a later
/// build, producing bytes the signature doesn't cover. [`Endorsement::statement`]
/// parses it for deciding whether to accept the endorsement; verification
/// always uses the original string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endorsement {
    /// The canonical JSON of an [`EndorsementStatement`], verbatim.
    pub statement: String,
    /// Base64 Ed25519 signature by `previous_key` over
    /// [`Endorsement::signing_bytes`].
    pub signature: String,
}

impl Endorsement {
    /// Pairs a statement with the signature its previous key made over
    /// [`EndorsementStatement::signing_bytes`].
    pub fn new(
        statement: &EndorsementStatement,
        signature_base64: impl Into<String>,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self {
            statement: statement.to_document()?,
            signature: signature_base64.into(),
        })
    }

    /// The exact bytes the signature covers, taken from the string as it
    /// arrived.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        SignaturePurpose::Endorsement.bytes_to_sign(self.statement.as_bytes())
    }

    /// What the endorsement claims, for deciding whether to accept it. Don't
    /// re-serialise this to verify; use [`Endorsement::signing_bytes`].
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

    #[test]
    fn verification_reads_the_bytes_that_arrived_rather_than_rebuilding_them() {
        let wire = Endorsement {
            // key order and spacing a re-serialisation wouldn't reproduce, plus
            // a field this build doesn't know
            statement: "{\"new_key\":{\"key_id\":\"sk_new\",\"public_key\":\"ed25519:AAAAnew\"} , \"org_id\":\"org_1\",\"issued_at\":\"2026-09-24T11:00:00Z\",\"previous_key\":{\"key_id\":\"sk_old\",\"public_key\":\"ed25519:AAAAold\"},\"note\":\"from a later build\"}".into(),
            signature: "c2ln".into(),
        };
        assert_eq!(
            wire.signing_bytes(),
            SignaturePurpose::Endorsement.bytes_to_sign(wire.statement.as_bytes())
        );
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

    #[test]
    fn a_statement_missing_a_key_material_is_rejected() {
        let json = "{\"org_id\":\"org_1\",\"issued_at\":\"2026-09-24T11:00:00Z\",\
                    \"previous_key\":{\"key_id\":\"sk_old\"},\
                    \"new_key\":{\"key_id\":\"sk_new\",\"public_key\":\"ed25519:x\"}}";
        assert!(serde_json::from_str::<EndorsementStatement>(json).is_err());
    }
}
