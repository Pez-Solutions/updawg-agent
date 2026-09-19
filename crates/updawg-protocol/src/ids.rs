//! Type-prefixed identifiers.
//!
//! The server stores `UUIDv7` primary keys and exposes them with a type prefix
//! (`hst_`, `job_`, `org_`). Keeping them as distinct newtypes rather than bare
//! strings means a host id cannot be passed where a job id is expected.

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! prefixed_id {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// The conventional prefix for this identifier type.
            pub const PREFIX: &'static str = $prefix;

            #[must_use]
            pub fn new(raw: impl Into<String>) -> Self {
                Self(raw.into())
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Whether the value carries the prefix this type expects.
            #[must_use]
            pub fn is_well_formed(&self) -> bool {
                self.0.starts_with(Self::PREFIX)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

prefixed_id!(OrgId, "org_", "Identifies an organization (the tenant).");
prefixed_id!(HostId, "hst_", "Identifies one enrolled host.");
prefixed_id!(JobId, "job_", "Identifies one job delivered to one agent.");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_through_json_as_plain_strings() {
        let id = HostId::new("hst_webprod01");
        let json = serde_json::to_string(&id).unwrap_or_default();
        assert_eq!(json, "\"hst_webprod01\"");
    }

    #[test]
    fn well_formedness_checks_the_expected_prefix() {
        assert!(HostId::new("hst_abc").is_well_formed());
        assert!(!HostId::new("job_abc").is_well_formed());
    }
}
