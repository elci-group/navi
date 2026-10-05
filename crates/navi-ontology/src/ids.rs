//! Typed, prefixed identifiers. The prefix makes cross-kind confusion
//! impossible even in raw JSON: an `ObservationId` must start with `obs:`.

use crate::OntologyError;
use serde::{Deserialize, Serialize};
use std::fmt;

fn validate(prefix: &str, value: &str) -> Result<(), OntologyError> {
    let err = |reason: &str| OntologyError::InvalidId {
        value: value.to_string(),
        reason: reason.to_string(),
    };
    let rest = value
        .strip_prefix(prefix)
        .ok_or_else(|| err(&format!("must start with {prefix:?}")))?;
    if rest.is_empty() {
        return Err(err("empty after prefix"));
    }
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(err("must not contain whitespace or control characters"));
    }
    Ok(())
}

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            pub fn new(value: impl Into<String>) -> Result<Self, OntologyError> {
                let value = value.into();
                validate(Self::PREFIX, &value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = OntologyError;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id_type!(
    /// A raw telemetry observation — the leaf of every provenance chain.
    ObservationId, "obs:");
id_type!(EntityId, "ent:");
id_type!(RelationshipId, "rel:");
id_type!(HypothesisId, "hyp:");
id_type!(ThreatId, "thr:");
id_type!(SafeguardId, "sg:");
id_type!(AgentId, "agent:");
id_type!(CapabilityId, "cap:");
id_type!(ActionId, "act:");
id_type!(ApprovalId, "appr:");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_enforced() {
        assert!(EntityId::new("ent:auth-api").is_ok());
        assert!(EntityId::new("obs:auth-api").is_err());
        assert!(EntityId::new("ent:").is_err());
        assert!(EntityId::new("ent:a b").is_err());
    }

    #[test]
    fn deserialization_validates() {
        let ok: Result<ObservationId, _> = serde_json::from_str("\"obs:1\"");
        assert!(ok.is_ok());
        let bad: Result<ObservationId, _> = serde_json::from_str("\"ent:1\"");
        assert!(bad.is_err());
    }
}
