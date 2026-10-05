//! Interoperability references to MITRE ATT&CK and D3FEND (directive §14).
//!
//! Phase 0 validates identifier *shape* only. It deliberately ships no
//! technique catalogue: inventing names for ids would itself be fabrication.
//! Catalogue resolution belongs to `navi-attck` / `navi-d3fend`.

use crate::OntologyError;
use serde::{Deserialize, Serialize};

fn digits(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| b.is_ascii_digit())
}

/// `TA0006` (tactic), `T1110` (technique) or `T1110.004` (sub-technique).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AttackRef(String);

impl AttackRef {
    pub fn new(value: impl Into<String>) -> Result<Self, OntologyError> {
        let value = value.into();
        let ok = if let Some(rest) = value.strip_prefix("TA") {
            digits(rest, 4)
        } else if let Some(rest) = value.strip_prefix('T') {
            match rest.split_once('.') {
                Some((t, sub)) => digits(t, 4) && digits(sub, 3),
                None => digits(rest, 4),
            }
        } else {
            false
        };
        if ok {
            Ok(Self(value))
        } else {
            Err(OntologyError::InvalidStandardRef {
                value,
                reason: "expected ATT&CK id like TA0006, T1110 or T1110.004".into(),
            })
        }
    }

    pub fn is_tactic(&self) -> bool {
        self.0.starts_with("TA")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for AttackRef {
    type Error = OntologyError;
    fn try_from(v: String) -> Result<Self, Self::Error> {
        Self::new(v)
    }
}
impl From<AttackRef> for String {
    fn from(r: AttackRef) -> Self {
        r.0
    }
}

/// A D3FEND technique id such as `D3-ANET` or `D3-CR`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct D3fendRef(String);

impl D3fendRef {
    pub fn new(value: impl Into<String>) -> Result<Self, OntologyError> {
        let value = value.into();
        let ok = value.strip_prefix("D3-").is_some_and(|r| {
            !r.is_empty()
                && r.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        });
        if ok {
            Ok(Self(value))
        } else {
            Err(OntologyError::InvalidStandardRef {
                value,
                reason: "expected D3FEND id like D3-ANET".into(),
            })
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for D3fendRef {
    type Error = OntologyError;
    fn try_from(v: String) -> Result<Self, Self::Error> {
        Self::new(v)
    }
}
impl From<D3fendRef> for String {
    fn from(r: D3fendRef) -> Self {
        r.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_shapes() {
        for ok in ["TA0006", "T1110", "T1110.004"] {
            assert!(AttackRef::new(ok).is_ok(), "{ok}");
        }
        for bad in ["T111", "T1110.4", "TA06", "credential-stuffing", "t1110"] {
            assert!(AttackRef::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn d3fend_shapes() {
        assert!(D3fendRef::new("D3-ANET").is_ok());
        assert!(D3fendRef::new("D3-").is_err());
        assert!(D3fendRef::new("ANET").is_err());
    }
}
