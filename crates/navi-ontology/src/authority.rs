use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Ordered from least to most consequential (directive §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityLevel {
    Observe,
    Query,
    Correlate,
    Simulate,
    Propose,
    TemporaryContainment,
    CredentialRevocation,
    NetworkIsolation,
    DestructiveRemediation,
    PermanentPolicyChange,
}

impl AuthorityLevel {
    pub const ALL: [AuthorityLevel; 10] = [
        Self::Observe,
        Self::Query,
        Self::Correlate,
        Self::Simulate,
        Self::Propose,
        Self::TemporaryContainment,
        Self::CredentialRevocation,
        Self::NetworkIsolation,
        Self::DestructiveRemediation,
        Self::PermanentPolicyChange,
    ];

    /// Levels that change reality rather than merely reading or reasoning.
    pub fn mutates_reality(self) -> bool {
        self > Self::Propose
    }
}

/// What it takes to exercise an authority level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Gate {
    Autonomous,
    PolicyDependent,
    HumanApproval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityPolicy {
    pub version: String,
    pub gates: BTreeMap<AuthorityLevel, Gate>,
}

impl AuthorityPolicy {
    /// The default production policy from directive §10.
    pub fn default_production() -> Self {
        use AuthorityLevel::*;
        let gates = AuthorityLevel::ALL
            .into_iter()
            .map(|l| {
                let g = match l {
                    Observe | Query | Correlate | Simulate | Propose => Gate::Autonomous,
                    TemporaryContainment => Gate::PolicyDependent,
                    _ => Gate::HumanApproval,
                };
                (l, g)
            })
            .collect();
        Self {
            version: "production-default/1".into(),
            gates,
        }
    }

    /// Unlisted levels fail closed to human approval. Reality-mutating
    /// levels can never be configured `Autonomous` by this policy alone
    /// — that is a Phase 6 decision and needs an ontology bump.
    pub fn gate(&self, level: AuthorityLevel) -> Gate {
        let g = self
            .gates
            .get(&level)
            .copied()
            .unwrap_or(Gate::HumanApproval);
        if level.mutates_reality() && g == Gate::Autonomous {
            Gate::PolicyDependent
        } else {
            g
        }
    }
}

impl Default for AuthorityPolicy {
    fn default() -> Self {
        Self::default_production()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_defaults() {
        let p = AuthorityPolicy::default_production();
        assert_eq!(p.gate(AuthorityLevel::Correlate), Gate::Autonomous);
        assert_eq!(
            p.gate(AuthorityLevel::TemporaryContainment),
            Gate::PolicyDependent
        );
        assert_eq!(
            p.gate(AuthorityLevel::CredentialRevocation),
            Gate::HumanApproval
        );
        assert_eq!(
            p.gate(AuthorityLevel::PermanentPolicyChange),
            Gate::HumanApproval
        );
    }

    #[test]
    fn missing_gate_fails_closed() {
        let p = AuthorityPolicy {
            version: "x".into(),
            gates: BTreeMap::new(),
        };
        assert_eq!(p.gate(AuthorityLevel::Observe), Gate::HumanApproval);
    }

    #[test]
    fn mutation_cannot_be_autonomous() {
        let mut p = AuthorityPolicy::default_production();
        p.gates
            .insert(AuthorityLevel::NetworkIsolation, Gate::Autonomous);
        assert_eq!(
            p.gate(AuthorityLevel::NetworkIsolation),
            Gate::PolicyDependent
        );
    }
}
