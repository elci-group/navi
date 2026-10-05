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
    /// Phase 6: capabilities a human has allowed Navi to self-authorise,
    /// each backed by a readiness certificate. Empty by default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub autonomy: Vec<AutonomyGrant>,
}

/// The smallest window a human is given to interrupt an autonomous action.
pub const MIN_GRACE_MS: i64 = 1_000;

/// A human decision to let Navi self-authorise one capability (directive
/// §10 "temporary low-risk containment — policy dependent", §25 Phase 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyGrant {
    pub capability: crate::CapabilityId,
    /// Digest of the readiness certificate that justifies the grant.
    pub certificate: String,
    /// Time between self-authorisation and execution, during which a human
    /// can cancel.
    pub grace_ms: i64,
    /// The longest an autonomous intervention may stay in force.
    pub max_duration_ms: i64,
    pub granted_by: String,
}

impl AutonomyGrant {
    /// Only bounded, expiring, reversible, low-risk temporary containment
    /// can ever be autonomous (doctrine V). Everything else stays gated.
    pub fn check(&self, cap: &crate::Capability) -> Result<(), String> {
        if cap.id != self.capability {
            return Err(format!("grant names {}, not {}", self.capability, cap.id));
        }
        if cap.authority.max(cap.kind.minimum_authority()) != AuthorityLevel::TemporaryContainment {
            return Err(format!(
                "{} is {:?}; only temporary containment can be autonomous",
                cap.id, cap.authority
            ));
        }
        if cap.risk_class != crate::RiskClass::Low {
            return Err(format!(
                "{} is {:?} risk; only low-risk capabilities can be autonomous",
                cap.id, cap.risk_class
            ));
        }
        if !matches!(cap.expiry, crate::Expiry::At(_)) {
            return Err(format!(
                "{} never expires; autonomous capabilities must",
                cap.id
            ));
        }
        if !matches!(cap.rollback_method, crate::Rollback::Method(_)) {
            return Err(format!("{} has no rollback method", cap.id));
        }
        if self.grace_ms < MIN_GRACE_MS {
            return Err(format!(
                "grace {}ms is below the {MIN_GRACE_MS}ms human interruption window",
                self.grace_ms
            ));
        }
        if self.max_duration_ms <= 0 {
            return Err("an autonomous intervention needs a positive maximum duration".into());
        }
        let hex = self.certificate.strip_prefix("sha256:").unwrap_or("");
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "{:?} is not a certificate digest",
                self.certificate
            ));
        }
        if self.granted_by.trim().is_empty() {
            return Err("a grant must name the human who made it".into());
        }
        Ok(())
    }
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
            autonomy: vec![],
        }
    }

    pub fn grant_for(&self, cap: &crate::CapabilityId) -> Option<&AutonomyGrant> {
        self.autonomy.iter().find(|g| &g.capability == cap)
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
            autonomy: vec![],
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
