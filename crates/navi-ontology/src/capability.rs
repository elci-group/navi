use crate::{AuthorityLevel, CapabilityId, EntityClass, EntityId, OntologyError, Timestamp};
use serde::{Deserialize, Serialize};

/// The loadout vocabulary from directive §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityKind {
    Scan,
    Trace,
    Scope,
    Shield,
    Barrier,
    Lock,
    Isolate,
    Cleanse,
    Restore,
    Recall,
    Beacon,
    Drone,
}

impl CapabilityKind {
    /// The least authority that honestly describes what this kind does. A
    /// capability may declare more, never less: a LOCK cannot be filed as
    /// "observe" to dodge an approval gate.
    pub fn minimum_authority(self) -> AuthorityLevel {
        use AuthorityLevel as A;
        match self {
            Self::Scan | Self::Scope | Self::Drone => A::Query,
            Self::Trace => A::Correlate,
            Self::Beacon => A::Propose,
            Self::Shield | Self::Barrier => A::TemporaryContainment,
            Self::Lock => A::CredentialRevocation,
            Self::Isolate => A::NetworkIsolation,
            Self::Cleanse | Self::Restore | Self::Recall => A::DestructiveRemediation,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Rollback {
    Method(String),
    /// Explicitly irreversible, with a stated reason (doctrine V).
    Irreversible {
        justification: String,
    },
    /// Read-only capabilities have nothing to roll back.
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Expiry {
    At(Timestamp),
    Never,
}

/// A defensive capability with every field §9 requires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub id: CapabilityId,
    pub kind: CapabilityKind,
    /// Entities whose `contains`-subtrees this capability may target.
    pub scope: Vec<EntityId>,
    pub target_classes: Vec<EntityClass>,
    pub authority: AuthorityLevel,
    pub risk_class: RiskClass,
    /// The capability's own gate. Effective gate is the stricter of this
    /// and the authority policy's gate.
    pub approval_requirement: crate::Gate,
    pub rollback_method: Rollback,
    pub verification_method: String,
    pub expiry: Expiry,
}

impl Capability {
    pub fn check(&self) -> Result<(), OntologyError> {
        let required = self.kind.minimum_authority();
        if self.authority < required {
            return Err(OntologyError::UnderstatedAuthority {
                kind: self.kind,
                required,
                declared: self.authority,
            });
        }
        if self.scope.is_empty() {
            return Err(OntologyError::EmptyField {
                field: "capability.scope",
            });
        }
        if self.target_classes.is_empty() {
            return Err(OntologyError::EmptyField {
                field: "capability.target_classes",
            });
        }
        if self.verification_method.trim().is_empty() {
            return Err(OntologyError::EmptyField {
                field: "capability.verification_method",
            });
        }
        match &self.rollback_method {
            Rollback::Method(m) if m.trim().is_empty() => {
                return Err(OntologyError::EmptyField {
                    field: "capability.rollback_method",
                })
            }
            Rollback::Irreversible { justification } if justification.trim().is_empty() => {
                return Err(OntologyError::EmptyField {
                    field: "rollback.justification",
                })
            }
            Rollback::NotApplicable if self.authority.mutates_reality() => {
                return Err(OntologyError::EmptyField {
                    field: "capability.rollback_method",
                })
            }
            _ => {}
        }
        Ok(())
    }

    pub fn expired_at(&self, t: Timestamp) -> bool {
        matches!(self.expiry, Expiry::At(e) if t >= e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Gate;

    fn cap(kind: CapabilityKind, authority: AuthorityLevel) -> Capability {
        Capability {
            id: CapabilityId::new("cap:x").unwrap(),
            kind,
            scope: vec![EntityId::new("ent:prod").unwrap()],
            target_classes: vec![EntityClass::Credential],
            authority,
            risk_class: RiskClass::High,
            approval_requirement: Gate::HumanApproval,
            rollback_method: Rollback::Method("reissue credential".into()),
            verification_method: "auth attempts with token fail".into(),
            expiry: Expiry::Never,
        }
    }

    #[test]
    fn understated_authority_is_rejected() {
        assert!(cap(CapabilityKind::Lock, AuthorityLevel::Observe)
            .check()
            .is_err());
        assert!(
            cap(CapabilityKind::Lock, AuthorityLevel::CredentialRevocation)
                .check()
                .is_ok()
        );
    }

    #[test]
    fn mutating_capability_needs_rollback_story() {
        let mut c = cap(CapabilityKind::Lock, AuthorityLevel::CredentialRevocation);
        c.rollback_method = Rollback::NotApplicable;
        assert!(c.check().is_err());
    }
}
