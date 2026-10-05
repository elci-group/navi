use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OntologyError {
    #[error("invalid id {value:?}: {reason}")]
    InvalidId { value: String, reason: String },
    #[error("invalid confidence: {0}")]
    InvalidConfidence(String),
    #[error("empty provenance: every security-significant claim needs at least one source")]
    EmptyProvenance,
    #[error("derived fact {rule:?} has no inputs")]
    EmptyDerivation { rule: String },
    #[error("field {field} must not be empty")]
    EmptyField { field: &'static str },
    #[error("invalid standards reference {value:?}: {reason}")]
    InvalidStandardRef { value: String, reason: String },
    #[error("illegal epistemic transition {from:?} -> {to:?}: {reason}")]
    IllegalEpistemicTransition {
        from: crate::EpistemicState,
        to: crate::EpistemicState,
        reason: String,
    },
    #[error("illegal action transition from {from:?} via {via}: {reason}")]
    IllegalActionTransition {
        from: crate::ActionState,
        via: &'static str,
        reason: String,
    },
    #[error("capability {kind:?} requires at least {required:?} authority, declared {declared:?}")]
    UnderstatedAuthority {
        kind: crate::CapabilityKind,
        required: crate::AuthorityLevel,
        declared: crate::AuthorityLevel,
    },
    #[error("invalid time window: {0}")]
    InvalidTimeWindow(String),
}
