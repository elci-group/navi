//! Navi Phase 0 — the canonical security ontology.
//!
//! This crate is the vocabulary of the *semantic state graph* (directive §2).
//! It knows nothing about rendering. Every type here enforces its own
//! invariants at construction/deserialization time, so that a value which
//! exists is a value which is legal:
//!
//! * a [`Confidence`] cannot exist without an [`Estimator`] (§19),
//! * a [`Provenance`] cannot be empty (§5, "no pixel without provenance"),
//! * an epistemic promotion requires new evidence (§6),
//! * an [`Action`] cannot reach `Succeeded` from a command return alone, nor
//!   `Verified` without a separate verification step (§20),
//! * a [`Capability`] cannot claim less authority than its kind intrinsically
//!   requires (§9, §10).
//!
//! Cross-object invariants (does this id exist? does this evidence ground out
//! in a real observation?) live in `navi-graph`.

mod action;
mod agent;
mod authority;
mod capability;
mod confidence;
mod entity;
mod epistemic;
mod error;
mod hypothesis;
mod ids;
mod observation;
mod provenance;
mod relationship;
mod safeguard;
mod standards;
mod threat;
mod time;

pub use action::{Action, ActionState, ActionTransition, Approval, ApprovalKind, Principal};
pub use agent::{Agent, AgentEvent, AgentPhase, AgentRole, NextStep};
pub use authority::{AuthorityLevel, AuthorityPolicy, Gate};
pub use capability::{Capability, CapabilityKind, Expiry, RiskClass, Rollback};
pub use confidence::{Confidence, Estimator};
pub use entity::{Entity, EntityClass, TrustState};
pub use epistemic::{EpistemicPolicy, EpistemicState};
pub use error::OntologyError;
pub use hypothesis::{EpistemicTransition, Hypothesis};
pub use ids::{
    ActionId, AgentId, ApprovalId, CapabilityId, EntityId, HypothesisId, ObservationId,
    RelationshipId, SafeguardId, ThreatId,
};
pub use observation::{Observation, TelemetrySource};
pub use provenance::{Provenance, SourceRef};
pub use relationship::{RelationKind, Relationship};
pub use safeguard::{Safeguard, SafeguardKind, SafeguardStatus};
pub use standards::{AttackRef, D3fendRef};
pub use threat::Threat;
pub use time::Timestamp;

/// Version of this ontology. Bumped on any change to the meaning of a type
/// (directive §3: "this ontology MUST be versioned").
///
/// 0.2: agent events may declare `objective` and `next` (§8 HUD), so the
/// realm never has to infer what Navi intends to do next.
///
/// 0.3: a VERIFIED intervention may be rolled back (lifting containment);
/// VERIFIED is no longer terminal.
pub const ONTOLOGY_VERSION: &str = "navi-ontology/0.3";
