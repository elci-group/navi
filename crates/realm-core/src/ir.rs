//! Realm Intermediate Representation (directive §4). Every object carries
//! `source_ids` and (where the ontology has it) `provenance`, so selecting
//! anything in any renderer can descend to evidence (§5).

use crate::contract::VisualContract;
use crate::grammar::{EpistemicView, Primitive};
use navi_ontology::{
    ActionState, AgentPhase, AgentRole, AttackRef, AuthorityLevel, CapabilityKind, Confidence,
    D3fendRef, EntityClass, EpistemicState, Gate, Provenance, RelationKind, RiskClass,
    SafeguardKind, SafeguardStatus, Timestamp, TrustState,
};
use serde::{Deserialize, Serialize};

/// Prefix for realm ids: `realm:<source id>`.
pub const REALM_PREFIX: &str = "realm:";

pub fn realm_id(source: &str) -> String {
    format!("{REALM_PREFIX}{source}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Realm {
    pub grammar_version: String,
    pub ontology_version: String,
    pub compiler_version: String,
    /// Digest of the canonical semantic graph this realm was compiled from.
    pub source_digest: String,
    /// The latest instant any input speaks about.
    pub epoch: Timestamp,
    pub entities: Vec<RealmEntity>,
    pub edges: Vec<RealmEdge>,
    pub controls: Vec<RealmControl>,
    pub hazards: Vec<RealmHazard>,
    pub agents: Vec<RealmAgent>,
    /// Reverse resolution (§5): for every entity, edge, control and hazard,
    /// the chain down to raw observations, so selecting it can show why it
    /// exists.
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub realm_id: String,
    pub tree: EvidenceNode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceNode {
    pub id: String,
    pub kind: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<EvidenceNode>,
}

impl EvidenceNode {
    pub fn observation_leaves(&self) -> usize {
        usize::from(self.kind == "observation")
            + self
                .children
                .iter()
                .map(EvidenceNode::observation_leaves)
                .sum::<usize>()
    }
}

/// Confidence as the realm shows it: exact, with its estimator (§6: 0.51
/// and 0.99 must never look alike).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfidenceView {
    pub basis_points: u16,
    pub percent: String,
    pub estimator: String,
}

impl ConfidenceView {
    pub fn percent_label(bp: u16) -> String {
        if bp.is_multiple_of(100) {
            format!("{}%", bp / 100)
        } else {
            format!("{}.{:02}%", bp / 100, bp % 100)
        }
    }
}

impl From<&Confidence> for ConfidenceView {
    fn from(c: &Confidence) -> Self {
        Self {
            basis_points: c.basis_points(),
            percent: Self::percent_label(c.basis_points()),
            estimator: format!("{}@{}", c.estimator().name(), c.estimator().version()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Risk {
    /// Hazards that name this entity as a target/subject.
    pub hazards: Vec<String>,
    /// The strongest epistemic state among them.
    pub max_state: Option<EpistemicState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmEntity {
    pub realm_id: String,
    pub source_ids: Vec<String>,
    pub entity_class: EntityClass,
    pub semantic_type: Primitive,
    pub name: String,
    pub trust_state: TrustState,
    /// Containing place (from `contains` relationships).
    pub parent: Option<String>,
    pub risk: Risk,
    /// Strongest epistemic state of any hazard naming this as its *actor*.
    pub hostility: Option<EpistemicState>,
    pub guarded_by: Vec<String>,
    pub focused_by: Vec<String>,
    pub observed_at: Timestamp,
    pub valid_until: Option<Timestamp>,
    pub stale: bool,
    pub provenance: Provenance,
    pub visual_contract: VisualContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmEdge {
    pub realm_id: String,
    pub source_ids: Vec<String>,
    pub kind: RelationKind,
    pub semantic_type: Primitive,
    pub from: String,
    pub to: String,
    pub crosses_boundary: bool,
    pub provenance: Provenance,
    pub visual_contract: VisualContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmControl {
    pub realm_id: String,
    pub source_ids: Vec<String>,
    pub kind: SafeguardKind,
    pub semantic_type: Primitive,
    pub name: String,
    pub protects: Vec<String>,
    pub enforced_by: Option<String>,
    pub status: SafeguardStatus,
    pub d3fend: Vec<D3fendRef>,
    pub provenance: Provenance,
    pub visual_contract: VisualContract,
}

/// One per hypothesis. Threats attributed to the hypothesis are folded in
/// (their ids join `source_ids`, their actor/targets are carried).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmHazard {
    pub realm_id: String,
    pub source_ids: Vec<String>,
    pub semantic_type: Primitive,
    pub epistemic_state: EpistemicState,
    pub view: EpistemicView,
    pub confidence: ConfidenceView,
    pub claim: String,
    pub attack: Vec<AttackRef>,
    /// `None` renders as "?" — never an invented attacker.
    pub actor: Option<String>,
    pub targets: Vec<String>,
    pub opened_at: Timestamp,
    pub provenance: Provenance,
    pub visual_contract: VisualContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadoutSlot {
    pub capability: String,
    pub kind: CapabilityKind,
    pub authority: AuthorityLevel,
    /// Effective gate: what it takes to use this.
    pub gate: Gate,
    pub risk_class: RiskClass,
    pub expired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionView {
    pub realm_id: String,
    pub capability: String,
    pub target: String,
    pub hypothesis: String,
    pub state: ActionState,
}

/// Navi's embodiment. Position and intent come only from its latest
/// structured agent event (§7: never inferred from animation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAgent {
    pub realm_id: String,
    pub source_ids: Vec<String>,
    pub name: String,
    pub role: AgentRole,
    pub semantic_type: Primitive,
    pub phase: AgentPhase,
    pub at: Timestamp,
    /// The place Navi is attending to (last event target). `None` if it has
    /// never emitted an event with a target.
    pub location: Option<String>,
    pub reason: String,
    pub hypothesis: Option<String>,
    pub confidence: Option<ConfidenceView>,
    pub authority: AuthorityLevel,
    pub loadout: Vec<LoadoutSlot>,
    pub actions: Vec<ActionView>,
    /// Every agent event in order: where attention went and why (§25 Phase 2).
    pub trajectory: Vec<crate::Waypoint>,
    pub visual_contract: VisualContract,
}

impl Realm {
    pub fn entity(&self, id: &str) -> Option<&RealmEntity> {
        self.entities.iter().find(|e| e.realm_id == id)
    }

    /// Every realm id in the realm, any collection.
    pub fn all_ids(&self) -> impl Iterator<Item = &str> {
        self.entities
            .iter()
            .map(|x| x.realm_id.as_str())
            .chain(self.edges.iter().map(|x| x.realm_id.as_str()))
            .chain(self.controls.iter().map(|x| x.realm_id.as_str()))
            .chain(self.hazards.iter().map(|x| x.realm_id.as_str()))
            .chain(self.agents.iter().map(|x| x.realm_id.as_str()))
    }

    /// The nearest zone (world/region/district) at or above `id`. `None`
    /// for unplaced entities (outside the estate).
    pub fn zone_of(&self, id: &str) -> Option<&str> {
        let mut cur = self.entity(id);
        let mut hops = 0;
        while let Some(e) = cur {
            if e.semantic_type.is_zone() {
                return Some(&e.realm_id);
            }
            hops += 1;
            if hops > self.entities.len() {
                return None; // cycle; reported by validate
            }
            cur = e.parent.as_deref().and_then(|p| self.entity(p));
        }
        None
    }
}
