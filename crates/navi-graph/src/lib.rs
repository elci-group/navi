//! The canonical semantic state graph (directive §2, middle plane).
//!
//! `navi-ontology` guarantees each object is internally legal; this crate
//! guarantees the *document* is: every reference resolves, every piece of
//! provenance grounds out in a real observation, every action respects the
//! authority model, and the agent event stream is a legal walk of the loop.
//! A [`SemanticGraph`] only exists if all of that holds.

mod explain;
mod validate;

pub use explain::ExplainNode;
pub use validate::{Code, Violation};

use navi_ontology::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The on-disk / on-wire form. Order of items is irrelevant: the graph is
/// canonicalised on load.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphDocument {
    pub ontology_version: String,
    #[serde(default)]
    pub authority_policy: AuthorityPolicy,
    #[serde(default)]
    pub epistemic_policy: EpistemicPolicy,
    #[serde(default)]
    pub observations: Vec<Observation>,
    #[serde(default)]
    pub entities: Vec<Entity>,
    #[serde(default)]
    pub relationships: Vec<Relationship>,
    #[serde(default)]
    pub hypotheses: Vec<Hypothesis>,
    #[serde(default)]
    pub threats: Vec<Threat>,
    #[serde(default)]
    pub safeguards: Vec<Safeguard>,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub agents: Vec<Agent>,
    #[serde(default)]
    pub agent_events: Vec<AgentEvent>,
    #[serde(default)]
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone)]
pub struct SemanticGraph {
    pub authority_policy: AuthorityPolicy,
    pub epistemic_policy: EpistemicPolicy,
    pub observations: BTreeMap<ObservationId, Observation>,
    pub entities: BTreeMap<EntityId, Entity>,
    pub relationships: BTreeMap<RelationshipId, Relationship>,
    pub hypotheses: BTreeMap<HypothesisId, Hypothesis>,
    pub threats: BTreeMap<ThreatId, Threat>,
    pub safeguards: BTreeMap<SafeguardId, Safeguard>,
    pub capabilities: BTreeMap<CapabilityId, Capability>,
    pub agents: BTreeMap<AgentId, Agent>,
    /// Keyed by (agent, seq): the per-agent event stream in order.
    pub agent_events: BTreeMap<(AgentId, u64), AgentEvent>,
    pub actions: BTreeMap<ActionId, Action>,
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("parse error: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("{} violation(s)", .0.len())]
    Invalid(Vec<Violation>),
}

fn index<K: Ord + Clone + std::fmt::Display, V>(
    items: Vec<V>,
    key: impl Fn(&V) -> K,
    violations: &mut Vec<Violation>,
) -> BTreeMap<K, V> {
    let mut map = BTreeMap::new();
    for item in items {
        match map.entry(key(&item)) {
            std::collections::btree_map::Entry::Occupied(e) => violations.push(Violation::new(
                Code::DuplicateId,
                e.key().to_string(),
                "id appears more than once",
            )),
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(item);
            }
        }
    }
    map
}

impl SemanticGraph {
    pub fn from_json(text: &str) -> Result<Self, LoadError> {
        let doc: GraphDocument = serde_json::from_str(text)?;
        Self::load(doc).map_err(LoadError::Invalid)
    }

    pub fn load(doc: GraphDocument) -> Result<Self, Vec<Violation>> {
        let mut v = Vec::new();
        if doc.ontology_version != ONTOLOGY_VERSION {
            v.push(Violation::new(
                Code::OntologyVersionMismatch,
                "document",
                format!(
                    "document is {:?}, this build speaks {ONTOLOGY_VERSION:?}",
                    doc.ontology_version
                ),
            ));
        }
        let mut events_seen = std::collections::BTreeSet::new();
        let mut agent_events = BTreeMap::new();
        for e in doc.agent_events {
            let k = (e.agent.clone(), e.seq);
            if !events_seen.insert(k.clone()) {
                v.push(Violation::new(
                    Code::DuplicateId,
                    format!("{}#{}", k.0, k.1),
                    "duplicate agent event seq",
                ));
            } else {
                agent_events.insert(k, e);
            }
        }
        let g = SemanticGraph {
            authority_policy: doc.authority_policy,
            epistemic_policy: doc.epistemic_policy,
            observations: index(doc.observations, |o| o.id.clone(), &mut v),
            entities: index(doc.entities, |o| o.id.clone(), &mut v),
            relationships: index(doc.relationships, |o| o.id.clone(), &mut v),
            hypotheses: index(doc.hypotheses, |o| o.id.clone(), &mut v),
            threats: index(doc.threats, |o| o.id.clone(), &mut v),
            safeguards: index(doc.safeguards, |o| o.id.clone(), &mut v),
            capabilities: index(doc.capabilities, |o| o.id.clone(), &mut v),
            agents: index(doc.agents, |o| o.id.clone(), &mut v),
            agent_events,
            actions: index(doc.actions, |o| o.id.clone(), &mut v),
        };
        v.extend(g.validate());
        if v.is_empty() {
            Ok(g)
        } else {
            v.sort();
            Err(v)
        }
    }

    /// The canonical document: every collection in id order, every JSON
    /// object key sorted. Identical canonical state => identical bytes.
    pub fn to_document(&self) -> GraphDocument {
        GraphDocument {
            ontology_version: ONTOLOGY_VERSION.to_string(),
            authority_policy: self.authority_policy.clone(),
            epistemic_policy: self.epistemic_policy.clone(),
            observations: self.observations.values().cloned().collect(),
            entities: self.entities.values().cloned().collect(),
            relationships: self.relationships.values().cloned().collect(),
            hypotheses: self.hypotheses.values().cloned().collect(),
            threats: self.threats.values().cloned().collect(),
            safeguards: self.safeguards.values().cloned().collect(),
            capabilities: self.capabilities.values().cloned().collect(),
            agents: self.agents.values().cloned().collect(),
            agent_events: self.agent_events.values().cloned().collect(),
            actions: self.actions.values().cloned().collect(),
        }
    }

    pub fn canonical_json(&self) -> String {
        // Going through `Value` sorts every object's keys (serde_json's
        // default map is a BTreeMap).
        let value = serde_json::to_value(self.to_document()).expect("ontology types serialize");
        serde_json::to_string(&value).expect("value serializes")
    }

    /// `sha256:<hex>` of the canonical JSON.
    pub fn digest(&self) -> String {
        let hash = Sha256::digest(self.canonical_json().as_bytes());
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        format!("sha256:{hex}")
    }

    /// Is `target` equal to, or inside (via `contains` edges), `root`?
    pub fn within(&self, root: &EntityId, target: &EntityId) -> bool {
        let mut stack = vec![root];
        let mut seen = std::collections::BTreeSet::new();
        while let Some(n) = stack.pop() {
            if n == target {
                return true;
            }
            if !seen.insert(n) {
                continue;
            }
            stack.extend(
                self.relationships
                    .values()
                    .filter(|r| r.kind == RelationKind::Contains && &r.from == n)
                    .map(|r| &r.to),
            );
        }
        false
    }

    /// The effective gate for a capability: the stricter of the
    /// capability's own requirement and the authority policy, evaluated at
    /// the higher of its declared and intrinsic authority — so a capability
    /// that understates its authority is still gated as what it really is.
    pub fn effective_gate(&self, cap: &Capability) -> Gate {
        let authority = cap.authority.max(cap.kind.minimum_authority());
        cap.approval_requirement
            .max(self.authority_policy.gate(authority))
    }

    pub fn summary(&self) -> BTreeMap<&'static str, usize> {
        BTreeMap::from([
            ("observations", self.observations.len()),
            ("entities", self.entities.len()),
            ("relationships", self.relationships.len()),
            ("hypotheses", self.hypotheses.len()),
            ("threats", self.threats.len()),
            ("safeguards", self.safeguards.len()),
            ("capabilities", self.capabilities.len()),
            ("agents", self.agents.len()),
            ("agent_events", self.agent_events.len()),
            ("actions", self.actions.len()),
        ])
    }
}
