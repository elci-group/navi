//! Navi traversal (directive §25 Phase 2, §13, §22).
//!
//! Agent attention produces movement: between two consecutive agent events
//! Navi's attention moves from one place to the next along a route over the
//! realm's actual topology. Movement may be interpolated by a renderer;
//! the waypoints (semantic events) may not.

use crate::ir::{ConfidenceView, Realm};
use navi_ontology::{ActionState, AgentPhase, AuthorityLevel, EpistemicState, Timestamp};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Movement {
    /// Into or out of a containing place.
    Walk,
    Road,
    Door,
    Bridge,
    /// Along a logical relationship, or a jump where no topological path
    /// exists (`via: None`).
    Teleport,
}

impl Movement {
    fn cost(self) -> u32 {
        match self {
            Self::Walk | Self::Road => 1,
            Self::Door => 2,
            Self::Bridge => 3,
            Self::Teleport => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteStep {
    pub movement: Movement,
    pub from: String,
    pub to: String,
    /// The realm edge travelled, if any.
    pub via: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NextView {
    pub phase: AgentPhase,
    pub target: Option<String>,
    pub intent: String,
}

/// The §8 brief at one waypoint, with realm ids. Produced by
/// `navi-graph`'s headless `brief`; the realm only re-addresses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BriefView {
    pub location: Option<String>,
    pub location_from_seq: Option<u64>,
    pub path: Vec<String>,
    pub reason: String,
    pub objective: Option<String>,
    pub hypothesis: Option<String>,
    pub hypothesis_from_seq: Option<u64>,
    pub claim: Option<String>,
    pub state_then: Option<EpistemicState>,
    pub evidence_then: Vec<String>,
    pub phase: AgentPhase,
    pub authority: AuthorityLevel,
    pub action: Option<String>,
    pub action_state_then: Option<ActionState>,
    pub confidence: Option<ConfidenceView>,
    pub confidence_from_seq: Option<u64>,
    pub hypothesis_confidence_then: Option<ConfidenceView>,
    pub next: Option<NextView>,
    pub legal_next: Vec<AgentPhase>,
    pub awaiting_authorisation: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Waypoint {
    pub seq: u64,
    pub at: Timestamp,
    pub phase: AgentPhase,
    pub location: Option<String>,
    /// How attention got here from the previous waypoint's location.
    pub route: Vec<RouteStep>,
    pub brief: BriefView,
}

/// Neighbour place, how you get there, and the edge travelled (if any).
type Hop<'r> = (&'r str, Movement, Option<&'r str>);

impl Realm {
    fn adjacency(&self) -> BTreeMap<&str, Vec<Hop<'_>>> {
        let mut adj: BTreeMap<&str, Vec<Hop<'_>>> = BTreeMap::new();
        for e in &self.entities {
            adj.entry(&e.realm_id).or_default();
            if let Some(p) = e.parent.as_deref().filter(|p| self.entity(p).is_some()) {
                adj.entry(&e.realm_id)
                    .or_default()
                    .push((p, Movement::Walk, None));
                adj.entry(p)
                    .or_default()
                    .push((&e.realm_id, Movement::Walk, None));
            }
        }
        for e in &self.edges {
            let m = match e.semantic_type {
                crate::Primitive::Road => Movement::Road,
                crate::Primitive::Door => Movement::Door,
                crate::Primitive::Bridge => Movement::Bridge,
                _ => Movement::Teleport,
            };
            adj.entry(&e.from)
                .or_default()
                .push((&e.to, m, Some(&e.realm_id)));
            adj.entry(&e.to)
                .or_default()
                .push((&e.from, m, Some(&e.realm_id)));
        }
        for v in adj.values_mut() {
            v.sort();
        }
        adj
    }

    /// The cheapest route over the realm's topology, deterministic on ties.
    /// No path at all is an explicit `Teleport` with `via: None`.
    pub fn route(&self, from: &str, to: &str) -> Vec<RouteStep> {
        if from == to {
            return vec![];
        }
        let adj = self.adjacency();
        let mut dist: BTreeMap<&str, u32> = BTreeMap::from([(from, 0)]);
        let mut prev: BTreeMap<&str, Hop<'_>> = BTreeMap::new();
        let mut heap = BinaryHeap::from([Reverse((0u32, from))]);
        while let Some(Reverse((d, n))) = heap.pop() {
            if n == to {
                break;
            }
            if dist.get(n).is_some_and(|&best| d > best) {
                continue;
            }
            for &(m, mv, via) in adj.get(n).map(Vec::as_slice).unwrap_or(&[]) {
                let nd = d + mv.cost();
                if dist.get(m).is_none_or(|&best| nd < best) {
                    dist.insert(m, nd);
                    prev.insert(m, (n, mv, via));
                    heap.push(Reverse((nd, m)));
                }
            }
        }
        if !prev.contains_key(to) {
            return vec![RouteStep {
                movement: Movement::Teleport,
                from: from.into(),
                to: to.into(),
                via: None,
            }];
        }
        let mut steps = vec![];
        let mut cur = to;
        while cur != from {
            let (p, mv, via) = prev[cur];
            steps.push(RouteStep {
                movement: mv,
                from: p.into(),
                to: cur.into(),
                via: via.map(Into::into),
            });
            cur = p;
        }
        steps.reverse();
        steps
    }
}
