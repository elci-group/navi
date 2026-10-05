//! The Realm Compiler (directive §4): `SemanticGraph -> Realm`.
//!
//! Pure and deterministic: identical canonical state + identical
//! [`COMPILER_VERSION`] produce byte-identical realms (§26). The compiler
//! performs no security reasoning of its own; every decision about *what
//! something is* comes from `navi-graph`, every decision about *how it
//! appears* comes from `realm_core::grammar` and `realm_core::contract`.

use navi_graph::SemanticGraph;
use navi_ontology::*;
use realm_core::{contract, grammar, *};
use std::collections::{BTreeMap, BTreeSet};

pub const COMPILER_VERSION: &str = "realm-compiler/0.2";

fn rid(id: &impl ToString) -> String {
    realm_id(&id.to_string())
}

fn blank() -> VisualContract {
    VisualContract {
        primitive: Primitive::Fog,
        glyph: ' ',
        fill: Token::Neutral,
        stroke: Token::Neutral,
        line: Line::Solid,
        badges: BTreeSet::new(),
        label: String::new(),
    }
}

/// The latest instant any part of the graph speaks about.
pub fn epoch(g: &SemanticGraph) -> Timestamp {
    let mut t = Timestamp(0);
    let mut see = |x: Timestamp| t = t.max(x);
    g.observations.values().for_each(|o| see(o.observed_at));
    g.entities.values().for_each(|e| see(e.observed_at));
    g.agent_events.values().for_each(|e| see(e.at));
    for h in g.hypotheses.values() {
        see(h.opened_at);
        h.transitions.iter().for_each(|x| see(x.at));
    }
    for a in g.actions.values() {
        see(a.proposed_at);
        a.history.iter().for_each(|x| see(x.at()));
    }
    t
}

pub fn compile(g: &SemanticGraph) -> Realm {
    let epoch = epoch(g);

    // Containment: first `contains` relationship (by id) wins if an entity
    // has several containers; nesting needs a single parent.
    let mut parent: BTreeMap<&EntityId, &EntityId> = BTreeMap::new();
    for r in g
        .relationships
        .values()
        .filter(|r| r.kind == RelationKind::Contains)
    {
        parent.entry(&r.to).or_insert(&r.from);
    }

    // Hazards: one per hypothesis, with its threats folded in.
    let mut hazards: Vec<RealmHazard> = g
        .hypotheses
        .values()
        .map(|h| {
            let threats: Vec<&Threat> = g
                .threats
                .values()
                .filter(|t| t.hypothesis == h.id)
                .collect();
            let actors: BTreeSet<&EntityId> =
                threats.iter().filter_map(|t| t.actor.as_ref()).collect();
            // Ambiguous attribution renders as "?", never as a guess.
            let actor = (actors.len() == 1 && threats.iter().all(|t| t.actor.is_some()))
                .then(|| rid(actors.iter().next().unwrap()));
            let targets: BTreeSet<String> = if threats.is_empty() {
                h.subjects.iter().map(rid).collect()
            } else {
                threats
                    .iter()
                    .flat_map(|t| t.targets.iter().map(rid))
                    .collect()
            };
            let mut source_ids = vec![h.id.to_string()];
            source_ids.extend(threats.iter().map(|t| t.id.to_string()));
            let state = h.state();
            let technique = h.attack.iter().any(|a| !a.is_tactic());
            let mut hz = RealmHazard {
                realm_id: rid(&h.id),
                source_ids,
                semantic_type: grammar::hazard_primitive(state),
                epistemic_state: state,
                view: grammar::epistemic_view(state, technique),
                confidence: ConfidenceView::from(h.confidence()),
                claim: h.claim.clone(),
                attack: h.attack.clone(),
                actor,
                targets: targets.into_iter().collect(),
                opened_at: h.opened_at,
                provenance: h.evidence(),
                visual_contract: blank(),
            };
            hz.visual_contract = contract::hazard(&hz);
            hz
        })
        .collect();
    hazards.sort_by(|a, b| a.realm_id.cmp(&b.realm_id));

    // Agents: state from the latest event only.
    // Position = latest event with a target; belief = latest event with a
    // hypothesis. Each contributing event is cited in `source_ids`.
    let mut latest: BTreeMap<&AgentId, &AgentEvent> = BTreeMap::new();
    let mut located: BTreeMap<&AgentId, &AgentEvent> = BTreeMap::new();
    let mut believed: BTreeMap<&AgentId, &AgentEvent> = BTreeMap::new();
    // Latest confidence estimate per (agent, hypothesis).
    let mut estimated: BTreeMap<(&AgentId, &HypothesisId), &AgentEvent> = BTreeMap::new();
    for ((agent, _), e) in &g.agent_events {
        if let (Some(h), Some(_)) = (&e.hypothesis, &e.confidence) {
            estimated.insert((agent, h), e);
        }
        latest.insert(agent, e);
        if e.target.is_some() {
            located.insert(agent, e);
        }
        if e.hypothesis.is_some() {
            believed.insert(agent, e);
        }
    }
    let agents: Vec<RealmAgent> = g
        .agents
        .values()
        .map(|a| {
            let ev = latest.get(&a.id);
            let at = located.get(&a.id);
            let belief = believed.get(&a.id);
            let estimate = belief
                .and_then(|b| b.hypothesis.as_ref())
                .and_then(|h| estimated.get(&(&a.id, h)));
            let mut cited: Vec<u64> = [ev, at, belief, estimate]
                .into_iter()
                .flatten()
                .map(|e| e.seq)
                .collect();
            cited.sort_unstable_by(|x, y| y.cmp(x));
            cited.dedup();
            let mut source_ids = vec![a.id.to_string()];
            source_ids.extend(cited.into_iter().map(|seq| format!("{}#{seq}", a.id)));
            let loadout = a
                .loadout
                .iter()
                .filter_map(|c| g.capabilities.get(c))
                .map(|c| LoadoutSlot {
                    capability: c.id.to_string(),
                    kind: c.kind,
                    authority: c.authority,
                    gate: g.effective_gate(c),
                    risk_class: c.risk_class,
                    expired: c.expired_at(epoch),
                })
                .collect();
            let actions = g
                .actions
                .values()
                .filter(|x| x.agent == a.id)
                .map(|x| ActionView {
                    realm_id: rid(&x.id),
                    capability: x.capability.to_string(),
                    target: rid(&x.target),
                    hypothesis: rid(&x.hypothesis),
                    state: x.state(),
                })
                .collect();
            let mut ra = RealmAgent {
                realm_id: rid(&a.id),
                source_ids,
                name: a.name.clone(),
                role: a.role,
                semantic_type: Primitive::Navi,
                phase: ev.map(|e| e.phase),
                at: ev.map(|e| e.at),
                location: at.and_then(|e| e.target.as_ref()).map(rid),
                reason: ev.map(|e| e.reason.clone()),
                hypothesis: belief.and_then(|e| e.hypothesis.as_ref()).map(rid),
                confidence: estimate
                    .and_then(|e| e.confidence.as_ref())
                    .map(ConfidenceView::from),
                authority: ev.map(|e| e.authority),
                loadout,
                actions,
                trajectory: vec![],
                visual_contract: blank(),
            };
            ra.visual_contract = contract::agent(&ra);
            ra
        })
        .collect();

    let controls: Vec<RealmControl> = g
        .safeguards
        .values()
        .map(|s| {
            let mut c = RealmControl {
                realm_id: rid(&s.id),
                source_ids: vec![s.id.to_string()],
                kind: s.kind,
                semantic_type: grammar::control_primitive(s.kind),
                name: s.name.clone(),
                protects: s.protects.iter().map(rid).collect(),
                enforced_by: s.enforced_by.as_ref().map(rid),
                status: s.status,
                d3fend: s.d3fend.clone(),
                provenance: s.provenance.clone(),
                visual_contract: blank(),
            };
            c.visual_contract = contract::control(&c);
            c
        })
        .collect();

    let entities: Vec<RealmEntity> = g
        .entities
        .values()
        .map(|e| {
            let id = rid(&e.id);
            let targeting: Vec<&RealmHazard> =
                hazards.iter().filter(|h| h.targets.contains(&id)).collect();
            let hostility = hazards
                .iter()
                .filter(|h| h.actor.as_deref() == Some(id.as_str()))
                .map(|h| h.epistemic_state)
                .max();
            let mut re = RealmEntity {
                semantic_type: grammar::entity_primitive(e.class, e.trust, hostility),
                source_ids: vec![e.id.to_string()],
                entity_class: e.class,
                name: e.name.clone(),
                trust_state: e.trust,
                parent: parent.get(&e.id).map(rid),
                risk: Risk {
                    hazards: targeting.iter().map(|h| h.realm_id.clone()).collect(),
                    max_state: targeting.iter().map(|h| h.epistemic_state).max(),
                },
                hostility,
                guarded_by: controls
                    .iter()
                    .filter(|c| c.status == SafeguardStatus::Active && c.protects.contains(&id))
                    .map(|c| c.realm_id.clone())
                    .collect(),
                focused_by: agents
                    .iter()
                    .filter(|a| a.location.as_deref() == Some(id.as_str()))
                    .map(|a| a.realm_id.clone())
                    .collect(),
                observed_at: e.observed_at,
                valid_until: e.valid_until,
                stale: e.valid_until.is_some_and(|v| v < epoch),
                provenance: e.provenance.clone(),
                realm_id: id,
                visual_contract: blank(),
            };
            re.visual_contract = contract::entity(&re);
            re
        })
        .collect();

    let mut realm = Realm {
        grammar_version: GRAMMAR_VERSION.to_string(),
        branch: g.branch.as_ref().map(|b| BranchInfo {
            fork_of: b.fork_of.clone(),
            at: b.at,
            label: b.label.clone(),
        }),
        ontology_version: ONTOLOGY_VERSION.to_string(),
        compiler_version: COMPILER_VERSION.to_string(),
        source_digest: g.digest(),
        epoch,
        entities,
        edges: vec![],
        controls,
        hazards,
        agents,
        evidence: vec![],
    };

    let edges = g
        .relationships
        .values()
        .filter_map(|r| {
            let (from, to) = (rid(&r.from), rid(&r.to));
            let crosses = realm.zone_of(&from) != realm.zone_of(&to);
            let semantic_type = grammar::edge_primitive(r.kind, crosses)?;
            let mut e = RealmEdge {
                realm_id: rid(&r.id),
                source_ids: vec![r.id.to_string()],
                kind: r.kind,
                semantic_type,
                from,
                to,
                crosses_boundary: crosses,
                provenance: r.provenance.clone(),
                visual_contract: blank(),
            };
            e.visual_contract = contract::edge(&e);
            Some(e)
        })
        .collect();
    realm.edges = edges;

    // Trajectories need the finished topology to route over.
    let trajectories: Vec<Vec<Waypoint>> = realm
        .agents
        .iter()
        .map(|a| trajectory(g, &realm, a))
        .collect();
    for (a, t) in realm.agents.iter_mut().zip(trajectories) {
        a.trajectory = t;
    }

    let primaries: Vec<String> = realm
        .entities
        .iter()
        .map(|x| x.source_ids[0].clone())
        .chain(realm.edges.iter().map(|x| x.source_ids[0].clone()))
        .chain(realm.controls.iter().map(|x| x.source_ids[0].clone()))
        .chain(realm.hazards.iter().map(|x| x.source_ids[0].clone()))
        .collect();
    realm.evidence = primaries
        .iter()
        .filter_map(|src| {
            g.explain(src).map(|t| Evidence {
                realm_id: realm_id(src),
                tree: evidence(&t),
            })
        })
        .collect();
    realm.evidence.sort_by(|a, b| a.realm_id.cmp(&b.realm_id));
    realm
}

fn evidence(n: &navi_graph::ExplainNode) -> EvidenceNode {
    EvidenceNode {
        id: n.id.clone(),
        kind: n.kind.to_string(),
        summary: n.summary.clone(),
        children: n.children.iter().map(evidence).collect(),
    }
}

fn trajectory(g: &SemanticGraph, realm: &Realm, a: &RealmAgent) -> Vec<Waypoint> {
    let Ok(id) = AgentId::new(a.source_ids[0].clone()) else {
        return vec![];
    };
    let mut out: Vec<Waypoint> = vec![];
    for seq in g.agent_seqs(&id) {
        let Some(b) = g.brief(&id, Some(seq)) else {
            continue;
        };
        let location = b.where_.target.as_ref().map(|t| rid(&t.value));
        let route = match (
            out.last().and_then(|w| w.location.as_deref()),
            location.as_deref(),
        ) {
            (Some(f), Some(t)) => realm.route(f, t),
            _ => vec![],
        };
        let brief = BriefView {
            location: location.clone(),
            location_from_seq: b.where_.target.as_ref().map(|t| t.from_seq),
            path: b.where_.path.clone(),
            reason: b.why.reason.clone(),
            objective: b.why.objective.as_ref().map(|o| o.value.clone()),
            hypothesis: b.why.hypothesis.as_ref().map(|h| rid(&h.value)),
            hypothesis_from_seq: b.why.hypothesis.as_ref().map(|h| h.from_seq),
            claim: b.why.claim.clone(),
            state_then: b.why.state_then,
            evidence_then: b.why.evidence_then.iter().map(|o| o.to_string()).collect(),
            phase: b.what.phase,
            authority: b.what.authority,
            action: b.what.action.as_ref().map(rid),
            action_state_then: b.what.action_state_then,
            confidence: b
                .confidence
                .as_ref()
                .map(|c| ConfidenceView::from(&c.navi.value)),
            confidence_from_seq: b.confidence.as_ref().map(|c| c.navi.from_seq),
            hypothesis_confidence_then: b
                .confidence
                .as_ref()
                .and_then(|c| c.hypothesis_then.as_ref())
                .map(ConfidenceView::from),
            next: b.next.declared.as_ref().map(|n| NextView {
                phase: n.phase,
                target: n.target.as_ref().map(rid),
                intent: n.intent.clone(),
            }),
            legal_next: b.next.legal.clone(),
            awaiting_authorisation: b.next.awaiting_authorisation.iter().map(rid).collect(),
        };
        out.push(Waypoint {
            seq,
            at: b.at,
            phase: b.what.phase,
            location,
            route,
            brief,
        });
    }
    out
}
