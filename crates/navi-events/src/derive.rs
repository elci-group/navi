//! Derive a log from a snapshot document (one that has no history).
//!
//! A snapshot only says what is true *now*. The conservative reading used
//! here:
//!
//! * Observations are facts with timestamps; they are never moved.
//! * Every other object enters the log at its own time, or later if
//!   something it cites did not exist yet — nothing appears before its
//!   evidence.
//! * An entity whose final form cites later evidence is *split*: at its own
//!   time it is asserted with only the evidence that existed then and trust
//!   `unknown` (the snapshot cannot say what its trust was before it was
//!   assessed, and inventing one would be fabrication); its final form is
//!   re-asserted once all its evidence exists.
//!
//! Every move and split is reported as a [`Retimed`], so the operator can
//! see where a snapshot could not be replayed faithfully and record a
//! native log instead.

use crate::{Event, IncidentLog, LogEntry, LOG_VERSION};
use navi_graph::SemanticGraph;
use navi_ontology::*;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Obs(ObservationId),
    Cap(CapabilityId),
    Agent(AgentId),
    /// The earliest version of an entity that its evidence allows.
    EntEarly(EntityId),
    Ent(EntityId),
    Rel(RelationshipId),
    Sg(SafeguardId),
    HypOpen(HypothesisId),
    HypTr(HypothesisId, usize),
    Threat(ThreatId),
    ActProp(ActionId),
    ActTr(ActionId, usize),
    AgEv(AgentId, u64),
}

impl Key {
    fn label(&self) -> String {
        match self {
            Key::Obs(i) => i.to_string(),
            Key::Cap(i) => i.to_string(),
            Key::Agent(i) => i.to_string(),
            Key::EntEarly(i) => format!("{i} (first assertion)"),
            Key::Ent(i) => i.to_string(),
            Key::Rel(i) => i.to_string(),
            Key::Sg(i) => i.to_string(),
            Key::HypOpen(i) => format!("{i} (opened)"),
            Key::HypTr(i, n) => format!("{i} transition {}", n + 1),
            Key::Threat(i) => i.to_string(),
            Key::ActProp(i) => format!("{i} (proposed)"),
            Key::ActTr(i, n) => format!("{i} transition {}", n + 1),
            Key::AgEv(a, s) => format!("{a}#{s}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Retimed {
    pub object: String,
    pub own_time: Timestamp,
    pub logged_at: Timestamp,
    pub note: String,
}

fn source_keys(s: &SourceRef, out: &mut Vec<Key>) {
    match s {
        SourceRef::Observation(i) => out.push(Key::Obs(i.clone())),
        SourceRef::Hypothesis(i) => out.push(Key::HypOpen(i.clone())),
        SourceRef::Safeguard(i) => out.push(Key::Sg(i.clone())),
        SourceRef::Action(i) => out.push(Key::ActProp(i.clone())),
        SourceRef::Derived { inputs, .. } => inputs.iter().for_each(|x| source_keys(x, out)),
    }
}

fn prov_keys(p: &Provenance) -> Vec<Key> {
    let mut out = vec![];
    p.sources().iter().for_each(|s| source_keys(s, &mut out));
    out
}

pub fn derive(g: &SemanticGraph) -> (IncidentLog, Vec<Retimed>) {
    // (own time, references, event)
    let mut items: BTreeMap<Key, (Option<Timestamp>, Vec<Key>, Event)> = BTreeMap::new();
    for o in g.observations.values() {
        // Facts are never moved; a missing subject is left for validation
        // to report rather than hidden by shifting the observation.
        items.insert(
            Key::Obs(o.id.clone()),
            (
                Some(o.observed_at),
                vec![],
                Event::ObservationRecorded {
                    observation: o.clone(),
                },
            ),
        );
    }
    for e in g.entities.values() {
        items.insert(
            Key::Ent(e.id.clone()),
            (
                Some(e.observed_at),
                prov_keys(&e.provenance),
                Event::EntityAsserted { entity: e.clone() },
            ),
        );
    }
    for r in g.relationships.values() {
        let mut refs = prov_keys(&r.provenance);
        refs.extend([Key::EntEarly(r.from.clone()), Key::EntEarly(r.to.clone())]);
        items.insert(
            Key::Rel(r.id.clone()),
            (
                None,
                refs,
                Event::RelationshipAsserted {
                    relationship: r.clone(),
                },
            ),
        );
    }
    for s in g.safeguards.values() {
        let mut refs = prov_keys(&s.provenance);
        refs.extend(
            s.protects
                .iter()
                .chain(&s.enforced_by)
                .map(|e| Key::EntEarly(e.clone())),
        );
        items.insert(
            Key::Sg(s.id.clone()),
            (
                None,
                refs,
                Event::SafeguardAsserted {
                    safeguard: s.clone(),
                },
            ),
        );
    }
    for c in g.capabilities.values() {
        let refs = c.scope.iter().map(|e| Key::EntEarly(e.clone())).collect();
        items.insert(
            Key::Cap(c.id.clone()),
            (
                None,
                refs,
                Event::CapabilityGranted {
                    capability: c.clone(),
                },
            ),
        );
    }
    for a in g.agents.values() {
        let refs = a.loadout.iter().map(|c| Key::Cap(c.clone())).collect();
        items.insert(
            Key::Agent(a.id.clone()),
            (None, refs, Event::AgentRegistered { agent: a.clone() }),
        );
    }
    for h in g.hypotheses.values() {
        let mut refs = prov_keys(&h.initial_evidence);
        refs.extend(h.subjects.iter().map(|e| Key::EntEarly(e.clone())));
        let opened = Hypothesis {
            transitions: vec![],
            ..h.clone()
        };
        items.insert(
            Key::HypOpen(h.id.clone()),
            (
                Some(h.opened_at),
                refs,
                Event::HypothesisOpened { hypothesis: opened },
            ),
        );
        for (i, t) in h.transitions.iter().enumerate() {
            let mut refs = prov_keys(&t.evidence);
            refs.push(if i == 0 {
                Key::HypOpen(h.id.clone())
            } else {
                Key::HypTr(h.id.clone(), i - 1)
            });
            items.insert(
                Key::HypTr(h.id.clone(), i),
                (
                    Some(t.at),
                    refs,
                    Event::HypothesisTransitioned {
                        hypothesis: h.id.clone(),
                        transition: t.clone(),
                    },
                ),
            );
        }
    }
    for t in g.threats.values() {
        let mut refs = vec![Key::HypOpen(t.hypothesis.clone())];
        refs.extend(
            t.actor
                .iter()
                .chain(&t.targets)
                .map(|e| Key::EntEarly(e.clone())),
        );
        items.insert(
            Key::Threat(t.id.clone()),
            (None, refs, Event::ThreatAttributed { threat: t.clone() }),
        );
    }
    for a in g.actions.values() {
        let refs = vec![
            Key::Agent(a.agent.clone()),
            Key::Cap(a.capability.clone()),
            Key::EntEarly(a.target.clone()),
            Key::HypOpen(a.hypothesis.clone()),
        ];
        let proposed = Action {
            history: vec![],
            ..a.clone()
        };
        items.insert(
            Key::ActProp(a.id.clone()),
            (
                Some(a.proposed_at),
                refs,
                Event::ActionProposed { action: proposed },
            ),
        );
        for (i, t) in a.history.iter().enumerate() {
            let mut refs = match t {
                ActionTransition::ObserveEffect { effect: p, .. }
                | ActionTransition::Verify { evidence: p, .. }
                | ActionTransition::RollBack { evidence: p, .. } => prov_keys(p),
                _ => vec![],
            };
            refs.push(if i == 0 {
                Key::ActProp(a.id.clone())
            } else {
                Key::ActTr(a.id.clone(), i - 1)
            });
            items.insert(
                Key::ActTr(a.id.clone(), i),
                (
                    Some(t.at()),
                    refs,
                    Event::ActionTransitioned {
                        action: a.id.clone(),
                        transition: t.clone(),
                    },
                ),
            );
        }
    }
    let mut prev_event: BTreeMap<&AgentId, u64> = BTreeMap::new();
    for ((agent, seq), e) in &g.agent_events {
        let mut refs = vec![Key::Agent(agent.clone())];
        refs.extend(
            e.target
                .iter()
                .chain(e.next.as_ref().and_then(|n| n.target.as_ref()))
                .map(|x| Key::EntEarly(x.clone())),
        );
        refs.extend(e.hypothesis.iter().map(|h| Key::HypOpen(h.clone())));
        refs.extend(e.action.iter().map(|a| Key::ActProp(a.clone())));
        if let Some(p) = prev_event.insert(agent, *seq) {
            refs.push(Key::AgEv(agent.clone(), p));
        }
        items.insert(
            Key::AgEv(agent.clone(), *seq),
            (
                Some(e.at),
                refs,
                Event::AgentEventEmitted { event: e.clone() },
            ),
        );
    }

    let t0 = items
        .values()
        .filter_map(|i| i.0)
        .min()
        .unwrap_or(Timestamp(0));
    // Fixed point: an item's time is the latest of its own time and the
    // times of everything it references; an entity's first assertion needs
    // only *one* of its sources to exist. Monotone and bounded, so it ends.
    let mut time: BTreeMap<Key, Timestamp> = items
        .iter()
        .map(|(k, v)| (k.clone(), v.0.unwrap_or(t0)))
        .collect();
    let early_ids: Vec<EntityId> = g.entities.keys().cloned().collect();
    for id in &early_ids {
        time.insert(Key::EntEarly(id.clone()), g.entities[id].observed_at);
    }
    loop {
        let mut changed = false;
        for (k, (_, refs, _)) in &items {
            let need = refs
                .iter()
                .filter_map(|r| time.get(r))
                .max()
                .copied()
                .unwrap_or(t0);
            if need > time[k] {
                time.insert(k.clone(), need);
                changed = true;
            }
        }
        for id in &early_ids {
            let e = &g.entities[id];
            let first_source = prov_keys(&e.provenance)
                .iter()
                .filter_map(|r| time.get(r))
                .min()
                .copied()
                .unwrap_or(t0);
            let need = e.observed_at.max(first_source);
            let k = Key::EntEarly(id.clone());
            if need > time[&k] {
                time.insert(k, need);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // Split entities whose final form needs later evidence.
    let mut retimed = vec![];
    for id in &early_ids {
        let e = &g.entities[id];
        let (early, fin) = (
            time[&Key::EntEarly(id.clone())],
            time[&Key::Ent(id.clone())],
        );
        if early < fin {
            let available: Vec<SourceRef> = e
                .provenance
                .sources()
                .iter()
                .filter(|s| {
                    let mut ks = vec![];
                    source_keys(s, &mut ks);
                    ks.iter().all(|k| time.get(k).is_some_and(|t| *t <= early))
                })
                .cloned()
                .collect();
            let first = Entity {
                trust: TrustState::Unknown,
                provenance: Provenance::new(available)
                    .expect("at least one source available by construction"),
                ..e.clone()
            };
            items.insert(
                Key::EntEarly(id.clone()),
                (Some(early), vec![], Event::EntityAsserted { entity: first }),
            );
            retimed.push(Retimed {
                object: id.to_string(),
                own_time: e.observed_at,
                logged_at: fin,
                note: format!("split: first asserted at {early} with trust unknown and the evidence available then; final form (trust {}) from {fin}", trust_name(e.trust)),
            });
        } else {
            // No split: the single assertion is the early one.
            time.insert(Key::Ent(id.clone()), early.max(fin));
            let (_, refs, ev) = items.remove(&Key::Ent(id.clone())).expect("inserted above");
            items.insert(Key::EntEarly(id.clone()), (Some(e.observed_at), refs, ev));
            time.insert(Key::EntEarly(id.clone()), early.max(fin));
        }
    }

    // Objects whose own timestamp must equal their log time are re-stamped
    // when they move (an action proposed "at" 4800 that could not exist
    // before 5000 is proposed at 5000).
    let mut ordered: Vec<(Timestamp, Key, Event)> = items
        .into_iter()
        .map(|(k, (own, _, mut ev))| {
            let at = time[&k];
            let is_entity = matches!(k, Key::Ent(_) | Key::EntEarly(_));
            if let Some(o) = own.filter(|o| *o != at && !is_entity) {
                retimed.push(Retimed {
                    object: k.label(),
                    own_time: o,
                    logged_at: at,
                    note: format!("moved from {o} to {at}: something it cites did not exist yet"),
                });
                match &mut ev {
                    Event::HypothesisOpened { hypothesis } => hypothesis.opened_at = at,
                    Event::HypothesisTransitioned { transition, .. } => transition.at = at,
                    Event::ActionProposed { action } => action.proposed_at = at,
                    Event::AgentEventEmitted { event } => event.at = at,
                    Event::ActionTransitioned { transition, .. } => restamp(transition, at),
                    _ => {}
                }
            }
            (at, k, ev)
        })
        .collect();
    ordered.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));

    let mut events = vec![
        LogEntry {
            seq: 1,
            at: t0,
            event: Event::AuthorityPolicySet {
                policy: g.authority_policy.clone(),
            },
        },
        LogEntry {
            seq: 2,
            at: t0,
            event: Event::EpistemicPolicySet {
                policy: g.epistemic_policy.clone(),
            },
        },
    ];
    for (at, _, event) in ordered {
        events.push(LogEntry {
            seq: events.len() as u64 + 1,
            at,
            event,
        });
    }
    let log = IncidentLog {
        log_version: LOG_VERSION.into(),
        ontology_version: ONTOLOGY_VERSION.into(),
        branch: g.branch.clone(),
        events,
    };
    (log, retimed)
}

fn restamp(t: &mut ActionTransition, at: Timestamp) {
    match t {
        ActionTransition::Authorise { at: a, .. }
        | ActionTransition::Reject { at: a, .. }
        | ActionTransition::Cancel { at: a, .. }
        | ActionTransition::BeginExecution { at: a }
        | ActionTransition::ExecutionReturned { at: a, .. }
        | ActionTransition::ObserveEffect { at: a, .. }
        | ActionTransition::Verify { at: a, .. }
        | ActionTransition::RollBack { at: a, .. } => *a = at,
    }
}

fn trust_name(t: TrustState) -> String {
    match serde_json::to_value(t) {
        Ok(serde_json::Value::String(s)) => s,
        _ => "?".into(),
    }
}
