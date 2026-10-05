use crate::{Event, IncidentLog, LogViolation};
use navi_graph::GraphDocument;
use navi_ontology::*;
use std::collections::BTreeMap;

impl IncidentLog {
    /// Apply events (up to and including instant `upto`) to an empty state.
    /// Structural misuse of the log is an error here; semantic validity is
    /// judged by loading the result as a graph.
    pub fn fold(&self, upto: Option<Timestamp>) -> Result<GraphDocument, LogViolation> {
        let mut doc = GraphDocument {
            ontology_version: self.ontology_version.clone(),
            branch: self.branch.clone(),
            ..GraphDocument::default()
        };
        let mut obs: BTreeMap<ObservationId, Observation> = BTreeMap::new();
        let mut ents: BTreeMap<EntityId, Entity> = BTreeMap::new();
        let mut rels: BTreeMap<RelationshipId, Relationship> = BTreeMap::new();
        let mut sgs: BTreeMap<SafeguardId, Safeguard> = BTreeMap::new();
        let mut caps: BTreeMap<CapabilityId, Capability> = BTreeMap::new();
        let mut agents: BTreeMap<AgentId, Agent> = BTreeMap::new();
        let mut hyps: BTreeMap<HypothesisId, Hypothesis> = BTreeMap::new();
        let mut threats: BTreeMap<ThreatId, Threat> = BTreeMap::new();
        let mut acts: BTreeMap<ActionId, Action> = BTreeMap::new();

        for e in self
            .events
            .iter()
            .take_while(|e| upto.is_none_or(|t| e.at <= t))
        {
            let err = |m: String| LogViolation {
                seq: Some(e.seq),
                at: Some(e.at),
                message: m,
                graph: vec![],
            };
            match &e.event {
                Event::AuthorityPolicySet { policy } => doc.authority_policy = policy.clone(),
                Event::EpistemicPolicySet { policy } => doc.epistemic_policy = policy.clone(),
                Event::ObservationRecorded { observation } => {
                    if obs
                        .insert(observation.id.clone(), observation.clone())
                        .is_some()
                    {
                        return Err(err(format!(
                            "{} recorded twice: observations are immutable",
                            observation.id
                        )));
                    }
                }
                Event::EntityAsserted { entity } => {
                    ents.insert(entity.id.clone(), entity.clone());
                }
                Event::RelationshipAsserted { relationship } => {
                    rels.insert(relationship.id.clone(), relationship.clone());
                }
                Event::SafeguardAsserted { safeguard } => {
                    sgs.insert(safeguard.id.clone(), safeguard.clone());
                }
                Event::CapabilityGranted { capability } => {
                    caps.insert(capability.id.clone(), capability.clone());
                }
                Event::AgentRegistered { agent } => {
                    agents.insert(agent.id.clone(), agent.clone());
                }
                Event::ThreatAttributed { threat } => {
                    threats.insert(threat.id.clone(), threat.clone());
                }
                Event::HypothesisOpened { hypothesis } => {
                    if !hypothesis.transitions.is_empty() {
                        return Err(err(format!(
                            "{} opened with history; transitions are separate events",
                            hypothesis.id
                        )));
                    }
                    if hypothesis.opened_at != e.at {
                        return Err(err(format!(
                            "{} opened_at {} but logged at {}",
                            hypothesis.id, hypothesis.opened_at, e.at
                        )));
                    }
                    if hyps
                        .insert(hypothesis.id.clone(), hypothesis.clone())
                        .is_some()
                    {
                        return Err(err(format!("{} opened twice", hypothesis.id)));
                    }
                }
                Event::HypothesisTransitioned {
                    hypothesis,
                    transition,
                } => {
                    if transition.at != e.at {
                        return Err(err(format!(
                            "transition at {} logged at {}",
                            transition.at, e.at
                        )));
                    }
                    let h = hyps
                        .get_mut(hypothesis)
                        .ok_or_else(|| err(format!("{hypothesis} was never opened")))?;
                    h.transitions.push(transition.clone());
                }
                Event::ActionProposed { action } => {
                    if !action.history.is_empty() {
                        return Err(err(format!(
                            "{} proposed with history; transitions are separate events",
                            action.id
                        )));
                    }
                    if action.proposed_at != e.at {
                        return Err(err(format!(
                            "{} proposed_at {} but logged at {}",
                            action.id, action.proposed_at, e.at
                        )));
                    }
                    if acts.insert(action.id.clone(), action.clone()).is_some() {
                        return Err(err(format!("{} proposed twice", action.id)));
                    }
                }
                Event::ActionTransitioned { action, transition } => {
                    if transition.at() != e.at {
                        return Err(err(format!(
                            "transition at {} logged at {}",
                            transition.at(),
                            e.at
                        )));
                    }
                    let a = acts
                        .get_mut(action)
                        .ok_or_else(|| err(format!("{action} was never proposed")))?;
                    a.history.push(transition.clone());
                }
                Event::AgentEventEmitted { event } => {
                    if event.at != e.at {
                        return Err(err(format!(
                            "agent event at {} logged at {}",
                            event.at, e.at
                        )));
                    }
                    doc.agent_events.push(event.clone());
                }
            }
        }
        doc.observations = obs.into_values().collect();
        doc.entities = ents.into_values().collect();
        doc.relationships = rels.into_values().collect();
        doc.safeguards = sgs.into_values().collect();
        doc.capabilities = caps.into_values().collect();
        doc.agents = agents.into_values().collect();
        doc.hypotheses = hyps.into_values().collect();
        doc.threats = threats.into_values().collect();
        doc.actions = acts.into_values().collect();
        Ok(doc)
    }
}
