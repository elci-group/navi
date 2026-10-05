//! Phase 2, headless half: the agent brief (where / why / what /
//! confidence / next) straight from the semantic graph, no realm involved.

use navi_graph::{Code, LoadError, SemanticGraph};
use navi_ontology::{ActionState, AgentId, AgentPhase, EpistemicState};
use serde_json::{json, Value};

const REPO_RUNTIME: &str = include_str!("../../../tests/fixtures/scenarios/repo-runtime.json");
const STUFFING: &str = include_str!("../../../tests/fixtures/scenarios/credential-stuffing.json");

fn g(text: &str) -> SemanticGraph {
    SemanticGraph::from_json(text).unwrap()
}

fn navi() -> AgentId {
    AgentId::new("agent:navi-01").unwrap()
}

fn codes(v: &Value) -> Vec<Code> {
    match SemanticGraph::from_json(&v.to_string()) {
        Ok(_) => vec![],
        Err(LoadError::Invalid(vs)) => vs.into_iter().map(|v| v.code).collect(),
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn belief_is_reported_as_of_the_event() {
    let b = g(REPO_RUNTIME).brief(&navi(), Some(3)).unwrap();
    assert_eq!(b.why.state_then, Some(EpistemicState::Anomalous)); // promoted later, at t=4000
    assert_eq!(
        b.why
            .evidence_then
            .iter()
            .map(|o| o.as_str())
            .collect::<Vec<_>>(),
        ["obs:egress-1"]
    );
    let latest = g(REPO_RUNTIME).brief(&navi(), None).unwrap();
    assert_eq!(latest.seq, 7);
    assert_eq!(latest.why.state_then, Some(EpistemicState::Suspicious));
    assert_eq!(latest.why.evidence_then.len(), 2);
}

#[test]
fn carried_values_cite_their_event() {
    let b = g(REPO_RUNTIME).brief(&navi(), Some(7)).unwrap();
    // Event 7 states no hypothesis or confidence of its own.
    assert_eq!(b.why.hypothesis.as_ref().unwrap().from_seq, 6);
    assert_eq!(b.confidence.as_ref().unwrap().navi.from_seq, 5);
    assert_eq!(b.where_.target.as_ref().unwrap().from_seq, 7);
    assert_eq!(b.where_.path, ["elci", "prod", "shop", "api", "api-5d2b-2"]);
}

#[test]
fn stale_agent_estimates_are_visible() {
    // At #4 Navi already estimates 55% while the hypothesis still holds 35%.
    let b = g(REPO_RUNTIME).brief(&navi(), Some(4)).unwrap();
    let c = b.confidence.clone().unwrap();
    assert_eq!(c.navi.value.basis_points(), 5500);
    assert_eq!(c.hypothesis_then.unwrap().basis_points(), 3500);
    assert!(b.render(&g(REPO_RUNTIME)).contains("≠ Navi's estimate"));
}

#[test]
fn next_is_declared_never_inferred() {
    let graph = g(REPO_RUNTIME);
    let b = graph.brief(&navi(), Some(7)).unwrap();
    assert_eq!(b.next.declared.as_ref().unwrap().phase, AgentPhase::Act);
    assert_eq!(b.next.legal, AgentPhase::Authorise.successors());
    assert_eq!(b.next.awaiting_authorisation.len(), 1);
    // Strip the declaration: the brief says "undeclared", it does not guess.
    let mut v: Value = serde_json::from_str(REPO_RUNTIME).unwrap();
    for e in v["agent_events"].as_array_mut().unwrap() {
        e.as_object_mut().unwrap().remove("next");
    }
    let bare = SemanticGraph::from_json(&v.to_string()).unwrap();
    let b = bare.brief(&navi(), Some(7)).unwrap();
    assert!(b.next.declared.is_none());
    assert!(b.render(&bare).contains("NEXT        undeclared"));
}

#[test]
fn execute_success_verified_stay_distinct_over_time() {
    let graph = g(STUFFING);
    let at = |seq| {
        graph
            .brief(&navi(), Some(seq))
            .unwrap()
            .what
            .action_state_then
    };
    assert_eq!(at(9), Some(ActionState::Authorised));
    assert_eq!(at(10), Some(ActionState::Executing));
    // At #11 (t=9000) the effect is observed but verification (t=9100) has not happened.
    assert_eq!(at(11), Some(ActionState::Succeeded));
    assert_eq!(
        graph
            .actions
            .values()
            .find(|a| a.id.as_str() == "act:shield")
            .unwrap()
            .state(),
        ActionState::Verified
    );
}

#[test]
fn unknown_agent_or_event_has_no_brief() {
    let graph = g(REPO_RUNTIME);
    assert!(graph
        .brief(&AgentId::new("agent:nobody").unwrap(), None)
        .is_none());
    assert!(graph.brief(&navi(), Some(99)).is_none());
}

#[test]
fn illegal_declared_next_is_rejected() {
    let mut v: Value = serde_json::from_str(REPO_RUNTIME).unwrap();
    v["agent_events"][0]["next"]["phase"] = json!("ACT");
    assert!(codes(&v).contains(&Code::AgentEventViolation));
    let mut v: Value = serde_json::from_str(REPO_RUNTIME).unwrap();
    v["agent_events"][0]["next"]["target"] = json!("ent:nowhere");
    assert!(codes(&v).contains(&Code::AgentEventViolation));
    let mut v: Value = serde_json::from_str(REPO_RUNTIME).unwrap();
    v["agent_events"][0]["objective"] = json!("  ");
    assert!(codes(&v).contains(&Code::AgentEventViolation));
}
