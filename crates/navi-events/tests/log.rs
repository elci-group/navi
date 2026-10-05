//! Phase 3, headless half: the incident log.

use navi_events::{derive, fork, Event, ForkSpec, IncidentLog};
use navi_graph::SemanticGraph;
use navi_ontology::{Timestamp, TrustState};
use serde_json::{json, Value};

const STUFFING: &str = include_str!("../../../tests/fixtures/scenarios/credential-stuffing.json");
const REPO_RUNTIME: &str = include_str!("../../../tests/fixtures/scenarios/repo-runtime.json");
const STUFFING_LOG: &str =
    include_str!("../../../tests/fixtures/logs/credential-stuffing.log.json");
const REPO_LOG: &str = include_str!("../../../tests/fixtures/logs/repo-runtime.log.json");
const FORK: &str =
    include_str!("../../../tests/fixtures/forks/repo-runtime-approve-isolation.json");
const BRANCH: &str =
    include_str!("../../../tests/fixtures/forks/repo-runtime-approve-isolation.branch.json");

fn log(text: &str) -> IncidentLog {
    IncidentLog::from_json(text).unwrap()
}

fn mutated(text: &str, f: impl FnOnce(&mut Value)) -> IncidentLog {
    let mut v: Value = serde_json::from_str(text).unwrap();
    f(&mut v);
    serde_json::from_value(v).unwrap()
}

#[test]
fn committed_logs_are_what_derivation_produces() {
    for (snap, committed) in [(STUFFING, STUFFING_LOG), (REPO_RUNTIME, REPO_LOG)] {
        let (derived, _) = derive(&SemanticGraph::from_json(snap).unwrap());
        assert_eq!(derived, log(committed), "regenerate with `navi log derive`");
    }
}

#[test]
fn every_prefix_is_a_valid_graph() {
    for text in [STUFFING_LOG, REPO_LOG, BRANCH] {
        assert!(log(text).validate().is_empty());
    }
}

#[test]
fn final_state_is_the_snapshot() {
    for (snap, text) in [(STUFFING, STUFFING_LOG), (REPO_RUNTIME, REPO_LOG)] {
        let original = SemanticGraph::from_json(snap).unwrap();
        assert_eq!(log(text).graph().unwrap().digest(), original.digest());
    }
}

#[test]
fn observations_are_never_retimed() {
    for text in [STUFFING_LOG, REPO_LOG] {
        for e in log(text).events {
            if let Event::ObservationRecorded { observation } = e.event {
                assert_eq!(e.at, observation.observed_at, "{}", observation.id);
            }
        }
    }
}

#[test]
fn snapshot_entities_are_split_not_backdated() {
    let (l, notes) = derive(&SemanticGraph::from_json(STUFFING).unwrap());
    let asserts: Vec<(Timestamp, TrustState)> = l
        .events
        .iter()
        .filter_map(|e| match &e.event {
            Event::EntityAsserted { entity } if entity.id.as_str() == "ent:public-auth" => {
                Some((e.at, entity.trust))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        asserts,
        [
            (Timestamp(0), TrustState::Unknown),
            (Timestamp(1500), TrustState::Degraded)
        ]
    );
    assert!(notes
        .iter()
        .any(|n| n.object == "ent:public-auth" && n.note.starts_with("split")));
    // Navi's first look stays at the time it happened.
    let g = l.graph_at(Timestamp(1000)).unwrap();
    assert_eq!(g.agent_events.len(), 1);
}

#[test]
fn anachronistic_intent_is_detected() {
    // Declaring a next target before that entity was ever observed.
    let mut v: Value = serde_json::from_str(STUFFING).unwrap();
    for e in v["agent_events"].as_array_mut().unwrap() {
        if e["seq"] == 3 {
            e["next"]["target"] = json!("ent:src-cluster");
        }
    }
    let (_, notes) = derive(&SemanticGraph::from_json(&v.to_string()).unwrap());
    assert!(
        notes
            .iter()
            .any(|n| n.object == "agent:navi-01#3" && n.note.starts_with("moved")),
        "{notes:?}"
    );
}

#[test]
fn state_at_an_instant_reflects_only_the_past() {
    let l = log(REPO_LOG);
    let early = l.graph_at(Timestamp(3200)).unwrap();
    let h = early
        .hypotheses
        .values()
        .find(|h| h.id.as_str() == "hyp:c2")
        .unwrap();
    assert_eq!(h.state(), navi_ontology::EpistemicState::Anomalous);
    assert!(early.actions.is_empty());
    let before = l.graph_at(Timestamp(-1)).unwrap();
    assert!(before.entities.is_empty());
}

#[test]
fn structural_misuse_is_rejected() {
    let gap = mutated(REPO_LOG, |v| v["events"][5]["seq"] = json!(99));
    assert!(!gap.validate().is_empty());
    let backwards = mutated(REPO_LOG, |v| {
        let n = v["events"].as_array().unwrap().len();
        v["events"][n - 1]["at"] = json!(0);
    });
    assert!(backwards
        .validate()
        .iter()
        .any(|x| x.message.contains("append-only")));
    let dup = mutated(REPO_LOG, |v| {
        let first = v["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["event"]["type"] == "observation_recorded")
            .unwrap()
            .clone();
        let arr = v["events"].as_array_mut().unwrap();
        let n = arr.len() as u64;
        let mut copy = first;
        copy["seq"] = json!(n + 1);
        copy["at"] = arr.last().unwrap()["at"].clone();
        copy["event"]["observation"]["observed_at"] = copy["at"].clone();
        arr.push(copy);
    });
    assert!(dup
        .validate()
        .iter()
        .any(|x| x.message.contains("immutable")));
}

#[test]
fn an_invalid_moment_is_found_even_if_the_end_is_valid() {
    // Move Navi's PLAN event (which names act:isolate) before the action exists.
    let l = mutated(REPO_LOG, |v| {
        let arr = v["events"].as_array_mut().unwrap();
        for e in arr.iter_mut() {
            if e["event"]["type"] == "action_proposed" {
                e["at"] = json!(4900);
                e["event"]["action"]["proposed_at"] = json!(4900);
            }
        }
        arr.sort_by_key(|e| e["at"].as_i64());
        for (i, e) in arr.iter_mut().enumerate() {
            e["seq"] = json!(i + 1);
        }
    });
    assert!(l.graph().is_ok(), "the final state alone looks fine");
    let v = l.validate();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].at, Some(Timestamp(4800)));
    assert!(!v[0].graph.is_empty());
}

// ── FORK ───────────────────────────────────────────────────────────────────

fn spec() -> ForkSpec {
    serde_json::from_str(FORK).unwrap()
}

#[test]
fn fork_is_a_marked_branch_and_reality_is_untouched() {
    let base = log(REPO_LOG);
    let before = base.digest();
    let branch = fork(&base, &spec()).unwrap();
    assert_eq!(base.digest(), before);
    let b = branch.branch.as_ref().unwrap();
    assert_eq!(b.fork_of, before);
    assert_eq!(b.at, Timestamp(4900));
    assert_ne!(
        branch.graph().unwrap().digest(),
        base.graph().unwrap().digest()
    );
    assert!(branch.graph().unwrap().branch.is_some());
    assert_eq!(branch, log(BRANCH), "regenerate with `navi log fork`");
    // History before the fork point is identical.
    let up_to = |l: &IncidentLog| l.graph_at(Timestamp(4900)).unwrap().to_document();
    let (mut a, b2) = (up_to(&base), up_to(&branch));
    a.branch = b2.branch.clone();
    assert_eq!(
        serde_json::to_value(a).unwrap(),
        serde_json::to_value(b2).unwrap()
    );
}

#[test]
fn counterfactuals_obey_the_same_rules() {
    // Skip the human approval: execution without authorisation is refused.
    let mut s = spec();
    s.events.retain(|e| {
        !matches!(
            &e.event,
            Event::ActionTransitioned {
                transition: navi_ontology::ActionTransition::Authorise { .. },
                ..
            }
        )
    });
    assert!(fork(&log(REPO_LOG), &s).is_err());
    // Claim success from the command's own report.
    let mut s = spec();
    s.events
        .retain(|e| !matches!(&e.event, Event::ObservationRecorded { .. }));
    assert!(fork(&log(REPO_LOG), &s).is_err());
}

#[test]
fn history_before_a_fork_is_fixed() {
    let mut s = spec();
    s.events[0].at = Timestamp(4000);
    assert!(fork(&log(REPO_LOG), &s).is_err());
    let mut s = spec();
    s.label = " ".into();
    assert!(fork(&log(REPO_LOG), &s).is_err());
    let mut s = spec();
    s.at = Timestamp(-5);
    assert!(fork(&log(REPO_LOG), &s).is_err());
}

#[test]
fn dvr_lines_read_like_an_incident() {
    let l = log(STUFFING_LOG);
    let lines: Vec<String> = l.events.iter().map(|e| e.summary()).collect();
    assert!(lines
        .iter()
        .any(|x| x.contains("hyp:cred-stuffing SUSPICIOUS → PROBABLE 83%")));
    assert!(lines.iter().any(
        |x| x.contains("act:shield command returned") && x.contains("effect not yet observed")
    ));
    assert!(lines.iter().any(|x| x.contains("act:shield verified")));
}
