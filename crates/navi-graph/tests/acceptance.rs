//! Directive §19 and §26 acceptance tests, as far as they apply to Phase 0.
//! Each test starts from a valid scenario and introduces exactly one fault.

use navi_graph::{Code, LoadError, SemanticGraph};
use navi_ontology::{ActionId, ActionState, EpistemicState, HypothesisId};
use serde_json::{json, Value};

const FIXTURE: &str = include_str!("../../../tests/fixtures/scenarios/credential-stuffing.json");

fn base() -> Value {
    serde_json::from_str(FIXTURE).unwrap()
}

fn load(v: &Value) -> Result<SemanticGraph, LoadError> {
    SemanticGraph::from_json(&v.to_string())
}

fn codes(v: &Value) -> Vec<Code> {
    match load(v) {
        Ok(_) => vec![],
        Err(LoadError::Invalid(vs)) => vs.into_iter().map(|v| v.code).collect(),
        Err(LoadError::Parse(e)) => panic!("expected validation failure, got parse error: {e}"),
    }
}

fn parse_fails(v: &Value) -> bool {
    matches!(load(v), Err(LoadError::Parse(_)))
}

fn find<'a>(v: &'a mut Value, coll: &str, id: &str) -> &'a mut Value {
    v[coll]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|x| x["id"] == id)
        .unwrap_or_else(|| panic!("{coll}/{id}"))
}

fn event(v: &mut Value, seq: u64) -> &mut Value {
    v["agent_events"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e["seq"] == seq)
        .unwrap()
}

#[test]
fn baseline_is_valid() {
    let g = load(&base()).unwrap_or_else(|e| match e {
        LoadError::Invalid(v) => panic!("{v:#?}"),
        e => panic!("{e}"),
    });
    let h = &g.hypotheses[&HypothesisId::new("hyp:cred-stuffing").unwrap()];
    assert_eq!(h.state(), EpistemicState::Probable);
    assert_eq!(
        g.actions[&ActionId::new("act:shield").unwrap()].state(),
        ActionState::Verified
    );
    assert_eq!(
        g.actions[&ActionId::new("act:barrier").unwrap()].state(),
        ActionState::Proposed
    );
}

// ── Determinism ────────────────────────────────────────────────────────────

#[test]
fn determinism_is_order_independent() {
    let a = load(&base()).unwrap();
    let mut shuffled = base();
    for (_, coll) in shuffled.as_object_mut().unwrap() {
        if let Some(arr) = coll.as_array_mut() {
            arr.reverse();
        }
    }
    let b = load(&shuffled).unwrap();
    assert_eq!(a.digest(), b.digest());
    assert_eq!(a.canonical_json(), b.canonical_json());
}

#[test]
fn canonical_form_is_a_fixed_point() {
    let a = load(&base()).unwrap();
    let b = SemanticGraph::from_json(&a.canonical_json()).unwrap();
    assert_eq!(a.canonical_json(), b.canonical_json());
    assert_eq!(a.digest(), b.digest());
}

#[test]
fn digest_changes_with_semantics() {
    let a = load(&base()).unwrap();
    let mut v = base();
    find(&mut v, "observations", "obs:req-rate")["attributes"]["rpm"] = json!(4272);
    assert_ne!(a.digest(), load(&v).unwrap().digest());
}

// ── Provenance completeness & reverse resolution ───────────────────────────

#[test]
fn every_security_significant_object_resolves_to_observations() {
    let g = load(&base()).unwrap();
    let ids = g
        .entities
        .keys()
        .map(|k| k.to_string())
        .chain(g.relationships.keys().map(|k| k.to_string()))
        .chain(g.threats.keys().map(|k| k.to_string()))
        .chain(g.safeguards.keys().map(|k| k.to_string()))
        .chain(g.actions.keys().map(|k| k.to_string()));
    for id in ids {
        let tree = g.explain(&id).unwrap();
        assert!(
            !tree.observations().is_empty(),
            "{id} has no observation leaves"
        );
    }
}

#[test]
fn reverse_resolution_enemy_to_raw_observation() {
    let g = load(&base()).unwrap();
    let tree = g.explain("thr:stuffing").unwrap();
    assert_eq!(tree.children[0].kind, "hypothesis");
    let leaves = tree.observations();
    for o in [
        "obs:req-rate",
        "obs:auth-fail",
        "obs:novel-ids",
        "obs:reputation",
    ] {
        assert!(leaves.contains(o), "missing {o}");
    }
    let text = tree.render();
    assert!(text.contains("PROBABLE"), "{text}");
    assert!(text.contains("T1110.004"), "{text}");
    assert!(text.contains("raw=loki://"), "{text}");
}

#[test]
fn unknown_ids_explain_to_nothing() {
    let g = load(&base()).unwrap();
    assert!(g.explain("thr:nope").is_none());
    assert!(g.explain("garbage").is_none());
}

// ── §19 anti-hallucination rejections ──────────────────────────────────────

#[test]
fn entity_without_source_is_rejected() {
    let mut v = base();
    find(&mut v, "entities", "ent:auth-api")["provenance"] = json!([]);
    assert!(parse_fails(&v));
    let mut v = base();
    find(&mut v, "entities", "ent:auth-api")
        .as_object_mut()
        .unwrap()
        .remove("provenance");
    assert!(parse_fails(&v));
}

#[test]
fn entity_citing_nonexistent_source_is_rejected() {
    let mut v = base();
    find(&mut v, "entities", "ent:auth-api")["provenance"] =
        json!([{ "observation": "obs:invented" }]);
    let c = codes(&v);
    assert!(c.contains(&Code::DanglingReference));
    assert!(c.contains(&Code::UngroundedProvenance));
}

#[test]
fn relationship_without_evidence_is_rejected() {
    let mut v = base();
    find(&mut v, "relationships", "rel:src-edge")["provenance"] = json!([]);
    assert!(parse_fails(&v));
}

#[test]
fn threat_without_classification_is_rejected() {
    let mut v = base();
    find(&mut v, "threats", "thr:stuffing")["hypothesis"] = json!("hyp:missing");
    assert!(codes(&v).contains(&Code::DanglingReference));
    let mut v = base();
    find(&mut v, "threats", "thr:stuffing")
        .as_object_mut()
        .unwrap()
        .remove("hypothesis");
    assert!(parse_fails(&v));
}

#[test]
fn action_without_agent_event_is_rejected() {
    let mut v = base();
    event(&mut v, 8)["action"] = json!("act:barrier"); // act:shield loses its PLAN event
    assert!(codes(&v).contains(&Code::AgentEventViolation));
    let mut v = base();
    event(&mut v, 10).as_object_mut().unwrap().remove("action");
    assert!(codes(&v).contains(&Code::AgentEventViolation));
}

#[test]
fn success_without_state_delta_is_rejected() {
    // Effect evidence predates execution: it cannot be the effect.
    let mut v = base();
    find(&mut v, "actions", "act:shield")["history"][3]["effect"] =
        json!([{ "observation": "obs:waf-cfg" }]);
    assert!(codes(&v).contains(&Code::VerificationViolation));
    // Effect is only the action's own report.
    let mut v = base();
    find(&mut v, "actions", "act:shield")["history"][3]["effect"] =
        json!([{ "action": "act:shield" }]);
    assert!(codes(&v).contains(&Code::InvalidObject));
}

#[test]
fn remediation_without_verification_step_is_rejected() {
    let mut v = base();
    find(&mut v, "actions", "act:shield")["history"]
        .as_array_mut()
        .unwrap()
        .remove(3); // drop observe_effect
    assert!(codes(&v).contains(&Code::InvalidObject));
}

#[test]
fn confidence_without_estimator_is_rejected() {
    let mut v = base();
    find(&mut v, "hypotheses", "hyp:cred-stuffing")["initial_confidence"] = json!({ "value": 0.4 });
    assert!(parse_fails(&v));
}

#[test]
fn circular_reasoning_is_ungrounded() {
    let mut v = base();
    let est = json!({ "name": "e", "version": "1" });
    let hyps = v["hypotheses"].as_array_mut().unwrap();
    for (me, other) in [("hyp:a", "hyp:b"), ("hyp:b", "hyp:a")] {
        hyps.push(json!({
            "id": me, "subjects": ["ent:auth-api"], "claim": "c", "opened_at": 0, "opened_as": "ANOMALOUS",
            "initial_confidence": { "value": 0.3, "estimator": est },
            "initial_evidence": [{ "hypothesis": other }]
        }));
    }
    assert!(codes(&v).contains(&Code::UngroundedProvenance));
}

// ── Epistemic fidelity ─────────────────────────────────────────────────────

#[test]
fn compromise_requires_probable_hypothesis() {
    let mut v = base();
    find(&mut v, "entities", "ent:src-cluster")["trust"] = json!("compromised");
    assert!(codes(&v).contains(&Code::EpistemicOverclaim));
    // public-auth cites a PROBABLE hypothesis about itself: allowed.
    let mut v = base();
    find(&mut v, "entities", "ent:public-auth")["trust"] = json!("compromised");
    assert!(codes(&v).is_empty());
}

#[test]
fn compromise_backed_by_a_weak_hypothesis_is_rejected() {
    let mut v = base();
    find(&mut v, "entities", "ent:public-auth")["trust"] = json!("compromised");
    find(&mut v, "hypotheses", "hyp:cred-stuffing")["transitions"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(codes(&v).contains(&Code::EpistemicOverclaim));
}

#[test]
fn epistemic_ladder_cannot_be_skipped() {
    let mut v = base();
    find(&mut v, "hypotheses", "hyp:cred-stuffing")["transitions"][1]["from"] = json!("ANOMALOUS");
    assert!(codes(&v).contains(&Code::InvalidObject));
}

#[test]
fn coin_flip_cannot_be_probable() {
    let mut v = base();
    find(&mut v, "hypotheses", "hyp:cred-stuffing")["transitions"][1]["confidence"]["value"] =
        json!(0.51);
    assert!(codes(&v).contains(&Code::InvalidObject));
}

#[test]
fn threat_cannot_target_beyond_its_hypothesis() {
    let mut v = base();
    find(&mut v, "threats", "thr:stuffing")["targets"] = json!(["ent:identity-db"]);
    assert!(codes(&v).contains(&Code::EpistemicOverclaim));
}

// ── Authority fidelity ─────────────────────────────────────────────────────

#[test]
fn capability_not_in_loadout() {
    let mut v = base();
    find(&mut v, "agents", "agent:navi-01")["loadout"] = json!(["cap:scan", "cap:barrier"]);
    assert!(codes(&v).contains(&Code::AuthorityViolation));
}

#[test]
fn approval_weaker_than_gate() {
    let mut v = base();
    find(&mut v, "actions", "act:shield")["history"][0]["approval"]["kind"] =
        json!({ "autonomous": { "policy_version": "production-default/1" } });
    assert!(codes(&v).contains(&Code::AuthorityViolation));
}

#[test]
fn human_gate_needs_a_human() {
    let mut v = base();
    find(&mut v, "actions", "act:barrier")["history"] = json!([
        { "type": "authorise", "at": 4300, "approval": { "id": "appr:b", "kind": { "policy": { "rule": "x" } } } }
    ]);
    assert!(codes(&v).contains(&Code::AuthorityViolation));
    find(&mut v, "actions", "act:barrier")["history"][0]["approval"]["kind"] =
        json!({ "human": { "principal": "oncall" } });
    assert!(codes(&v).is_empty());
}

#[test]
fn policy_cannot_make_mutation_autonomous() {
    let mut v = base();
    v["authority_policy"] = json!({
        "version": "yolo/1",
        "gates": { "temporary_containment": "autonomous" }
    });
    find(&mut v, "actions", "act:shield")["history"][0]["approval"]["kind"] =
        json!({ "autonomous": { "policy_version": "yolo/1" } });
    assert!(codes(&v).contains(&Code::AuthorityViolation));
}

#[test]
fn understated_capability_authority() {
    let mut v = base();
    find(&mut v, "capabilities", "cap:barrier")["authority"] = json!("observe");
    assert!(codes(&v).contains(&Code::InvalidObject));
}

#[test]
fn understated_authority_is_still_gated_as_what_it_is() {
    // Mislabel BARRIER as observe-only AND drop its own approval requirement,
    // then self-approve autonomously. BARRIER is intrinsically at least
    // temporary containment, so the gate is still policy-dependent.
    let mut v = base();
    let cap = find(&mut v, "capabilities", "cap:barrier");
    cap["authority"] = json!("observe");
    cap["approval_requirement"] = json!("autonomous");
    find(&mut v, "actions", "act:barrier")["history"] = json!([
        { "type": "authorise", "at": 4300, "approval": { "id": "appr:b",
          "kind": { "autonomous": { "policy_version": "production-default/1" } } } }
    ]);
    let c = codes(&v);
    assert!(c.contains(&Code::InvalidObject), "{c:?}");
    assert!(c.contains(&Code::AuthorityViolation), "{c:?}");
}

#[test]
fn target_outside_scope_or_class() {
    let mut v = base();
    find(&mut v, "actions", "act:barrier")["target"] = json!("ent:src-cluster");
    let c = codes(&v);
    assert!(
        c.iter().filter(|c| **c == Code::AuthorityViolation).count() >= 2,
        "{c:?}"
    );
}

#[test]
fn reasoning_phases_cannot_exercise_mutation() {
    let mut v = base();
    event(&mut v, 5)["authority"] = json!("network_isolation");
    assert!(codes(&v).contains(&Code::AgentEventViolation));
}

#[test]
fn act_must_match_capability_authority() {
    let mut v = base();
    event(&mut v, 10)["authority"] = json!("permanent_policy_change");
    assert!(codes(&v).contains(&Code::AgentEventViolation));
}

#[test]
fn agent_loop_cannot_jump_to_act() {
    let mut v = base();
    event(&mut v, 9)["phase"] = json!("EVALUATE"); // EVALUATE -> ACT is illegal
    assert!(codes(&v).contains(&Code::AgentEventViolation));
}

// ── Human interruption ─────────────────────────────────────────────────────

#[test]
fn human_can_stop_pending_intervention() {
    let mut v = base();
    find(&mut v, "actions", "act:barrier")["history"] = json!([
        { "type": "cancel", "at": 4300, "by": { "human": { "name": "oncall" } }, "reason": "shield sufficient" }
    ]);
    let g = load(&v).unwrap();
    assert_eq!(
        g.actions[&ActionId::new("act:barrier").unwrap()].state(),
        ActionState::Cancelled
    );

    find(&mut v, "actions", "act:barrier")["history"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "type": "begin_execution", "at": 4400 }));
    assert!(codes(&v).contains(&Code::InvalidObject));
}

// ── Verification ───────────────────────────────────────────────────────────

#[test]
fn verification_must_use_declared_method() {
    let mut v = base();
    find(&mut v, "actions", "act:shield")["history"][4]["method"] = json!("looked fine");
    assert!(codes(&v).contains(&Code::VerificationViolation));
}

#[test]
fn verification_must_be_independent_of_success_evidence() {
    let mut v = base();
    find(&mut v, "actions", "act:shield")["history"][4]["evidence"] =
        json!([{ "observation": "obs:rate-after" }]);
    assert!(codes(&v).contains(&Code::InvalidObject));
}

// ── Graceful incompleteness ────────────────────────────────────────────────

#[test]
fn missing_telemetry_is_reported_not_papered_over() {
    let mut v = base();
    v["observations"]
        .as_array_mut()
        .unwrap()
        .retain(|o| o["id"] != "obs:inv-k8s");
    let c = codes(&v);
    assert!(c.contains(&Code::DanglingReference));
    assert!(c.contains(&Code::UngroundedProvenance));
}

#[test]
fn unclassified_entities_are_first_class() {
    let mut v = base();
    find(&mut v, "entities", "ent:src-cluster")["class"] = json!("unknown");
    find(&mut v, "capabilities", "cap:scan")["target_classes"] = json!(["unknown"]);
    assert!(load(&v).is_ok());
}

#[test]
fn ontology_version_is_enforced() {
    let mut v = base();
    v["ontology_version"] = json!("navi-ontology/9.9");
    assert!(codes(&v).contains(&Code::OntologyVersionMismatch));
}

#[test]
fn duplicate_ids_are_rejected() {
    let mut v = base();
    let dup = v["observations"][0].clone();
    v["observations"].as_array_mut().unwrap().push(dup);
    assert!(codes(&v).contains(&Code::DuplicateId));
}
