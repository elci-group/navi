//! Phase 1 acceptance: directive §26 as it applies to the compiled realm,
//! plus the renderer-side §19 gate against tampered/forged Realm IR.

use navi_graph::SemanticGraph;
use navi_ontology::{EpistemicState, Gate};
use realm_core::{EpistemicView, Primitive, Realm, RealmViolationCode as C};
use serde_json::{json, Value};

const STUFFING: &str = include_str!("../../../tests/fixtures/scenarios/credential-stuffing.json");
const REPO_RUNTIME: &str = include_str!("../../../tests/fixtures/scenarios/repo-runtime.json");

fn graph(text: &str) -> SemanticGraph {
    SemanticGraph::from_json(text).unwrap_or_else(|e| panic!("{e:?}"))
}

fn compile(text: &str) -> Realm {
    realm_compiler::compile(&graph(text))
}

fn entity<'r>(r: &'r Realm, id: &str) -> &'r realm_core::RealmEntity {
    r.entity(&format!("realm:{id}"))
        .unwrap_or_else(|| panic!("{id}"))
}

fn hazard<'r>(r: &'r Realm, id: &str) -> &'r realm_core::RealmHazard {
    r.hazards
        .iter()
        .find(|h| h.realm_id == format!("realm:{id}"))
        .unwrap()
}

fn edge<'r>(r: &'r Realm, id: &str) -> &'r realm_core::RealmEdge {
    r.edges
        .iter()
        .find(|e| e.realm_id == format!("realm:{id}"))
        .unwrap()
}

#[test]
fn scenarios_compile_to_valid_realms() {
    for text in [STUFFING, REPO_RUNTIME] {
        let r = compile(text);
        assert_eq!(r.validate(), vec![]);
    }
}

// ── Determinism ────────────────────────────────────────────────────────────

#[test]
fn determinism_same_state_same_realm() {
    for text in [STUFFING, REPO_RUNTIME] {
        let a = serde_json::to_string(&compile(text)).unwrap();
        let mut v: Value = serde_json::from_str(text).unwrap();
        for (_, coll) in v.as_object_mut().unwrap() {
            if let Some(arr) = coll.as_array_mut() {
                arr.reverse();
            }
        }
        let b = serde_json::to_string(&compile(&v.to_string())).unwrap();
        assert_eq!(a, b);
        let l1 = realm_layout::layout(&compile(text));
        let l2 = realm_layout::layout(&compile(&v.to_string()));
        assert_eq!(l1, l2);
        assert_eq!(
            realm_render::svg(&compile(text)).unwrap(),
            realm_render::svg(&compile(&v.to_string())).unwrap()
        );
    }
}

#[test]
fn realm_ir_roundtrips() {
    let r = compile(REPO_RUNTIME);
    let back: Realm = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(r, back);
    assert_eq!(back.validate(), vec![]);
}

// ── Provenance completeness & reverse resolution ───────────────────────────

#[test]
fn every_realm_object_resolves_to_raw_observations() {
    for text in [STUFFING, REPO_RUNTIME] {
        let g = graph(text);
        let r = realm_compiler::compile(&g);
        let primaries = r
            .entities
            .iter()
            .map(|x| &x.source_ids[0])
            .chain(r.edges.iter().map(|x| &x.source_ids[0]))
            .chain(r.controls.iter().map(|x| &x.source_ids[0]))
            .chain(r.hazards.iter().map(|x| &x.source_ids[0]));
        for src in primaries {
            let tree = g
                .explain(src)
                .unwrap_or_else(|| panic!("{src} does not resolve"));
            assert!(
                !tree.observations().is_empty(),
                "{src} has no observation leaves"
            );
        }
        for a in &r.agents {
            for ev in &a.source_ids[1..] {
                let (agent, seq) = ev.split_once('#').unwrap();
                let key = (
                    navi_ontology::AgentId::new(agent).unwrap(),
                    seq.parse().unwrap(),
                );
                assert!(
                    g.agent_events.contains_key(&key),
                    "{ev} is not a real agent event"
                );
            }
        }
    }
}

// ── Epistemic fidelity ─────────────────────────────────────────────────────

#[test]
fn suspicion_is_not_rendered_as_an_enemy() {
    let r = compile(REPO_RUNTIME);
    let c2 = hazard(&r, "hyp:c2");
    assert_eq!(c2.epistemic_state, EpistemicState::Suspicious);
    assert_eq!(c2.semantic_type, Primitive::UnknownEntity);
    assert_eq!(c2.view, EpistemicView::UnknownEntity);
    assert!(
        c2.visual_contract.label.starts_with("c2_beacon?"),
        "{}",
        c2.visual_contract.label
    );
    // Unattributed: no actor is invented.
    assert_eq!(c2.actor, None);
    assert_eq!(
        entity(&r, "ent:ext-203").semantic_type,
        Primitive::UnknownEntity
    );
    // Low-confidence drift is fog, not a threat.
    let drift = hazard(&r, "hyp:dep-drift");
    assert_eq!(drift.semantic_type, Primitive::Fog);
    assert_eq!(drift.view, EpistemicView::Silhouette);
}

#[test]
fn sufficient_evidence_produces_an_enemy() {
    let r = compile(STUFFING);
    let h = hazard(&r, "hyp:cred-stuffing");
    assert_eq!(h.semantic_type, Primitive::Enemy);
    assert_eq!(h.view, EpistemicView::ClassifiedHostile);
    assert_eq!(h.actor.as_deref(), Some("realm:ent:src-cluster"));
    assert_eq!(
        entity(&r, "ent:src-cluster").semantic_type,
        Primitive::Enemy
    );
}

#[test]
fn promotion_in_the_graph_changes_the_realm() {
    let mut v: Value = serde_json::from_str(REPO_RUNTIME).unwrap();
    let h = v["hypotheses"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|h| h["id"] == "hyp:c2")
        .unwrap();
    h["transitions"].as_array_mut().unwrap().push(json!({
        "at": 5000, "from": "SUSPICIOUS", "to": "PROBABLE",
        "confidence": { "value": 0.71, "estimator": { "name": "egress-anomaly", "version": "0.2" } },
        "evidence": [{ "observation": "obs:dep-change" }], "reason": "test promotion"
    }));
    let r = compile(&v.to_string());
    assert_eq!(r.validate(), vec![]);
    assert_eq!(hazard(&r, "hyp:c2").semantic_type, Primitive::Enemy);
    // Still unattributed: an enemy, but "?" as actor.
    assert_eq!(hazard(&r, "hyp:c2").actor, None);
    assert_eq!(
        entity(&r, "ent:api-pod-2").risk.max_state,
        Some(EpistemicState::Probable)
    );
}

#[test]
fn confidence_values_stay_distinct() {
    let r = compile(STUFFING);
    let h = hazard(&r, "hyp:cred-stuffing");
    assert_eq!(h.confidence.percent, "83%");
    assert_eq!(realm_core::ConfidenceView::percent_label(5100), "51%");
    assert_eq!(realm_core::ConfidenceView::percent_label(9900), "99%");
    assert_eq!(realm_core::ConfidenceView::percent_label(5150), "51.50%");
}

// ── Grammar ────────────────────────────────────────────────────────────────

#[test]
fn grammar_maps_the_estate() {
    let r = compile(REPO_RUNTIME);
    assert_eq!(entity(&r, "ent:org").semantic_type, Primitive::World);
    assert_eq!(entity(&r, "ent:prod").semantic_type, Primitive::Region);
    assert_eq!(entity(&r, "ent:shop").semantic_type, Primitive::District);
    assert_eq!(entity(&r, "ent:api").semantic_type, Primitive::Building);
    assert_eq!(entity(&r, "ent:api-pod-2").semantic_type, Primitive::Room);
    assert_eq!(entity(&r, "ent:ingress").semantic_type, Primitive::Portal);
    assert_eq!(entity(&r, "ent:orders-db").semantic_type, Primitive::Vault);
    assert_eq!(edge(&r, "rel:web-api").semantic_type, Primitive::Road);
    assert_eq!(edge(&r, "rel:pod2-egress").semantic_type, Primitive::Bridge);
    assert_eq!(edge(&r, "rel:api-db-auth").semantic_type, Primitive::Door);
    assert_eq!(
        edge(&r, "rel:artifact-deploys").semantic_type,
        Primitive::Teleport
    );
    // Containment is nesting, never an edge.
    assert!(r
        .edges
        .iter()
        .all(|e| e.kind != navi_ontology::RelationKind::Contains));
    assert_eq!(
        entity(&r, "ent:api-pod-2").parent.as_deref(),
        Some("realm:ent:api")
    );
}

#[test]
fn stale_and_unknown_are_explicit() {
    let r = compile(REPO_RUNTIME);
    assert!(entity(&r, "ent:web-pod-1").stale);
    assert!(entity(&r, "ent:web-pod-1")
        .visual_contract
        .badges
        .contains(&realm_core::Badge::Stale));
    // Unplaced actor stays outside the estate rather than being guessed into it.
    assert_eq!(entity(&r, "ent:ext-203").parent, None);
    // Control whose enforcement was not observed does not guard anything.
    assert!(entity(&r, "ent:shop").guarded_by.is_empty());
    assert_eq!(entity(&r, "ent:api").guarded_by, vec!["realm:sg:netpol"]);
}

// ── Authority fidelity ─────────────────────────────────────────────────────

#[test]
fn hud_shows_exactly_the_loadout() {
    let r = compile(REPO_RUNTIME);
    let a = &r.agents[0];
    let caps: Vec<_> = a.loadout.iter().map(|s| s.capability.as_str()).collect();
    assert_eq!(caps, ["cap:scan", "cap:trace", "cap:isolate"]);
    let iso = a
        .loadout
        .iter()
        .find(|s| s.capability == "cap:isolate")
        .unwrap();
    assert_eq!(iso.gate, Gate::HumanApproval);
    assert_eq!(a.location.as_deref(), Some("realm:ent:api-pod-2"));
    assert_eq!(a.hypothesis.as_deref(), Some("realm:hyp:c2"));
    assert_eq!(a.confidence.as_ref().unwrap().percent, "55%");
    let text = realm_render::text(&r).unwrap();
    assert!(text.contains("HUMAN APPROVAL REQUIRED"));
    assert!(text.contains("PROPOSED  (awaiting authorisation)"));
}

// ── Renderer-side §19 gate: tampered / forged Realm IR ─────────────────────

fn tampered(f: impl FnOnce(&mut Value)) -> Vec<C> {
    let mut v = serde_json::to_value(compile(REPO_RUNTIME)).unwrap();
    f(&mut v);
    let r: Realm = serde_json::from_value(v).expect("still well-formed Realm IR");
    let codes: Vec<C> = r.validate().into_iter().map(|x| x.code).collect();
    assert!(
        realm_render::text(&r).is_err() || codes.is_empty(),
        "renderer drew a refused realm"
    );
    assert!(realm_render::svg(&r).is_err() || codes.is_empty());
    codes
}

fn find<'a>(v: &'a mut Value, coll: &str, id: &str) -> &'a mut Value {
    v[coll]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|x| x["realm_id"] == format!("realm:{id}"))
        .unwrap()
}

#[test]
fn forged_enemy_is_refused() {
    let c = tampered(|v| find(v, "hazards", "hyp:c2")["semantic_type"] = json!("enemy"));
    assert!(c.contains(&C::SemanticMismatch));
    let c = tampered(|v| find(v, "entities", "ent:ext-203")["semantic_type"] = json!("enemy"));
    assert!(c.contains(&C::SemanticMismatch));
}

#[test]
fn invented_attribution_is_refused() {
    let c = tampered(|v| find(v, "hazards", "hyp:c2")["actor"] = json!("realm:ent:ext-203"));
    assert!(c.contains(&C::InconsistentDerivation), "{c:?}");
}

#[test]
fn sourceless_object_is_refused() {
    let c = tampered(|v| find(v, "entities", "ent:api")["source_ids"] = json!([]));
    assert!(c.contains(&C::MissingSource));
    let c = tampered(|v| find(v, "entities", "ent:api")["source_ids"] = json!(["ent:web"]));
    assert!(c.contains(&C::MissingSource));
}

#[test]
fn prettified_trust_is_refused() {
    let c = tampered(|v| {
        find(v, "entities", "ent:api-pod-2")["visual_contract"]["fill"] = json!("trust_trusted")
    });
    assert!(c.contains(&C::ContractMismatch));
}

#[test]
fn inflated_confidence_label_is_refused() {
    let c = tampered(|v| find(v, "hazards", "hyp:c2")["confidence"]["percent"] = json!("95%"));
    assert!(c.contains(&C::ContractMismatch));
}

#[test]
fn ui_affordance_beyond_authority_is_refused() {
    let c = tampered(|v| {
        let slots = v["agents"][0]["loadout"].as_array_mut().unwrap();
        slots.retain(|s| s["capability"] != "cap:isolate");
    });
    assert!(c.contains(&C::AuthorityOverreach));
    let c = tampered(|v| {
        let slots = v["agents"][0]["loadout"].as_array_mut().unwrap();
        for s in slots
            .iter_mut()
            .filter(|s| s["capability"] == "cap:isolate")
        {
            s["gate"] = json!("autonomous");
        }
    });
    assert!(c.contains(&C::AuthorityOverreach));
}

#[test]
fn hidden_boundary_crossing_is_refused() {
    let c = tampered(|v| {
        let e = find(v, "edges", "rel:pod2-egress");
        e["crosses_boundary"] = json!(false);
        e["semantic_type"] = json!("road");
    });
    assert!(c.contains(&C::InconsistentDerivation));
}

#[test]
fn dangling_and_cyclic_structure_is_refused() {
    let c = tampered(|v| {
        v["entities"]
            .as_array_mut()
            .unwrap()
            .retain(|e| e["realm_id"] != "realm:ent:orders-db")
    });
    assert!(c.contains(&C::DanglingReference));
    let c = tampered(|v| find(v, "entities", "ent:org")["parent"] = json!("realm:ent:api"));
    assert!(c.contains(&C::ContainmentCycle));
}

#[test]
fn foreign_grammar_is_refused() {
    let c = tampered(|v| v["grammar_version"] = json!("realm-grammar/9"));
    assert!(c.contains(&C::VersionMismatch));
}

#[test]
fn removing_a_hazard_from_risk_is_refused() {
    let c = tampered(|v| {
        let e = find(v, "entities", "ent:api-pod-2");
        e["risk"] = json!({ "hazards": [], "max_state": null });
    });
    assert!(c.contains(&C::InconsistentDerivation));
}

// ── Renderer independence ──────────────────────────────────────────────────

#[test]
fn navi_never_depends_on_the_realm() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../");
    for krate in ["navi-ontology", "navi-graph", "navi-cli"] {
        let manifest = std::fs::read_to_string(format!("{root}{krate}/Cargo.toml")).unwrap();
        assert!(
            !manifest.contains("realm-"),
            "{krate} depends on a realm crate"
        );
    }
}
