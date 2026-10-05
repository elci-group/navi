//! Phase 2 acceptance: Navi traversal and click-to-explain in the realm.

use navi_graph::SemanticGraph;
use realm_core::{Movement, Realm, RealmViolationCode as C};
use serde_json::{json, Value};

const STUFFING: &str = include_str!("../../../tests/fixtures/scenarios/credential-stuffing.json");
const REPO_RUNTIME: &str = include_str!("../../../tests/fixtures/scenarios/repo-runtime.json");

fn compile(text: &str) -> Realm {
    realm_compiler::compile(&SemanticGraph::from_json(text).unwrap())
}

fn moves(r: &Realm, seq: u64) -> Vec<(Movement, String, Option<String>)> {
    let w = r.agents[0]
        .trajectory
        .iter()
        .find(|w| w.seq == seq)
        .unwrap();
    w.route
        .iter()
        .map(|s| (s.movement, s.to.clone(), s.via.clone()))
        .collect()
}

#[test]
fn one_waypoint_per_agent_event() {
    for (text, n) in [(STUFFING, 12), (REPO_RUNTIME, 7)] {
        let r = compile(text);
        let a = &r.agents[0];
        assert_eq!(a.trajectory.len(), n);
        let last = a.trajectory.last().unwrap();
        assert_eq!(
            (Some(last.phase), &last.location, Some(last.at)),
            (a.phase, &a.location, a.at)
        );
        assert_eq!(r.validate(), vec![]);
    }
}

#[test]
fn attention_follows_real_topology() {
    let r = compile(REPO_RUNTIME);
    let bridge = Some("realm:rel:pod2-egress".to_string());
    assert_eq!(
        moves(&r, 4),
        [(Movement::Bridge, "realm:ent:ext-203".into(), bridge.clone())]
    );
    assert_eq!(
        moves(&r, 5),
        [(Movement::Bridge, "realm:ent:api-pod-2".into(), bridge)]
    );
    assert!(moves(&r, 2).is_empty()); // attention did not move

    let r = compile(STUFFING);
    // public-auth → auth-api along the road they communicate over.
    assert_eq!(
        moves(&r, 3),
        [(
            Movement::Road,
            "realm:ent:auth-api".into(),
            Some("realm:rel:edge-auth".into())
        )]
    );
    // auth-api → the external source cluster: back along the road, then across the bridge.
    let m = moves(&r, 4);
    assert_eq!(
        m.iter().map(|x| x.0).collect::<Vec<_>>(),
        [Movement::Road, Movement::Bridge]
    );
    assert_eq!(m.last().unwrap().1, "realm:ent:src-cluster");
}

#[test]
fn no_path_is_an_explicit_teleport() {
    let mut v: Value = serde_json::from_str(REPO_RUNTIME).unwrap();
    v["relationships"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["id"] != "rel:pod2-egress");
    let r = compile(&v.to_string());
    assert_eq!(r.validate(), vec![]);
    assert_eq!(
        moves(&r, 4),
        [(Movement::Teleport, "realm:ent:ext-203".into(), None)]
    );
}

#[test]
fn every_object_can_be_clicked_through_to_observations() {
    for text in [STUFFING, REPO_RUNTIME] {
        let r = compile(text);
        let n = r.entities.len() + r.edges.len() + r.controls.len() + r.hazards.len();
        assert_eq!(r.evidence.len(), n);
        assert!(r.evidence.iter().all(|e| e.tree.observation_leaves() > 0));
    }
}

#[test]
fn deterministic_trajectory_and_html() {
    let a = compile(REPO_RUNTIME);
    let mut v: Value = serde_json::from_str(REPO_RUNTIME).unwrap();
    for (_, coll) in v.as_object_mut().unwrap() {
        if let Some(arr) = coll.as_array_mut() {
            arr.reverse();
        }
    }
    let b = compile(&v.to_string());
    assert_eq!(a, b);
    assert_eq!(
        realm_render::html(&a).unwrap(),
        realm_render::html(&b).unwrap()
    );
    assert_eq!(
        realm_render::trace(&a).unwrap(),
        realm_render::trace(&b).unwrap()
    );
}

// ── Tampering with movement / briefs is refused ────────────────────────────

fn tampered(f: impl FnOnce(&mut Value)) -> Vec<C> {
    let mut v = serde_json::to_value(compile(REPO_RUNTIME)).unwrap();
    f(&mut v);
    let r: Realm = serde_json::from_value(v).unwrap();
    let codes: Vec<C> = r.validate().into_iter().map(|x| x.code).collect();
    if !codes.is_empty() {
        assert!(realm_render::html(&r).is_err());
        assert!(realm_render::trace(&r).is_err());
    }
    codes
}

fn waypoint(v: &mut Value, seq: u64) -> &mut Value {
    v["agents"][0]["trajectory"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|w| w["seq"] == seq)
        .unwrap()
}

#[test]
fn walking_through_walls_is_refused() {
    // Claim attention teleported instead of crossing the evidenced bridge.
    let c = tampered(|v| {
        waypoint(v, 4)["route"] = json!([{ "movement": "teleport", "from": "realm:ent:api-pod-2", "to": "realm:ent:ext-203", "via": null }]);
    });
    assert!(c.contains(&C::TrajectoryViolation));
}

#[test]
fn relocated_waypoint_is_refused() {
    let c = tampered(|v| {
        let w = waypoint(v, 6);
        w["location"] = json!("realm:ent:orders-db");
        w["brief"]["location"] = json!("realm:ent:orders-db");
    });
    assert!(c.contains(&C::TrajectoryViolation));
}

#[test]
fn invented_next_step_is_refused() {
    let c = tampered(|v| waypoint(v, 1)["brief"]["next"]["phase"] = json!("ACT"));
    assert!(c.contains(&C::TrajectoryViolation));
    let c = tampered(|v| waypoint(v, 1)["brief"]["legal_next"] = json!(["ACT"]));
    assert!(c.contains(&C::TrajectoryViolation));
}

#[test]
fn hud_disagreeing_with_trajectory_is_refused() {
    let c = tampered(|v| v["agents"][0]["location"] = json!("realm:ent:ext-203"));
    assert!(c.contains(&C::TrajectoryViolation));
}

#[test]
fn missing_or_empty_evidence_is_refused() {
    let c = tampered(|v| {
        v["evidence"]
            .as_array_mut()
            .unwrap()
            .retain(|e| e["realm_id"] != "realm:hyp:c2")
    });
    assert!(c.contains(&C::MissingEvidence));
    let c = tampered(|v| {
        let e = v["evidence"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e["realm_id"] == "realm:ent:api")
            .unwrap();
        e["tree"]["children"] = json!([]);
    });
    assert!(c.contains(&C::MissingEvidence));
}

#[test]
fn html_cannot_be_broken_out_of() {
    let hostile = "x</script><script>alert(1)</script>";
    let mut v: Value = serde_json::from_str(REPO_RUNTIME).unwrap();
    v["entities"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e["id"] == "ent:api")
        .unwrap()["name"] = json!(hostile);
    let html = realm_render::html(&compile(&v.to_string())).unwrap();
    assert!(
        !html.contains("<script>alert"),
        "entity name escaped into executable script"
    );
    assert_eq!(html.matches("</script>").count(), 1);
}
