//! Phase 5 acceptance: semantic level of detail and lenses.

use navi_graph::SemanticGraph;
use navi_ontology::EpistemicState;
use realm_core::{Realm, RealmViolationCode};
use realm_lod::{view, Detail, Lens, LensRequest, View, ViewSpec};

const REPO_RUNTIME: &str = include_str!("../../../tests/fixtures/scenarios/repo-runtime.json");
const STUFFING: &str = include_str!("../../../tests/fixtures/scenarios/credential-stuffing.json");
const TOKEN: &str = include_str!("../../../tests/fixtures/scenarios/token-theft.json");
const REPO_LOG: &str = include_str!("../../../tests/fixtures/logs/repo-runtime.log.json");

fn realm(t: &str) -> Realm {
    realm_compiler::compile(&SemanticGraph::from_json(t).unwrap())
}

fn attention(r: &Realm) -> View {
    view(r, &ViewSpec::default())
}

fn d(v: &View, id: &str) -> Detail {
    v.detail[&format!("realm:{id}")].clone()
}

#[test]
fn detail_grows_toward_attention() {
    let r = realm(REPO_RUNTIME);
    let v = attention(&r);
    assert_eq!(v.focus, ["realm:ent:api-pod-2"]);
    assert!(v.focus_reason.contains("LC-DEFENCE-01"));
    // The path to the focus is open…
    for id in ["ent:org", "ent:prod", "ent:shop", "ent:api"] {
        assert_eq!(d(&v, id), Detail::Expanded, "{id}");
    }
    assert_eq!(d(&v, "ent:api-pod-2"), Detail::Leaf);
    // …while detail elsewhere is compressed.
    assert_eq!(d(&v, "ent:web"), Detail::Collapsed);
    assert_eq!(d(&v, "ent:web-pod-1"), Detail::Hidden);
    assert_eq!(v.check(&r), Vec::<String>::new());
}

#[test]
fn compression_never_conceals_a_hazard() {
    let r = realm(REPO_RUNTIME);
    let v = attention(&r);
    // branch-main (UNEXPLAINED drift) is hidden inside the collapsed repo.
    assert_eq!(d(&v, "ent:branch-main"), Detail::Hidden);
    let repo = &v.aggregates["realm:ent:repo"];
    assert_eq!(repo.max_hazard, Some(EpistemicState::Unexplained));
    assert_eq!(repo.hidden, 1);
    assert_eq!(v.anchor(&r, "realm:ent:branch-main"), "realm:ent:repo");
    let text = realm_render::text_view(&r, &v).unwrap();
    assert!(text.contains("main shown at elci/shop"));
    assert!(text.contains("⊞~UNEXPLAINED"));
    for h in &r.hazards {
        assert!(
            text.contains(&h.visual_contract.label),
            "{} missing from the view",
            h.realm_id
        );
    }
}

#[test]
fn reanchored_edges_still_name_their_real_endpoints() {
    let r = realm(REPO_RUNTIME);
    let v = attention(&r);
    let text = realm_render::text_view(&r, &v).unwrap();
    assert!(text.contains(
        "release.yml → api  (deploys_to)  [rel:artifact-deploys]  — really shop-api:1.42.0 → api"
    ));
    let svg = realm_render::svg_view(&r, &v).unwrap();
    assert!(svg.contains("data-source-ids=\"rel:artifact-deploys\""));
}

#[test]
fn tampered_views_are_refused() {
    let r = realm(REPO_RUNTIME);
    let refused = |v: &View| {
        let e = realm_render::text_view(&r, v).unwrap_err();
        assert!(e
            .0
            .iter()
            .all(|x| x.code == RealmViolationCode::Concealment));
        assert!(realm_render::svg_view(&r, v).is_err());
    };
    // Understate what a collapsed place hides.
    let mut v = attention(&r);
    v.aggregates.get_mut("realm:ent:repo").unwrap().max_hazard = None;
    assert!(!v.check(&r).is_empty());
    refused(&v);
    // Hide the focus.
    let mut v = attention(&r);
    v.detail
        .insert("realm:ent:api-pod-2".into(), Detail::Hidden);
    assert!(!v.check(&r).is_empty());
    refused(&v);
    // Hide something with nothing standing in for it.
    let mut v = attention(&r);
    v.detail
        .insert("realm:ent:orders-db".into(), Detail::Hidden);
    assert!(!v.check(&r).is_empty());
    refused(&v);
}

#[test]
fn operator_focus_and_depth() {
    let r = realm(REPO_RUNTIME);
    let v = view(
        &r,
        &ViewSpec {
            focus: vec!["realm:ent:branch-main".into()],
            depth: 1,
            lens: LensRequest::None,
        },
    );
    assert_eq!(v.focus_reason, "operator focus");
    assert_eq!(d(&v, "ent:repo"), Detail::Expanded);
    assert_eq!(d(&v, "ent:prod"), Detail::Collapsed);
    // Navi is attending inside prod: shown there, not lost.
    assert_eq!(v.anchor(&r, "realm:ent:api-pod-2"), "realm:ent:prod");
    assert_eq!(
        v.aggregates["realm:ent:prod"].max_hazard,
        Some(EpistemicState::Suspicious)
    );
    assert!(v.check(&r).is_empty());
    // Deep enough, nothing collapses.
    let v = view(
        &r,
        &ViewSpec {
            depth: 99,
            ..ViewSpec::default()
        },
    );
    assert!(v.aggregates.is_empty());
    assert!(v.detail.values().all(|x| *x != Detail::Hidden));
}

#[test]
fn idle_navi_falls_back_to_the_strongest_hazard() {
    let log = navi_events::IncidentLog::from_json(REPO_LOG).unwrap();
    let rep = realm_replay::Replay::build(&log).unwrap();
    let frame = rep.at(navi_ontology::Timestamp(2999)).unwrap();
    let v = attention(&frame.realm);
    assert!(
        v.focus_reason.contains("strongest hazard"),
        "{}",
        v.focus_reason
    );
    assert_eq!(v.focus, ["realm:ent:branch-main"]);
    let v = attention(&rep.frames[0].realm);
    assert!(v.focus.is_empty());
    assert!(v.check(&rep.frames[0].realm).is_empty());
}

#[test]
fn lens_follows_what_is_under_attack() {
    let lens = |t: &str| attention(&realm(t)).lens.map(|l| l.lens);
    assert_eq!(lens(TOKEN), Some(Lens::Iam));
    assert_eq!(lens(STUFFING), Some(Lens::Network));
    assert_eq!(lens(REPO_RUNTIME), Some(Lens::Network));
    let v = attention(&realm(TOKEN));
    let strip = v.lens.unwrap();
    assert!(strip.reason.contains("ci-deploy-token (credential)"));
    let credential = strip
        .stages
        .iter()
        .find(|s| s.name == "credential")
        .unwrap();
    assert_eq!(credential.entities, ["realm:ent:deploy-token"]);
}

#[test]
fn lens_can_be_forced_or_disabled_and_ties_are_reported() {
    let r = realm(REPO_RUNTIME);
    let v = view(
        &r,
        &ViewSpec {
            lens: LensRequest::Fixed(Lens::SupplyChain),
            ..ViewSpec::default()
        },
    );
    assert_eq!(v.lens.unwrap().lens, Lens::SupplyChain);
    let v = view(
        &r,
        &ViewSpec {
            lens: LensRequest::None,
            ..ViewSpec::default()
        },
    );
    assert!(v.lens.is_none() && v.lens_note.is_none());
    // Nothing happening yet (first replay frame): no lens, and it says why.
    let log = navi_events::IncidentLog::from_json(REPO_LOG).unwrap();
    let first = realm_replay::Replay::build(&log).unwrap().frames[0]
        .realm
        .clone();
    let v = attention(&first);
    assert!(v.lens.is_none());
    assert!(
        v.lens_note
            .as_deref()
            .is_some_and(|n| n.starts_with("no lens: nothing")),
        "{:?}",
        v.lens_note
    );
}

#[test]
fn views_are_deterministic_and_leave_the_realm_alone() {
    let r = realm(REPO_RUNTIME);
    let before = r.digest();
    let (a, b) = (attention(&r), attention(&r));
    assert_eq!(a, b);
    assert_eq!(
        realm_render::svg_view(&r, &a).unwrap(),
        realm_render::svg_view(&r, &b).unwrap()
    );
    assert_eq!(r.digest(), before);
}
