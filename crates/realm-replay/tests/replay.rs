//! Phase 3 acceptance: replay fidelity, snapshot + deltas, COMPARE, FORK.

use navi_events::IncidentLog;
use navi_graph::SemanticGraph;
use navi_ontology::{ActionState, Timestamp};
use realm_replay::{compare, reconstruct, ChangeKind, Delta, ReconstructError, Replay};

const REPO_RUNTIME: &str = include_str!("../../../tests/fixtures/scenarios/repo-runtime.json");
const STUFFING_LOG: &str =
    include_str!("../../../tests/fixtures/logs/credential-stuffing.log.json");
const REPO_LOG: &str = include_str!("../../../tests/fixtures/logs/repo-runtime.log.json");
const BRANCH: &str =
    include_str!("../../../tests/fixtures/forks/repo-runtime-approve-isolation.branch.json");

fn replay(text: &str) -> Replay {
    Replay::build(&IncidentLog::from_json(text).unwrap()).unwrap()
}

#[test]
fn one_valid_frame_per_instant() {
    for text in [STUFFING_LOG, REPO_LOG, BRANCH] {
        let log = IncidentLog::from_json(text).unwrap();
        let r = replay(text);
        assert_eq!(r.frames.len(), log.instants().len());
        for f in &r.frames {
            assert_eq!(f.realm.validate(), vec![], "frame at {}", f.at);
            assert!(!f.lines.is_empty());
        }
    }
}

#[test]
fn replay_ends_where_the_snapshot_is() {
    let r = replay(REPO_LOG);
    let snapshot = realm_compiler::compile(&SemanticGraph::from_json(REPO_RUNTIME).unwrap());
    assert_eq!(r.frames.last().unwrap().realm, snapshot);
}

#[test]
fn replay_fidelity_through_snapshot_and_deltas() {
    for text in [STUFFING_LOG, REPO_LOG, BRANCH] {
        let r = replay(text);
        let s = r.stream();
        // Over the wire and back.
        let s: realm_replay::Stream =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        let rebuilt = reconstruct(&s).unwrap();
        assert_eq!(rebuilt.len(), r.frames.len());
        for ((at, realm), f) in rebuilt.iter().zip(&r.frames) {
            assert_eq!((*at, realm), (f.at, &f.realm));
        }
        // Deltas, not repeated snapshots: far smaller than sending every frame.
        let full: usize = r
            .frames
            .iter()
            .map(|f| serde_json::to_string(&f.realm).unwrap().len())
            .sum();
        let sent = serde_json::to_string(&s).unwrap().len();
        assert!(
            sent * 2 < full,
            "stream {sent} bytes vs {full} for full frames"
        );
    }
}

#[test]
fn tampered_streams_are_detected() {
    let mut s = replay(REPO_LOG).stream();
    let f = s
        .frames
        .iter_mut()
        .find(|f| {
            f.deltas
                .iter()
                .any(|d| matches!(d, Delta::Upsert { collection, .. } if collection == "hazards"))
        })
        .unwrap();
    for d in &mut f.deltas {
        if let Delta::Upsert { collection, value } = d {
            if collection == "hazards" {
                value["epistemic_state"] = serde_json::json!("CONFIRMED");
            }
        }
    }
    assert!(matches!(
        reconstruct(&s),
        Err(ReconstructError::Digest { .. })
    ));

    let mut s = replay(REPO_LOG).stream();
    s.frames[0].deltas.push(Delta::Remove {
        collection: "secrets".into(),
        realm_id: "x".into(),
    });
    assert!(matches!(
        reconstruct(&s),
        Err(ReconstructError::Unknown { .. })
    ));

    let mut s = replay(REPO_LOG).stream();
    s.stream_version = "realm-stream/9".into();
    assert!(matches!(reconstruct(&s), Err(ReconstructError::Version(_))));
}

#[test]
fn deterministic_replay() {
    let a = serde_json::to_string(&replay(REPO_LOG).stream()).unwrap();
    let b = serde_json::to_string(&replay(REPO_LOG).stream()).unwrap();
    assert_eq!(a, b);
}

#[test]
fn rewind_shows_the_past_not_the_present() {
    let r = replay(REPO_LOG);
    let at = |t| r.at(Timestamp(t)).unwrap();
    assert!(r.at(Timestamp(-1)).is_none());
    // Before t=3000 nothing is suspicious and Navi is idle.
    let f = at(2999);
    assert!(f.realm.hazards.iter().all(|h| h.claim != "c2_beacon"));
    assert_eq!(f.realm.agents[0].phase, None);
    assert_eq!(f.realm.agents[0].location, None);
    // Between instants, the earlier frame is in force.
    assert_eq!(at(3150).at, Timestamp(3100));
}

#[test]
fn compare_two_instants() {
    let r = replay(REPO_LOG);
    let c = compare(
        &r.at(Timestamp(3000)).unwrap().realm,
        &r.at(Timestamp(4000)).unwrap().realm,
    );
    assert!(c
        .iter()
        .any(|x| x.kind == ChangeKind::Added && x.realm_id == "realm:hyp:c2"));
    let pod = c
        .iter()
        .find(|x| x.realm_id == "realm:ent:api-pod-2")
        .unwrap();
    assert!(
        pod.details.iter().any(|d| d == "risk: none → SUSPICIOUS"),
        "{:?}",
        pod.details
    );
    assert!(compare(&r.frames[3].realm, &r.frames[3].realm).is_empty());
}

#[test]
fn compare_reality_with_a_counterfactual() {
    let (real, cf) = (replay(REPO_LOG), replay(BRANCH));
    let a = &real.frames.last().unwrap().realm;
    let b = &cf.frames.last().unwrap().realm;
    assert!(a.branch.is_none());
    assert_eq!(b.branch.as_ref().unwrap().fork_of, real.log_digest);
    let navi = compare(a, b)
        .into_iter()
        .find(|x| x.realm_id == "realm:agent:navi-01")
        .unwrap();
    assert!(
        navi.details
            .iter()
            .any(|d| d == "action act:isolate: PROPOSED → VERIFIED"),
        "{:?}",
        navi.details
    );
    let real_act = &a.agents[0].actions[0];
    assert_eq!(
        real_act.state,
        ActionState::Proposed,
        "reality is unchanged by the fork"
    );
}

#[test]
fn counterfactuals_are_labelled_everywhere() {
    let cf = replay(BRANCH);
    let r = &cf.frames.last().unwrap().realm;
    let banner = "NOT REALITY";
    assert!(realm_render::text(r).unwrap().contains(banner));
    assert!(realm_render::svg(r).unwrap().contains(banner));
    assert!(realm_render::html(r).unwrap().contains(banner));
    assert!(realm_render::trace(r).unwrap().contains(banner));
    let frames: Vec<realm_render::DvrFrame> = cf
        .frames
        .iter()
        .map(|f| realm_render::DvrFrame {
            at: f.at,
            lines: &f.lines,
            realm: &f.realm,
        })
        .collect();
    assert!(realm_render::dvr(&frames).unwrap().contains(banner));
    // Reality never is.
    let real = replay(REPO_LOG);
    assert!(!realm_render::text(&real.frames.last().unwrap().realm)
        .unwrap()
        .contains(banner));
}

#[test]
fn dvr_page_is_self_contained_and_escaped() {
    let r = replay(STUFFING_LOG);
    let frames: Vec<realm_render::DvrFrame> = r
        .frames
        .iter()
        .map(|f| realm_render::DvrFrame {
            at: f.at,
            lines: &f.lines,
            realm: &f.realm,
        })
        .collect();
    let html = realm_render::dvr(&frames).unwrap();
    assert!(html.starts_with("<!doctype html>"));
    assert!(!html.contains("src=\"http"));
    assert_eq!(html.matches("</script>").count(), 1);
    for label in ["replay", "rewind", "play", "step", "live", "compare"] {
        assert!(html.contains(label), "{label} control missing");
    }
}
