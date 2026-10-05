//! Phase 6 acceptance: readiness certification and bounded autonomy.

use navi_actions::{auto_approve, cancel, expire, run, Refusal, RunOptions};
use navi_events::IncidentLog;
use navi_graph::{Code, LoadError, SemanticGraph};
use navi_ontology::{ActionId, ActionState, ApprovalKind, CapabilityId, CapabilityKind, Timestamp};
use navi_readiness::{evaluate, grant, Certificate, Thresholds};
use std::sync::OnceLock;

const STUFFING_LOG: &str =
    include_str!("../../../tests/fixtures/logs/credential-stuffing.log.json");
const REPO_LOG: &str = include_str!("../../../tests/fixtures/logs/repo-runtime.log.json");
const TOKEN_LOG: &str = include_str!("../../../tests/fixtures/logs/token-theft.log.json");

fn log(t: &str) -> IncidentLog {
    IncidentLog::from_json(t).unwrap()
}
fn corpus() -> Vec<IncidentLog> {
    vec![log(STUFFING_LOG), log(REPO_LOG), log(TOKEN_LOG)]
}
fn cert() -> &'static Certificate {
    static C: OnceLock<Certificate> = OnceLock::new();
    C.get_or_init(|| evaluate(&corpus(), Thresholds::default()))
}
fn cap(s: &str) -> CapabilityId {
    CapabilityId::new(s).unwrap()
}
fn act(s: &str) -> ActionId {
    ActionId::new(s).unwrap()
}
fn state(l: &IncidentLog, a: &str) -> ActionState {
    l.graph().unwrap().actions[&act(a)].state()
}
fn granted() -> IncidentLog {
    grant(
        &log(TOKEN_LOG),
        &cap("cap:shield"),
        cert(),
        30_000,
        600_000,
        "ciso",
        None,
    )
    .unwrap()
}

// ── Readiness ──────────────────────────────────────────────────────────────

#[test]
fn certificate_reflects_trials() {
    let c = cert();
    assert!(c.verify().is_ok());
    for k in [
        CapabilityKind::Shield,
        CapabilityKind::Barrier,
        CapabilityKind::Lock,
        CapabilityKind::Isolate,
    ] {
        assert!(c.covers(k), "{k:?} not certified");
    }
    let shield = c
        .kinds
        .iter()
        .find(|k| k.kind == CapabilityKind::Shield)
        .unwrap();
    for name in [
        "verification",
        "replay",
        "provenance",
        "determinism",
        "fault-detection",
        "rollback",
        "human-interruption",
        "authority",
    ] {
        assert!(
            shield.criteria.iter().any(|x| x.name == name && x.passed()),
            "{name}"
        );
    }
    let faults = shield
        .criteria
        .iter()
        .find(|x| x.name == "fault-detection")
        .unwrap();
    assert_eq!(faults.trials, 3);
    // Untrialable actions are skipped, with the reason — not counted either way.
    assert!(shield
        .skipped
        .iter()
        .any(|s| s.contains("already Verified")));
    assert_eq!(c.corpus.len(), 3);
}

#[test]
fn thresholds_and_empty_corpora_certify_nothing() {
    assert!(evaluate(&[], Thresholds::default()).certified.is_empty());
    let strict = evaluate(&corpus(), Thresholds { min_actions: 5 });
    assert!(strict.certified.is_empty());
    assert!(strict.verify().is_ok());
}

#[test]
fn certificates_are_deterministic_and_tamper_evident() {
    assert_eq!(&evaluate(&corpus(), Thresholds::default()), cert());
    let mut forged = cert().clone();
    forged.certified.push(CapabilityKind::Cleanse);
    assert!(forged.verify().is_err());
    assert!(grant(
        &log(TOKEN_LOG),
        &cap("cap:shield"),
        &forged,
        30_000,
        600_000,
        "ciso",
        None
    )
    .is_err());
}

// ── What may be granted ────────────────────────────────────────────────────

#[test]
fn only_bounded_low_risk_containment_can_be_granted() {
    for c in ["cap:lock", "cap:barrier"] {
        let e = grant(
            &log(TOKEN_LOG),
            &cap(c),
            cert(),
            30_000,
            600_000,
            "ciso",
            None,
        )
        .unwrap_err();
        assert!(e.contains("only temporary containment"), "{c}: {e}");
    }
    let e = grant(
        &log(TOKEN_LOG),
        &cap("cap:shield"),
        cert(),
        10,
        600_000,
        "ciso",
        None,
    )
    .unwrap_err();
    assert!(e.contains("interruption window"), "{e}");
    let e = grant(
        &log(TOKEN_LOG),
        &cap("cap:shield"),
        cert(),
        30_000,
        600_000,
        " ",
        None,
    )
    .unwrap_err();
    assert!(e.contains("name the human"), "{e}");
    let l = granted();
    assert!(l.validate().is_empty());
    let g = l.graph().unwrap();
    assert_eq!(g.authority_policy.autonomy.len(), 1);
    assert!(g.authority_policy.version.ends_with("+autonomy:shield"));
}

#[test]
fn a_certificate_must_cover_the_kind() {
    let narrow = evaluate(&[log(REPO_LOG)], Thresholds::default());
    assert!(!narrow.covers(CapabilityKind::Shield));
    let e = grant(
        &log(TOKEN_LOG),
        &cap("cap:shield"),
        &narrow,
        30_000,
        600_000,
        "ciso",
        None,
    )
    .unwrap_err();
    assert!(e.contains("does not certify"), "{e}");
}

// ── Bounded autonomy in action ─────────────────────────────────────────────

#[test]
fn no_grant_no_autonomy_and_human_gates_stay_human() {
    assert!(matches!(
        auto_approve(&log(TOKEN_LOG), &act("act:throttle"), None),
        Err(Refusal::Gate(_))
    ));
    assert!(matches!(
        auto_approve(&granted(), &act("act:revoke"), None),
        Err(Refusal::Gate(_))
    ));
    assert!(matches!(
        auto_approve(&granted(), &act("act:block"), None),
        Err(Refusal::Gate(_))
    ));
}

#[test]
fn self_authorisation_is_real_bounded_and_interruptible() {
    let l = auto_approve(&granted(), &act("act:throttle"), None).unwrap();
    assert!(
        l.branch.is_none(),
        "an autonomous decision is a real decision"
    );
    let g = l.graph().unwrap();
    let ap = g.actions[&act("act:throttle")].approval().unwrap().clone();
    assert!(
        matches!(ap.kind, ApprovalKind::Autonomous { certificate: Some(ref c), .. } if c == &cert().digest)
    );
    let (nb, ex) = (ap.not_before.unwrap(), ap.expires_at.unwrap());
    // Inside the window: refused; a human can still stop it.
    assert!(matches!(
        run(&l, &act("act:throttle"), RunOptions::default()),
        Err(Refusal::NotRunnable { .. })
    ));
    let stopped = cancel(&l, &act("act:throttle"), "oncall", "not needed", None).unwrap();
    assert_eq!(state(&stopped, "act:throttle"), ActionState::Cancelled);
    // After the window it runs (in the sandbox).
    let r = run(
        &l,
        &act("act:throttle"),
        RunOptions {
            at: Some(nb),
            ..RunOptions::default()
        },
    )
    .unwrap();
    assert!(!r.in_reality && r.branch.branch.is_some());
    assert_eq!(state(&r.branch, "act:throttle"), ActionState::Verified);
    // And it ends on its own.
    assert!(expire(&r.branch, Some(Timestamp(ex.0 - 1)))
        .unwrap()
        .is_none());
    let lifted = expire(&r.branch, Some(ex)).unwrap().unwrap();
    assert_eq!(
        state(&lifted.branch, "act:throttle"),
        ActionState::RolledBack
    );
}

// ── The graph enforces the bounds, whoever writes the log ─────────────────

fn tampered(f: impl FnOnce(&mut serde_json::Value)) -> Vec<Code> {
    let l = auto_approve(&granted(), &act("act:throttle"), None).unwrap();
    let mut v = serde_json::to_value(l.graph().unwrap().to_document()).unwrap();
    f(&mut v);
    match SemanticGraph::from_json(&v.to_string()) {
        Ok(_) => vec![],
        Err(LoadError::Invalid(vs)) => vs.into_iter().map(|x| x.code).collect(),
        Err(e) => panic!("{e}"),
    }
}

fn approval(v: &mut serde_json::Value) -> &mut serde_json::Value {
    let a = v["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|a| a["id"] == "act:throttle")
        .unwrap();
    &mut a["history"][0]["approval"]
}

#[test]
fn forged_autonomy_is_refused_by_the_graph() {
    assert_eq!(tampered(|_| {}), vec![]);
    // No interruption window.
    assert!(tampered(|v| {
        approval(v).as_object_mut().unwrap().remove("not_before");
    })
    .contains(&Code::AuthorityViolation));
    // Longer than the grant allows.
    assert!(
        tampered(|v| approval(v)["expires_at"] = serde_json::json!(99_999_999))
            .contains(&Code::AuthorityViolation)
    );
    // A certificate the grant does not rest on.
    assert!(
        tampered(|v| approval(v)["kind"]["autonomous"]["certificate"] =
            serde_json::json!(format!("sha256:{}", "0".repeat(64))))
        .contains(&Code::AuthorityViolation)
    );
    // Grant withdrawn.
    assert!(tampered(|v| {
        v["authority_policy"]
            .as_object_mut()
            .unwrap()
            .remove("autonomy");
    })
    .contains(&Code::AuthorityViolation));
    // A grant for something that may never be autonomous.
    assert!(tampered(
        |v| v["authority_policy"]["autonomy"][0]["capability"] = serde_json::json!("cap:lock")
    )
    .contains(&Code::AuthorityViolation));
}

#[test]
fn execution_inside_the_window_is_refused_by_the_graph() {
    let l = auto_approve(&granted(), &act("act:throttle"), None).unwrap();
    let nb = l.graph().unwrap().actions[&act("act:throttle")]
        .approval()
        .unwrap()
        .not_before
        .unwrap();
    let ran = run(
        &l,
        &act("act:throttle"),
        RunOptions {
            at: Some(nb),
            ..RunOptions::default()
        },
    )
    .unwrap();
    let mut v = serde_json::to_value(ran.branch.graph().unwrap().to_document()).unwrap();
    let a = v["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|a| a["id"] == "act:throttle")
        .unwrap();
    a["history"][1]["at"] = serde_json::json!(nb.0 - 1);
    match SemanticGraph::from_json(&v.to_string()) {
        Err(LoadError::Invalid(vs)) => {
            assert!(vs.iter().any(|x| x.message.contains("interruption window")))
        }
        other => panic!("accepted: {:?}", other.is_ok()),
    }
}
