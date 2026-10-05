//! Phase 4 acceptance: gated, sandboxed intervention.

use navi_actions::{approve, cancel, roll_back, run, Approver, Outcome, Refusal, RunOptions};
use navi_events::{Event, IncidentLog};
use navi_ontology::{ActionId, ActionState, ActionTransition, Timestamp};
use navi_simulator::Faults;

const REPO_LOG: &str = include_str!("../../../tests/fixtures/logs/repo-runtime.log.json");
const TOKEN_LOG: &str = include_str!("../../../tests/fixtures/logs/token-theft.log.json");
const STUFFING_LOG: &str =
    include_str!("../../../tests/fixtures/logs/credential-stuffing.log.json");

fn log(t: &str) -> IncidentLog {
    IncidentLog::from_json(t).unwrap()
}
fn id(s: &str) -> ActionId {
    ActionId::new(s).unwrap()
}
fn human(n: &str) -> Approver {
    Approver::Human(n.into())
}
fn state(l: &IncidentLog, a: &str) -> ActionState {
    l.graph().unwrap().actions[&id(a)].state()
}
fn approved_isolation() -> IncidentLog {
    approve(
        &log(REPO_LOG),
        &id("act:isolate"),
        human("oncall"),
        None,
        None,
    )
    .unwrap()
}
fn faults(f: impl FnOnce(&mut Faults)) -> RunOptions {
    let mut o = RunOptions::default();
    f(&mut o.faults);
    o
}

// ── Gates ──────────────────────────────────────────────────────────────────

#[test]
fn nothing_runs_without_authorisation() {
    let e = run(&log(REPO_LOG), &id("act:isolate"), RunOptions::default()).unwrap_err();
    assert!(
        matches!(
            e,
            Refusal::NotRunnable {
                state: ActionState::Proposed,
                ..
            }
        ),
        "{e}"
    );
    assert!(e.to_string().contains("HumanApproval"));
}

#[test]
fn approvals_must_meet_the_gate() {
    let e = approve(
        &log(REPO_LOG),
        &id("act:isolate"),
        Approver::Policy("auto".into()),
        None,
        None,
    )
    .unwrap_err();
    assert!(matches!(e, Refusal::Gate(_)));
    let e = approve(&log(REPO_LOG), &id("act:isolate"), human("  "), None, None).unwrap_err();
    assert!(matches!(e, Refusal::Gate(_)));
    // Approving twice is not a thing.
    let e = approve(
        &approved_isolation(),
        &id("act:isolate"),
        human("oncall"),
        None,
        None,
    )
    .unwrap_err();
    assert!(matches!(
        e,
        Refusal::NotRunnable {
            state: ActionState::Authorised,
            ..
        }
    ));
}

#[test]
fn approval_is_recorded_in_reality_not_in_a_branch() {
    let l = approved_isolation();
    assert!(l.branch.is_none());
    assert_eq!(state(&l, "act:isolate"), ActionState::Authorised);
    assert!(l.validate().is_empty());
}

#[test]
fn lapsed_approvals_do_not_run() {
    let l = approve(
        &log(REPO_LOG),
        &id("act:isolate"),
        human("oncall"),
        None,
        Some(Timestamp(5050)),
    )
    .unwrap();
    let e = run(
        &l,
        &id("act:isolate"),
        RunOptions {
            at: Some(Timestamp(5100)),
            ..RunOptions::default()
        },
    )
    .unwrap_err();
    assert!(matches!(e, Refusal::Expired(_)), "{e}");
}

#[test]
fn navi_must_legally_reach_act() {
    // Credential stuffing: Navi has already closed its loop (LEARN).
    let l = approve(
        &log(STUFFING_LOG),
        &id("act:barrier"),
        human("ciso"),
        None,
        None,
    )
    .unwrap();
    let e = run(&l, &id("act:barrier"), RunOptions::default()).unwrap_err();
    assert!(matches!(e, Refusal::Loop(_)), "{e}");
}

// ── The lifecycle cannot be shortcut ───────────────────────────────────────

fn transitions(l: &IncidentLog, a: &str) -> Vec<String> {
    l.graph().unwrap().actions[&id(a)]
        .history
        .iter()
        .map(|t| t.name().to_string())
        .collect()
}

#[test]
fn verified_run_is_a_sandbox_branch() {
    let base = approved_isolation();
    let before = base.digest();
    let r = run(&base, &id("act:isolate"), RunOptions::default()).unwrap();
    assert_eq!(r.outcome, Outcome::Verified);
    assert_eq!(base.digest(), before, "reality was modified");
    assert_eq!(state(&base, "act:isolate"), ActionState::Authorised);
    let b = r
        .branch
        .branch
        .as_ref()
        .expect("a sandbox run must be a counterfactual branch");
    assert_eq!(b.fork_of, before);
    assert!(b.label.starts_with("sandbox:"));
    assert_eq!(
        transitions(&r.branch, "act:isolate"),
        [
            "authorise",
            "begin_execution",
            "execution_returned",
            "observe_effect",
            "verify"
        ]
    );
    assert_eq!(state(&r.branch, "act:isolate"), ActionState::Verified);
    // Every observation added by the run is sandbox telemetry.
    for e in &r.branch.events[base.events.len()..] {
        if let Event::ObservationRecorded { observation } = &e.event {
            assert_eq!(observation.source.system, navi_simulator::SOURCE_SYSTEM);
        }
    }
}

#[test]
fn ok_from_the_command_is_not_success() {
    let r = run(
        &approved_isolation(),
        &id("act:isolate"),
        faults(|f| f.silent_noop = true),
    )
    .unwrap();
    assert_eq!(r.outcome, Outcome::EffectNotObserved { rolled_back: false });
    assert_eq!(state(&r.branch, "act:isolate"), ActionState::Executed);
    assert!(!transitions(&r.branch, "act:isolate").contains(&"observe_effect".to_string()));
}

#[test]
fn success_is_not_verification() {
    let r = run(
        &approved_isolation(),
        &id("act:isolate"),
        faults(|f| f.verification_fails = true),
    )
    .unwrap();
    assert_eq!(
        r.outcome,
        Outcome::VerificationFailed { rolled_back: false }
    );
    assert_eq!(
        state(&r.branch, "act:isolate"),
        ActionState::VerificationFailed
    );
}

#[test]
fn failures_can_be_undone_automatically() {
    let mut o = faults(|f| f.verification_fails = true);
    o.rollback_on_failure = true;
    let r = run(&approved_isolation(), &id("act:isolate"), o).unwrap();
    assert_eq!(r.outcome, Outcome::VerificationFailed { rolled_back: true });
    assert_eq!(state(&r.branch, "act:isolate"), ActionState::RolledBack);
    let mut o = faults(|f| f.silent_noop = true);
    o.rollback_on_failure = true;
    let r = run(&approved_isolation(), &id("act:isolate"), o).unwrap();
    assert_eq!(state(&r.branch, "act:isolate"), ActionState::RolledBack);
}

#[test]
fn failed_commands_are_failures() {
    let r = run(
        &approved_isolation(),
        &id("act:isolate"),
        faults(|f| f.command_fails = true),
    )
    .unwrap();
    assert_eq!(r.outcome, Outcome::CommandFailed);
    assert_eq!(state(&r.branch, "act:isolate"), ActionState::Failed);
}

// ── Human interruption ─────────────────────────────────────────────────────

#[test]
fn humans_can_stop_pending_interventions() {
    let l = cancel(
        &approved_isolation(),
        &id("act:isolate"),
        "oncall",
        "false positive",
        None,
    )
    .unwrap();
    assert_eq!(state(&l, "act:isolate"), ActionState::Cancelled);
    assert!(matches!(
        run(&l, &id("act:isolate"), RunOptions::default()),
        Err(Refusal::NotRunnable { .. })
    ));
    // Once it has run it cannot be "cancelled" — only rolled back.
    let ran = run(
        &approved_isolation(),
        &id("act:isolate"),
        RunOptions::default(),
    )
    .unwrap()
    .branch;
    assert!(cancel(&ran, &id("act:isolate"), "oncall", "late", None).is_err());
    let undone = roll_back(&ran, &id("act:isolate"), "oncall", None).unwrap();
    assert_eq!(
        state(&undone.branch, "act:isolate"),
        ActionState::RolledBack
    );
}

// ── Revoke, block, rollback across one incident ────────────────────────────

#[test]
fn revoke_then_block_then_lift_the_revocation() {
    let l = approve(
        &log(TOKEN_LOG),
        &id("act:revoke"),
        human("ciso"),
        None,
        None,
    )
    .unwrap();
    let l = approve(&l, &id("act:block"), human("ciso"), None, None).unwrap();
    let r1 = run(&l, &id("act:revoke"), RunOptions::default()).unwrap();
    assert_eq!(r1.outcome, Outcome::Verified);
    let r2 = run(&r1.branch, &id("act:block"), RunOptions::default()).unwrap();
    assert_eq!(r2.outcome, Outcome::Verified);
    let r3 = roll_back(&r2.branch, &id("act:revoke"), "ciso", None).unwrap();
    let g = r3.branch.graph().unwrap();
    assert_eq!(
        g.actions[&id("act:revoke")].state(),
        ActionState::RolledBack
    );
    assert_eq!(g.actions[&id("act:block")].state(), ActionState::Verified);
    // The rollback cites observed restoration, not the command.
    let rb = g.actions[&id("act:revoke")]
        .history
        .iter()
        .find_map(|t| match t {
            ActionTransition::RollBack { evidence, .. } => Some(evidence.clone()),
            _ => None,
        });
    assert!(!rb.unwrap().direct_observations().is_empty());
    // Branch of a branch of a branch, each pointing at its parent.
    assert_eq!(
        r3.branch.branch.as_ref().unwrap().fork_of,
        r2.branch.digest()
    );
    // The sandbox, rebuilt from the final state, has only the block in force.
    let sb = navi_simulator::Sandbox::from_graph(&g);
    assert!(sb.is_active(&id("act:block")));
    assert!(!sb.is_active(&id("act:revoke")));
}

#[test]
fn irreversible_capabilities_cannot_be_rolled_back() {
    let mut v: serde_json::Value = serde_json::from_str(REPO_LOG).unwrap();
    for e in v["events"].as_array_mut().unwrap() {
        if e["event"]["type"] == "capability_granted"
            && e["event"]["capability"]["id"] == "cap:isolate"
        {
            e["event"]["capability"]["rollback_method"] =
                serde_json::json!({ "irreversible": { "justification": "test" } });
        }
    }
    let l: IncidentLog = serde_json::from_value(v).unwrap();
    let l = approve(&l, &id("act:isolate"), human("oncall"), None, None).unwrap();
    let ran = run(&l, &id("act:isolate"), RunOptions::default())
        .unwrap()
        .branch;
    assert!(matches!(
        roll_back(&ran, &id("act:isolate"), "oncall", None),
        Err(Refusal::Unsupported(_))
    ));
}

#[test]
fn runs_are_deterministic() {
    let a = run(
        &approved_isolation(),
        &id("act:isolate"),
        RunOptions::default(),
    )
    .unwrap();
    let b = run(
        &approved_isolation(),
        &id("act:isolate"),
        RunOptions::default(),
    )
    .unwrap();
    assert_eq!(a.branch, b.branch);
    assert_eq!(a.narrative, b.narrative);
}
