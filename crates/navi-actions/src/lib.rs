//! The intervention executor (directive §25 Phase 4, §10, §20).
//!
//! * [`approve`] and [`cancel`] record real operator decisions in the log
//!   they are given, after checking the approval against the effective gate.
//! * [`run`] and [`roll_back`] act **only on the sandbox** and return a
//!   counterfactual *branch* of the incident (§2: reality ≠ realm — a
//!   sandbox run must never read as if production changed). The branch is
//!   built with the Phase 3 fork machinery, so it is validated by every
//!   rule reality is.
//!
//! The lifecycle cannot be shortcut: nothing runs without authorisation; a
//! command returning OK yields `EXECUTED`, not success; `SUCCEEDED` needs
//! sandbox telemetry showing the change; `VERIFIED` needs a separate probe
//! using the capability's declared verification method.

use navi_events::{fork, Event, ForkEvent, ForkSpec, IncidentLog, LogViolation};
use navi_graph::SemanticGraph;
use navi_ontology::*;
use navi_simulator::{describe, Actuator, Faults, Intervention, Reading, Sandbox};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    #[error("{0}")]
    NotFound(String),
    #[error("{action} is {state:?}: {why}")]
    NotRunnable {
        action: ActionId,
        state: ActionState,
        why: String,
    },
    #[error("approval refused: {0}")]
    Gate(String),
    #[error("expired: {0}")]
    Expired(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("agent loop: {0}")]
    Loop(String),
    #[error("the result would not be a valid incident: {}", .0.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("; "))]
    Invalid(Vec<LogViolation>),
}

impl From<Vec<LogViolation>> for Refusal {
    fn from(v: Vec<LogViolation>) -> Self {
        Refusal::Invalid(v)
    }
}

pub enum Approver {
    Human(String),
    Policy(String),
}

fn graph(log: &IncidentLog) -> Result<SemanticGraph, Refusal> {
    log.graph().map_err(|e| Refusal::Invalid(vec![e]))
}

fn find<'g>(
    g: &'g SemanticGraph,
    action: &ActionId,
) -> Result<(&'g Action, &'g Capability), Refusal> {
    let a = g
        .actions
        .get(action)
        .ok_or_else(|| Refusal::NotFound(format!("no action {action} in this incident")))?;
    let c = g
        .capabilities
        .get(&a.capability)
        .ok_or_else(|| Refusal::NotFound(format!("no capability {}", a.capability)))?;
    Ok((a, c))
}

fn now(log: &IncidentLog, at: Option<Timestamp>) -> Timestamp {
    at.unwrap_or_else(|| Timestamp(log.end().map_or(0, |t| t.0 + 100)))
}

/// Record an approval. Refuses one weaker than the effective gate.
pub fn approve(
    log: &IncidentLog,
    action: &ActionId,
    by: Approver,
    at: Option<Timestamp>,
    expires_at: Option<Timestamp>,
) -> Result<IncidentLog, Refusal> {
    let g = graph(log)?;
    let (a, cap) = find(&g, action)?;
    let state = a.state();
    if state != ActionState::Proposed {
        return Err(Refusal::NotRunnable {
            action: a.id.clone(),
            state,
            why: "only a proposed action can be approved".into(),
        });
    }
    let t = now(log, at);
    if cap.expired_at(t) {
        return Err(Refusal::Expired(format!("{} expired before {t}", cap.id)));
    }
    let gate = g.effective_gate(cap);
    let kind = match by {
        Approver::Human(principal) if !principal.trim().is_empty() => {
            ApprovalKind::Human { principal }
        }
        Approver::Policy(rule) if gate == Gate::HumanApproval => {
            return Err(Refusal::Gate(format!(
                "{} requires a human; policy {rule:?} cannot approve it",
                cap.id
            )))
        }
        Approver::Policy(rule) if !rule.trim().is_empty() => ApprovalKind::Policy { rule },
        _ => {
            return Err(Refusal::Gate(
                "an approval needs a named principal or rule".into(),
            ))
        }
    };
    let n = a.history.len() + 1;
    let approval = Approval {
        id: ApprovalId::new(format!(
            "appr:{}-{n}",
            a.id.as_str().trim_start_matches("act:")
        ))
        .expect("valid id"),
        kind,
        expires_at,
        not_before: None,
    };
    Ok(log.append(vec![(
        t,
        Event::ActionTransitioned {
            action: a.id.clone(),
            transition: ActionTransition::Authorise { at: t, approval },
        },
    )])?)
}

/// Stop a pending intervention (§26 human interruption).
pub fn cancel(
    log: &IncidentLog,
    action: &ActionId,
    by: &str,
    reason: &str,
    at: Option<Timestamp>,
) -> Result<IncidentLog, Refusal> {
    let g = graph(log)?;
    let (a, _) = find(&g, action)?;
    let state = a.state();
    if !state.is_pending() {
        return Err(Refusal::NotRunnable {
            action: a.id.clone(),
            state,
            why: "only a pending (proposed or authorised) action can be cancelled; once it has run, roll it back".into(),
        });
    }
    let t = now(log, at);
    Ok(log.append(vec![(
        t,
        Event::ActionTransitioned {
            action: a.id.clone(),
            transition: ActionTransition::Cancel {
                at: t,
                by: Principal::Human { name: by.into() },
                reason: reason.into(),
            },
        },
    )])?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Effect observed and independently verified.
    Verified,
    /// Effect observed, but verification failed.
    VerificationFailed {
        rolled_back: bool,
    },
    /// The command returned OK, but the sandbox shows no change.
    EffectNotObserved {
        rolled_back: bool,
    },
    CommandFailed,
    RolledBack,
}

#[derive(Debug)]
pub struct Run {
    /// The resulting log: a counterfactual branch for a sandbox actuator,
    /// the incident itself (appended) for a production one.
    pub branch: IncidentLog,
    /// True if the result was written to reality.
    pub in_reality: bool,
    pub outcome: Outcome,
    /// What happened, step by step.
    pub narrative: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RunOptions {
    pub at: Option<Timestamp>,
    pub faults: Faults,
    /// Undo the intervention if its effect is not observed or verification
    /// fails (doctrine V: prefer recoverable outcomes).
    pub rollback_on_failure: bool,
}

/// Builds the hypothetical event list for a sandbox branch.
struct Script<'g> {
    g: &'g SemanticGraph,
    events: Vec<ForkEvent>,
    narrative: Vec<String>,
    next_obs: usize,
    stem: String,
    agent: AgentId,
    next_seq: u64,
}

impl Script<'_> {
    fn push(&mut self, at: Timestamp, event: Event, line: String) {
        self.events.push(ForkEvent { at, event });
        self.narrative.push(format!("{at}  {line}"));
    }

    fn observe(&mut self, r: Reading, at: Timestamp) -> SourceRef {
        let id = loop {
            self.next_obs += 1;
            let candidate = ObservationId::new(format!("obs:sbx-{}-{}", self.stem, self.next_obs))
                .expect("valid id");
            if !self.g.observations.contains_key(&candidate) {
                break candidate;
            }
        };
        let summary = format!(
            "sandbox observes {} {}",
            r.kind,
            serde_json::to_string(&r.attributes).unwrap_or_default()
        );
        self.push(
            at,
            Event::ObservationRecorded {
                observation: r.into_observation(id.clone(), at),
            },
            summary,
        );
        SourceRef::Observation(id)
    }

    fn agent_event(
        &mut self,
        at: Timestamp,
        a: &Action,
        phase: AgentPhase,
        authority: AuthorityLevel,
        reason: String,
        next: Option<(AgentPhase, &str)>,
    ) {
        let event = AgentEvent {
            agent: self.agent.clone(),
            seq: self.next_seq,
            at,
            phase,
            target: Some(a.target.clone()),
            reason: reason.clone(),
            hypothesis: Some(a.hypothesis.clone()),
            confidence: None,
            authority,
            action: Some(a.id.clone()),
            objective: None,
            next: next.map(|(p, intent)| NextStep {
                phase: p,
                target: Some(a.target.clone()),
                intent: intent.into(),
            }),
        };
        self.next_seq += 1;
        let w = serde_json::to_value(phase)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        self.push(
            at,
            Event::AgentEventEmitted { event },
            format!("{} {w}: {reason}", self.agent),
        );
    }

    fn transition(&mut self, a: &Action, t: ActionTransition, line: &str) {
        let at = t.at();
        self.push(
            at,
            Event::ActionTransitioned {
                action: a.id.clone(),
                transition: t,
            },
            format!("{} {line}", a.id),
        );
    }
}

fn last_agent_event<'g>(g: &'g SemanticGraph, agent: &AgentId) -> Option<&'g AgentEvent> {
    g.agent_events
        .iter()
        .rev()
        .find(|((id, _), _)| id == agent)
        .map(|(_, e)| e)
}

fn script<'g>(g: &'g SemanticGraph, a: &Action) -> Result<Script<'g>, Refusal> {
    let last = last_agent_event(g, &a.agent)
        .ok_or_else(|| Refusal::Loop(format!("{} has emitted no events", a.agent)))?;
    Ok(Script {
        g,
        events: vec![],
        narrative: vec![],
        next_obs: 0,
        stem: a.id.as_str().trim_start_matches("act:").to_string(),
        agent: a.agent.clone(),
        next_seq: last.seq + 1,
    })
}

fn branch(
    log: &IncidentLog,
    label: String,
    s: Script,
    sandbox: bool,
) -> Result<(IncidentLog, Vec<String>), Refusal> {
    if !sandbox {
        // A production actuator changed reality: record it in the incident.
        let events = s.events.into_iter().map(|e| (e.at, e.event)).collect();
        return Ok((log.append(events)?, s.narrative));
    }
    let spec = ForkSpec {
        label,
        at: log.end().unwrap_or(Timestamp(0)),
        events: s.events,
    };
    Ok((fork(log, &spec)?, s.narrative))
}

fn roll_back_steps(
    s: &mut Script,
    sandbox: &mut dyn Actuator,
    a: &Action,
    iv: &Intervention,
    at: Timestamp,
) -> Result<(), Refusal> {
    let receipt = sandbox.roll_back(&a.id).map_err(Refusal::Unsupported)?;
    s.narrative.push(format!("{at}  {receipt}"));
    let mut evidence = vec![s.observe(sandbox.control_reading(&a.id, iv), at)];
    let restored = sandbox.restored_readings(iv);
    let all_back = restored.iter().all(|(_, ok)| *ok);
    for (r, _) in restored {
        evidence.push(s.observe(r, at));
    }
    if !all_back {
        return Err(Refusal::Unsupported(
            "the actuator does not show the prior state restored; rollback not recorded".into(),
        ));
    }
    let t = Timestamp(at.0 + 100);
    s.transition(
        a,
        ActionTransition::RollBack {
            at: t,
            evidence: Provenance::new(evidence).expect("non-empty"),
        },
        "rolled back (restoration observed)",
    );
    Ok(())
}

/// Execute an authorised action in the sandbox, as a branch of `log`.
pub fn run(log: &IncidentLog, action: &ActionId, opts: RunOptions) -> Result<Run, Refusal> {
    let g = graph(log)?;
    let mut sandbox = Sandbox::from_graph(&g).with_faults(opts.faults);
    run_on(log, action, opts, &mut sandbox)
}

/// Execute an authorised action through any actuator. A sandbox writes a
/// counterfactual branch; anything else writes to the incident itself.
pub fn run_on(
    log: &IncidentLog,
    action: &ActionId,
    opts: RunOptions,
    sandbox: &mut dyn Actuator,
) -> Result<Run, Refusal> {
    let g = graph(log)?;
    let (a, cap) = find(&g, action)?;
    let state = a.state();
    let gate = g.effective_gate(cap);
    match state {
        ActionState::Authorised => {}
        ActionState::Proposed => {
            return Err(Refusal::NotRunnable {
                action: a.id.clone(),
                state,
                why: format!("awaiting authorisation ({gate:?})"),
            })
        }
        _ => {
            return Err(Refusal::NotRunnable {
                action: a.id.clone(),
                state,
                why: "only an authorised action can run".into(),
            })
        }
    }
    let t0 = now(log, opts.at);
    if cap.expired_at(t0) {
        return Err(Refusal::Expired(format!("{} expired before {t0}", cap.id)));
    }
    if let Some(e) = a
        .approval()
        .and_then(|ap| ap.expires_at)
        .filter(|e| *e <= t0)
    {
        return Err(Refusal::Expired(format!(
            "the approval for {} lapsed at {e}",
            a.id
        )));
    }
    if let Some(nb) = a
        .approval()
        .and_then(|ap| ap.not_before)
        .filter(|nb| t0 < *nb)
    {
        return Err(Refusal::NotRunnable {
            action: a.id.clone(),
            state,
            why: format!("inside the human interruption window: it may not run before {nb}"),
        });
    }
    let iv = Intervention::for_action(&g, a).map_err(Refusal::Unsupported)?;
    let in_sandbox = sandbox.is_sandbox();
    let via = sandbox.name();
    let mut s = script(&g, a)?;

    // Navi must legally reach ACT for *this* action.
    let last = last_agent_event(&g, &a.agent).expect("checked in script");
    let mut t = t0;
    let at_authorise = last.phase == AgentPhase::Authorise && last.action.as_ref() == Some(&a.id);
    if !at_authorise {
        // Reach ACT for *this* action only along legal edges.
        let via_plan = last.phase != AgentPhase::Plan;
        if via_plan && !last.phase.can_transition_to(AgentPhase::Plan) {
            return Err(Refusal::Loop(format!(
                "{} is at {:?} (event #{}); it cannot legally return to PLAN and ACT on {} from there",
                a.agent, last.phase, last.seq, a.id
            )));
        }
        if via_plan {
            s.agent_event(
                t,
                a,
                AgentPhase::Plan,
                AuthorityLevel::Propose,
                format!("resume {}: authorisation is on record", a.id),
                Some((AgentPhase::Authorise, "confirm the approval")),
            );
            t = Timestamp(t.0 + 100);
        }
        s.agent_event(
            t,
            a,
            AgentPhase::Authorise,
            AuthorityLevel::Propose,
            "approval on record".into(),
            Some((AgentPhase::Act, "execute")),
        );
        t = Timestamp(t.0 + 100);
    }

    let what = describe(&iv);
    s.transition(
        a,
        ActionTransition::BeginExecution { at: t },
        &format!("execution begins via {via}: {what}"),
    );
    s.agent_event(
        t,
        a,
        AgentPhase::Act,
        cap.authority,
        format!("execute {what} via {via}"),
        Some((AgentPhase::Verify, "check the effect independently")),
    );
    let tb = t;
    let at = |dt: i64| Timestamp(tb.0 + dt);

    let returned = sandbox.execute(&a.id, &iv);
    let (ok, receipt) = match &returned {
        Ok(r) => (true, r.clone()),
        Err(e) => (false, e.clone()),
    };
    s.transition(
        a,
        ActionTransition::ExecutionReturned {
            at: at(200),
            receipt: receipt.clone(),
            ok,
        },
        &format!(
            "command returned {}: {receipt}",
            if ok { "OK" } else { "FAILURE" }
        ),
    );
    if !ok {
        s.agent_event(
            at(300),
            a,
            AgentPhase::Verify,
            AuthorityLevel::Query,
            "command failed; nothing took effect".into(),
            Some((AgentPhase::Learn, "record the failure")),
        );
        let (b, narrative) = branch(
            log,
            format!("sandbox: {what} ({}) — command failed", a.id),
            s,
            in_sandbox,
        )?;
        return Ok(Run {
            branch: b,
            in_reality: !in_sandbox,
            outcome: Outcome::CommandFailed,
            narrative,
        });
    }

    // EXECUTE != SUCCESS: look at the sandbox.
    let control = s.observe(sandbox.control_reading(&a.id, &iv), at(700));
    let mut effect = vec![control];
    let readings = sandbox.effect_readings(&iv);
    let took =
        sandbox.is_active(&a.id) && !readings.is_empty() && readings.iter().all(|(_, ok)| *ok);
    for (r, _) in readings {
        effect.push(s.observe(r, at(1500)));
    }
    if !took {
        s.agent_event(
            at(1600),
            a,
            AgentPhase::Verify,
            AuthorityLevel::Query,
            "command returned OK but the sandbox shows no change".into(),
            Some((
                AgentPhase::Learn,
                "record that the intervention did not take",
            )),
        );
        let mut rolled_back = false;
        if opts.rollback_on_failure {
            roll_back_steps(&mut s, sandbox, a, &iv, at(1700))?;
            rolled_back = true;
        }
        let (b, narrative) = branch(
            log,
            format!("sandbox: {what} ({}) — effect not observed", a.id),
            s,
            in_sandbox,
        )?;
        return Ok(Run {
            branch: b,
            in_reality: !in_sandbox,
            outcome: Outcome::EffectNotObserved { rolled_back },
            narrative,
        });
    }
    s.transition(
        a,
        ActionTransition::ObserveEffect {
            at: at(1600),
            effect: Provenance::new(effect).expect("non-empty"),
        },
        "effect observed in sandbox telemetry",
    );

    // SUCCESS != VERIFIED: an independent probe by the declared method.
    s.agent_event(
        at(2400),
        a,
        AgentPhase::Verify,
        AuthorityLevel::Query,
        format!("verify: {}", cap.verification_method),
        Some((AgentPhase::Learn, "record the verified outcome")),
    );
    let (probe, passed) = sandbox.verification_probe(&a.id, &iv, &cap.verification_method);
    let evidence = s.observe(probe, at(2500));
    s.transition(
        a,
        ActionTransition::Verify {
            at: at(2600),
            method: cap.verification_method.clone(),
            evidence: Provenance::single(evidence).expect("non-empty"),
            passed,
        },
        if passed {
            "verified"
        } else {
            "verification FAILED"
        },
    );
    let outcome = if passed {
        Outcome::Verified
    } else if opts.rollback_on_failure {
        roll_back_steps(&mut s, sandbox, a, &iv, at(2700))?;
        Outcome::VerificationFailed { rolled_back: true }
    } else {
        Outcome::VerificationFailed { rolled_back: false }
    };
    let tag = match outcome {
        Outcome::Verified => "verified",
        _ => "verification failed",
    };
    let (b, narrative) = branch(
        log,
        format!("sandbox: {what} ({}) — {tag}", a.id),
        s,
        in_sandbox,
    )?;
    Ok(Run {
        branch: b,
        in_reality: !in_sandbox,
        outcome,
        narrative,
    })
}

/// Undo an executed intervention in the sandbox, as a branch of `log`.
pub fn roll_back(
    log: &IncidentLog,
    action: &ActionId,
    by: &str,
    at: Option<Timestamp>,
) -> Result<Run, Refusal> {
    let g = graph(log)?;
    let mut sandbox = Sandbox::from_graph(&g);
    roll_back_on(log, action, by, at, &mut sandbox)
}

/// Undo an executed intervention through any actuator.
pub fn roll_back_on(
    log: &IncidentLog,
    action: &ActionId,
    by: &str,
    at: Option<Timestamp>,
    sandbox: &mut dyn Actuator,
) -> Result<Run, Refusal> {
    let g = graph(log)?;
    let (a, cap) = find(&g, action)?;
    let state = a.state();
    if !matches!(
        state,
        ActionState::Executed
            | ActionState::Succeeded
            | ActionState::Verified
            | ActionState::Failed
            | ActionState::VerificationFailed
    ) {
        return Err(Refusal::NotRunnable {
            action: a.id.clone(),
            state,
            why: "only an executed action can be rolled back".into(),
        });
    }
    if let Rollback::Irreversible { justification } = &cap.rollback_method {
        return Err(Refusal::Unsupported(format!(
            "{} is declared irreversible: {justification}",
            cap.id
        )));
    }
    if by.trim().is_empty() {
        return Err(Refusal::Gate("a rollback needs a named principal".into()));
    }
    let iv = Intervention::for_action(&g, a).map_err(Refusal::Unsupported)?;
    let in_sandbox = sandbox.is_sandbox();
    let mut s = script(&g, a)?;
    roll_back_steps(&mut s, sandbox, a, &iv, now(log, at))?;
    let (b, narrative) = branch(
        log,
        format!("sandbox: roll back {} (by {by})", a.id),
        s,
        in_sandbox,
    )?;
    Ok(Run {
        branch: b,
        in_reality: !in_sandbox,
        outcome: Outcome::RolledBack,
        narrative,
    })
}

/// Navi self-authorises a proposed action under an autonomy grant
/// (directive §10, §25 Phase 6). Recorded in the incident itself — it is a
/// real decision — with a human interruption window before execution may
/// begin and an expiry bounded by the grant and the capability.
pub fn auto_approve(
    log: &IncidentLog,
    action: &ActionId,
    at: Option<Timestamp>,
) -> Result<IncidentLog, Refusal> {
    let g = graph(log)?;
    let (a, cap) = find(&g, action)?;
    let state = a.state();
    if state != ActionState::Proposed {
        return Err(Refusal::NotRunnable {
            action: a.id.clone(),
            state,
            why: "only a proposed action can be authorised".into(),
        });
    }
    let gate = g.effective_gate(cap);
    if gate == Gate::HumanApproval {
        return Err(Refusal::Gate(format!(
            "{} requires a human; no grant can make it autonomous",
            cap.id
        )));
    }
    let grant = g.authority_policy.grant_for(&cap.id).ok_or_else(|| {
        Refusal::Gate(format!(
            "no autonomy grant for {}; a human or policy must approve",
            cap.id
        ))
    })?;
    grant.check(cap).map_err(Refusal::Gate)?;
    let t = now(log, at);
    if cap.expired_at(t) {
        return Err(Refusal::Expired(format!("{} expired before {t}", cap.id)));
    }
    let cap_end = match cap.expiry {
        Expiry::At(e) => e,
        Expiry::Never => unreachable!("grant.check requires an expiry"),
    };
    let not_before = Timestamp(t.0 + grant.grace_ms);
    let expires = Timestamp((t.0 + grant.max_duration_ms).min(cap_end.0));
    if expires <= not_before {
        return Err(Refusal::Expired(format!(
            "{} would expire before its interruption window ends",
            cap.id
        )));
    }

    let mut s = script(&g, a)?;
    let last = last_agent_event(&g, &a.agent).expect("checked in script");
    if last.phase != AgentPhase::Plan {
        if !last.phase.can_transition_to(AgentPhase::Plan) {
            return Err(Refusal::Loop(format!(
                "{} is at {:?} (event #{}); it cannot legally return to PLAN for {}",
                a.agent, last.phase, last.seq, a.id
            )));
        }
        s.agent_event(
            t,
            a,
            AgentPhase::Plan,
            AuthorityLevel::Propose,
            format!("resume {}", a.id),
            Some((
                AgentPhase::Authorise,
                "self-authorise under the autonomy grant",
            )),
        );
    }
    let n = a.history.len() + 1;
    let approval = Approval {
        id: ApprovalId::new(format!(
            "appr:{}-auto-{n}",
            a.id.as_str().trim_start_matches("act:")
        ))
        .expect("valid id"),
        kind: ApprovalKind::Autonomous {
            policy_version: g.authority_policy.version.clone(),
            certificate: Some(grant.certificate.clone()),
        },
        expires_at: Some(expires),
        not_before: Some(not_before),
    };
    s.transition(
        a,
        ActionTransition::Authorise { at: t, approval },
        "self-authorised under the autonomy grant",
    );
    s.agent_event(
        t,
        a,
        AgentPhase::Authorise,
        AuthorityLevel::Propose,
        format!("self-authorised under grant by {}; humans may cancel until {not_before}; expires {expires}", grant.granted_by),
        Some((AgentPhase::Act, "execute after the interruption window")),
    );
    Ok(log.append(s.events.into_iter().map(|e| (e.at, e.event)).collect())?)
}

/// Roll back every executed intervention whose approval has lapsed by `at`
/// (doctrine V: bounded, expiring, recoverable). `Ok(None)` if nothing is due.
pub fn expire(log: &IncidentLog, at: Option<Timestamp>) -> Result<Option<Run>, Refusal> {
    let g = graph(log)?;
    let mut sandbox = Sandbox::from_graph(&g);
    expire_on(log, at, &mut sandbox)
}

pub fn expire_on(
    log: &IncidentLog,
    at: Option<Timestamp>,
    sandbox: &mut dyn Actuator,
) -> Result<Option<Run>, Refusal> {
    let g = graph(log)?;
    let t = now(log, at);
    let due: Vec<&Action> = g
        .actions
        .values()
        .filter(|a| {
            matches!(
                a.state(),
                ActionState::Executed
                    | ActionState::Succeeded
                    | ActionState::Verified
                    | ActionState::VerificationFailed
            ) && a
                .approval()
                .and_then(|ap| ap.expires_at)
                .is_some_and(|e| e <= t)
        })
        .collect();
    let Some(first) = due.first() else {
        return Ok(None);
    };
    let in_sandbox = sandbox.is_sandbox();
    let mut s = script(&g, first)?;
    let mut clock = t;
    let mut ids = vec![];
    for a in &due {
        let iv = Intervention::for_action(&g, a).map_err(Refusal::Unsupported)?;
        s.narrative.push(format!(
            "{clock}  {} approval lapsed; lifting {}",
            a.id,
            describe(&iv)
        ));
        roll_back_steps(&mut s, sandbox, a, &iv, clock)?;
        ids.push(a.id.to_string());
        clock = Timestamp(clock.0 + 200);
    }
    let (b, narrative) = branch(
        log,
        format!("sandbox: expired containment lifted ({})", ids.join(", ")),
        s,
        in_sandbox,
    )?;
    Ok(Some(Run {
        branch: b,
        in_reality: !in_sandbox,
        outcome: Outcome::RolledBack,
        narrative,
    }))
}
