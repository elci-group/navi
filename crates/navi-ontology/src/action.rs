//! Directive §20 — the safety invariant:
//!
//! ```text
//! DETECT != DIAGNOSE != PROPOSE != AUTHORISE != EXECUTE != SUCCESS != VERIFIED
//! ```
//!
//! DETECT is an [`Observation`](crate::Observation), DIAGNOSE is a
//! [`Hypothesis`](crate::Hypothesis); an [`Action`] cannot exist without
//! one. From PROPOSE onward every step is a distinct, evidenced transition.
//! State is derived by replaying history, never stored.

use crate::{
    ActionId, AgentId, ApprovalId, CapabilityId, EntityId, HypothesisId, OntologyError, Provenance,
    SourceRef, Timestamp,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionState {
    Proposed,
    Authorised,
    Executing,
    /// The command returned. Says nothing about whether it worked.
    Executed,
    /// An observed state delta matches the expected effect.
    Succeeded,
    /// An independent verification confirmed the effect.
    Verified,
    Rejected,
    Cancelled,
    Failed,
    VerificationFailed,
    RolledBack,
}

impl ActionState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Verified | Self::Rejected | Self::Cancelled | Self::RolledBack
        )
    }

    /// Not yet touching reality: a human can still stop it (§26).
    pub fn is_pending(self) -> bool {
        matches!(self, Self::Proposed | Self::Authorised)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Principal {
    Human { name: String },
    Policy { rule: String },
    Agent(AgentId),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalKind {
    /// Granted by the authority policy itself (only valid for autonomous gates).
    Autonomous {
        policy_version: String,
    },
    Policy {
        rule: String,
    },
    Human {
        principal: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub id: ApprovalId,
    pub kind: ApprovalKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", deny_unknown_fields)]
pub enum ActionTransition {
    Authorise {
        at: Timestamp,
        approval: Approval,
    },
    Reject {
        at: Timestamp,
        by: Principal,
        reason: String,
    },
    Cancel {
        at: Timestamp,
        by: Principal,
        reason: String,
    },
    BeginExecution {
        at: Timestamp,
    },
    ExecutionReturned {
        at: Timestamp,
        receipt: String,
        ok: bool,
    },
    /// The effect was observed in reality. The evidence must point outside
    /// the action itself — a command's own success report is not an effect.
    ObserveEffect {
        at: Timestamp,
        effect: Provenance,
    },
    Verify {
        at: Timestamp,
        method: String,
        evidence: Provenance,
        passed: bool,
    },
    RollBack {
        at: Timestamp,
        evidence: Provenance,
    },
}

impl ActionTransition {
    pub fn at(&self) -> Timestamp {
        match self {
            Self::Authorise { at, .. }
            | Self::Reject { at, .. }
            | Self::Cancel { at, .. }
            | Self::BeginExecution { at }
            | Self::ExecutionReturned { at, .. }
            | Self::ObserveEffect { at, .. }
            | Self::Verify { at, .. }
            | Self::RollBack { at, .. } => *at,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Authorise { .. } => "authorise",
            Self::Reject { .. } => "reject",
            Self::Cancel { .. } => "cancel",
            Self::BeginExecution { .. } => "begin_execution",
            Self::ExecutionReturned { .. } => "execution_returned",
            Self::ObserveEffect { .. } => "observe_effect",
            Self::Verify { .. } => "verify",
            Self::RollBack { .. } => "roll_back",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub id: ActionId,
    pub agent: AgentId,
    pub capability: CapabilityId,
    pub target: EntityId,
    /// PROPOSE requires DIAGNOSE: no hypothesis, no action.
    pub hypothesis: HypothesisId,
    pub rationale: String,
    pub expected_effect: String,
    pub proposed_at: Timestamp,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<ActionTransition>,
}

impl Action {
    #[allow(clippy::too_many_arguments)] // one argument per required field
    pub fn propose(
        id: ActionId,
        agent: AgentId,
        capability: CapabilityId,
        target: EntityId,
        hypothesis: HypothesisId,
        rationale: impl Into<String>,
        expected_effect: impl Into<String>,
        proposed_at: Timestamp,
    ) -> Result<Self, OntologyError> {
        let a = Self {
            id,
            agent,
            capability,
            target,
            hypothesis,
            rationale: rationale.into(),
            expected_effect: expected_effect.into(),
            proposed_at,
            history: vec![],
        };
        a.check()?;
        Ok(a)
    }

    pub fn state(&self) -> ActionState {
        // `check` guarantees the replay is legal for any value that passed
        // validation; for unvalidated values we still return the best answer.
        let mut s = ActionState::Proposed;
        let mut effect = None;
        for t in &self.history {
            match Self::step(&self.id, s, effect.as_ref(), t) {
                Ok((next, e)) => {
                    s = next;
                    effect = e.or(effect);
                }
                Err(_) => break,
            }
        }
        s
    }

    pub fn apply(&mut self, t: ActionTransition) -> Result<ActionState, OntologyError> {
        self.history.push(t);
        match self.check() {
            Ok(()) => Ok(self.state()),
            Err(e) => {
                self.history.pop();
                Err(e)
            }
        }
    }

    pub fn check(&self) -> Result<(), OntologyError> {
        if self.rationale.trim().is_empty() {
            return Err(OntologyError::EmptyField {
                field: "action.rationale",
            });
        }
        if self.expected_effect.trim().is_empty() {
            return Err(OntologyError::EmptyField {
                field: "action.expected_effect",
            });
        }
        let mut s = ActionState::Proposed;
        let mut last = self.proposed_at;
        let mut effect: Option<Provenance> = None;
        for t in &self.history {
            if t.at() < last {
                return Err(OntologyError::IllegalActionTransition {
                    from: s,
                    via: t.name(),
                    reason: format!("{} precedes previous step at {last}", t.at()),
                });
            }
            let (next, e) = Self::step(&self.id, s, effect.as_ref(), t)?;
            s = next;
            effect = e.or(effect);
            last = t.at();
        }
        Ok(())
    }

    fn step(
        id: &ActionId,
        from: ActionState,
        effect: Option<&Provenance>,
        t: &ActionTransition,
    ) -> Result<(ActionState, Option<Provenance>), OntologyError> {
        use ActionState as S;
        use ActionTransition as T;
        let illegal = |reason: &str| OntologyError::IllegalActionTransition {
            from,
            via: t.name(),
            reason: reason.to_string(),
        };
        let next = match (from, t) {
            (S::Proposed, T::Authorise { approval, at }) => {
                if approval.expires_at.is_some_and(|e| e <= *at) {
                    return Err(illegal("approval already expired"));
                }
                S::Authorised
            }
            (S::Proposed, T::Reject { reason, .. }) => {
                if reason.trim().is_empty() {
                    return Err(illegal("rejection needs a reason"));
                }
                S::Rejected
            }
            (S::Proposed | S::Authorised, T::Cancel { reason, .. }) => {
                if reason.trim().is_empty() {
                    return Err(illegal("cancellation needs a reason"));
                }
                S::Cancelled
            }
            (S::Authorised, T::BeginExecution { .. }) => S::Executing,
            (S::Executing, T::ExecutionReturned { ok, receipt, .. }) => {
                if receipt.trim().is_empty() {
                    return Err(illegal("execution needs a receipt"));
                }
                if *ok {
                    S::Executed
                } else {
                    S::Failed
                }
            }
            (S::Executed, T::ObserveEffect { effect, .. }) => {
                let only_self = effect
                    .sources()
                    .iter()
                    .all(|s| matches!(s, SourceRef::Action(a) if a == id));
                if only_self {
                    return Err(illegal(
                        "success cannot rest solely on the action's own report",
                    ));
                }
                return Ok((S::Succeeded, Some(effect.clone())));
            }
            (
                S::Succeeded,
                T::Verify {
                    method,
                    evidence,
                    passed,
                    ..
                },
            ) => {
                if method.trim().is_empty() {
                    return Err(illegal("verification needs a method"));
                }
                if let Some(e) = effect {
                    if !e.adds_to(evidence) {
                        return Err(illegal(
                            "verification must be independent of the success evidence",
                        ));
                    }
                }
                if *passed {
                    S::Verified
                } else {
                    S::VerificationFailed
                }
            }
            (
                S::Executed | S::Succeeded | S::Failed | S::VerificationFailed,
                T::RollBack { .. },
            ) => S::RolledBack,
            (S::Executing, T::Cancel { .. }) => {
                return Err(illegal(
                    "execution already started; stop it with a rollback, not a cancel",
                ))
            }
            _ => return Err(illegal("transition not permitted from this state")),
        };
        Ok((next, None))
    }

    /// State as of instant `t`, or `None` before the proposal existed.
    pub fn state_at(&self, t: Timestamp) -> Option<ActionState> {
        if t < self.proposed_at {
            return None;
        }
        let upto = Action {
            history: self
                .history
                .iter()
                .take_while(|x| x.at() <= t)
                .cloned()
                .collect(),
            ..self.clone()
        };
        Some(upto.state())
    }

    pub fn approval(&self) -> Option<&Approval> {
        self.history.iter().find_map(|t| match t {
            ActionTransition::Authorise { approval, .. } => Some(approval),
            _ => None,
        })
    }

    pub fn executed_at(&self) -> Option<Timestamp> {
        self.history.iter().find_map(|t| match t {
            ActionTransition::ExecutionReturned { at, .. } => Some(*at),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ObservationId;
    use ActionTransition as T;

    fn action() -> Action {
        Action::propose(
            ActionId::new("act:1").unwrap(),
            AgentId::new("agent:navi-01").unwrap(),
            CapabilityId::new("cap:lock").unwrap(),
            EntityId::new("ent:token").unwrap(),
            HypothesisId::new("hyp:1").unwrap(),
            "token used from 312 novel identities",
            "token rejected on next use",
            Timestamp(0),
        )
        .unwrap()
    }
    fn obs(n: &str) -> Provenance {
        Provenance::single(SourceRef::Observation(
            ObservationId::new(format!("obs:{n}")).unwrap(),
        ))
        .unwrap()
    }
    fn approve(at: i64) -> T {
        T::Authorise {
            at: Timestamp(at),
            approval: Approval {
                id: ApprovalId::new("appr:1").unwrap(),
                kind: ApprovalKind::Human {
                    principal: "oncall".into(),
                },
                expires_at: None,
            },
        }
    }
    fn run_to_executed(a: &mut Action) {
        a.apply(approve(1)).unwrap();
        a.apply(T::BeginExecution { at: Timestamp(2) }).unwrap();
        a.apply(T::ExecutionReturned {
            at: Timestamp(3),
            receipt: "200 OK".into(),
            ok: true,
        })
        .unwrap();
    }

    #[test]
    fn full_lifecycle() {
        let mut a = action();
        run_to_executed(&mut a);
        assert_eq!(a.state(), ActionState::Executed);
        a.apply(T::ObserveEffect {
            at: Timestamp(4),
            effect: obs("denied"),
        })
        .unwrap();
        assert_eq!(a.state(), ActionState::Succeeded);
        a.apply(T::Verify {
            at: Timestamp(5),
            method: "replay auth".into(),
            evidence: obs("replay"),
            passed: true,
        })
        .unwrap();
        assert_eq!(a.state(), ActionState::Verified);
    }

    #[test]
    fn state_at_replays_history() {
        let mut a = action();
        run_to_executed(&mut a);
        assert_eq!(a.state_at(Timestamp(-1)), None);
        assert_eq!(a.state_at(Timestamp(0)), Some(ActionState::Proposed));
        assert_eq!(a.state_at(Timestamp(2)), Some(ActionState::Executing));
        assert_eq!(a.state_at(Timestamp(99)), Some(ActionState::Executed));
    }

    #[test]
    fn execute_is_not_success() {
        let mut a = action();
        run_to_executed(&mut a);
        // jumping straight to verify is illegal
        let r = a.apply(T::Verify {
            at: Timestamp(4),
            method: "m".into(),
            evidence: obs("x"),
            passed: true,
        });
        assert!(r.is_err());
        assert_eq!(a.state(), ActionState::Executed);
    }

    #[test]
    fn self_report_is_not_an_effect() {
        let mut a = action();
        run_to_executed(&mut a);
        let me = Provenance::single(SourceRef::Action(a.id.clone())).unwrap();
        assert!(a
            .apply(T::ObserveEffect {
                at: Timestamp(4),
                effect: me
            })
            .is_err());
    }

    #[test]
    fn verification_must_be_independent() {
        let mut a = action();
        run_to_executed(&mut a);
        a.apply(T::ObserveEffect {
            at: Timestamp(4),
            effect: obs("denied"),
        })
        .unwrap();
        let r = a.apply(T::Verify {
            at: Timestamp(5),
            method: "m".into(),
            evidence: obs("denied"),
            passed: true,
        });
        assert!(r.is_err());
    }

    #[test]
    fn cannot_execute_unauthorised() {
        let mut a = action();
        assert!(a.apply(T::BeginExecution { at: Timestamp(1) }).is_err());
    }

    #[test]
    fn human_can_interrupt_pending() {
        let mut a = action();
        a.apply(approve(1)).unwrap();
        a.apply(T::Cancel {
            at: Timestamp(2),
            by: Principal::Human {
                name: "oncall".into(),
            },
            reason: "false positive".into(),
        })
        .unwrap();
        assert_eq!(a.state(), ActionState::Cancelled);
        assert!(a.apply(T::BeginExecution { at: Timestamp(3) }).is_err());
    }

    #[test]
    fn failed_command_is_failed() {
        let mut a = action();
        a.apply(approve(1)).unwrap();
        a.apply(T::BeginExecution { at: Timestamp(2) }).unwrap();
        a.apply(T::ExecutionReturned {
            at: Timestamp(3),
            receipt: "500".into(),
            ok: false,
        })
        .unwrap();
        assert_eq!(a.state(), ActionState::Failed);
        assert!(a
            .apply(T::ObserveEffect {
                at: Timestamp(4),
                effect: obs("x")
            })
            .is_err());
    }

    #[test]
    fn expired_approval_is_rejected() {
        let mut a = action();
        let r = a.apply(T::Authorise {
            at: Timestamp(10),
            approval: Approval {
                id: ApprovalId::new("appr:1").unwrap(),
                kind: ApprovalKind::Human {
                    principal: "oncall".into(),
                },
                expires_at: Some(Timestamp(5)),
            },
        });
        assert!(r.is_err());
    }
}
