use crate::{
    AttackRef, Confidence, EntityId, EpistemicPolicy, EpistemicState, HypothesisId, OntologyError,
    Provenance, Timestamp,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpistemicTransition {
    pub at: Timestamp,
    pub from: EpistemicState,
    pub to: EpistemicState,
    pub confidence: Confidence,
    /// Evidence that justified this step. On promotion it must contribute
    /// something the hypothesis did not already hold.
    pub evidence: Provenance,
    pub reason: String,
}

/// An inference about the estate. Distinct from an observation (§6):
/// observations are what telemetry said; hypotheses are what Navi believes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hypothesis {
    pub id: HypothesisId,
    pub subjects: Vec<EntityId>,
    /// Short machine-ish label, e.g. `credential_stuffing`.
    pub claim: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attack: Vec<AttackRef>,
    pub opened_at: Timestamp,
    pub opened_as: EpistemicState,
    pub initial_confidence: Confidence,
    pub initial_evidence: Provenance,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transitions: Vec<EpistemicTransition>,
}

impl Hypothesis {
    #[allow(clippy::too_many_arguments)] // one argument per required field
    pub fn open(
        id: HypothesisId,
        subjects: Vec<EntityId>,
        claim: impl Into<String>,
        opened_at: Timestamp,
        opened_as: EpistemicState,
        confidence: Confidence,
        evidence: Provenance,
        policy: &EpistemicPolicy,
    ) -> Result<Self, OntologyError> {
        let h = Self {
            id,
            subjects,
            claim: claim.into(),
            attack: vec![],
            opened_at,
            opened_as,
            initial_confidence: confidence,
            initial_evidence: evidence,
            transitions: vec![],
        };
        h.check(policy)?;
        Ok(h)
    }

    /// Current state, derived by replaying transitions — never stored
    /// separately, so it cannot drift from its history.
    pub fn state(&self) -> EpistemicState {
        self.transitions.last().map_or(self.opened_as, |t| t.to)
    }

    /// State as of instant `t`, or `None` if the hypothesis did not yet
    /// exist. Lets a replayed event show what was believed *then*.
    pub fn state_at(&self, t: Timestamp) -> Option<EpistemicState> {
        (t >= self.opened_at).then(|| {
            self.transitions
                .iter()
                .take_while(|x| x.at <= t)
                .last()
                .map_or(self.opened_as, |x| x.to)
        })
    }

    pub fn confidence_at(&self, t: Timestamp) -> Option<&Confidence> {
        (t >= self.opened_at).then(|| {
            self.transitions
                .iter()
                .take_while(|x| x.at <= t)
                .last()
                .map_or(&self.initial_confidence, |x| &x.confidence)
        })
    }

    /// Evidence held as of instant `t` (empty before the hypothesis existed).
    pub fn evidence_at(&self, t: Timestamp) -> Option<Provenance> {
        (t >= self.opened_at).then(|| {
            self.transitions
                .iter()
                .take_while(|x| x.at <= t)
                .fold(self.initial_evidence.clone(), |acc, x| {
                    acc.union(&x.evidence)
                })
        })
    }

    pub fn confidence(&self) -> &Confidence {
        self.transitions
            .last()
            .map_or(&self.initial_confidence, |t| &t.confidence)
    }

    /// All evidence accumulated so far.
    pub fn evidence(&self) -> Provenance {
        self.transitions
            .iter()
            .fold(self.initial_evidence.clone(), |acc, t| {
                acc.union(&t.evidence)
            })
    }

    pub fn transition(
        &mut self,
        t: EpistemicTransition,
        policy: &EpistemicPolicy,
    ) -> Result<(), OntologyError> {
        Self::check_step(self.state(), &self.evidence(), self.last_at(), &t, policy)?;
        self.transitions.push(t);
        Ok(())
    }

    fn last_at(&self) -> Timestamp {
        self.transitions.last().map_or(self.opened_at, |t| t.at)
    }

    fn check_step(
        current: EpistemicState,
        held: &Provenance,
        last_at: Timestamp,
        t: &EpistemicTransition,
        policy: &EpistemicPolicy,
    ) -> Result<(), OntologyError> {
        let illegal = |reason: String| OntologyError::IllegalEpistemicTransition {
            from: t.from,
            to: t.to,
            reason,
        };
        if t.from != current {
            return Err(illegal(format!(
                "hypothesis is {current:?}, not {:?}",
                t.from
            )));
        }
        if !t.from.can_transition_to(t.to) {
            return Err(illegal("promotion must be one step at a time".into()));
        }
        if t.at < last_at {
            return Err(illegal(format!(
                "{} precedes previous step at {last_at}",
                t.at
            )));
        }
        if t.to > t.from && !held.adds_to(&t.evidence) {
            return Err(illegal("promotion requires new evidence".into()));
        }
        if t.reason.trim().is_empty() {
            return Err(OntologyError::EmptyField {
                field: "transition.reason",
            });
        }
        policy.check(t.to, &t.confidence)
    }

    /// Validate the whole object, including replaying its history.
    pub fn check(&self, policy: &EpistemicPolicy) -> Result<(), OntologyError> {
        if self.subjects.is_empty() {
            return Err(OntologyError::EmptyField {
                field: "hypothesis.subjects",
            });
        }
        if self.claim.trim().is_empty() {
            return Err(OntologyError::EmptyField {
                field: "hypothesis.claim",
            });
        }
        if self.opened_as == EpistemicState::Unseen {
            return Err(OntologyError::IllegalEpistemicTransition {
                from: EpistemicState::Unseen,
                to: EpistemicState::Unseen,
                reason: "a hypothesis cannot be about nothing seen".into(),
            });
        }
        // Opening directly at PROBABLE/CONFIRMED would skip the ladder.
        if self.opened_as > EpistemicState::Suspicious {
            return Err(OntologyError::IllegalEpistemicTransition {
                from: EpistemicState::Unseen,
                to: self.opened_as,
                reason: "hypotheses open at SUSPICIOUS or below and must earn promotion".into(),
            });
        }
        policy.check(self.opened_as, &self.initial_confidence)?;
        let mut state = self.opened_as;
        let mut held = self.initial_evidence.clone();
        let mut last_at = self.opened_at;
        for t in &self.transitions {
            Self::check_step(state, &held, last_at, t, policy)?;
            state = t.to;
            held = held.union(&t.evidence);
            last_at = t.at;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Estimator, ObservationId, SourceRef};
    use EpistemicState::*;

    fn conf(v: f64) -> Confidence {
        Confidence::new(v, Estimator::new("e", "1").unwrap()).unwrap()
    }
    fn ev(n: &str) -> Provenance {
        Provenance::single(SourceRef::Observation(
            ObservationId::new(format!("obs:{n}")).unwrap(),
        ))
        .unwrap()
    }
    fn step(
        at: i64,
        from: EpistemicState,
        to: EpistemicState,
        c: f64,
        e: &str,
    ) -> EpistemicTransition {
        EpistemicTransition {
            at: Timestamp(at),
            from,
            to,
            confidence: conf(c),
            evidence: ev(e),
            reason: "r".into(),
        }
    }
    fn hyp() -> Hypothesis {
        Hypothesis::open(
            HypothesisId::new("hyp:1").unwrap(),
            vec![EntityId::new("ent:auth").unwrap()],
            "credential_stuffing",
            Timestamp(0),
            Anomalous,
            conf(0.4),
            ev("a"),
            &EpistemicPolicy::default(),
        )
        .unwrap()
    }

    #[test]
    fn ladder_climb() {
        let p = EpistemicPolicy::default();
        let mut h = hyp();
        h.transition(step(1, Anomalous, Suspicious, 0.5, "b"), &p)
            .unwrap();
        h.transition(step(2, Suspicious, Probable, 0.83, "c"), &p)
            .unwrap();
        assert_eq!(h.state(), Probable);
        assert_eq!(h.evidence().sources().len(), 3);
        h.check(&p).unwrap();
    }

    #[test]
    fn state_at_replays_history() {
        let p = EpistemicPolicy::default();
        let mut h = hyp();
        h.transition(step(10, Anomalous, Suspicious, 0.5, "b"), &p)
            .unwrap();
        assert_eq!(h.state_at(Timestamp(-1)), None);
        assert_eq!(h.state_at(Timestamp(5)), Some(Anomalous));
        assert_eq!(h.state_at(Timestamp(10)), Some(Suspicious));
        assert_eq!(h.confidence_at(Timestamp(5)).unwrap().basis_points(), 4000);
    }

    #[test]
    fn skipping_is_rejected() {
        let mut h = hyp();
        assert!(h
            .transition(
                step(1, Anomalous, Probable, 0.9, "b"),
                &EpistemicPolicy::default()
            )
            .is_err());
    }

    #[test]
    fn promotion_without_new_evidence_is_rejected() {
        let mut h = hyp();
        assert!(h
            .transition(
                step(1, Anomalous, Suspicious, 0.5, "a"),
                &EpistemicPolicy::default()
            )
            .is_err());
    }

    #[test]
    fn low_confidence_confirmation_is_rejected() {
        let p = EpistemicPolicy::default();
        let mut h = hyp();
        h.transition(step(1, Anomalous, Suspicious, 0.5, "b"), &p)
            .unwrap();
        assert!(h
            .transition(step(2, Suspicious, Probable, 0.51, "c"), &p)
            .is_err());
    }

    #[test]
    fn opening_confirmed_is_rejected() {
        let mut h = hyp();
        h.opened_as = Confirmed;
        h.initial_confidence = conf(0.99);
        assert!(h.check(&EpistemicPolicy::default()).is_err());
    }

    #[test]
    fn time_cannot_run_backwards() {
        let p = EpistemicPolicy::default();
        let mut h = hyp();
        h.transition(step(5, Anomalous, Suspicious, 0.5, "b"), &p)
            .unwrap();
        assert!(h
            .transition(step(4, Suspicious, Anomalous, 0.3, "c"), &p)
            .is_err());
    }
}
