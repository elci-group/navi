use crate::{
    ActionId, AgentId, AuthorityLevel, CapabilityId, Confidence, EntityId, HypothesisId, Timestamp,
};
use serde::{Deserialize, Serialize};

/// Directive §18 roles. Phase 0: capability boundaries, not separate models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    Sentinel,
    Tracker,
    Hunter,
    Guardian,
    Medic,
    Archivist,
    Scout,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    pub id: AgentId,
    pub name: String,
    pub role: AgentRole,
    pub loadout: Vec<CapabilityId>,
}

/// The mandatory loop from directive §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentPhase {
    Perceive,
    Orient,
    Hypothesise,
    Investigate,
    Evaluate,
    Plan,
    Authorise,
    Act,
    Verify,
    Learn,
}

impl AgentPhase {
    pub const ALL: [AgentPhase; 10] = [
        Self::Perceive,
        Self::Orient,
        Self::Hypothesise,
        Self::Investigate,
        Self::Evaluate,
        Self::Plan,
        Self::Authorise,
        Self::Act,
        Self::Verify,
        Self::Learn,
    ];

    /// Every phase this one may legally move to, in loop order.
    pub fn successors(self) -> Vec<AgentPhase> {
        Self::ALL
            .into_iter()
            .filter(|p| self.can_transition_to(*p))
            .collect()
    }

    /// Legal successor phases. The main loop plus the backward edges a real
    /// investigation needs (need more evidence, plan denied, verification
    /// failed). Any phase may return to PERCEIVE (abandon / reset).
    pub fn can_transition_to(self, to: Self) -> bool {
        use AgentPhase::*;
        if to == Perceive {
            return true;
        }
        matches!(
            (self, to),
            (Perceive, Orient)
                | (Orient, Hypothesise)
                | (Hypothesise, Investigate)
                | (Investigate, Evaluate)
                | (Evaluate, Plan)
                | (Evaluate, Investigate)
                | (Evaluate, Hypothesise)
                | (Evaluate, Learn)
                | (Plan, Authorise)
                | (Authorise, Act)
                | (Authorise, Plan)
                | (Authorise, Learn)
                | (Act, Verify)
                | (Verify, Learn)
                | (Verify, Plan)
        )
    }

    /// The most authority an event in this phase may claim to exercise.
    /// Only ACT touches reality; everything before it is at most PROPOSE.
    pub fn authority_ceiling(self) -> Option<AuthorityLevel> {
        match self {
            AgentPhase::Act => None,
            _ => Some(AuthorityLevel::Propose),
        }
    }
}

/// One structured phase-transition event (directive §7). Renderers consume
/// these; they MUST NOT infer agent intent from anything else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEvent {
    pub agent: AgentId,
    /// Strictly increasing per agent.
    pub seq: u64,
    pub at: Timestamp,
    pub phase: AgentPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<EntityId>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypothesis: Option<HypothesisId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    pub authority: AuthorityLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionId>,
    /// The standing objective this event serves (§8 "CURRENT OBJECTIVE").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective: Option<String>,
    /// What the agent declares it will do next (§8 "NEXT"). Declared, never
    /// inferred: a renderer with no `next` shows "undeclared".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<NextStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NextStep {
    pub phase: AgentPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<EntityId>,
    pub intent: String,
}

#[cfg(test)]
mod tests {
    use super::AgentPhase::*;

    #[test]
    fn main_loop_is_legal() {
        let order = [
            Perceive,
            Orient,
            Hypothesise,
            Investigate,
            Evaluate,
            Plan,
            Authorise,
            Act,
            Verify,
            Learn,
            Perceive,
        ];
        for w in order.windows(2) {
            assert!(w[0].can_transition_to(w[1]), "{:?}->{:?}", w[0], w[1]);
        }
    }

    #[test]
    fn successors_follow_the_table() {
        assert_eq!(Plan.successors(), vec![Perceive, Authorise]);
        assert!(Act.successors().contains(&Verify));
        assert!(!Act.successors().contains(&Learn));
    }

    #[test]
    fn cannot_jump_to_act() {
        assert!(!Perceive.can_transition_to(Act));
        assert!(!Evaluate.can_transition_to(Act));
        assert!(!Plan.can_transition_to(Act));
    }
}
