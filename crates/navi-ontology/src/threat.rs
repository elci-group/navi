use crate::{EntityId, HypothesisId, ThreatId};
use serde::{Deserialize, Serialize};

/// A threat is *always* a projection of a hypothesis: its classification
/// state is the hypothesis's epistemic state. There is no way to express a
/// threat with no classification (§19).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Threat {
    pub id: ThreatId,
    pub hypothesis: HypothesisId,
    /// The acting entity, if attributed. `None` renders as "?" — never as
    /// an invented attacker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<EntityId>,
    pub targets: Vec<EntityId>,
}
