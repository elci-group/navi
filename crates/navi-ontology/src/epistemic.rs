use crate::{Confidence, OntologyError};
use serde::{Deserialize, Serialize};

/// Directive §6. Ordered: `Unseen < Observed < … < Confirmed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EpistemicState {
    Unseen,
    Observed,
    Unexplained,
    Anomalous,
    Suspicious,
    Probable,
    Confirmed,
}

impl EpistemicState {
    pub const ALL: [EpistemicState; 7] = [
        Self::Unseen,
        Self::Observed,
        Self::Unexplained,
        Self::Anomalous,
        Self::Suspicious,
        Self::Probable,
        Self::Confirmed,
    ];

    pub fn next(self) -> Option<Self> {
        Self::ALL.get(self as usize + 1).copied()
    }

    /// Promotion is one step at a time; demotion (evidence retracted,
    /// benign explanation found) may jump any distance.
    pub fn can_transition_to(self, to: Self) -> bool {
        to < self || Some(to) == self.next()
    }
}

/// Minimum confidence a hypothesis must carry to occupy a state. A
/// "CONFIRMED" claim at 30% is incoherent and is rejected, not rendered.
/// These are defaults; they are versioned with the document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpistemicPolicy {
    pub version: String,
    /// Basis points (0..=10000).
    pub probable_min_bp: u16,
    pub confirmed_min_bp: u16,
}

impl Default for EpistemicPolicy {
    fn default() -> Self {
        Self {
            version: "default/1".into(),
            probable_min_bp: 6_000,
            confirmed_min_bp: 9_000,
        }
    }
}

impl EpistemicPolicy {
    pub fn check(
        &self,
        state: EpistemicState,
        confidence: &Confidence,
    ) -> Result<(), OntologyError> {
        let min = match state {
            EpistemicState::Probable => self.probable_min_bp,
            EpistemicState::Confirmed => self.confirmed_min_bp,
            _ => 0,
        };
        if confidence.basis_points() < min {
            return Err(OntologyError::IllegalEpistemicTransition {
                from: state,
                to: state,
                reason: format!(
                    "{state:?} requires confidence >= {:.2}, have {:.2}",
                    f64::from(min) / 10_000.0,
                    confidence.value()
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use EpistemicState::*;

    #[test]
    fn promotion_is_single_step() {
        assert!(Observed.can_transition_to(Unexplained));
        assert!(!Observed.can_transition_to(Confirmed));
        assert!(!Anomalous.can_transition_to(Probable));
        assert!(!Confirmed.can_transition_to(Confirmed));
    }

    #[test]
    fn demotion_is_free() {
        assert!(Confirmed.can_transition_to(Observed));
        assert!(Probable.can_transition_to(Unseen));
    }
}
