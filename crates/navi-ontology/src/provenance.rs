use crate::{ActionId, HypothesisId, ObservationId, OntologyError, SafeguardId};
use serde::{Deserialize, Serialize};

/// One evidentiary source (directive §5): an observation, a derived fact,
/// a policy/safeguard, a hypothesis, or an agent action.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceRef {
    Observation(ObservationId),
    /// A fact computed by a named rule from other sources, e.g.
    /// `auth_failure_ratio` over a window of observations.
    Derived {
        rule: String,
        inputs: Vec<SourceRef>,
    },
    Safeguard(SafeguardId),
    Hypothesis(HypothesisId),
    Action(ActionId),
}

impl SourceRef {
    fn check(&self) -> Result<(), OntologyError> {
        if let SourceRef::Derived { rule, inputs } = self {
            if rule.trim().is_empty() {
                return Err(OntologyError::EmptyField {
                    field: "derived.rule",
                });
            }
            if inputs.is_empty() {
                return Err(OntologyError::EmptyDerivation { rule: rule.clone() });
            }
            inputs.iter().try_for_each(SourceRef::check)?;
        }
        Ok(())
    }

    /// Every observation id reachable *syntactically* within this source
    /// (does not follow hypothesis/action references — that is graph work).
    pub fn direct_observations(&self) -> Vec<&ObservationId> {
        match self {
            SourceRef::Observation(id) => vec![id],
            SourceRef::Derived { inputs, .. } => inputs
                .iter()
                .flat_map(|s| s.direct_observations())
                .collect(),
            _ => vec![],
        }
    }
}

/// A non-empty, canonically ordered set of sources.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "Vec<SourceRef>", into = "Vec<SourceRef>")]
pub struct Provenance {
    sources: Vec<SourceRef>,
}

impl Provenance {
    pub fn new(sources: impl IntoIterator<Item = SourceRef>) -> Result<Self, OntologyError> {
        let mut sources: Vec<SourceRef> = sources.into_iter().collect();
        if sources.is_empty() {
            return Err(OntologyError::EmptyProvenance);
        }
        sources.iter().try_for_each(SourceRef::check)?;
        sources.sort();
        sources.dedup();
        Ok(Self { sources })
    }

    pub fn single(source: SourceRef) -> Result<Self, OntologyError> {
        Self::new([source])
    }

    pub fn sources(&self) -> &[SourceRef] {
        &self.sources
    }

    pub fn contains(&self, source: &SourceRef) -> bool {
        self.sources.binary_search(source).is_ok()
    }

    /// True if `other` contributes at least one source not already here.
    pub fn adds_to(&self, other: &Provenance) -> bool {
        other.sources.iter().any(|s| !self.contains(s))
    }

    pub fn union(&self, other: &Provenance) -> Provenance {
        let mut sources = self.sources.clone();
        sources.extend(other.sources.iter().cloned());
        sources.sort();
        sources.dedup();
        Provenance { sources }
    }

    pub fn direct_observations(&self) -> Vec<&ObservationId> {
        self.sources
            .iter()
            .flat_map(|s| s.direct_observations())
            .collect()
    }
}

impl TryFrom<Vec<SourceRef>> for Provenance {
    type Error = OntologyError;
    fn try_from(v: Vec<SourceRef>) -> Result<Self, Self::Error> {
        Provenance::new(v)
    }
}

impl From<Provenance> for Vec<SourceRef> {
    fn from(p: Provenance) -> Self {
        p.sources
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(n: &str) -> SourceRef {
        SourceRef::Observation(ObservationId::new(format!("obs:{n}")).unwrap())
    }

    #[test]
    fn empty_is_rejected() {
        assert_eq!(Provenance::new([]), Err(OntologyError::EmptyProvenance));
        assert!(serde_json::from_str::<Provenance>("[]").is_err());
    }

    #[test]
    fn empty_derivation_is_rejected() {
        let d = SourceRef::Derived {
            rule: "ratio".into(),
            inputs: vec![],
        };
        assert!(Provenance::single(d).is_err());
    }

    #[test]
    fn canonical_order() {
        let a = Provenance::new([obs("b"), obs("a"), obs("b")]).unwrap();
        let b = Provenance::new([obs("a"), obs("b")]).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.sources().len(), 2);
    }

    #[test]
    fn adds_to_detects_new_evidence() {
        let a = Provenance::new([obs("a")]).unwrap();
        assert!(!a.adds_to(&Provenance::new([obs("a")]).unwrap()));
        assert!(a.adds_to(&Provenance::new([obs("a"), obs("c")]).unwrap()));
    }

    #[test]
    fn json_shape() {
        let p: Provenance = serde_json::from_str(
            r#"[{"observation":"obs:1"},{"derived":{"rule":"r","inputs":[{"observation":"obs:2"}]}}]"#,
        )
        .unwrap();
        assert_eq!(p.direct_observations().len(), 2);
    }
}
