use crate::OntologyError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Who/what produced a confidence value. Directive §19 forbids
/// "confidence without estimator/source", so it is structurally required.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "EstimatorRepr")]
pub struct Estimator {
    name: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EstimatorRepr {
    name: String,
    version: String,
}

impl TryFrom<EstimatorRepr> for Estimator {
    type Error = OntologyError;
    fn try_from(r: EstimatorRepr) -> Result<Self, Self::Error> {
        Estimator::new(r.name, r.version)
    }
}

impl Estimator {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Result<Self, OntologyError> {
        let (name, version) = (name.into(), version.into());
        if name.trim().is_empty() {
            return Err(OntologyError::EmptyField {
                field: "estimator.name",
            });
        }
        if version.trim().is_empty() {
            return Err(OntologyError::EmptyField {
                field: "estimator.version",
            });
        }
        Ok(Self { name, version })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// A probability in `[0, 1]`, stored as integer basis points so that it
/// hashes and compares deterministically. `0.51` and `0.99` are distinct
/// values all the way to the renderer (§6).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "ConfidenceRepr", into = "ConfidenceRepr")]
pub struct Confidence {
    basis_points: u16,
    estimator: Estimator,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfidenceRepr {
    value: f64,
    estimator: Estimator,
}

impl TryFrom<ConfidenceRepr> for Confidence {
    type Error = OntologyError;
    fn try_from(r: ConfidenceRepr) -> Result<Self, Self::Error> {
        Confidence::new(r.value, r.estimator)
    }
}

impl From<Confidence> for ConfidenceRepr {
    fn from(c: Confidence) -> Self {
        ConfidenceRepr {
            value: c.value(),
            estimator: c.estimator,
        }
    }
}

impl Confidence {
    pub const SCALE: u16 = 10_000;

    pub fn new(value: f64, estimator: Estimator) -> Result<Self, OntologyError> {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(OntologyError::InvalidConfidence(format!(
                "{value} is not a probability in [0, 1]"
            )));
        }
        Ok(Self {
            basis_points: (value * f64::from(Self::SCALE)).round() as u16,
            estimator,
        })
    }

    pub fn basis_points(&self) -> u16 {
        self.basis_points
    }

    pub fn value(&self) -> f64 {
        f64::from(self.basis_points) / f64::from(Self::SCALE)
    }

    pub fn estimator(&self) -> &Estimator {
        &self.estimator
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:.2}% ({}@{})",
            self.value() * 100.0,
            self.estimator.name,
            self.estimator.version
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn est() -> Estimator {
        Estimator::new("auth-anomaly", "1").unwrap()
    }

    #[test]
    fn range_is_enforced() {
        assert!(Confidence::new(-0.01, est()).is_err());
        assert!(Confidence::new(1.01, est()).is_err());
        assert!(Confidence::new(f64::NAN, est()).is_err());
        assert!(Confidence::new(0.0, est()).is_ok());
        assert!(Confidence::new(1.0, est()).is_ok());
    }

    #[test]
    fn distinct_values_stay_distinct() {
        let a = Confidence::new(0.51, est()).unwrap();
        let b = Confidence::new(0.99, est()).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.basis_points(), 5100);
    }

    #[test]
    fn estimator_is_required_in_json() {
        let r: Result<Confidence, _> = serde_json::from_str(r#"{"value":0.5}"#);
        assert!(r.is_err());
        let r: Result<Confidence, _> =
            serde_json::from_str(r#"{"value":0.5,"estimator":{"name":"","version":"1"}}"#);
        assert!(r.is_err());
    }

    #[test]
    fn roundtrip_is_stable() {
        let c = Confidence::new(0.8333, est()).unwrap();
        let s = serde_json::to_string(&c).unwrap();
        let back: Confidence = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
        assert_eq!(s, serde_json::to_string(&back).unwrap());
    }
}
