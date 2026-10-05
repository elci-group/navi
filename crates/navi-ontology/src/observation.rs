use crate::{EntityId, ObservationId, OntologyError, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Where an observation came from. Observations are the axioms of the
/// graph: they carry no provenance of their own, so their *source* must be
/// explicit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySource {
    /// e.g. `k8s-audit`, `envoy-access-log`, `github-actions`.
    pub system: String,
    /// The concrete collector instance, e.g. `fluentbit/prod-eu-1`.
    pub collector: String,
}

/// A normalized fact as reported by telemetry — the "raw observation" at
/// the bottom of reverse resolution (directive §26).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub id: ObservationId,
    pub source: TelemetrySource,
    pub observed_at: Timestamp,
    /// The entity this observation is about, if it is about one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<EntityId>,
    /// Normalized kind, e.g. `http.request_rate`, `process.spawn`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, serde_json::Value>,
    /// Pointer to the raw record (log offset, object key, event id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_ref: Option<String>,
}

impl Observation {
    pub fn check(&self) -> Result<(), OntologyError> {
        if self.source.system.trim().is_empty() {
            return Err(OntologyError::EmptyField {
                field: "observation.source.system",
            });
        }
        if self.source.collector.trim().is_empty() {
            return Err(OntologyError::EmptyField {
                field: "observation.source.collector",
            });
        }
        if self.kind.trim().is_empty() {
            return Err(OntologyError::EmptyField {
                field: "observation.kind",
            });
        }
        Ok(())
    }
}
