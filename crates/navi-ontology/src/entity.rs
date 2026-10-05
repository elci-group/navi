use crate::{EntityId, OntologyError, Provenance, Timestamp};
use serde::{Deserialize, Serialize};

/// What a thing *is* in the estate. Deliberately computational, not
/// spatial: the realm grammar (Phase 1, `realm-core`) maps these to
/// buildings, rooms, vaults etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityClass {
    Organisation,
    Environment,
    Domain,
    Subnet,
    Cluster,
    Host,
    Service,
    Workload,
    Container,
    Process,
    Socket,
    Endpoint,
    Identity,
    Credential,
    Role,
    Permission,
    DataStore,
    Repository,
    Branch,
    Pipeline,
    Artifact,
    Registry,
    Deployment,
    ExternalActor,
    /// Something was observed but could not be classified (§26,
    /// "graceful incompleteness").
    Unknown,
}

/// How far the estate currently trusts an entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustState {
    Trusted,
    Unverified,
    Degraded,
    Compromised,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entity {
    pub id: EntityId,
    pub class: EntityClass,
    pub name: String,
    pub trust: TrustState,
    /// Required: §19 "entity without source" is rejected.
    pub provenance: Provenance,
    pub observed_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<Timestamp>,
}

impl Entity {
    pub fn check(&self) -> Result<(), OntologyError> {
        if self.name.trim().is_empty() {
            return Err(OntologyError::EmptyField {
                field: "entity.name",
            });
        }
        if let Some(until) = self.valid_until {
            if until < self.observed_at {
                return Err(OntologyError::InvalidTimeWindow(format!(
                    "{}: valid_until {until} precedes observed_at {}",
                    self.id, self.observed_at
                )));
            }
        }
        Ok(())
    }
}
