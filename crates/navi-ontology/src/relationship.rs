use crate::{EntityId, OntologyError, Provenance, RelationshipId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    /// Structural nesting (environment ⊃ domain ⊃ service ⊃ pod). Defines
    /// capability scope and, later, semantic level of detail.
    Contains,
    CommunicatesWith,
    DependsOn,
    AuthenticatesTo,
    Exposes,
    HoldsCredential,
    HasRole,
    Grants,
    Stores,
    BuildsFrom,
    Produces,
    DeploysTo,
    RunsOn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relationship {
    pub id: RelationshipId,
    pub kind: RelationKind,
    pub from: EntityId,
    pub to: EntityId,
    /// Required: §19 "relationship without evidence" is rejected.
    pub provenance: Provenance,
}

impl Relationship {
    pub fn check(&self) -> Result<(), OntologyError> {
        if self.kind == RelationKind::Contains && self.from == self.to {
            return Err(OntologyError::InvalidId {
                value: self.id.to_string(),
                reason: "an entity cannot contain itself".into(),
            });
        }
        Ok(())
    }
}
