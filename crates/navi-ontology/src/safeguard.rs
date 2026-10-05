use crate::{D3fendRef, EntityId, Provenance, SafeguardId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeguardKind {
    Firewall,
    Acl,
    Waf,
    RateLimit,
    Authentication,
    Mfa,
    Encryption,
    NetworkPolicy,
    AdmissionControl,
    BranchProtection,
    Monitoring,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeguardStatus {
    Active,
    Inactive,
    /// Configuration exists but enforcement could not be observed.
    Unknown,
}

/// A defensive control (realm: wall / guard / door).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Safeguard {
    pub id: SafeguardId,
    pub kind: SafeguardKind,
    pub name: String,
    pub protects: Vec<EntityId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced_by: Option<EntityId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub d3fend: Vec<D3fendRef>,
    pub status: SafeguardStatus,
    pub provenance: Provenance,
}
