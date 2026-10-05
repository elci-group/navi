//! Directive §3: the universal realm grammar. Versioned; meanings MUST NOT
//! drift between sessions. Changing any mapping below requires bumping
//! [`GRAMMAR_VERSION`], and renderers refuse realms of another version.

use navi_ontology::{EntityClass, EpistemicState, RelationKind, SafeguardKind, TrustState};
use serde::{Deserialize, Serialize};

pub const GRAMMAR_VERSION: &str = "realm-grammar/0.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Primitive {
    Universe,
    World,
    Region,
    District,
    Building,
    Room,
    Road,
    Bridge,
    Portal,
    Door,
    Wall,
    Guard,
    Object,
    Vault,
    Npc,
    UnknownEntity,
    Enemy,
    Corruption,
    Fog,
    Navi,
    Tool,
    Damage,
    Healing,
    Teleport,
}

impl Primitive {
    pub const ALL: [Primitive; 24] = [
        Self::Universe,
        Self::World,
        Self::Region,
        Self::District,
        Self::Building,
        Self::Room,
        Self::Road,
        Self::Bridge,
        Self::Portal,
        Self::Door,
        Self::Wall,
        Self::Guard,
        Self::Object,
        Self::Vault,
        Self::Npc,
        Self::UnknownEntity,
        Self::Enemy,
        Self::Corruption,
        Self::Fog,
        Self::Navi,
        Self::Tool,
        Self::Damage,
        Self::Healing,
        Self::Teleport,
    ];

    /// The canonical meaning, verbatim from §3.
    pub fn meaning(self) -> &'static str {
        match self {
            Self::Universe => "managed estate",
            Self::World => "organisation / trust authority",
            Self::Region => "environment / major security zone",
            Self::District => "domain / subnet / cluster / service family",
            Self::Building => "host / application / substantial workload",
            Self::Room => "process / container / component",
            Self::Road => "permitted communication relationship",
            Self::Bridge => "cross-boundary dependency",
            Self::Portal => "API / ingress / integration",
            Self::Door => "authenticated access boundary",
            Self::Wall => "policy / ACL / firewall",
            Self::Guard => "active enforcement mechanism",
            Self::Object => "resource / artefact",
            Self::Vault => "sensitive data store",
            Self::Npc => "known benign actor/service",
            Self::UnknownEntity => "insufficiently classified actor",
            Self::Enemy => "sufficiently evidenced hostile behaviour",
            Self::Corruption => "compromised/degraded trust",
            Self::Fog => "epistemic uncertainty",
            Self::Navi => "defensive autonomous agent",
            Self::Tool => "authorised defensive capability",
            Self::Damage => "measurable adverse state transition",
            Self::Healing => "verified remediation",
            Self::Teleport => "non-topological logical transition",
        }
    }

    /// Places can contain other places.
    pub fn is_container(self) -> bool {
        matches!(
            self,
            Self::World | Self::Region | Self::District | Self::Building
        )
    }

    /// Places that delimit a security zone: crossing one turns a road into
    /// a bridge.
    pub fn is_zone(self) -> bool {
        matches!(self, Self::World | Self::Region | Self::District)
    }
}

/// The epistemic threshold at which hostile behaviour counts as
/// "sufficiently evidenced" (§3 Enemy, §6).
pub const ENEMY_THRESHOLD: EpistemicState = EpistemicState::Probable;

/// Primitive for an entity. `hostility` is the strongest epistemic state of
/// any hazard naming this entity as its actor.
pub fn entity_primitive(
    class: EntityClass,
    trust: TrustState,
    hostility: Option<EpistemicState>,
) -> Primitive {
    use EntityClass as C;
    match class {
        C::Organisation => Primitive::World,
        C::Environment => Primitive::Region,
        C::Domain | C::Subnet | C::Cluster => Primitive::District,
        C::Host | C::Service | C::Workload | C::Repository | C::Pipeline | C::Registry => {
            Primitive::Building
        }
        C::Container | C::Process | C::Socket | C::Branch | C::Deployment => Primitive::Room,
        C::Endpoint => Primitive::Portal,
        C::DataStore => Primitive::Vault,
        C::Identity | C::Credential | C::Role | C::Permission | C::Artifact => Primitive::Object,
        C::ExternalActor | C::Unknown => match hostility {
            Some(s) if s >= ENEMY_THRESHOLD => Primitive::Enemy,
            _ if class == C::ExternalActor && trust == TrustState::Trusted => Primitive::Npc,
            _ => Primitive::UnknownEntity,
        },
    }
}

/// Primitive for a relationship, or `None` for structural containment
/// (which is expressed as nesting, not as an edge).
pub fn edge_primitive(kind: RelationKind, crosses_boundary: bool) -> Option<Primitive> {
    use RelationKind as K;
    Some(match kind {
        K::Contains => return None,
        K::AuthenticatesTo => Primitive::Door,
        K::HasRole
        | K::Grants
        | K::HoldsCredential
        | K::BuildsFrom
        | K::Produces
        | K::DeploysTo => Primitive::Teleport,
        K::CommunicatesWith | K::DependsOn | K::Exposes | K::Stores | K::RunsOn => {
            if crosses_boundary {
                Primitive::Bridge
            } else {
                Primitive::Road
            }
        }
    })
}

pub fn control_primitive(kind: SafeguardKind) -> Primitive {
    match kind {
        SafeguardKind::Authentication | SafeguardKind::Mfa => Primitive::Door,
        SafeguardKind::Monitoring => Primitive::Guard,
        _ => Primitive::Wall,
    }
}

/// A hazard (hypothesis, possibly with an attributed threat) is fog until
/// it is anomalous, an unknown entity until it is probable, and an enemy
/// only once it is sufficiently evidenced.
pub fn hazard_primitive(state: EpistemicState) -> Primitive {
    use EpistemicState as E;
    match state {
        E::Unseen | E::Observed | E::Unexplained => Primitive::Fog,
        E::Anomalous | E::Suspicious => Primitive::UnknownEntity,
        E::Probable | E::Confirmed => Primitive::Enemy,
    }
}

/// §6: the visual resolution ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicView {
    Fog,
    Movement,
    Silhouette,
    UnknownEntity,
    ClassifiedHostile,
    IdentifiedTechnique,
}

/// `has_technique`: the hypothesis cites an ATT&CK (sub-)technique, not
/// merely a tactic. Only then may a CONFIRMED hazard show as identified.
pub fn epistemic_view(state: EpistemicState, has_technique: bool) -> EpistemicView {
    use EpistemicState as E;
    match state {
        E::Unseen => EpistemicView::Fog,
        E::Observed => EpistemicView::Movement,
        E::Unexplained => EpistemicView::Silhouette,
        E::Anomalous | E::Suspicious => EpistemicView::UnknownEntity,
        E::Probable => EpistemicView::ClassifiedHostile,
        E::Confirmed if has_technique => EpistemicView::IdentifiedTechnique,
        E::Confirmed => EpistemicView::ClassifiedHostile,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_primitive_has_a_meaning() {
        let meanings: std::collections::BTreeSet<_> =
            Primitive::ALL.iter().map(|p| p.meaning()).collect();
        assert_eq!(meanings.len(), Primitive::ALL.len());
    }

    #[test]
    fn enemy_requires_evidence() {
        use EpistemicState::*;
        for s in [Unseen, Observed, Unexplained, Anomalous, Suspicious] {
            assert_ne!(hazard_primitive(s), Primitive::Enemy, "{s:?}");
            assert_ne!(
                entity_primitive(EntityClass::ExternalActor, TrustState::Unknown, Some(s)),
                Primitive::Enemy
            );
        }
        assert_eq!(hazard_primitive(Probable), Primitive::Enemy);
    }

    #[test]
    fn unclassified_actor_is_not_npc() {
        assert_eq!(
            entity_primitive(EntityClass::ExternalActor, TrustState::Unknown, None),
            Primitive::UnknownEntity
        );
        assert_eq!(
            entity_primitive(EntityClass::ExternalActor, TrustState::Trusted, None),
            Primitive::Npc
        );
        assert_eq!(
            entity_primitive(EntityClass::Unknown, TrustState::Trusted, None),
            Primitive::UnknownEntity
        );
    }

    #[test]
    fn roads_become_bridges_across_boundaries() {
        assert_eq!(
            edge_primitive(RelationKind::CommunicatesWith, false),
            Some(Primitive::Road)
        );
        assert_eq!(
            edge_primitive(RelationKind::CommunicatesWith, true),
            Some(Primitive::Bridge)
        );
        assert_eq!(
            edge_primitive(RelationKind::DeploysTo, false),
            Some(Primitive::Teleport)
        );
        assert_eq!(edge_primitive(RelationKind::Contains, true), None);
    }

    #[test]
    fn confirmed_needs_technique_to_be_identified() {
        assert_eq!(
            epistemic_view(EpistemicState::Confirmed, false),
            EpistemicView::ClassifiedHostile
        );
        assert_eq!(
            epistemic_view(EpistemicState::Confirmed, true),
            EpistemicView::IdentifiedTechnique
        );
    }
}
