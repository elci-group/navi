//! Context-sensitive geography (directive §12): the same primitives laid out
//! along the chain that matters for this kind of incident.

use crate::View;
use navi_ontology::{EntityClass as C, RelationKind};
use realm_core::Realm;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Lens {
    Iam,
    Network,
    SupplyChain,
}

impl Lens {
    pub const ALL: [Lens; 3] = [Lens::Iam, Lens::Network, Lens::SupplyChain];

    /// The chain from §12, as stages of entity classes.
    pub fn stages(self) -> Vec<(&'static str, Vec<C>)> {
        match self {
            Lens::Iam => vec![
                ("identity", vec![C::Identity]),
                ("credential", vec![C::Credential]),
                ("role", vec![C::Role]),
                ("permission", vec![C::Permission]),
                (
                    "resource",
                    vec![C::Endpoint, C::Service, C::DataStore, C::Workload],
                ),
            ],
            Lens::Network => vec![
                (
                    "host",
                    vec![C::Host, C::Workload, C::Container, C::Process, C::Service],
                ),
                ("interface", vec![C::Endpoint, C::Socket]),
                ("boundary", vec![C::Subnet, C::Cluster]),
                ("destination", vec![C::ExternalActor, C::DataStore]),
            ],
            Lens::SupplyChain => vec![
                ("developer", vec![C::Identity]),
                ("repository", vec![C::Repository, C::Branch]),
                ("ci", vec![C::Pipeline]),
                ("artefact", vec![C::Artifact]),
                ("registry", vec![C::Registry]),
                ("deployment", vec![C::Deployment, C::Service, C::Workload]),
            ],
        }
    }

    /// Classes that indicate this kind of incident (generic resources such
    /// as services and endpoints indicate nothing).
    fn characteristic(self) -> &'static [C] {
        match self {
            Lens::Iam => &[C::Identity, C::Credential, C::Role, C::Permission],
            Lens::Network => &[
                C::Host,
                C::Socket,
                C::Subnet,
                C::ExternalActor,
                C::Container,
                C::Process,
            ],
            Lens::SupplyChain => &[
                C::Repository,
                C::Branch,
                C::Pipeline,
                C::Artifact,
                C::Registry,
                C::Deployment,
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LensChoice {
    pub lens: Lens,
    /// Which entities, of which classes, decided it.
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Stage {
    pub name: String,
    pub entities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LensStrip {
    pub lens: Lens,
    pub reason: String,
    pub stages: Vec<Stage>,
    /// Realm edges between strip entities.
    pub edges: Vec<String>,
}

fn neighbours(realm: &Realm) -> BTreeMap<&str, BTreeSet<&str>> {
    let mut n: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for e in &realm.edges {
        if e.kind != RelationKind::Contains {
            n.entry(&e.from).or_default().insert(&e.to);
            n.entry(&e.to).or_default().insert(&e.from);
        }
    }
    n
}

/// The attention neighbourhood with weights: focus 3, what hazards
/// (anomalous or worse) target 2, attributed actors and direct relationship
/// neighbours 1. The lens follows what is under attack more than who is
/// attacking.
fn weighted(realm: &Realm, view: &View) -> BTreeMap<String, u32> {
    fn bump(w: &mut BTreeMap<String, u32>, id: &str, by: u32) {
        let e = w.entry(id.to_string()).or_insert(0);
        *e = (*e).max(by);
    }
    let mut w: BTreeMap<String, u32> = BTreeMap::new();
    for f in &view.focus {
        bump(&mut w, f, 3);
    }
    for h in realm
        .hazards
        .iter()
        .filter(|h| h.epistemic_state >= navi_ontology::EpistemicState::Anomalous)
    {
        for t in &h.targets {
            bump(&mut w, t, 2);
        }
        if let Some(a) = &h.actor {
            bump(&mut w, a, 1);
        }
    }
    let n = neighbours(realm);
    let core: Vec<String> = w.keys().cloned().collect();
    for c in core {
        for m in n.get(c.as_str()).into_iter().flatten() {
            bump(&mut w, m, 1);
        }
    }
    w
}

/// Pick the lens the data points to. `Err` explains a tie or no signal.
pub fn choose(realm: &Realm, view: &View) -> Result<LensChoice, String> {
    let w = weighted(realm, view);
    let mut scored: Vec<(u32, Lens, Vec<String>)> = Lens::ALL
        .iter()
        .map(|l| {
            let mut why = vec![];
            let mut score = 0;
            for (id, weight) in &w {
                if let Some(e) = realm.entity(id) {
                    if l.characteristic().contains(&e.entity_class) {
                        score += weight;
                        why.push(format!(
                            "{} ({})",
                            e.name,
                            realm_core::wire(&e.entity_class)
                        ));
                    }
                }
            }
            (score, *l, why)
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let (best, lens, why) = scored[0].clone();
    if best == 0 {
        return Err(
            "no lens: nothing near the attention indicates IAM, network or supply chain".into(),
        );
    }
    let tied: Vec<String> = scored
        .iter()
        .filter(|s| s.0 == best)
        .map(|s| realm_core::wire(&s.1))
        .collect();
    if tied.len() > 1 {
        return Err(format!(
            "no lens: {} are equally indicated",
            tied.join(" and ")
        ));
    }
    Ok(LensChoice {
        lens,
        reason: format!("attention involves {}", why.join(", ")),
    })
}

/// Entities within two relationship hops of the attention, placed on the
/// lens's chain.
pub fn strip(realm: &Realm, view: &View, choice: LensChoice) -> LensStrip {
    let n = neighbours(realm);
    let w = weighted(realm, view);
    let mut near: BTreeSet<&str> = w.keys().map(String::as_str).collect();
    let first: Vec<&str> = near.iter().copied().collect();
    for id in first {
        near.extend(n.get(id).into_iter().flatten().copied());
    }
    let stages: Vec<Stage> = choice
        .lens
        .stages()
        .into_iter()
        .map(|(name, classes)| {
            let mut entities: Vec<&realm_core::RealmEntity> = realm
                .entities
                .iter()
                .filter(|e| near.contains(e.realm_id.as_str()) && classes.contains(&e.entity_class))
                .collect();
            entities.sort_by(|a, b| (&a.name, &a.realm_id).cmp(&(&b.name, &b.realm_id)));
            Stage {
                name: name.into(),
                entities: entities.into_iter().map(|e| e.realm_id.clone()).collect(),
            }
        })
        .collect();
    // An entity appears in the first stage that claims it.
    let mut seen = BTreeSet::new();
    let stages: Vec<Stage> = stages
        .into_iter()
        .map(|s| Stage {
            entities: s
                .entities
                .into_iter()
                .filter(|e| seen.insert(e.clone()))
                .collect(),
            ..s
        })
        .collect();
    let members: BTreeSet<&str> = stages
        .iter()
        .flat_map(|s| s.entities.iter().map(String::as_str))
        .collect();
    let edges = realm
        .edges
        .iter()
        .filter(|e| members.contains(e.from.as_str()) && members.contains(e.to.as_str()))
        .map(|e| e.realm_id.clone())
        .collect();
    LensStrip {
        lens: choice.lens,
        reason: choice.reason,
        stages,
        edges,
    }
}
