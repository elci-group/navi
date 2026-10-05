//! Adaptive world generation (directive §11, §12, doctrine VI).
//!
//! * **Semantic level of detail.** The realm becomes more detailed in the
//!   direction of operational attention: places on the path to the focus
//!   are expanded, others are collapsed into a single box.
//! * **Compress, never conceal.** A collapsed place carries an aggregate of
//!   everything inside it (how much is hidden, the worst trust, the
//!   strongest hazard, corruption), and every hazard, edge, control and
//!   agent pointing into hidden detail is re-pointed to the nearest visible
//!   place *with the original target still named*. [`View::check`]
//!   recomputes all of it.
//! * **Lenses.** A context-specific strip that lays the incident out along
//!   the chain the directive names for its kind (IAM, network, supply
//!   chain). The lens is chosen from the data around the attention and says
//!   why. Primitives and visual contracts never change — only geometry.

mod lens;

pub use lens::{Lens, LensChoice, LensStrip, Stage};

use navi_ontology::{EpistemicState, TrustState};
use realm_core::Realm;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Detail {
    /// Drawn with its children.
    Expanded,
    /// Drawn as one box standing in for its whole subtree.
    Collapsed,
    /// Inside a collapsed ancestor; represented by it.
    Hidden,
    /// Visible, with nothing inside.
    Leaf,
}

/// What a collapsed place stands in for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Aggregate {
    /// Number of places hidden inside it.
    pub hidden: usize,
    /// Worst trust anywhere inside (or of the place itself).
    pub worst_trust: TrustState,
    /// Strongest hazard targeting anything inside.
    pub max_hazard: Option<EpistemicState>,
    /// Degraded or compromised trust somewhere inside.
    pub corruption: bool,
    /// Edges entirely inside it (not drawn).
    pub internal_edges: usize,
}

/// A pointer into hidden detail, re-anchored to what is visible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reanchor {
    pub original: String,
    pub shown_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct View {
    /// The attention the view is built around.
    pub focus: Vec<String>,
    /// Why that focus (Navi's location, operator choice, strongest hazard).
    pub focus_reason: String,
    pub depth: usize,
    pub detail: BTreeMap<String, Detail>,
    pub aggregates: BTreeMap<String, Aggregate>,
    pub lens: Option<LensStrip>,
    /// Why no lens is shown, when one was asked for automatically.
    pub lens_note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LensRequest {
    Auto,
    None,
    Fixed(Lens),
}

/// How the view is requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewSpec {
    /// Explicit focus (realm ids); empty means "where Navi is attending".
    pub focus: Vec<String>,
    /// Places at or above this containment depth are always expanded.
    pub depth: usize,
    pub lens: LensRequest,
}

impl Default for ViewSpec {
    fn default() -> Self {
        Self {
            focus: vec![],
            depth: 2,
            lens: LensRequest::Auto,
        }
    }
}

fn trust_rank(t: TrustState) -> u8 {
    // Worst first: compromised > degraded > unknown > unverified > trusted.
    match t {
        TrustState::Trusted => 0,
        TrustState::Unverified => 1,
        TrustState::Unknown => 2,
        TrustState::Degraded => 3,
        TrustState::Compromised => 4,
    }
}

pub(crate) struct Tree<'r> {
    pub parent: BTreeMap<&'r str, &'r str>,
    pub children: BTreeMap<&'r str, Vec<&'r str>>,
}

pub(crate) fn tree(realm: &Realm) -> Tree<'_> {
    let ids: BTreeSet<&str> = realm.entities.iter().map(|e| e.realm_id.as_str()).collect();
    let mut parent = BTreeMap::new();
    let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for e in &realm.entities {
        if let Some(p) = e.parent.as_deref().filter(|p| ids.contains(p)) {
            parent.insert(e.realm_id.as_str(), p);
            children.entry(p).or_default().push(&e.realm_id);
        }
    }
    Tree { parent, children }
}

impl Tree<'_> {
    fn ancestors_or_self<'a>(&'a self, id: &'a str) -> Vec<&'a str> {
        let mut out = vec![id];
        let mut cur = id;
        while let Some(p) = self.parent.get(cur) {
            if out.contains(p) {
                break;
            }
            out.push(p);
            cur = p;
        }
        out
    }

    fn depth(&self, id: &str) -> usize {
        self.ancestors_or_self(id).len() - 1
    }

    fn subtree<'a>(&'a self, id: &'a str) -> Vec<&'a str> {
        let mut out = vec![];
        let mut stack = vec![id];
        while let Some(n) = stack.pop() {
            if out.contains(&n) {
                continue;
            }
            out.push(n);
            stack.extend(self.children.get(n).map(Vec::as_slice).unwrap_or(&[]));
        }
        out
    }
}

/// Where attention is: the explicit focus, else every agent's location,
/// else the target of the strongest hazard. Each choice says why.
fn attention(realm: &Realm, spec: &ViewSpec) -> (Vec<String>, String) {
    let known: BTreeSet<&str> = realm.entities.iter().map(|e| e.realm_id.as_str()).collect();
    let explicit: Vec<String> = spec
        .focus
        .iter()
        .filter(|f| known.contains(f.as_str()))
        .cloned()
        .collect();
    if !explicit.is_empty() {
        return (explicit, "operator focus".into());
    }
    let navi: BTreeSet<String> = realm
        .agents
        .iter()
        .filter_map(|a| a.location.clone())
        .collect();
    if !navi.is_empty() {
        let names: Vec<&str> = realm
            .agents
            .iter()
            .filter(|a| a.location.is_some())
            .map(|a| a.name.as_str())
            .collect();
        return (
            navi.into_iter().collect(),
            format!("where {} is attending", names.join(", ")),
        );
    }
    let strongest = realm.hazards.iter().map(|h| h.epistemic_state).max();
    let targets: BTreeSet<String> = realm
        .hazards
        .iter()
        .filter(|h| Some(h.epistemic_state) == strongest)
        .flat_map(|h| h.targets.iter().cloned())
        .collect();
    if !targets.is_empty() {
        return (
            targets.into_iter().collect(),
            "no agent is attending; strongest hazard".into(),
        );
    }
    (
        vec![],
        "nothing to attend to; showing the estate to depth".into(),
    )
}

/// Build the view for a realm. Pure and deterministic.
pub fn view(realm: &Realm, spec: &ViewSpec) -> View {
    let t = tree(realm);
    let (focus, focus_reason) = attention(realm, spec);
    let on_path: BTreeSet<&str> = focus.iter().flat_map(|f| t.ancestors_or_self(f)).collect();

    let mut detail = BTreeMap::new();
    for e in &realm.entities {
        let id = e.realm_id.as_str();
        let has_children = t.children.contains_key(id);
        let expanded = has_children && (t.depth(id) < spec.depth || on_path.contains(id));
        detail.insert(
            id.to_string(),
            if !has_children {
                Detail::Leaf
            } else if expanded {
                Detail::Expanded
            } else {
                Detail::Collapsed
            },
        );
    }
    // Hidden: anything with a non-expanded ancestor.
    for e in &realm.entities {
        let id = e.realm_id.as_str();
        let hidden = t.ancestors_or_self(id)[1..]
            .iter()
            .any(|a| detail.get(*a) != Some(&Detail::Expanded));
        if hidden {
            detail.insert(id.to_string(), Detail::Hidden);
        }
    }

    let aggregates = detail
        .iter()
        .filter(|(_, d)| **d == Detail::Collapsed)
        .map(|(id, _)| (id.clone(), aggregate(realm, &t, id)))
        .collect();

    let mut v = View {
        focus,
        focus_reason,
        depth: spec.depth,
        detail,
        aggregates,
        lens: None,
        lens_note: None,
    };
    match spec.lens {
        LensRequest::None => {}
        LensRequest::Fixed(l) => {
            v.lens = Some(lens::strip(
                realm,
                &v,
                LensChoice {
                    lens: l,
                    reason: "requested".into(),
                },
            ))
        }
        LensRequest::Auto => match lens::choose(realm, &v) {
            Ok(c) => v.lens = Some(lens::strip(realm, &v, c)),
            Err(note) => v.lens_note = Some(note),
        },
    }
    v
}

fn aggregate(realm: &Realm, t: &Tree, id: &str) -> Aggregate {
    let inside = t.subtree(id);
    let set: BTreeSet<&str> = inside.iter().copied().collect();
    let ents: Vec<&realm_core::RealmEntity> =
        inside.iter().filter_map(|i| realm.entity(i)).collect();
    Aggregate {
        hidden: inside.len() - 1,
        worst_trust: ents
            .iter()
            .map(|e| e.trust_state)
            .max_by_key(|t| trust_rank(*t))
            .unwrap_or(TrustState::Unknown),
        max_hazard: ents.iter().filter_map(|e| e.risk.max_state).max(),
        corruption: ents.iter().any(|e| {
            matches!(
                e.trust_state,
                TrustState::Degraded | TrustState::Compromised
            )
        }),
        internal_edges: realm
            .edges
            .iter()
            .filter(|e| set.contains(e.from.as_str()) && set.contains(e.to.as_str()))
            .count(),
    }
}

impl View {
    pub fn is_visible(&self, id: &str) -> bool {
        !matches!(self.detail.get(id), Some(Detail::Hidden))
    }

    /// The visible place standing for `id` (itself, or its nearest visible
    /// ancestor). Unplaced ids are their own anchor.
    pub fn anchor(&self, realm: &Realm, id: &str) -> String {
        let t = tree(realm);
        t.ancestors_or_self(id)
            .into_iter()
            .find(|a| self.is_visible(a))
            .unwrap_or(id)
            .to_string()
    }

    /// Every pointer into hidden detail, and where it is shown instead.
    pub fn reanchored(&self, realm: &Realm) -> Vec<Reanchor> {
        let mut ids: BTreeSet<&str> = BTreeSet::new();
        for e in &realm.edges {
            ids.extend([e.from.as_str(), e.to.as_str()]);
        }
        for h in &realm.hazards {
            ids.extend(h.targets.iter().map(String::as_str));
            ids.extend(h.actor.as_deref());
        }
        for c in &realm.controls {
            ids.extend(c.protects.iter().map(String::as_str));
        }
        ids.extend(realm.agents.iter().filter_map(|a| a.location.as_deref()));
        ids.into_iter()
            .filter(|i| !self.is_visible(i))
            .map(|i| Reanchor {
                original: i.to_string(),
                shown_at: self.anchor(realm, i),
            })
            .collect()
    }

    /// The anti-concealment check (doctrine VI): recompute every detail
    /// level and aggregate, and require that every focus is visible and
    /// every hazard still lands on something visible.
    pub fn check(&self, realm: &Realm) -> Vec<String> {
        let mut out = vec![];
        let t = tree(realm);
        for e in &realm.entities {
            if !self.detail.contains_key(&e.realm_id) {
                out.push(format!("{} has no detail level", e.realm_id));
            }
        }
        for f in &self.focus {
            if !self.is_visible(f) {
                out.push(format!("focus {f} is hidden"));
            }
        }
        for (id, d) in &self.detail {
            if *d == Detail::Collapsed {
                match self.aggregates.get(id) {
                    None => out.push(format!("collapsed {id} has no aggregate")),
                    Some(a) if *a != aggregate(realm, &t, id) => {
                        out.push(format!("aggregate for {id} misstates what it hides"))
                    }
                    _ => {}
                }
            }
            if *d == Detail::Hidden
                && !t.ancestors_or_self(id)[1..]
                    .iter()
                    .any(|a| self.detail.get(*a) == Some(&Detail::Collapsed))
            {
                out.push(format!(
                    "{id} is hidden without a collapsed ancestor standing in for it"
                ));
            }
        }
        for h in &realm.hazards {
            for target in &h.targets {
                let shown = self.anchor(realm, target);
                if !self.is_visible(&shown) {
                    out.push(format!(
                        "{} targets {target}, which has no visible anchor",
                        h.realm_id
                    ));
                    continue;
                }
                if shown != *target {
                    let state = self.aggregates.get(&shown).and_then(|a| a.max_hazard);
                    if state.is_none_or(|s| s < h.epistemic_state) {
                        out.push(format!(
                            "{shown} hides {} without carrying its hazard",
                            h.realm_id
                        ));
                    }
                }
            }
        }
        out
    }
}
