//! Deterministic 2D layout (directive §25 Phase 1).
//!
//! Containment becomes nesting: worlds hold regions hold districts hold
//! buildings hold rooms. Children are packed into a near-square grid in a
//! fixed order, on an integer cell grid, so identical realms always lay
//! out identically. Layout places things; it never decides what they are.

use realm_core::{Primitive, Realm, RealmEntity};
use serde::Serialize;
use std::collections::BTreeMap;

/// The frame around everything: the managed estate (§3 Universe).
pub const UNIVERSE_ID: &str = "realm:universe";

pub const LEAF_MIN_W: u32 = 20;
/// Border, label, status, hazard, border.
pub const LEAF_H: u32 = 5;
const H_GAP: u32 = 2;
const V_GAP: u32 = 1;
const PAD: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
    pub fn center(&self) -> (u32, u32) {
        (self.x + self.w / 2, self.y + self.h / 2)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Placed {
    pub rect: Rect,
    pub depth: u32,
    /// True if this place has children laid out inside it.
    pub container: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Layout {
    pub width: u32,
    pub height: u32,
    /// Keyed by realm id; includes [`UNIVERSE_ID`].
    pub places: BTreeMap<String, Placed>,
}

struct Tree<'r> {
    children: BTreeMap<&'r str, Vec<&'r RealmEntity>>,
    roots: Vec<&'r RealmEntity>,
}

fn order_key(e: &RealmEntity) -> (bool, Primitive, &str, &str) {
    // Containers first, then by primitive, name, id: stable and readable.
    (
        !e.semantic_type.is_container(),
        e.semantic_type,
        e.name.as_str(),
        e.realm_id.as_str(),
    )
}

fn tree(realm: &Realm) -> Tree<'_> {
    let ids: std::collections::BTreeSet<&str> =
        realm.entities.iter().map(|e| e.realm_id.as_str()).collect();
    let mut children: BTreeMap<&str, Vec<&RealmEntity>> = BTreeMap::new();
    let mut roots = Vec::new();
    for e in &realm.entities {
        match e.parent.as_deref().filter(|p| ids.contains(p)) {
            Some(p) => children.entry(p).or_default().push(e),
            None => roots.push(e),
        }
    }
    for v in children.values_mut() {
        v.sort_by(|a, b| order_key(a).cmp(&order_key(b)));
    }
    roots.sort_by(|a, b| order_key(a).cmp(&order_key(b)));
    Tree { children, roots }
}

fn label_w(e: &RealmEntity) -> u32 {
    e.visual_contract.label.chars().count() as u32
}

/// Size of a node, and its children's offsets relative to it.
fn measure<'r>(
    t: &Tree<'r>,
    kids: &[&'r RealmEntity],
    title_w: u32,
    sizes: &mut BTreeMap<&'r str, (u32, u32)>,
) -> (u32, u32, Vec<(&'r str, u32, u32)>) {
    if kids.is_empty() {
        return ((title_w + 6).max(LEAF_MIN_W), LEAF_H, vec![]);
    }
    let dims: Vec<(&str, u32, u32)> = kids
        .iter()
        .map(|k| {
            let (w, h) = size(t, k, sizes);
            (k.realm_id.as_str(), w, h)
        })
        .collect();
    let cols = (dims.len() as f64).sqrt().ceil() as usize;
    let mut offsets = Vec::new();
    let (mut y, mut inner_w) = (1u32, 0u32);
    for row in dims.chunks(cols) {
        let mut x = PAD;
        let rh = row.iter().map(|d| d.2).max().unwrap_or(0);
        for (id, w, _) in row {
            offsets.push((*id, x, y));
            x += w + H_GAP;
        }
        inner_w = inner_w.max(x - H_GAP);
        y += rh + V_GAP;
    }
    let w = (inner_w + PAD).max(title_w + 8);
    (w, y, offsets)
}

fn size<'r>(
    t: &Tree<'r>,
    e: &'r RealmEntity,
    sizes: &mut BTreeMap<&'r str, (u32, u32)>,
) -> (u32, u32) {
    if let Some(s) = sizes.get(e.realm_id.as_str()) {
        return *s;
    }
    let kids = t
        .children
        .get(e.realm_id.as_str())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let (w, h, _) = measure(t, kids, label_w(e), sizes);
    sizes.insert(&e.realm_id, (w, h));
    (w, h)
}

#[allow(clippy::too_many_arguments)]
fn place<'r>(
    t: &Tree<'r>,
    id: &'r str,
    kids: &[&'r RealmEntity],
    title_w: u32,
    x: u32,
    y: u32,
    depth: u32,
    sizes: &mut BTreeMap<&'r str, (u32, u32)>,
    out: &mut BTreeMap<String, Placed>,
) {
    let (w, h, offsets) = measure(t, kids, title_w, sizes);
    out.insert(
        id.to_string(),
        Placed {
            rect: Rect { x, y, w, h },
            depth,
            container: !kids.is_empty(),
        },
    );
    for (kid, dx, dy) in offsets {
        let e = kids
            .iter()
            .find(|k| k.realm_id == kid)
            .expect("child measured");
        let grand = t.children.get(kid).map(Vec::as_slice).unwrap_or(&[]);
        place(
            t,
            kid,
            grand,
            label_w(e),
            x + dx,
            y + dy,
            depth + 1,
            sizes,
            out,
        );
    }
}

pub fn layout(realm: &Realm) -> Layout {
    let t = tree(realm);
    let mut sizes = BTreeMap::new();
    let mut places = BTreeMap::new();
    let roots = t.roots.clone();
    place(
        &t,
        UNIVERSE_ID,
        &roots,
        "Universe".len() as u32,
        0,
        0,
        0,
        &mut sizes,
        &mut places,
    );
    let u = places[UNIVERSE_ID].rect;
    Layout {
        width: u.w,
        height: u.h,
        places,
    }
}

/// Structural guarantees, usable by any test: every place sits strictly
/// inside its parent, and siblings never overlap. Returns the first breach.
pub fn check(realm: &Realm, l: &Layout) -> Result<(), String> {
    let nested = |a: &Rect, b: &Rect| {
        b.x > a.x && b.y > a.y && b.x + b.w < a.x + a.w && b.y + b.h < a.y + a.h
    };
    let overlap = |a: &Rect, b: &Rect| {
        a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h
    };
    let ids: std::collections::BTreeSet<&str> =
        realm.entities.iter().map(|e| e.realm_id.as_str()).collect();
    let parent_of = |e: &RealmEntity| {
        e.parent
            .as_deref()
            .filter(|p| ids.contains(p))
            .unwrap_or(UNIVERSE_ID)
            .to_string()
    };
    for e in &realm.entities {
        let r = l
            .places
            .get(&e.realm_id)
            .ok_or(format!("{} not placed", e.realm_id))?;
        let p = parent_of(e);
        if !nested(&l.places[&p].rect, &r.rect) {
            return Err(format!("{} not inside {p}", e.realm_id));
        }
    }
    for a in &realm.entities {
        for b in &realm.entities {
            if a.realm_id < b.realm_id
                && parent_of(a) == parent_of(b)
                && overlap(&l.places[&a.realm_id].rect, &l.places[&b.realm_id].rect)
            {
                return Err(format!("{} overlaps {}", a.realm_id, b.realm_id));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_realm_is_just_the_universe() {
        let realm = Realm {
            grammar_version: realm_core::GRAMMAR_VERSION.into(),
            branch: None,
            ontology_version: String::new(),
            compiler_version: String::new(),
            source_digest: String::new(),
            epoch: navi_ontology::Timestamp(0),
            entities: vec![],
            edges: vec![],
            controls: vec![],
            hazards: vec![],
            agents: vec![],
            evidence: vec![],
        };
        let l = layout(&realm);
        assert_eq!(l.places.len(), 1);
        check(&realm, &l).unwrap();
    }
}
