//! Projection of a realm through a level-of-detail view. The original realm
//! is validated, the view is checked for concealment, and only then is the
//! projection (visible places; everything else re-anchored) drawn.

use crate::{gate, Refused};
use realm_core::{contract, wire};
use realm_core::{Realm, RealmViolation, RealmViolationCode};
use realm_lod::{Aggregate, View};
use std::collections::BTreeSet;

pub(crate) struct ViewCtx<'a> {
    pub original: &'a Realm,
    pub view: &'a View,
}

impl ViewCtx<'_> {
    pub fn original_name<'b>(&'b self, id: &'b str) -> &'b str {
        self.original.entity(id).map_or(id, |e| e.name.as_str())
    }
}

fn dedup(v: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    v.into_iter().filter(|x| seen.insert(x.clone())).collect()
}

pub(crate) fn prepare<'a>(
    realm: &'a Realm,
    view: &'a View,
) -> Result<(Realm, ViewCtx<'a>), Refused> {
    gate(realm)?;
    let problems = view.check(realm);
    if !problems.is_empty() {
        return Err(Refused(
            problems
                .into_iter()
                .map(|m| RealmViolation::new(RealmViolationCode::Concealment, "view", m))
                .collect(),
        ));
    }
    let anchor = |id: &str| view.anchor(realm, id);
    let mut p = realm.clone();
    p.entities.retain(|e| view.is_visible(&e.realm_id));
    for e in &mut p.edges {
        e.from = anchor(&e.from);
        e.to = anchor(&e.to);
    }
    p.edges.retain(|e| e.from != e.to);
    for h in &mut p.hazards {
        h.targets = dedup(h.targets.iter().map(|t| anchor(t)).collect());
        h.actor = h.actor.as_deref().map(anchor);
    }
    for c in &mut p.controls {
        c.protects = dedup(c.protects.iter().map(|t| anchor(t)).collect());
    }
    for a in &mut p.agents {
        a.location = a.location.as_deref().map(anchor);
    }
    Ok((
        p,
        ViewCtx {
            original: realm,
            view,
        },
    ))
}

pub(crate) fn aggregate_line(a: &Aggregate) -> String {
    let x = if a.corruption { " x" } else { "" };
    format!("⊞{} inside{x}", a.hidden)
}

pub(crate) fn aggregate_hazard(a: &Aggregate) -> Option<String> {
    a.max_hazard.map(|s| {
        let g = contract::glyph(realm_core::grammar::hazard_primitive(s));
        format!("⊞{g}{}", wire(&s))
    })
}
