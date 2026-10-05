use navi_ontology::{ActionState, Gate, SafeguardStatus, TrustState};
use realm_core::{contract, grammar, wire, Primitive, Realm, RealmAgent, RealmEntity};
use std::collections::BTreeSet;

pub fn name<'r>(realm: &'r Realm, id: &'r str) -> &'r str {
    realm.entity(id).map_or(id, |e| e.name.as_str())
}

fn trust_mark(t: TrustState) -> &'static str {
    match t {
        TrustState::Trusted => "ok",
        TrustState::Unverified => "unv",
        TrustState::Degraded => "DEGRADED",
        TrustState::Compromised => "COMPROMISED",
        TrustState::Unknown => "trust?",
    }
}

/// The status line for an entity, built only from realm objects:
/// Navi focus first (never truncated away), corruption, trust, controls,
/// staleness.
pub fn markers(realm: &Realm, e: &RealmEntity) -> String {
    let mut parts = vec![];
    if !e.focused_by.is_empty() {
        parts.push("@".to_string());
    }
    if e.visual_contract
        .badges
        .contains(&realm_core::Badge::Corruption)
    {
        parts.push(contract::glyph(Primitive::Corruption).to_string());
    }
    parts.push(trust_mark(e.trust_state).to_string());
    for c in realm
        .controls
        .iter()
        .filter(|c| c.protects.contains(&e.realm_id))
    {
        let suffix = match c.status {
            SafeguardStatus::Active => "",
            SafeguardStatus::Inactive => "-",
            SafeguardStatus::Unknown => "?",
        };
        parts.push(format!("{}{suffix}", c.visual_contract.glyph));
    }
    if e.stale {
        parts.push("stale".into());
    }
    parts.join(" ")
}

/// The strongest hazard against an entity, e.g. `?SUSPICIOUS`. Shown on its
/// own line so the epistemic state is never truncated.
pub fn hazard_mark(e: &RealmEntity) -> Option<String> {
    e.risk.max_state.map(|s| {
        let g = contract::glyph(grammar::hazard_primitive(s));
        format!("{g}{}", wire(&s))
    })
}

fn gate_label(g: Gate) -> &'static str {
    match g {
        Gate::Autonomous => "autonomous",
        Gate::PolicyDependent => "policy approval",
        Gate::HumanApproval => "HUMAN APPROVAL REQUIRED",
    }
}

/// §8 HUD, bounded to structured telemetry — no free-form reasoning.
pub fn hud_lines(realm: &Realm, a: &RealmAgent) -> Vec<String> {
    let mut l = vec![format!("NAVI / {}  ({})", a.name, wire(&a.role))];
    l.push(format!("  PHASE      {}  at {}", wire(&a.phase), a.at));
    l.push(format!(
        "  TARGET     {}",
        a.location
            .as_deref()
            .map_or("?".to_string(), |x| path(realm, x))
    ));
    l.push(format!("  REASON     {}", a.reason));
    if let Some(h) = a
        .hypothesis
        .as_deref()
        .and_then(|h| realm.hazards.iter().find(|x| x.realm_id == h))
    {
        let q = if h.semantic_type == Primitive::Enemy {
            ""
        } else {
            "?"
        };
        l.push(format!(
            "  HYPOTHESIS {}{q}  {}",
            h.claim,
            wire(&h.epistemic_state)
        ));
        if !h.attack.is_empty() {
            let ids: Vec<_> = h.attack.iter().map(|x| x.as_str()).collect();
            l.push(format!("  ATT&CK     {}", ids.join(", ")));
        }
    }
    if let Some(c) = &a.confidence {
        l.push(format!("  CONFIDENCE {}  ({})", c.percent, c.estimator));
    }
    l.push(format!("  EXERCISING {}", wire(&a.authority)));
    l.push("  LOADOUT".into());
    for s in &a.loadout {
        let exp = if s.expired { "  [EXPIRED]" } else { "" };
        l.push(format!(
            "    {:<8} {:<24} {}{exp}",
            wire(&s.kind),
            wire(&s.authority),
            gate_label(s.gate)
        ));
    }
    if !a.actions.is_empty() {
        l.push("  ACTIONS".into());
        for act in &a.actions {
            let kind = a
                .loadout
                .iter()
                .find(|s| s.capability == act.capability)
                .map_or("?".into(), |s| wire(&s.kind));
            let note = match act.state {
                ActionState::Proposed => "  (awaiting authorisation)",
                ActionState::Executed => "  (command returned; effect unobserved)",
                ActionState::Succeeded => "  (effect observed; not yet verified)",
                _ => "",
            };
            l.push(format!(
                "    {kind} → {}  {}{note}",
                name(realm, &act.target),
                wire(&act.state)
            ));
        }
    }
    l
}

/// `org → prod → shop → api` style location path.
pub fn path(realm: &Realm, id: &str) -> String {
    let mut parts = vec![];
    let mut cur = realm.entity(id);
    while let Some(e) = cur {
        parts.push(e.name.as_str());
        if parts.len() > realm.entities.len() {
            break;
        }
        cur = e.parent.as_deref().and_then(|p| realm.entity(p));
    }
    parts.reverse();
    parts.join(" → ")
}

/// Primitives present in this realm, for the legend.
pub fn primitives_used(realm: &Realm) -> BTreeSet<Primitive> {
    let mut s = BTreeSet::from([Primitive::Universe]);
    s.extend(realm.entities.iter().map(|e| e.semantic_type));
    s.extend(realm.edges.iter().map(|e| e.semantic_type));
    s.extend(realm.controls.iter().map(|e| e.semantic_type));
    s.extend(realm.hazards.iter().map(|e| e.semantic_type));
    if !realm.agents.is_empty() {
        s.insert(Primitive::Navi);
    }
    if realm.entities.iter().any(|e| {
        matches!(
            e.trust_state,
            TrustState::Degraded | TrustState::Compromised
        )
    }) {
        s.insert(Primitive::Corruption);
    }
    s
}

pub fn source_list(sources: &[String]) -> String {
    sources.join(", ")
}
