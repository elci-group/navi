//! Visual contracts: how a realm object looks, as a pure function of its
//! semantics. Renderers map [`Token`]s to concrete colours through the
//! grammar-versioned [`Token::color`] palette and may not choose their own.

use crate::grammar::Primitive;
use crate::ir::*;
use crate::wire;
use navi_ontology::{EpistemicState, SafeguardStatus, TrustState};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Semantic colour roles. Fixed per grammar version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Token {
    Neutral,
    TrustTrusted,
    TrustUnverified,
    TrustDegraded,
    TrustCompromised,
    TrustUnknown,
    Hostile,
    Unclassified,
    Fog,
    ControlActive,
    ControlInactive,
    ControlUnknown,
    Navi,
    Road,
    Bridge,
    Teleport,
    Door,
}

impl Token {
    pub fn for_trust(t: TrustState) -> Self {
        match t {
            TrustState::Trusted => Self::TrustTrusted,
            TrustState::Unverified => Self::TrustUnverified,
            TrustState::Degraded => Self::TrustDegraded,
            TrustState::Compromised => Self::TrustCompromised,
            TrustState::Unknown => Self::TrustUnknown,
        }
    }

    /// The palette for `realm-grammar/0.1`. Hue carries meaning: green =
    /// trusted, amber = degraded, red = compromised/hostile, grey = unknown,
    /// violet = unclassified, blue = defensive.
    pub fn color(self) -> &'static str {
        match self {
            Self::Neutral => "#8a8f98",
            Self::TrustTrusted => "#2f8f5b",
            Self::TrustUnverified => "#6f8fa8",
            Self::TrustDegraded => "#c98a1b",
            Self::TrustCompromised => "#c0392b",
            Self::TrustUnknown => "#9aa0a6",
            Self::Hostile => "#e0312b",
            Self::Unclassified => "#8e5cc8",
            Self::Fog => "#b8bec6",
            Self::ControlActive => "#2b6cd4",
            Self::ControlInactive => "#9aa0a6",
            Self::ControlUnknown => "#7d8fb3",
            Self::Navi => "#14a6d9",
            Self::Road => "#5d6672",
            Self::Bridge => "#3a4350",
            Self::Teleport => "#8e5cc8",
            Self::Door => "#2b6cd4",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Line {
    Solid,
    Double,
    Dashed,
    Dotted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Badge {
    /// Trust degraded or compromised (§3 Corruption).
    Corruption,
    /// `valid_until` is before the realm epoch.
    Stale,
    /// At least one active control protects this.
    Guarded,
    /// The strongest hazard against this object, by epistemic state.
    Hazard(EpistemicState),
    /// A Navi is currently attending here.
    NaviFocus,
    /// Control exists but is not active / not observed active.
    Unenforced,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VisualContract {
    pub primitive: Primitive,
    pub glyph: char,
    pub fill: Token,
    pub stroke: Token,
    pub line: Line,
    pub badges: BTreeSet<Badge>,
    pub label: String,
}

pub fn glyph(p: Primitive) -> char {
    match p {
        Primitive::Universe => 'U',
        Primitive::World => 'W',
        Primitive::Region => 'R',
        Primitive::District => 'D',
        Primitive::Building => 'B',
        Primitive::Room => 'r',
        Primitive::Road => '-',
        Primitive::Bridge => '=',
        Primitive::Portal => 'P',
        Primitive::Door => '+',
        Primitive::Wall => '#',
        Primitive::Guard => 'G',
        Primitive::Object => 'o',
        Primitive::Vault => 'V',
        Primitive::Npc => 'n',
        Primitive::UnknownEntity => '?',
        Primitive::Enemy => '!',
        Primitive::Corruption => 'x',
        Primitive::Fog => '~',
        Primitive::Navi => '@',
        Primitive::Tool => 't',
        Primitive::Damage => 'X',
        Primitive::Healing => 'h',
        Primitive::Teleport => '>',
    }
}

pub fn entity(e: &RealmEntity) -> VisualContract {
    let mut badges = BTreeSet::new();
    if matches!(
        e.trust_state,
        TrustState::Degraded | TrustState::Compromised
    ) {
        badges.insert(Badge::Corruption);
    }
    if e.stale {
        badges.insert(Badge::Stale);
    }
    if !e.guarded_by.is_empty() {
        badges.insert(Badge::Guarded);
    }
    if let Some(s) = e.risk.max_state {
        badges.insert(Badge::Hazard(s));
    }
    if !e.focused_by.is_empty() {
        badges.insert(Badge::NaviFocus);
    }
    let hostile = e
        .hostility
        .is_some_and(|s| s >= crate::grammar::ENEMY_THRESHOLD);
    let stroke = if hostile {
        Token::Hostile
    } else if e.semantic_type == Primitive::UnknownEntity {
        Token::Unclassified
    } else {
        Token::Neutral
    };
    let line = if e.stale || e.trust_state == TrustState::Unknown {
        Line::Dashed
    } else if e.semantic_type.is_zone() {
        Line::Double
    } else {
        Line::Solid
    };
    VisualContract {
        primitive: e.semantic_type,
        glyph: glyph(e.semantic_type),
        fill: Token::for_trust(e.trust_state),
        stroke,
        line,
        badges,
        label: e.name.clone(),
    }
}

pub fn edge(e: &RealmEdge) -> VisualContract {
    let (stroke, line) = match e.semantic_type {
        Primitive::Bridge => (Token::Bridge, Line::Double),
        Primitive::Teleport => (Token::Teleport, Line::Dashed),
        Primitive::Door => (Token::Door, Line::Solid),
        _ => (Token::Road, Line::Solid),
    };
    VisualContract {
        primitive: e.semantic_type,
        glyph: glyph(e.semantic_type),
        fill: Token::Neutral,
        stroke,
        line,
        badges: BTreeSet::new(),
        label: wire(&e.kind),
    }
}

pub fn control(c: &RealmControl) -> VisualContract {
    let (fill, line, mut badges) = match c.status {
        SafeguardStatus::Active => (Token::ControlActive, Line::Solid, BTreeSet::new()),
        SafeguardStatus::Inactive => (
            Token::ControlInactive,
            Line::Dotted,
            BTreeSet::from([Badge::Unenforced]),
        ),
        SafeguardStatus::Unknown => (
            Token::ControlUnknown,
            Line::Dashed,
            BTreeSet::from([Badge::Unenforced]),
        ),
    };
    if c.status == SafeguardStatus::Active {
        badges.insert(Badge::Guarded);
    }
    VisualContract {
        primitive: c.semantic_type,
        glyph: glyph(c.semantic_type),
        fill,
        stroke: fill,
        line,
        badges,
        label: c.name.clone(),
    }
}

pub fn hazard(h: &RealmHazard) -> VisualContract {
    let (fill, line) = match h.semantic_type {
        Primitive::Enemy => (Token::Hostile, Line::Solid),
        Primitive::UnknownEntity => (Token::Unclassified, Line::Dashed),
        _ => (Token::Fog, Line::Dotted),
    };
    // Below the enemy threshold the claim is shown *as a question*.
    let q = if h.semantic_type == Primitive::Enemy {
        ""
    } else {
        "?"
    };
    VisualContract {
        primitive: h.semantic_type,
        glyph: glyph(h.semantic_type),
        fill,
        stroke: fill,
        line,
        badges: BTreeSet::from([Badge::Hazard(h.epistemic_state)]),
        label: format!(
            "{}{q} {} {}",
            h.claim,
            wire(&h.epistemic_state),
            h.confidence.percent
        ),
    }
}

pub fn agent(a: &RealmAgent) -> VisualContract {
    VisualContract {
        primitive: Primitive::Navi,
        glyph: glyph(Primitive::Navi),
        fill: Token::Navi,
        stroke: Token::Navi,
        line: Line::Solid,
        badges: BTreeSet::new(),
        label: match a.phase {
            Some(p) => format!("{} {}", a.name, wire(&p)),
            None => format!("{} idle", a.name),
        },
    }
}
