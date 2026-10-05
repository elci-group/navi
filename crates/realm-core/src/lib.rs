//! Realm core: the stable mapping from computational semantics to spatial
//! semantics (directive §3), the Realm Intermediate Representation (§4), and
//! the validator every renderer must pass before drawing (§19).
//!
//! The central rule: **a realm object's spatial meaning is a pure function of
//! its security semantics.** [`grammar`] decides the primitive, [`contract`]
//! decides how it looks, and [`Realm::validate`] recomputes both, so a
//! compiler bug or a tampered/forged RIR cannot paint an enemy, a wall or a
//! green "trusted" building that the semantics do not justify.

pub mod contract;
pub mod grammar;
mod ir;
mod traversal;
mod validate;

pub use contract::{Badge, Line, Token, VisualContract};
pub use grammar::{EpistemicView, Primitive, GRAMMAR_VERSION};
pub use ir::*;
pub use traversal::{BriefView, Movement, NextView, RouteStep, Waypoint};
pub use validate::{RealmViolation, RealmViolationCode};

/// The canonical wire name of an ontology enum value (e.g. `PROBABLE`).
pub fn wire<T: serde::Serialize>(t: &T) -> String {
    match serde_json::to_value(t) {
        Ok(serde_json::Value::String(s)) => s,
        Ok(v) => v.to_string(),
        Err(_) => "?".into(),
    }
}
