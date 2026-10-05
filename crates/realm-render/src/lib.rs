//! Disposable renderers (directive §21). They draw Realm IR and nothing
//! else: no security logic, no inference. Each refuses to draw a realm that
//! fails [`realm_core::Realm::validate`].

mod common;
mod svg;
mod text;

pub use common::{hazard_mark, hud_lines, markers};
use realm_core::{Realm, RealmViolation};

#[derive(Debug)]
pub struct Refused(pub Vec<RealmViolation>);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "renderer refused realm: {} violation(s)", self.0.len())?;
        for v in &self.0 {
            writeln!(f, "  {v}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Refused {}

fn gate(realm: &Realm) -> Result<(), Refused> {
    let v = realm.validate();
    if v.is_empty() {
        Ok(())
    } else {
        Err(Refused(v))
    }
}

/// Terminal rendering: a box-drawn map plus edge/control/hazard/Navi panels.
pub fn text(realm: &Realm) -> Result<String, Refused> {
    gate(realm)?;
    Ok(text::render(realm, &realm_layout::layout(realm)))
}

/// Standalone SVG. Every element carries `data-realm-id`,
/// `data-source-ids` and a `<title>` with its provenance.
pub fn svg(realm: &Realm) -> Result<String, Refused> {
    gate(realm)?;
    Ok(svg::render(realm, &realm_layout::layout(realm)))
}
