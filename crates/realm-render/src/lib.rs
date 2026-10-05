//! Disposable renderers (directive §21). They draw Realm IR and nothing
//! else: no security logic, no inference. Each refuses to draw a realm that
//! fails [`realm_core::Realm::validate`].

mod common;
mod dvr;
mod html;
mod lod;
mod svg;
mod text;

pub use common::{brief_lines, hazard_mark, hud_lines, markers, step_label};
pub use dvr::DvrFrame;
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

pub(crate) fn gate(realm: &Realm) -> Result<(), Refused> {
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
    Ok(text::render(realm, &realm_layout::layout(realm), None))
}

/// Terminal rendering of a level-of-detail view (§11, §12).
pub fn text_view(realm: &Realm, view: &realm_lod::View) -> Result<String, Refused> {
    let (projected, ctx) = lod::prepare(realm, view)?;
    Ok(text::render(
        &projected,
        &realm_layout::layout(&projected),
        Some(&ctx),
    ))
}

/// SVG rendering of a level-of-detail view (§11, §12).
pub fn svg_view(realm: &Realm, view: &realm_lod::View) -> Result<String, Refused> {
    let (projected, ctx) = lod::prepare(realm, view)?;
    Ok(svg::render(
        &projected,
        &realm_layout::layout(&projected),
        Some(&ctx),
    ))
}

/// Standalone SVG. Every element carries `data-realm-id`,
/// `data-source-ids` and a `<title>` with its provenance.
pub fn svg(realm: &Realm) -> Result<String, Refused> {
    gate(realm)?;
    Ok(svg::render(realm, &realm_layout::layout(realm), None))
}

/// Navi's trajectory as text: every waypoint, the route taken to reach it,
/// and the brief (where / why / what / confidence / next) at that moment.
pub fn trace(realm: &Realm) -> Result<String, Refused> {
    gate(realm)?;
    Ok(text::trace(realm))
}

/// Interactive HTML: the SVG realm plus a timeline that moves Navi along its
/// validated routes, and a panel that explains whatever is selected. The
/// page only displays precomputed realm data; it contains no security logic.
pub fn html(realm: &Realm) -> Result<String, Refused> {
    gate(realm)?;
    Ok(html::render(realm, &realm_layout::layout(realm)))
}

/// The security DVR page for a sequence of frames (see `realm-replay`).
pub fn dvr(frames: &[DvrFrame]) -> Result<String, Refused> {
    dvr::render(frames)
}
