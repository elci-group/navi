use crate::common::*;
use realm_core::{contract, wire, Line, Primitive, Realm, Token};
use realm_layout::{Layout, UNIVERSE_ID};
use std::fmt::Write;

const SX: u32 = 8;
const SY: u32 = 18;
const HUD_W: u32 = 470;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn dash(l: Line) -> &'static str {
    match l {
        Line::Solid | Line::Double => "",
        Line::Dashed => r#" stroke-dasharray="6 4""#,
        Line::Dotted => r#" stroke-dasharray="2 3""#,
    }
}

fn width(l: Line) -> &'static str {
    if l == Line::Double {
        "2.5"
    } else {
        "1.2"
    }
}

fn title(lines: &[String]) -> String {
    format!("<title>{}</title>", esc(&lines.join("\n")))
}

fn prov(p: &navi_ontology::Provenance) -> String {
    serde_json::to_string(p).unwrap_or_default()
}

pub fn render(realm: &Realm, layout: &Layout) -> String {
    let map_w = layout.width * SX;
    let map_h = layout.height * SY;
    let hud_h: u32 = realm
        .agents
        .iter()
        .map(|a| hud_lines(realm, a).len() as u32 + 1)
        .sum::<u32>()
        * 16;
    let legend: Vec<Primitive> = primitives_used(realm).into_iter().collect();
    let legend_h = (legend.len() as u32 + 2) * 16;
    let top = 40;
    let w = map_w + HUD_W + 40;
    let h = top + map_h.max(hud_h) + legend_h + 30;
    let mut s = String::new();
    let _ = write!(
        s,
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" font-family="ui-monospace, Menlo, Consolas, monospace" font-size="12">
<desc>{} · {} · {} · source {}</desc>
<rect x="0" y="0" width="{w}" height="{h}" fill="#101418"/>
<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#c9d1d9"/></marker></defs>
<text x="12" y="24" fill="#c9d1d9" font-size="14">REALM · {} · epoch {}</text>
"##,
        realm.grammar_version,
        realm.ontology_version,
        realm.compiler_version,
        realm.source_digest,
        esc(&realm.source_digest),
        realm.epoch
    );
    let _ = writeln!(s, r#"<g transform="translate(10,{top})">"#);

    // Places, parents before children.
    let mut order: Vec<(&String, &realm_layout::Placed)> = layout.places.iter().collect();
    order.sort_by_key(|(id, p)| (p.depth, (*id).clone()));
    for (id, p) in &order {
        let r = &p.rect;
        let (x, y, rw, rh) = (r.x * SX, r.y * SY, r.w * SX, r.h * SY);
        if *id == UNIVERSE_ID {
            let _ = writeln!(
                s,
                r##"<g data-realm-id="{UNIVERSE_ID}"><rect x="{x}" y="{y}" width="{rw}" height="{rh}" rx="6" fill="none" stroke="#3a4350" stroke-width="2"/><text x="{}" y="{}" fill="#8a8f98">U Universe — {}</text></g>"##,
                x + 8,
                y + 13,
                esc(Primitive::Universe.meaning())
            );
            continue;
        }
        let Some(e) = realm.entity(id) else { continue };
        let vc = &e.visual_contract;
        let tip = title(&[
            format!("{} {}", vc.glyph, e.name),
            format!("{} — {}", wire(&vc.primitive), vc.primitive.meaning()),
            format!(
                "class {} · trust {}",
                wire(&e.entity_class),
                wire(&e.trust_state)
            ),
            format!("realm id {}", e.realm_id),
            format!("sources {}", source_list(&e.source_ids)),
            format!("provenance {}", prov(&e.provenance)),
        ]);
        let opacity = if p.container { "0.07" } else { "0.22" };
        let _ = writeln!(
            s,
            r#"<g data-realm-id="{}" data-source-ids="{}" data-primitive="{}">{tip}<rect x="{x}" y="{y}" width="{rw}" height="{rh}" rx="4" fill="{}" fill-opacity="{opacity}" stroke="{}" stroke-width="{}"{}/>"#,
            esc(&e.realm_id),
            esc(&source_list(&e.source_ids)),
            wire(&vc.primitive),
            vc.fill.color(),
            vc.stroke.color(),
            width(vc.line),
            dash(vc.line)
        );
        let hz = hazard_mark(e);
        let hz_tok = e
            .risk
            .max_state
            .map(|st| match realm_core::grammar::hazard_primitive(st) {
                Primitive::Enemy => Token::Hostile,
                Primitive::Fog => Token::Fog,
                _ => Token::Unclassified,
            });
        if p.container {
            // One title line: children start on the next row.
            let _ = write!(
                s,
                r##"<text x="{}" y="{}"><tspan fill="{}">{} {}</tspan><tspan fill="#8a8f98" font-size="10">  {}</tspan>"##,
                x + 8,
                y + 13,
                vc.fill.color(),
                esc(&vc.glyph.to_string()),
                esc(&vc.label),
                esc(&markers(realm, e))
            );
            if let (Some(hz), Some(t)) = (&hz, hz_tok) {
                let _ = write!(
                    s,
                    r##"<tspan fill="{}" font-size="10">  {}</tspan>"##,
                    t.color(),
                    esc(hz)
                );
            }
            s.push_str("</text>\n");
        } else {
            let _ = writeln!(
                s,
                r##"<text x="{}" y="{}" fill="{}">{} {}</text>"##,
                x + 8,
                y + 14,
                vc.fill.color(),
                esc(&vc.glyph.to_string()),
                esc(&vc.label)
            );
            let _ = writeln!(
                s,
                r##"<text x="{}" y="{}" fill="#8a8f98" font-size="10">{}</text>"##,
                x + 8,
                y + 32,
                esc(&markers(realm, e))
            );
            if let (Some(hz), Some(t)) = (&hz, hz_tok) {
                let _ = writeln!(
                    s,
                    r##"<text x="{}" y="{}" fill="{}" font-size="10">{}</text>"##,
                    x + 8,
                    y + 50,
                    t.color(),
                    esc(hz)
                );
            }
        }
        s.push_str("</g>\n");
    }

    // Connections.
    for e in &realm.edges {
        let (Some(a), Some(b)) = (layout.places.get(&e.from), layout.places.get(&e.to)) else {
            continue;
        };
        let ((x1, y1), (x2, y2)) = (a.rect.center(), b.rect.center());
        let (x1, y1, x2, y2) = (x1 * SX, y1 * SY, x2 * SX, y2 * SY);
        let (mx, my) = ((x1 + x2) / 2, (y1 + y2) / 2 + 24);
        let vc = &e.visual_contract;
        let tip = title(&[
            format!(
                "{} {} → {}",
                wire(&vc.primitive),
                name(realm, &e.from),
                name(realm, &e.to)
            ),
            format!("{} — {}", vc.label, vc.primitive.meaning()),
            format!("sources {}", source_list(&e.source_ids)),
            format!("provenance {}", prov(&e.provenance)),
        ]);
        let _ = writeln!(
            s,
            r#"<g data-realm-id="{}" data-source-ids="{}" data-primitive="{}">{tip}<path d="M{x1},{y1} Q{mx},{my} {x2},{y2}" fill="none" stroke="{}" stroke-width="{}"{} marker-end="url(#arrow)" opacity="0.85"/></g>"#,
            esc(&e.realm_id),
            esc(&source_list(&e.source_ids)),
            wire(&vc.primitive),
            vc.stroke.color(),
            width(vc.line),
            dash(vc.line)
        );
    }

    // Controls: drawn on the boundary of what they protect.
    for c in &realm.controls {
        let vc = &c.visual_contract;
        let tip = title(&[
            format!("{} {} ({})", wire(&vc.primitive), c.name, wire(&c.status)),
            vc.primitive.meaning().to_string(),
            format!("sources {}", source_list(&c.source_ids)),
            format!("provenance {}", prov(&c.provenance)),
        ]);
        for p in &c.protects {
            let Some(pl) = layout.places.get(p) else {
                continue;
            };
            let (x, y, rw, rh) = (
                pl.rect.x * SX,
                pl.rect.y * SY,
                pl.rect.w * SX,
                pl.rect.h * SY,
            );
            let _ = writeln!(
                s,
                r##"<g data-realm-id="{}" data-source-ids="{}" data-primitive="{}">{tip}<rect x="{}" y="{}" width="{}" height="{}" rx="5" fill="none" stroke="{}" stroke-width="3" stroke-opacity="0.8"{}/><text x="{}" y="{}" fill="{}" font-size="11">{}</text></g>"##,
                esc(&c.realm_id),
                esc(&source_list(&c.source_ids)),
                wire(&vc.primitive),
                x as i64 - 3,
                y as i64 - 3,
                rw + 6,
                rh + 6,
                vc.fill.color(),
                dash(vc.line),
                x + rw - 14,
                y + rh - 4,
                vc.fill.color(),
                esc(&vc.glyph.to_string())
            );
        }
    }

    // Hazards: markers on their targets, styled by epistemic state.
    for h in &realm.hazards {
        let vc = &h.visual_contract;
        let actor = h.actor.as_deref().map_or("?", |a| name(realm, a));
        let tip = title(&[
            vc.label.clone(),
            format!("{} — {}", wire(&vc.primitive), vc.primitive.meaning()),
            format!(
                "view {} · estimator {}",
                wire(&h.view),
                h.confidence.estimator
            ),
            format!("actor {actor}"),
            format!("sources {}", source_list(&h.source_ids)),
            format!("evidence {}", prov(&h.provenance)),
        ]);
        for (i, t) in h.targets.iter().enumerate() {
            let Some(pl) = layout.places.get(t) else {
                continue;
            };
            let cx = (pl.rect.x + pl.rect.w) * SX - 14 - (i as u32 % 3) * 2;
            let cy = pl.rect.y * SY + 12;
            let _ = writeln!(
                s,
                r##"<g data-realm-id="{}" data-source-ids="{}" data-primitive="{}">{tip}<circle cx="{cx}" cy="{cy}" r="9" fill="{}" fill-opacity="{}" stroke="{}" stroke-width="1.5"{}/><text x="{cx}" y="{}" text-anchor="middle" fill="#ffffff" font-weight="bold">{}</text></g>"##,
                esc(&h.realm_id),
                esc(&source_list(&h.source_ids)),
                wire(&vc.primitive),
                vc.fill.color(),
                if vc.primitive == Primitive::Enemy {
                    "0.95"
                } else {
                    "0.45"
                },
                vc.stroke.color(),
                dash(vc.line),
                cy + 4,
                esc(&vc.glyph.to_string())
            );
        }
    }

    // Navi.
    for a in &realm.agents {
        let Some(pl) = a.location.as_deref().and_then(|l| layout.places.get(l)) else {
            continue;
        };
        let (cx, cy) = (pl.rect.x * SX + 4, pl.rect.y * SY + 4);
        let tip = title(&hud_lines(realm, a));
        let _ = writeln!(
            s,
            r##"<g data-realm-id="{}" data-source-ids="{}" data-primitive="navi">{tip}<circle cx="{cx}" cy="{cy}" r="10" fill="{}" stroke="#ffffff" stroke-width="1.5"/><text x="{cx}" y="{}" text-anchor="middle" fill="#ffffff" font-weight="bold">@</text></g>"##,
            esc(&a.realm_id),
            esc(&source_list(&a.source_ids)),
            Token::Navi.color(),
            cy + 4
        );
    }
    s.push_str("</g>\n");

    // HUD panel.
    let hx = map_w + 30;
    let mut y = top + 12;
    for a in &realm.agents {
        for (i, l) in hud_lines(realm, a).iter().enumerate() {
            let fill = if i == 0 {
                Token::Navi.color()
            } else if l.contains("HUMAN APPROVAL") {
                "#e0a030"
            } else {
                "#c9d1d9"
            };
            let _ = writeln!(
                s,
                r#"<text x="{hx}" y="{y}" fill="{fill}" xml:space="preserve">{}</text>"#,
                esc(l)
            );
            y += 16;
        }
        y += 16;
    }

    // Legend.
    let mut ly = top + map_h.max(hud_h) + 24;
    let _ = writeln!(
        s,
        r##"<text x="12" y="{ly}" fill="#8a8f98">LEGEND · {}</text>"##,
        esc(&realm.grammar_version)
    );
    for p in legend {
        ly += 16;
        let _ = writeln!(
            s,
            r##"<text x="20" y="{ly}" fill="#c9d1d9" xml:space="preserve">{}  {:<15} {}</text>"##,
            esc(&contract::glyph(p).to_string()),
            wire(&p),
            esc(p.meaning())
        );
    }
    s.push_str("</svg>\n");
    s
}
