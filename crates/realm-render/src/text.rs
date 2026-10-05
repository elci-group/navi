use crate::common::*;
use realm_core::{contract, wire, Line, Primitive, Realm};
use realm_layout::{Layout, Rect, UNIVERSE_ID};

struct Canvas {
    w: usize,
    cells: Vec<Vec<char>>,
}

impl Canvas {
    fn new(w: u32, h: u32) -> Self {
        Self {
            w: w as usize,
            cells: vec![vec![' '; w as usize]; h as usize],
        }
    }

    fn put(&mut self, x: u32, y: u32, c: char) {
        if let Some(row) = self.cells.get_mut(y as usize) {
            if let Some(cell) = row.get_mut(x as usize) {
                *cell = c;
            }
        }
    }

    /// Write `s` from `x`, never past `max_x` (exclusive); truncates with '…'.
    fn puts(&mut self, x: u32, y: u32, s: &str, max_x: u32) {
        let room = max_x.saturating_sub(x) as usize;
        let n = s.chars().count();
        let text: String = if n <= room {
            s.to_string()
        } else if room > 0 {
            s.chars().take(room - 1).chain(['…']).collect()
        } else {
            String::new()
        };
        for (i, c) in text.chars().enumerate() {
            self.put(x + i as u32, y, c);
        }
    }

    fn frame(&mut self, r: &Rect, line: Option<Line>) {
        let (h, v, tl, tr, bl, br) = match line {
            None => ('━', '┃', '┏', '┓', '┗', '┛'),
            Some(Line::Double) => ('═', '║', '╔', '╗', '╚', '╝'),
            Some(Line::Dashed) => ('╌', '╎', '┌', '┐', '└', '┘'),
            Some(Line::Dotted) => ('┈', '┊', '┌', '┐', '└', '┘'),
            Some(Line::Solid) => ('─', '│', '┌', '┐', '└', '┘'),
        };
        let (x1, y1) = (r.x + r.w - 1, r.y + r.h - 1);
        for x in r.x..=x1 {
            self.put(x, r.y, h);
            self.put(x, y1, h);
        }
        for y in r.y..=y1 {
            self.put(r.x, y, v);
            self.put(x1, y, v);
        }
        self.put(r.x, r.y, tl);
        self.put(x1, r.y, tr);
        self.put(r.x, y1, bl);
        self.put(x1, y1, br);
        // clear interior (children are drawn afterwards)
        for y in r.y + 1..y1 {
            for x in r.x + 1..x1 {
                self.put(x, y, ' ');
            }
        }
    }

    fn finish(self) -> String {
        let mut s = String::new();
        for row in self.cells {
            let line: String = row.into_iter().collect();
            s.push_str(line.trim_end());
            s.push('\n');
        }
        debug_assert!(self.w > 0 || s.is_empty() || s == "\n");
        s
    }
}

pub fn render(realm: &Realm, layout: &Layout) -> String {
    let mut cv = Canvas::new(layout.width, layout.height);
    let mut order: Vec<(&String, &realm_layout::Placed)> = layout.places.iter().collect();
    order.sort_by_key(|(id, p)| (p.depth, (*id).clone()));
    for (id, p) in order {
        let r = &p.rect;
        if id == UNIVERSE_ID {
            cv.frame(r, None);
            cv.puts(
                r.x + 2,
                r.y,
                &format!(" {} Universe ", contract::glyph(Primitive::Universe)),
                r.x + r.w - 2,
            );
            continue;
        }
        let Some(e) = realm.entity(id) else { continue };
        let vc = &e.visual_contract;
        cv.frame(r, Some(vc.line));
        let max = r.x + r.w - 1;
        if p.container {
            let hz = hazard_mark(e).map(|h| format!(" {h}")).unwrap_or_default();
            let title = format!(" {} {} · {}{hz} ", vc.glyph, vc.label, markers(realm, e));
            cv.puts(r.x + 2, r.y, &title, max - 1);
        } else {
            cv.puts(
                r.x + 2,
                r.y + 1,
                &format!("{} {}", vc.glyph, vc.label),
                max - 1,
            );
            cv.puts(r.x + 2, r.y + 2, &markers(realm, e), max - 1);
            if let Some(h) = hazard_mark(e) {
                cv.puts(r.x + 2, r.y + 3, &h, max - 1);
            }
        }
    }

    let banner = realm
        .banner()
        .map_or(String::new(), |b| format!("!!! {b} !!!\n"));
    let mut out = format!(
        "{banner}REALM  {}  ·  {}  ·  {}\nsource {}  epoch {}\n\n",
        realm.grammar_version,
        realm.ontology_version,
        realm.compiler_version,
        realm.source_digest,
        realm.epoch
    );
    out.push_str(&cv.finish());

    if !realm.edges.is_empty() {
        out.push_str("\nCONNECTIONS\n");
        for e in &realm.edges {
            out.push_str(&format!(
                "  {} {:<9} {} → {}  ({})  [{}]\n",
                e.visual_contract.glyph,
                wire(&e.semantic_type),
                name(realm, &e.from),
                name(realm, &e.to),
                e.visual_contract.label,
                source_list(&e.source_ids)
            ));
        }
    }
    if !realm.controls.is_empty() {
        out.push_str("\nCONTROLS\n");
        for c in &realm.controls {
            let targets: Vec<_> = c.protects.iter().map(|p| name(realm, p)).collect();
            let d3: Vec<_> = c.d3fend.iter().map(|d| d.as_str()).collect();
            let d3 = if d3.is_empty() {
                String::new()
            } else {
                format!("  D3FEND {}", d3.join(","))
            };
            out.push_str(&format!(
                "  {} {:<5} {:<18} {:<8} protects {}{d3}  [{}]\n",
                c.visual_contract.glyph,
                wire(&c.semantic_type),
                c.name,
                wire(&c.status).to_uppercase(),
                targets.join(", "),
                source_list(&c.source_ids)
            ));
        }
    }
    if !realm.hazards.is_empty() {
        out.push_str("\nHAZARDS\n");
        for h in &realm.hazards {
            let actor = h.actor.as_deref().map_or("?", |a| name(realm, a));
            let targets: Vec<_> = h.targets.iter().map(|t| name(realm, t)).collect();
            out.push_str(&format!(
                "  {} {}  ({})  actor {actor} → {}  view {}  [{}]\n",
                h.visual_contract.glyph,
                h.visual_contract.label,
                h.confidence.estimator,
                targets.join(", "),
                wire(&h.view),
                source_list(&h.source_ids)
            ));
        }
    }
    for a in &realm.agents {
        out.push('\n');
        for l in hud_lines(realm, a) {
            out.push_str(&l);
            out.push('\n');
        }
    }
    out.push_str(&format!("\nLEGEND ({})\n", realm.grammar_version));
    for p in primitives_used(realm) {
        out.push_str(&format!(
            "  {} {:<15} {}\n",
            contract::glyph(p),
            wire(&p),
            p.meaning()
        ));
    }
    out.push_str("  markers: ok/unv/trust? trust · ~ ? ! hazard state · # + G controls (? unknown, - inactive) · @ Navi\n");
    out
}

pub fn trace(realm: &Realm) -> String {
    let mut out = realm
        .banner()
        .map_or(String::new(), |b| format!("!!! {b} !!!\n\n"));
    for a in &realm.agents {
        out.push_str(&format!(
            "TRAJECTORY  {} ({})  ·  {} waypoint(s)\n",
            a.name,
            wire(&a.role),
            a.trajectory.len()
        ));
        for w in &a.trajectory {
            let at = w.location.as_deref().map_or("?", |l| name(realm, l));
            out.push_str(&format!(
                "\n#{:<3} {}  {:<12} @ {at}\n",
                w.seq,
                w.at,
                wire(&w.phase)
            ));
            for step in &w.route {
                out.push_str(&format!("      move  {}\n", step_label(realm, step)));
            }
            for l in brief_lines(realm, w) {
                out.push_str(&format!("      {l}\n"));
            }
        }
        out.push('\n');
    }
    out
}
