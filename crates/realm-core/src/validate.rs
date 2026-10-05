//! The renderer-side gate (directive §19): a renderer calls
//! [`Realm::validate`] and refuses to draw anything that fails. It trusts
//! nothing the compiler said — it recomputes every primitive and visual
//! contract from the semantics carried alongside.

use crate::contract;
use crate::grammar::{self, Primitive};
use crate::ir::*;
use navi_ontology::{Gate, ONTOLOGY_VERSION};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RealmViolationCode {
    /// Realm speaks a different grammar/ontology; meanings could drift.
    VersionMismatch,
    DuplicateId,
    /// §19 entity without source.
    MissingSource,
    DanglingReference,
    /// Primitive not what the grammar derives from the semantics.
    SemanticMismatch,
    /// Visual contract not what the semantics dictate.
    ContractMismatch,
    /// Derived cross-references (risk, guards, focus) disagree with the realm.
    InconsistentDerivation,
    /// §10 UI affordance exceeds actual authority.
    AuthorityOverreach,
    ContainmentCycle,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct RealmViolation {
    pub code: RealmViolationCode,
    pub subject: String,
    pub message: String,
}

impl fmt::Display for RealmViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} [{}]: {}", self.code, self.subject, self.message)
    }
}

struct Out(Vec<RealmViolation>);

impl Out {
    fn push(&mut self, code: RealmViolationCode, subject: &str, message: impl Into<String>) {
        self.0.push(RealmViolation {
            code,
            subject: subject.to_string(),
            message: message.into(),
        });
    }
}

impl Realm {
    pub fn validate(&self) -> Vec<RealmViolation> {
        use RealmViolationCode as C;
        let mut out = Out(Vec::new());

        if self.grammar_version != grammar::GRAMMAR_VERSION {
            out.push(
                C::VersionMismatch,
                "realm",
                format!(
                    "grammar {:?}, renderer speaks {:?}",
                    self.grammar_version,
                    grammar::GRAMMAR_VERSION
                ),
            );
        }
        if self.ontology_version != ONTOLOGY_VERSION {
            out.push(
                C::VersionMismatch,
                "realm",
                format!(
                    "ontology {:?}, renderer speaks {ONTOLOGY_VERSION:?}",
                    self.ontology_version
                ),
            );
        }

        // Identity and sourcing.
        let mut seen = BTreeSet::new();
        for id in self.all_ids() {
            if !seen.insert(id) {
                out.push(C::DuplicateId, id, "realm id appears more than once");
            }
        }
        let sourced = |id: &str, sources: &[String], out: &mut Out| match sources.first() {
            None => out.push(C::MissingSource, id, "no source ids"),
            Some(first) if realm_id(first) != id => out.push(
                C::MissingSource,
                id,
                format!("realm id does not derive from primary source {first}"),
            ),
            _ => {}
        };
        for e in &self.entities {
            sourced(&e.realm_id, &e.source_ids, &mut out);
        }
        for e in &self.edges {
            sourced(&e.realm_id, &e.source_ids, &mut out);
        }
        for c in &self.controls {
            sourced(&c.realm_id, &c.source_ids, &mut out);
        }
        for h in &self.hazards {
            sourced(&h.realm_id, &h.source_ids, &mut out);
        }
        for a in &self.agents {
            sourced(&a.realm_id, &a.source_ids, &mut out);
            if a.source_ids.len() < 2 {
                out.push(
                    C::MissingSource,
                    &a.realm_id,
                    "agent state must cite the agent event it comes from",
                );
            }
        }

        // References.
        let places: BTreeSet<&str> = self.entities.iter().map(|e| e.realm_id.as_str()).collect();
        let hazards: BTreeSet<&str> = self.hazards.iter().map(|h| h.realm_id.as_str()).collect();
        let need = |subject: &str, what: &str, id: &str, set: &BTreeSet<&str>, out: &mut Out| {
            if !set.contains(id) {
                out.push(
                    C::DanglingReference,
                    subject,
                    format!("{what} {id} does not exist"),
                );
            }
        };
        for e in &self.entities {
            if let Some(p) = &e.parent {
                need(&e.realm_id, "parent", p, &places, &mut out);
            }
            for h in &e.risk.hazards {
                need(&e.realm_id, "hazard", h, &hazards, &mut out);
            }
        }
        for e in &self.edges {
            need(&e.realm_id, "endpoint", &e.from, &places, &mut out);
            need(&e.realm_id, "endpoint", &e.to, &places, &mut out);
        }
        for c in &self.controls {
            for p in c.protects.iter().chain(&c.enforced_by) {
                need(&c.realm_id, "entity", p, &places, &mut out);
            }
        }
        for h in &self.hazards {
            for p in h.actor.iter().chain(&h.targets) {
                need(&h.realm_id, "entity", p, &places, &mut out);
            }
        }
        for a in &self.agents {
            if let Some(l) = &a.location {
                need(&a.realm_id, "location", l, &places, &mut out);
            }
            if let Some(h) = &a.hypothesis {
                need(&a.realm_id, "hypothesis", h, &hazards, &mut out);
            }
            for act in &a.actions {
                need(&act.realm_id, "target", &act.target, &places, &mut out);
            }
        }

        // Containment must be a forest.
        for e in &self.entities {
            let mut cur = e.parent.as_deref();
            let mut hops = 0;
            while let Some(p) = cur {
                hops += 1;
                if p == e.realm_id || hops > self.entities.len() {
                    out.push(C::ContainmentCycle, &e.realm_id, "containment chain loops");
                    break;
                }
                cur = self.entity(p).and_then(|x| x.parent.as_deref());
            }
        }

        // Derived cross-references must agree with the realm.
        let mut risk: BTreeMap<&str, (BTreeSet<&str>, Option<_>)> = BTreeMap::new();
        let mut hostility: BTreeMap<&str, _> = BTreeMap::new();
        for h in &self.hazards {
            for t in &h.targets {
                let r = risk.entry(t.as_str()).or_default();
                r.0.insert(h.realm_id.as_str());
                r.1 = r.1.max(Some(h.epistemic_state));
            }
            if let Some(a) = &h.actor {
                let e = hostility.entry(a.as_str()).or_insert(h.epistemic_state);
                *e = (*e).max(h.epistemic_state);
            }
        }
        let mut guards: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for c in &self.controls {
            if c.status == navi_ontology::SafeguardStatus::Active {
                for p in &c.protects {
                    guards
                        .entry(p.as_str())
                        .or_default()
                        .insert(c.realm_id.as_str());
                }
            }
        }
        let mut focus: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for a in &self.agents {
            if let Some(l) = &a.location {
                focus
                    .entry(l.as_str())
                    .or_default()
                    .insert(a.realm_id.as_str());
            }
        }
        for e in &self.entities {
            let id = e.realm_id.as_str();
            let (want_h, want_max) = risk.get(id).cloned().unwrap_or_default();
            let have_h: BTreeSet<&str> = e.risk.hazards.iter().map(String::as_str).collect();
            if have_h != want_h || e.risk.max_state != want_max {
                out.push(
                    C::InconsistentDerivation,
                    id,
                    "risk does not match the hazards that target it",
                );
            }
            if e.hostility != hostility.get(id).copied() {
                out.push(
                    C::InconsistentDerivation,
                    id,
                    "hostility does not match the hazards naming it as actor",
                );
            }
            let have_g: BTreeSet<&str> = e.guarded_by.iter().map(String::as_str).collect();
            if have_g != guards.get(id).cloned().unwrap_or_default() {
                out.push(
                    C::InconsistentDerivation,
                    id,
                    "guarded_by does not match active controls",
                );
            }
            let have_f: BTreeSet<&str> = e.focused_by.iter().map(String::as_str).collect();
            if have_f != focus.get(id).cloned().unwrap_or_default() {
                out.push(
                    C::InconsistentDerivation,
                    id,
                    "focused_by does not match agent locations",
                );
            }
            if e.stale != e.valid_until.is_some_and(|v| v < self.epoch) {
                out.push(
                    C::InconsistentDerivation,
                    id,
                    "stale flag disagrees with valid_until/epoch",
                );
            }
        }

        // Semantics: recompute every primitive from the grammar.
        for e in &self.entities {
            let want = grammar::entity_primitive(e.entity_class, e.trust_state, e.hostility);
            if e.semantic_type != want {
                out.push(
                    C::SemanticMismatch,
                    &e.realm_id,
                    format!("is {:?}, grammar says {want:?}", e.semantic_type),
                );
            }
            if e.visual_contract != contract::entity(e) {
                out.push(
                    C::ContractMismatch,
                    &e.realm_id,
                    "visual contract not derived from semantics",
                );
            }
        }
        for e in &self.edges {
            let crosses = self.zone_of(&e.from) != self.zone_of(&e.to);
            if crosses != e.crosses_boundary {
                out.push(
                    C::InconsistentDerivation,
                    &e.realm_id,
                    "crosses_boundary disagrees with containment",
                );
            }
            match grammar::edge_primitive(e.kind, crosses) {
                Some(want) if want == e.semantic_type => {}
                Some(want) => out.push(
                    C::SemanticMismatch,
                    &e.realm_id,
                    format!("is {:?}, grammar says {want:?}", e.semantic_type),
                ),
                None => out.push(
                    C::SemanticMismatch,
                    &e.realm_id,
                    "containment is nesting, not an edge",
                ),
            }
            if e.visual_contract != contract::edge(e) {
                out.push(
                    C::ContractMismatch,
                    &e.realm_id,
                    "visual contract not derived from semantics",
                );
            }
        }
        for c in &self.controls {
            let want = grammar::control_primitive(c.kind);
            if c.semantic_type != want {
                out.push(
                    C::SemanticMismatch,
                    &c.realm_id,
                    format!("is {:?}, grammar says {want:?}", c.semantic_type),
                );
            }
            if c.visual_contract != contract::control(c) {
                out.push(
                    C::ContractMismatch,
                    &c.realm_id,
                    "visual contract not derived from semantics",
                );
            }
        }
        for h in &self.hazards {
            let want = grammar::hazard_primitive(h.epistemic_state);
            if h.semantic_type != want {
                out.push(
                    C::SemanticMismatch,
                    &h.realm_id,
                    format!("is {:?}, grammar says {want:?}", h.semantic_type),
                );
            }
            let technique = h.attack.iter().any(|a| !a.is_tactic());
            let view = grammar::epistemic_view(h.epistemic_state, technique);
            if h.view != view {
                out.push(
                    C::SemanticMismatch,
                    &h.realm_id,
                    format!("view {:?}, grammar says {view:?}", h.view),
                );
            }
            if h.confidence.percent != ConfidenceView::percent_label(h.confidence.basis_points)
                || h.confidence.estimator.trim().is_empty()
            {
                out.push(
                    C::ContractMismatch,
                    &h.realm_id,
                    "confidence label/estimator inconsistent",
                );
            }
            if h.visual_contract != contract::hazard(h) {
                out.push(
                    C::ContractMismatch,
                    &h.realm_id,
                    "visual contract not derived from semantics",
                );
            }
        }
        for a in &self.agents {
            if a.semantic_type != Primitive::Navi {
                out.push(C::SemanticMismatch, &a.realm_id, "agents are Navi");
            }
            if a.visual_contract != contract::agent(a) {
                out.push(
                    C::ContractMismatch,
                    &a.realm_id,
                    "visual contract not derived from semantics",
                );
            }
            // Authority fidelity: the HUD may only show what Navi holds.
            let held: BTreeSet<&str> = a.loadout.iter().map(|s| s.capability.as_str()).collect();
            for act in &a.actions {
                if !held.contains(act.capability.as_str()) {
                    out.push(
                        C::AuthorityOverreach,
                        &act.realm_id,
                        format!("{} is not in {}'s loadout", act.capability, a.realm_id),
                    );
                }
            }
            for s in &a.loadout {
                let floor = s.authority.max(s.kind.minimum_authority());
                if floor.mutates_reality() && s.gate == Gate::Autonomous {
                    out.push(
                        C::AuthorityOverreach,
                        &a.realm_id,
                        format!(
                            "{} mutates reality but is shown as autonomous",
                            s.capability
                        ),
                    );
                }
            }
            let top = a.loadout.iter().map(|s| s.authority).max();
            if top.is_none_or(|t| a.authority > t)
                && a.authority > navi_ontology::AuthorityLevel::Observe
            {
                out.push(
                    C::AuthorityOverreach,
                    &a.realm_id,
                    format!("exercising {:?} beyond its loadout", a.authority),
                );
            }
        }

        out.0.sort();
        out.0
    }
}
