//! Reverse resolution (directive §5, §26): from any object down to the raw
//! observations that caused it to exist.

use crate::SemanticGraph;
use navi_ontology::*;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExplainNode {
    pub id: String,
    pub kind: &'static str,
    pub summary: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<ExplainNode>,
}

/// The canonical (wire) name of an ontology enum value, e.g. `PROBABLE`.
/// Operator-facing text uses the ontology's vocabulary, not Rust's.
pub(crate) fn wire<T: Serialize>(t: &T) -> String {
    match serde_json::to_value(t) {
        Ok(serde_json::Value::String(s)) => s,
        Ok(v) => v.to_string(),
        Err(_) => "?".into(),
    }
}

impl ExplainNode {
    fn leaf(id: impl Into<String>, kind: &'static str, summary: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind,
            summary: summary.into(),
            children: vec![],
        }
    }

    /// Raw observation ids at the leaves of this tree.
    pub fn observations(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        self.collect(&mut out);
        out
    }

    fn collect(&self, out: &mut BTreeSet<String>) {
        if self.kind == "observation" {
            out.insert(self.id.clone());
        }
        self.children.iter().for_each(|c| c.collect(out));
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        self.render_into(&mut s, "", true, true);
        s
    }

    fn render_into(&self, out: &mut String, prefix: &str, last: bool, root: bool) {
        let (branch, next) = if root {
            ("", String::new())
        } else if last {
            ("└── ", format!("{prefix}    "))
        } else {
            ("├── ", format!("{prefix}│   "))
        };
        out.push_str(&format!(
            "{prefix}{branch}[{}] {}  {}\n",
            self.kind, self.id, self.summary
        ));
        for (i, c) in self.children.iter().enumerate() {
            c.render_into(out, &next, i + 1 == self.children.len(), false);
        }
    }
}

impl SemanticGraph {
    /// Explain any object by id. `None` if no such object exists.
    pub fn explain(&self, id: &str) -> Option<ExplainNode> {
        let mut path = BTreeSet::new();
        if let Ok(i) = ThreatId::new(id) {
            let t = self.threats.get(&i)?;
            let h = self.hypotheses.get(&t.hypothesis);
            let actor = t.actor.as_ref().map_or("?".to_string(), |a| a.to_string());
            let class = h.map_or("?".to_string(), |h| {
                format!("{} @ {}", wire(&h.state()), h.confidence())
            });
            let targets: Vec<_> = t.targets.iter().map(|t| t.to_string()).collect();
            return Some(ExplainNode {
                id: id.into(),
                kind: "threat",
                summary: format!(
                    "actor {actor} → {}; classification {class}",
                    targets.join(", ")
                ),
                children: vec![
                    self.explain_source(&SourceRef::Hypothesis(t.hypothesis.clone()), &mut path)
                ],
            });
        }
        if let Ok(i) = EntityId::new(id) {
            let e = self.entities.get(&i)?;
            return Some(ExplainNode {
                id: id.into(),
                kind: "entity",
                summary: format!("{} {:?}, trust {}", wire(&e.class), e.name, wire(&e.trust)),
                children: self.explain_prov(&e.provenance, &mut path),
            });
        }
        if let Ok(i) = RelationshipId::new(id) {
            let r = self.relationships.get(&i)?;
            return Some(ExplainNode {
                id: id.into(),
                kind: "relationship",
                summary: format!("{} {} {}", r.from, wire(&r.kind), r.to),
                children: self.explain_prov(&r.provenance, &mut path),
            });
        }
        if let Ok(i) = ActionId::new(id) {
            let a = self.actions.get(&i)?;
            let mut children =
                vec![self.explain_source(&SourceRef::Hypothesis(a.hypothesis.clone()), &mut path)];
            for t in &a.history {
                let (label, p) = match t {
                    ActionTransition::ObserveEffect { effect, .. } => ("effect", effect),
                    ActionTransition::Verify { evidence, .. } => ("verification", evidence),
                    ActionTransition::RollBack { evidence, .. } => ("rollback", evidence),
                    _ => continue,
                };
                children.push(ExplainNode {
                    id: format!("{id}/{label}"),
                    kind: "evidence",
                    summary: format!("{label} at {}", t.at()),
                    children: self.explain_prov(p, &mut path),
                });
            }
            return Some(ExplainNode {
                id: id.into(),
                kind: "action",
                summary: format!(
                    "{} via {} on {}: {}",
                    a.agent,
                    a.capability,
                    a.target,
                    wire(&a.state())
                ),
                children,
            });
        }
        let src = if let Ok(i) = HypothesisId::new(id) {
            self.hypotheses
                .contains_key(&i)
                .then_some(SourceRef::Hypothesis(i))
        } else if let Ok(i) = SafeguardId::new(id) {
            self.safeguards
                .contains_key(&i)
                .then_some(SourceRef::Safeguard(i))
        } else if let Ok(i) = ObservationId::new(id) {
            self.observations
                .contains_key(&i)
                .then_some(SourceRef::Observation(i))
        } else {
            None
        }?;
        Some(self.explain_source(&src, &mut path))
    }

    fn explain_prov(&self, p: &Provenance, path: &mut BTreeSet<String>) -> Vec<ExplainNode> {
        p.sources()
            .iter()
            .map(|s| self.explain_source(s, path))
            .collect()
    }

    fn explain_source(&self, s: &SourceRef, path: &mut BTreeSet<String>) -> ExplainNode {
        match s {
            SourceRef::Observation(id) => match self.observations.get(id) {
                Some(o) => {
                    let attrs = serde_json::to_string(&o.attributes).unwrap_or_default();
                    let raw = o
                        .raw_ref
                        .as_deref()
                        .map(|r| format!(" raw={r}"))
                        .unwrap_or_default();
                    ExplainNode::leaf(
                        id.to_string(),
                        "observation",
                        format!(
                            "{} {attrs} from {}/{} at {}{raw}",
                            o.kind, o.source.system, o.source.collector, o.observed_at
                        ),
                    )
                }
                None => ExplainNode::leaf(id.to_string(), "missing", "?"),
            },
            SourceRef::Derived { rule, inputs } => ExplainNode {
                id: format!("derived:{rule}"),
                kind: "derived",
                summary: format!("computed by rule {rule:?}"),
                children: inputs
                    .iter()
                    .map(|i| self.explain_source(i, path))
                    .collect(),
            },
            SourceRef::Hypothesis(id) => {
                let Some(h) = self.hypotheses.get(id) else {
                    return ExplainNode::leaf(id.to_string(), "missing", "?");
                };
                let attack: Vec<_> = h.attack.iter().map(|a| a.as_str()).collect();
                let attack = if attack.is_empty() {
                    String::new()
                } else {
                    format!(" ATT&CK {}", attack.join(","))
                };
                let summary = format!(
                    "{} — {} @ {}{attack}",
                    h.claim,
                    wire(&h.state()),
                    h.confidence()
                );
                self.guarded(id.to_string(), "hypothesis", summary, path, |g, path| {
                    g.explain_prov(&h.evidence(), path)
                })
            }
            SourceRef::Safeguard(id) => {
                let Some(sg) = self.safeguards.get(id) else {
                    return ExplainNode::leaf(id.to_string(), "missing", "?");
                };
                let summary = format!("{} {:?} ({})", wire(&sg.kind), sg.name, wire(&sg.status));
                self.guarded(id.to_string(), "safeguard", summary, path, |g, path| {
                    g.explain_prov(&sg.provenance, path)
                })
            }
            SourceRef::Action(id) => match self.actions.get(id) {
                Some(a) => {
                    let summary = format!("{} via {}", wire(&a.state()), a.capability);
                    self.guarded(id.to_string(), "action", summary, path, |g, path| {
                        vec![g.explain_source(&SourceRef::Hypothesis(a.hypothesis.clone()), path)]
                    })
                }
                None => ExplainNode::leaf(id.to_string(), "missing", "?"),
            },
        }
    }

    fn guarded(
        &self,
        id: String,
        kind: &'static str,
        summary: String,
        path: &mut BTreeSet<String>,
        children: impl FnOnce(&Self, &mut BTreeSet<String>) -> Vec<ExplainNode>,
    ) -> ExplainNode {
        if !path.insert(id.clone()) {
            return ExplainNode::leaf(id, kind, "(cycle)");
        }
        let c = children(self, path);
        path.remove(&id);
        ExplainNode {
            id,
            kind,
            summary,
            children: c,
        }
    }
}
