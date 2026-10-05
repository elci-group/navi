//! The agent brief (directive §8, §25 Phase 2): for any agent event, WHERE
//! Navi is attending, WHY, WHAT it is doing, with what CONFIDENCE, and what
//! it declared it will do NEXT.
//!
//! Headless by design (§23: Navi must work with the renderer absent).
//! Everything is structured telemetry: no free-form reasoning is produced
//! or reconstructed. Belief is reported *as of the event*, and every value
//! carried forward from an earlier event says which event it came from.

use crate::SemanticGraph;
use navi_ontology::*;
use serde::Serialize;

/// A value together with the agent event (sequence number) that set it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Sourced<T> {
    pub value: T,
    pub from_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BriefWhere {
    pub target: Option<Sourced<EntityId>>,
    /// Entity names from the outermost container to the target.
    pub path: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BriefWhy {
    pub reason: String,
    pub objective: Option<Sourced<String>>,
    pub hypothesis: Option<Sourced<HypothesisId>>,
    pub claim: Option<String>,
    /// The hypothesis's epistemic state at the time of the event.
    pub state_then: Option<EpistemicState>,
    /// Observations the hypothesis rested on at the time of the event.
    pub evidence_then: Vec<ObservationId>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BriefWhat {
    pub phase: AgentPhase,
    pub authority: AuthorityLevel,
    pub action: Option<ActionId>,
    pub action_state_then: Option<ActionState>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BriefConfidence {
    /// Navi's own estimate, from the latest event that gave one for this
    /// hypothesis.
    pub navi: Sourced<Confidence>,
    /// What the hypothesis itself held at that time. Shown side by side so
    /// a stale agent estimate is visible rather than hidden.
    pub hypothesis_then: Option<Confidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BriefNext {
    /// What the agent declared. `None` renders as "undeclared".
    pub declared: Option<NextStep>,
    /// The phases the agent loop permits from here.
    pub legal: Vec<AgentPhase>,
    /// This agent's proposals still awaiting authorisation at the time.
    pub awaiting_authorisation: Vec<ActionId>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentBrief {
    pub agent: AgentId,
    pub name: String,
    pub seq: u64,
    pub at: Timestamp,
    #[serde(rename = "where")]
    pub where_: BriefWhere,
    pub why: BriefWhy,
    pub what: BriefWhat,
    pub confidence: Option<BriefConfidence>,
    pub next: BriefNext,
}

impl SemanticGraph {
    /// Containment path (outermost first) to `id`, by entity name.
    pub fn path_to(&self, id: &EntityId) -> Vec<String> {
        let mut parent = std::collections::BTreeMap::new();
        for r in self
            .relationships
            .values()
            .filter(|r| r.kind == RelationKind::Contains)
        {
            parent.entry(&r.to).or_insert(&r.from);
        }
        let mut out = vec![];
        let mut cur = Some(id);
        while let Some(c) = cur {
            if out.len() > self.entities.len() {
                break;
            }
            out.push(
                self.entities
                    .get(c)
                    .map_or_else(|| c.to_string(), |e| e.name.clone()),
            );
            cur = parent.get(c).copied();
        }
        out.reverse();
        out
    }

    /// Sequence numbers of an agent's events, in order.
    pub fn agent_seqs(&self, agent: &AgentId) -> Vec<u64> {
        self.agent_events
            .keys()
            .filter(|(a, _)| a == agent)
            .map(|(_, s)| *s)
            .collect()
    }

    /// Brief for `agent` at event `seq` (default: its latest event).
    pub fn brief(&self, agent: &AgentId, seq: Option<u64>) -> Option<AgentBrief> {
        let a = self.agents.get(agent)?;
        let events: Vec<&AgentEvent> = self
            .agent_events
            .iter()
            .filter(|((id, s), _)| id == agent && seq.is_none_or(|q| *s <= q))
            .map(|(_, e)| e)
            .collect();
        let ev = *events.last()?;
        if seq.is_some_and(|q| q != ev.seq) {
            return None;
        }
        let latest = |f: &dyn Fn(&AgentEvent) -> bool| events.iter().rev().find(|e| f(e)).copied();

        let target = latest(&|e| e.target.is_some()).map(|e| Sourced {
            value: e.target.clone().expect("filtered"),
            from_seq: e.seq,
        });
        let objective = latest(&|e| e.objective.is_some()).map(|e| Sourced {
            value: e.objective.clone().expect("filtered"),
            from_seq: e.seq,
        });
        let hyp_ev = latest(&|e| e.hypothesis.is_some());
        let hypothesis = hyp_ev.map(|e| Sourced {
            value: e.hypothesis.clone().expect("filtered"),
            from_seq: e.seq,
        });
        let h = hypothesis
            .as_ref()
            .and_then(|s| self.hypotheses.get(&s.value));
        let estimate = hypothesis.as_ref().and_then(|hs| {
            latest(&|e| e.hypothesis.as_ref() == Some(&hs.value) && e.confidence.is_some())
        });

        let action_state_then = ev
            .action
            .as_ref()
            .and_then(|x| self.actions.get(x))
            .and_then(|x| x.state_at(ev.at));
        let awaiting = self
            .actions
            .values()
            .filter(|x| {
                &x.agent == agent
                    && x.state_at(ev.at)
                        .is_some_and(|s| s == ActionState::Proposed)
            })
            .map(|x| x.id.clone())
            .collect();

        let mut evidence_then: Vec<ObservationId> = h
            .and_then(|h| h.evidence_at(ev.at))
            .map(|p| p.direct_observations().into_iter().cloned().collect())
            .unwrap_or_default();
        evidence_then.sort();
        evidence_then.dedup();

        Some(AgentBrief {
            agent: a.id.clone(),
            name: a.name.clone(),
            seq: ev.seq,
            at: ev.at,
            where_: BriefWhere {
                path: target
                    .as_ref()
                    .map(|t| self.path_to(&t.value))
                    .unwrap_or_default(),
                target,
            },
            why: BriefWhy {
                reason: ev.reason.clone(),
                objective,
                claim: h.map(|h| h.claim.clone()),
                state_then: h.and_then(|h| h.state_at(ev.at)),
                evidence_then,
                hypothesis,
            },
            what: BriefWhat {
                phase: ev.phase,
                authority: ev.authority,
                action: ev.action.clone(),
                action_state_then,
            },
            confidence: estimate.map(|e| BriefConfidence {
                navi: Sourced {
                    value: e.confidence.clone().expect("filtered"),
                    from_seq: e.seq,
                },
                hypothesis_then: h.and_then(|h| h.confidence_at(ev.at)).cloned(),
            }),
            next: BriefNext {
                declared: ev.next.clone(),
                legal: ev.phase.successors(),
                awaiting_authorisation: awaiting,
            },
        })
    }
}

fn w<T: Serialize>(t: &T) -> String {
    crate::explain::wire(t)
}

fn carried<T>(s: &Sourced<T>, now: u64) -> String {
    if s.from_seq == now {
        String::new()
    } else {
        format!("  (since #{})", s.from_seq)
    }
}

impl AgentBrief {
    /// Plain-text rendering (the headless "click on Navi").
    pub fn render(&self, g: &SemanticGraph) -> String {
        let name = |id: &EntityId| {
            g.entities
                .get(id)
                .map_or_else(|| id.to_string(), |e| e.name.clone())
        };
        let mut l = vec![format!(
            "NAVI / {}  event #{} at {}",
            self.name, self.seq, self.at
        )];
        match &self.where_.target {
            Some(t) => l.push(format!(
                "WHERE       {}{}",
                self.where_.path.join(" → "),
                carried(t, self.seq)
            )),
            None => l.push("WHERE       ?  (no target declared yet)".into()),
        }
        l.push(format!("WHY         {}", self.why.reason));
        if let Some(o) = &self.why.objective {
            l.push(format!("  objective {}{}", o.value, carried(o, self.seq)));
        }
        if let Some(h) = &self.why.hypothesis {
            let state = self.why.state_then.map_or("?".into(), |s| w(&s));
            let q = if self
                .why
                .state_then
                .is_some_and(|s| s >= EpistemicState::Probable)
            {
                ""
            } else {
                "?"
            };
            l.push(format!(
                "  believes  {}{q} — {state} at the time  [{}]{}",
                self.why.claim.as_deref().unwrap_or("?"),
                h.value,
                carried(h, self.seq)
            ));
            let ev: Vec<_> = self.why.evidence_then.iter().map(|o| o.as_str()).collect();
            l.push(format!(
                "  evidence  {}",
                if ev.is_empty() {
                    "—".into()
                } else {
                    ev.join(", ")
                }
            ));
        }
        let act = match (&self.what.action, self.what.action_state_then) {
            (Some(a), Some(s)) => format!("  on {a} ({})", w(&s)),
            (Some(a), None) => format!("  on {a}"),
            _ => String::new(),
        };
        l.push(format!(
            "WHAT        {} exercising {}{act}",
            w(&self.what.phase),
            w(&self.what.authority)
        ));
        match &self.confidence {
            Some(c) => {
                let held = c.hypothesis_then.as_ref().map_or(String::new(), |h| {
                    let note = if h.basis_points() == c.navi.value.basis_points() {
                        ""
                    } else {
                        "  ≠ Navi's estimate"
                    };
                    format!("; hypothesis held {:.0}%{note}", h.value() * 100.0)
                });
                l.push(format!(
                    "CONFIDENCE  {}{held}{}",
                    c.navi.value,
                    carried(&c.navi, self.seq)
                ));
            }
            None => l.push("CONFIDENCE  —  (no estimate given)".into()),
        }
        match &self.next.declared {
            Some(n) => {
                let tgt = n
                    .target
                    .as_ref()
                    .map_or(String::new(), |t| format!(" → {}", name(t)));
                l.push(format!("NEXT        {}{tgt}: {}", w(&n.phase), n.intent));
            }
            None => l.push("NEXT        undeclared".into()),
        }
        let legal: Vec<_> = self.next.legal.iter().map(w).collect();
        l.push(format!("  legal     {}", legal.join(", ")));
        if !self.next.awaiting_authorisation.is_empty() {
            let a: Vec<_> = self
                .next
                .awaiting_authorisation
                .iter()
                .map(|x| x.as_str())
                .collect();
            l.push(format!("  awaiting  {}", a.join(", ")));
        }
        l.join("\n") + "\n"
    }
}
