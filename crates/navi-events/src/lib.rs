//! The incident log (directive §15, §16): security state as an append-only
//! sequence of events. The semantic graph at any instant is the fold of
//! the log up to that instant, and **every prefix must itself be a valid
//! graph** — the incident was legal at every moment, not just at the end.
//!
//! Headless: nothing here knows about the realm.

mod derive;
mod fold;
mod fork;
mod summary;

pub use derive::{derive, Retimed};
pub use fork::{fork, ForkEvent, ForkSpec};

use navi_graph::{Branch, Violation};
use navi_ontology::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const LOG_VERSION: &str = "navi-log/0.1";

/// One state change. Mutable facts (entities, relationships, safeguards,
/// capabilities, agents, threats) are *re-asserted* to change them;
/// observations, hypotheses and actions are append-only and evolve only
/// through their own transitions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", deny_unknown_fields)]
pub enum Event {
    AuthorityPolicySet {
        policy: AuthorityPolicy,
    },
    EpistemicPolicySet {
        policy: EpistemicPolicy,
    },
    ObservationRecorded {
        observation: Observation,
    },
    EntityAsserted {
        entity: Entity,
    },
    RelationshipAsserted {
        relationship: Relationship,
    },
    SafeguardAsserted {
        safeguard: Safeguard,
    },
    CapabilityGranted {
        capability: Capability,
    },
    AgentRegistered {
        agent: Agent,
    },
    /// Must carry no transitions; those arrive as `HypothesisTransitioned`.
    HypothesisOpened {
        hypothesis: Hypothesis,
    },
    HypothesisTransitioned {
        hypothesis: HypothesisId,
        transition: EpistemicTransition,
    },
    ThreatAttributed {
        threat: Threat,
    },
    /// Must carry no history; that arrives as `ActionTransitioned`.
    ActionProposed {
        action: Action,
    },
    ActionTransitioned {
        action: ActionId,
        transition: ActionTransition,
    },
    AgentEventEmitted {
        event: AgentEvent,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogEntry {
    pub seq: u64,
    pub at: Timestamp,
    pub event: Event,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentLog {
    pub log_version: String,
    pub ontology_version: String,
    /// Present only on counterfactual branches (see [`fork`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<Branch>,
    pub events: Vec<LogEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LogViolation {
    pub seq: Option<u64>,
    pub at: Option<Timestamp>,
    pub message: String,
    /// Graph violations of the state at `at`, if that is what failed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub graph: Vec<Violation>,
}

impl std::fmt::Display for LogViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.seq, self.at) {
            (Some(s), Some(t)) => write!(f, "#{s} at {t}: {}", self.message)?,
            (None, Some(t)) => write!(f, "at {t}: {}", self.message)?,
            _ => write!(f, "{}", self.message)?,
        }
        for v in &self.graph {
            write!(f, "\n    {v}")?;
        }
        Ok(())
    }
}

impl IncidentLog {
    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }

    /// `sha256:` of the canonical JSON (sorted keys).
    pub fn digest(&self) -> String {
        let value = serde_json::to_value(self).expect("log serializes");
        let bytes = serde_json::to_string(&value).expect("value serializes");
        let hash = Sha256::digest(bytes.as_bytes());
        format!(
            "sha256:{}",
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    }

    /// Distinct event instants, in order. Each is a replay frame.
    pub fn instants(&self) -> Vec<Timestamp> {
        let mut v: Vec<Timestamp> = self.events.iter().map(|e| e.at).collect();
        v.dedup();
        v
    }

    /// The validated semantic graph as of instant `t` (all events at or
    /// before `t`).
    pub fn graph_at(&self, t: Timestamp) -> Result<navi_graph::SemanticGraph, LogViolation> {
        let doc = self.fold(Some(t))?;
        navi_graph::SemanticGraph::load(doc).map_err(|graph| LogViolation {
            seq: None,
            at: Some(t),
            message: "state at this instant is not a valid semantic graph".into(),
            graph,
        })
    }

    /// The final state.
    pub fn graph(&self) -> Result<navi_graph::SemanticGraph, LogViolation> {
        match self.instants().last() {
            Some(t) => self.graph_at(*t),
            None => {
                navi_graph::SemanticGraph::load(self.fold(None)?).map_err(|graph| LogViolation {
                    seq: None,
                    at: None,
                    message: "empty log does not fold to a valid graph".into(),
                    graph,
                })
            }
        }
    }

    /// Append events (at or after the log's last instant). The result is
    /// validated in full, so an append can never make history illegal.
    pub fn append(
        &self,
        events: Vec<(Timestamp, Event)>,
    ) -> Result<IncidentLog, Vec<LogViolation>> {
        let last = self.events.last().map(|e| e.at);
        if let Some((t, _)) = events.iter().find(|(t, _)| last.is_some_and(|l| *t < l)) {
            return Err(vec![LogViolation {
                seq: None,
                at: Some(*t),
                message: "cannot append before the end of the log: it is append-only".into(),
                graph: vec![],
            }]);
        }
        let mut out = self.clone();
        for (at, event) in events {
            out.events.push(LogEntry {
                seq: out.events.len() as u64 + 1,
                at,
                event,
            });
        }
        let problems = out.validate();
        if problems.is_empty() {
            Ok(out)
        } else {
            Err(problems)
        }
    }

    /// The last instant in the log, if any.
    pub fn end(&self) -> Option<Timestamp> {
        self.events.last().map(|e| e.at)
    }

    /// Structural checks, then the strong property: the state after every
    /// instant is a valid semantic graph. Reports the first failing instant
    /// (later ones usually cascade from it).
    pub fn validate(&self) -> Vec<LogViolation> {
        let mut out = vec![];
        let v = |seq, at, m: String| LogViolation {
            seq,
            at,
            message: m,
            graph: vec![],
        };
        if self.log_version != LOG_VERSION {
            out.push(v(
                None,
                None,
                format!(
                    "log is {:?}, this build speaks {LOG_VERSION:?}",
                    self.log_version
                ),
            ));
        }
        if self.ontology_version != ONTOLOGY_VERSION {
            out.push(v(
                None,
                None,
                format!(
                    "ontology {:?}, this build speaks {ONTOLOGY_VERSION:?}",
                    self.ontology_version
                ),
            ));
        }
        for (i, e) in self.events.iter().enumerate() {
            if e.seq != i as u64 + 1 {
                out.push(v(
                    Some(e.seq),
                    Some(e.at),
                    format!("sequence numbers must run 1..n; expected #{}", i + 1),
                ));
            }
            if i > 0 && e.at < self.events[i - 1].at {
                out.push(v(
                    Some(e.seq),
                    Some(e.at),
                    "time runs backwards: the log is append-only".into(),
                ));
            }
        }
        if !out.is_empty() {
            return out;
        }
        for t in self.instants() {
            if let Err(e) = self.graph_at(t) {
                out.push(e);
                break;
            }
        }
        out
    }
}
