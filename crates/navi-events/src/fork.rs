//! Counterfactual forks (directive §15 FORK).
//!
//! A fork takes a recorded incident up to an instant and continues it with
//! operator-authored hypothetical events ("what if a human had approved the
//! quarantine at t+5200?"). The result is a separate *branch* log:
//! marked as such in its header and in every graph and realm derived from
//! it, validated by exactly the same rules as reality (a counterfactual
//! cannot skip verification either), and never written into the base log.
//!
//! Predicting what Navi itself *would* have done needs a simulator
//! (`navi-simulator`, later phase); this module records and validates
//! scenarios, it does not invent agent behaviour.

use crate::{Event, IncidentLog, LogEntry, LogViolation};
use navi_graph::Branch;
use navi_ontology::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkEvent {
    pub at: Timestamp,
    pub event: Event,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkSpec {
    pub label: String,
    /// Fork point: base events at or before this instant are kept.
    pub at: Timestamp,
    pub events: Vec<ForkEvent>,
}

pub fn fork(base: &IncidentLog, spec: &ForkSpec) -> Result<IncidentLog, Vec<LogViolation>> {
    let err = |m: String| {
        vec![LogViolation {
            seq: None,
            at: Some(spec.at),
            message: m,
            graph: vec![],
        }]
    };
    if spec.label.trim().is_empty() {
        return Err(err("a fork needs a label".into()));
    }
    let base_problems = base.validate();
    if !base_problems.is_empty() {
        return Err(base_problems);
    }
    if base.events.first().is_none_or(|e| spec.at < e.at) {
        return Err(err("fork point precedes the recorded incident".into()));
    }
    if let Some(e) = spec.events.iter().find(|e| e.at <= spec.at) {
        return Err(err(format!(
            "hypothetical event at {} is not after the fork point: history before a fork is fixed",
            e.at
        )));
    }
    if spec.events.windows(2).any(|w| w[1].at < w[0].at) {
        return Err(err("hypothetical events must be in time order".into()));
    }
    let mut events: Vec<LogEntry> = base
        .events
        .iter()
        .filter(|e| e.at <= spec.at)
        .cloned()
        .collect();
    for e in &spec.events {
        events.push(LogEntry {
            seq: events.len() as u64 + 1,
            at: e.at,
            event: e.event.clone(),
        });
    }
    let branch = IncidentLog {
        log_version: base.log_version.clone(),
        ontology_version: base.ontology_version.clone(),
        branch: Some(Branch {
            fork_of: base.digest(),
            at: spec.at,
            label: spec.label.clone(),
        }),
        events,
    };
    let problems = branch.validate();
    if problems.is_empty() {
        Ok(branch)
    } else {
        Err(problems)
    }
}
