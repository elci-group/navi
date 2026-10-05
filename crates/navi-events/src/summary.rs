//! One-line DVR descriptions of log events (directive §16).

use crate::{Event, LogEntry};
use navi_ontology::*;
use serde::Serialize;

fn w<T: Serialize>(t: &T) -> String {
    match serde_json::to_value(t) {
        Ok(serde_json::Value::String(s)) => s,
        Ok(v) => v.to_string(),
        Err(_) => "?".into(),
    }
}

fn pct(c: &Confidence) -> String {
    let bp = c.basis_points();
    if bp.is_multiple_of(100) {
        format!("{}%", bp / 100)
    } else {
        format!("{}.{:02}%", bp / 100, bp % 100)
    }
}

impl LogEntry {
    pub fn summary(&self) -> String {
        match &self.event {
            Event::AuthorityPolicySet { policy } => format!("authority policy {}", policy.version),
            Event::EpistemicPolicySet { policy } => format!("epistemic policy {}", policy.version),
            Event::ObservationRecorded { observation: o } => {
                let on = o
                    .subject
                    .as_ref()
                    .map_or(String::new(), |s| format!(" on {s}"));
                format!(
                    "{} observed{on} via {}  [{}]",
                    o.kind, o.source.system, o.id
                )
            }
            Event::EntityAsserted { entity: e } => {
                format!(
                    "{} {} \"{}\" asserted, trust {}",
                    w(&e.class),
                    e.id,
                    e.name,
                    w(&e.trust)
                )
            }
            Event::RelationshipAsserted { relationship: r } => {
                format!("{} {} {}  [{}]", r.from, w(&r.kind), r.to, r.id)
            }
            Event::SafeguardAsserted { safeguard: s } => {
                format!("{} \"{}\" {}  [{}]", w(&s.kind), s.name, w(&s.status), s.id)
            }
            Event::CapabilityGranted { capability: c } => {
                format!("{} {} granted at {}", c.id, w(&c.kind), w(&c.authority))
            }
            Event::AgentRegistered { agent: a } => format!(
                "{} \"{}\" ({}) on duty, {} capabilities",
                a.id,
                a.name,
                w(&a.role),
                a.loadout.len()
            ),
            Event::HypothesisOpened { hypothesis: h } => {
                format!(
                    "{} hypothesised: {} {}  [{}]",
                    h.claim,
                    w(&h.opened_as),
                    pct(&h.initial_confidence),
                    h.id
                )
            }
            Event::HypothesisTransitioned {
                hypothesis,
                transition: t,
            } => {
                format!(
                    "{hypothesis} {} → {} {}: {}",
                    w(&t.from),
                    w(&t.to),
                    pct(&t.confidence),
                    t.reason
                )
            }
            Event::ThreatAttributed { threat: t } => {
                let actor = t.actor.as_ref().map_or("?".into(), |a| a.to_string());
                let targets: Vec<_> = t.targets.iter().map(|x| x.to_string()).collect();
                format!(
                    "{} attributed: actor {actor} → {}",
                    t.id,
                    targets.join(", ")
                )
            }
            Event::ActionProposed { action: a } => format!(
                "{} proposes {} on {}  [{}]",
                a.agent, a.capability, a.target, a.id
            ),
            Event::ActionTransitioned { action, transition } => {
                let what = match transition {
                    ActionTransition::Authorise { approval, .. } => match &approval.kind {
                        ApprovalKind::Human { principal } => {
                            format!("approved by human {principal}")
                        }
                        ApprovalKind::Policy { rule } => format!("approved by policy {rule}"),
                        ApprovalKind::Autonomous { policy_version } => {
                            format!("authorised autonomously ({policy_version})")
                        }
                    },
                    ActionTransition::Reject { reason, .. } => format!("rejected: {reason}"),
                    ActionTransition::Cancel { reason, .. } => format!("cancelled: {reason}"),
                    ActionTransition::BeginExecution { .. } => "execution begins".into(),
                    ActionTransition::ExecutionReturned {
                        ok: true, receipt, ..
                    } => format!("command returned ({receipt}); effect not yet observed"),
                    ActionTransition::ExecutionReturned {
                        ok: false, receipt, ..
                    } => format!("command failed ({receipt})"),
                    ActionTransition::ObserveEffect { .. } => "effect observed".into(),
                    ActionTransition::Verify {
                        passed: true,
                        method,
                        ..
                    } => format!("verified: {method}"),
                    ActionTransition::Verify {
                        passed: false,
                        method,
                        ..
                    } => format!("verification FAILED: {method}"),
                    ActionTransition::RollBack { .. } => "rolled back".into(),
                };
                format!("{action} {what}")
            }
            Event::AgentEventEmitted { event: e } => {
                let c = e
                    .confidence
                    .as_ref()
                    .map_or(String::new(), |c| format!(" ({})", pct(c)));
                format!("{} {}: {}{c}", e.agent, w(&e.phase), e.reason)
            }
        }
    }
}
