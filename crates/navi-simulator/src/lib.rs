//! A deterministic sandbox estate for interventions (directive §25 Phase 4).
//!
//! The sandbox is built from a semantic graph: the communication flows its
//! relationships describe, the credentials it knows about, and the
//! interventions already in force. Interventions change sandbox state only.
//! Everything the sandbox reports comes back as *observations* whose source
//! system is `sandbox`, so nothing it says can be mistaken for production
//! telemetry, and faults can be injected to exercise the paths where a
//! command "succeeds" but nothing actually changed.

use navi_graph::SemanticGraph;
use navi_ontology::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

pub const SIMULATOR: &str = "navi-simulator/0.1";
pub const SOURCE_SYSTEM: &str = "sandbox";

/// What a capability does to the sandbox.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum Intervention {
    RateLimit {
        target: EntityId,
    },
    Block {
        target: EntityId,
        sources: Vec<EntityId>,
    },
    Isolate {
        target: EntityId,
    },
    Revoke {
        credential: EntityId,
    },
}

impl Intervention {
    pub fn target(&self) -> &EntityId {
        match self {
            Self::RateLimit { target } | Self::Block { target, .. } | Self::Isolate { target } => {
                target
            }
            Self::Revoke { credential } => credential,
        }
    }

    /// Map an action to its sandbox intervention. Only the reversible
    /// containment kinds of Phase 4 are supported; everything else is
    /// refused rather than approximated.
    pub fn for_action(g: &SemanticGraph, action: &Action) -> Result<Self, String> {
        let cap = g
            .capabilities
            .get(&action.capability)
            .ok_or("unknown capability")?;
        let target = action.target.clone();
        Ok(match cap.kind {
            CapabilityKind::Shield => Self::RateLimit { target },
            CapabilityKind::Barrier => {
                // Block the actors the diagnosis attributes, else every
                // external source the sandbox sees talking to the target.
                let mut sources: BTreeSet<EntityId> = g
                    .threats
                    .values()
                    .filter(|t| t.hypothesis == action.hypothesis)
                    .filter_map(|t| t.actor.clone())
                    .collect();
                if sources.is_empty() {
                    sources = g
                        .relationships
                        .values()
                        .filter(|r| r.to == target && g.entities.get(&r.from).is_some_and(|e| e.class == EntityClass::ExternalActor))
                        .map(|r| r.from.clone())
                        .collect();
                }
                if sources.is_empty() {
                    return Err("BARRIER needs an attributed or observed external source to block".into());
                }
                Self::Block { target, sources: sources.into_iter().collect() }
            }
            CapabilityKind::Isolate => Self::Isolate { target },
            CapabilityKind::Lock => Self::Revoke { credential: target },
            other => return Err(format!("{other:?} is not a sandboxed intervention in Phase 4 (block / isolate / revoke / rate-limit only)")),
        })
    }
}

/// Deliberate failure modes, to prove the lifecycle cannot be fooled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Faults {
    /// The command reports failure.
    pub command_fails: bool,
    /// The command reports success but the change never takes effect.
    pub silent_noop: bool,
    /// The change takes effect, but the independent verification probe
    /// finds the threat still active (e.g. the workload re-spawned).
    pub verification_fails: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowResult {
    Allowed,
    Limited,
    Denied,
}

/// One sandbox reading, ready to become an observation.
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    /// The telemetry system that produced the reading (`sandbox` here).
    pub system: String,
    pub collector: String,
    pub kind: String,
    pub subject: EntityId,
    pub attributes: BTreeMap<String, serde_json::Value>,
}

impl Reading {
    pub fn into_observation(self, id: ObservationId, at: Timestamp) -> Observation {
        Observation {
            id,
            source: TelemetrySource {
                system: self.system,
                collector: self.collector,
            },
            observed_at: at,
            subject: Some(self.subject),
            kind: self.kind,
            attributes: self.attributes,
            raw_ref: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sandbox {
    flows: BTreeSet<(EntityId, EntityId)>,
    credentials: BTreeSet<EntityId>,
    /// Interventions that actually took effect, by action.
    active: BTreeMap<ActionId, Intervention>,
    pub faults: Faults,
}

impl Sandbox {
    /// The sandbox as the graph describes it, including every intervention
    /// whose effect was observed and that has not been rolled back.
    pub fn from_graph(g: &SemanticGraph) -> Self {
        let flows = g
            .relationships
            .values()
            .filter(|r| {
                matches!(
                    r.kind,
                    RelationKind::CommunicatesWith
                        | RelationKind::DependsOn
                        | RelationKind::AuthenticatesTo
                )
            })
            .map(|r| (r.from.clone(), r.to.clone()))
            .collect();
        let credentials = g
            .entities
            .values()
            .filter(|e| e.class == EntityClass::Credential)
            .map(|e| e.id.clone())
            .collect();
        let mut s = Self {
            flows,
            credentials,
            active: BTreeMap::new(),
            faults: Faults::default(),
        };
        for a in g.actions.values() {
            let took = a
                .history
                .iter()
                .any(|t| matches!(t, ActionTransition::ObserveEffect { .. }));
            let undone = a
                .history
                .iter()
                .any(|t| matches!(t, ActionTransition::RollBack { .. }));
            if took && !undone {
                if let Ok(iv) = Intervention::for_action(g, a) {
                    s.active.insert(a.id.clone(), iv);
                }
            }
        }
        s
    }

    pub fn with_faults(mut self, faults: Faults) -> Self {
        self.faults = faults;
        self
    }

    /// Run an intervention. `Ok(receipt)` means the *command* returned
    /// success — which is not the same as the change having happened.
    pub fn execute(&mut self, action: &ActionId, iv: &Intervention) -> Result<String, String> {
        if self.faults.command_fails {
            return Err(format!(
                "sandbox: {} rejected the request (injected fault)",
                describe(iv)
            ));
        }
        if !self.faults.silent_noop {
            self.active.insert(action.clone(), iv.clone());
        }
        Ok(format!("sandbox: {} applied for {action}", describe(iv)))
    }

    pub fn roll_back(&mut self, action: &ActionId) -> Result<String, String> {
        match self.active.remove(action) {
            Some(iv) => Ok(format!("sandbox: {} removed", describe(&iv))),
            None => Ok(format!(
                "sandbox: nothing in force for {action}; no change needed"
            )),
        }
    }

    pub fn is_active(&self, action: &ActionId) -> bool {
        self.active.contains_key(action)
    }

    pub fn flow(&self, from: &EntityId, to: &EntityId) -> FlowResult {
        let mut result = FlowResult::Allowed;
        for iv in self.active.values() {
            match iv {
                Intervention::Isolate { target } if target == from || target == to => {
                    return FlowResult::Denied
                }
                Intervention::Block { target, sources }
                    if target == to && sources.contains(from) =>
                {
                    return FlowResult::Denied
                }
                Intervention::RateLimit { target } if target == to => result = FlowResult::Limited,
                _ => {}
            }
        }
        result
    }

    pub fn credential_valid(&self, c: &EntityId) -> bool {
        self.credentials.contains(c)
            && !self
                .active
                .values()
                .any(|iv| matches!(iv, Intervention::Revoke { credential } if credential == c))
    }

    /// The flows an intervention is meant to change.
    fn affected_flows(&self, iv: &Intervention) -> Vec<(EntityId, EntityId)> {
        match iv {
            Intervention::Isolate { target } => self
                .flows
                .iter()
                .filter(|(a, b)| a == target || b == target)
                .cloned()
                .collect(),
            Intervention::RateLimit { target } => self
                .flows
                .iter()
                .filter(|(_, b)| b == target)
                .cloned()
                .collect(),
            Intervention::Block { target, sources } => sources
                .iter()
                .map(|s| (s.clone(), target.clone()))
                .collect(),
            Intervention::Revoke { .. } => vec![],
        }
    }

    /// Readings of the control itself: is it in force?
    pub fn control_reading(&self, action: &ActionId, iv: &Intervention) -> Reading {
        Reading {
            system: SOURCE_SYSTEM.into(),
            collector: SIMULATOR.into(),
            kind: "sandbox.control_state".into(),
            subject: iv.target().clone(),
            attributes: BTreeMap::from([
                ("action".into(), json!(action.as_str())),
                ("intervention".into(), json!(describe(iv))),
                ("in_force".into(), json!(self.is_active(action))),
            ]),
        }
    }

    /// Readings of the traffic/credentials the intervention should affect,
    /// and whether each shows the intended result.
    pub fn effect_readings(&self, iv: &Intervention) -> Vec<(Reading, bool)> {
        if let Intervention::Revoke { credential } = iv {
            let valid = self.credential_valid(credential);
            return vec![(
                Reading {
                    system: SOURCE_SYSTEM.into(),
                    collector: SIMULATOR.into(),
                    kind: "sandbox.auth_attempt".into(),
                    subject: credential.clone(),
                    attributes: BTreeMap::from([(
                        "result".into(),
                        json!(if valid { "accepted" } else { "rejected" }),
                    )]),
                },
                !valid,
            )];
        }
        let want = if matches!(iv, Intervention::RateLimit { .. }) {
            FlowResult::Limited
        } else {
            FlowResult::Denied
        };
        self.affected_flows(iv)
            .into_iter()
            .map(|(a, b)| {
                let r = self.flow(&a, &b);
                (
                    Reading {
                        system: SOURCE_SYSTEM.into(),
                        collector: SIMULATOR.into(),
                        kind: "sandbox.flow_check".into(),
                        subject: iv.target().clone(),
                        attributes: BTreeMap::from([
                            ("from".into(), json!(a.as_str())),
                            ("to".into(), json!(b.as_str())),
                            ("result".into(), json!(r)),
                        ]),
                    },
                    r == want,
                )
            })
            .collect()
    }

    /// Readings after a rollback: the affected flows/credentials are back.
    pub fn restored_readings(&self, iv: &Intervention) -> Vec<(Reading, bool)> {
        if let Intervention::Revoke { credential } = iv {
            let valid = self.credential_valid(credential);
            return vec![(
                Reading {
                    system: SOURCE_SYSTEM.into(),
                    collector: SIMULATOR.into(),
                    kind: "sandbox.auth_attempt".into(),
                    subject: credential.clone(),
                    attributes: BTreeMap::from([(
                        "result".into(),
                        json!(if valid { "accepted" } else { "rejected" }),
                    )]),
                },
                valid,
            )];
        }
        self.affected_flows(iv)
            .into_iter()
            .map(|(a, b)| {
                let r = self.flow(&a, &b);
                (
                    Reading {
                        system: SOURCE_SYSTEM.into(),
                        collector: SIMULATOR.into(),
                        kind: "sandbox.flow_check".into(),
                        subject: iv.target().clone(),
                        attributes: BTreeMap::from([
                            ("from".into(), json!(a.as_str())),
                            ("to".into(), json!(b.as_str())),
                            ("result".into(), json!(r)),
                        ]),
                    },
                    r == FlowResult::Allowed,
                )
            })
            .collect()
    }

    /// The independent verification probe, run against the capability's
    /// declared verification method. It re-measures rather than re-reading
    /// earlier evidence.
    pub fn verification_probe(
        &self,
        action: &ActionId,
        iv: &Intervention,
        method: &str,
    ) -> (Reading, bool) {
        let checks = self.effect_readings(iv);
        let held = self.is_active(action) && !checks.is_empty() && checks.iter().all(|(_, ok)| *ok);
        let passed = held && !self.faults.verification_fails;
        let mut attributes = BTreeMap::from([
            ("method".into(), json!(method)),
            ("checks".into(), json!(checks.len())),
            ("passed".into(), json!(passed)),
        ]);
        if held && self.faults.verification_fails {
            attributes.insert(
                "finding".into(),
                json!("threat activity resumed from a replacement workload (injected fault)"),
            );
        }
        (
            Reading {
                system: SOURCE_SYSTEM.into(),
                collector: SIMULATOR.into(),
                kind: "sandbox.verification_probe".into(),
                subject: iv.target().clone(),
                attributes,
            },
            passed,
        )
    }
}

/// Something that can carry out interventions and report what it sees.
/// The sandbox is the only implementation that ships: a production actuator
/// would implement this against real systems, and its results would be
/// written to the incident itself rather than to a counterfactual branch.
pub trait Actuator {
    /// True if this actuator does not touch reality.
    fn is_sandbox(&self) -> bool;
    fn name(&self) -> String;
    fn execute(&mut self, action: &ActionId, iv: &Intervention) -> Result<String, String>;
    fn roll_back(&mut self, action: &ActionId) -> Result<String, String>;
    fn is_active(&self, action: &ActionId) -> bool;
    fn control_reading(&self, action: &ActionId, iv: &Intervention) -> Reading;
    fn effect_readings(&self, iv: &Intervention) -> Vec<(Reading, bool)>;
    fn restored_readings(&self, iv: &Intervention) -> Vec<(Reading, bool)>;
    fn verification_probe(
        &self,
        action: &ActionId,
        iv: &Intervention,
        method: &str,
    ) -> (Reading, bool);
}

impl Actuator for Sandbox {
    fn is_sandbox(&self) -> bool {
        true
    }
    fn name(&self) -> String {
        SIMULATOR.into()
    }
    fn execute(&mut self, action: &ActionId, iv: &Intervention) -> Result<String, String> {
        Sandbox::execute(self, action, iv)
    }
    fn roll_back(&mut self, action: &ActionId) -> Result<String, String> {
        Sandbox::roll_back(self, action)
    }
    fn is_active(&self, action: &ActionId) -> bool {
        Sandbox::is_active(self, action)
    }
    fn control_reading(&self, action: &ActionId, iv: &Intervention) -> Reading {
        Sandbox::control_reading(self, action, iv)
    }
    fn effect_readings(&self, iv: &Intervention) -> Vec<(Reading, bool)> {
        Sandbox::effect_readings(self, iv)
    }
    fn restored_readings(&self, iv: &Intervention) -> Vec<(Reading, bool)> {
        Sandbox::restored_readings(self, iv)
    }
    fn verification_probe(
        &self,
        action: &ActionId,
        iv: &Intervention,
        method: &str,
    ) -> (Reading, bool) {
        Sandbox::verification_probe(self, action, iv, method)
    }
}

pub fn describe(iv: &Intervention) -> String {
    match iv {
        Intervention::RateLimit { target } => format!("rate limit on {target}"),
        Intervention::Block { target, sources } => {
            let s: Vec<_> = sources.iter().map(|x| x.as_str()).collect();
            format!("block {} → {target}", s.join(","))
        }
        Intervention::Isolate { target } => format!("quarantine of {target}"),
        Intervention::Revoke { credential } => format!("revocation of {credential}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> EntityId {
        EntityId::new(s).unwrap()
    }

    fn sandbox() -> Sandbox {
        Sandbox {
            flows: BTreeSet::from([
                (id("ent:pod"), id("ent:ext")),
                (id("ent:web"), id("ent:pod")),
            ]),
            credentials: BTreeSet::from([id("ent:token")]),
            active: BTreeMap::new(),
            faults: Faults::default(),
        }
    }

    fn act(s: &str) -> ActionId {
        ActionId::new(s).unwrap()
    }

    #[test]
    fn isolate_denies_every_flow_touching_the_target() {
        let mut s = sandbox();
        let iv = Intervention::Isolate {
            target: id("ent:pod"),
        };
        s.execute(&act("act:1"), &iv).unwrap();
        assert!(s.effect_readings(&iv).iter().all(|(_, ok)| *ok));
        assert_eq!(s.effect_readings(&iv).len(), 2);
        s.roll_back(&act("act:1")).unwrap();
        assert!(s.restored_readings(&iv).iter().all(|(_, ok)| *ok));
    }

    #[test]
    fn silent_noop_returns_ok_but_changes_nothing() {
        let mut s = sandbox().with_faults(Faults {
            silent_noop: true,
            ..Faults::default()
        });
        let iv = Intervention::Isolate {
            target: id("ent:pod"),
        };
        assert!(s.execute(&act("act:1"), &iv).is_ok());
        assert!(!s.is_active(&act("act:1")));
        assert!(s.effect_readings(&iv).iter().all(|(_, ok)| !*ok));
    }

    #[test]
    fn revoke_rejects_the_credential() {
        let mut s = sandbox();
        let iv = Intervention::Revoke {
            credential: id("ent:token"),
        };
        assert!(s.credential_valid(&id("ent:token")));
        s.execute(&act("act:2"), &iv).unwrap();
        assert!(!s.credential_valid(&id("ent:token")));
        let (_, passed) = s.verification_probe(&act("act:2"), &iv, "m");
        assert!(passed);
    }

    #[test]
    fn verification_fault_fails_the_probe_only() {
        let mut s = sandbox().with_faults(Faults {
            verification_fails: true,
            ..Faults::default()
        });
        let iv = Intervention::Isolate {
            target: id("ent:pod"),
        };
        s.execute(&act("act:1"), &iv).unwrap();
        assert!(s.effect_readings(&iv).iter().all(|(_, ok)| *ok));
        assert!(!s.verification_probe(&act("act:1"), &iv, "m").1);
    }
}
