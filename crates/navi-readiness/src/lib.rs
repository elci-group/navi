//! The Phase 6 gate (directive §25: "production autonomy only after
//! deterministic replay, provenance, rollback, authority and verification
//! have demonstrated sufficient reliability").
//!
//! [`evaluate`] puts every runnable intervention in a corpus of incidents
//! through sandbox trials — clean, repeated, and under every injected fault
//! — and scores the §26 properties per capability kind. A kind is certified
//! only if every criterion held on every trial, on enough actions. The
//! [`Certificate`] is bound by digest to its content (and so to the corpus
//! digests it lists).
//!
//! [`grant`] is the human step: it checks a certificate and records an
//! autonomy grant in the incident's authority policy. The ontology limits
//! what can be granted (temporary, low-risk, expiring, reversible
//! containment); the certificate decides whether it may be.

use navi_actions::{approve, cancel, roll_back, run, Approver, Outcome, Refusal, RunOptions};
use navi_events::{Event, IncidentLog};
use navi_graph::SemanticGraph;
use navi_ontology::*;
use navi_simulator::{Faults, Intervention};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const CERT_VERSION: &str = "navi-readiness/0.1";
const TRIAL_PRINCIPAL: &str = "readiness-trial";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thresholds {
    /// Distinct actions of a kind that must be trialled before it can be certified.
    pub min_actions: usize,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self { min_actions: 1 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Criterion {
    pub name: String,
    pub trials: usize,
    pub failures: Vec<String>,
}

impl Criterion {
    pub fn passed(&self) -> bool {
        self.trials > 0 && self.failures.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindReport {
    pub kind: CapabilityKind,
    /// `log-digest-prefix/action` for every action trialled.
    pub trialled: Vec<String>,
    /// Actions that could not be trialled in their incident, and why.
    pub skipped: Vec<String>,
    pub criteria: Vec<Criterion>,
    pub ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    pub cert_version: String,
    pub ontology_version: String,
    pub simulator: String,
    /// Digests of the incident logs the trials ran on.
    pub corpus: Vec<String>,
    pub thresholds: Thresholds,
    pub kinds: Vec<KindReport>,
    pub certified: Vec<CapabilityKind>,
    /// `sha256:` over everything above.
    pub digest: String,
}

impl Certificate {
    fn content_digest(&self) -> String {
        let mut c = self.clone();
        c.digest = String::new();
        let value = serde_json::to_value(&c).expect("certificate serializes");
        let bytes = serde_json::to_string(&value).expect("value serializes");
        format!(
            "sha256:{}",
            Sha256::digest(bytes.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }

    /// The digest matches the content and this build speaks its versions.
    pub fn verify(&self) -> Result<(), String> {
        if self.cert_version != CERT_VERSION {
            return Err(format!(
                "certificate is {:?}, this build speaks {CERT_VERSION:?}",
                self.cert_version
            ));
        }
        if self.ontology_version != ONTOLOGY_VERSION {
            return Err(format!(
                "certificate is for {:?}, this build speaks {ONTOLOGY_VERSION:?}",
                self.ontology_version
            ));
        }
        if self.digest != self.content_digest() {
            return Err("certificate content does not match its digest".into());
        }
        Ok(())
    }

    pub fn covers(&self, kind: CapabilityKind) -> bool {
        self.certified.contains(&kind)
    }
}

struct Tally(BTreeMap<&'static str, Criterion>);

/// Per capability kind: the tally, the actions trialled, and those skipped.
type KindTrials = (Tally, Vec<String>, Vec<String>);

/// An injected fault and the outcome that proves it was detected.
type FaultCase = (&'static str, Faults, fn(&Outcome) -> bool);

impl Tally {
    fn new() -> Self {
        Tally(BTreeMap::new())
    }
    fn check(&mut self, name: &'static str, ok: bool, what: impl FnOnce() -> String) {
        let c = self.0.entry(name).or_insert_with(|| Criterion {
            name: name.into(),
            trials: 0,
            failures: vec![],
        });
        c.trials += 1;
        if !ok {
            c.failures.push(what());
        }
    }
}

fn state(l: &IncidentLog, a: &ActionId) -> Option<ActionState> {
    l.graph()
        .ok()
        .and_then(|g| g.actions.get(a).map(|x| x.state()))
}

fn grounded(g: &SemanticGraph, a: &ActionId) -> bool {
    g.explain(a.as_str()).is_some_and(|t| {
        // Effect and verification chains must each reach observations.
        t.children
            .iter()
            .filter(|c| c.kind == "evidence")
            .all(|c| !c.observations().is_empty())
            && t.children.iter().any(|c| c.kind == "evidence")
    })
}

/// Trial one action. `Err` means it could not be trialled in this incident.
fn trial(log: &IncidentLog, a: &Action, label: &str, t: &mut Tally) -> Result<(), String> {
    let prepared = match a.state() {
        ActionState::Authorised => log.clone(),
        ActionState::Proposed => {
            // Authority: it must not run before it is authorised.
            let early = run(log, &a.id, RunOptions::default());
            t.check(
                "authority",
                matches!(early, Err(Refusal::NotRunnable { .. })),
                || format!("{label}: ran without authorisation"),
            );
            match approve(
                log,
                &a.id,
                Approver::Human(TRIAL_PRINCIPAL.into()),
                None,
                None,
            ) {
                Ok(l) => l,
                Err(e) => return Err(format!("{label}: cannot be authorised here ({e})")),
            }
        }
        s => return Err(format!("{label}: already {s:?}")),
    };

    let clean = match run(&prepared, &a.id, RunOptions::default()) {
        Ok(r) => r,
        Err(e @ (Refusal::Loop(_) | Refusal::Expired(_))) => return Err(format!("{label}: {e}")),
        Err(e) => {
            t.check("verification", false, || {
                format!("{label}: clean run refused: {e}")
            });
            return Ok(());
        }
    };
    t.check("verification", clean.outcome == Outcome::Verified, || {
        format!("{label}: clean run ended {:?}", clean.outcome)
    });
    t.check("replay", clean.branch.validate().is_empty(), || {
        format!("{label}: trial branch has an invalid instant")
    });
    if let Ok(g) = clean.branch.graph() {
        t.check("provenance", grounded(&g, &a.id), || {
            format!("{label}: effect or verification evidence does not reach observations")
        });
    }
    let again = run(&prepared, &a.id, RunOptions::default()).map(|r| r.branch);
    t.check(
        "determinism",
        again.as_ref().ok() == Some(&clean.branch),
        || format!("{label}: two identical runs differ"),
    );

    let faults: [FaultCase; 3] = [
        (
            "silent-noop",
            Faults {
                silent_noop: true,
                ..Faults::default()
            },
            |o| matches!(o, Outcome::EffectNotObserved { .. }),
        ),
        (
            "command-fails",
            Faults {
                command_fails: true,
                ..Faults::default()
            },
            |o| *o == Outcome::CommandFailed,
        ),
        (
            "verification-fails",
            Faults {
                verification_fails: true,
                ..Faults::default()
            },
            |o| matches!(o, Outcome::VerificationFailed { .. }),
        ),
    ];
    for (name, f, expected) in faults {
        let r = run(
            &prepared,
            &a.id,
            RunOptions {
                faults: f,
                ..RunOptions::default()
            },
        );
        let ok = r.as_ref().is_ok_and(|r| {
            expected(&r.outcome)
                && !matches!(
                    state(&r.branch, &a.id),
                    Some(ActionState::Succeeded | ActionState::Verified)
                )
        });
        t.check("fault-detection", ok, || {
            format!("{label}: {name} was not detected")
        });
    }

    let undone = roll_back(&clean.branch, &a.id, TRIAL_PRINCIPAL, None);
    t.check(
        "rollback",
        undone
            .as_ref()
            .is_ok_and(|r| state(&r.branch, &a.id) == Some(ActionState::RolledBack)),
        || {
            format!(
                "{label}: rollback failed: {:?}",
                undone.as_ref().err().map(|e| e.to_string())
            )
        },
    );

    let stopped = cancel(&prepared, &a.id, TRIAL_PRINCIPAL, "readiness trial", None);
    let honoured = stopped.as_ref().is_ok_and(|l| {
        matches!(
            run(l, &a.id, RunOptions::default()),
            Err(Refusal::NotRunnable { .. })
        )
    });
    t.check("human-interruption", honoured, || {
        format!("{label}: cancellation not honoured")
    });
    Ok(())
}

/// Run the trials and issue a certificate. Pure and deterministic.
pub fn evaluate(corpus: &[IncidentLog], thresholds: Thresholds) -> Certificate {
    let mut per_kind: BTreeMap<CapabilityKind, KindTrials> = BTreeMap::new();
    let mut digests = vec![];
    for log in corpus {
        let digest = log.digest();
        digests.push(digest.clone());
        let short = &digest[7..19];
        let Ok(g) = log.graph() else { continue };
        if !log.validate().is_empty() {
            continue;
        }
        for a in g.actions.values() {
            let Some(cap) = g.capabilities.get(&a.capability) else {
                continue;
            };
            if Intervention::for_action(&g, a).is_err() {
                continue;
            }
            let label = format!("{short}/{}", a.id);
            let entry = per_kind
                .entry(cap.kind)
                .or_insert_with(|| (Tally::new(), vec![], vec![]));
            match trial(log, a, &label, &mut entry.0) {
                Ok(()) => entry.1.push(label),
                Err(why) => entry.2.push(why),
            }
        }
    }
    digests.sort();
    let kinds: Vec<KindReport> = per_kind
        .into_iter()
        .map(|(kind, (tally, trialled, skipped))| {
            let criteria: Vec<Criterion> = tally.0.into_values().collect();
            let required = [
                "verification",
                "replay",
                "provenance",
                "determinism",
                "fault-detection",
                "rollback",
                "human-interruption",
            ];
            let all_present = required
                .iter()
                .all(|r| criteria.iter().any(|c| c.name == *r));
            let ready = trialled.len() >= thresholds.min_actions
                && all_present
                && criteria.iter().all(Criterion::passed);
            KindReport {
                kind,
                trialled,
                skipped,
                criteria,
                ready,
            }
        })
        .collect();
    let mut cert = Certificate {
        cert_version: CERT_VERSION.into(),
        ontology_version: ONTOLOGY_VERSION.into(),
        simulator: navi_simulator::SIMULATOR.into(),
        corpus: digests,
        thresholds,
        certified: kinds.iter().filter(|k| k.ready).map(|k| k.kind).collect(),
        kinds,
        digest: String::new(),
    };
    cert.digest = cert.content_digest();
    cert
}

/// A human grants Navi autonomy for one capability, backed by a certificate.
pub fn grant(
    log: &IncidentLog,
    capability: &CapabilityId,
    cert: &Certificate,
    grace_ms: i64,
    max_duration_ms: i64,
    by: &str,
    at: Option<Timestamp>,
) -> Result<IncidentLog, String> {
    cert.verify()?;
    let g = log.graph().map_err(|e| e.to_string())?;
    let cap = g
        .capabilities
        .get(capability)
        .ok_or(format!("no capability {capability} in this incident"))?;
    if !cert.covers(cap.kind) {
        return Err(format!(
            "certificate {} does not certify {:?}",
            &cert.digest[..19],
            cap.kind
        ));
    }
    let new = AutonomyGrant {
        capability: capability.clone(),
        certificate: cert.digest.clone(),
        grace_ms,
        max_duration_ms,
        granted_by: by.into(),
    };
    new.check(cap)?;
    let mut policy = g.authority_policy.clone();
    policy.autonomy.retain(|x| &x.capability != capability);
    policy.autonomy.push(new);
    policy
        .autonomy
        .sort_by(|a, b| a.capability.cmp(&b.capability));
    policy.version = format!(
        "{}+autonomy:{}",
        g.authority_policy.version,
        capability.as_str().trim_start_matches("cap:")
    );
    let t = at.unwrap_or_else(|| Timestamp(log.end().map_or(0, |e| e.0 + 100)));
    log.append(vec![(t, Event::AuthorityPolicySet { policy })])
        .map_err(|v| {
            v.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        })
}
