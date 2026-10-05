//! Whole-document validation. Every rule here corresponds to a clause of
//! the directive; the `Code` names say which.

use crate::SemanticGraph;
use navi_ontology::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Code {
    OntologyVersionMismatch,
    DuplicateId,
    /// An object failed its own ontology-level check.
    InvalidObject,
    /// §19: entity without source / relationship without evidence / any
    /// reference to something that does not exist.
    DanglingReference,
    /// §5: provenance that never reaches a real observation (or only
    /// reaches one through a cycle).
    UngroundedProvenance,
    /// §6/III: a certainty claim not backed by an equally certain hypothesis.
    EpistemicOverclaim,
    /// §10/§26: authority fidelity.
    AuthorityViolation,
    /// §7/§19: action without agent event, illegal phase walk.
    AgentEventViolation,
    /// §20/§26: effect/verification evidence that cannot be what it claims.
    VerificationViolation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Violation {
    pub code: Code,
    pub subject: String,
    pub message: String,
}

impl Violation {
    pub fn new(code: Code, subject: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code,
            subject: subject.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} [{}]: {}", self.code, self.subject, self.message)
    }
}

/// Grounding memo: does a node's provenance bottom out in observations?
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    Visiting,
    Grounded,
    Ungrounded,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Node {
    Hypothesis(HypothesisId),
    Safeguard(SafeguardId),
    Action(ActionId),
}

struct Grounder<'g> {
    g: &'g SemanticGraph,
    memo: BTreeMap<Node, Mark>,
}

impl Grounder<'_> {
    fn source(&mut self, s: &SourceRef) -> bool {
        match s {
            SourceRef::Observation(id) => self.g.observations.contains_key(id),
            SourceRef::Derived { inputs, .. } => inputs.iter().all(|i| self.source(i)),
            SourceRef::Hypothesis(id) => self.node(Node::Hypothesis(id.clone())),
            SourceRef::Safeguard(id) => self.node(Node::Safeguard(id.clone())),
            SourceRef::Action(id) => self.node(Node::Action(id.clone())),
        }
    }

    fn provenance(&mut self, p: &Provenance) -> bool {
        // Every source must ground: one solid source cannot launder a
        // fabricated one sitting next to it.
        p.sources().iter().all(|s| self.source(s))
    }

    fn node(&mut self, n: Node) -> bool {
        match self.memo.get(&n) {
            Some(Mark::Grounded) => return true,
            Some(Mark::Ungrounded | Mark::Visiting) => return false,
            None => {}
        }
        self.memo.insert(n.clone(), Mark::Visiting);
        let ok = match &n {
            Node::Hypothesis(id) => match self.g.hypotheses.get(id) {
                Some(h) => self.provenance(&h.evidence()),
                None => false,
            },
            Node::Safeguard(id) => match self.g.safeguards.get(id) {
                Some(s) => self.provenance(&s.provenance.clone()),
                None => false,
            },
            Node::Action(id) => match self.g.actions.get(id) {
                Some(a) => self.node(Node::Hypothesis(a.hypothesis.clone())),
                None => false,
            },
        };
        self.memo
            .insert(n, if ok { Mark::Grounded } else { Mark::Ungrounded });
        ok
    }
}

impl SemanticGraph {
    /// Does a certificate-backed autonomous approval satisfy this gate?
    /// Only for policy-dependent gates, only under a valid grant, only with
    /// the grant's interruption window and duration bound respected.
    pub fn autonomy_satisfies(
        &self,
        cap: &Capability,
        appr: &Approval,
        gate: Gate,
        authorised_at: Option<Timestamp>,
    ) -> Result<(), String> {
        let ApprovalKind::Autonomous {
            certificate: Some(cert),
            ..
        } = &appr.kind
        else {
            return Err("not a certificate-backed autonomous approval".into());
        };
        if gate != Gate::PolicyDependent {
            return Err(format!("{gate:?} gates cannot be satisfied autonomously"));
        }
        let grant = self
            .authority_policy
            .grant_for(&cap.id)
            .ok_or(format!("no autonomy grant for {}", cap.id))?;
        grant.check(cap)?;
        if &grant.certificate != cert {
            return Err("certificate differs from the grant's".into());
        }
        let at = authorised_at.ok_or("not authorised")?;
        match appr.not_before {
            Some(nb) if nb.0 >= at.0 + grant.grace_ms => {}
            _ => {
                return Err(format!(
                    "needs a {}ms human interruption window",
                    grant.grace_ms
                ))
            }
        }
        let cap_end = match cap.expiry {
            Expiry::At(e) => e,
            Expiry::Never => return Err("capability never expires".into()),
        };
        match appr.expires_at {
            Some(e) if e.0 <= at.0 + grant.max_duration_ms && e <= cap_end => Ok(()),
            _ => Err(format!(
                "must expire within {}ms and before the capability does",
                grant.max_duration_ms
            )),
        }
    }

    pub(crate) fn validate(&self) -> Vec<Violation> {
        let mut v = Vec::new();
        self.check_objects(&mut v);
        self.check_references(&mut v);
        self.check_grounding(&mut v);
        self.check_epistemics(&mut v);
        self.check_capabilities_and_actions(&mut v);
        self.check_agent_events(&mut v);
        self.check_grants(&mut v);
        v
    }

    fn check_grants(&self, v: &mut Vec<Violation>) {
        for g in &self.authority_policy.autonomy {
            let problem = match self.capabilities.get(&g.capability) {
                None => Some(format!(
                    "grants autonomy for {}, which does not exist",
                    g.capability
                )),
                Some(c) => g.check(c).err(),
            };
            if let Some(m) = problem {
                v.push(Violation::new(
                    Code::AuthorityViolation,
                    self.authority_policy.version.clone(),
                    m,
                ));
            }
        }
    }

    fn check_objects(&self, v: &mut Vec<Violation>) {
        let mut push = |id: &dyn fmt::Display, r: Result<(), OntologyError>| {
            if let Err(e) = r {
                v.push(Violation::new(
                    Code::InvalidObject,
                    id.to_string(),
                    e.to_string(),
                ));
            }
        };
        for o in self.observations.values() {
            push(&o.id, o.check());
        }
        for e in self.entities.values() {
            push(&e.id, e.check());
        }
        for r in self.relationships.values() {
            push(&r.id, r.check());
        }
        for h in self.hypotheses.values() {
            push(&h.id, h.check(&self.epistemic_policy));
        }
        for c in self.capabilities.values() {
            push(&c.id, c.check());
        }
        for a in self.actions.values() {
            push(&a.id, a.check());
        }
        for s in self.safeguards.values() {
            if s.protects.is_empty() {
                push(
                    &s.id,
                    Err(OntologyError::EmptyField {
                        field: "safeguard.protects",
                    }),
                );
            }
        }
        for t in self.threats.values() {
            if t.targets.is_empty() {
                push(
                    &t.id,
                    Err(OntologyError::EmptyField {
                        field: "threat.targets",
                    }),
                );
            }
        }
    }

    fn source_exists(&self, s: &SourceRef) -> Result<(), String> {
        match s {
            SourceRef::Observation(id) if !self.observations.contains_key(id) => {
                Err(id.to_string())
            }
            SourceRef::Hypothesis(id) if !self.hypotheses.contains_key(id) => Err(id.to_string()),
            SourceRef::Safeguard(id) if !self.safeguards.contains_key(id) => Err(id.to_string()),
            SourceRef::Action(id) if !self.actions.contains_key(id) => Err(id.to_string()),
            SourceRef::Derived { inputs, .. } => {
                inputs.iter().try_for_each(|i| self.source_exists(i))
            }
            _ => Ok(()),
        }
    }

    fn check_references(&self, v: &mut Vec<Violation>) {
        let mut dangling = |subject: &dyn fmt::Display, what: &str, missing: &dyn fmt::Display| {
            v.push(Violation::new(
                Code::DanglingReference,
                subject.to_string(),
                format!("{what} references {missing}, which does not exist"),
            ));
        };
        let ent = |id: &EntityId| self.entities.contains_key(id);

        let prov =
            |subject: &dyn fmt::Display,
             what: &str,
             p: &Provenance,
             d: &mut dyn FnMut(&dyn fmt::Display, &str, &dyn fmt::Display)| {
                for s in p.sources() {
                    if let Err(missing) = self.source_exists(s) {
                        d(subject, what, &missing);
                    }
                }
            };

        for o in self.observations.values() {
            if let Some(s) = &o.subject {
                if !ent(s) {
                    dangling(&o.id, "subject", s);
                }
            }
        }
        for e in self.entities.values() {
            prov(&e.id, "provenance", &e.provenance, &mut dangling);
        }
        for r in self.relationships.values() {
            for end in [&r.from, &r.to] {
                if !ent(end) {
                    dangling(&r.id, "endpoint", end);
                }
            }
            prov(&r.id, "provenance", &r.provenance, &mut dangling);
        }
        for h in self.hypotheses.values() {
            for s in &h.subjects {
                if !ent(s) {
                    dangling(&h.id, "subject", s);
                }
            }
            prov(&h.id, "evidence", &h.evidence(), &mut dangling);
        }
        for t in self.threats.values() {
            if !self.hypotheses.contains_key(&t.hypothesis) {
                dangling(&t.id, "classification hypothesis", &t.hypothesis);
            }
            for e in t.actor.iter().chain(&t.targets) {
                if !ent(e) {
                    dangling(&t.id, "entity", e);
                }
            }
        }
        for s in self.safeguards.values() {
            for e in s.protects.iter().chain(&s.enforced_by) {
                if !ent(e) {
                    dangling(&s.id, "entity", e);
                }
            }
            prov(&s.id, "provenance", &s.provenance, &mut dangling);
        }
        for c in self.capabilities.values() {
            for e in &c.scope {
                if !ent(e) {
                    dangling(&c.id, "scope", e);
                }
            }
        }
        for a in self.agents.values() {
            for c in &a.loadout {
                if !self.capabilities.contains_key(c) {
                    dangling(&a.id, "loadout", c);
                }
            }
        }
        for e in self.agent_events.values() {
            let subj = format!("{}#{}", e.agent, e.seq);
            if !self.agents.contains_key(&e.agent) {
                dangling(&subj, "agent", &e.agent);
            }
            if let Some(t) = &e.target {
                if !ent(t) {
                    dangling(&subj, "target", t);
                }
            }
            if let Some(h) = &e.hypothesis {
                if !self.hypotheses.contains_key(h) {
                    dangling(&subj, "hypothesis", h);
                }
            }
            if let Some(a) = &e.action {
                if !self.actions.contains_key(a) {
                    dangling(&subj, "action", a);
                }
            }
        }
        for a in self.actions.values() {
            if !self.agents.contains_key(&a.agent) {
                dangling(&a.id, "agent", &a.agent);
            }
            if !self.capabilities.contains_key(&a.capability) {
                dangling(&a.id, "capability", &a.capability);
            }
            if !ent(&a.target) {
                dangling(&a.id, "target", &a.target);
            }
            if !self.hypotheses.contains_key(&a.hypothesis) {
                dangling(&a.id, "hypothesis", &a.hypothesis);
            }
            for t in &a.history {
                let p = match t {
                    ActionTransition::ObserveEffect { effect, .. } => effect,
                    ActionTransition::Verify { evidence, .. }
                    | ActionTransition::RollBack { evidence, .. } => evidence,
                    _ => continue,
                };
                prov(&a.id, t.name(), p, &mut dangling);
            }
        }
    }

    fn check_grounding(&self, v: &mut Vec<Violation>) {
        let mut g = Grounder {
            g: self,
            memo: BTreeMap::new(),
        };
        let mut bad = |subject: &dyn fmt::Display, what: &str| {
            v.push(Violation::new(
                Code::UngroundedProvenance,
                subject.to_string(),
                format!(
                    "{what} does not resolve to observations (missing link or circular reasoning)"
                ),
            ));
        };
        for e in self.entities.values() {
            if !g.provenance(&e.provenance) {
                bad(&e.id, "provenance");
            }
        }
        for r in self.relationships.values() {
            if !g.provenance(&r.provenance) {
                bad(&r.id, "provenance");
            }
        }
        for h in self.hypotheses.values() {
            if !g.node(Node::Hypothesis(h.id.clone())) {
                bad(&h.id, "evidence");
            }
        }
        for s in self.safeguards.values() {
            if !g.node(Node::Safeguard(s.id.clone())) {
                bad(&s.id, "provenance");
            }
        }
    }

    fn check_epistemics(&self, v: &mut Vec<Violation>) {
        // A COMPROMISED trust state is a certainty claim. It must cite a
        // hypothesis that is at least PROBABLE about this entity.
        for e in self.entities.values() {
            if e.trust != TrustState::Compromised {
                continue;
            }
            let backed = e.provenance.sources().iter().any(|s| match s {
                SourceRef::Hypothesis(h) => self.hypotheses.get(h).is_some_and(|h| {
                    h.state() >= EpistemicState::Probable && h.subjects.contains(&e.id)
                }),
                _ => false,
            });
            if !backed {
                v.push(Violation::new(
                    Code::EpistemicOverclaim,
                    e.id.to_string(),
                    "trust=compromised needs a PROBABLE-or-better hypothesis about this entity in its provenance",
                ));
            }
        }
        for t in self.threats.values() {
            if let Some(h) = self.hypotheses.get(&t.hypothesis) {
                for target in &t.targets {
                    if !h.subjects.contains(target) {
                        v.push(Violation::new(
                            Code::EpistemicOverclaim,
                            t.id.to_string(),
                            format!("target {target} is not a subject of {}", h.id),
                        ));
                    }
                }
            }
        }
    }

    fn check_capabilities_and_actions(&self, v: &mut Vec<Violation>) {
        let mut auth = |subject: &dyn fmt::Display, msg: String| {
            v.push(Violation::new(
                Code::AuthorityViolation,
                subject.to_string(),
                msg,
            ));
        };
        let mut verif = Vec::new();
        for a in self.actions.values() {
            let (Some(agent), Some(cap), Some(target)) = (
                self.agents.get(&a.agent),
                self.capabilities.get(&a.capability),
                self.entities.get(&a.target),
            ) else {
                continue; // dangling, already reported
            };
            if !agent.loadout.contains(&cap.id) {
                auth(
                    &a.id,
                    format!("{} does not carry {} in its loadout", agent.id, cap.id),
                );
            }
            if !cap.target_classes.contains(&target.class) {
                auth(
                    &a.id,
                    format!("{} cannot target {:?} entities", cap.id, target.class),
                );
            }
            if !cap.scope.iter().any(|root| self.within(root, &target.id)) {
                auth(
                    &a.id,
                    format!("{} is outside the scope of {}", target.id, cap.id),
                );
            }
            if cap.expired_at(a.proposed_at) {
                auth(
                    &a.id,
                    format!("{} had expired when the action was proposed", cap.id),
                );
            }
            if let Some(appr) = a.approval() {
                let gate = self.effective_gate(cap);
                let authorised_at = a.history.iter().find_map(|t| match t {
                    ActionTransition::Authorise { at, .. } => Some(*at),
                    _ => None,
                });
                let autonomy = self.autonomy_satisfies(cap, appr, gate, authorised_at);
                let sufficient = matches!(
                    (&appr.kind, gate),
                    (_, Gate::Autonomous)
                        | (
                            ApprovalKind::Policy { .. } | ApprovalKind::Human { .. },
                            Gate::PolicyDependent
                        )
                        | (ApprovalKind::Human { .. }, Gate::HumanApproval)
                ) || autonomy.is_ok();
                if let (
                    ApprovalKind::Autonomous {
                        certificate: Some(_),
                        ..
                    },
                    Err(why),
                ) = (&appr.kind, &autonomy)
                {
                    auth(
                        &a.id,
                        format!("autonomous approval not covered by a grant: {why}"),
                    );
                }
                if !sufficient {
                    auth(
                        &a.id,
                        format!(
                            "{gate:?} gate for {:?} not satisfied by {:?} approval",
                            cap.authority, appr.kind
                        ),
                    );
                }
                if let Some(nb) = appr.not_before {
                    let began = a.history.iter().find_map(|t| match t {
                        ActionTransition::BeginExecution { at } => Some(*at),
                        _ => None,
                    });
                    if began.is_some_and(|b| b < nb) {
                        auth(
                            &a.id,
                            format!(
                                "executed inside the human interruption window (not before {nb})"
                            ),
                        );
                    }
                }
                if let ApprovalKind::Autonomous {
                    policy_version,
                    certificate: None,
                } = &appr.kind
                {
                    if policy_version != &self.authority_policy.version {
                        auth(&a.id, format!("autonomous approval cites policy {policy_version:?}, document uses {:?}", self.authority_policy.version));
                    }
                }
                if let Some(ActionTransition::Authorise { at, .. }) = a
                    .history
                    .iter()
                    .find(|t| matches!(t, ActionTransition::Authorise { .. }))
                {
                    if cap.expired_at(*at) {
                        auth(&a.id, format!("{} had expired at authorisation", cap.id));
                    }
                }
            }

            // Effect and verification evidence must be real-world and post-execution.
            let executed_at = a.executed_at();
            for t in &a.history {
                match t {
                    ActionTransition::ObserveEffect { effect, .. } => {
                        let post = effect.direct_observations().iter().any(|o| {
                            self.observations
                                .get(*o)
                                .is_some_and(|o| executed_at.is_some_and(|x| o.observed_at >= x))
                        });
                        if !post {
                            verif.push(Violation::new(
                                Code::VerificationViolation,
                                a.id.to_string(),
                                "effect must cite at least one observation made at or after execution returned",
                            ));
                        }
                    }
                    ActionTransition::Verify { method, .. }
                        if method != &cap.verification_method =>
                    {
                        verif.push(Violation::new(
                            Code::VerificationViolation,
                            a.id.to_string(),
                            format!(
                                "verified by {method:?}, capability requires {:?}",
                                cap.verification_method
                            ),
                        ));
                    }
                    _ => {}
                }
            }
        }
        v.extend(verif);
    }

    fn check_agent_events(&self, v: &mut Vec<Violation>) {
        let mut push = |subject: String, msg: String| {
            v.push(Violation::new(Code::AgentEventViolation, subject, msg));
        };
        let mut last: BTreeMap<&AgentId, &AgentEvent> = BTreeMap::new();
        // (action -> phases that referenced it)
        let mut referenced: BTreeMap<&ActionId, BTreeSet<AgentPhase>> = BTreeMap::new();
        for ((agent_id, seq), e) in &self.agent_events {
            let subj = format!("{agent_id}#{seq}");
            if e.reason.trim().is_empty() {
                push(subj.clone(), "event needs a reason".into());
            }
            if let Some(prev) = last.get(agent_id) {
                if !prev.phase.can_transition_to(e.phase) {
                    push(
                        subj.clone(),
                        format!("illegal phase transition {:?} -> {:?}", prev.phase, e.phase),
                    );
                }
                if e.at < prev.at {
                    push(
                        subj.clone(),
                        format!("time runs backwards ({} < {})", e.at, prev.at),
                    );
                }
            } else if e.phase != AgentPhase::Perceive {
                push(
                    subj.clone(),
                    format!("an agent's first event must be PERCEIVE, got {:?}", e.phase),
                );
            }
            last.insert(agent_id, e);

            // Authority claimed by the event must be (a) allowed in this
            // phase and (b) actually held.
            if let Some(ceiling) = e.phase.authority_ceiling() {
                if e.authority > ceiling {
                    push(
                        subj.clone(),
                        format!("{:?} cannot exercise {:?}", e.phase, e.authority),
                    );
                }
            }
            if let Some(agent) = self.agents.get(agent_id) {
                let held = agent
                    .loadout
                    .iter()
                    .filter_map(|c| self.capabilities.get(c))
                    .map(|c| c.authority)
                    .max()
                    .unwrap_or(AuthorityLevel::Observe);
                if e.authority > held {
                    push(
                        subj.clone(),
                        format!("claims {:?} but loadout tops out at {held:?}", e.authority),
                    );
                }
            }
            if e.phase == AgentPhase::Act {
                match e.action.as_ref().and_then(|a| self.actions.get(a)) {
                    None => push(
                        subj.clone(),
                        "ACT event must name the action it executes".into(),
                    ),
                    Some(a) => {
                        if &a.agent != agent_id {
                            push(subj.clone(), format!("{} belongs to {}", a.id, a.agent));
                        }
                        if let Some(c) = self.capabilities.get(&a.capability) {
                            if e.authority != c.authority {
                                push(
                                    subj.clone(),
                                    format!(
                                        "ACT claims {:?}, {} is {:?}",
                                        e.authority, c.id, c.authority
                                    ),
                                );
                            }
                        }
                    }
                }
            }
            if let Some(a) = &e.action {
                referenced.entry(a).or_default().insert(e.phase);
            }
            if e.objective.as_ref().is_some_and(|o| o.trim().is_empty()) {
                push(
                    subj.clone(),
                    "objective, if declared, must not be empty".into(),
                );
            }
            if let Some(n) = &e.next {
                if !e.phase.can_transition_to(n.phase) {
                    push(
                        subj.clone(),
                        format!(
                            "declared next phase {:?} is not a legal successor of {:?}",
                            n.phase, e.phase
                        ),
                    );
                }
                if n.intent.trim().is_empty() {
                    push(subj.clone(), "declared next step needs an intent".into());
                }
                if let Some(t) = &n.target {
                    if !self.entities.contains_key(t) {
                        push(
                            subj.clone(),
                            format!("declared next target {t} does not exist"),
                        );
                    }
                }
            }
        }

        // §19: action without agent event.
        for a in self.actions.values() {
            let phases = referenced.get(&a.id);
            if !phases.is_some_and(|p| p.contains(&AgentPhase::Plan)) {
                push(
                    a.id.to_string(),
                    "no PLAN agent event proposes this action".into(),
                );
            }
            let began = a
                .history
                .iter()
                .any(|t| matches!(t, ActionTransition::BeginExecution { .. }));
            if began && !phases.is_some_and(|p| p.contains(&AgentPhase::Act)) {
                push(
                    a.id.to_string(),
                    "action executed without an ACT agent event".into(),
                );
            }
        }
    }
}
