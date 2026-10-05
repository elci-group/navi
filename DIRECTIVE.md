# ELCI Technical Directive — Cyber-Realm / Navi

> Source directive for this repository, preserved verbatim (2026-10-05;
> only `utm_source` tracking parameters were stripped from links) so
> that later phases are built against the actual text.

**Directive class:** Security Infrastructure / Agentic Observability  
**Working codename:** `navi`  
**Conceptual metaphor:** MegaMan Battle Network  
**Primary objective:** Convert live computational infrastructure, security state, uncertainty, defensive controls, and autonomous-agent behaviour into a deterministic, explorable, human-comprehensible spatial environment.

The implementation MUST treat the cyber-realm as an **observability projection**, never as the source of security truth.

Existing standards provide useful primitives rather than requiring ELCI to invent an isolated security ontology: STIX 2.1 provides a machine-readable representation of cyber-threat and observable information; ATT&CK itself is distributed in STIX and models adversary techniques; D3FEND provides an ontology for defensive countermeasures and mappings from STIX objects into defensive artefacts. [OASIS Open](https://www.oasis-open.org/standard/stix2-1/)

---

## 1. Governing proposition

ELCI SHALL construct a **Cyber-Realm Projection System (CRPS)** in which:

> **machine state → semantic state → spatial state → human perception**

rather than:

> machine state → pretty graph.

The system exists to answer, continuously and visually:

**What exists? What is happening? What does Navi currently know? What does Navi suspect? Where is Navi looking? Why is it looking there? What can it do? What has it done? What changed because of it?**

A competent operator watching the realm without reading raw logs SHOULD acquire a materially useful understanding of system security state.

An expert MUST always be able to descend from any visual abstraction to the evidence that caused it to exist.

---

# 2. Non-negotiable architectural invariant

```text
REALITY != REALM
```

The realm MUST NOT become authoritative system state.

Architecture:

```text
                    ┌─────────────────────────────┐
                    │       PHYSICAL REALITY      │
                    │                             │
                    │ Hosts · Processes · IAM     │
                    │ Git · CI · Cloud · Network  │
                    │ Files · APIs · Containers   │
                    └──────────────┬──────────────┘
                                   │
                              telemetry
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────┐
│                 REALITY / EVIDENCE PLANE                  │
│                                                           │
│ normalized entities · events · relationships · provenance │
└─────────────────────────────┬─────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────┐
│                    SEMANTIC STATE GRAPH                   │
│                                                           │
│ identity · topology · trust · policy · risk · history     │
│ ATT&CK · D3FEND · STIX · ELCI extensions                  │
└──────────────┬──────────────────────────┬─────────────────┘
               │                          │
               ▼                          ▼
      ┌────────────────┐         ┌────────────────┐
      │  NAVI RUNTIME  │         │ REALM COMPILER │
      │                │         │                │
      │ perceive       │         │ topology       │
      │ investigate    │         │ geometry       │
      │ hypothesise    │         │ semantics      │
      │ plan           │         │ LOD            │
      │ intervene      │         │ rendering      │
      └───────┬────────┘         └────────┬───────┘
              │                           │
              └────────────┬──────────────┘
                           ▼
                ┌─────────────────────┐
                │   OBSERVER PLANE    │
                │                     │
                │  realtime "game"    │
                │  SOC view           │
                │  CLI                │
                │  replay             │
                │  audit              │
                └─────────────────────┘
```

No rendering-layer state MAY independently modify reality.

---

# 3. Universal realm grammar

ELCI SHALL define a stable mapping between computational semantics and spatial semantics.

| Realm primitive | Canonical meaning |
|---|---|
| Universe | managed estate |
| World | organisation / trust authority |
| Region | environment / major security zone |
| District | domain / subnet / cluster / service family |
| Building | host / application / substantial workload |
| Room | process / container / component |
| Road | permitted communication relationship |
| Bridge | cross-boundary dependency |
| Portal | API / ingress / integration |
| Door | authenticated access boundary |
| Wall | policy / ACL / firewall |
| Guard | active enforcement mechanism |
| Object | resource / artefact |
| Vault | sensitive data store |
| NPC | known benign actor/service |
| Unknown entity | insufficiently classified actor |
| Enemy | sufficiently evidenced hostile behaviour |
| Corruption | compromised/degraded trust |
| Fog | epistemic uncertainty |
| Navi | defensive autonomous agent |
| Weapon/tool | authorised defensive capability |
| Damage | measurable adverse state transition |
| Healing | verified remediation |
| Teleport | non-topological logical transition |

This ontology MUST be versioned.

Visual meaning MUST NOT drift between sessions.

A red door cannot mean "unauthenticated ingress" today and "critical vulnerability" tomorrow.

---

# 4. Semantic world compiler

Create:

```text
realm-compiler/
```

Its responsibility is to transform the canonical state graph into a **Realm Intermediate Representation — RIR**.

Illustrative structure:

```rust
Realm {
    id,
    epoch,
    topology,
    entities,
    relationships,
    hazards,
    safeguards,
    uncertainty,
    agent_states,
    provenance,
}
```

Every rendered object MUST contain:

```rust
RealmEntity {
    realm_id,
    source_ids,
    entity_class,
    semantic_type,
    trust_state,
    confidence,
    risk,
    relationships,
    visual_contract,
    observed_at,
    valid_until,
    provenance,
}
```

The renderer MUST therefore be incapable of inventing security semantics merely to improve visual presentation.

---

# 5. Provenance invariant

Adopt:

> **NO PIXEL WITHOUT PROVENANCE**

More precisely:

Any visual element purporting to communicate system state MUST resolve to one or more canonical observations, derived facts, policies, hypotheses or agent actions.

For example:

```text
"enemy attacking gateway"
        │
        ▼
RealmThreatEntity
        │
        ▼
ThreatHypothesis
        │
        ├── 4,271 requests/min
        ├── 96.2% auth failure
        ├── 312 novel identities
        ├── source distribution anomaly
        └── reputation correlation
```

Selecting any entity SHALL expose this chain.

---

# 6. Epistemic rendering

Navi MUST distinguish **observation from inference**.

Do not render:

```text
ANOMALY = ENEMY
```

Instead implement an epistemic state machine:

```text
UNSEEN
  ↓
OBSERVED
  ↓
UNEXPLAINED
  ↓
ANOMALOUS
  ↓
SUSPICIOUS
  ↓
PROBABLE
  ↓
CONFIRMED
```

The visual representation SHOULD progressively resolve accordingly.

For example:

```text
fog
 ↓
movement
 ↓
silhouette
 ↓
unknown entity
 ↓
classified hostile entity
 ↓
identified technique/campaign
```

Confidence MUST remain independently inspectable.

A 0.51 hypothesis and a 0.99 determination MUST NOT appear epistemically equivalent.

---

# 7. Navi agent contract

Navi is not an animated avatar attached to an LLM.

Navi is a **defensive control-plane actor with a rendered embodiment**.

Its mandatory execution loop SHALL be:

```text
PERCEIVE
   ↓
ORIENT
   ↓
HYPOTHESISE
   ↓
INVESTIGATE
   ↓
EVALUATE
   ↓
PLAN
   ↓
AUTHORISE
   ↓
ACT
   ↓
VERIFY
   ↓
LEARN
```

Every transition MUST emit a structured event.

Example:

```json
{
  "agent": "navi-01",
  "phase": "INVESTIGATE",
  "target": "service://identity/auth",
  "reason": "authentication anomaly",
  "hypothesis": "credential_stuffing",
  "confidence": 0.83,
  "authority": "observe_only"
}
```

The visual client consumes these events.

It MUST NOT infer agent intent from animation.

---

# 8. Visible cognition

Navi SHALL expose a bounded **reasoning telemetry interface**, not private free-form chain-of-thought.

Operators require:

```text
OBSERVATION
HYPOTHESIS
EVIDENCE
CONFIDENCE
CURRENT OBJECTIVE
SELECTED TARGET
PLANNED ACTION
AUTHORITY
EXPECTED EFFECT
ACTUAL EFFECT
```

Example HUD:

```text
NAVI / LC-DEFENCE-01
──────────────────────────────────

OBJECTIVE
Investigate anomalous authentication traffic

TARGET
prod → identity → public-auth

OBSERVED
Request rate +4,493%

HYPOTHESIS
Distributed credential stuffing

CONFIDENCE
94%

ATT&CK
Credential Access

NEXT
Inspect identity/source correlation

AUTHORITY
OBSERVE
SIMULATE
PROPOSE

BLOCK
LOCK
QUARANTINE
        [HUMAN APPROVAL REQUIRED]
```

ATT&CK is suitable for this classification layer because it provides a machine-readable knowledge base of adversary tactics and techniques rather than merely a visualization taxonomy. [MITRE ATT&CK](https://attack.mitre.org/resources/attack-data-and-tools/)

---

# 9. Capability-as-loadout

Defensive authority SHALL be represented as a Navi loadout.

Examples:

```text
SCAN          telemetry query
TRACE         causal/path analysis
SCOPE         deep inspection
SHIELD        rate limiting
BARRIER       ACL/WAF/firewall modification
LOCK          credential revocation
ISOLATE       workload quarantine
CLEANSE       remediation
RESTORE       known-good restoration
RECALL        rollback
BEACON        human escalation
DRONE         delegated investigation
```

Every capability requires:

```text
capability
scope
target_classes
authority
risk_class
approval_requirement
rollback_method
verification_method
expiry
```

D3FEND SHOULD inform the defensive vocabulary where applicable; its model explicitly describes countermeasures and relationships to cyber artefacts, complementing ATT&CK's adversary-oriented model. [MITRE D3FEND](https://d3fend.mitre.org/resources/D3FEND.pdf)

---

# 10. Human authority model

Default production policy:

```text
OBSERVE      autonomous
QUERY        autonomous
CORRELATE    autonomous
SIMULATE     autonomous
PROPOSE      autonomous

TEMPORARY LOW-RISK CONTAINMENT
             policy dependent

CREDENTIAL REVOCATION
NETWORK ISOLATION
DESTRUCTIVE REMEDIATION
PERMANENT POLICY CHANGE
             human/policy approval
```

Authority MUST be visually apparent.

A Navi incapable of modifying a database SHOULD visibly lack the corresponding capability.

**UI affordance MUST NOT exceed actual authority.**

---

# 11. Attention-dependent geometry

Do not attempt a one-to-one rendering of an entire enterprise.

That will produce visual entropy.

Implement **Semantic Level of Detail (SLOD).**

At distance:

```text
Organisation
    ↓
Production
```

Approaching:

```text
Production
 ├── Identity
 ├── Payments
 ├── Storage
 └── Edge
```

Investigating Identity:

```text
Identity
 ├── auth-api
 ├── session-service
 ├── oauth-gateway
 └── identity-db
```

Deep investigation:

```text
auth-api
 ├── pod-771
 ├── pod-772
 └── pod-773
      ├── process
      ├── socket
      └── credential context
```

The world therefore becomes more detailed **in the direction of operational attention**.

---

# 12. Context-sensitive realm generation

Geometry SHALL adapt to the security problem while semantic primitives remain invariant.

An IAM investigation should privilege:

```text
identity → credential → role → permission → resource
```

A network incident:

```text
host → interface → connection → boundary → destination
```

A supply-chain incident:

```text
developer
    ↓
repository
    ↓
dependency
    ↓
CI
    ↓
artefact
    ↓
registry
    ↓
deployment
```

A DreamSequence/Cortex investigation could instead expose:

```text
repo
 ↓
branch
 ↓
workflow
 ↓
build
 ↓
artifact
 ↓
deployment
 ↓
runtime
```

The Realm Compiler therefore performs **semantic cartography**, not generic graph drawing.

---

# 13. Threat choreography

Threat movement MUST represent actual causal or potential attack-path relationships.

An attacker cannot visually walk through a wall simply because that creates attractive animation.

Movement means something.

Examples:

```text
crossing bridge
= communication/dependency traversal

opening door
= authentication/authorization success

breaking door
= access-control defeat

entering room
= execution/access within component

corrupting object
= integrity/trust change

replicating
= propagation

hiding
= reduced observability/evasion

attacking Navi
= interference with defensive capability
```

The visual simulation MUST therefore obey the canonical security graph.

---

# 14. Threat-framework integration

Use standards as interoperability layers rather than allowing them to dictate the complete ELCI ontology.

Recommended relationship:

```text
                 ELCI SECURITY ONTOLOGY
                        │
             ┌──────────┼──────────┐
             │          │          │
           STIX       ATT&CK     D3FEND
             │          │          │
          exchange    offense    defence
```

ATT&CK itself builds its specification on STIX 2.1 and adds ATT&CK-specific objects and constraints, making this composition technically natural. [MITRE ATT&CK](https://mitre-attack.github.io/attack-data-model/docs/principles/attack-specification-overview/)

ELCI extensions SHOULD represent concepts the external standards do not adequately capture, particularly:

```text
agent attention
agent authority
agent hypothesis
epistemic confidence
investigation state
simulated intervention
approval state
realm geometry
causal provenance
counterfactual outcome
```

---

# 15. Time must be first-class

Every state transition MUST be event sourced.

The cyber realm MUST support:

```text
LIVE
PAUSE
STEP
REWIND
REPLAY
COMPARE
FORK
```

`FORK` is especially important.

At any historical point an operator SHOULD be able to ask:

> What would Navi have done if quarantine authority had been enabled here?

This creates a counterfactual simulation branch without modifying production.

---

# 16. Security DVR

Record sufficient state to deterministically reconstruct incidents.

An incident replay might become:

```text
12:43:17  unknown outbound connection
12:43:18  Navi observes
12:43:19  process ancestry correlated
12:43:21  destination intelligence retrieved
12:43:24  C2 hypothesis = 0.87
12:43:26  containment simulation begins
12:43:29  dependency impact calculated
12:43:31  quarantine recommended
12:43:34  human approval received
12:43:35  workload isolated
12:43:38  connection terminates
12:43:44  service redundancy verified
12:43:51  incident contained
```

The operator should literally be able to **watch this happen again**.

---

# 17. Counterfactual ghosts

When Navi considers multiple interventions, the realm SHOULD optionally render proposed outcomes as non-authoritative "ghost" states.

For example:

```text
CURRENT
   │
   ├── quarantine pod ──► predicted service impact 0%
   │
   ├── block IP ────────► predicted evasion probability 71%
   │
   └── revoke token ────► predicted containment 94%
```

The operator can therefore understand *why* Navi recommends one action rather than another without requiring access to hidden reasoning.

---

# 18. Multi-agent operation

The architecture MUST anticipate multiple Navis.

```text
NAVI
├── Sentinel       broad observation
├── Tracker        entity/path investigation
├── Hunter         threat hypothesis testing
├── Guardian       defensive intervention
├── Medic          remediation/restoration
├── Archivist      provenance/replay
└── Scout          delegated exploration
```

These need not initially be separate models.

They SHOULD initially represent **roles/capability boundaries**.

If later distributed across specialised models or providers, the visualization contract remains unchanged.

This also fits naturally with ELCI's broader specialised-agent/swarm architecture.

---

# 19. Anti-hallucination requirements

The renderer MUST reject:

```text
entity without source
relationship without evidence
threat without classification state
action without agent event
damage without state delta
remediation without verification
confidence without estimator/source
```

The system SHOULD fail visually conservative.

Unknown becomes:

```text
?
```

not an invented explanation.

---

# 20. Safety invariant

The most important Navi lifecycle rule is:

```text
DETECT != DIAGNOSE
DIAGNOSE != PROPOSE
PROPOSE != AUTHORISE
AUTHORISE != EXECUTE
EXECUTE != SUCCESS
SUCCESS != VERIFIED
```

Each transition requires independently represented state.

This prevents the UI—and eventually the autonomous system itself—from collapsing:

> "I think this is malicious"

into:

> "I may therefore destroy it."

---

# 21. Renderer architecture

Keep rendering technologically disposable.

```text
realm-core
    ↓
realm-protocol
    ↓
 ┌──────────┬───────────┬───────────┬──────────┐
 │          │           │           │
 WebGL     Desktop      CLI         XR
 Realm     Realm        Realm       Realm
```

A renderer consumes something resembling:

```text
RealmSnapshot
RealmDelta
AgentEvent
ThreatEvent
ControlEvent
EvidenceEvent
```

It MUST NOT contain security logic.

This allows a lightweight 2D implementation first and a sophisticated 3D implementation later without rewriting Navi.

---

# 22. Performance model

Do **not** stream complete world snapshots.

Use:

```text
snapshot + ordered deltas
```

For example:

```text
t0 FULL STATE
t1 + entity
t2 ~ trust(entity)
t3 + connection
t4 + hypothesis
t5 ~ Navi.target
t6 + proposed_action
```

Clients reconstruct local state.

The target experience should feel realtime even where underlying security reasoning is asynchronous.

Movement can interpolate between authoritative state transitions; **semantic events cannot**.

---

# 23. Suggested Rust workspace

For ELCI, I would make the system aggressively modular:

```text
navi/
├── Cargo.toml
├── crates/
│   ├── navi-core/
│   ├── navi-events/
│   ├── navi-evidence/
│   ├── navi-ontology/
│   ├── navi-topology/
│   ├── navi-trust/
│   ├── navi-threat/
│   ├── navi-policy/
│   ├── navi-authority/
│   ├── navi-agent/
│   ├── navi-planner/
│   ├── navi-simulator/
│   ├── navi-actions/
│   ├── navi-verifier/
│   ├── navi-attck/
│   ├── navi-d3fend/
│   ├── navi-stix/
│   ├── realm-core/
│   ├── realm-compiler/
│   ├── realm-protocol/
│   ├── realm-layout/
│   ├── realm-replay/
│   ├── realm-server/
│   ├── realm-web/
│   └── realm-cli/
└── tests/
    ├── fixtures/
    ├── scenarios/
    ├── replay/
    ├── provenance/
    ├── authority/
    └── adversarial/
```

The separation between `navi-*` and `realm-*` is deliberate.

**Navi must be capable of operating with the renderer completely absent.**

---

# 24. Integration with Lucid / DreamSequence

The higher-order architecture becomes particularly interesting inside the existing ELCI stack.

```text
                DREAMSEQUENCE
                      │
       ┌──────────────┼───────────────┐
       │              │               │
    Cortex          Lucid           Navi
       │              │               │
 repository       reasoning       defence
 cognition       orchestration     cognition
       │              │               │
       └──────────────┼───────────────┘
                      │
                 REALITY GRAPH
                      │
                      ▼
                  CYBER REALM
```

Cortex knows **what the software estate is**.

Lucid can reason about **what should happen**.

Navi observes **what is happening and whether it is safe**.

The Realm provides the human with a common visual language across all three.

That is considerably more ambitious than a security visualization.

It becomes an **ELCI spatial representation of computational state**.

---

# 25. MVP

Do not start with a 3D city.

That would optimise the least important layer first.

Build:

**Phase 0 — ontology**

```text
entity
relationship
observation
hypothesis
confidence
threat
safeguard
agent
capability
action
authority
provenance
```

**Phase 1 — deterministic 2D realm**

One repository + one runtime environment.

Render:

```text
services
processes
connections
boundaries
Navi
anomalies
controls
```

**Phase 2 — Navi traversal**

Agent attention produces movement.

Clicking Navi explains:

```text
where
why
what
confidence
next
```

**Phase 3 — replay**

Record and reproduce an entire simulated incident.

**Phase 4 — intervention**

Introduce sandboxed:

```text
block
isolate
revoke
rollback
```

with policy gates.

**Phase 5 — adaptive world generation**

Add semantic LOD and domain-specific geography.

**Phase 6 — production autonomy**

Only after deterministic replay, provenance, rollback, authority and verification have demonstrated sufficient reliability.

---

# 26. Acceptance tests

The implementation SHALL NOT be considered ELCI-grade until these hold:

**Determinism:** identical canonical state + realm compiler version produces semantically identical realm state.

**Provenance completeness:** every security-significant visual entity resolves to evidence.

**Reverse resolution:** an operator can move from enemy → hypothesis → evidence → raw observation.

**Authority fidelity:** Navi cannot visually or operationally exercise capabilities it does not possess.

**Epistemic fidelity:** uncertainty cannot be visually represented as certainty.

**Replay fidelity:** recorded incidents reconstruct their semantic state transitions.

**Renderer independence:** Navi continues operating headlessly.

**Graceful incompleteness:** missing telemetry creates explicit unknown state rather than fabricated topology.

**Human interruption:** authorised operators can stop pending autonomous interventions.

**Verification:** interventions cannot enter `SUCCESS` solely because their command returned successfully.

---

# 27. Governing ELCI doctrine

The system should ultimately obey six laws:

> **I. Reality precedes representation.**  
> The map is never authoritative over the territory.
>
> **II. Every representation carries provenance.**  
> Nothing security-significant may appear without an evidentiary path.
>
> **III. Uncertainty remains uncertainty.**  
> Visualization may simplify complexity but never manufacture certainty.
>
> **IV. Agency must be observable.**  
> Humans must be able to understand where Navi is, what it is pursuing, what it believes, what it proposes and what authority it possesses.
>
> **V. Intervention must be reversible wherever technically possible.**  
> Autonomous defence should prefer bounded, expiring and recoverable actions.
>
> **VI. The realm compresses complexity; it does not conceal it.**  
> Every abstraction must permit descent into underlying technical reality.

The end state is therefore not **"MegaMan for cybersecurity."**

It is a **live, provenance-preserving spatial representation of machine epistemology and computational reality**, in which the autonomous defender happens to possess an embodied representation.

That distinction is what makes the MegaMan metaphor architecturally useful rather than merely cosmetic.
