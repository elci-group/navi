# Navi — Cyber-Realm Projection System

ELCI security-infrastructure project (codename `navi`). The goal, per
[`DIRECTIVE.md`](DIRECTIVE.md), is a live, provenance-preserving spatial
representation of security state in which a defensive agent ("Navi") has an
embodied, observable presence.

```text
machine state → semantic state → spatial state → human perception
```

**Status: Phase 0 (ontology) complete.** There is no renderer yet, by
design: the directive's MVP builds the semantic layer first.

## What exists

| Crate | Role |
|---|---|
| `navi-ontology` | The canonical vocabulary: observations, entities, relationships, hypotheses, threats, safeguards, capabilities, authority, agents, actions, provenance, confidence. Each type enforces its own invariants on construction **and** on deserialization. |
| `navi-graph` | The semantic state graph. Validates a whole document (references, provenance grounding, authority fidelity, agent event stream), produces a canonical form + `sha256` digest, and reverse-resolves any object to raw observations. |
| `navi-cli` | The `navi` binary. |

## Invariants enforced today

| Directive clause | Enforcement |
|---|---|
| §5 No pixel without provenance | `Provenance` cannot be empty; every source must exist and **ground out in real observations** (cycles and fabricated ids are `UNGROUNDED_PROVENANCE`). |
| §6 Observation ≠ inference | Hypotheses climb `UNSEEN → … → CONFIRMED` one step at a time, each promotion needs *new* evidence, `PROBABLE` needs ≥ 0.60 and `CONFIRMED` ≥ 0.90 (versioned `EpistemicPolicy`). They cannot open above `SUSPICIOUS`. Confidence is stored in basis points: 0.51 ≠ 0.99. |
| §7 Agent loop | `AgentEvent` streams must start at `PERCEIVE` and follow legal phase edges; pre-`ACT` phases cannot claim more than `PROPOSE` authority. |
| §9 Capability-as-loadout | Every capability carries all nine required fields. A kind cannot under-declare its authority (`LOCK` is never "observe"), and even if it tries it is still gated at its intrinsic level. |
| §10 Human authority | Default production policy built in; unlisted levels fail closed to human approval; reality-mutating levels can never be made `Autonomous` by policy. |
| §19 Anti-hallucination | Entities without a source, relationships without evidence, threats without a classifying hypothesis, actions without agent events, success without an observed state delta, and confidence without an estimator are all rejected. |
| §20 Safety invariant | `PROPOSED → AUTHORISED → EXECUTING → EXECUTED → SUCCEEDED → VERIFIED` are distinct, evidenced states. A command's return code is not success; success needs post-execution observations that are not the action's own report; verification must add independent evidence and use the capability's declared method. Pending actions can be cancelled by a human; executing ones cannot be "cancelled", only rolled back. |
| §26 Determinism | Canonical form is independent of input order and is a fixed point; the digest changes iff semantics change. |
| §26 Graceful incompleteness | Missing telemetry yields explicit violations; `unknown` is a first-class entity class and trust state. Threat actors may be absent (renders as `?`, never invented). |

## Usage

```sh
cargo build
navi validate tests/fixtures/scenarios/credential-stuffing.json   # exit 0
navi validate tests/fixtures/adversarial/invented-attacker.json   # exit 1, lists violations
navi explain  tests/fixtures/scenarios/credential-stuffing.json thr:stuffing
navi digest   tests/fixtures/scenarios/credential-stuffing.json
navi canonical <file>
navi policy
```

`--json` is available on `validate` and `explain`.

`navi explain … thr:stuffing` descends enemy → hypothesis → evidence → raw
observation (directive §26, reverse resolution):

```text
[threat] thr:stuffing  actor ent:src-cluster → ent:public-auth, ent:auth-api; classification PROBABLE @ 83.00% (auth-anomaly@0.1)
└── [hypothesis] hyp:cred-stuffing  credential_stuffing — PROBABLE @ 83.00% (auth-anomaly@0.1) ATT&CK TA0006,T1110.004
    ├── [observation] obs:auth-fail  auth.failure_ratio {"ratio":0.962,"window_s":60} from auth-api/otel/prod-eu-1 at t+1000ms
    ├── ...
```

## Deliberate Phase 0 limits

- ATT&CK / D3FEND references are **shape-validated only**. No technique
  catalogue ships, because inventing names for ids would itself be
  fabrication; catalogue resolution belongs in the future `navi-attck` /
  `navi-d3fend` crates.
- Timestamps are integer milliseconds. Wall-clock formatting is a
  presentation concern.
- Documents are validated whole. The event-sourced log with snapshot +
  delta streaming (§15, §22) is Phase 3.
- STIX import/export does not exist yet.

## Roadmap

See [`ROADMAP.md`](ROADMAP.md).

## Testing

```sh
cargo test                                   # 78 tests
cargo clippy --all-targets -- -D warnings
```

Acceptance tests (`crates/navi-graph/tests/acceptance.rs`) each start from
the valid scenario and inject exactly one fault.
