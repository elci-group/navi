# Navi — Cyber-Realm Projection System

ELCI security-infrastructure project (codename `navi`). The goal, per
[`DIRECTIVE.md`](DIRECTIVE.md), is a live, provenance-preserving spatial
representation of security state in which a defensive agent ("Navi") has an
embodied, observable presence.

```text
machine state → semantic state → spatial state → human perception
```

**Status: Phase 1 (deterministic 2D realm) complete.** Phase 0 built the
semantic layer; Phase 1 projects it into a spatial realm with a terminal and
an SVG renderer.

![The repo + runtime scenario rendered as a realm](docs/realm-repo-runtime.svg)

*`tests/fixtures/scenarios/repo-runtime.json`: a delivery region (repo,
branch, CI, artifact, registry) and a production region (ingress, services,
pods, database). Navi is attending to `api-5d2b-2`, whose unattributed
outbound connection is `SUSPICIOUS` at 55% — rendered as `?`, not as an
enemy — and its proposed `ISOLATE` waits on human approval. Hover any
element for its provenance.*

## What exists

| Crate | Role |
|---|---|
| `navi-ontology` | The canonical vocabulary: observations, entities, relationships, hypotheses, threats, safeguards, capabilities, authority, agents, actions, provenance, confidence. Each type enforces its own invariants on construction **and** on deserialization. |
| `navi-graph` | The semantic state graph. Validates a whole document (references, provenance grounding, authority fidelity, agent event stream), produces a canonical form + `sha256` digest, and reverse-resolves any object to raw observations. |
| `navi-cli` | The `navi` binary. |
| `realm-core` | The versioned realm grammar (§3), Realm IR (§4), visual contracts, and the validator every renderer must pass. |
| `realm-compiler` | `SemanticGraph → Realm`. Pure and deterministic; no security reasoning of its own. |
| `realm-layout` | Deterministic 2D containment layout on an integer grid. |
| `realm-render` | Disposable renderers: terminal text and standalone SVG. No security logic. |
| `realm-cli` | The `realm` binary. |

`navi-*` crates never depend on `realm-*` (enforced by a test): Navi runs
with the renderer absent.

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

## Realm invariants (Phase 1)

| Directive clause | Enforcement |
|---|---|
| §3 Stable grammar | Every primitive's meaning is fixed in `realm-grammar/0.1`; renderers refuse realms of any other grammar or ontology version. Colours are semantic tokens with one palette per grammar version. |
| §4 Renderer cannot invent semantics | `Realm::validate` recomputes every primitive *and* every visual contract from the semantics carried beside it. A forged enemy, a prettified trust colour, an inflated confidence label, or a hidden boundary crossing is refused, and the renderers draw nothing. |
| §5 No pixel without provenance | Every realm id derives from its primary source id; every SVG element carries `data-source-ids` and a `<title>` with its provenance. Tests resolve every realm object back to raw observations. |
| §6 Epistemic rendering | Hazards are fog below `ANOMALOUS`, `?` unknown entities through `SUSPICIOUS`, and enemies only from `PROBABLE`; below that the claim is shown as a question (`c2_beacon?`). Confidence is shown exactly with its estimator. Unattributed threats have actor `?`. |
| §7 / §8 Agent | Navi's position, phase, belief and confidence come only from structured agent events, each cited in `source_ids`; the HUD shows bounded telemetry, not reasoning text. |
| §10 Authority fidelity | The HUD lists exactly the loadout with each capability's effective gate; showing an action outside the loadout, or a reality-mutating capability as autonomous, is refused. |
| §26 Determinism | Same state + same compiler version gives byte-identical RIR, layout and SVG, independent of input order. |
| §26 Graceful incompleteness | Unplaced entities sit outside the estate instead of being guessed into it; stale entities are dashed and marked; controls whose enforcement wasn't observed don't count as guarding anything. |

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

```sh
realm render tests/fixtures/scenarios/repo-runtime.json            # terminal map + HUD
realm render tests/fixtures/scenarios/repo-runtime.json -f svg -o realm.svg
realm compile <state.json> -o realm.json   # Realm IR
realm check realm.json                     # what a renderer checks before drawing
realm render realm.json                    # renders RIR or state documents
realm grammar                              # the §3 grammar table
```

`navi explain … thr:stuffing` descends enemy → hypothesis → evidence → raw
observation (directive §26, reverse resolution):

```text
[threat] thr:stuffing  actor ent:src-cluster → ent:public-auth, ent:auth-api; classification PROBABLE @ 83.00% (auth-anomaly@0.1)
└── [hypothesis] hyp:cred-stuffing  credential_stuffing — PROBABLE @ 83.00% (auth-anomaly@0.1) ATT&CK TA0006,T1110.004
    ├── [observation] obs:auth-fail  auth.failure_ratio {"ratio":0.962,"window_s":60} from auth-api/otel/prod-eu-1 at t+1000ms
    ├── ...
```

## Deliberate limits so far

- ATT&CK / D3FEND references are **shape-validated only**. No technique
  catalogue ships, because inventing names for ids would itself be
  fabrication; catalogue resolution belongs in the future `navi-attck` /
  `navi-d3fend` crates.
- Timestamps are integer milliseconds. Wall-clock formatting is a
  presentation concern.
- Documents are validated whole. The event-sourced log with snapshot +
  delta streaming (§15, §22) is Phase 3.
- STIX import/export does not exist yet.
- The realm is a snapshot: Navi does not yet move through it over time
  (Phase 2), and there is no replay (Phase 3).
- An entity with several `contains` parents is nested under the first by
  relationship id; edges are drawn centre-to-centre without routing.

## Roadmap

See [`ROADMAP.md`](ROADMAP.md).

## Testing

```sh
cargo test                                   # 113 tests
cargo clippy --all-targets -- -D warnings
```

Acceptance tests (`crates/navi-graph/tests/acceptance.rs`,
`crates/realm-compiler/tests/phase1.rs`) each start from a valid scenario
and inject exactly one fault — into the semantic graph for Phase 0, into
compiled Realm IR for Phase 1.
