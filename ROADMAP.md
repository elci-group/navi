# Roadmap

Phases follow directive §25. Each one is built and tested for real before
the next one starts.

- [x] **Phase 0 — ontology.** `navi-ontology`, `navi-graph`, `navi-cli`.
      Covers entity, relationship, observation, hypothesis, confidence,
      threat, safeguard, agent, capability, action, authority, provenance.
- [x] **Phase 1 — deterministic 2D realm.** `realm-core` (versioned realm
      grammar §3, RIR §4, renderer-side validator §19), `realm-compiler`,
      `realm-layout`, `realm-render` (text + SVG), `realm-cli`. Scenario:
      one repository + one runtime environment.
- [x] **Phase 2 — Navi traversal.** Ontology 0.2 (declared `objective` /
      `next`), headless `navi brief`, validated attention routes over realm
      topology, evidence chains in the realm, `realm trace`, interactive
      HTML timeline.
- [x] **Phase 3 — replay.** `navi-events` (prefix-valid incident log,
      snapshot derivation, counterfactual forks, DVR lines), `realm-replay`
      (frames, snapshot + deltas with digests, reconstruction, COMPARE),
      DVR page, counterfactual banners.
- [x] **Phase 4 — intervention.** `navi-simulator` (sandbox with fault
      injection), `navi-actions` (approve / cancel in the log; run / roll
      back in the sandbox as counterfactual branches), ontology 0.3
      (verified interventions can be lifted), token-theft scenario.
- [x] **Phase 5 — adaptive world generation.** `realm-lod`: attention-driven
      level of detail with aggregates and re-anchoring checked against
      concealment; IAM / network / supply-chain lenses chosen from data.
- [ ] **Phase 6 — production autonomy.** Only after replay, provenance,
      rollback, authority and verification have demonstrated reliability.

All §26 acceptance criteria now have tests. Renderer independence is
enforced by a test: `navi-*` crates never depend on `realm-*`. Still to
come: a Navi simulator, so a fork can ask what Navi *would* have done
rather than only record what an operator supposes.
