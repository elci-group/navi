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
- [ ] **Phase 2 — Navi traversal.** Agent attention drives movement;
      selecting Navi explains where/why/what/confidence/next (§8 HUD).
- [ ] **Phase 3 — replay.** Event-sourced log, snapshot + ordered deltas,
      LIVE/PAUSE/STEP/REWIND/REPLAY/COMPARE/FORK (§15, §16, §22).
- [ ] **Phase 4 — intervention.** Sandboxed block/isolate/revoke/rollback
      behind the policy gates that Phase 0 already models.
- [ ] **Phase 5 — adaptive world generation.** Semantic LOD, domain-specific
      geography (§11, §12).
- [ ] **Phase 6 — production autonomy.** Only after replay, provenance,
      rollback, authority and verification have demonstrated reliability.

Acceptance criteria (§26) still open after Phase 1: replay fidelity
(Phase 3). Renderer independence is enforced by a test: `navi-*` crates
never depend on `realm-*`.
