# Engineering status

_Last updated: 2026-09-26 (first live-lab receipt, version 0.1.0)._

## Milestone map (phases from docs/research/original-design.md)

| Phase | State | Notes |
|---|---|---|
| 0: Research and architecture | done | AGENTS.md, architecture, semantics, threat model, claims, ADRs 0001–0004 |
| 1: Core engine | done | Typed model, production engine, independent reference checker |
| 2: Data/telemetry | partial | Replay bundles, validation, dedup, gaps, redaction. **Missing:** Go collector, PostgreSQL, migrations |
| 3: Security intelligence | done (MVP scope) | Provenance hyperedges, two epistemic views, interleaving, planner |
| 4: Backend | partial | FastAPI with bearer auth, roles, per-cluster scoping. **Missing:** persistence, worker/jobs, SSE, cancellation, OIDC |
| 5: Frontend | not started | |
| 6: Demo laboratory | partial | Semantic spike executed once via `live-lab` (6/6 steps agree, receipt in `labs/receipts/`). The canary downstream service is not yet in the lab |
| 7: Detection/evaluation | partial | 16 hand-authored cases. **Missing:** lab-derived labels, held-out templates |
| 8: Advanced capabilities | not started | |
| 9: Hardening | not started | No adversarial review yet |
| 10: Benchmarks | partial | Baselines/ablations on the hand-authored corpus only (circular labels) |
| 11: Documentation | partial | README, CLI/API/semantics docs. Not yet reproduced in a fresh environment by a third party |
| 12: Final audit | not started | |

## Known failures and open risks

1. **Thin live validation.** One `live-lab` run (Kubernetes v1.31.4) agreed with the model on
   6/6 spike steps, including S-TOK-4 (bound token rejected 0.01 s after Pod deletion). This is
   one version, one run, one idle cluster; other rules and other versions remain model-level.
2. The engine's propagation assumptions (RBAC and deletion effective before the next step)
   are idealized. The lab records real delays, but the model does not consume them yet.
3. Hand-authored expectations and the engine share authors. Only the differential,
   witness-replay, and mutation tests are independent of engine output.
4. GitHub Actions are pinned by tag, and container images and the kind node image are not
   pinned by digest. `uv.lock` pins the Python dependency set, but CI still installs with pip
   rather than the lockfile. There is no SBOM.
5. The API keeps state in memory only.
6. The Dockerfile and compose file have not been built in any environment.

## Next safe task

In order: (a) add the canary downstream service to the lab (S-SEC-2..4);
(b) PostgreSQL persistence and a leased worker (design prompt 08); (c) the investigation
frontend (prompt 12).
