# Engineering status

_Last updated: 2026-09-25 (first vertical slice, version 0.1.0)._

## Milestone map (phases from docs/research/original-design.md)

| Phase | State | Notes |
|---|---|---|
| 0: Research and architecture | done | AGENTS.md, architecture, semantics, threat model, claims, ADRs 0001–0004 |
| 1: Core engine | done | Typed model, production engine, independent reference checker |
| 2: Data/telemetry | partial | Replay bundles, validation, dedup, gaps, redaction. **Missing:** Go collector, PostgreSQL, migrations |
| 3: Security intelligence | done (MVP scope) | Provenance hyperedges, two epistemic views, interleaving, planner |
| 4: Backend | partial | FastAPI with bearer auth, roles, per-cluster scoping. **Missing:** persistence, worker/jobs, SSE, cancellation, OIDC |
| 5: Frontend | not started | |
| 6: Demo laboratory | scripts written, **not executed** | No Docker daemon in the development environment. The canary downstream service is not yet in the lab |
| 7: Detection/evaluation | partial | 16 hand-authored cases. **Missing:** lab-derived labels, held-out templates |
| 8: Advanced capabilities | not started | |
| 9: Hardening | not started | No adversarial review yet |
| 10: Benchmarks | partial | Baselines/ablations on the hand-authored corpus only (circular labels) |
| 11: Documentation | partial | README, CLI/API/semantics docs. Not yet reproduced in a fresh environment by a third party |
| 12: Final audit | not started | |

## Known failures and open risks

1. **No live validation.** Every conclusion is model-level. The central assumption (S-TOK-4,
   bound-token rejection after Pod deletion, and its timing) is untested against a real API
   server. Next step: run `live-lab` on a disposable host.
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

Run the `live-lab` workflow (manual dispatch) or `scripts/lab create && scripts/lab spike` on
a disposable Docker-capable Linux host. Commit the receipt under `labs/receipts/`. If every
step agrees, update the profile's `conformance_status` for the covered rules. If any step
contradicts the model, open a "Semantic contradiction" issue and revise the model before
doing anything else.

After that, in order: (a) add the canary downstream service to the lab (S-SEC-2..4);
(b) PostgreSQL persistence and a leased worker (design prompt 08); (c) the investigation
frontend (prompt 12).
