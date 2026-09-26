# Engineering status

_Last updated: 2026-09-26 (persistence, collector, frontend, hardened lab; version 0.1.0)._

## Milestone map (phases from docs/research/original-design.md)

| Phase | State | Notes |
|---|---|---|
| 0: Research and architecture | done | AGENTS.md, architecture, semantics, threat model, claims, ADRs 0001–0004 |
| 1: Core engine | done | Typed model, production engine, independent reference checker |
| 2: Data/telemetry | partial | Replay bundles, validation, dedup, gaps, redaction. Go collector (`services/collector`): read-only list/watch inventory, audit file + webhook ingestion, audit-ID dedup, explicit gap records, bounded spool, `afterlock.replay/1` output; tested with fakes and a golden bundle. **Missing:** a run against a live cluster; evidence/cursor/history tables in PostgreSQL |
| 3: Security intelligence | done (MVP scope) | Provenance hyperedges, two epistemic views, interleaving, planner |
| 4: Backend | partial | FastAPI with bearer auth, roles, per-cluster scoping. PostgreSQL storage (`migrations/`, checksummed runner), leased worker (`services/worker`: SKIP LOCKED claims, heartbeats, bounded retries, cancellation, publication only inside the lease-checking transaction), async `*-jobs` endpoints. PostgreSQL contract tests pass in CI. **Missing:** SSE progress, OIDC, retention job, replay export from the DB, interruptible engine calls |
| 5: Frontend | partial | `services/web` (React + Vite + TS) over the v1 API: case upload, analysis, objectives, witnesses, timeline, coverage, explanation, verification, plans; model-level vs lab-confirmed shown separately. **Missing:** provenance graph, evidence drawer, Playwright end-to-end, accessibility audit, async-job wiring |
| 6: Demo laboratory | done (spike scope) | Canary relying service, Calico-enforced NetworkPolicies with isolation steps, `lab reset`, `spike --repeat N`. 3 repeated runs x 15 steps all agree with the model (receipts in `labs/receipts/`) |
| 7: Detection/evaluation | partial | 16 hand-authored cases plus lab-derived labels (`benchmarks/labels/lab-derived.json`, from observations only). **Missing:** held-out templates |
| 8: Advanced capabilities | not started | |
| 9: Hardening | partial | Actions pinned by SHA, images by digest, CI installs from `uv.lock`, CycloneDX SBOM job, Dependabot. First pattern-based review in `docs/security/review-2026-09-26.md`. **Missing:** full adversarial review, provenance/signing |
| 10: Benchmarks | partial | Baselines/ablations; lab-derived labels reported separately from hand-authored ones |
| 11: Documentation | partial | README, CLI/API/semantics/collector/frontend docs. Not yet reproduced in a fresh environment by a third party |
| 12: Final audit | not started | |

## Known failures and open risks

1. **Live validation covers one version.** Kubernetes v1.31.4 on an idle kind cluster: 15/15
   steps agree across 3 runs (S-TOK-4, S-SEC-1..4, admission, network isolation). Other rules
   and versions remain model-level.
2. **Propagation is idealized in the model.** Canary rotation (S-SEC-4) takes effect after the
   kubelet refreshes the mounted Secret: 54.7 s with the default sync period, 2.4-13.5 s with
   `syncFrequency: 10s`. During that window the copied credential still works. The model treats
   rotation as instantaneous.
3. Hand-authored expectations and the engine share authors. Lab-derived labels exist but cover
   4 cases.
4. Containers (API/worker image, web image, compose stack, collector image) have never been
   built; no Docker on the development host and no CI build job.
5. Open review items: request-size limit is Content-Length-only (chunked bodies unbounded);
   in-memory store unbounded; verification endpoint can be CPU-expensive; `/v1/docs` is
   unauthenticated; `case_id` is globally unique so a 409 can reveal another cluster's case.
6. The collector has not run against a real API server; Secret metadata collection is opt-in
   because RBAC cannot restrict `list secrets` to metadata.
7. Calico, postgres and web base images are pinned by tag, not digest.

## Next safe task

In order: (a) a CI job that builds all container images and brings up `docker compose`;
(b) run the collector against the kind lab (audit webhook plus a watch-expiry fault) and record
receipts; (c) SSE progress and OIDC (prompt 08/09 remainder); (d) Playwright end-to-end tests for
the frontend against the API.
