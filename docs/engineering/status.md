# Engineering status

_Last updated: 2026-09-26 (second parallel round: containers, collector in lab, SSE/OIDC, e2e, held-out set, S-SEC-5; version 0.1.0)._

## Milestone map (phases from docs/research/original-design.md)

| Phase | State | Notes |
|---|---|---|
| 0: Research and architecture | done | AGENTS.md, architecture, semantics, threat model, claims, ADRs 0001–0004 |
| 1: Core engine | done | Typed model, production engine, independent reference checker |
| 2: Data/telemetry | partial | Replay bundles, validation, dedup, gaps, redaction. Go collector with read-only RBAC, audit ingestion, gap records, spool. **Live lab:** the collector runs against kind with audit logging; its bundle validates (1220 events), passes the leak scan, and records injected restarts as gaps. **Open:** the attacker Pod create is not yet correlated to the live Pod UID and 48 list calls fail, so the engine concludes `unknown` (not `residual_path`) from collected evidence. Conservative, but a real defect under investigation |
| 3: Security intelligence | done (MVP scope) | Provenance hyperedges, two epistemic views, interleaving, planner |
| 4: Backend | mostly done | Bearer and optional OIDC auth (RS256/ES256), roles, per-cluster scoping; PostgreSQL storage with migrations 0001–0003 (case ids unique per cluster); leased worker; async jobs; SSE job progress carrying the manifest version; streamed body limit, bounded in-memory store, verification/plan concurrency limits, API docs off by default. **Missing:** retention job, replay export from the DB, audit logging, OIDC against a real identity provider |
| 5: Frontend | mostly done | `services/web`: case upload, analysis via background jobs (polling, cancel), results, provenance graph with evidence drawer, credential-lifecycle view, verification, plans. Playwright end-to-end against the real API passes in CI, including axe with zero serious/critical violations in light and dark. **Missing:** SSE consumption, OpenAPI-generated types |
| 6: Demo laboratory | done (spike scope) | Canary relying service, Calico-enforced NetworkPolicies with isolation steps, `lab reset`, `spike --repeat N`. 3 repeated runs x 15 steps all agree with the model (receipts in `labs/receipts/`) |
| 7: Detection/evaluation | partial | 16 hand-authored cases, lab-derived labels, and 44 held-out cases from 5 seeded templates labelled only by the reference checker (`datasets/heldout/`). **Missing:** held-out templates executed in the lab |
| 8: Advanced capabilities | started | S-SEC-5: optional per-service rotation propagation window, honoured by engine, reference checker and planner. **Missing:** a lab receipt at t+d; other items |
| 9: Hardening | partial | Actions pinned by SHA, all Dockerfile/compose images by digest (Calico by manifest SHA-256 only), lockfile installs, SBOM, Dependabot. Review findings 3–6, 8 and the case-id disclosure fixed. **Missing:** full adversarial review, provenance/signing, uvicorn not in the lockfile |
| 10: Benchmarks | partial | Hand-authored, lab-derived and held-out labels reported separately. Held-out engine-vs-reference agreement 44/44; committed reports hold no timings |
| 11: Documentation | partial | README, CLI/API/semantics/collector/frontend docs. Not yet reproduced in a fresh environment by a third party |
| 12: Final audit | not started | |

## Known failures and open risks

1. **Collected evidence is not yet enough for a conclusion.** From the live collector bundle
   the engine concludes `unknown`, while the hand-authored case concludes `residual_path`:
   Pod-create correlation to the live UID fails and 48 list calls fail. The engine errs on the
   safe side (no false containment claim).
2. **Live validation covers one version.** Kubernetes v1.31.4 on an idle kind cluster: 15/15
   spike steps agree across 3 runs. Other rules and versions remain model-level.
3. **Propagation.** Rotation took 2.4–54.7 s in the lab. The model can now represent it
   (S-SEC-5), but only when inputs supply the delay.
4. Held-out labels come from a second implementation of the same written semantics; they
   cannot catch a flaw in the semantics themselves.
5. OIDC is tested only with local keys and a fake JWKS. All API limits are per process.
6. uvicorn is installed by pinned version, not from the lockfile.

## Next safe task

(a) Fix collector Pod-UID correlation and the failing list calls, then rerun `live-lab` until
`collect` is `lab_confirmed`; (b) a lab receipt for S-SEC-5 (old credential rejected at t+d);
(c) add uvicorn to a locked extra; (d) full adversarial review (phase 9) and final audit.
