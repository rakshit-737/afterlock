# Engineering status

_Last updated: 2026-09-26 (release candidate for v0.1.0: R1 and R6 resolved, docs site
published)._

Maturity: **research-grade, not production-ready.** See `docs/engineering/final-audit.md` for
the acceptance matrix, risk register (R1-R23) and verdict.

## Milestone map (phases from docs/research/original-design.md)

| Phase | State | Notes |
|---|---|---|
| 0: Research and architecture | done | AGENTS.md, architecture, semantics, threat model, claims, ADRs 0001–0004 |
| 1: Core engine | done | Typed model, production engine, independent reference checker |
| 2: Data/telemetry | mostly done | Replay bundles, validation, dedup, gaps, redaction (also inventory/case files, encoded tokens). Go collector: read-only RBAC, namespace-scoped Secret metadata, audit ingestion with evidence window, content-hashed dedup, gap records, spool. **Lab-confirmed** for residual-token and targeted-containment from collected evidence; webhook receiver exercised through the supervisor relay. **Missing:** kube-apiserver's own webhook backend, watch-expiry fault, evidence/cursor tables in PostgreSQL |
| 3: Security intelligence | done (MVP scope) | Provenance hyperedges, two epistemic views, interleaving, planner |
| 4: Backend | mostly done | Static and OIDC auth, per-cluster scoping, PostgreSQL (migrations 0001–0003), leased worker with attempt-fenced leases, async jobs, SSE, limits, docs off by default. **Missing:** retention job, DB replay export, audit logging, OIDC against a real IdP |
| 5: Frontend | mostly done | Jobs, provenance graph, evidence drawer, credential lifecycle; Playwright + axe in CI. **Missing:** SSE consumption, OpenAPI-generated types |
| 6: Demo laboratory | done (spike scope) | Canary, Calico isolation, reset, repeat. 3 x 17 steps agree (latest `spike-summary-20260926T132141Z.json`, run 36244828581) |
| 7: Detection/evaluation | partial | Hand-authored, lab-derived (14 receipts) and 44 held-out cases. **Missing:** held-out templates run in the lab |
| 8: Advanced capabilities | started | S-SEC-5 rotation propagation window, lab steps agree 3/3 (`d` measured in the same run). Other items not started |
| 9: Hardening | mostly done | Adversarial reviews of API side (`review-2026-09-26-adversarial-api.md`, 2 Medium fixed) and engine side (`...-adversarial-engine.md`, 12 fixed incl. 4 High false-containment). SHA/digest pins, lockfile installs everywhere (API image installs from `uv.lock` with `--require-hashes`, checked in CI), SBOM, Dependabot. **Missing:** provenance/signing |
| 10: Benchmarks | partial | Hand-authored, lab-derived and held-out labels reported separately (held-out 44/44); report regenerated in the final audit. No confidence intervals or scaling benchmark |
| 11: Documentation | mostly done | Docs site on GitHub Pages (https://rakshit-737.github.io/afterlock/, `mkdocs build --strict`); docs made consistent by the final audit; portable checks reproduced from a fresh clone. Not yet reproduced by a third party |
| 12: Final audit | done | `docs/engineering/final-audit.md`; release blockers R1 and R6 resolved; tagged v0.1.0 (research release) |

## Known failures and open risks

1. **Possible-history token expiry (R1) — resolved.** Expiry is now evaluated at the time of
   each hypothetical use in both checkers (optional `history_start` bounds the window). No
   dataset label changed; no lab step exercises token expiry yet.
2. **Live validation covers one version and one cluster shape.** Kubernetes v1.31.4, one idle
   single-node kind cluster: 17/17 spike steps agree across 3 runs; collector evidence
   reproduces residual-token and targeted-containment conclusions.
3. **Model-level only:** token expiry/audience/SA-UID rules, controllers and exec, RBAC details,
   list/watch Secret reads (A-3, fixed in both checkers, no lab step), ordering races, all 44
   held-out cases.
4. **Propagation.** Rotation took 2.4–16 s with `syncFrequency: 10s` and 54.7 s with the default.
   S-SEC-5 represents it when inputs supply the delay; in the lab `d` is measured in the same run.
5. Held-out labels come from a second implementation of the same written semantics.
6. Release provenance and signing are not implemented.
7. OIDC tested only with local keys; all API limits are per process; one cluster can flood the
   shared job queue (unconfirmed).

## Next safe task

(a) Lab steps for list/watch Secret reads, token expiry and `defender-race`; (b) Kubernetes
version matrix and a multi-node cluster; (c) run held-out templates in the lab; (d) release
provenance/signing; (e) observability and a scaling benchmark.
