# Changelog

## 0.1.0 (unreleased): first vertical slice

- Typed temporal state model that separates permissions, credential possession,
  credential validity, and acquired knowledge (`afterlock.analysis-input/1`).
- Production capability engine with provenance hyperedges, evidence-supported and
  conservative-possible views, and attacker actions interleaved between defender steps.
- Independent reference checker: explicit-state BFS explorer plus witness replay.
- Replay bundles (`afterlock.replay/1`) with checksums, deduplication, conflict and
  gap handling, and redaction rejection.
- Containment planner (bounded uniform-cost search) with legitimate-operation
  constraints and a naive-containment baseline.
- CLI (`import`, `analyze`, `explain`, `verify`, `plan`, `export`) and an in-memory FastAPI service.
- 16 hand-authored semantic cases, differential and metamorphic property tests, and a
  mutation check.
- Live lab: semantic spike, canary relying service (S-SEC-2..4), Calico-enforced network
  isolation, `lab reset`, `spike --repeat N`. 3 runs x 15 steps agree with the model.
- PostgreSQL persistence (optional extra `postgres`) with plain-SQL migrations, a leased job
  worker, and async job endpoints. `/v1/health` reports the backend; analysis IDs are now
  random (`an-<16 hex>`).
- Go metadata collector (`services/collector`) producing `afterlock.replay/1` bundles, with
  read-only RBAC, audit policy, distroless image, and CI job.
- Investigation frontend (`services/web`, React/Vite/TypeScript) with an unprivileged nginx
  image.
- Supply chain: actions pinned by SHA, images by digest, lockfile installs, CycloneDX SBOM,
  Dependabot. Lab-derived benchmark labels.
