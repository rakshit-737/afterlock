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
- Live-lab spike scripts and a CI workflow. **Not executed yet.**
