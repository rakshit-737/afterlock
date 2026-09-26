# Verification record

Environment: Linux x86_64 cloud container, Python 3.11.15, Go 1.24.7, Node 22.22.2.
**No Docker daemon, kind, or kubectl** (`scripts/doctor --profile live-lab` → not available).
Date: 2026-09-25, commit following `e9a07bc`.

## Executed

| Check | Command | Result |
|---|---|---|
| Lint | `ruff check packages services tests datasets benchmarks` | pass |
| Types (strict) | `mypy` | pass (9 files) |
| All tests | `./scripts/verify` (150 Hypothesis examples per differential test) | 122 passed, 1 skipped (live lab: BLOCKED) |
| Replay reproducibility | generator rerun + `git diff --exit-code datasets/replay` | pass |
| Engine vs reference disagreement search, 1 live attacker workload | 4,000 Hypothesis examples | no disagreement found |
| Same, 2 live attacker workloads per SA | 1,000 examples | no disagreement found (an earlier 600-example run found the possible-history `pods/exec` gap, now fixed) |
| Witness validity search | 3,000 examples | no invalid witness (after the model-controller premise fix) |
| Mutation checks | `tests/differential/test_mutation.py` | 4/4 mutants killed |
| Benchmark | `python benchmarks/run.py --repeat 3` | see `benchmarks/reports/semantic-corpus.md` |
| CLI demo | `make demo` | pass |

## Live lab (2026-09-26)

`live-lab` workflow, run [36221758899](https://github.com/rakshit-737/afterlock/actions/runs/36221758899),
GitHub-hosted ubuntu-24.04, kind with Kubernetes v1.31.4. `tests/conformance`: 1 passed.
Receipt: `labs/receipts/spike-20260926T054738Z.json`. All 6 steps agree with the model:

| Step | Predicted | Observed HTTP |
|---|---|---|
| ci-creates-release-reader-pod | may_create | 201 |
| attacker-reads-secret | violated | 200 |
| ci-creation-blocked-after-binding-removal | blocked | 403 (0.01 s) |
| residual-token-still-reads-secret | violated | 200 |
| bound-token-rejected-after-pod-deletion (S-TOK-4) | rejected | 401 (0.01 s after deletion) |
| negative-control-admission-denies | satisfied_within_scope | 422 |

Single run on one version; timings are from one idle cluster and are not a bound.

## Not executed (these are not passes)

| Check | Why | How to run |
|---|---|---|
| Container build / compose | no Docker daemon | `docker compose up --build` |
| GitHub Actions `ci` workflow | not inspected | push |
