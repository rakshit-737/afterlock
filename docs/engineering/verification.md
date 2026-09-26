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

## Not executed (these are not passes)

| Check | Why | How to run |
|---|---|---|
| Live Kubernetes conformance / semantic spike | no Docker daemon | `live-lab` workflow or `scripts/lab create && scripts/lab spike` |
| Container build / compose | no Docker daemon | `docker compose up --build` |
| GitHub Actions workflows | not triggered from this environment | push / manual dispatch |
