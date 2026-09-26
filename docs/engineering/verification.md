# Verification record

Original local environment (historical; current evidence is the CI and live-lab runs below): Linux x86_64 cloud container, Python 3.11.15, Go 1.24.7, Node 22.22.2.
**No Docker daemon, kind, or kubectl** (`scripts/doctor --profile live-lab` → not available).
Date: 2026-09-25, commit following `e9a07bc`.

## Executed (2026-09-25, historical counts)

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

### Canary relying service (run [36223689954](https://github.com/rakshit-737/afterlock/actions/runs/36223689954))

Receipt: `labs/receipts/spike-20260926T062752Z.json`, `lab_confirmed`, 11/11 steps. It repeats the six
steps above (same statuses) and adds:

| Step | Predicted | Observed HTTP |
|---|---|---|
| copied-credential-accepted-by-canary (S-SEC-2) | violated | 200 |
| copied-credential-survives-kubernetes-containment (S-SEC-3) | violated | 200 |
| rotation-acknowledged-by-canary (S-SEC-4) | acknowledged | 200 (54.68 s) |
| copied-credential-rejected-after-rotation (S-SEC-3) | satisfied_within_scope | 401 |
| legitimate-workload-uses-rotated-credential | preserved | 200 |

The receipt contains no credential values (checked: no `synthetic-` string). The rotation delay is
the kubelet's mounted-Secret refresh; the model treats rotation as instantaneous.

### Hardened lab, 3 repeats (run [36227357340](https://github.com/rakshit-737/afterlock/actions/runs/36227357340))

Calico v3.29.1 (manifest checked against a pinned SHA-256), kubelet `syncFrequency: 10s`,
kindest/node pinned by digest. `spike --repeat 3`: every run `lab_confirmed`, 15/15 steps,
observations identical across runs (`labs/receipts/spike-summary-20260926T073847Z.json`).
New isolation steps: outsider -> canary and attacker -> outsider get no answer (status 0,
expected `no_answer`); the reachability controls answer (401, 404). Rotation acknowledged in
2.43 / 11.33 / 13.54 s (min / median / max). No credential values in any receipt.

## CI (run [36228425312](https://github.com/rakshit-737/afterlock/actions/runs/36228425312))

All jobs pass on ubuntu-24.04:

| Job | What it runs |
|---|---|
| portable | `uv sync --frozen`, doctor, ruff, mypy, pytest, replay determinism, benchmarks |
| postgres | migrations on postgres:16, then migration/storage/worker/job-API tests; any "BLOCKED" skip fails the job |
| web | `npm ci`, policy lint, typecheck, vitest, vite build |
| collector | `go mod verify`, gofmt, `go vet`, `go test -race`, static build |
| sbom | CycloneDX SBOMs from the lockfile and the environment |

Local (Windows 11): `services/web` 31 tests pass; collector `go test -race -count=3` passes with
go1.24.13; `tests/unit/test_lab_receipts.py` passes. Windows checkouts need LF line endings for
replay checksums (`.gitattributes` enforces this).

## Second round (2026-09-26)

CI run [36235167730](https://github.com/rakshit-737/afterlock/actions/runs/36235167730): all six
jobs pass. New since the first round:

| Job | New coverage |
|---|---|
| containers | builds api/worker, web, collector images; `docker compose up --wait`; `scripts/compose-smoke`: postgres-backed health, case -> analysis job -> `residual_path`, web CSP and `/v1` proxy, non-root / read-only rootfs / cap_drop ALL on every service |
| web | Playwright end-to-end against the real API (6 tests) incl. axe zero serious/critical in light and dark |
| postgres | migration 0003 and per-cluster case ids, SSE on PostgreSQL |
| portable | OIDC validator (local keys, fake JWKS), held-out determinism and 44/44 engine-reference agreement, S-SEC-5 property tests |

A flaky OIDC test (time claims computed at collection time) was fixed before this run.

### Collector against the live lab (run [36234401716](https://github.com/rakshit-737/afterlock/actions/runs/36234401716))

`lab_contradicted`. Passing: bundle written, bundle validates (1220 events, 0 rejected),
restart gaps recorded (2 injected), no credential material in any produced file. Failing:
Pod-create not correlated to the live UID; conclusion `unknown` vs `residual_path`; 48
`list-failed` gaps. An earlier run found a real engine defect: `project()` raised `KeyError`
when one stolen token appeared in several audit events (fixed, regression test added).

### Collector lab-confirmed (run [36237039829](https://github.com/rakshit-737/afterlock/actions/runs/36237039829))

`labs/receipts/collect-20260926T105833Z.json`: `lab_confirmed`, 6/6 checks. Bundle validates;
attacker Pod create correlated to the live UID and service account; binding deletion present;
collected conclusion `residual_path` equals the hand-authored residual-token case
(`protect-secret` violated); 2 injected restarts recorded as `collector-restart` gaps; leak scan
clean over every produced file. Same run: spike 3 x 15 steps all agree. Fixes that got here:
namespace-scoped Secret listing (48 forbidden lists before), `--audit-since` window (stale Pod
creates from earlier runs), restart detection from spool existence.

## Current evidence (2026-09-26)

- CI run [36244804735](https://github.com/rakshit-737/afterlock/actions/runs/36244804735): all
  six jobs pass. portable: 359 passed, 20 skipped (BLOCKED: PostgreSQL / live lab), mypy 15
  files; postgres: 41 passed; web: 46 vitest + 6 Playwright (axe zero serious/critical);
  collector: vet, race tests, build; containers: build + compose smoke; sbom.
- Live lab run [36244828581](https://github.com/rakshit-737/afterlock/actions/runs/36244828581)
  (after the adversarial engine fixes): spike 3 x 17 steps all agree, including `s-sec-5-*`
  (old credential accepted ~0.1 s after rotation; refused at 5.13 / 16.12 / 18.14 s);
  collector 28/28 checks with both windows (`collect-20260926T132806Z.json`).
- Fresh-clone reproduction (Windows 11, uv 0.11.32, CPython 3.12, commit `b574b8f`):
  `git -c core.autocrlf=false clone`, `uv sync --frozen --extra dev --extra postgres --extra oidc --extra api`,
  ruff pass, mypy pass (15 files), full pytest 358 passed, 20 skipped (BLOCKED), 1 failed
  (`test_symlinked_file_rejected`: Windows symlink privilege, host limitation).

## Release candidate (2026-09-26)

After the R1 (possible-history expiry at use time) and R6 (API image from `uv.lock`) fixes:
CI run [36259016014](https://github.com/rakshit-737/afterlock/actions/runs/36259016014) all six
jobs pass, including the `containers` check that the image's installed packages equal the
`uv.lock` export. Live lab run [36259040198](https://github.com/rakshit-737/afterlock/actions/runs/36259040198):
spike 3 x 17 steps all agree (`spike-summary-20260926T172813Z.json`); collector `lab_confirmed`,
28/28 (`collect-20260926T173423Z.json`). Docs site built with `mkdocs build --strict` and
deployed (run 36258112577).

## Not executed (these are not passes)

| Check | Why | How to run |
|---|---|---|
| kube-apiserver audit webhook backend | lab relays the log file to the receiver instead | configure `--audit-webhook-config-file` in the kind patch |
| Watch-expiry (410) fault | not injected in the lab | planned lab step |
| Held-out templates in the lab | only reference-labelled | planned |
| list/watch Secret read lab step (A-3) | fixed in both checkers, never observed live | planned spike step |
| Other Kubernetes versions / multi-node | single kind v1.31.4 node | version matrix in `live-lab` |
| OIDC against a real IdP | local keys and fake JWKS only | staging IdP |
| Scaling benchmark (1,000 entities) | not written | planned |
| Third-party reproduction | none yet | external reviewer |
