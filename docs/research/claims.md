# Research claims, evidence, and disconfirming tests

Every claim is paired with the test that could falsify it and the evidence available **today**.

| # | Claim | Falsification test | Current evidence |
|---|---|---|---|
| C1 | Removing an acquisition permission does not remove capabilities acquired through it | Lab: after `ci-pod-creator` is deleted, the stolen token still reads the Secret | **Lab-confirmed on one version** (kind, Kubernetes v1.31.4): `residual-token-still-reads-secret` returned 200 after the binding removal in every spike run (latest 3/3, `labs/receipts/spike-summary-20260926T132141Z.json`), and the collector-evidence path reproduces the `residual_path` conclusion (`collect-20260926T132806Z.json`) |
| C2 | Deleting the bound Pod makes its token unusable against the API | Lab: time until HTTP 401 after the deletion completes | **Lab-confirmed on one version**: `bound-token-rejected-after-pod-deletion` got 401 about 0.01 s after deletion completed (3/3 runs, latest summary). One idle cluster; not a latency bound |
| C3 | History-aware analysis makes fewer false containment claims than snapshot-only analysis | Compare on independently labelled lab executions | Hand-authored corpus: 0/6 vs 5/11 (circular labels). Lab-derived labels (observed HTTP statuses only): full 6/6 vs snapshot-only 3/6 agreement, but only 6 objectives in 4 cases from one lab scenario (`benchmarks/reports`). **Not evidence of real-world accuracy** |
| C4 | Interleaving analysis catches ordering failures that final-state analysis misses | `defender-race` in the lab | Hand-authored corpus and held-out templates only; `defender-race` has not been executed in the lab |
| C5 | The engine agrees with an independently written explorer on small models | Hypothesis differential tests | Passing: 16 cases plus generated suites (see verification.md for counts), and 44/44 held-out template cases (`datasets/heldout/`, reference-derived labels, `benchmarks/reports`) |
| C6 | Witnesses are independently checkable | `verify_witnesses` across all cases and generated inputs | Passing. One engine bug was found and fixed this way |
| C7 | Constrained planning is less disruptive than naive containment | Legitimate-operation checks in the lab | Partly lab-backed: after the targeted plan's steps, `legitimate-workload-uses-rotated-credential` got 200 and the copied credential 401 (3/3 runs). That the naive plan breaks `release-app` is **model-only**; the naive plan has not been executed in the lab |
| C8 | Missing evidence never yields containment | Gap, stale, rejected, conflicting, and unsupported cases | Unit tests pass; a mutation test confirms detection |

## Hypotheses (not results)

- H1: History and lifecycle modeling reduce false containment claims compared with a
  snapshot-only analysis, on held-out scenario templates executed in a real cluster.
- H2: Constrained sequence search yields valid plans with less legitimate-operation
  disruption than indiscriminate revocation.
