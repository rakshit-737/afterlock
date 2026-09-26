# Research claims, evidence, and disconfirming tests

Every claim is paired with the test that could falsify it and the evidence available **today**.

| # | Claim | Falsification test | Current evidence |
|---|---|---|---|
| C1 | Removing an acquisition permission does not remove capabilities acquired through it | Lab: after `ci-pod-creator` is deleted, the stolen token still reads the Secret | Model and hand-authored cases only. **Lab step written, not run** |
| C2 | Deleting the bound Pod makes its token unusable against the API | Lab: time until HTTP 401 after the deletion completes | Not run. The model assumes it happens before the next step |
| C3 | History-aware analysis makes fewer false containment claims than snapshot-only analysis | Compare on independently labelled lab executions | Hand-authored corpus only: 0/6 vs 5/11 (`benchmarks/reports`). Circular labels; **not evidence of real-world accuracy** |
| C4 | Interleaving analysis catches ordering failures that final-state analysis misses | `defender-race` in the lab | Hand-authored corpus only |
| C5 | The engine agrees with an independently written explorer on small models | Hypothesis differential tests | Passing: 16 cases plus generated suites (see verification.md for counts) |
| C6 | Witnesses are independently checkable | `verify_witnesses` across all cases and generated inputs | Passing. One engine bug was found and fixed this way |
| C7 | Constrained planning is less disruptive than naive containment | Legitimate-operation checks in the lab | Model only: the naive plan breaks `release-app`, the found plan preserves it |
| C8 | Missing evidence never yields containment | Gap, stale, rejected, conflicting, and unsupported cases | Unit tests pass; a mutation test confirms detection |

## Hypotheses (not results)

- H1: History and lifecycle modeling reduce false containment claims compared with a
  snapshot-only analysis, on held-out scenario templates executed in a real cluster.
- H2: Constrained sequence search yields valid plans with less legitimate-operation
  disruption than indiscriminate revocation.
