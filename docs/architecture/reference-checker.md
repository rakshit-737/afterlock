# Reference checker independence

`packages/afterlock_reference` exists to disagree with the engine when the engine is
wrong. It is only useful if it does not share the engine's mistakes.

## Rules

- It must not import `afterlock` (enforced in `tests/security`).
- It parses raw `afterlock.analysis-input/1` JSON itself.
- It encodes state as frozen tuples and explores **single attacker actions and defender
  steps as separate BFS transitions**. The engine instead computes per-interval fixpoints
  over dataclasses.
- It does **not** use the engine's one-representative-workload canonicalization. It
  allows up to `max_live_attacker_workloads_per_sa` live attacker workloads (default 2)
  and reports `complete: false` when `max_states` is reached.

## What is deliberately shared

- The written specification in `docs/semantics/supported.md`.
- Naming conventions for engine-modeled objects (`model-pod:<ns>:<sa>:i<k>`,
  `model-deploy:…`, controller replacements `<uid>-p<k>`). The witness verifier needs
  these to reconstruct objects a witness claims were created.

## Two entry points

| Function | Checks |
|---|---|
| `explore(raw)` | Set of objectives reachable at the final phase, per view, over all interleavings |
| `verify_witnesses(raw, bundle)` | Every step's premises were established earlier; every condition (usability, authorization with the claimed bindings, admission, existence, versions) holds in an independently rebuilt environment at that interval; the goal is derived at the final interval |

## Known limits

Exploration is exponential and practical only for small inputs. Agreement between the
engine and the checker is **model-level verification**. It is not lab validation, and the
bundle keeps the two in separate dimensions.

## Findings so far

- The first differential run found a checker bug: secret reads iterated the wrong state
  field. It was fixed before any commit.
- Hypothesis found an **engine** bug. A witness used `pods/exec` into a Pod owned by an
  attacker-created controller, but omitted that controller's creation, so the witness
  could not be replayed. The engine now adds the creation of any model-created object to
  the derivation's premises. There is a regression test for this.
- A disagreement search at two live attacker workloads found an **engine** semantic gap.
  In the conservative-possible history phase, the engine suppressed every creation-type
  action, `pods/exec` included, so it missed that a historical foothold could have taken
  control of Pods that still exist. Both implementations now run the full closure in the
  history phase and discard objects created there (they are not in today's inventory).
  The regression input is `tests/differential/regression_history_exec.json`.
