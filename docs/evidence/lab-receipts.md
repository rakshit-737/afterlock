# Lab receipts

Receipts are JSON records written by the lab supervisor. Each one compares a real Kubernetes
API outcome with the engine's prediction. They are committed in
[`labs/receipts/`](https://github.com/rakshit-737/afterlock/tree/main/labs/receipts) and checked
by `tests/unit/test_lab_receipts.py`.

Latest evidence (from the [final audit](../engineering/final-audit.md), live-lab run
[36244828581](https://github.com/rakshit-737/afterlock/actions/runs/36244828581)):

| Receipt | What it shows |
|---|---|
| `spike-summary-20260926T132141Z.json` | 3 runs x 17 steps, `all_runs_agree: true`, `missing_steps: {}` |
| `collect-20260926T132806Z.json` | Collector-evidence path, `lab_confirmed`, 28/28 checks, both windows |

Scope: Kubernetes v1.31.4, one idle single-node kind cluster. A receipt confirms only the
steps it records; everything else stays model-level. See the
[verification record](../engineering/verification.md) for the full history and the
[live lab tutorial](../tutorials/live-lab.md) to reproduce them.
