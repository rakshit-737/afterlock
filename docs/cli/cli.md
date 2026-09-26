# CLI reference

State lives in `$AFTERLOCK_HOME` (default `./.afterlock`). The CLI never contacts a cluster.

| Command | Purpose |
|---|---|
| `afterlock version` | Print the version |
| `afterlock capabilities` | Profiles, modes, result dimensions, and execution-profile status |
| `afterlock replay import <bundle-dir>` | Validate and project a replay bundle, then store the canonical input. Exit code 2 means `invalid_input` |
| `afterlock analyze --case <id> [--remediation plan.json] [--mode MODE]` | Analyze and store a result bundle |
| `afterlock analyze --bundle <dir>` | Analyze a bundle directly and print the result JSON |
| `afterlock explain [--latest \| <result.json>]` | Human-readable explanation |
| `afterlock verify [--latest \| <result.json>] [--max-states N]` | Replay witnesses and compare with reference exploration. Writes `*.verification.json`. Exit code 1 means the checker disagrees |
| `afterlock plan --case <id> [--max-length 4] [--max-evaluations 5000]` | Constrained containment search, with the proposed and naive plans for comparison |
| `afterlock export --case <id> --out <dir>` | Input and results with a SHA-256 manifest |
| `afterlock canonical-input --case <id>` | Print canonical analysis-input JSON |

Modes: `full` (default), `snapshot_only`, `history_without_lifecycle`, `final_state_only`.
The last three are baselines, used for evaluation only.

A remediation file is a JSON list of defender actions:

```json
[
  {"kind": "remove_binding", "namespace": "demo", "name": "ci-pod-creator"},
  {"kind": "delete_pods_except", "namespace": "demo", "service_account": "release-reader", "keep_uids": ["pod-release-0001"]},
  {"kind": "rotate_downstream_credential", "service": "canary-service"}
]
```
