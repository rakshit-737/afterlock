# Scenario families (hand-authored corpus)

The expectations in `datasets/fixtures/expected.json` were written from these descriptions.

| Case | Family | Expected |
|---|---|---|
| residual-token | Residual delegated credential | residual: the token and the copied credential survive binding removal |
| targeted-containment | Legitimate-operation preservation | contained; release workload preserved |
| defender-race | Defender action race | residual: the Pod is recreated between steps |
| copied-downstream | Copied downstream credential | Kubernetes objective met; downstream objective violated |
| alternative-binding | Alternative role binding | residual via a ClusterRoleBinding |
| controller-replacement | Controller replacement | residual: the Deployment recreates the Pod |
| controller-contained | Controller replacement (fixed) | contained |
| admission-denied | Admission denial (negative control) | contained |
| admission-unsupported | Unsupported admission | unknown |
| no-admission-control | Admission denial (positive counterpart) | residual |
| token-expiry-active | Token expiration | residual |
| token-expiry-wait | Token expiration | contained after waiting past expiry |
| audience-mismatch | Audience mismatch | contained |
| same-name-recreation | Same-name object recreation | contained: the new UID does not revive the bound token |
| incomplete-telemetry | Incomplete telemetry | unknown |
| possible-read | Partial observation | downstream possibly violated (conservative view only) |

The template-level held-out split, lab-derived labels, and generated scenario families
are planned (`docs/engineering/status.md`).
