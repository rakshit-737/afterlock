# Prior art and positioning

This is a targeted comparison based on public repository descriptions. It is not an
exhaustive literature review.

| Project | Relevant capability | Relationship |
|---|---|---|
| [KubeHound](https://github.com/DataDog/KubeHound) | Kubernetes attack graphs and path calculation | Closest overlap. AFTERLOCK does not claim Kubernetes attack-path discovery |
| [BloodHound](https://github.com/SpecterOps/BloodHound) | Identity and privilege graphs (OpenGraph) | Establishes the value of identity graphs |
| [PMapper](https://github.com/nccgroup/PMapper) | AWS IAM privilege escalation, including indirect access | Delegated-access simulation is established |
| [Cartography](https://github.com/cartography-cncf/cartography) | Multi-platform asset graphs | A possible future inventory source |
| [Stratus Red Team](https://github.com/DataDog/stratus-red-team) | Reproducible cloud adversary emulation | Precedent for the lab |
| [Kyverno](https://github.com/kyverno/kyverno) | Admission policy enforcement | A control to model. Policy alone does not revoke acquired access |
| [MulVAL](https://github.com/risksense/mulval) | Logic-based attack-graph generation | Prior art for declarative rules. AFTERLOCK's rule engine is not novel by itself |

Primary semantic references: Kubernetes documentation on
[service account administration](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
and [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).

**Intended contribution:** the bounded combination of history-aware residual-capability
modeling, remediation-sequence search, independently checkable explanations, and
reproducible execution tests. Whether that is publishable depends on a broader review and
on lab results.
