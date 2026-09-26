# Supported semantics: profile `k8s-1.31-core-v1`

**Conformance status: partial.** Each rule below is implemented twice: in
`packages/afterlock/semantics.py` + `engine.py`, and independently in
`packages/afterlock_reference`. The "Lab step" column names the step in
`labs/supervisor/lab.py spike` that confirms or contradicts the rule. Every named step agrees
with the model in the committed receipts (latest: 3 runs x 17 steps,
`labs/receipts/spike-summary-20260926T132141Z.json`), on Kubernetes v1.31.4 in one idle kind
cluster only. Rules marked "planned" or "—" are model-level only.

## Identity and authentication

| ID | Rule | Lab step |
|---|---|---|
| S-ID-1 | A service-account username is `system:serviceaccount:<ns>:<name>`. | — |
| S-TOK-1 | A projected SA token is usable only if unexpired at the time of use (`t < expires_at`). In the defender phases `t` is the interval's time. In the conservative view's possible-history phase, expiry is evaluated at the time each hypothetical use would occur, anywhere in the window `[history_start, analysis_time]` (`history_start` is an optional input field; absent means unbounded below). A seeded token that expired by `analysis_time` is therefore usable in history iff `expires_at > history_start` (always, when `history_start` is absent), and what it yields there (Secret knowledge, control of Pods that still exist) carries forward. The phase runs whenever the view has a historical Pod or such an expired seeded token. The evidence-supported view never assumes history. | planned (expiry case) |
| S-TOK-2 | …only if its audience is one of the profile's API-server audiences. | planned |
| S-TOK-3 | …only if the service account exists **with the same UID**. | planned |
| S-TOK-4 | …only if the bound Pod exists **with the same UID** and runs as that SA. | `bound-token-rejected-after-pod-deletion` |
| S-TOK-5 | A controlled, existing Pod yields a fresh token (TTL `projected_token_ttl_seconds`) for each audience it projects. | `attacker-reads-secret` |
| S-TOK-6 | A token observed in audit metadata has **no modeled expiry** unless one was observed. This is conservative, because clusters can extend token lifetimes. | — |
| S-TOK-X | Legacy Secret-based tokens and external validators are **unsupported**, so any possession of them makes the result `unknown`. | — |

## Authorization (RBAC)

| ID | Rule | Lab step |
|---|---|---|
| S-RBAC-1 | RBAC is additive; a request is authorized if any binding grants it. | — |
| S-RBAC-2 | A RoleBinding grants only in its namespace, including when it references a ClusterRole. A ClusterRoleBinding grants in every namespace. | — |
| S-RBAC-3 | Subjects: `ServiceAccount` (by namespace and name), `User`, `Group` (`system:authenticated`, `system:serviceaccounts`, `system:serviceaccounts:<ns>`). | — |
| S-RBAC-4 | A rule with `resourceNames` never authorizes a request without a name (create, list). | — |
| S-RBAC-5 | A binding whose role is missing grants nothing. | — |
| S-RBAC-6 | Binding removal takes effect before the next defender step. | `ci-creation-blocked-after-binding-removal` (timed) |
| S-RBAC-X | Webhook/ABAC authorizers, aggregated ClusterRoles, `escalate`/`bind`/`impersonate` verbs, and non-resource URLs are **not modeled**. | — |

## Workloads

| ID | Rule | Lab step |
|---|---|---|
| S-WL-1 | `create pods` in a namespace lets the creator run a Pod as any SA in that namespace, subject to admission. | `ci-creates-release-reader-pod` |
| S-WL-2 | `create deployments` likewise creates a controller. The controller keeps one Pod alive: after deletion it creates a replacement with UID `<controller>-p<k>` (the next `k` whose UID no existing Pod has) before the next step. | planned |
| S-WL-3 | Deleting a controller cascades to its Pods. | planned |
| S-WL-4 | `create pods/exec` on a named Pod grants control of that Pod. | planned |
| S-WL-5 | Pod deletion is complete before the next defender step. | `bound-token-rejected-after-pod-deletion` records the actual delay |
| S-WL-X | Jobs, StatefulSets, DaemonSets, ephemeral containers, node access, and `pods/attach` are **not modeled**. | — |

## Admission

| ID | Rule | Lab step |
|---|---|---|
| S-ADM-1 | `service-account-restriction`: for a listed creator (or `*`), Pods and pod templates may use only the listed SAs. | `negative-control-admission-denies` (CEL ValidatingAdmissionPolicy) |
| S-ADM-X | Any other admission policy in a namespace makes workload-creation feasibility there **unknown**. | — |

## Secrets and downstream credentials

| ID | Rule | Lab step |
|---|---|---|
| S-SEC-1 | An authorized `get`, `list` or `watch` on a Secret yields knowledge of its current version (list and watch responses carry Secret data). `resourceNames` are matched against the Secret's name for all three, because a list/watch can be narrowed with a `metadata.name` field selector. Knowledge is permanent. An observed successful list/watch by the attacker is projected as knowledge of every inventory Secret in its scope, at the inventory version. | `attacker-reads-secret` (get); list/watch planned |
| S-SEC-2 | Knowing a Secret version that a downstream service sources yields that service's credential for that version. | `copied-credential-accepted-by-canary` |
| S-SEC-3 | A downstream credential authenticates only if the service currently accepts that version. | `copied-credential-survives-kubernetes-containment`, `copied-credential-rejected-after-rotation` |
| S-SEC-4 | `rotate_downstream_credential` increments the Secret version and makes the service accept only the new version, as one atomic, acknowledged defender step. | `rotation-acknowledged-by-canary` (outcome agrees; in the lab the change took 54.7 s with the default kubelet sync and 2.4-16 s with `syncFrequency: 10s`, so the step is not atomic in time; see S-SEC-5) |
| S-SEC-5 | Optional per-service `rotation_propagation_seconds` (inventory `services[]`, integer >= 0, default 0). When it is `d > 0`, a rotation at time `t` still increments the Secret version and the accepted version immediately, but the service **also keeps accepting the previously accepted version while `time < t + d`**. Only a later `wait` advances time, so a plan must wait at least `d` after the rotation for the old copy to stop working. With `d = 0` or the field absent, behaviour is exactly S-SEC-4. Source the value from measurement (lab: 54.7 s default kubelet sync, 2.4-13.5 s with `syncFrequency: 10s`). Legitimate operations are evaluated against the new version only, so the model over-approximates the attacker, not legitimate availability, during the window. | lab-confirmed (3/3 runs, latest summary): `s-sec-5-old-credential-accepted-right-after-rotation` (model with measured `d = ceil(ack)`, no wait: violated) and `s-sec-5-old-credential-rejected-after-propagation-wait` (probe at >= `d` + 2 s; model after `wait d`: satisfied_within_scope). `d` is measured in the same run, so a pass shows consistency with the observed timing, not an independent prediction of `d` |

## Defender actions

`remove_binding`, `delete_pod` (by UID), `delete_controller` (by UID),
`delete_pods_except` / `delete_controllers_except` (by namespace and SA, with an
allowlist of UIDs to keep), `delete_service_account`, `rotate_downstream_credential`, and
`wait`. Actions that reference absent objects are no-ops and produce a note. UIDs with the
prefixes `model-pod:` and `model-deploy:` are reserved for objects the engine models but
never observed, and cannot be targeted individually. Input that gives an inventory Pod or
controller, or a `controls_pod` / `controls_controller` / `historical_pod` fact, such a UID
is rejected as invalid.

## Attacker model

The attacker holds the seeded compromised credentials plus whatever the evidence shows
it acquired. It performs every supported transition between defender steps. It does not
escape containers, compromise nodes, or exploit the control plane.
