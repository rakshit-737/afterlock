# Semantic profiles

A semantic profile pins the Kubernetes behavior the engine assumes. The copy
here is for review. The runtime copy is packaged at
`packages/afterlock/profiles/`, and CI checks that the two are identical
(`tests/unit/test_profiles.py`).

| Profile | Kubernetes | Conformance status |
|---|---|---|
| `k8s-1.31-core-v1` | 1.31 | **unverified**: the live kind spike (`labs/supervisor/lab.py spike`) has not been executed yet |

A profile's conformance status changes only when a lab receipt exists for every rule it claims.
