# Threat model

## Assets, actors, boundaries

| Category | Scope |
|---|---|
| Protected assets | A declared Secret, and a synthetic downstream service that accepts the credential stored in it |
| Legitimate activity | A release workload that must keep reading the current credential and using the service |
| Initial attacker access | Seeded compromise of a namespace-scoped CI service account. It is assumed, not exploited |
| Attacker capabilities | Supported API requests with currently usable credentials; creating permitted workloads; keeping earlier-acquired credentials and information |
| Defender capabilities | The defender actions listed in `docs/semantics/supported.md` |
| Trusted computing base | Kubernetes control plane, the admission behavior in the profile, the analysis host, the lab host |
| Evidence boundary | Collectors report observations. They cannot establish that something did not happen |
| Execution boundary | Only `labs/supervisor/lab.py` mutates anything, and only in the recorded lab |

## Assumptions and what happens if they fail

| Assumption | If it fails |
|---|---|
| Control-plane behavior matches the profile | Results need revalidation. The profile is marked unverified until lab receipts exist |
| No node, host, or control-plane compromise | The attacker may hold capabilities outside the model |
| Protected targets are declared | Undeclared assets are not analyzed |
| Unsupported admission and authentication mechanisms are disclosed | Relevant conclusions become `unknown` |
| Evidence freshness is declared (`required_sources`, heartbeats) | A stale source becomes a coverage gap |
| Downstream rotation is acknowledged by the relying service | Updating the Secret alone does not revoke the old credential |

## Platform threats

| Threat | Mitigation in this version | Status |
|---|---|---|
| Credential leakage via evidence | Forbidden-key and credential-pattern rejection; no bodies persisted; canary tests | implemented, tested |
| Malicious telemetry | Size, depth, length, and count limits; strict schema; unknown event types ignored with diagnostics | implemented, tested |
| Bundle tampering and path tricks | SHA-256 manifest; fixed filenames; symlinks rejected | implemented, tested |
| Insecure deserialization | JSON only | implemented |
| Command injection | Defender actions are a closed vocabulary with unknown fields rejected; the lab uses argv lists, never shell strings | implemented |
| Authorization bypass (API) | Server-side role checks per cluster; cross-cluster reads return 404 | implemented, tested |
| Expensive requests | Derivation cap, planner caps, body-size limit | partial (no per-user concurrency limits) |
| Executor abuse | Lab identity pinned to endpoint, CA digest, namespace UID, and instance id; local endpoint only | written, **not executed** |
| Stored XSS | No frontend yet. The API returns JSON and text/plain | n/a |
| Dependency compromise | Zero runtime dependencies in core; pinned kind/kubectl checksums; SHA-pinned actions; digest-pinned images; CI installs from `uv.lock`; CycloneDX SBOM in CI (docs/security/supply-chain.md) | partial (no provenance/signing; API image build not lockfile-based) |

## Out of scope for V1

Exploit discovery, arbitrary network paths, external identity providers, application-session
revocation, cluster-admin or host-root attackers, and proving that copied data was destroyed.
