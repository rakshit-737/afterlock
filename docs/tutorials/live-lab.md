# Live lab: semantic spike

**Status:** the 11-step spike has receipts (`labs/receipts/spike-20260926T*.json`,
single runs, kindnet CNI). The network-isolation steps, `reset`, `--repeat`, Calico, the
digest-pinned node image, and the lowered kubelet sync period are **written, not yet
executed**; see `docs/engineering/verification.md` for what has actually run.

## Requirements

- A **disposable** Linux host with a Docker daemon, `kind`, and `kubectl`. Never use a host
  that holds real cluster credentials.
- About 4 CPU and 8 GB RAM for the spike.
- `python scripts/doctor --profile live-lab` must report `available`.

## Run

```bash
scripts/lab create             # kind cluster "afterlock-lab" + Calico; records the lab identity in labs/.state/lab.json
scripts/lab spike              # real API outcomes vs model predictions -> labs/receipts/spike-*.json
scripts/lab reset              # back to the post-create state, same cluster (see below)
scripts/lab spike --repeat 3   # reset+spike 3 times: spike-<ts>-r{1,2,3}.json + spike-summary-<ts>.json
python benchmarks/lab_labels.py  # receipts -> benchmarks/labels/lab-derived.json
scripts/lab destroy            # deletes only the recorded cluster
```

A plain `spike` expects the post-create state; run `reset` before a second plain `spike`.
`--repeat` always resets before each run.

Or run the `live-lab` workflow (manual dispatch) on a disposable GitHub-hosted runner.

## What the spike checks

| Step | Model prediction |
|---|---|
| CI token creates a Pod as `release-reader` | allowed |
| That Pod's token reads `release-credential` | allowed |
| After deleting `ci-pod-creator`, CI creation is denied | denied (time until effective is recorded) |
| The stolen token still reads the Secret | **allowed: residual access** |
| After the Pod is fully deleted, the stolen token is rejected | 401 (time recorded) |
| With the CEL admission policy, CI cannot select `release-reader` | denied |
| Copied Secret value works at the canary, before and after Kubernetes containment | accepted |
| After rotation, the canary accepts the new value (time recorded) and rejects the copy | rejected |
| Legitimate workload reads the rotated value and still uses the canary | preserved |
| Control: canary answers `canary-probe` in `demo` | reachable (401 without credential) |
| A Pod in namespace `outsider` gets **no answer** from the canary | unreachable |
| Control: `outsider` HTTP server answers `canary-probe` | reachable (404) |
| An attacker Pod gets **no answer** from `outsider` (egress default-deny) | unreachable |

### Expectation modes

Each step declares `expect`: `answer_ok` (2xx), `answer_denied` (an explicit HTTP answer
>= 300), or `no_answer` (no HTTP answer at all, status 0). Status 0 never counts as a
refusal; it only agrees with `no_answer`. Because a broken probe also produces status 0,
every `no_answer` step is preceded by a control proving the same destination answers an
allowed client, and the receipt records a fixed `probe_reason` (`timeout`, `refused`,
`dns`, `other`).

## Network isolation

kind's default CNI (kindnet) does not enforce NetworkPolicy, so policies alone would prove
nothing. `labs/kind/cluster.yaml` disables it and `scripts/lab create` installs Calico v3.29.1
from a pinned URL, refusing the manifest unless its SHA-256 matches `CALICO_SHA256` in
`labs/supervisor/lab.py`. (Calico's container images are referenced by tag inside that
manifest, not by digest.) The supervisor then applies:

- `canary`: default-deny ingress; only pods in namespace `demo` may reach the canary on 8080.
- `demo`: attacker pods (`afterlock.dev/actor=attacker`) have default-deny egress except DNS,
  the API server endpoint, and the canary.

The spike **verifies** isolation with the steps above instead of trusting the manifests.

## Reset and repeated runs

`reset` deletes attacker pods, removes the admission policy, re-applies the scenario,
canary, and isolation manifests and the network policies (restoring `ci-pod-creator`),
re-seeds a fresh synthetic credential and waits until the canary accepts it, then re-checks
the recorded lab identity (namespace UIDs must not change). With `--repeat N` each run's
receipt records its reset timing; the summary states whether all runs agree and gives
min/median/max for every `elapsed_seconds*` field.

## Rotation delay

The canary reads its mounted Secret per request, so rotation takes effect when the kubelet
refreshes the volume. The first canary run measured 54.7 s with the default 1 m sync
period. `cluster.yaml` lowers `syncFrequency` to 10 s for the lab; the delay is still
measured and recorded in every receipt, and it is a property of this lab configuration,
not of Kubernetes in general.

## Collector run (`collect`)

**Status: written, not yet executed.** `scripts/lab collect` runs `reset`, then the spike
with the Go collector (`services/collector`) running on the host:

1. `labs/kind/cluster.yaml` enables API server audit logging with
   `services/collector/deploy/audit-policy.yaml` (Metadata level, no bodies). `create`
   stages the policy in `/tmp/afterlock-lab/policy/`; the log is mounted back to
   `/tmp/afterlock-lab/audit/audit.log` (read through `docker exec` on the node if the host
   file is root-only). **Clusters created before this change have no audit log; recreate them.**
2. The supervisor applies `deploy/rbac.yaml` (list/watch only) plus the Secret-metadata
   ClusterRole bound by a RoleBinding in `demo` only, and creates a 30-minute token for the
   `afterlock/afterlock-collector` ServiceAccount. The collector gets a kubeconfig holding
   only that token (0600, private temp dir, deleted afterwards) — never admin credentials.
3. Process A watches inventory from the start. After the attacker Pod is created it is
   killed with SIGKILL and process B restarts on the same spool (fault injection).
4. At the checkpoint after `residual-token-still-reads-secret` (binding removed, attacker
   Pod alive — the state of the `residual-token` replay case), B is stopped and process C
   ingests the audit log, relists inventory and writes the `afterlock.replay/1` bundle with a
   case derived from `datasets/replay/residual-token/case.json` (live UIDs; the downstream
   canary objective is dropped because the collector does not observe services).
5. The spike then continues as usual.

Extra receipt steps (supervisor checks: `observation: "supervisor-check"`, status 200 when
the check holds, 422 when it fails, `expect: answer_ok`):

| Step | Holds when |
|---|---|
| `collector-writes-bundle` | process C exits 0 |
| `collected-bundle-validates` | `ReplayBundle.load` + `project` succeed with no rejected or conflicting events |
| `collected-inventory-shows-attack-and-containment` | the CI identity's Pod create is collected and correlated to the live Pod UID/SA, the Pod is in inventory, and the `ci-pod-creator` delete is collected and absent from inventory |
| `collected-conclusion-matches-residual-token` | same model conclusion (`residual_path`) and same status on shared objectives as the hand-authored case |
| `collector-restart-recorded-as-gap` | at least two `collector-restart` gap records (kill of A, stop of B) |
| `collected-bundle-has-no-credential-material` | no file produced (bundles, spool, logs, result) contains the CI token, the stolen Pod token, the copied Secret value or the collector token (raw, base64, base64url), a JWT, private key, bearer header or canary |

The receipt is `labs/receipts/collect-<ts>.json`. The bundle and its analysis result are
copied to `labs/collected/residual-token-<ts>/` **only if the leak scan is clean**; the
workflow uploads that directory as the `collected-bundle` artifact only after `collect`
succeeded. The collector binary is built by the workflow (`AFTERLOCK_COLLECTOR_BIN`);
locally, `collect` runs `go build` itself.

## Lab-derived labels

`benchmarks/lab_labels.py` turns receipts into labels for the matching replay cases
(`benchmarks/labels/lab-derived.json`), using only observed HTTP statuses, never the
recorded model prediction. `benchmarks/run.py` reports agreement with these labels as a
separate label set next to the hand-authored expectations. Conflicting observations are
labelled `disputed`; no-answer observations produce no label.

Any disagreement is recorded as `lab_contradicted`. It must be investigated, and the model
must be revised before the profile can be marked verified.

## Safety

The supervisor refuses to act unless the context, local API endpoint, CA digest,
namespace UID, and lab instance label all match the record. Tokens exist only in process
memory, and response bodies are never read. The fake Secret value is random and never stored.
