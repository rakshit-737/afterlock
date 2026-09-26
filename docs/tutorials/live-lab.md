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
