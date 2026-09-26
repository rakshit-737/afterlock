# Live lab: semantic spike

**Status:** executed in the `live-lab` workflow. The latest run (36244828581) recorded
`spike --repeat 3` with 17/17 steps agreeing in every run
(`labs/receipts/spike-summary-20260926T132141Z.json`; Calico, digest-pinned node image,
`syncFrequency: 10s`, network-isolation steps, `reset`) and a `lab_confirmed` collector run
(`collect-20260926T132806Z.json`). One Kubernetes version (v1.31.4), one idle single-node
cluster; see `docs/engineering/verification.md` for what has actually run.

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
| S-SEC-5: old value probed right after rotation, model with measured `d` and no wait | violated (old value accepted) |
| S-SEC-5: old value probed at least `d` + 2 s after rotation, model after `wait d` | satisfied_within_scope (old value refused) |
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

### S-SEC-5 receipt (lab-confirmed: 3/3 runs, `spike-summary-20260926T132141Z.json`)

Right after the rotation is written, the supervisor probes the old value once, then polls
new and old every ~2 s until the new value is accepted and the old one refused. That
acknowledgement time `ack` is an upper bound on when the old value stopped working; the
model is parameterised with `d = ceil(ack)` (`rotation_propagation_seconds` on
`canary-service`, applied to the `targeted-containment` analysis input), which
over-approximates the window. Two steps are recorded:

- `s-sec-5-old-credential-accepted-right-after-rotation`: observed = the first probe;
  prediction = model with `d` and no wait (`violated`).
- `s-sec-5-old-credential-rejected-after-propagation-wait`: probe at least `d` + 2 s after
  the rotation; prediction = model after `wait d` (`satisfied_within_scope`).

Both carry `d`, `ack`, and a `window` summary of every old-value probe (first probe time
and status, last acceptance, first refusal, and whether the value was ever accepted again
after a refusal). Limits, stated plainly: `d` is measured in the same run that is checked,
so this confirms the model is consistent with the observed timing, not that `d` was
predicted; one late probe does not prove the old value can never work again; and the probe
latency (a `kubectl exec`, ~0.3–1 s) sets the resolution. If the first probe already sees a
refusal, the window was not observed; the rotation is repeated (old = the previously
accepted value) up to 3 times, every attempt is recorded, and if none observes the window
the step disagrees and the run is `lab_contradicted` rather than passing.

## Collector run (`collect`)

**Status:** both windows (residual-token and targeted containment) and the S-SEC-5 steps are
lab-confirmed (`labs/receipts/collect-20260926T132806Z.json`, 28/28 checks, run 36244828581). `scripts/lab collect` runs `reset`, then the spike
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
5. Second window: right after C, process D starts on a
   **fresh spool** (no injected restart) with a case derived from
   `datasets/replay/targeted-containment/case.json`, while the attacker Pod still exists.
   This matters: the audit log has no Pod UIDs, and the collector correlates a Pod creation
   with a UID only from Pods it observed itself. D cannot re-read the audit log, so at the
   second checkpoint (binding removed, attacker Pod deleted, credential rotated, before the
   negative control restores the binding) the supervisor relays the API server audit log to
   D's loopback webhook receiver (`--insecure-http-loopback`, random bearer token in a 0600
   file) as `audit.k8s.io/v1` EventList batches; D is then stopped and writes the bundle.
6. The spike then continues as usual.

The second-window case keeps only what the collector can observe: `protect-secret`,
`release-read`, `remove_binding` and `delete_pods_except` (keep UID = live `release-app`
UID; any other template UID is refused, never invented). `protect-canary`,
`release-canary` and `rotate_downstream_credential` are dropped and listed in the
receipt's `coverage_limitations` — the canary's accepted value is not a Kubernetes object
the collector sees; those items are checked only by the canary probes. The case's
`analysis_time` is D's start (the collector reads the case at start).

Any coverage gap makes the engine report `unknown`, and a real lab bundle always has
`audit-before-window` (cluster setup, earlier runs) and `rbac-rule-unmodeled` (non-resource
URL rules) gaps. The comparison therefore reports two results: the **raw** result (no gap
resolved, expected `unknown`) and a result in which only those two gap kinds are declared
resolved, each with a stated reason added to the case assumptions
(`collected.GAP_RESOLUTIONS`). Any other gap (collector restart, uncorrelated Pod,
unsynced inventory, dropped/malformed audit, stale source) or engine unknown blocks the
match; so does a raw `violated`/`possibly_violated`.

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
| `collector-writes-contained-bundle` | every audit batch relayed with HTTP 200, no malformed audit line, D exits 0 and wrote a bundle |
| `contained-bundle-validates` | the second bundle loads and projects with no rejected or conflicting events |
| `contained-inventory-shows-attack-and-containment` | Pod create collected and correlated to the live (now deleted) UID/SA; binding and Pod delete collected; both absent from inventory; only the kept UID runs as `release-reader`; a patch/update of `release-credential` (rotation) collected |
| `collected-conclusion-matches-targeted-containment` | no blocking gap, no raw violation, and with the declared resolutions the conclusion (`contained_within_scope`) and `protect-secret` match the hand-authored case; raw result, resolved gap kinds and coverage limitations recorded |
| `contained-bundle-has-no-credential-material` | leak scan over every file of both windows, adding the rotated values, the legitimate-workload token and the webhook token |

The receipt is `labs/receipts/collect-<ts>.json`. The bundle and its analysis result are
copied to `labs/collected/residual-token-<ts>/` (and the second window's bundle, raw and
gap-resolved results to `labs/collected/targeted-containment-<ts>/`)
**only if the leak scan is clean**; the
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
