# AFTERLOCK collector (phase 2)

`services/collector` is a Go program that gathers **metadata-only** Kubernetes
evidence and writes an `afterlock.replay/1` bundle (`manifest.json`,
`inventory.json`, `events.jsonl`, `case.json`) that
`afterlock.evidence.ReplayBundle.load` and `project` accept.

Status: implemented and tested against a fake clientset and fixture audit logs.
**Not yet run against a live cluster** (see "Not verified" below).

## What it does

| Input | Mechanism | Output |
|---|---|---|
| Pods, ServiceAccounts, Roles, ClusterRoles, RoleBindings, ClusterRoleBindings | list + watch (typed client-go clientset) | `inventory.json` |
| ValidatingAdmissionPolicies | list + watch | one `collector.gap` per policy: observed but CEL is not translated, so admission effects are not modeled |
| Secrets (optional, `--secret-metadata`) | list + watch through the **metadata** client (`PartialObjectMetadata`), so the API server strips bodies before responding | `inventory.secrets` (namespace, name, UID, version) |
| Audit log file (`--audit-log`, JSON lines, `audit.k8s.io/v1`) | file reader | `k8s.api.response` envelopes |
| Audit webhook backend (`--webhook-listen`, `POST /v1/audit`, `EventList`) | HTTPS receiver, bearer token | `k8s.api.response` envelopes |

Every run ends with a `collector.heartbeat` record, so `required_sources` /
`max_evidence_staleness_seconds` in `case.json` work as for other sources.

## Security boundary

* **Read-only.** The only API verbs issued are `list` and `watch`
  (`TestGoldenBundle` asserts this against the fake clientset's recorded
  actions). RBAC: [`services/collector/deploy/rbac.yaml`](../../services/collector/deploy/rbac.yaml).
* **No Secret data, no tokens.** Audit events are decoded into a struct that
  holds only allowlisted metadata (`auditID`, `stage`, `verb`, `user.username`,
  `user.uid`, the `authentication.kubernetes.io/pod-uid` extra, `objectRef`,
  `responseStatus.code`, `stageTimestamp`). `requestObject`/`responseObject`
  are discarded immediately (and counted, so a `RequestResponse` audit policy
  is visible), and `requestURI`, source IPs, groups, annotations and other
  user extras (including `credential-id`) are never read. Inventory
  converters copy allowlisted fields only; Pod specs, env vars, annotations
  (including `last-applied-configuration`) and managed fields are dropped.
  The Secret converter rejects anything that is not `PartialObjectMetadata`.
* **Redaction.** Every emitted string passes `internal/redact`: values that
  look like JWTs, private keys, `Bearer …` headers or seeded
  `AFTERLOCK-CANARY-…` values are replaced with `[redacted]`. The spool and the
  bundle writer run a fail-closed check (same forbidden keys and patterns as
  `packages/afterlock/evidence.py`) before any byte is written.
* **Canary tests.** `testdata/audit.log` and the fake cluster seed canaries in
  request/response bodies, request URIs, annotations, credential IDs, Pod env
  vars, a Secret's `data` and an object name. Go tests and
  `tests/integration/test_collector_bundle.py` assert none reach the spool or
  the bundle.
* **Secret metadata is off by default.** RBAC cannot grant "metadata only":
  `list secrets` permits reading bodies with any client. The optional grant is
  in a separate manifest,
  [`secret-metadata-rbac.yaml`](../../services/collector/deploy/secret-metadata-rbac.yaml),
  with that warning. When disabled, the bundle carries a
  `secret-metadata-disabled` gap, and Secret reads without a known version
  become missing-metadata coverage gaps in the analysis, never "no read".
* **Webhook receiver** requires TLS (`--tls-cert/--tls-key`); plain HTTP is
  allowed only on a loopback address with `--insecure-http-loopback`. Callers
  must send `Authorization: Bearer <token>` (≥16 characters, from
  `--webhook-token-file`, compared in constant time). Bodies are capped at
  8 MiB. A batch is acknowledged only after the spool is fsynced.
* The container ([`Dockerfile`](../../services/collector/Dockerfile)) is a
  static binary on `distroless/static-debian12:nonroot`, both images pinned by
  digest.

Recommended audit policy: [`deploy/audit-policy.yaml`](../../services/collector/deploy/audit-policy.yaml)
(`Metadata` level; bodies are never logged).

## Evidence semantics

* **Deduplication by audit ID.** `event_id` is `audit:<auditID>`; a record
  delivered twice (log replay, webhook retry, both backends) is spooled once.
  Only the `ResponseComplete` and `Panic` stages are evidence.
* **Sequences.** The spool assigns `source_sequence` monotonically per
  `--source-id`; it is the ordering key the Python projector uses.
* **resourceVersion is opaque.** It is only passed back to resume a watch and
  compared for equality. Secret `version` in `inventory.json` is a
  collector-local counter: 1 at first sight of a UID, +1 each time the
  resourceVersion string changes. A new UID under the same name restarts at 1.
  Versions are **not comparable across collector runs**.
* **Pod UID correlation.** At `Metadata` level an audit record for a Pod
  `create` does not carry the new Pod's UID. The bundle writer fills
  `target.uid`/`target.service_account` only when exactly one Pod with that
  namespace/name observed by the watch during this session has a
  `creationTimestamp` within 10 s before the audit stage timestamp (marked
  `uid_source: inventory-correlation`). Zero or multiple matches produce a
  `pod-uncorrelated` gap; a UID is never guessed from the name alone.
* **Actor.** `actor.username`; `actor.sa_uid` from `user.uid` for service
  accounts; `actor.pod_uid` from the bound-token Pod UID extra. Events using
  impersonation are not modeled and become `audit-unmodeled` gaps.
* **RBAC rules.** `apiGroups` are not retained (the analysis model has no
  group dimension), which over-approximates permissions: conservative for
  residual access. Non-resource-URL rules are dropped with an
  `rbac-rule-unmodeled` gap.

## Gap records

All gaps are `collector.gap` envelopes with `gap_id`, `gap_kind` and `reason`;
the projector turns each into an `observation_gap` coverage gap.

| `gap_kind` | Cause |
|---|---|
| `resource-version-expired` | watch returned 410 Expired/Gone; followed by a relist |
| `relist` | a kind was relisted; states between snapshots were not observed |
| `watch-restarted` | a watch stream ended and was resumed from the last resourceVersion |
| `watch-error`, `watch-failed`, `list-failed` | API errors; inventory incomplete until recovered |
| `inventory-unsynced` | a kind never completed a list (or `--no-cluster`) |
| `spool-overflow`, `spool-overflow-summary` | the spool was full; the summary carries the drop count |
| `collector-restart` | the collector started with an existing spool (plus torn-tail notice if a partial record was discarded) |
| `audit-malformed`, `audit-dropped` | an audit record or webhook batch could not be parsed or exceeded limits |
| `audit-unmodeled` | impersonation |
| `pod-uncorrelated` | a successful Pod create/exec whose UID could not be determined |
| `admission-policy-unmodeled`, `rbac-rule-unmodeled`, `secret-metadata-disabled` | observed but not modeled |

## Spool

`--spool` (default `afterlock-spool.jsonl`) is an append-only JSON-lines file
bounded by `--spool-max-bytes` and `--spool-max-records`. Two records and
4 KiB are reserved for overflow gaps. On overflow the collector logs an
`ALARM` line, increments `afterlock_collector_spool_dropped_total`, sets
`afterlock_collector_spool_overflow 1`, and writes a gap. On restart the spool
is reopened: sequence numbers and the audit-ID dedup set are restored and a
`collector-restart` gap is written.

## Usage

```sh
# Convert an audit log offline (no cluster access; inventory recorded as unsynced gaps)
afterlock-collector --no-cluster --cluster-id lab-local --audit-log audit.log \
  --case case-template.json --out bundle/

# In-cluster: watch inventory and receive webhook audit batches until SIGTERM
afterlock-collector --cluster-id prod-eu1 --source-id prod-eu1-audit \
  --webhook-listen :8443 --webhook-token-file /var/run/afterlock/token \
  --tls-cert /tls/tls.crt --tls-key /tls/tls.key \
  --spool /data/spool.jsonl --out /data/bundle
```

Without `--case` an empty case (no objectives, no seeded compromise) is
written. The bundle loads, but `project` rejects it until an analyst supplies
objectives, as intended.

Health: `GET /healthz`; metrics (Prometheus text): `GET /metrics` on the
webhook listener.

## Tests

```sh
cd services/collector
go vet ./...
go test ./...                                          # includes byte-for-byte golden check
go test ./internal/bundle -run TestGoldenBundle -update  # regenerate testdata/golden-bundle (review the diff)
cd ../.. && pytest tests/integration/test_collector_bundle.py
```

## Dependencies

`k8s.io/client-go`, `k8s.io/api`, `k8s.io/apimachinery` v0.31.14 (matching the
`k8s-1.31-core-v1` profile), plus their transitive modules pinned in
`go.sum`. client-go is the reference Kubernetes client: it provides
authenticated in-cluster/kubeconfig transport, typed list/watch, the
metadata-only client for Secrets, and the fake clientsets used by the tests.
Reimplementing these on `net/http` would be more code to audit, not less. No
informer/cache machinery is used, because informers relist silently and would
hide exactly the gaps the collector must record.

## Not verified

* No run against a real API server (kind or otherwise): watch expiry, bookmark
  handling, metadata-client behaviour and webhook delivery from a real
  kube-apiserver are exercised only with fakes.
* The container image has not been built in this change.
* Correlation window and relist backoff are fixed defaults, not tuned.
