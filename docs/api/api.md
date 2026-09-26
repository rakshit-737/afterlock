# HTTP API (v1)

Start with `AFTERLOCK_API_TOKENS=... make api` (and/or `AFTERLOCK_OIDC_*`, see
[authentication](../deployment/authentication.md)). OpenAPI, Swagger UI and ReDoc are **off by
default**: `AFTERLOCK_API_DOCS=authenticated` serves `/v1/openapi.json` to any authenticated
caller; `AFTERLOCK_API_DOCS=public` serves `/v1/openapi.json`, `/v1/docs`, `/v1/redoc` without
auth (development only). Storage is **in-memory** by default, so a restart loses all cases. Set `AFTERLOCK_DATABASE_URL` to use PostgreSQL. Run `python -m afterlock_api.migrate`
first; `docker compose up` does this. `GET /v1/health` returns `storage: "in-memory" | "postgresql"`.

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/v1/health` | none | |
| POST | `/v1/cases` | analyst (for that cluster) | Inline replay bundle `{case_id, cluster_id, inventory, case, events}`. 422 means `invalid_input`. 409 only if the id exists **in that cluster** |
| GET | `/v1/cases?limit&offset` | viewer | Only cases in the caller's clusters. `items` (ids) plus `entries` (`{case_id, cluster_id}`) |
| GET | `/v1/cases/{id}?cluster_id` | viewer | 404 for both missing and other-cluster cases. 409 `ambiguous_case` if the id exists in several of *your* clusters; pass `cluster_id` |
| POST | `/v1/cases/{id}/analyses` | analyst | `{remediation?, mode?}` |
| GET | `/v1/analyses/{id}` | viewer | |
| GET | `/v1/analyses/{id}/explanation` | viewer | text/plain |
| POST | `/v1/analyses/{id}/verification` | analyst | Reference checker, bounded by `AFTERLOCK_VERIFY_MAX_STATES` (default and maximum 50,000). 429 when concurrency-limited |
| POST | `/v1/cases/{id}/plans` | analyst | `{max_length ≤ 5, max_evaluations ≤ 10000}`. 429 when concurrency-limited |
| POST | `/v1/cases/{id}/analysis-jobs` | analyst | Same body as `/analyses` plus `max_attempts` (1–10, default 3). **202** `{job_id, state, manifest_id}`, `Location: /v1/jobs/{job_id}` |
| POST | `/v1/cases/{id}/plan-jobs` | analyst | Same body as `/plans` plus `max_attempts`. 202 |
| POST | `/v1/analyses/{id}/verification-jobs` | analyst | Optional `{max_attempts}`. 202 |
| GET | `/v1/jobs/{job_id}` | viewer | `{job_id, cluster_id, manifest_id, kind, state, attempts, max_attempts, cancel_requested, last_error, result_id, result?}` |
| GET | `/v1/jobs/{job_id}/events` | viewer | `text/event-stream` progress (below). 404 for missing/other-cluster jobs, 429 when too many streams |
| POST | `/v1/jobs/{job_id}/cancel` | analyst | 202 with the job. 409 if already terminal |
| any | `/v1/lab/*` | — | Always 403. The API cannot mutate clusters |

Every case-scoped endpoint (`/v1/cases/{id}/...`) accepts the same optional `?cluster_id=`.

Request bodies are limited to 4 MiB, counted on the bytes actually received (chunked bodies
without `Content-Length` included): 413 `request_too_large`. Unknown request fields are rejected.

## Resource limits

| Limit | Default | Setting | Response |
|---|---|---|---|
| In-memory cases / results / jobs | 1,000 / 10,000 / 10,000 | `AFTERLOCK_MEMORY_MAX_CASES`, `_RESULTS`, `_JOBS` | 507 `storage_full` (a job whose result would exceed the cap is `failed`) |
| Concurrent synchronous verification + planning | 1 per principal, 4 total | `AFTERLOCK_HEAVY_CONCURRENCY_PER_PRINCIPAL`, `_TOTAL` | 429, `Retry-After: 5` |
| Reference-checker states | 50,000 | `AFTERLOCK_VERIFY_MAX_STATES` (1..50,000) | exploration reported `complete: false` |
| Open progress streams | 4 per principal, 64 total | `AFTERLOCK_SSE_STREAMS_PER_PRINCIPAL`, `_TOTAL` | 429 |
| Progress stream duration | 300 s | `AFTERLOCK_SSE_MAX_SECONDS` | final `timeout` event |

Limits are per API process. The asynchronous `*-jobs` endpoints are the intended path for
heavy work; the synchronous ones are limited rather than queued.

## Asynchronous jobs

The synchronous endpoints above are unchanged. The `*-jobs` endpoints validate the request,
store an immutable content-addressed manifest together with a `queued` job in one
transaction, and return 202. Job `state` is one of `queued`, `leased`, `running`,
`succeeded`, `failed`, `cancelled`.

- `succeeded` includes `result_id` and `result`. For analysis jobs, `result_id` is also
  readable at `/v1/analyses/{result_id}`, including its explanation and verification.
- `failed` includes `last_error`. Input errors are not retried. Unexpected errors and
  expired leases are retried up to `max_attempts` times.
- Cancelling a queued job is immediate. Cancelling a leased or running job sets
  `cancel_requested`; the job becomes `cancelled` and never publishes a result.

### Progress events (SSE)

`GET /v1/jobs/{job_id}/events` streams:

```
retry: 1500

id: 1
event: state
data: {"attempts":0,"cancel_requested":false,"cluster_id":"lab-local","job_id":"job-…","kind":"analysis","last_error":null,"manifest_id":"mf-…","max_attempts":3,"result_id":null,"seq":1,"state":"queued"}

: heartbeat

id: 2
event: state
data: {… "state":"succeeded","result_id":"an-…" …}
```

- One `state` event per observed change of `(state, attempts, cancel_requested, result_id)`;
  the first event is the current state. The stream closes after a terminal state.
- Every event carries `manifest_id`, the content address of the job's exact input and engine
  version. A client must only combine events and results with the same `manifest_id`, so
  progress for one analysis version is never mixed with results for another. The result body
  is not streamed; fetch `/v1/jobs/{id}` or `/v1/analyses/{result_id}`.
- Heartbeat comments (`: heartbeat`) every 15 s. After `AFTERLOCK_SSE_MAX_SECONDS` a
  `timeout` event is sent and the stream closes; reconnect to continue (events restart at
  `seq` 1 with the current state; `Last-Event-ID` is not interpreted).
- Implemented by polling storage (0.5 s) for both backends; PostgreSQL `LISTEN/NOTIFY` is not
  used. Intermediate states shorter than the poll interval may not be observed.

Jobs, like cases, are cluster-scoped. Another cluster's job returns 404, the same as a
missing job. With PostgreSQL, jobs run in the `afterlock_worker` process
(`python -m afterlock_worker`). In-memory, they run inside the API process after the
response.
