# HTTP API (v1)

Start with `AFTERLOCK_API_TOKENS=... make api`. OpenAPI is served at `/v1/openapi.json`,
and interactive docs at `/v1/docs`. Storage is **in-memory** by default, so a restart loses
all cases. Set `AFTERLOCK_DATABASE_URL` to use PostgreSQL. Run `python -m afterlock_api.migrate`
first; `docker compose up` does this. `GET /v1/health` returns `storage: "in-memory" | "postgresql"`.

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/v1/health` | none | |
| POST | `/v1/cases` | analyst (for that cluster) | Inline replay bundle `{case_id, cluster_id, inventory, case, events}`. 422 means `invalid_input` |
| GET | `/v1/cases?limit&offset` | viewer | Only cases in the caller's clusters |
| GET | `/v1/cases/{id}` | viewer | 404 for both missing and other-cluster cases |
| POST | `/v1/cases/{id}/analyses` | analyst | `{remediation?, mode?}` |
| GET | `/v1/analyses/{id}` | viewer | |
| GET | `/v1/analyses/{id}/explanation` | viewer | text/plain |
| POST | `/v1/analyses/{id}/verification` | analyst | Reference checker (bounded to 50,000 states) |
| POST | `/v1/cases/{id}/plans` | analyst | `{max_length ≤ 5, max_evaluations ≤ 10000}` |
| POST | `/v1/cases/{id}/analysis-jobs` | analyst | Same body as `/analyses` plus `max_attempts` (1–10, default 3). **202** `{job_id, state, manifest_id}`, `Location: /v1/jobs/{job_id}` |
| POST | `/v1/cases/{id}/plan-jobs` | analyst | Same body as `/plans` plus `max_attempts`. 202 |
| POST | `/v1/analyses/{id}/verification-jobs` | analyst | Optional `{max_attempts}`. 202 |
| GET | `/v1/jobs/{job_id}` | viewer | `{job_id, cluster_id, manifest_id, kind, state, attempts, max_attempts, cancel_requested, last_error, result_id, result?}` |
| POST | `/v1/jobs/{job_id}/cancel` | analyst | 202 with the job. 409 if already terminal |
| any | `/v1/lab/*` | — | Always 403. The API cannot mutate clusters |

Request bodies are limited to 4 MiB. Unknown request fields are rejected.

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

Jobs, like cases, are cluster-scoped. Another cluster's job returns 404, the same as a
missing job. With PostgreSQL, jobs run in the `afterlock_worker` process
(`python -m afterlock_worker`). In-memory, they run inside the API process after the
response.
