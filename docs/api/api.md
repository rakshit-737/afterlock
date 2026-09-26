# HTTP API (v1)

Start with `AFTERLOCK_API_TOKENS=... make api`. OpenAPI is served at `/v1/openapi.json`,
and interactive docs at `/v1/docs`. Storage is **in-memory**, so a restart loses all cases.

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
| any | `/v1/lab/*` | — | Always 403. The API cannot mutate clusters |

Request bodies are limited to 4 MiB. Unknown request fields are rejected.
