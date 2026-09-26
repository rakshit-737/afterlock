# Adversarial review: API, auth, storage, worker, web, CI (2026-09-26)

Phase 9 adversarial pass over `services/api`, `services/worker`, `migrations/`,
`services/web` (src, nginx, Dockerfile), `compose.yaml`, `services/api/Dockerfile` and
`.github/workflows/`. The collector, lab and engine are out of scope (reviewed separately).
Follows the starter in [review-2026-09-26.md](review-2026-09-26.md).

Rule: a finding is listed as confirmed only with a failing test written first; anything
not demonstrated is under "Unconfirmed".

## Confirmed findings

| # | Severity | Location | Finding | Reproduction | Fix | Status |
|---|---|---|---|---|---|---|
| A-1 | Medium | `services/api/afterlock_api/oidc.py` (`OIDCValidator._key`) | A **failed** JWKS refresh did not start the `jwks_min_refresh` back-off (`_fetched_at` only moved on success). During an IdP outage after the TTL, or at startup, every bearer token presented to the API (no valid credential needed: any JWS-shaped string with an allowed `alg` and a `kid`) triggered a JWKS fetch while holding the validator lock, each fetch up to the 5 s urllib timeout. All OIDC validation serialized behind it: unauthenticated DoS and outbound request amplification toward the IdP. | `tests/security/test_adversarial_api.py::test_failed_jwks_refresh_is_rate_limited`, `::test_jwks_outage_at_start_is_rate_limited_too` (100 validations -> ~100 fetches before the fix) | `fix(security): rate-limit failed JWKS refreshes in the OIDC validator`: every fetch attempt starts the back-off; cached keys keep serving meanwhile. | Fixed |
| A-2 | Medium | `services/api/afterlock_api/storage.py` (`MemoryStorage._held`, `PostgresStorage._extend`, `PostgresStorage._lock_held`) | Leases were matched on `(job_id, cluster_id, lease_owner)` only. When an expired job was re-claimed under the **same owner name** (all in-process drains use `api-inprocess`; a restarted worker container keeps `hostname-pid` = `<id>-1`), the stale holder could heartbeat, re-queue (`fail`), fail, acknowledge cancel or publish against the new attempt's lease, violating the documented publication invariant. | `tests/security/test_adversarial_api.py::test_stale_lease_cannot_*`, `tests/integration/test_storage_contract.py::test_stale_lease_with_same_owner_is_fenced_by_attempt` (memory; PostgreSQL variant runs in CI) | `fix(security): fence job leases by attempt number, not only owner name`: both backends also require `attempts = lease.attempt`. | Fixed (PostgreSQL path verified by CI only; skipped locally) |

## Checked, no defect found

- **Cross-cluster reads**: every case/analysis/job/SSE/cancel/verification path goes through
  a scoped storage call; `?cluster_id=` only narrows within the caller's scope; missing and
  unauthorized return the same 404; `AmbiguousCase` only fires across the caller's own clusters.
- **SQL**: all PostgreSQL statements are parameterized; the only f-string SQL interpolates
  a constant column list (`_JOB_COLS`) and migration placeholders.
- **OIDC**: `none`/`HS*` rejected before key lookup; key type must match `alg`; `iss`, `aud`,
  `exp`, `iat`, `sub` required; `iat` in the future rejected; wildcard cluster opt-in only;
  unknown-kid storms rate-limited (now also on failure, A-1).
- **Deep JSON**: nesting of 500-5,000 levels in `case`, and 100,000-level bodies (authenticated
  and not) give 201 or 400, never 500, on Python 3.11 and 3.14.
- **Frontend**: token kept in React state only, `credentials: "omit"`, `redirect: "error"`,
  path segments `encodeURIComponent`-escaped, no `innerHTML`/`dangerouslySetInnerHTML`,
  `Location` header not followed. nginx CSP `default-src 'none'`, `script-src 'self'`, no inline.
- **Containers**: all services non-root, `read_only`, `cap_drop: ALL`, `no-new-privileges`,
  ports bound to 127.0.0.1, base images digest-pinned.
- **CI**: `pull_request` only (no `pull_request_target`), `permissions: contents: read`,
  `persist-credentials: false`, actions pinned by SHA, no `${{ github.event.* }}` in `run:`.

## Unconfirmed / open (not demonstrated, no fix)

- **Unbounded PostgreSQL job queue per principal**: an analyst can enqueue jobs without a
  quota; the worker is FIFO across clusters, so one cluster's analyst can delay others.
  Design gap (fairness/quota), not demonstrated as a crash.
- **Synchronous `POST /v1/cases/{id}/analyses` is not behind the heavy-concurrency limiter**
  (verification and planning are). No input found that makes `analyze` expensive enough to
  matter; not demonstrated.
- **`last_error` shows `Type: message` of unexpected worker exceptions** to viewers of the
  same cluster. No path found where the message contains secrets or other clusters' data.
- **OIDC `sub` truncated to 200 chars** in the principal name: two subjects sharing a prefix
  share concurrency slots. Not an authorization bypass.
- **API image still installs dependencies unpinned** (starter finding 9, still open).
- **OIDC audience arrays**: PyJWT accepts a token whose `aud` list contains the configured
  audience; `azp` is not checked. This is standard OIDC behaviour. Tokens minted for several
  audiences are therefore accepted.

## Commands and results (local, Windows, Python 3.11 venv from `uv.lock`)

| Command | Result |
|---|---|
| `python -m ruff check packages services tests datasets benchmarks labs` | All checks passed |
| `python -m mypy` | no issues in 15 source files |
| `python -m pytest -q tests/integration tests/unit tests/security` | 237 passed, 18 skipped (PostgreSQL: BLOCKED locally), 1 failed: `tests/unit/test_evidence.py::test_symlinked_file_rejected` (Windows cannot create symlinks without privilege; unrelated, pre-existing) |
| `cd services/web && npm ci && npm run lint && npm run typecheck && npm test` | lint clean, typecheck clean, 46 tests passed |
