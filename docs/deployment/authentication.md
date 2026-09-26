# Authentication and deployment

## Local bootstrap (implemented)

`AFTERLOCK_API_TOKENS` holds comma-separated `<token>:<role>:<cluster>[|<cluster>]` entries.
Tokens must be at least 16 characters. Only their SHA-256 digests are kept in memory, and
they are compared in constant time. Roles: `viewer` (read), `analyst` (read, import, analyze,
plan, verify), and `lab-operator` (no API powers; reserved for the out-of-process supervisor).

Bind the API to localhost (as `compose.yaml` does), or front it with TLS.

## Shared deployments (not implemented)

Put an OIDC-aware reverse proxy in front of the API. Native OIDC, per-user concurrency
limits, and audit logging of API access are planned.

## Containers

`services/api/Dockerfile` runs as UID 10001. `compose.yaml` sets `read_only`, drops all
capabilities, and sets `no-new-privileges`. The container build has **not** been tested in
the development environment, which had no Docker daemon. Base images are not yet pinned by
digest.
