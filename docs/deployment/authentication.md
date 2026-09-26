# Authentication and deployment

## Local bootstrap (implemented)

`AFTERLOCK_API_TOKENS` holds comma-separated `<token>:<role>:<cluster>[|<cluster>]` entries.
Tokens must be at least 16 characters. Only their SHA-256 digests are kept in memory, and
they are compared in constant time. Roles: `viewer` (read), `analyst` (read, import, analyze,
plan, verify), and `lab-operator` (no API powers; reserved for the out-of-process supervisor).

Bind the API to localhost (as `compose.yaml` does), or front it with TLS.

## OIDC bearer tokens (implemented, optional)

Install the extra: `pip install 'afterlock[oidc]'` (PyJWT with `cryptography`). Setting
`AFTERLOCK_OIDC_ISSUER` enables validation of `Authorization: Bearer <JWT>`; static tokens keep
working alongside it (a presented token is first compared with the static digests).

| Variable | Required | Meaning |
|---|---|---|
| `AFTERLOCK_OIDC_ISSUER` | yes | Exact `iss` value |
| `AFTERLOCK_OIDC_AUDIENCE` | yes | Required `aud` value |
| `AFTERLOCK_OIDC_JWKS_URL` | yes | HTTPS JWKS URL (plain HTTP refused) |
| `AFTERLOCK_OIDC_ROLE_CLAIM` | no (`afterlock_role`) | Claim holding a string or list of strings |
| `AFTERLOCK_OIDC_ROLE_MAP` | no | `value:role,...`, e.g. `afterlock-analysts:analyst,afterlock-readers:viewer`. When set, only mapped values count |
| `AFTERLOCK_OIDC_CLUSTERS_CLAIM` | no (`afterlock_clusters`) | List of cluster ids, or a `|`-separated string |
| `AFTERLOCK_OIDC_ALLOW_WILDCARD_CLUSTER` | no | `1` lets a `*` cluster claim through (refused by default) |
| `AFTERLOCK_OIDC_LEEWAY_SECONDS` | no (30) | Clock-skew leeway for `exp`/`nbf`/`iat` (0..300) |
| `AFTERLOCK_OIDC_JWKS_TTL_SECONDS` | no (300) | JWKS cache lifetime |

Validation rules:

- Only `RS256` and `ES256`. `alg: none`, all `HS*`, and anything else are rejected before any
  key lookup, and the JWK's key type must match the algorithm (no RSA-key-as-HMAC-secret confusion).
- `kid` is required. The JWKS is cached; an unknown `kid` triggers at most one refetch per 30 s
  (rotation without letting junk tokens hammer the IdP). If the IdP is unreachable after a
  successful fetch, the cached keys keep working; with no successful fetch, tokens are rejected.
- `iss`, `aud`, `sub`, `exp`, `iat` are required; `nbf` is honoured; `iat` in the future (beyond
  leeway) is rejected.
- Several roles resolve to the most privileged of `analyst` > `viewer` > `lab-operator`. No
  recognised role, or no/empty clusters claim, means 401.
- Every failure is a generic 401 `invalid token`; the reason is not returned.

Principals are named `oidc:<sub>` (used for per-principal concurrency limits). Not implemented:
token revocation/introspection, `azp` checks, discovery (`.well-known/openid-configuration`),
and audit logging of API access. Validation was tested only with locally generated keys and a
fake JWKS, never against a real IdP.

## Containers

`services/api/Dockerfile` runs as UID 10001. `compose.yaml` sets `read_only`, drops all
capabilities, and sets `no-new-privileges`. The container build has **not** been tested in
the development environment, which had no Docker daemon. Base images are not yet pinned by
digest.
