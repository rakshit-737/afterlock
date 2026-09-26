# Security policy

AFTERLOCK is research-grade software. Its inventories and explanations describe
cluster weaknesses, so treat result bundles as sensitive.

## Reporting a vulnerability

Please use GitHub private vulnerability reporting for this repository, if the
maintainers have enabled it. If it is not enabled, open an issue asking for a
private contact channel; do not include details in the issue.

## Security properties the project aims to keep

- Production-facing operation is read-only. The API and CLI never mutate clusters.
- Only `labs/supervisor/lab.py` mutates resources, and only in a cluster whose
  recorded identity (endpoint, CA digest, namespace UID, lab instance id) matches.
- Tokens and Secret bodies are never persisted. Evidence records containing
  credential-like fields or values are rejected and become coverage gaps
  (`tests/security/test_redaction_and_boundaries.py`).
- Parsing is JSON only. No pickle, no YAML object loaders, and no dynamically loaded plugins.
- API authorization is enforced server-side, per cluster (`tests/integration/test_api.py`).

## Known gaps (tracked in docs/engineering/status.md)

- Only a pattern-based starter review exists (docs/security/review-2026-09-26.md); the full
  adversarial review (design phase 9) has not been performed.
- Actions are SHA-pinned, images digest-pinned, CI installs from `uv.lock`, and CI emits a
  CycloneDX SBOM (docs/security/supply-chain.md). Not yet done: signed/attested release
  artifacts and provenance; the API container build does not install from the lockfile.
- API authentication is static bearer tokens only (local bootstrap). There is no OIDC yet.
