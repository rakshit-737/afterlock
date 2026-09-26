# Supply chain: pins and how to update them

Every external input to CI, the lab, and the API image is pinned to an immutable
identifier. A tag or version string is kept next to each pin as a comment for humans;
the immutable identifier is what is enforced. Never write a pin you did not resolve
yourself from the upstream source (commands below).

Pins recorded 2026-09-26.

## GitHub Actions (commit SHA)

| Action | Pin | Tag | Used in |
|---|---|---|---|
| actions/checkout | `11d5960a326750d5838078e36cf38b85af677262` | v4.4.0 | ci.yml, live-lab.yml |
| actions/setup-python | `a26af69be951a213d495a4c3e4e4022e16d87065` | v5.6.0 | ci.yml, live-lab.yml |
| actions/upload-artifact | `ea165f8d65b6e75b540449e92b4886f43607fa02` | v4.6.2 | ci.yml, live-lab.yml |
| astral-sh/setup-uv | `c18668ad3cf93ea998bef934396af7bb5c839dc7` | v10.2.0 | ci.yml, live-lab.yml |

Resolve a tag to a commit:

```sh
gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq '.object'
# if .object.type == "tag" (annotated), dereference it:
gh api repos/<owner>/<repo>/git/tags/<object.sha> --jq '.object.sha'
```

Write the result as `uses: owner/repo@<40-hex-sha> # vX.Y.Z`. Dependabot
(`.github/dependabot.yml`) proposes weekly bumps and rewrites the SHA and comment together.

## Python dependencies (uv.lock)

- `uv.lock` pins every package, version, and artifact hash for all extras.
- CI installs with uv `0.11.32` (via `setup-uv`, `version:` input) using
  `uv lock --check` (fails if `uv.lock` disagrees with `pyproject.toml`) and
  `uv sync --frozen --extra dev` (installs exactly the lock; never re-resolves).
- Update: edit `pyproject.toml` if ranges change, then `uv lock --upgrade-package <name>`
  (or `uv lock --upgrade`), run `./scripts/verify`, commit `pyproject.toml` and `uv.lock`
  together. Dependabot's `uv` ecosystem does the same.
- Update uv itself: change `version:` in every `setup-uv` step.

## Container images (digest)

| Image | Digest | Used in |
|---|---|---|
| python:3.11-slim | `sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e` | services/api/Dockerfile (both stages) |
| kindest/node:v1.31.4 | `sha256:2cb39f7295fe7eafee0842b1052a599a4fb0f8bcf3f83d96c7f4864c357c6c30` | labs/kind/cluster.yaml (matches the kind v0.26.0 release notes) |
| busybox:1.36.1 | `sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662` | labs/manifests/*.yaml, labs/supervisor/lab.py |
| python:3.12-alpine | `sha256:4c47124a8391cb7a9f571164147d154777cf012a4ece5f86097130d7a4478111` | labs/manifests/canary-service.yaml |

All digests are multi-architecture index (manifest list) digests, so the same pin works
on amd64 and arm64. Resolve one:

```sh
docker buildx imagetools inspect python:3.11-slim     # "Digest:" line
# without docker: anonymous token + HEAD on the registry
TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull" | jq -r .token)
curl -sI -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.oci.image.index.v1+json" \
  -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
  https://registry-1.docker.io/v2/library/python/manifests/3.11-slim | grep -i docker-content-digest
```

For kind node images use the digest published in the kind release notes for the kind
version in `.github/workflows/live-lab.yml`; changing the kind version requires a new
node digest.

## Lab binaries (checksum)

`kind` and `kubectl` are downloaded by version and verified against the upstream
`.sha256` files in `live-lab.yml`. The checksum is fetched from the same origin as the
binary, so this detects corruption, not an upstream compromise.

## SBOM

- CI job `sbom` (ci.yml) uploads artifact `sbom-cyclonedx` with:
  - `afterlock-lock.cdx.json`: every package in `uv.lock` (all extras), from
    `uv export --format cyclonedx1.5` (experimental uv feature);
  - `afterlock-env.cdx.json`: the installed dev environment, from
    `cyclonedx-py environment` (cyclonedx-bom `7.4.0`, run in an isolated `uvx` env).
- Local: `scripts/sbom` (needs uv and a synced `.venv`); output goes to `sbom/` (git-ignored).
- The SBOM tool is pinned by version, not by hash.

## Known gaps

- `services/api/Dockerfile` installs `.[api]` and `uvicorn==0.30.6` with pip, resolving
  transitive dependencies at build time instead of from `uv.lock`.
- No signed artifacts, provenance attestations, or SBOM for the container image.
- Upstream checksum for kind/kubectl is same-origin (see above).
