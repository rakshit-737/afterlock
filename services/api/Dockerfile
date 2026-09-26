# AFTERLOCK API and worker image (the worker runs `python -m afterlock_worker`). Unprivileged, read-only root filesystem expected at runtime.
# Base image pinned by multi-arch index digest (resolved 2026-09-26 from registry-1.docker.io).
# Update procedure: docs/security/supply-chain.md.
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e AS build
# uv 0.11.32, pinned by multi-arch index digest (resolved 2026-09-26 from ghcr.io).
# Build stage only: it exports the locked requirements and never reaches the runtime image.
COPY --from=ghcr.io/astral-sh/uv:0.11.32@sha256:df4cae8f3a96d175e2e5f992e597550000edbe78fdc2594d5cd8de1a217f504c /uv /usr/local/bin/uv
WORKDIR /src
COPY pyproject.toml uv.lock README.md ./
COPY services/api/build-requirements.txt ./build-requirements.txt
# Third-party dependencies come only from uv.lock, with every artifact hash verified:
# --frozen never re-resolves; --require-hashes makes pip refuse any unhashed or mismatched file.
RUN uv export --frozen --no-dev --extra api --extra postgres --no-emit-project \
        --format requirements-txt --output-file /src/requirements.lock.txt \
 && pip install --no-cache-dir --require-hashes --no-deps --only-binary=:all: \
        --prefix=/install -r /src/requirements.lock.txt \
 && pip install --no-cache-dir --require-hashes -r /src/build-requirements.txt
COPY packages ./packages
COPY services/api ./services/api
COPY services/worker ./services/worker
# The project itself: no dependencies, no index, no build isolation (uses the hashed setuptools above).
RUN pip install --no-cache-dir --no-deps --no-index --no-build-isolation --prefix=/install .

FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e
COPY --from=build /install /usr/local
COPY migrations /app/migrations
ENV AFTERLOCK_MIGRATIONS_DIR=/app/migrations
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin afterlock
USER 10001
EXPOSE 8080
CMD ["python", "-m", "uvicorn", "afterlock_api.app:app", "--host", "0.0.0.0", "--port", "8080"]
