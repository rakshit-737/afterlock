# AFTERLOCK API and worker image (the worker runs `python -m afterlock_worker`). Unprivileged, read-only root filesystem expected at runtime.
# Base image pinned by multi-arch index digest (resolved 2026-09-26 from registry-1.docker.io).
# Update procedure: docs/security/supply-chain.md.
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY packages ./packages
COPY services/api ./services/api
COPY services/worker ./services/worker
RUN pip install --no-cache-dir --prefix=/install ".[api,postgres]"

FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e
COPY --from=build /install /usr/local
COPY migrations /app/migrations
ENV AFTERLOCK_MIGRATIONS_DIR=/app/migrations
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin afterlock
USER 10001
EXPOSE 8080
CMD ["python", "-m", "uvicorn", "afterlock_api.app:app", "--host", "0.0.0.0", "--port", "8080"]
