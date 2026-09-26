# AFTERLOCK API image. Unprivileged, read-only root filesystem expected at runtime.
# Pin the base image by digest before release (docs/engineering/status.md tracks this).
FROM python:3.11-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY packages ./packages
COPY services/api ./services/api
RUN pip install --no-cache-dir --prefix=/install ".[api]" "uvicorn==0.30.6"

FROM python:3.11-slim
COPY --from=build /install /usr/local
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin afterlock
USER 10001
EXPOSE 8080
CMD ["python", "-m", "uvicorn", "afterlock_api.app:app", "--host", "0.0.0.0", "--port", "8080"]
