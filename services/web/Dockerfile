# AFTERLOCK investigation UI: static files served by unprivileged nginx.
# Build context: services/web. Base images pinned by multi-arch index digest
# (resolved 2026-09-26 from registry-1.docker.io); update procedure: docs/security/supply-chain.md.
# Runtime expects a read-only root filesystem with tmpfs on /tmp (pid file) and
# /var/cache/nginx (client/proxy temp dirs); see compose.yaml.
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY index.html tsconfig.json vite.config.ts ./
COPY scripts ./scripts
COPY src ./src
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
USER 101
EXPOSE 8080
