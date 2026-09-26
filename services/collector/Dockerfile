# AFTERLOCK collector image: static binary on distroless, non-root.
# Build from this directory:  docker build -t afterlock-collector services/collector
# Base images are pinned by digest (resolved 2026-09-26); refresh deliberately.
FROM golang:1.24.13-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-mod=readonly GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
RUN go build -trimpath -ldflags="-s -w" -o /out/afterlock-collector ./cmd/afterlock-collector

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/afterlock-collector /afterlock-collector
# 65532 is the distroless "nonroot" user. Run with a read-only root filesystem
# and a writable volume for --spool and --out.
USER 65532:65532
ENTRYPOINT ["/afterlock-collector"]
