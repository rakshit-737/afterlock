"""Versioned HTTP API over the AFTERLOCK domain packages.

Reasoning lives in ``afterlock``; this module only authenticates, authorizes,
validates request shape, and stores results. Every sensitive operation is
checked here, independently of any frontend.

Authentication: static bearer tokens configured via ``AFTERLOCK_API_TOKENS``
(``<token>:<role>:<cluster>[|<cluster>...]`` entries separated by commas).
Tokens are compared by SHA-256 digest in constant time and are never logged.
Optionally, OIDC bearer JWTs are validated natively (``afterlock_api.oidc``; configured by
``AFTERLOCK_OIDC_*``). See docs/deployment/authentication.md.

Resource bounds: request bodies are limited on the bytes actually received (chunked bodies
included), in-memory storage is capped, CPU-heavy synchronous endpoints and progress streams
have per-principal and global concurrency limits (429), and progress streams have a maximum
duration. OpenAPI/Swagger/ReDoc are off unless ``AFTERLOCK_API_DOCS`` enables them.

Storage: ``afterlock_api.storage``. In-memory per process by default; PostgreSQL when
``AFTERLOCK_DATABASE_URL`` is set. Synchronous endpoints compute in the request; the
``*-jobs`` endpoints enqueue leased jobs (202) executed by ``afterlock_worker`` (PostgreSQL)
or in-process after the response (in-memory).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.background import BackgroundTask
from starlette.types import ASGIApp, Message, Receive, Send
from starlette.types import Scope as ASGIScope

import afterlock_reference as reference
from afterlock import __version__
from afterlock.engine import MODE_FULL, MODES
from afterlock.evidence import BundleError, ReplayBundle, project
from afterlock.model import ModelError, parse_analysis_input
from afterlock.planner import PlannerConfig, plan
from afterlock.results import analyze, explain
from afterlock_api.oidc import OIDCConfig, OIDCError, OIDCValidator
from afterlock_api.storage import (
    TERMINAL,
    AmbiguousCase,
    MemoryStorage,
    Scope,
    Storage,
    StorageFull,
    build_manifest,
    env_int,
    from_env,
    scope_for,
)

MAX_BODY_BYTES = 4 * 1024 * 1024
ROLES = ("viewer", "analyst", "lab-operator")
DOCS_MODES = ("off", "authenticated", "public")
MAX_VERIFY_STATES = 50_000


@dataclass(frozen=True)
class Settings:
    """Operational limits. ``from_env`` reads ``AFTERLOCK_*``; tests construct it directly."""

    max_body_bytes: int = MAX_BODY_BYTES
    docs: str = "off"
    verify_max_states: int = MAX_VERIFY_STATES
    heavy_per_principal: int = 1  # concurrent verification/plan requests per principal
    heavy_total: int = 4
    sse_per_principal: int = 4
    sse_total: int = 64
    sse_max_seconds: float = 300.0
    sse_heartbeat_seconds: float = 15.0
    sse_poll_seconds: float = 0.5

    def __post_init__(self) -> None:
        if self.docs not in DOCS_MODES:
            raise ValueError(f"AFTERLOCK_API_DOCS must be one of {DOCS_MODES}")
        if not 1 <= self.verify_max_states <= MAX_VERIFY_STATES:
            raise ValueError(f"AFTERLOCK_VERIFY_MAX_STATES must be within 1..{MAX_VERIFY_STATES}")
        if not 0 < self.sse_max_seconds <= 3600:
            raise ValueError("AFTERLOCK_SSE_MAX_SECONDS must be within (0, 3600]")

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            docs=os.environ.get("AFTERLOCK_API_DOCS", "off") or "off",
            verify_max_states=env_int("AFTERLOCK_VERIFY_MAX_STATES", MAX_VERIFY_STATES),
            heavy_per_principal=env_int("AFTERLOCK_HEAVY_CONCURRENCY_PER_PRINCIPAL", 1),
            heavy_total=env_int("AFTERLOCK_HEAVY_CONCURRENCY_TOTAL", 4),
            sse_per_principal=env_int("AFTERLOCK_SSE_STREAMS_PER_PRINCIPAL", 4),
            sse_total=env_int("AFTERLOCK_SSE_STREAMS_TOTAL", 64),
            sse_max_seconds=float(env_int("AFTERLOCK_SSE_MAX_SECONDS", 300)),
        )


class BodyLimit:
    """Pure ASGI middleware bounding the request body by the bytes actually received.

    A declared ``Content-Length`` above the limit is refused up front; otherwise the body is
    read (chunked or not) up to the limit and replayed to the application. Anything larger
    gets 413 without the application ever seeing it.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def _reject(self, send: Send) -> None:
        await JSONResponse({"error": "request_too_large"}, status_code=413)({"type": "http"}, _no_receive, send)

    async def __call__(self, scope: ASGIScope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        length = dict(scope["headers"]).get(b"content-length")
        if length is not None and (not length.isdigit() or int(length) > self.max_bytes):
            await self._reject(send)
            return
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":  # client went away before sending the body
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > self.max_bytes:
                await self._reject(send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()  # afterwards only http.disconnect can arrive

        await self.app(scope, replay, send)


async def _no_receive() -> Message:  # pragma: no cover - JSONResponse never reads the body
    return {"type": "http.disconnect"}


class ConcurrencyLimiter:
    """Non-blocking per-principal and global slot counter; a full limiter answers 429."""

    def __init__(self, per_principal: int, total: int, what: str) -> None:
        self.per_principal, self.total, self.what = per_principal, total, what
        self._lock = threading.Lock()
        self._held: dict[str, int] = {}

    def acquire(self, name: str) -> None:
        with self._lock:
            if self._held.get(name, 0) >= self.per_principal or sum(self._held.values()) >= self.total:
                raise HTTPException(429, f"too many concurrent {self.what} requests", headers={"Retry-After": "5"})
            self._held[name] = self._held.get(name, 0) + 1

    def release(self, name: str) -> None:
        with self._lock:
            left = self._held.get(name, 0) - 1
            if left > 0:
                self._held[name] = left
            else:
                self._held.pop(name, None)

    @contextmanager
    def slot(self, name: str) -> Iterator[None]:
        self.acquire(name)
        try:
            yield
        finally:
            self.release(name)


@dataclass(frozen=True)
class Principal:
    name: str
    role: str
    clusters: frozenset[str]

    def may_read(self, cluster: str) -> bool:
        return cluster in self.clusters or "*" in self.clusters

    def may_analyze(self, cluster: str) -> bool:
        return self.role == "analyst" and self.may_read(cluster)

    @property
    def scope(self) -> Scope:
        return scope_for(self.clusters)


def _parse_tokens(spec: str) -> dict[bytes, Principal]:
    out: dict[bytes, Principal] = {}
    for i, entry in enumerate(e.strip() for e in spec.split(",") if e.strip()):
        parts = entry.split(":")
        if len(parts) != 3 or parts[1] not in ROLES or len(parts[0]) < 16:
            raise ValueError(f"AFTERLOCK_API_TOKENS entry {i} is malformed (token must be >= 16 chars)")
        out[hashlib.sha256(parts[0].encode()).digest()] = Principal(f"principal-{i}", parts[1], frozenset(parts[2].split("|")))
    return out


class InlineBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    cluster_id: str = Field(min_length=1, max_length=128)
    inventory: dict[str, Any]
    case: dict[str, Any]
    events: list[dict[str, Any]] = Field(default_factory=list, max_length=50_000)


class AnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    remediation: list[dict[str, Any]] | None = Field(default=None, max_length=32)
    mode: Literal["full", "snapshot_only", "history_without_lifecycle", "final_state_only"] = MODE_FULL


class PlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_length: int = Field(default=4, ge=1, le=5)
    max_evaluations: int = Field(default=2_000, ge=1, le=10_000)


class JobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_attempts: int = Field(default=3, ge=1, le=10)


class AnalysisJobRequest(AnalysisRequest, JobRequest):
    pass


class PlanJobRequest(PlanRequest, JobRequest):
    pass


def create_app(
    token_spec: str | None = None,
    storage: Storage | None = None,
    run_jobs_inprocess: bool | None = None,
    *,
    settings: Settings | None = None,
    oidc: OIDCValidator | None = None,
) -> FastAPI:
    tokens = _parse_tokens(token_spec if token_spec is not None else os.environ.get("AFTERLOCK_API_TOKENS", ""))
    cfg = settings if settings is not None else Settings.from_env()
    if oidc is None and token_spec is None:
        oidc_cfg = OIDCConfig.from_env()
        oidc = OIDCValidator(oidc_cfg) if oidc_cfg is not None else None
    store: Storage = storage if storage is not None else from_env()
    # Without PostgreSQL there is no separate worker; run queued jobs in-process after the response.
    inprocess_worker = isinstance(store, MemoryStorage) if run_jobs_inprocess is None else run_jobs_inprocess
    public_docs = cfg.docs == "public"
    app = FastAPI(title="AFTERLOCK API", version=__version__, docs_url="/v1/docs" if public_docs else None,
                  redoc_url="/v1/redoc" if public_docs else None, openapi_url="/v1/openapi.json" if public_docs else None)
    app.add_middleware(BodyLimit, max_bytes=cfg.max_body_bytes)
    heavy = ConcurrencyLimiter(cfg.heavy_per_principal, cfg.heavy_total, "verification/planning")
    streams = ConcurrencyLimiter(cfg.sse_per_principal, cfg.sse_total, "progress stream")
    app.state.limiters = {"heavy": heavy, "streams": streams}  # introspection for operators and tests

    @app.exception_handler(StorageFull)
    async def storage_full(request: Request, exc: StorageFull) -> JSONResponse:
        return JSONResponse({"error": "storage_full", "detail": str(exc)}, status_code=507)

    @app.exception_handler(AmbiguousCase)
    async def ambiguous(request: Request, exc: AmbiguousCase) -> JSONResponse:
        # Only raised when the caller can see the case in several clusters: nothing leaks.
        return JSONResponse({"error": "ambiguous_case", "detail": str(exc)}, status_code=409)

    def principal(request: Request) -> Principal:
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
        token = header[7:]
        presented = hashlib.sha256(token.encode()).digest()
        for known, p in tokens.items():
            if hmac.compare_digest(presented, known):
                return p
        if oidc is not None:
            try:
                ident = oidc.validate(token)
            except OIDCError:
                pass  # reason deliberately not returned to the client
            else:
                return Principal(f"oidc:{ident.subject[:200]}", ident.role, ident.clusters)
        raise HTTPException(401, "invalid token", headers={"WWW-Authenticate": "Bearer"})

    if cfg.docs == "authenticated":
        @app.get("/v1/openapi.json", include_in_schema=False)
        def openapi_schema(p: Principal = Depends(principal)) -> dict[str, Any]:
            return app.openapi()

    def get_case(case_id: str, p: Principal, cluster_id: str | None = None) -> dict[str, Any]:
        # Scoped lookup: missing and unauthorized give the same 404, so cluster membership does not leak.
        c = store.get_case(case_id, p.scope, cluster_id)
        if c is None:
            raise HTTPException(404, "case not found")
        return c

    def get_analysis(analysis_id: str, p: Principal) -> dict[str, Any]:
        a = store.get_analysis(analysis_id, p.scope)
        if a is None:
            raise HTTPException(404, "analysis not found")
        return a

    @app.get("/v1/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "storage": store.kind}

    @app.post("/v1/cases", status_code=201)
    def create_case(body: InlineBundle, p: Principal = Depends(principal)) -> dict[str, Any]:
        if not p.may_analyze(body.cluster_id):
            raise HTTPException(403, "analyst role for this cluster required")
        bundle = ReplayBundle(
            manifest={"schema": "afterlock.replay/1", "case_id": body.case_id, "cluster_id": body.cluster_id},
            inventory=body.inventory,
            case=body.case,
            event_lines=[json.dumps(e) for e in body.events],
        )
        try:
            raw, diag = project(bundle)
        except (BundleError, ModelError) as exc:
            raise HTTPException(422, {"conclusion": "invalid_input", "error": str(exc)}) from exc
        # Case ids are unique per cluster: 409 only for a duplicate in this (authorized) cluster.
        if not store.create_case({"case_id": body.case_id, "cluster_id": body.cluster_id, "input": raw, "diagnostics": diag}):
            raise HTTPException(409, "case already exists in this cluster")
        return {"case_id": body.case_id, "diagnostics": diag, "coverage_gaps": raw["coverage_gaps"]}

    @app.get("/v1/cases")
    def list_cases(limit: int = 50, offset: int = 0, p: Principal = Depends(principal)) -> dict[str, Any]:
        if not (1 <= limit <= 200) or offset < 0:
            raise HTTPException(422, "invalid pagination")
        visible = store.list_cases(p.scope)[offset : offset + limit]
        return {"items": [c["case_id"] for c in visible], "entries": visible, "total": len(store.list_case_ids(p.scope))}

    @app.get("/v1/cases/{case_id}")
    def read_case(case_id: str, cluster_id: str | None = None, p: Principal = Depends(principal)) -> dict[str, Any]:
        c = get_case(case_id, p, cluster_id)
        return {"case_id": case_id, "cluster_id": c["cluster_id"], "input": c["input"], "diagnostics": c["diagnostics"]}

    def analysis_input(case_id: str, body: AnalysisRequest, p: Principal, cluster_id: str | None) -> tuple[dict[str, Any], dict[str, Any]]:
        c = get_case(case_id, p, cluster_id)
        if not p.may_analyze(c["cluster_id"]):
            raise HTTPException(403, "analyst role for this cluster required")
        raw = dict(c["input"])
        if body.remediation is not None:
            raw["remediation"] = body.remediation
        try:
            parse_analysis_input(raw)
        except ModelError as exc:
            raise HTTPException(422, {"conclusion": "invalid_input", "error": str(exc)}) from exc
        if body.mode not in MODES:  # explicit check: asserts are stripped under python -O
            raise HTTPException(422, "unsupported analysis mode")
        return c, raw

    @app.post("/v1/cases/{case_id}/analyses", status_code=201)
    def run_analysis(case_id: str, body: AnalysisRequest, cluster_id: str | None = None, p: Principal = Depends(principal)) -> dict[str, Any]:
        c, raw = analysis_input(case_id, body, p, cluster_id)
        result = analyze(parse_analysis_input(raw), body.mode)
        manifest = build_manifest(c["cluster_id"], case_id, "analysis", {"input": raw, "mode": body.mode})
        analysis_id = store.record_analysis(manifest, result)
        return {"id": analysis_id, "result": result}

    @app.get("/v1/analyses/{analysis_id}")
    def read_analysis(analysis_id: str, p: Principal = Depends(principal)) -> dict[str, Any]:
        a = get_analysis(analysis_id, p)
        return {"id": analysis_id, "case_id": a["case_id"], "result": a["result"]}

    @app.get("/v1/analyses/{analysis_id}/explanation", response_class=PlainTextResponse)
    def read_explanation(analysis_id: str, p: Principal = Depends(principal)) -> str:
        return explain(get_analysis(analysis_id, p)["result"])

    @app.post("/v1/analyses/{analysis_id}/verification")
    def verify(analysis_id: str, p: Principal = Depends(principal)) -> dict[str, Any]:
        a = get_analysis(analysis_id, p)
        if not p.may_analyze(a["cluster_id"]):
            raise HTTPException(403, "analyst role for this cluster required")
        with heavy.slot(p.name):
            return {
                "witnesses": reference.verify_witnesses(a["input"], a["result"]),
                "reference_exploration": reference.explore(a["input"], reference.ReferenceLimits(max_states=cfg.verify_max_states)),
            }

    @app.post("/v1/cases/{case_id}/plans")
    def make_plan(case_id: str, body: PlanRequest, cluster_id: str | None = None, p: Principal = Depends(principal)) -> dict[str, Any]:
        c = get_case(case_id, p, cluster_id)
        if not p.may_analyze(c["cluster_id"]):
            raise HTTPException(403, "analyst role for this cluster required")
        try:
            inp = parse_analysis_input(c["input"])
        except ModelError as exc:
            raise HTTPException(422, {"conclusion": "invalid_input", "error": str(exc)}) from exc
        with heavy.slot(p.name):
            return plan(inp, PlannerConfig(max_length=body.max_length, max_evaluations=body.max_evaluations))

    # Asynchronous jobs -----------------------------------------------------------------
    def enqueue(manifest: dict[str, Any], p: Principal, max_attempts: int, background: BackgroundTasks) -> JSONResponse:
        job = store.enqueue(manifest, created_by=p.name, max_attempts=max_attempts)
        if inprocess_worker:
            from afterlock_worker.runner import drain

            background.add_task(drain, store, "api-inprocess")
        return JSONResponse({"job_id": job["job_id"], "state": job["state"], "manifest_id": job["manifest_id"]}, status_code=202,
                            headers={"Location": f"/v1/jobs/{job['job_id']}"})

    @app.post("/v1/cases/{case_id}/analysis-jobs", status_code=202)
    def create_analysis_job(case_id: str, body: AnalysisJobRequest, background: BackgroundTasks, cluster_id: str | None = None,
                            p: Principal = Depends(principal)) -> JSONResponse:
        c, raw = analysis_input(case_id, body, p, cluster_id)
        return enqueue(build_manifest(c["cluster_id"], case_id, "analysis", {"input": raw, "mode": body.mode}), p, body.max_attempts, background)

    @app.post("/v1/cases/{case_id}/plan-jobs", status_code=202)
    def create_plan_job(case_id: str, body: PlanJobRequest, background: BackgroundTasks, cluster_id: str | None = None,
                        p: Principal = Depends(principal)) -> JSONResponse:
        c = get_case(case_id, p, cluster_id)
        if not p.may_analyze(c["cluster_id"]):
            raise HTTPException(403, "analyst role for this cluster required")
        payload = {"input": c["input"], "max_length": body.max_length, "max_evaluations": body.max_evaluations}
        return enqueue(build_manifest(c["cluster_id"], case_id, "plan", payload), p, body.max_attempts, background)

    @app.post("/v1/analyses/{analysis_id}/verification-jobs", status_code=202)
    def create_verification_job(analysis_id: str, background: BackgroundTasks, body: JobRequest | None = None,
                                p: Principal = Depends(principal)) -> JSONResponse:
        a = get_analysis(analysis_id, p)
        if not p.may_analyze(a["cluster_id"]):
            raise HTTPException(403, "analyst role for this cluster required")
        payload = {"input": a["input"], "result": a["result"], "analysis_id": analysis_id}
        attempts = body.max_attempts if body is not None else 3
        return enqueue(build_manifest(a["cluster_id"], a["case_id"], "verification", payload), p, attempts, background)

    @app.get("/v1/jobs/{job_id}")
    def read_job(job_id: str, p: Principal = Depends(principal)) -> dict[str, Any]:
        job = store.get_job(job_id, p.scope)
        if job is None:
            raise HTTPException(404, "job not found")
        return job

    @app.get("/v1/jobs/{job_id}/events", response_class=StreamingResponse)
    async def job_events(job_id: str, request: Request, p: Principal = Depends(principal)) -> StreamingResponse:
        """Server-sent events: one ``state`` event per observed job transition.

        Every event carries the content-addressed ``manifest_id`` (input hash + engine version),
        so a client never mixes progress for one analysis version with results of another.
        Poll-based for both backends; heartbeat comments keep proxies from idling the stream
        out; the stream ends at a terminal state or after ``sse_max_seconds``.
        """
        first = await run_in_threadpool(store.get_job, job_id, p.scope)
        if first is None:
            raise HTTPException(404, "job not found")
        streams.acquire(p.name)
        released = False

        def release() -> None:  # idempotent: runs from the generator and again as a background task
            nonlocal released
            if not released:
                released = True
                streams.release(p.name)

        # The background task covers a client that disconnects before the generator starts.
        return StreamingResponse(_events(first, request, p, release), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
                                 background=BackgroundTask(release))

    async def _events(job: dict[str, Any], request: Request, p: Principal, release: Callable[[], None]) -> AsyncIterator[str]:
        try:
            start = last_beat = time.monotonic()
            seq, last = 0, None
            yield f"retry: {int(cfg.sse_poll_seconds * 1000) + 1000}\n\n"
            while True:
                key = (job["state"], job["attempts"], job["cancel_requested"], job["result_id"])
                if key != last:
                    seq, last = seq + 1, key
                    event = {k: job[k] for k in ("job_id", "cluster_id", "kind", "manifest_id", "state", "attempts",
                                                  "max_attempts", "cancel_requested", "last_error", "result_id")}
                    event["seq"] = seq
                    yield f"id: {seq}\nevent: state\ndata: {json.dumps(event, sort_keys=True)}\n\n"
                    if job["state"] in TERMINAL:
                        return
                now = time.monotonic()
                if now - start >= cfg.sse_max_seconds:
                    yield f"event: timeout\ndata: {json.dumps({'job_id': job['job_id'], 'seq': seq})}\n\n"
                    return
                if now - last_beat >= cfg.sse_heartbeat_seconds:
                    last_beat = now
                    yield ": heartbeat\n\n"
                if await request.is_disconnected():
                    return
                await asyncio.sleep(cfg.sse_poll_seconds)
                nxt = await run_in_threadpool(store.get_job, job["job_id"], p.scope)
                if nxt is None:  # cannot happen today (jobs are never deleted); end rather than guess
                    return
                job = nxt
        finally:
            release()

    @app.post("/v1/jobs/{job_id}/cancel", status_code=202)
    def cancel_job(job_id: str, p: Principal = Depends(principal)) -> dict[str, Any]:
        job = store.get_job(job_id, p.scope)
        if job is None:
            raise HTTPException(404, "job not found")
        if not p.may_analyze(job["cluster_id"]):
            raise HTTPException(403, "analyst role for this cluster required")
        if job["state"] in ("succeeded", "failed", "cancelled"):
            raise HTTPException(409, f"job already {job['state']}")
        out = store.cancel_job(job_id, p.scope)
        assert out is not None
        return out

    @app.api_route("/v1/lab/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    def lab(path: str, p: Principal = Depends(principal)) -> None:
        # The lab executor is a separate, out-of-process supervisor. The API never mutates clusters.
        raise HTTPException(403, "the API cannot perform lab or cluster mutations")

    return app


app = create_app() if os.environ.get("AFTERLOCK_API_TOKENS") or os.environ.get("AFTERLOCK_OIDC_ISSUER") else None
