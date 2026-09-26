"""Versioned HTTP API over the AFTERLOCK domain packages.

Reasoning lives in ``afterlock``; this module only authenticates, authorizes,
validates request shape, and stores results. Every sensitive operation is
checked here, independently of any frontend.

Authentication: static bearer tokens configured via ``AFTERLOCK_API_TOKENS``
(``<token>:<role>:<cluster>[|<cluster>...]`` entries separated by commas).
Tokens are compared by SHA-256 digest in constant time and are never logged.
This is local bootstrap authentication; shared deployments should front the
API with OIDC (docs/deployment/authentication.md).

Storage: ``afterlock_api.storage``. In-memory per process by default; PostgreSQL when
``AFTERLOCK_DATABASE_URL`` is set. Synchronous endpoints compute in the request; the
``*-jobs`` endpoints enqueue leased jobs (202) executed by ``afterlock_worker`` (PostgreSQL)
or in-process after the response (in-memory).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

import afterlock_reference as reference
from afterlock import __version__
from afterlock.engine import MODE_FULL, MODES
from afterlock.evidence import BundleError, ReplayBundle, project
from afterlock.model import ModelError, parse_analysis_input
from afterlock.planner import PlannerConfig, plan
from afterlock.results import analyze, explain
from afterlock_api.storage import MemoryStorage, Scope, Storage, build_manifest, from_env, scope_for

MAX_BODY_BYTES = 4 * 1024 * 1024
ROLES = ("viewer", "analyst", "lab-operator")


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


def create_app(token_spec: str | None = None, storage: Storage | None = None, run_jobs_inprocess: bool | None = None) -> FastAPI:
    tokens = _parse_tokens(token_spec if token_spec is not None else os.environ.get("AFTERLOCK_API_TOKENS", ""))
    store: Storage = storage if storage is not None else from_env()
    # Without PostgreSQL there is no separate worker; run queued jobs in-process after the response.
    inprocess_worker = isinstance(store, MemoryStorage) if run_jobs_inprocess is None else run_jobs_inprocess
    app = FastAPI(title="AFTERLOCK API", version=__version__, docs_url="/v1/docs", openapi_url="/v1/openapi.json")

    @app.middleware("http")
    async def limit_body(request: Request, call_next: Any) -> Any:
        length = request.headers.get("content-length")
        if length is not None and (not length.isdigit() or int(length) > MAX_BODY_BYTES):
            return JSONResponse({"error": "request_too_large"}, status_code=413)
        return await call_next(request)

    def principal(request: Request) -> Principal:
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
        presented = hashlib.sha256(header[7:].encode()).digest()
        for known, p in tokens.items():
            if hmac.compare_digest(presented, known):
                return p
        raise HTTPException(401, "invalid token", headers={"WWW-Authenticate": "Bearer"})

    def get_case(case_id: str, p: Principal) -> dict[str, Any]:
        # Scoped lookup: missing and unauthorized give the same 404, so cluster membership does not leak.
        c = store.get_case(case_id, p.scope)
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
        if not store.create_case({"case_id": body.case_id, "cluster_id": body.cluster_id, "input": raw, "diagnostics": diag}):
            raise HTTPException(409, "case already exists")
        return {"case_id": body.case_id, "diagnostics": diag, "coverage_gaps": raw["coverage_gaps"]}

    @app.get("/v1/cases")
    def list_cases(limit: int = 50, offset: int = 0, p: Principal = Depends(principal)) -> dict[str, Any]:
        if not (1 <= limit <= 200) or offset < 0:
            raise HTTPException(422, "invalid pagination")
        visible = store.list_case_ids(p.scope)
        return {"items": visible[offset : offset + limit], "total": len(visible)}

    @app.get("/v1/cases/{case_id}")
    def read_case(case_id: str, p: Principal = Depends(principal)) -> dict[str, Any]:
        c = get_case(case_id, p)
        return {"case_id": case_id, "cluster_id": c["cluster_id"], "input": c["input"], "diagnostics": c["diagnostics"]}

    def analysis_input(case_id: str, body: AnalysisRequest, p: Principal) -> tuple[dict[str, Any], dict[str, Any]]:
        c = get_case(case_id, p)
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
    def run_analysis(case_id: str, body: AnalysisRequest, p: Principal = Depends(principal)) -> dict[str, Any]:
        c, raw = analysis_input(case_id, body, p)
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
        return {
            "witnesses": reference.verify_witnesses(a["input"], a["result"]),
            "reference_exploration": reference.explore(a["input"], reference.ReferenceLimits(max_states=50_000)),
        }

    @app.post("/v1/cases/{case_id}/plans")
    def make_plan(case_id: str, body: PlanRequest, p: Principal = Depends(principal)) -> dict[str, Any]:
        c = get_case(case_id, p)
        if not p.may_analyze(c["cluster_id"]):
            raise HTTPException(403, "analyst role for this cluster required")
        try:
            inp = parse_analysis_input(c["input"])
        except ModelError as exc:
            raise HTTPException(422, {"conclusion": "invalid_input", "error": str(exc)}) from exc
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
    def create_analysis_job(case_id: str, body: AnalysisJobRequest, background: BackgroundTasks, p: Principal = Depends(principal)) -> JSONResponse:
        c, raw = analysis_input(case_id, body, p)
        return enqueue(build_manifest(c["cluster_id"], case_id, "analysis", {"input": raw, "mode": body.mode}), p, body.max_attempts, background)

    @app.post("/v1/cases/{case_id}/plan-jobs", status_code=202)
    def create_plan_job(case_id: str, body: PlanJobRequest, background: BackgroundTasks, p: Principal = Depends(principal)) -> JSONResponse:
        c = get_case(case_id, p)
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


app = create_app() if os.environ.get("AFTERLOCK_API_TOKENS") else None
