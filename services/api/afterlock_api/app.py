"""Versioned HTTP API over the AFTERLOCK domain packages.

Reasoning lives in ``afterlock``; this module only authenticates, authorizes,
validates request shape, and stores results. Every sensitive operation is
checked here, independently of any frontend.

Authentication: static bearer tokens configured via ``AFTERLOCK_API_TOKENS``
(``<token>:<role>:<cluster>[|<cluster>...]`` entries separated by commas).
Tokens are compared by SHA-256 digest in constant time and are never logged.
This is local bootstrap authentication; shared deployments should front the
API with OIDC (docs/deployment/authentication.md).

Storage: in-memory, per process. PostgreSQL persistence is a documented,
unimplemented milestone.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import os
import threading
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

import afterlock_reference as reference
from afterlock import __version__
from afterlock.engine import MODE_FULL, MODES
from afterlock.evidence import BundleError, ReplayBundle, project
from afterlock.model import ModelError, parse_analysis_input
from afterlock.planner import PlannerConfig, plan
from afterlock.results import analyze, explain

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


class Store:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.cases: dict[str, dict[str, Any]] = {}
        self.analyses: dict[str, dict[str, Any]] = {}
        self.seq = itertools.count(1)


def create_app(token_spec: str | None = None) -> FastAPI:
    tokens = _parse_tokens(token_spec if token_spec is not None else os.environ.get("AFTERLOCK_API_TOKENS", ""))
    store = Store()
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
        c = store.cases.get(case_id)
        # Same response for missing and unauthorized, so cluster membership does not leak.
        if c is None or not p.may_read(c["cluster_id"]):
            raise HTTPException(404, "case not found")
        return c

    def get_analysis(analysis_id: str, p: Principal) -> dict[str, Any]:
        a = store.analyses.get(analysis_id)
        if a is None or not p.may_read(a["cluster_id"]):
            raise HTTPException(404, "analysis not found")
        return a

    @app.get("/v1/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "storage": "in-memory"}

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
        with store.lock:
            if body.case_id in store.cases:
                raise HTTPException(409, "case already exists")
            store.cases[body.case_id] = {"case_id": body.case_id, "cluster_id": body.cluster_id, "input": raw, "diagnostics": diag}
        return {"case_id": body.case_id, "diagnostics": diag, "coverage_gaps": raw["coverage_gaps"]}

    @app.get("/v1/cases")
    def list_cases(limit: int = 50, offset: int = 0, p: Principal = Depends(principal)) -> dict[str, Any]:
        if not (1 <= limit <= 200) or offset < 0:
            raise HTTPException(422, "invalid pagination")
        visible = sorted(c["case_id"] for c in store.cases.values() if p.may_read(c["cluster_id"]))
        return {"items": visible[offset : offset + limit], "total": len(visible)}

    @app.get("/v1/cases/{case_id}")
    def read_case(case_id: str, p: Principal = Depends(principal)) -> dict[str, Any]:
        c = get_case(case_id, p)
        return {"case_id": case_id, "cluster_id": c["cluster_id"], "input": c["input"], "diagnostics": c["diagnostics"]}

    @app.post("/v1/cases/{case_id}/analyses", status_code=201)
    def run_analysis(case_id: str, body: AnalysisRequest, p: Principal = Depends(principal)) -> dict[str, Any]:
        c = get_case(case_id, p)
        if not p.may_analyze(c["cluster_id"]):
            raise HTTPException(403, "analyst role for this cluster required")
        raw = dict(c["input"])
        if body.remediation is not None:
            raw["remediation"] = body.remediation
        try:
            inp = parse_analysis_input(raw)
        except ModelError as exc:
            raise HTTPException(422, {"conclusion": "invalid_input", "error": str(exc)}) from exc
        assert body.mode in MODES
        result = analyze(inp, body.mode)
        analysis_id = f"an-{next(store.seq):06d}"
        with store.lock:
            store.analyses[analysis_id] = {"id": analysis_id, "case_id": case_id, "cluster_id": c["cluster_id"], "input": raw, "result": result}
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
        return plan(parse_analysis_input(c["input"]), PlannerConfig(max_length=body.max_length, max_evaluations=body.max_evaluations))

    @app.api_route("/v1/lab/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    def lab(path: str, p: Principal = Depends(principal)) -> None:
        # The lab executor is a separate, out-of-process supervisor. The API never mutates clusters.
        raise HTTPException(403, "the API cannot perform lab or cluster mutations")

    return app


app = create_app() if os.environ.get("AFTERLOCK_API_TOKENS") else None
