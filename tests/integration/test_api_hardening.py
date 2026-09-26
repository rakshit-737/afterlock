"""Resource bounds and disclosure fixes from docs/security/review-2026-09-26.md (in-process, no network)."""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from afterlock_api.app import Settings, create_app
from afterlock_api.storage import MemoryStorage

from integration.test_api import ANALYST, OTHER, VIEWER, h, inline

MULTI = "multi-cluster-analyst-0123"
SPEC = f"{ANALYST}:analyst:lab-local,{VIEWER}:viewer:lab-local,{OTHER}:analyst:other,{MULTI}:analyst:lab-local|other"


def make(settings: Settings | None = None, storage: MemoryStorage | None = None) -> TestClient:
    return TestClient(create_app(SPEC, storage=storage or MemoryStorage(), run_jobs_inprocess=False, settings=settings or Settings()))


# Finding 3: body limit on bytes actually received -------------------------------------
def _chunks(total: int, size: int = 64 * 1024) -> Iterator[bytes]:
    sent = 0
    while sent < total:
        n = min(size, total - sent)
        sent += n
        yield b" " * n


def test_chunked_body_over_limit_is_refused() -> None:
    client = make(Settings(max_body_bytes=1024))
    # An iterator body is sent with Transfer-Encoding: chunked and no Content-Length.
    r = client.post("/v1/cases", content=_chunks(10_000, 512), headers=h(ANALYST) | {"content-type": "application/json"})
    assert r.status_code == 413 and r.json() == {"error": "request_too_large"}


def test_chunked_body_under_limit_is_processed() -> None:
    client = make()
    body = json.dumps(inline("residual-token")).encode()
    r = client.post("/v1/cases", content=iter([body[:1000], body[1000:]]), headers=h(ANALYST) | {"content-type": "application/json"})
    assert r.status_code == 201, r.text


def test_declared_length_over_limit_is_refused_and_malformed_length_too() -> None:
    client = make(Settings(max_body_bytes=1024))
    assert client.post("/v1/cases", content=b"x" * 2048, headers=h(ANALYST)).status_code == 413
    r = client.post("/v1/cases", content=b"{}", headers=h(ANALYST) | {"content-length": "abc"})
    assert r.status_code in (400, 413)


# Finding 4: bounded in-memory store ---------------------------------------------------
def test_memory_store_full_returns_507() -> None:
    client = make(storage=MemoryStorage(max_cases=1, max_results=1, max_jobs=1))
    assert client.post("/v1/cases", json=inline("residual-token"), headers=h(ANALYST)).status_code == 201
    r = client.post("/v1/cases", json=inline("targeted-containment"), headers=h(ANALYST))
    assert r.status_code == 507 and r.json()["error"] == "storage_full"
    assert client.post("/v1/cases/residual-token/analyses", json={}, headers=h(ANALYST)).status_code == 201
    assert client.post("/v1/cases/residual-token/analyses", json={}, headers=h(ANALYST)).status_code == 507
    assert client.post("/v1/cases/residual-token/analysis-jobs", json={}, headers=h(ANALYST)).status_code == 202
    assert client.post("/v1/cases/residual-token/analysis-jobs", json={}, headers=h(ANALYST)).status_code == 507


# Finding 5: verification CPU bound ----------------------------------------------------
def test_verification_concurrency_limit_per_principal() -> None:
    client = make()
    client.post("/v1/cases", json=inline("residual-token"), headers=h(ANALYST))
    aid = client.post("/v1/cases/residual-token/analyses", json={}, headers=h(ANALYST)).json()["id"]
    heavy = client.app.state.limiters["heavy"]
    heavy.acquire("principal-0")  # ANALYST is principal-0; simulate an in-flight verification
    try:
        r = client.post(f"/v1/analyses/{aid}/verification", headers=h(ANALYST))
        assert r.status_code == 429 and r.headers["retry-after"] == "5"
        assert client.post("/v1/cases/residual-token/plans", json={"max_length": 1, "max_evaluations": 10}, headers=h(ANALYST)).status_code == 429
        # Another principal still has its own slot.
        assert client.post(f"/v1/analyses/{aid}/verification", headers=h(MULTI)).status_code == 200
    finally:
        heavy.release("principal-0")
    assert client.post(f"/v1/analyses/{aid}/verification", headers=h(ANALYST)).status_code == 200


def test_verification_global_limit_and_state_cap() -> None:
    client = make(Settings(heavy_per_principal=5, heavy_total=1, verify_max_states=10))
    client.post("/v1/cases", json=inline("residual-token"), headers=h(ANALYST))
    aid = client.post("/v1/cases/residual-token/analyses", json={}, headers=h(ANALYST)).json()["id"]
    heavy = client.app.state.limiters["heavy"]
    heavy.acquire("someone-else")
    try:
        assert client.post(f"/v1/analyses/{aid}/verification", headers=h(ANALYST)).status_code == 429
    finally:
        heavy.release("someone-else")
    r = client.post(f"/v1/analyses/{aid}/verification", headers=h(ANALYST)).json()
    for view in r["reference_exploration"]["views"].values():
        # The cap is honoured and reported as incomplete, never as containment.
        assert view["states"] <= 10 and view["complete"] is False
    with pytest.raises(ValueError):
        Settings(verify_max_states=50_001)


# Finding 6: API docs ------------------------------------------------------------------
@pytest.mark.parametrize("path", ["/v1/docs", "/v1/openapi.json", "/v1/redoc", "/docs", "/redoc", "/openapi.json"])
def test_docs_disabled_by_default(path: str) -> None:
    assert make().get(path, headers=h(VIEWER)).status_code == 404


def test_docs_authenticated_mode_serves_schema_only_with_token() -> None:
    client = make(Settings(docs="authenticated"))
    assert client.get("/v1/openapi.json").status_code == 401
    r = client.get("/v1/openapi.json", headers=h(VIEWER))
    assert r.status_code == 200 and "/v1/jobs/{job_id}/events" in r.json()["paths"]
    assert client.get("/v1/docs", headers=h(VIEWER)).status_code == 404


def test_docs_public_mode_is_explicit() -> None:
    client = make(Settings(docs="public"))
    assert client.get("/v1/openapi.json").status_code == 200
    assert client.get("/v1/docs").status_code == 200
    assert client.get("/v1/redoc").status_code == 200
    with pytest.raises(ValueError):
        Settings(docs="yes")


# case_id uniqueness per cluster: 409 no longer reveals other clusters' cases ------------
def test_duplicate_case_id_in_other_cluster_is_not_a_conflict() -> None:
    client = make()
    assert client.post("/v1/cases", json=inline("residual-token"), headers=h(ANALYST)).status_code == 201
    other = inline("residual-token") | {"cluster_id": "other"}
    assert client.post("/v1/cases", json=other, headers=h(OTHER)).status_code == 201  # was 409: leaked existence
    assert client.post("/v1/cases", json=other, headers=h(OTHER)).status_code == 409  # same cluster: real conflict
    assert client.get("/v1/cases/residual-token", headers=h(OTHER)).json()["cluster_id"] == "other"
    assert client.get("/v1/cases/residual-token", headers=h(ANALYST)).json()["cluster_id"] == "lab-local"
    # A caller who can see both must disambiguate; this reveals only clusters it may read.
    r = client.get("/v1/cases/residual-token", headers=h(MULTI))
    assert r.status_code == 409 and r.json()["error"] == "ambiguous_case"
    assert client.get("/v1/cases/residual-token?cluster_id=other", headers=h(MULTI)).json()["cluster_id"] == "other"
    assert client.get("/v1/cases/residual-token?cluster_id=other", headers=h(ANALYST)).status_code == 404
    listing = client.get("/v1/cases", headers=h(MULTI)).json()
    assert listing["total"] == 2 and listing["entries"] == [{"case_id": "residual-token", "cluster_id": "lab-local"},
                                                            {"case_id": "residual-token", "cluster_id": "other"}]
    r = client.post("/v1/cases/residual-token/analyses?cluster_id=other", json={}, headers=h(MULTI))
    assert r.status_code == 201
    assert client.get(f"/v1/analyses/{r.json()['id']}", headers=h(ANALYST)).status_code == 404
