"""API contract and authorization tests (in-process, no network)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from afterlock.evidence import ReplayBundle
from afterlock_api.app import create_app

from conftest import REPLAY

ANALYST = "analyst-token-0123456789"
VIEWER = "viewer-token-0123456789"
OTHER = "other-cluster-analyst-0123"
LABOP = "lab-operator-token-0123456"


@pytest.fixture
def client() -> TestClient:
    spec = f"{ANALYST}:analyst:lab-local,{VIEWER}:viewer:lab-local,{OTHER}:analyst:other,{LABOP}:lab-operator:lab-local"
    return TestClient(create_app(spec))


def h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def inline(name: str) -> dict[str, Any]:
    b = ReplayBundle.load(REPLAY / name)
    return {"case_id": name, "cluster_id": b.manifest["cluster_id"], "inventory": b.inventory, "case": b.case,
            "events": [json.loads(line) for line in b.event_lines]}


def test_health_is_public(client: TestClient) -> None:
    assert client.get("/v1/health").json()["status"] == "ok"


def test_authentication_required(client: TestClient) -> None:
    assert client.get("/v1/cases").status_code == 401
    assert client.get("/v1/cases", headers=h("wrong-token-xxxxxxxxxxxx")).status_code == 401


def test_full_flow_and_role_separation(client: TestClient) -> None:
    assert client.post("/v1/cases", json=inline("residual-token"), headers=h(VIEWER)).status_code == 403
    assert client.post("/v1/cases", json=inline("residual-token"), headers=h(LABOP)).status_code == 403
    r = client.post("/v1/cases", json=inline("residual-token"), headers=h(ANALYST))
    assert r.status_code == 201, r.text
    assert client.post("/v1/cases", json=inline("residual-token"), headers=h(ANALYST)).status_code == 409

    assert client.get("/v1/cases", headers=h(VIEWER)).json()["items"] == ["residual-token"]
    assert client.post("/v1/cases/residual-token/analyses", json={}, headers=h(VIEWER)).status_code == 403
    r = client.post("/v1/cases/residual-token/analyses", json={}, headers=h(ANALYST))
    assert r.status_code == 201
    aid = r.json()["id"]
    assert r.json()["result"]["conclusion"]["model"] == "residual_path"
    assert "Containment FAILS" in client.get(f"/v1/analyses/{aid}/explanation", headers=h(VIEWER)).text

    remediation = inline("targeted-containment")["case"]["remediation"]
    r = client.post("/v1/cases/residual-token/analyses", json={"remediation": remediation}, headers=h(ANALYST))
    assert r.json()["result"]["conclusion"]["model"] == "contained_within_scope"

    v = client.post(f"/v1/analyses/{aid}/verification", headers=h(ANALYST)).json()
    assert all(w["valid"] for w in v["witnesses"].values())


def test_cross_cluster_access_is_indistinguishable_from_missing(client: TestClient) -> None:
    client.post("/v1/cases", json=inline("residual-token"), headers=h(ANALYST))
    aid = client.post("/v1/cases/residual-token/analyses", json={}, headers=h(ANALYST)).json()["id"]
    assert client.get("/v1/cases/residual-token", headers=h(OTHER)).status_code == 404
    assert client.get(f"/v1/analyses/{aid}", headers=h(OTHER)).status_code == 404
    assert client.get("/v1/cases/nope", headers=h(OTHER)).status_code == 404
    assert client.get("/v1/cases", headers=h(OTHER)).json()["items"] == []
    assert client.post("/v1/cases", json=inline("residual-token") | {"case_id": "x"}, headers=h(OTHER)).status_code == 403


def test_invalid_inputs(client: TestClient) -> None:
    body = inline("residual-token")
    body["case_id"] = "../etc/passwd"
    assert client.post("/v1/cases", json=body, headers=h(ANALYST)).status_code == 422
    body = inline("residual-token") | {"unexpected": 1}
    assert client.post("/v1/cases", json=body, headers=h(ANALYST)).status_code == 422
    client.post("/v1/cases", json=inline("residual-token"), headers=h(ANALYST))
    r = client.post("/v1/cases/residual-token/analyses", json={"remediation": [{"kind": "exec", "cmd": "id"}]}, headers=h(ANALYST))
    assert r.status_code == 422 and r.json()["detail"]["conclusion"] == "invalid_input"
    assert client.get("/v1/cases?limit=0", headers=h(VIEWER)).status_code == 422


def test_body_limit(client: TestClient) -> None:
    r = client.post("/v1/cases", content=b"x", headers=h(ANALYST) | {"content-length": str(10**9), "content-type": "application/json"})
    assert r.status_code == 413


def test_api_never_mutates_clusters(client: TestClient) -> None:
    for token in (ANALYST, LABOP):
        assert client.post("/v1/lab/execute", headers=h(token)).status_code == 403


def test_token_configuration_validated() -> None:
    with pytest.raises(ValueError):
        create_app("short:analyst:x")
    with pytest.raises(ValueError):
        create_app("long-enough-token-000:root:x")
