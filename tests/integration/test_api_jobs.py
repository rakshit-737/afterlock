"""Asynchronous job endpoints (in-memory backend, in-process worker, no network)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from afterlock_api.app import create_app
from afterlock_api.storage import MemoryStorage

from integration.test_api import ANALYST, LABOP, OTHER, VIEWER, h, inline

SPEC = f"{ANALYST}:analyst:lab-local,{VIEWER}:viewer:lab-local,{OTHER}:analyst:other,{LABOP}:lab-operator:lab-local"


def make(run_jobs: bool = True) -> tuple[TestClient, MemoryStorage]:
    store = MemoryStorage()
    client = TestClient(create_app(SPEC, storage=store, run_jobs_inprocess=run_jobs))
    assert client.post("/v1/cases", json=inline("residual-token"), headers=h(ANALYST)).status_code == 201
    return client, store


def test_health_reports_storage_kind() -> None:
    client, _ = make()
    assert client.get("/v1/health").json()["storage"] == "in-memory"


def test_analysis_job_lifecycle_and_scoping() -> None:
    client, _ = make()
    assert client.post("/v1/cases/residual-token/analysis-jobs", json={}, headers=h(VIEWER)).status_code == 403
    assert client.post("/v1/cases/residual-token/analysis-jobs", json={}, headers=h(OTHER)).status_code == 404
    r = client.post("/v1/cases/residual-token/analysis-jobs", json={"mode": "full"}, headers=h(ANALYST))
    assert r.status_code == 202, r.text
    jid = r.json()["job_id"]
    assert r.headers["location"] == f"/v1/jobs/{jid}"
    job = client.get(f"/v1/jobs/{jid}", headers=h(VIEWER)).json()
    assert job["state"] == "succeeded" and job["attempts"] == 1
    assert job["result"]["conclusion"]["model"] == "residual_path"
    assert client.get(f"/v1/jobs/{jid}", headers=h(OTHER)).status_code == 404
    assert client.get("/v1/jobs/job-doesnotexist", headers=h(VIEWER)).status_code == 404
    # Published analysis results are readable through the existing analysis endpoints.
    aid = job["result_id"]
    assert client.get(f"/v1/analyses/{aid}", headers=h(VIEWER)).json()["result"] == job["result"]
    assert client.post(f"/v1/jobs/{jid}/cancel", headers=h(ANALYST)).status_code == 409


def test_invalid_analysis_job_rejected_before_enqueue() -> None:
    client, store = make()
    r = client.post("/v1/cases/residual-token/analysis-jobs", json={"remediation": [{"kind": "exec", "cmd": "id"}]}, headers=h(ANALYST))
    assert r.status_code == 422 and r.json()["detail"]["conclusion"] == "invalid_input"
    assert store.jobs == {}
    assert client.post("/v1/cases/residual-token/analysis-jobs", json={"max_attempts": 0}, headers=h(ANALYST)).status_code == 422


def test_plan_and_verification_jobs() -> None:
    client, _ = make()
    r = client.post("/v1/cases/residual-token/plan-jobs", json={"max_length": 2, "max_evaluations": 200}, headers=h(ANALYST))
    assert r.status_code == 202
    plan_job = client.get(f"/v1/jobs/{r.json()['job_id']}", headers=h(ANALYST)).json()
    assert plan_job["state"] == "succeeded" and plan_job["kind"] == "plan" and plan_job["result_id"].startswith("pl-")

    aid = client.post("/v1/cases/residual-token/analyses", json={}, headers=h(ANALYST)).json()["id"]
    assert client.post(f"/v1/analyses/{aid}/verification-jobs", headers=h(OTHER)).status_code == 404
    r = client.post(f"/v1/analyses/{aid}/verification-jobs", headers=h(ANALYST))
    assert r.status_code == 202
    v = client.get(f"/v1/jobs/{r.json()['job_id']}", headers=h(ANALYST)).json()
    assert v["state"] == "succeeded" and all(w["valid"] for w in v["result"]["witnesses"].values())


def test_cancel_queued_job() -> None:
    client, _ = make(run_jobs=False)  # no in-process worker: the job stays queued
    jid = client.post("/v1/cases/residual-token/analysis-jobs", json={}, headers=h(ANALYST)).json()["job_id"]
    assert client.get(f"/v1/jobs/{jid}", headers=h(VIEWER)).json()["state"] == "queued"
    assert client.post(f"/v1/jobs/{jid}/cancel", headers=h(VIEWER)).status_code == 403
    assert client.post(f"/v1/jobs/{jid}/cancel", headers=h(OTHER)).status_code == 404
    r = client.post(f"/v1/jobs/{jid}/cancel", headers=h(ANALYST))
    assert r.status_code == 202 and r.json()["state"] == "cancelled"
