"""Server-sent job progress events (``GET /v1/jobs/{id}/events``).

The in-memory backend always runs. The PostgreSQL variant runs only when
``AFTERLOCK_TEST_DATABASE_URL`` is set (otherwise SKIPPED as BLOCKED, not a pass).
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from afterlock_api.app import Settings, create_app
from afterlock_api.storage import MemoryStorage, PostgresStorage, Storage
from afterlock_worker.runner import process_one

from integration.test_api import ANALYST, OTHER, VIEWER, h, inline
from integration.test_storage_contract import PG_URL, _pg_migrate, _pg_schema, needs_pg

SPEC = f"{ANALYST}:analyst:lab-local,{VIEWER}:viewer:lab-local,{OTHER}:analyst:other"
FAST = Settings(sse_poll_seconds=0.02, sse_heartbeat_seconds=0.05, sse_max_seconds=5)


def parse(text: str) -> list[dict[str, Any]]:
    """Minimal SSE parser: returns events and comment frames in order."""
    out: list[dict[str, Any]] = []
    for frame in text.split("\n\n"):
        if not frame.strip():
            continue
        ev: dict[str, Any] = {}
        for line in frame.split("\n"):
            if line.startswith(":"):
                ev["comment"] = line[1:].strip()
            else:
                k, _, v = line.partition(": ")
                ev[k] = v
        if "data" in ev:
            ev["data"] = json.loads(ev["data"])
        out.append(ev)
    return out


@pytest.fixture(params=["memory", pytest.param("postgres", marks=needs_pg)])
def store(request: pytest.FixtureRequest) -> Iterator[Storage]:
    if request.param == "memory":
        yield MemoryStorage()
        return
    gen = _pg_schema()
    schema = next(gen)
    try:
        _pg_migrate(schema)
        assert PG_URL
        yield PostgresStorage(PG_URL, schema=schema)
    finally:
        gen.close()


def client_for(store: Storage, settings: Settings = FAST) -> TestClient:
    c = TestClient(create_app(SPEC, storage=store, run_jobs_inprocess=False, settings=settings))
    assert c.post("/v1/cases", json=inline("residual-token"), headers=h(ANALYST)).status_code == 201
    return c


def test_stream_reports_transitions_with_manifest_version(store: Storage) -> None:
    client = client_for(store)
    job = client.post("/v1/cases/residual-token/analysis-jobs", json={}, headers=h(ANALYST)).json()

    def work() -> None:
        time.sleep(0.2)
        process_one(store, "w1", lease_seconds=30, heartbeat_interval=5)

    t = threading.Thread(target=work)
    t.start()
    r = client.get(f"/v1/jobs/{job['job_id']}/events", headers=h(VIEWER))
    t.join()
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    assert r.headers["cache-control"] == "no-store"
    events = [e for e in parse(r.text) if e.get("event") == "state"]
    states = [e["data"]["state"] for e in events]
    assert states[0] == "queued" and states[-1] == "succeeded"
    assert [e["data"]["seq"] for e in events] == list(range(1, len(events) + 1))
    assert [int(e["id"]) for e in events] == list(range(1, len(events) + 1))
    # Every event names the same content-addressed manifest: no mixing analysis versions.
    assert {e["data"]["manifest_id"] for e in events} == {job["manifest_id"]}
    assert events[-1]["data"]["result_id"] and "result" not in events[-1]["data"]
    assert any(e.get("comment") == "heartbeat" for e in parse(r.text))


def test_stream_ends_on_terminal_state_immediately(store: Storage) -> None:
    client = client_for(store)
    jid = client.post("/v1/cases/residual-token/analysis-jobs", json={}, headers=h(ANALYST)).json()["job_id"]
    client.post(f"/v1/jobs/{jid}/cancel", headers=h(ANALYST))
    events = [e for e in parse(client.get(f"/v1/jobs/{jid}/events", headers=h(VIEWER)).text) if e.get("event")]
    assert [e["data"]["state"] for e in events] == ["cancelled"]


def test_stream_is_bounded_in_duration(store: Storage) -> None:
    client = client_for(store, Settings(sse_poll_seconds=0.02, sse_heartbeat_seconds=0.05, sse_max_seconds=0.3))
    jid = client.post("/v1/cases/residual-token/analysis-jobs", json={}, headers=h(ANALYST)).json()["job_id"]
    t0 = time.monotonic()
    events = parse(client.get(f"/v1/jobs/{jid}/events", headers=h(VIEWER)).text)
    assert time.monotonic() - t0 < 5
    assert events[-1]["event"] == "timeout" and events[-1]["data"]["job_id"] == jid
    assert [e["data"]["state"] for e in events if e.get("event") == "state"] == ["queued"]
    assert any(e.get("comment") == "heartbeat" for e in events)


def test_stream_is_cluster_scoped_and_authenticated(store: Storage) -> None:
    client = client_for(store)
    jid = client.post("/v1/cases/residual-token/analysis-jobs", json={}, headers=h(ANALYST)).json()["job_id"]
    assert client.get(f"/v1/jobs/{jid}/events").status_code == 401
    assert client.get(f"/v1/jobs/{jid}/events", headers=h(OTHER)).status_code == 404
    assert client.get("/v1/jobs/job-doesnotexist/events", headers=h(VIEWER)).status_code == 404


def test_stream_concurrency_limit_and_release() -> None:
    store = MemoryStorage()
    client = client_for(store, Settings(sse_per_principal=1, sse_poll_seconds=0.02, sse_max_seconds=0.2))
    jid = client.post("/v1/cases/residual-token/analysis-jobs", json={}, headers=h(ANALYST)).json()["job_id"]
    streams = client.app.state.limiters["streams"]
    streams.acquire("principal-1")  # VIEWER is principal-1: an open stream elsewhere
    try:
        assert client.get(f"/v1/jobs/{jid}/events", headers=h(VIEWER)).status_code == 429
    finally:
        streams.release("principal-1")
    assert client.get(f"/v1/jobs/{jid}/events", headers=h(VIEWER)).status_code == 200
    assert client.get(f"/v1/jobs/{jid}/events", headers=h(VIEWER)).status_code == 200  # slot was released
    assert streams._held == {}
