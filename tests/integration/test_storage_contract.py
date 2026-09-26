"""Storage and job-execution contract, run against every backend.

The in-memory backend always runs. The PostgreSQL backend runs only when
``AFTERLOCK_TEST_DATABASE_URL`` points at a disposable database; otherwise those tests are
SKIPPED with reason "BLOCKED: no PostgreSQL (not a pass)". Each PostgreSQL test gets a fresh
schema that is dropped afterwards.
"""

from __future__ import annotations

import os
import secrets
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import pytest

from afterlock_api import migrate
from afterlock_api.storage import AmbiguousCase, MemoryStorage, PostgresStorage, Storage, StorageFull, build_manifest
from afterlock_worker.runner import PermanentJobError, process_one

from conftest import ROOT, raw_case

PG_URL = os.environ.get("AFTERLOCK_TEST_DATABASE_URL")
BLOCKED = "BLOCKED: no PostgreSQL (not a pass)"
needs_pg = pytest.mark.skipif(not PG_URL, reason=BLOCKED)
LEASE = 1.0  # seconds; PostgreSQL tests really wait for expiry


class FakeClock:
    def __init__(self) -> None:
        self.t = 1_000_000.0

    def __call__(self) -> float:
        return self.t


@dataclass
class Backend:
    storage: Any
    advance: Callable[[float], None]


def _pg_schema() -> Iterator[str]:
    import psycopg

    assert PG_URL
    schema = "t_" + secrets.token_hex(6)
    with psycopg.connect(PG_URL, autocommit=True) as c:
        c.execute(f"CREATE SCHEMA {schema}")  # generated identifier, not user input
    try:
        yield schema
    finally:
        with psycopg.connect(PG_URL, autocommit=True) as c:
            c.execute(f"DROP SCHEMA {schema} CASCADE")


def _pg_migrate(schema: str, target: int | None = None) -> list[int]:
    import psycopg

    assert PG_URL
    with psycopg.connect(PG_URL, options=f"-c search_path={schema}") as c:
        return migrate.apply(c, migrate.load(ROOT / "migrations"), target=target)


@pytest.fixture
def pg_schema() -> Iterator[str]:
    if not PG_URL:
        pytest.skip(BLOCKED)
    yield from _pg_schema()


@pytest.fixture(params=["memory", pytest.param("postgres", marks=needs_pg)])
def backend(request: pytest.FixtureRequest) -> Iterator[Backend]:
    if request.param == "memory":
        clock = FakeClock()

        def tick(s: float) -> None:
            clock.t += s

        yield Backend(MemoryStorage(clock=clock), tick)
        return
    gen = _pg_schema()
    schema = next(gen)
    try:
        _pg_migrate(schema)
        assert PG_URL
        yield Backend(PostgresStorage(PG_URL, schema=schema), time.sleep)
    finally:
        gen.close()


def fake_case(case_id: str = "case-a", cluster: str = "c1") -> dict[str, Any]:
    return {"case_id": case_id, "cluster_id": cluster, "input": {"profile": {"id": "k8s-1.31", "kubernetes_version": "1.31"}, "n": 1},
            "diagnostics": {"rejected": []}}


def job_for(s: Storage, case_id: str = "case-a", cluster: str = "c1", max_attempts: int = 3, mode: str = "full") -> dict[str, Any]:
    c = s.get_case(case_id, None) or fake_case(case_id, cluster)
    if s.get_case(case_id, None) is None:
        assert s.create_case(c)
    m = build_manifest(cluster, case_id, "analysis", {"input": c["input"], "mode": mode})
    return s.enqueue(m, created_by="principal-0", max_attempts=max_attempts)


def test_cases_are_immutable_and_cluster_scoped(backend: Backend) -> None:
    s = backend.storage
    assert s.create_case(fake_case())
    assert not s.create_case(fake_case())  # duplicate id refused
    assert s.get_case("case-a", frozenset({"c1"}))["input"]["n"] == 1
    assert s.get_case("case-a", frozenset({"c2"})) is None
    assert s.get_case("nope", None) is None
    assert s.list_case_ids(frozenset({"c2"})) == []
    assert s.list_case_ids(None) == ["case-a"]


def test_manifest_is_content_addressed() -> None:
    a = build_manifest("c1", "x", "analysis", {"input": {"k": 1}, "mode": "full"})
    b = build_manifest("c1", "x", "analysis", {"mode": "full", "input": {"k": 1}})
    c = build_manifest("c1", "x", "analysis", {"input": {"k": 2}, "mode": "full"})
    assert a["manifest_id"] == b["manifest_id"] != c["manifest_id"]
    assert a["semantic_profile"] == {} and a["engine_version"]


def test_claim_complete_and_scoped_read(backend: Backend) -> None:
    s = backend.storage
    job = job_for(s)
    assert job["state"] == "queued" and job["attempts"] == 0
    assert s.claim("w1", LEASE, frozenset({"c2"})) is None  # worker restricted to other cluster
    lease = s.claim("w1", LEASE)
    assert lease is not None and lease.job_id == job["job_id"] and lease.attempt == 1
    assert s.claim("w2", LEASE) is None  # leased jobs are not handed out twice
    assert s.mark_running(lease, LEASE) == "ok"
    assert s.get_job(job["job_id"], None)["state"] == "running"
    rid = s.complete(lease, {"conclusion": {"model": "x"}})
    assert rid is not None and rid.startswith("an-")
    done = s.get_job(job["job_id"], frozenset({"c1"}))
    assert done["state"] == "succeeded" and done["result_id"] == rid and done["result"] == {"conclusion": {"model": "x"}}
    assert s.get_job(job["job_id"], frozenset({"c2"})) is None


def test_worker_death_lease_expiry_rerun_and_duplicate_completion(backend: Backend) -> None:
    s = backend.storage
    job = job_for(s)
    dead = s.claim("worker-dead", LEASE)
    assert dead is not None and s.mark_running(dead, LEASE) == "ok"
    backend.advance(LEASE + 0.5)  # the worker dies: no heartbeat, lease expires
    alive = s.claim("worker-alive", LEASE)
    assert alive is not None and alive.job_id == job["job_id"] and alive.attempt == 2
    assert "expired" in (s.get_job(job["job_id"], None)["last_error"] or "")
    # The dead worker comes back: its lease is gone, so nothing it does can publish.
    assert s.heartbeat(dead, LEASE) == "lost"
    assert s.complete(dead, {"from": "dead"}) is None
    rid = s.complete(alive, {"from": "alive"})
    assert rid is not None
    assert s.complete(alive, {"from": "alive-again"}) is None  # duplicate acknowledgement ignored
    final = s.get_job(job["job_id"], None)
    assert final["state"] == "succeeded" and final["result"] == {"from": "alive"} and final["result_id"] == rid


def test_stale_lease_with_same_owner_is_fenced_by_attempt(backend: Backend) -> None:
    # Same owner name re-claims after expiry (e.g. the in-process "api-inprocess" drains).
    s = backend.storage
    job = job_for(s)
    stale = s.claim("same-owner", LEASE)
    assert stale is not None
    backend.advance(LEASE + 0.5)
    fresh = s.claim("same-owner", LEASE)
    assert fresh is not None and fresh.attempt == stale.attempt + 1
    assert s.heartbeat(stale, LEASE) == "lost"
    assert s.fail(stale, "transient") is None
    assert s.acknowledge_cancel(stale) is False
    assert s.complete(stale, {"from": "stale"}) is None
    assert s.mark_running(fresh, LEASE) == "ok"
    rid = s.complete(fresh, {"from": "fresh"})
    assert rid is not None and s.get_job(job["job_id"], None)["result"] == {"from": "fresh"}


def test_bounded_retries(backend: Backend) -> None:
    s = backend.storage
    job = job_for(s, max_attempts=2)
    lease = s.claim("w", LEASE)
    assert s.fail(lease, "transient", retryable=True) == "queued"
    lease = s.claim("w", LEASE)
    assert lease is not None and lease.attempt == 2
    backend.advance(LEASE + 0.5)  # dies on the last attempt
    assert s.claim("w", LEASE) is None
    j = s.get_job(job["job_id"], None)
    assert j["state"] == "failed" and "exhausted" in j["last_error"] and j["result_id"] is None


def test_permanent_failure_is_not_retried(backend: Backend) -> None:
    s = backend.storage
    job = job_for(s, max_attempts=3)
    lease = s.claim("w", LEASE)
    assert s.fail(lease, "invalid_input: x", retryable=False) == "failed"
    assert s.claim("w", LEASE) is None
    assert s.get_job(job["job_id"], None)["attempts"] == 1


def test_cancel_queued_and_running(backend: Backend) -> None:
    s = backend.storage
    queued = job_for(s)
    assert s.cancel_job(queued["job_id"], frozenset({"c2"})) is None  # other cluster cannot cancel
    assert s.cancel_job(queued["job_id"], frozenset({"c1"}))["state"] == "cancelled"
    assert s.claim("w", LEASE) is None

    running = job_for(s, mode="snapshot_only")
    lease = s.claim("w", LEASE)
    assert lease is not None and lease.job_id == running["job_id"]
    assert s.cancel_job(running["job_id"], None)["cancel_requested"] is True
    assert s.heartbeat(lease, LEASE) == "cancel"
    assert s.complete(lease, {"late": True}) is None  # cancelled work never publishes
    assert s.acknowledge_cancel(lease)
    j = s.get_job(running["job_id"], None)
    assert j["state"] == "cancelled" and j["result_id"] is None


def test_process_one_runs_engine_from_stored_manifest(backend: Backend) -> None:
    s = backend.storage
    raw = raw_case("residual-token")
    assert s.create_case({"case_id": "rt", "cluster_id": raw["cluster_id"], "input": raw, "diagnostics": {}})
    m = build_manifest(raw["cluster_id"], "rt", "analysis", {"input": raw, "mode": "full"})
    assert m["semantic_profile"]["id"]
    job = s.enqueue(m, created_by="principal-0")
    out = process_one(s, "w1", lease_seconds=30, heartbeat_interval=5)
    assert out.state == "succeeded" and out.job_id == job["job_id"]
    j = s.get_job(job["job_id"], None)
    assert j["result"]["conclusion"]["model"] == "residual_path"
    assert j["result"]["input_digest"]
    assert process_one(s, "w1").state == "idle"


def test_process_one_worker_death_mid_job_reruns(backend: Backend) -> None:
    s = backend.storage
    job = job_for(s)

    def dies(kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        backend.advance(LEASE + 0.5)  # stalls past the lease without heartbeating
        return {"stale": True}

    lost = process_one(s, "w-slow", lease_seconds=LEASE, heartbeat_interval=3600, executor=dies)
    assert lost.state == "lost"
    assert s.get_job(job["job_id"], None)["result_id"] is None
    ok = process_one(s, "w-fresh", lease_seconds=30, heartbeat_interval=5, executor=lambda k, p: {"fresh": True})
    assert ok.state == "succeeded"
    j = s.get_job(job["job_id"], None)
    assert j["result"] == {"fresh": True} and j["attempts"] == 2


def test_process_one_permanent_error(backend: Backend) -> None:
    s = backend.storage
    job = job_for(s)

    def bad(kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise PermanentJobError("invalid_input: nope")

    assert process_one(s, "w", executor=bad).state == "failed"
    assert s.get_job(job["job_id"], None)["last_error"] == "invalid_input: nope"


def test_tampered_manifest_is_not_executed() -> None:
    s = MemoryStorage()
    job = job_for(s)
    s.manifests[job["manifest_id"]]["payload"]["input"]["n"] = 2  # simulate corruption at rest
    assert process_one(s, "w", executor=lambda k, p: {"never": True}).state == "failed"
    assert s.get_job(job["job_id"], None)["result_id"] is None


# PostgreSQL-only: transaction and schema behavior -----------------------------------------


@needs_pg
def test_interrupted_publication_leaves_no_partial_result(pg_schema: str) -> None:
    assert PG_URL
    _pg_migrate(pg_schema)
    s = PostgresStorage(PG_URL, schema=pg_schema)
    job = job_for(s)
    lease = s.claim("w", 30)

    def crash() -> None:
        raise RuntimeError("connection lost mid-commit")

    s.before_publish_commit = crash
    with pytest.raises(RuntimeError):
        s.complete(lease, {"partial": True})
    j = s.get_job(job["job_id"], None)
    assert j["state"] == "leased" and j["result_id"] is None  # rolled back as a unit
    s.before_publish_commit = None
    assert s.complete(lease, {"whole": True}) is not None


@needs_pg
def test_schema_upgrade_from_0001_preserves_data_and_immutability(pg_schema: str) -> None:
    import psycopg

    assert PG_URL
    assert _pg_migrate(pg_schema, target=1) == [1]
    with pytest.raises(RuntimeError, match="schema version 1"):
        PostgresStorage(PG_URL, schema=pg_schema)
    old = PostgresStorage(PG_URL, schema=pg_schema, check_schema=False)
    job = job_for(old)
    assert _pg_migrate(pg_schema) == [2, 3]
    assert _pg_migrate(pg_schema) == []
    s = PostgresStorage(PG_URL, schema=pg_schema)
    assert s.get_job(job["job_id"], None)["state"] == "queued"
    lease = s.claim("w", 30)
    assert lease is not None and s.complete(lease, {"ok": 1})
    with psycopg.connect(PG_URL, options=f"-c search_path={pg_schema}") as c:
        for stmt in ("UPDATE cases SET diagnostics = '{}'::jsonb", "DELETE FROM results", "UPDATE analysis_manifests SET engine_version = 'x'"):
            with pytest.raises(psycopg.errors.RaiseException, match="immutable"):
                c.execute(stmt)
            c.rollback()


@needs_pg
def test_concurrent_claims_never_share_a_job(pg_schema: str) -> None:
    import threading

    assert PG_URL
    _pg_migrate(pg_schema)
    s = PostgresStorage(PG_URL, schema=pg_schema)
    jobs = {job_for(s, case_id=f"case-{i}")["job_id"] for i in range(8)}
    got: list[str] = []
    lock = threading.Lock()

    def worker(n: int) -> None:
        while (lease := s.claim(f"w{n}", 30)) is not None:
            with lock:
                got.append(lease.job_id)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(got) == sorted(jobs)


def test_case_ids_are_unique_per_cluster_not_globally(backend: Backend) -> None:
    s = backend.storage
    assert s.create_case(fake_case("case-a", "c1"))
    # The same id in another cluster is a different case, not a conflict (no cross-cluster leak).
    assert s.create_case(fake_case("case-a", "c2"))
    assert not s.create_case(fake_case("case-a", "c2"))
    assert s.get_case("case-a", frozenset({"c2"}))["cluster_id"] == "c2"
    with pytest.raises(AmbiguousCase):
        s.get_case("case-a", None)
    assert s.get_case("case-a", None, "c1")["cluster_id"] == "c1"
    assert s.get_case("case-a", frozenset({"c2"}), "c1") is None  # naming a cluster never widens scope
    assert s.list_cases(None) == [{"case_id": "case-a", "cluster_id": "c1"}, {"case_id": "case-a", "cluster_id": "c2"}]
    assert s.list_case_ids(frozenset({"c1"})) == ["case-a"]
    m1 = build_manifest("c1", "case-a", "analysis", {"input": {"n": 1}, "mode": "full"})
    m2 = build_manifest("c2", "case-a", "analysis", {"input": {"n": 1}, "mode": "full"})
    j1, j2 = s.enqueue(m1, created_by="p"), s.enqueue(m2, created_by="p")
    assert s.get_job(j1["job_id"], frozenset({"c2"})) is None and s.get_job(j2["job_id"], frozenset({"c2"})) is not None


def test_memory_storage_is_bounded() -> None:
    s = MemoryStorage(max_cases=1, max_results=1, max_jobs=1)
    assert s.create_case(fake_case("case-a"))
    with pytest.raises(StorageFull):
        s.create_case(fake_case("case-b"))
    assert not s.create_case(fake_case("case-a"))  # a duplicate is still reported as a duplicate
    m = build_manifest("c1", "case-a", "analysis", {"input": {"n": 1}, "mode": "full"})
    s.record_analysis(m, {"ok": 1})
    with pytest.raises(StorageFull):
        s.record_analysis(m, {"ok": 2})
    job = s.enqueue(m, created_by="p")
    with pytest.raises(StorageFull):
        s.enqueue(m, created_by="p")
    lease = s.claim("w", 30)
    assert lease is not None and s.complete(lease, {"ok": 3}) is None  # result cap: refused and visibly failed
    view = s.get_job(job["job_id"], None)
    assert view["state"] == "failed" and "limit" in view["last_error"]
    with pytest.raises(ValueError):
        MemoryStorage(max_cases=0)
