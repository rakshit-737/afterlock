"""Storage for the API and worker: cases, immutable manifests, leased jobs, results.

Two backends implement one contract:

* ``MemoryStorage`` - per process, lost on restart. Default when ``AFTERLOCK_DATABASE_URL``
  is unset; used by the portable test suite.
* ``PostgresStorage`` - PostgreSQL via psycopg 3 (optional extra ``afterlock[postgres]``).
  Schema comes from ``migrations/`` (see ``afterlock_api.migrate``); the backend refuses to
  start on a schema older than this release expects.

Database concerns stay here: the domain packages (``packages/afterlock``) never import this.

Scoping: every read takes a ``Scope`` (``None`` = all clusters, else the caller's cluster set)
and every worker write names both ``job_id`` and ``cluster_id``. All SQL is parameterized.
Case ids are unique per cluster (migration 0003), so a duplicate id in another cluster is not
an observable conflict. A lookup that matches the same id in several visible clusters raises
``AmbiguousCase`` unless the caller names the cluster.

Bounds: ``MemoryStorage`` refuses new cases, results, and jobs beyond configurable caps
(``StorageFull``) so one process cannot be grown without limit.

Job state machine::

    queued -> leased -> running -> succeeded | failed | cancelled
    leased/running --(lease expired)--> leased (re-claimed, attempts+1) | failed (attempts exhausted)
    leased/running --(failure, attempts left)--> queued
    queued --(cancel)--> cancelled;  leased/running --(cancel)--> cancel_requested, worker acknowledges

Publication invariant: a result is written only inside the transaction that (a) locks the job
row, (b) confirms the caller still holds an unexpired lease (same owner *and* attempt, so a
stale holder re-claimed under its own name is fenced out) and cancellation was not requested,
and (c) confirms the job's manifest and case rows are committed. The ``results.job_id`` unique
constraint makes a duplicate completion a no-op.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import secrets
import threading
import time
from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from afterlock import __version__ as ENGINE_VERSION

Scope = frozenset[str] | None
HeartbeatStatus = Literal["ok", "cancel", "lost"]
JOB_KINDS = ("analysis", "plan", "verification")
TERMINAL = ("succeeded", "failed", "cancelled")
RESULT_PREFIX = {"analysis": "an", "plan": "pl", "verification": "vf"}
SCHEMA_VERSION = 3  # highest migration this code requires
DEFAULT_MAX_CASES = 1_000
DEFAULT_MAX_RESULTS = 10_000
DEFAULT_MAX_JOBS = 10_000


class StorageFull(Exception):
    """A bounded backend refused a new record (in-memory caps)."""


class AmbiguousCase(Exception):
    """The case id exists in several clusters visible to the caller; name the cluster."""


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(obj)).hexdigest()


def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(8)}"


def build_manifest(cluster_id: str, case_id: str, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Content-addressed, immutable description of a computation's inputs."""
    if kind not in JOB_KINDS:
        raise ValueError(f"unknown job kind {kind!r}")
    inp = payload.get("input") or {}
    prof = inp.get("profile") if isinstance(inp, dict) else None
    profile = {"id": prof.get("id"), "kubernetes_version": prof.get("kubernetes_version")} if isinstance(prof, dict) else {}
    body = {"cluster_id": cluster_id, "case_id": case_id, "kind": kind, "engine_version": ENGINE_VERSION, "payload": payload}
    h = digest(body)
    return {
        "manifest_id": "mf-" + h.split(":", 1)[1][:40],
        "cluster_id": cluster_id,
        "case_id": case_id,
        "kind": kind,
        "input_hash": h,
        "semantic_profile": profile,
        "engine_version": ENGINE_VERSION,
        "payload": payload,
    }


def manifest_intact(m: dict[str, Any]) -> bool:
    body = {k: m[k] for k in ("cluster_id", "case_id", "kind", "engine_version", "payload")}
    return bool(digest(body) == m["input_hash"])


@dataclass(frozen=True)
class Lease:
    job_id: str
    cluster_id: str
    owner: str
    kind: str
    attempt: int
    manifest: dict[str, Any]


class Storage(Protocol):
    kind: str

    def create_case(self, case: dict[str, Any]) -> bool: ...
    def get_case(self, case_id: str, scope: Scope, cluster_id: str | None = None) -> dict[str, Any] | None: ...
    def list_case_ids(self, scope: Scope) -> list[str]: ...
    def list_cases(self, scope: Scope) -> list[dict[str, str]]: ...
    def record_analysis(self, manifest: dict[str, Any], result: dict[str, Any]) -> str: ...
    def get_analysis(self, result_id: str, scope: Scope) -> dict[str, Any] | None: ...
    def enqueue(self, manifest: dict[str, Any], created_by: str, max_attempts: int = 3) -> dict[str, Any]: ...
    def get_job(self, job_id: str, scope: Scope) -> dict[str, Any] | None: ...
    def cancel_job(self, job_id: str, scope: Scope) -> dict[str, Any] | None: ...
    def claim(self, owner: str, lease_seconds: float, scope: Scope = None) -> Lease | None: ...
    def mark_running(self, lease: Lease, lease_seconds: float) -> HeartbeatStatus: ...
    def heartbeat(self, lease: Lease, lease_seconds: float) -> HeartbeatStatus: ...
    def complete(self, lease: Lease, result: dict[str, Any]) -> str | None: ...
    def fail(self, lease: Lease, error: str, retryable: bool = True) -> str | None: ...
    def acknowledge_cancel(self, lease: Lease) -> bool: ...


def _visible(scope: Scope, cluster_id: str) -> bool:
    return scope is None or cluster_id in scope


def _pick_case(matches: list[dict[str, Any]], case_id: str) -> dict[str, Any] | None:
    if len(matches) > 1:
        raise AmbiguousCase(f"case {case_id!r} exists in several of your clusters; pass cluster_id")
    return matches[0] if matches else None


def _public_job(j: dict[str, Any], result_id: str | None, result: Any) -> dict[str, Any]:
    out = {k: j[k] for k in ("job_id", "cluster_id", "manifest_id", "kind", "state", "attempts", "max_attempts", "cancel_requested", "last_error")}
    out["result_id"] = result_id
    if result is not None:
        out["result"] = result
    return out


class MemoryStorage:
    """In-process backend with the same state machine as PostgreSQL. ``clock`` is injectable for tests."""

    kind = "in-memory"

    def __init__(
        self,
        clock: Callable[[], float] = time.time,
        *,
        max_cases: int = DEFAULT_MAX_CASES,
        max_results: int = DEFAULT_MAX_RESULTS,
        max_jobs: int = DEFAULT_MAX_JOBS,
    ) -> None:
        if min(max_cases, max_results, max_jobs) < 1:
            raise ValueError("in-memory storage caps must be >= 1")
        self.clock = clock
        self.lock = threading.RLock()
        self.max_cases, self.max_results, self.max_jobs = max_cases, max_results, max_jobs
        self.cases: dict[tuple[str, str], dict[str, Any]] = {}  # (cluster_id, case_id) -> case
        self.manifests: dict[str, dict[str, Any]] = {}
        self.jobs: dict[str, dict[str, Any]] = {}
        self.results: dict[str, dict[str, Any]] = {}
        self.result_by_job: dict[str, str] = {}

    # cases -----------------------------------------------------------------
    def create_case(self, case: dict[str, Any]) -> bool:
        key = (case["cluster_id"], case["case_id"])
        with self.lock:
            if key in self.cases:
                return False
            if len(self.cases) >= self.max_cases:
                raise StorageFull(f"in-memory case limit ({self.max_cases}) reached")
            rec = copy.deepcopy(case)
            rec["content_hash"] = digest(rec["input"])
            self.cases[key] = rec
            return True

    def get_case(self, case_id: str, scope: Scope, cluster_id: str | None = None) -> dict[str, Any] | None:
        with self.lock:
            matches = [c for (cl, cid), c in self.cases.items()
                       if cid == case_id and _visible(scope, cl) and (cluster_id is None or cl == cluster_id)]
            c = _pick_case(matches, case_id)
            return copy.deepcopy(c) if c is not None else None

    def list_cases(self, scope: Scope) -> list[dict[str, str]]:
        with self.lock:
            keys = sorted((cid, cl) for (cl, cid) in self.cases if _visible(scope, cl))
        return [{"case_id": cid, "cluster_id": cl} for cid, cl in keys]

    def list_case_ids(self, scope: Scope) -> list[str]:
        return [c["case_id"] for c in self.list_cases(scope)]

    # manifests and results ------------------------------------------------------
    def _put_manifest(self, m: dict[str, Any]) -> None:
        if (m["cluster_id"], m["case_id"]) not in self.cases:
            raise KeyError("manifest references an unknown case")
        self.manifests.setdefault(m["manifest_id"], copy.deepcopy(m))

    def record_analysis(self, manifest: dict[str, Any], result: dict[str, Any]) -> str:
        with self.lock:
            if len(self.results) >= self.max_results:
                raise StorageFull(f"in-memory result limit ({self.max_results}) reached")
            self._put_manifest(manifest)
            rid = new_id(RESULT_PREFIX[manifest["kind"]])
            self.results[rid] = {"result_id": rid, "cluster_id": manifest["cluster_id"], "case_id": manifest["case_id"],
                                 "manifest_id": manifest["manifest_id"], "job_id": None, "kind": manifest["kind"],
                                 "result_version": 1, "result": copy.deepcopy(result)}
            return rid

    def get_analysis(self, result_id: str, scope: Scope) -> dict[str, Any] | None:
        r = self.results.get(result_id)
        if r is None or r["kind"] != "analysis" or not _visible(scope, r["cluster_id"]):
            return None
        m = self.manifests[r["manifest_id"]]
        return {"id": result_id, "case_id": r["case_id"], "cluster_id": r["cluster_id"],
                "input": copy.deepcopy(m["payload"]["input"]), "result": copy.deepcopy(r["result"])}

    # jobs --------------------------------------------------------------------
    def enqueue(self, manifest: dict[str, Any], created_by: str, max_attempts: int = 3) -> dict[str, Any]:
        if not 1 <= max_attempts <= 10:
            raise ValueError("max_attempts must be in 1..10")
        with self.lock:
            if len(self.jobs) >= self.max_jobs:
                raise StorageFull(f"in-memory job limit ({self.max_jobs}) reached")
            self._put_manifest(manifest)
            jid = new_id("job")
            self.jobs[jid] = {"job_id": jid, "cluster_id": manifest["cluster_id"], "manifest_id": manifest["manifest_id"],
                              "kind": manifest["kind"], "state": "queued", "lease_owner": None, "lease_expires_at": None,
                              "heartbeat_at": None, "attempts": 0, "max_attempts": max_attempts, "cancel_requested": False,
                              "last_error": None, "created_by": created_by, "seq": len(self.jobs)}
            return self._view(self.jobs[jid])

    def _view(self, j: dict[str, Any]) -> dict[str, Any]:
        rid = self.result_by_job.get(j["job_id"])
        res = self.results[rid]["result"] if rid else None
        return copy.deepcopy(_public_job(j, rid, res))

    def get_job(self, job_id: str, scope: Scope) -> dict[str, Any] | None:
        with self.lock:
            j = self.jobs.get(job_id)
            return self._view(j) if j is not None and _visible(scope, j["cluster_id"]) else None

    def cancel_job(self, job_id: str, scope: Scope) -> dict[str, Any] | None:
        with self.lock:
            j = self.jobs.get(job_id)
            if j is None or not _visible(scope, j["cluster_id"]):
                return None
            if j["state"] == "queued":
                j.update(state="cancelled", cancel_requested=True)
            elif j["state"] in ("leased", "running"):
                j["cancel_requested"] = True
            return self._view(j)

    def _release(self, j: dict[str, Any], state: str, error: str | None = None) -> None:
        j.update(state=state, lease_owner=None, lease_expires_at=None)
        if error is not None:
            j["last_error"] = error

    def claim(self, owner: str, lease_seconds: float, scope: Scope = None) -> Lease | None:
        with self.lock:
            now = self.clock()
            for j in sorted(self.jobs.values(), key=lambda x: x["seq"]):
                if not _visible(scope, j["cluster_id"]):
                    continue
                expired = j["state"] in ("leased", "running") and j["lease_expires_at"] <= now
                if not (j["state"] == "queued" or expired):
                    continue
                if j["cancel_requested"]:
                    self._release(j, "cancelled")
                    continue
                if j["attempts"] >= j["max_attempts"]:
                    self._release(j, "failed", "lease expired and retry budget exhausted")
                    continue
                if expired:
                    j["last_error"] = f"lease held by {j['lease_owner']} expired; re-queued"
                j.update(state="leased", lease_owner=owner, lease_expires_at=now + lease_seconds, heartbeat_at=now, attempts=j["attempts"] + 1)
                return Lease(j["job_id"], j["cluster_id"], owner, j["kind"], j["attempts"], copy.deepcopy(self.manifests[j["manifest_id"]]))
            return None

    def _held(self, lease: Lease) -> dict[str, Any] | None:
        j = self.jobs.get(lease.job_id)
        if (j is None or j["cluster_id"] != lease.cluster_id or j["state"] not in ("leased", "running")
                or j["lease_owner"] != lease.owner or j["attempts"] != lease.attempt or j["lease_expires_at"] <= self.clock()):
            return None
        return j

    def heartbeat(self, lease: Lease, lease_seconds: float) -> HeartbeatStatus:
        with self.lock:
            j = self._held(lease)
            if j is None:
                return "lost"
            now = self.clock()
            j.update(heartbeat_at=now, lease_expires_at=now + lease_seconds)
            return "cancel" if j["cancel_requested"] else "ok"

    def mark_running(self, lease: Lease, lease_seconds: float) -> HeartbeatStatus:
        with self.lock:
            status = self.heartbeat(lease, lease_seconds)
            if status != "lost":
                self.jobs[lease.job_id]["state"] = "running"
            return status

    def complete(self, lease: Lease, result: dict[str, Any]) -> str | None:
        with self.lock:
            j = self._held(lease)
            if j is None or j["cancel_requested"] or j["job_id"] in self.result_by_job:
                return None
            m = self.manifests.get(j["manifest_id"])
            if m is None or (m["cluster_id"], m["case_id"]) not in self.cases:
                return None
            if len(self.results) >= self.max_results:
                # Refuse publication and fail the job visibly instead of growing without bound.
                self._release(j, "failed", f"in-memory result limit ({self.max_results}) reached")
                return None
            rid = new_id(RESULT_PREFIX[j["kind"]])
            self.results[rid] = {"result_id": rid, "cluster_id": j["cluster_id"], "case_id": m["case_id"], "manifest_id": m["manifest_id"],
                                 "job_id": j["job_id"], "kind": j["kind"], "result_version": 1, "result": copy.deepcopy(result)}
            self.result_by_job[j["job_id"]] = rid
            self._release(j, "succeeded")
            return rid

    def fail(self, lease: Lease, error: str, retryable: bool = True) -> str | None:
        with self.lock:
            j = self._held(lease)
            if j is None:
                return None
            if j["cancel_requested"]:
                self._release(j, "cancelled", error)
            elif retryable and j["attempts"] < j["max_attempts"]:
                self._release(j, "queued", error)
            else:
                self._release(j, "failed", error)
            return str(j["state"])

    def acknowledge_cancel(self, lease: Lease) -> bool:
        with self.lock:
            j = self._held(lease)
            if j is None or not j["cancel_requested"]:
                return False
            self._release(j, "cancelled")
            return True


class PostgresStorage:
    """PostgreSQL backend. One short-lived connection per operation; no pool dependency."""

    kind = "postgresql"

    def __init__(self, url: str, *, schema: str | None = None, check_schema: bool = True) -> None:
        import psycopg  # optional dependency: pip install 'afterlock[postgres]'
        from psycopg.rows import dict_row
        from psycopg.types.json import Jsonb

        self._psycopg = psycopg
        self._dict_row = dict_row
        self._jsonb = Jsonb
        self.url = url
        self.schema = schema
        #: Test seam: called inside the publication transaction just before commit.
        self.before_publish_commit: Callable[[], None] | None = None
        if check_schema:
            with self._connect() as conn:
                row = conn.execute("SELECT coalesce(max(version), 0) AS v FROM schema_migrations").fetchone()
                have = int(row["v"]) if row else 0
            if have < SCHEMA_VERSION:
                raise RuntimeError(f"database schema version {have} < required {SCHEMA_VERSION}; run: python -m afterlock_api.migrate")

    def _connect(self) -> Any:
        kwargs: dict[str, Any] = {"row_factory": self._dict_row}
        if self.schema is not None:
            kwargs["options"] = f"-c search_path={self.schema}"
        return self._psycopg.connect(self.url, **kwargs)

    @staticmethod
    def _scope(scope: Scope) -> tuple[bool, list[str]]:
        return (scope is None, sorted(scope or ()))

    # cases -----------------------------------------------------------------
    def create_case(self, case: dict[str, Any]) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO cases (case_id, cluster_id, content_hash, input, diagnostics) VALUES (%s, %s, %s, %s, %s)"
                " ON CONFLICT (cluster_id, case_id) DO NOTHING",
                (case["case_id"], case["cluster_id"], digest(case["input"]), self._jsonb(case["input"]), self._jsonb(case["diagnostics"])),
            )
            return bool(cur.rowcount == 1)

    def get_case(self, case_id: str, scope: Scope, cluster_id: str | None = None) -> dict[str, Any] | None:
        every, clusters = self._scope(scope)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT case_id, cluster_id, content_hash, input, diagnostics FROM cases"
                " WHERE case_id = %s AND (%s OR cluster_id = ANY(%s)) AND (%s::text IS NULL OR cluster_id = %s::text)"
                " ORDER BY cluster_id LIMIT 2",
                (case_id, every, clusters, cluster_id, cluster_id),
            ).fetchall()
        return _pick_case([dict(r) for r in rows], case_id)

    def list_cases(self, scope: Scope) -> list[dict[str, str]]:
        every, clusters = self._scope(scope)
        with self._connect() as conn:
            rows = conn.execute("SELECT case_id, cluster_id FROM cases WHERE (%s OR cluster_id = ANY(%s)) ORDER BY case_id, cluster_id",
                                (every, clusters)).fetchall()
        return [{"case_id": r["case_id"], "cluster_id": r["cluster_id"]} for r in rows]

    def list_case_ids(self, scope: Scope) -> list[str]:
        return [c["case_id"] for c in self.list_cases(scope)]

    # manifests and results ------------------------------------------------------
    def _put_manifest(self, conn: Any, m: dict[str, Any]) -> None:
        conn.execute(
            "INSERT INTO analysis_manifests (manifest_id, cluster_id, case_id, kind, input_hash, semantic_profile, engine_version, payload)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (manifest_id) DO NOTHING",
            (m["manifest_id"], m["cluster_id"], m["case_id"], m["kind"], m["input_hash"], self._jsonb(m["semantic_profile"]),
             m["engine_version"], self._jsonb(m["payload"])),
        )

    def record_analysis(self, manifest: dict[str, Any], result: dict[str, Any]) -> str:
        rid = new_id(RESULT_PREFIX[manifest["kind"]])
        with self._connect() as conn, conn.transaction():
            self._put_manifest(conn, manifest)
            conn.execute(
                "INSERT INTO results (result_id, cluster_id, case_id, manifest_id, job_id, kind, result) VALUES (%s, %s, %s, %s, NULL, %s, %s)",
                (rid, manifest["cluster_id"], manifest["case_id"], manifest["manifest_id"], manifest["kind"], self._jsonb(result)),
            )
        return rid

    def get_analysis(self, result_id: str, scope: Scope) -> dict[str, Any] | None:
        every, clusters = self._scope(scope)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT r.result_id, r.case_id, r.cluster_id, m.payload, r.result FROM results r"
                " JOIN analysis_manifests m ON m.manifest_id = r.manifest_id AND m.cluster_id = r.cluster_id"
                " WHERE r.result_id = %s AND r.kind = 'analysis' AND (%s OR r.cluster_id = ANY(%s))",
                (result_id, every, clusters),
            ).fetchone()
        if row is None:
            return None
        return {"id": row["result_id"], "case_id": row["case_id"], "cluster_id": row["cluster_id"], "input": row["payload"]["input"], "result": row["result"]}

    # jobs --------------------------------------------------------------------
    _JOB_COLS = "j.job_id, j.cluster_id, j.manifest_id, j.kind, j.state, j.attempts, j.max_attempts, j.cancel_requested, j.last_error"

    def enqueue(self, manifest: dict[str, Any], created_by: str, max_attempts: int = 3) -> dict[str, Any]:
        jid = new_id("job")
        # Manifest and job commit together: a job can never exist without its full input.
        with self._connect() as conn, conn.transaction():
            self._put_manifest(conn, manifest)
            conn.execute(
                "INSERT INTO jobs (job_id, cluster_id, manifest_id, kind, state, max_attempts, created_by) VALUES (%s, %s, %s, %s, 'queued', %s, %s)",
                (jid, manifest["cluster_id"], manifest["manifest_id"], manifest["kind"], max_attempts, created_by),
            )
        job = self.get_job(jid, frozenset({manifest["cluster_id"]}))
        assert job is not None
        return job

    def _job_view(self, conn: Any, job_id: str, every: bool, clusters: list[str]) -> dict[str, Any] | None:
        row = conn.execute(
            f"SELECT {self._JOB_COLS}, r.result_id, r.result FROM jobs j"
            " LEFT JOIN results r ON r.job_id = j.job_id AND r.cluster_id = j.cluster_id"
            " WHERE j.job_id = %s AND (%s OR j.cluster_id = ANY(%s))",
            (job_id, every, clusters),
        ).fetchone()
        if row is None:
            return None
        return _public_job(row, row["result_id"], row["result"])

    def get_job(self, job_id: str, scope: Scope) -> dict[str, Any] | None:
        every, clusters = self._scope(scope)
        with self._connect() as conn:
            return self._job_view(conn, job_id, every, clusters)

    def cancel_job(self, job_id: str, scope: Scope) -> dict[str, Any] | None:
        every, clusters = self._scope(scope)
        with self._connect() as conn, conn.transaction():
            conn.execute(
                "UPDATE jobs SET cancel_requested = true, updated_at = now(),"
                " state = CASE WHEN state = 'queued' THEN 'cancelled' ELSE state END"
                " WHERE job_id = %s AND (%s OR cluster_id = ANY(%s)) AND state IN ('queued', 'leased', 'running')",
                (job_id, every, clusters),
            )
            return self._job_view(conn, job_id, every, clusters)

    def claim(self, owner: str, lease_seconds: float, scope: Scope = None) -> Lease | None:
        every, clusters = self._scope(scope)
        with self._connect() as conn:
            while True:
                with conn.transaction():
                    row = conn.execute(
                        "SELECT job_id, cluster_id, kind, state, lease_owner, attempts, max_attempts, cancel_requested, manifest_id"
                        " FROM jobs WHERE (%s OR cluster_id = ANY(%s))"
                        " AND (state = 'queued' OR (state IN ('leased', 'running') AND lease_expires_at <= now()))"
                        " ORDER BY created_at, job_id LIMIT 1 FOR UPDATE SKIP LOCKED",
                        (every, clusters),
                    ).fetchone()
                    if row is None:
                        return None
                    key = (row["job_id"], row["cluster_id"])
                    if row["cancel_requested"]:
                        conn.execute("UPDATE jobs SET state = 'cancelled', lease_owner = NULL, lease_expires_at = NULL, updated_at = now()"
                                     " WHERE job_id = %s AND cluster_id = %s", key)
                        continue
                    if row["attempts"] >= row["max_attempts"]:
                        conn.execute("UPDATE jobs SET state = 'failed', lease_owner = NULL, lease_expires_at = NULL, updated_at = now(),"
                                     " last_error = 'lease expired and retry budget exhausted' WHERE job_id = %s AND cluster_id = %s", key)
                        continue
                    note = f"lease held by {row['lease_owner']} expired; re-queued" if row["state"] != "queued" else None
                    conn.execute(
                        "UPDATE jobs SET state = 'leased', lease_owner = %s, lease_expires_at = now() + make_interval(secs => %s),"
                        " heartbeat_at = now(), attempts = attempts + 1, updated_at = now(), last_error = coalesce(%s::text, last_error)"
                        " WHERE job_id = %s AND cluster_id = %s",
                        (owner, float(lease_seconds), note, *key),
                    )
                    m = conn.execute(
                        "SELECT manifest_id, cluster_id, case_id, kind, input_hash, semantic_profile, engine_version, payload"
                        " FROM analysis_manifests WHERE manifest_id = %s AND cluster_id = %s",
                        (row["manifest_id"], row["cluster_id"]),
                    ).fetchone()
                    return Lease(row["job_id"], row["cluster_id"], owner, row["kind"], row["attempts"] + 1, dict(m))

    def _extend(self, lease: Lease, lease_seconds: float, running: bool) -> HeartbeatStatus:
        with self._connect() as conn, conn.transaction():
            row = conn.execute(
                "UPDATE jobs SET heartbeat_at = now(), lease_expires_at = now() + make_interval(secs => %s), updated_at = now(),"
                " state = CASE WHEN %s THEN 'running' ELSE state END"
                " WHERE job_id = %s AND cluster_id = %s AND lease_owner = %s AND attempts = %s"
                " AND state IN ('leased', 'running') AND lease_expires_at > now()"
                " RETURNING cancel_requested",
                (float(lease_seconds), running, lease.job_id, lease.cluster_id, lease.owner, lease.attempt),
            ).fetchone()
        if row is None:
            return "lost"
        return "cancel" if row["cancel_requested"] else "ok"

    def heartbeat(self, lease: Lease, lease_seconds: float) -> HeartbeatStatus:
        return self._extend(lease, lease_seconds, running=False)

    def mark_running(self, lease: Lease, lease_seconds: float) -> HeartbeatStatus:
        return self._extend(lease, lease_seconds, running=True)

    def _lock_held(self, conn: Any, lease: Lease) -> dict[str, Any] | None:
        row = conn.execute(
            "SELECT j.job_id, j.kind, j.cancel_requested, j.attempts, j.max_attempts, m.manifest_id, m.case_id"
            " FROM jobs j"
            " JOIN analysis_manifests m ON m.manifest_id = j.manifest_id AND m.cluster_id = j.cluster_id"
            " JOIN cases c ON c.case_id = m.case_id AND c.cluster_id = m.cluster_id"
            " WHERE j.job_id = %s AND j.cluster_id = %s AND j.lease_owner = %s AND j.attempts = %s"
            " AND j.state IN ('leased', 'running') AND j.lease_expires_at > now()"
            " FOR UPDATE OF j",
            (lease.job_id, lease.cluster_id, lease.owner, lease.attempt),
        ).fetchone()
        return dict(row) if row else None

    def complete(self, lease: Lease, result: dict[str, Any]) -> str | None:
        rid = new_id(RESULT_PREFIX[lease.kind])
        with self._connect() as conn, conn.transaction():
            j = self._lock_held(conn, lease)
            if j is None or j["cancel_requested"]:
                return None
            ins = conn.execute(
                "INSERT INTO results (result_id, cluster_id, case_id, manifest_id, job_id, kind, result)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (job_id) DO NOTHING RETURNING result_id",
                (rid, lease.cluster_id, j["case_id"], j["manifest_id"], lease.job_id, j["kind"], self._jsonb(result)),
            ).fetchone()
            if ins is None:
                return None
            conn.execute(
                "UPDATE jobs SET state = 'succeeded', lease_owner = NULL, lease_expires_at = NULL, updated_at = now()"
                " WHERE job_id = %s AND cluster_id = %s",
                (lease.job_id, lease.cluster_id),
            )
            if self.before_publish_commit is not None:
                self.before_publish_commit()
        return rid

    def fail(self, lease: Lease, error: str, retryable: bool = True) -> str | None:
        with self._connect() as conn, conn.transaction():
            j = self._lock_held(conn, lease)
            if j is None:
                return None
            if j["cancel_requested"]:
                state = "cancelled"
            elif retryable and j["attempts"] < j["max_attempts"]:
                state = "queued"
            else:
                state = "failed"
            conn.execute(
                "UPDATE jobs SET state = %s, lease_owner = NULL, lease_expires_at = NULL, last_error = %s, updated_at = now()"
                " WHERE job_id = %s AND cluster_id = %s",
                (state, error[:2000], lease.job_id, lease.cluster_id),
            )
            return state

    def acknowledge_cancel(self, lease: Lease) -> bool:
        with self._connect() as conn, conn.transaction():
            j = self._lock_held(conn, lease)
            if j is None or not j["cancel_requested"]:
                return False
            conn.execute(
                "UPDATE jobs SET state = 'cancelled', lease_owner = NULL, lease_expires_at = NULL, updated_at = now()"
                " WHERE job_id = %s AND cluster_id = %s",
                (lease.job_id, lease.cluster_id),
            )
            return True


def scope_for(clusters: Collection[str]) -> Scope:
    return None if "*" in clusters else frozenset(clusters)


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    if raw == "":
        return default
    if not raw.isdigit() or int(raw) < 1:
        raise ValueError(f"{name} must be a positive integer")
    return int(raw)


def from_env() -> Storage:
    url = os.environ.get("AFTERLOCK_DATABASE_URL")
    if url:
        return PostgresStorage(url)
    return MemoryStorage(
        max_cases=env_int("AFTERLOCK_MEMORY_MAX_CASES", DEFAULT_MAX_CASES),
        max_results=env_int("AFTERLOCK_MEMORY_MAX_RESULTS", DEFAULT_MAX_RESULTS),
        max_jobs=env_int("AFTERLOCK_MEMORY_MAX_JOBS", DEFAULT_MAX_JOBS),
    )
