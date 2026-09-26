"""Leased job execution.

``process_one`` claims one job, verifies the manifest's content hash, marks the job running,
keeps the lease alive from a heartbeat thread while the (non-interruptible, pure) engine runs,
and then publishes, fails, or acknowledges cancellation. If the lease is lost (heartbeat
reports ``lost``) the computed result is discarded; ``Storage.complete`` would refuse it anyway.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import afterlock_reference as reference
from afterlock.engine import MODES
from afterlock.model import ModelError, parse_analysis_input
from afterlock.planner import PlannerConfig, plan
from afterlock.results import analyze
from afterlock_api.storage import Lease, Storage, manifest_intact

Executor = Callable[[str, dict[str, Any]], dict[str, Any]]


class PermanentJobError(Exception):
    """Input-level failure that retrying cannot fix."""


def execute(kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Run the engine on an immutable manifest payload. Pure: no storage access."""
    try:
        if kind == "analysis":
            mode = payload["mode"]
            if mode not in MODES:
                raise PermanentJobError(f"unsupported mode {mode!r}")
            return analyze(parse_analysis_input(payload["input"]), mode)
        if kind == "plan":
            cfg = PlannerConfig(max_length=int(payload["max_length"]), max_evaluations=int(payload["max_evaluations"]))
            return plan(parse_analysis_input(payload["input"]), cfg)
        if kind == "verification":
            return {
                "witnesses": reference.verify_witnesses(payload["input"], payload["result"]),
                "reference_exploration": reference.explore(payload["input"], reference.ReferenceLimits(max_states=50_000)),
            }
    except ModelError as exc:
        raise PermanentJobError(f"invalid_input: {exc}") from exc
    except KeyError as exc:
        raise PermanentJobError(f"manifest payload missing {exc}") from exc
    raise PermanentJobError(f"unknown job kind {kind!r}")


@dataclass
class Outcome:
    job_id: str | None
    state: str  # idle | succeeded | failed | queued | cancelled | lost
    result_id: str | None = None


def _heartbeat_loop(storage: Storage, lease: Lease, lease_seconds: float, interval: float, stop: threading.Event, flags: dict[str, bool]) -> None:
    while not stop.wait(interval):
        try:
            status = storage.heartbeat(lease, lease_seconds)
        except Exception:  # transient storage error: the lease may still expire; publication re-checks it
            continue
        if status == "lost":
            flags["lost"] = True
            return
        if status == "cancel":
            flags["cancel"] = True


def process_one(
    storage: Storage,
    owner: str,
    *,
    lease_seconds: float = 30.0,
    heartbeat_interval: float = 10.0,
    executor: Executor = execute,
) -> Outcome:
    lease = storage.claim(owner, lease_seconds)
    if lease is None:
        return Outcome(None, "idle")
    if not manifest_intact(lease.manifest):
        return Outcome(lease.job_id, storage.fail(lease, "manifest integrity check failed", retryable=False) or "lost")
    status = storage.mark_running(lease, lease_seconds)
    if status == "lost":
        return Outcome(lease.job_id, "lost")
    if status == "cancel":
        storage.acknowledge_cancel(lease)
        return Outcome(lease.job_id, "cancelled")

    stop = threading.Event()
    flags = {"lost": False, "cancel": False}
    hb = threading.Thread(target=_heartbeat_loop, args=(storage, lease, lease_seconds, heartbeat_interval, stop, flags), daemon=True)
    hb.start()
    try:
        result = executor(lease.kind, lease.manifest["payload"])
    except PermanentJobError as exc:
        return Outcome(lease.job_id, storage.fail(lease, str(exc), retryable=False) or "lost")
    except Exception as exc:  # unexpected: bounded retry via max_attempts
        return Outcome(lease.job_id, storage.fail(lease, f"{type(exc).__name__}: {exc}", retryable=True) or "lost")
    finally:
        stop.set()
        hb.join()

    if flags["lost"]:
        return Outcome(lease.job_id, "lost")
    if flags["cancel"] and storage.acknowledge_cancel(lease):
        return Outcome(lease.job_id, "cancelled")
    rid = storage.complete(lease, result)
    if rid is None:
        # Lease lost, cancellation raced in, or already published: never publish twice.
        return Outcome(lease.job_id, "cancelled" if storage.acknowledge_cancel(lease) else "lost")
    return Outcome(lease.job_id, "succeeded", rid)


def drain(storage: Storage, owner: str, limit: int = 100, **kw: Any) -> list[Outcome]:
    """Process queued jobs until none are claimable (used by the in-memory API)."""
    out: list[Outcome] = []
    for _ in range(limit):
        o = process_one(storage, owner, **kw)
        if o.state == "idle":
            break
        out.append(o)
    return out
