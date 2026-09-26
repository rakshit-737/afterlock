"""Worker process: ``AFTERLOCK_DATABASE_URL=... python -m afterlock_worker``.

Configuration (environment):
  AFTERLOCK_DATABASE_URL          required; the worker only runs against PostgreSQL
  AFTERLOCK_WORKER_ID             lease owner name (default: hostname-pid)
  AFTERLOCK_WORKER_LEASE_SECONDS  lease length (default 30)
  AFTERLOCK_WORKER_POLL_SECONDS   idle poll interval (default 2)
"""

from __future__ import annotations

import os
import signal
import socket
import sys
import threading
from typing import Any

from afterlock_api.storage import PostgresStorage

from .runner import process_one


def main() -> int:
    url = os.environ.get("AFTERLOCK_DATABASE_URL")
    if not url:
        print("AFTERLOCK_DATABASE_URL is required (the in-memory backend runs jobs inside the API process)", file=sys.stderr)
        return 2
    owner = os.environ.get("AFTERLOCK_WORKER_ID") or f"{socket.gethostname()}-{os.getpid()}"
    lease = float(os.environ.get("AFTERLOCK_WORKER_LEASE_SECONDS", "30"))
    poll = float(os.environ.get("AFTERLOCK_WORKER_POLL_SECONDS", "2"))
    storage = PostgresStorage(url)
    stopping = threading.Event()

    def stop(*_: Any) -> None:
        stopping.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(f"afterlock-worker {owner}: lease={lease}s poll={poll}s", flush=True)
    while not stopping.is_set():
        try:
            outcome = process_one(storage, owner, lease_seconds=lease, heartbeat_interval=max(lease / 3, 0.5))
        except Exception as exc:  # database unavailable etc.: back off, never crash-loop hot
            print(f"afterlock-worker: storage error {type(exc).__name__}", file=sys.stderr, flush=True)
            stopping.wait(poll)
            continue
        if outcome.state == "idle":
            stopping.wait(poll)
        else:
            print(f"afterlock-worker: job {outcome.job_id} -> {outcome.state}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
