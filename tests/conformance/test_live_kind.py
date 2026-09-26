"""Live Kubernetes conformance for profile k8s-1.31-core-v1.

These tests run only on a provisioned lab host (AFTERLOCK_LIVE_LAB=1 after
`scripts/lab create`). When skipped they are BLOCKED, not passed; the
profile's conformance_status stays "unverified" until a receipt exists.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.live_lab


@pytest.mark.skipif(os.environ.get("AFTERLOCK_LIVE_LAB") != "1", reason="BLOCKED: no provisioned kind lab (not a pass)")
def test_semantic_spike_agrees_with_model() -> None:
    before = set((ROOT / "labs" / "receipts").glob("spike-*.json"))
    subprocess.run([sys.executable, str(ROOT / "labs" / "supervisor" / "lab.py"), "spike"], check=True, timeout=1200)
    new = sorted(set((ROOT / "labs" / "receipts").glob("spike-*.json")) - before)
    assert new, "spike produced no receipt"
    receipt = json.loads(new[-1].read_text())
    contradictions = [r for r in receipt["receipts"] if not r["agrees"]]
    assert not contradictions, f"lab contradicts the model: {contradictions}"
