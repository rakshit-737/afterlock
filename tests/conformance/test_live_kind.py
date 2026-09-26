"""Live Kubernetes conformance for profile k8s-1.31-core-v1.

These tests run only on a provisioned lab host (AFTERLOCK_LIVE_LAB=1 after
`scripts/lab create`). When skipped they are BLOCKED, not passed; the
profile's conformance_status stays "unverified" until a receipt exists.

AFTERLOCK_LAB_REPEAT (default 1) runs reset+spike that many times and
requires every run to agree with the model, including the network-isolation
steps.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RECEIPTS = ROOT / "labs" / "receipts"
ISOLATION_STEPS = {"isolation-outsider-cannot-reach-canary", "isolation-attacker-egress-to-outsider-denied"}

pytestmark = pytest.mark.live_lab


@pytest.mark.skipif(os.environ.get("AFTERLOCK_LIVE_LAB") != "1", reason="BLOCKED: no provisioned kind lab (not a pass)")
def test_semantic_spike_agrees_with_model() -> None:
    repeat = int(os.environ.get("AFTERLOCK_LAB_REPEAT", "1"))
    before = set(RECEIPTS.glob("spike-*.json"))
    args = [sys.executable, str(ROOT / "labs" / "supervisor" / "lab.py"), "spike"]
    if repeat > 1:
        args += ["--repeat", str(repeat)]
    subprocess.run(args, check=True, timeout=1200 * repeat)
    new = sorted(set(RECEIPTS.glob("spike-*.json")) - before)
    runs = [p for p in new if not p.name.startswith("spike-summary-")]
    assert len(runs) == repeat, f"expected {repeat} run receipts, got {[p.name for p in runs]}"
    for path in runs:
        receipt = json.loads(path.read_text())
        contradictions = [r for r in receipt["receipts"] if not r["agrees"]]
        assert not contradictions, f"{path.name}: lab contradicts the model: {contradictions}"
        steps = {r["step"]: r for r in receipt["receipts"]}
        missing = ISOLATION_STEPS - steps.keys()
        assert not missing, f"{path.name}: isolation steps missing: {missing}"
        for step in ISOLATION_STEPS:
            assert steps[step]["model_prediction"] == "unreachable" and steps[step]["expect"] == "no_answer"
    if repeat > 1:
        summaries = [p for p in new if p.name.startswith("spike-summary-")]
        assert len(summaries) == 1, "repeat run wrote no summary"
        summary = json.loads(summaries[0].read_text())
        assert summary["run_count"] == repeat
        assert summary["all_runs_agree"], f"runs disagree: {summary['runs']} missing={summary['missing_steps']}"
