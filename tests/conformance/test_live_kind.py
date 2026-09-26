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
# S-SEC-5: step -> (model prediction, expectation). d is measured in the same run.
PROPAGATION_STEPS = {
    "s-sec-5-old-credential-accepted-right-after-rotation": ("violated", "answer_ok"),
    "s-sec-5-old-credential-rejected-after-propagation-wait": ("satisfied_within_scope", "answer_denied"),
}
COLLECT_CHECKS = {
    "collected-conclusion-matches-residual-token", "collected-bundle-has-no-credential-material",
    "collector-writes-contained-bundle", "contained-bundle-validates", "contained-inventory-shows-attack-and-containment",
    "collected-conclusion-matches-targeted-containment", "contained-bundle-has-no-credential-material",
}


def _check_propagation(name: str, steps: dict) -> None:
    missing = PROPAGATION_STEPS.keys() - steps.keys()
    assert not missing, f"{name}: S-SEC-5 steps missing: {missing}"
    d = {steps[s]["rotation_propagation_seconds"] for s in PROPAGATION_STEPS}
    assert len(d) == 1 and next(iter(d)) >= 1, f"{name}: inconsistent or zero measured d: {d}"
    for step, (prediction, expect) in PROPAGATION_STEPS.items():
        assert (steps[step]["model_prediction"], steps[step]["expect"]) == (prediction, expect)
        assert steps[step]["window"]["reaccepted_after_refusal"] is False
    late = steps["s-sec-5-old-credential-rejected-after-propagation-wait"]
    assert late["elapsed_seconds_since_rotation"] >= late["rotation_propagation_seconds"]

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
        _check_propagation(path.name, steps)
    if repeat > 1:
        summaries = [p for p in new if p.name.startswith("spike-summary-")]
        assert len(summaries) == 1, "repeat run wrote no summary"
        summary = json.loads(summaries[0].read_text())
        assert summary["run_count"] == repeat
        assert summary["all_runs_agree"], f"runs disagree: {summary['runs']} missing={summary['missing_steps']}"


@pytest.mark.skipif(os.environ.get("AFTERLOCK_LIVE_COLLECT") != "1",
                    reason="BLOCKED: collector run not requested (AFTERLOCK_LIVE_COLLECT=1 on a provisioned lab; not a pass)")
def test_collect_both_windows_agree_with_hand_authored_cases() -> None:
    before = set(RECEIPTS.glob("collect-*.json"))
    subprocess.run([sys.executable, str(ROOT / "labs" / "supervisor" / "lab.py"), "collect"], check=True, timeout=1800)
    new = sorted(set(RECEIPTS.glob("collect-*.json")) - before)
    assert len(new) == 1, f"expected one collect receipt, got {[p.name for p in new]}"
    receipt = json.loads(new[0].read_text())
    steps = {r["step"]: r for r in receipt["receipts"]}
    missing = COLLECT_CHECKS - steps.keys()
    assert not missing, f"collect checks missing: {missing}"
    assert receipt["validation"] == "lab_confirmed", [r for r in receipt["receipts"] if not r["agrees"]]
    cmp = steps["collected-conclusion-matches-targeted-containment"]["comparison"]
    assert cmp["shared_objectives"] == ["protect-secret"] and cmp["reference_conclusion"] == "contained_within_scope"
    assert not cmp["blocking"] and not cmp["raw_violations"]
    assert "protect-canary" in steps["collected-conclusion-matches-targeted-containment"]["coverage_limitations"]
    _check_propagation(new[0].name, steps)
