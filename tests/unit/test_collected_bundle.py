"""Pure checks used by `lab.py collect`: leak scanner, bundle checks, lab case, comparison."""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

from conftest import ROOT

sys.path.insert(0, str(ROOT / "labs" / "supervisor"))
sys.path.insert(0, str(ROOT / "packages"))
import collected as col  # noqa: E402
import receipts as rc  # noqa: E402

from afterlock.evidence import ReplayBundle, project  # noqa: E402
from afterlock.model import parse_analysis_input  # noqa: E402
from afterlock.results import analyze  # noqa: E402

GOLDEN = ROOT / "services" / "collector" / "testdata" / "golden-bundle"
CASE = json.loads((ROOT / "datasets" / "replay" / "residual-token" / "case.json").read_text())
HELD = {"ci-token": "synthetic-ci-token-value-0123", "copied": "synthetic-0123456789abcdef"}


def _tree(tmp_path: Path, content: bytes) -> Path:
    (tmp_path / "sub").mkdir()
    (tmp_path / "clean.json").write_text("{}\n")
    (tmp_path / "sub" / "f.jsonl").write_bytes(content)
    return tmp_path


# ---------------------------------------------------------------- leak scanner


def test_scan_clean_tree_has_no_findings(tmp_path: Path) -> None:
    assert col.scan_for_leaks(_tree(tmp_path, b'{"a": 1}\n'), HELD) == []


def test_scan_golden_bundle_is_clean() -> None:
    assert col.scan_for_leaks(GOLDEN, HELD) == []


@pytest.mark.parametrize(
    ("content", "kind"),
    [
        (HELD["copied"].encode(), "held:copied:value"),
        (base64.b64encode(HELD["ci-token"].encode()), "held:ci-token:base64"),
        (b"xx eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzeXN0ZW0ifQ.sig xx", "pattern:jwt"),
        (b"-----BEGIN RSA PRIVATE KEY-----", "pattern:private-key"),
        (b"AFTERLOCK-CANARY-abc123", "pattern:canary"),
        (b"Authorization: Bearer abcdefghijklmnopqrstuvwxyz", "pattern:bearer"),
    ],
)
def test_scan_finds_material_anywhere_without_echoing_it(tmp_path: Path, content: bytes, kind: str) -> None:
    findings = col.scan_for_leaks(_tree(tmp_path, b"prefix " + content + b" suffix\n"), HELD)
    assert {"file": "sub/f.jsonl", "kind": kind} in findings
    assert HELD["copied"] not in json.dumps(findings) and HELD["ci-token"] not in json.dumps(findings)


def test_scan_rejects_short_or_missing_values_and_empty_trees(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        col.scan_for_leaks(_tree(tmp_path, b"x"), {"t": "short"})
    with pytest.raises(ValueError):
        col.scan_for_leaks(tmp_path, {"t": ""})
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError):
        col.scan_for_leaks(empty, HELD)


# ---------------------------------------------------------------- bundle checks


def _events() -> list[dict]:
    return col.read_events(ReplayBundle.load(GOLDEN).event_lines)


def test_find_event_requires_success_and_exact_target() -> None:
    evs = _events()
    ev = col.find_event(evs, verb="create", resource="pods", namespace="demo", name="diagnostic-job")
    assert ev is not None and ev["target"]["uid"] == "pod-attacker-0001"
    assert col.find_event(evs, verb="create", resource="pods", namespace="demo", name="diagnostic-job", username="someone-else") is None
    assert col.find_event(evs, verb="delete", resource="pods", namespace="demo", name="diagnostic-job") is None


def test_gap_kinds_counts_collector_gaps() -> None:
    kinds = col.gap_kinds(_events())
    assert kinds["audit-malformed"] == 2 and kinds["pod-uncorrelated"] == 1
    assert "collector-restart" not in kinds


def _collected_like() -> tuple[dict, list[dict]]:
    inv = json.loads((GOLDEN / "inventory.json").read_text())
    inv["bindings"] = [b for b in inv["bindings"] if b["name"] != "ci-pod-creator"]
    evs = _events() + [
        {"event_type": "k8s.api.response", "action": {"verb": "delete", "resource": "rolebindings", "namespace": "demo"},
         "target": {"name": "ci-pod-creator"}, "outcome": {"http_status": 200}, "actor": {"username": "kubernetes-admin"}},
    ]
    return inv, evs


def test_inventory_checks_pass_for_attack_and_containment() -> None:
    inv, evs = _collected_like()
    creator = next(e for e in evs if e.get("target", {}).get("name") == "diagnostic-job")["actor"]["username"]
    checks = col.inventory_checks(inv, evs, namespace="demo", attacker_pod="diagnostic-job", attacker_pod_uid="pod-attacker-0001",
                                  attacker_sa="release-reader", creator=creator, binding="ci-pod-creator")
    assert all(checks.values()), checks


def test_inventory_checks_name_each_failure() -> None:
    inv, evs = _collected_like()
    inv["bindings"].append({"name": "ci-pod-creator", "namespace": "demo"})
    checks = col.inventory_checks(inv, evs[:-1], namespace="demo", attacker_pod="diagnostic-job", attacker_pod_uid="other-uid",
                                  attacker_sa="release-reader", creator="nobody", binding="ci-pod-creator")
    assert not any(checks.values()), checks


# ---------------------------------------------------------------- lab case and comparison


def test_lab_case_uses_live_uids_and_drops_downstream_items() -> None:
    case = col.lab_case(CASE, ci_username="system:serviceaccount:demo:ci-runner", ci_sa_uid="live-sa", release_pod_uid="live-pod",
                        analysis_time="2026-09-26T00:00:00Z", source_id="lab-collector")
    assert [o["id"] for o in case["objectives"]] == ["protect-secret"]
    assert [o["id"] for o in case["legitimate_operations"]] == ["release-read"]
    assert case["legitimate_operations"][0]["pod_uid"] == "live-pod"
    assert case["compromised_credentials"] == [{"id": "ci-runner-token", "kind": "sa_token", "username": "system:serviceaccount:demo:ci-runner",
                                                "sa_uid": "live-sa", "audience": "https://kubernetes.default.svc.cluster.local"}]
    assert case["required_sources"] == ["lab-collector"] and case["remediation"] == CASE["remediation"]
    assert any("protect-canary" in a and "release-canary" in a for a in case["assumptions"])


def _analyze(directory: Path) -> dict:
    return analyze(parse_analysis_input(project(ReplayBundle.load(directory))[0]))


def test_lab_case_on_a_residual_token_shaped_bundle_matches_the_reference(tmp_path: Path) -> None:
    """End to end without a lab: the residual-token evidence, re-cased with lab_case, reaches the same conclusion."""
    src = ReplayBundle.load(ROOT / "datasets" / "replay" / "residual-token")
    case = col.lab_case(CASE, ci_username="system:serviceaccount:demo:ci-runner", ci_sa_uid="sa-ci-runner-0001",
                        release_pod_uid="pod-release-0001", analysis_time=CASE["analysis_time"], source_id="lab-audit")
    ReplayBundle.write(tmp_path, case_id="residual-token-live", cluster_id=src.manifest["cluster_id"], inventory=src.inventory,
                       case=case, events=[json.loads(line) for line in src.event_lines if line.strip()])
    cmp = col.compare_conclusions(_analyze(tmp_path), _analyze(ROOT / "datasets" / "replay" / "residual-token"))
    assert cmp["match"], cmp
    assert cmp["shared_objectives"] == ["protect-secret"] and cmp["reference_conclusion"] == "residual_path"


def test_compare_conclusions_detects_mismatch_and_no_overlap() -> None:
    ref = {"conclusion": {"model": "residual_path"}, "objectives": [{"id": "a", "status": "violated"}]}
    assert not col.compare_conclusions({"conclusion": {"model": "residual_path"}, "objectives": [{"id": "a", "status": "unknown"}]}, ref)["match"]
    assert not col.compare_conclusions({"conclusion": {"model": "unknown"}, "objectives": [{"id": "a", "status": "violated"}]}, ref)["match"]
    assert not col.compare_conclusions({"conclusion": {"model": "residual_path"}, "objectives": [{"id": "b", "status": "violated"}]}, ref)["match"]
    assert col.compare_conclusions({"conclusion": {"model": "residual_path"}, "objectives": [{"id": "a", "status": "violated"}]}, ref)["match"]


# ---------------------------------------------------------------- supervisor-check receipts


def test_check_receipt_uses_expectation_modes() -> None:
    ok = rc.check_receipt("s", True, "valid", detail=1)
    bad = rc.check_receipt("s", False, "valid")
    assert ok["agrees"] and ok["observed_http_status"] == rc.CHECK_PASSED and ok["observation"] == "supervisor-check" and ok["detail"] == 1
    assert not bad["agrees"] and bad["observed_http_status"] == rc.CHECK_FAILED
    assert rc.validation([ok, bad]) == "lab_contradicted" and rc.validation([ok]) == "lab_confirmed"
