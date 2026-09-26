"""Pure logic for the second collection window (targeted containment) and the S-SEC-5 lab steps."""

from __future__ import annotations

import copy
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

TC_DIR = ROOT / "datasets" / "replay" / "targeted-containment"
TC = json.loads((TC_DIR / "case.json").read_text())
CI = "system:serviceaccount:demo:ci-runner"


def _analyze(directory: Path) -> dict:
    return analyze(parse_analysis_input(project(ReplayBundle.load(directory))[0]))


def _case(**kw) -> dict:
    args = {"ci_username": CI, "ci_sa_uid": "sa-ci-runner-0001", "release_pod_uid": "live-release",
            "analysis_time": TC["analysis_time"], "source_id": "lab-audit", "scenario": "targeted-containment"}
    return col.lab_case(TC, **{**args, **kw})


# ---------------------------------------------------------------- lab case


def test_targeted_case_maps_keep_uids_and_drops_downstream_items() -> None:
    case = _case()
    assert [o["id"] for o in case["objectives"]] == ["protect-secret"]
    assert [op["id"] for op in case["legitimate_operations"]] == ["release-read"]
    assert case["legitimate_operations"][0]["pod_uid"] == "live-release"
    kinds = [a["kind"] for a in case["remediation"]]
    assert kinds == ["remove_binding", "delete_pods_except"]
    assert case["remediation"][1]["keep_uids"] == ["live-release"]
    assert "pod-release-0001" not in json.dumps(case) and "pod-ci-0001" not in json.dumps(case)
    assert "targeted-containment" in case["description"]
    assert set(col.downstream_items(TC)) == {"protect-canary", "release-canary",
                                              "remediation:rotate_downstream_credential:canary-service"}


def test_lab_case_refuses_to_invent_uids() -> None:
    bad = copy.deepcopy(TC)
    bad["remediation"][1]["keep_uids"] = ["unknown-uid"]
    with pytest.raises(ValueError):
        col.lab_case(bad, ci_username=CI, ci_sa_uid="s", release_pod_uid="p", analysis_time=TC["analysis_time"], source_id="x")
    bad = copy.deepcopy(TC)
    bad["remediation"].append({"kind": "delete_pod", "uid": "pod-attacker-0001"})
    with pytest.raises(ValueError):
        col.lab_case(bad, ci_username=CI, ci_sa_uid="s", release_pod_uid="p", analysis_time=TC["analysis_time"], source_id="x")


# ---------------------------------------------------------------- post-containment bundle, end to end without a lab


def _gap(seq: int, kind: str) -> dict:
    return {"cluster_id": "lab-local", "event_id": f"g-{seq}", "event_type": "collector.gap", "gap_kind": kind,
            "gap_id": f"lab-audit:{kind}:{seq}", "reason": f"synthetic {kind}", "observed_at": "2026-01-01T12:29:00Z",
            "ingested_at": "2026-01-01T12:29:00Z", "schema_version": "1", "source_id": "lab-audit", "source_sequence": 200 + seq}


def _contained_bundle(tmp_path: Path, gap_kinds: list[str]) -> tuple[Path, list[dict]]:
    """targeted-containment evidence after the containment was applied: binding and attacker Pod gone."""
    src = ReplayBundle.load(TC_DIR)
    inv = copy.deepcopy(src.inventory)
    inv["bindings"] = [b for b in inv["bindings"] if b["name"] != "ci-pod-creator"]
    inv["pods"] = [p for p in inv["pods"] if p["uid"] not in ("pod-attacker-0001", "pod-ci-0001")]
    inv["services"] = []  # the collector does not observe downstream services
    events = [json.loads(line) for line in src.event_lines if line.strip()]
    events += [_gap(i, k) for i, k in enumerate(gap_kinds)]
    case = _case(release_pod_uid="pod-release-0001")
    out = tmp_path / "bundle"
    ReplayBundle.write(out, case_id="targeted-containment-live", cluster_id="lab-local", inventory=inv, case=case, events=events)
    return out, events


def _compare(tmp_path: Path, gap_kinds: list[str]) -> dict:
    out, events = _contained_bundle(tmp_path, gap_kinds)
    bundle = ReplayBundle.load(out)
    raw = _analyze(out)
    plan = col.plan_gap_resolution(raw["missing_coverage"], col.gap_index(events))
    res_dir = tmp_path / "resolved"
    ReplayBundle.write(res_dir, case_id="x", cluster_id="lab-local", inventory=bundle.inventory,
                       case=col.resolve_gaps(bundle.case, plan["resolved"]), events=events)
    return col.compare_containment(raw, _analyze(res_dir), _analyze(TC_DIR), plan)


def test_post_containment_bundle_without_gaps_matches_reference(tmp_path: Path) -> None:
    cmp = _compare(tmp_path, [])
    assert cmp["match"], cmp
    assert cmp["raw_conclusion"] == "contained_within_scope" == cmp["reference_conclusion"]
    assert cmp["shared_objectives"] == ["protect-secret"]


def test_resolvable_gaps_make_raw_unknown_but_match_after_declared_resolution(tmp_path: Path) -> None:
    cmp = _compare(tmp_path, ["audit-before-window", "rbac-rule-unmodeled", "rbac-rule-unmodeled"])
    assert cmp["raw_conclusion"] == "unknown"  # never silently contained
    assert cmp["match"], cmp
    assert cmp["resolved_gap_kinds"] == {"audit-before-window": 1, "rbac-rule-unmodeled": 2}


@pytest.mark.parametrize("kind", ["collector-restart", "pod-uncorrelated", "inventory-unsynced", "audit-dropped"])
def test_other_gaps_block_the_match(tmp_path: Path, kind: str) -> None:
    cmp = _compare(tmp_path, ["audit-before-window", kind])
    assert not cmp["match"]
    assert [b["kind"] for b in cmp["blocking"]] == [kind]


def test_raw_violation_blocks_the_match() -> None:
    ref = {"conclusion": {"model": "contained_within_scope"}, "objectives": [{"id": "a", "status": "satisfied_within_scope"}]}
    raw = {"conclusion": {"model": "residual_path"}, "objectives": [{"id": "a", "status": "violated"}]}
    cmp = col.compare_containment(raw, ref, ref, {"resolved": {}, "blocking": []})
    assert not cmp["match"] and cmp["raw_violations"] == {"a": "violated"}


def test_resolve_gaps_states_one_reason_per_kind() -> None:
    case = col.resolve_gaps({"assumptions": ["x"]}, {"g2": "rbac-rule-unmodeled", "g1": "rbac-rule-unmodeled"})
    assert case["resolved_gaps"] == ["g1", "g2"]
    assert case["assumptions"] == ["x", col.GAP_RESOLUTIONS["rbac-rule-unmodeled"]]


def test_containment_checks_name_each_step() -> None:
    evs = [
        {"event_type": "k8s.api.response", "action": {"verb": "create", "resource": "pods", "namespace": "demo"},
         "target": {"name": "diagnostic-job", "uid": "att", "service_account": "release-reader"},
         "outcome": {"http_status": 201}, "actor": {"username": CI}},
        {"event_type": "k8s.api.response", "action": {"verb": "delete", "resource": "rolebindings", "namespace": "demo"},
         "target": {"name": "ci-pod-creator"}, "outcome": {"http_status": 200}, "actor": {"username": "admin"}},
        {"event_type": "k8s.api.response", "action": {"verb": "delete", "resource": "pods", "namespace": "demo"},
         "target": {"name": "diagnostic-job"}, "outcome": {"http_status": 200}, "actor": {"username": "admin"}},
        {"event_type": "k8s.api.response", "action": {"verb": "patch", "resource": "secrets", "namespace": "demo"},
         "target": {"name": "release-credential"}, "outcome": {"http_status": 200}, "actor": {"username": "admin"}},
    ]
    inv = {"pods": [{"uid": "rel", "namespace": "demo", "service_account": "release-reader"}], "bindings": []}
    kw = {"namespace": "demo", "attacker_pod": "diagnostic-job", "attacker_pod_uid": "att", "attacker_sa": "release-reader",
          "creator": CI, "binding": "ci-pod-creator", "secret": "release-credential", "keep_uids": ["rel"]}
    assert all(col.containment_checks(inv, evs, **kw).values())
    inv["pods"].append({"uid": "att", "namespace": "demo", "service_account": "release-reader"})
    failed = col.containment_checks(inv, evs[:1], **kw)
    assert {k for k, v in failed.items() if not v} == {
        "binding-delete-event-present", "attacker-pod-delete-event-present", "attacker-pod-absent-from-inventory",
        "only-kept-pods-run-as-attacker-sa", "source-secret-rotation-event-present"}


def test_audit_batches_split_and_count_malformed_lines() -> None:
    lines = [json.dumps({"auditID": str(i), "pad": "x" * 100}).encode() for i in range(10)]
    bodies, malformed = col.audit_batches(b"\n".join([*lines, b"{not json", b"[1]", b""]), max_bytes=400)
    assert malformed == 2 and len(bodies) > 1
    items = [it for b in bodies for it in json.loads(b)["items"]]
    assert [it["auditID"] for it in items] == [str(i) for i in range(10)]
    assert all(json.loads(b)["kind"] == "EventList" for b in bodies)
    assert col.audit_batches(b"") == ([], 0)


# ---------------------------------------------------------------- S-SEC-5


def _tc_input() -> dict:
    return project(ReplayBundle.load(TC_DIR))[0]


def _canary(doc: dict) -> str:
    return {o["id"]: o["status"] for o in analyze(parse_analysis_input(doc))["objectives"]}["protect-canary"]


@pytest.mark.parametrize(("ack", "d"), [(0.0, 0), (0.2, 1), (6.83, 7), (7.0, 7)])
def test_propagation_seconds_rounds_up(ack: float, d: int) -> None:
    assert rc.propagation_seconds(ack) == d


def test_propagation_seconds_rejects_negative() -> None:
    with pytest.raises(ValueError):
        rc.propagation_seconds(-1)


def test_model_with_measured_delay_predicts_violated_then_satisfied_after_wait() -> None:
    base = _tc_input()
    d = rc.propagation_seconds(6.83)
    doc = rc.with_rotation_propagation(base, service="canary-service", delay_seconds=d)
    assert _canary(doc) == "violated"
    assert _canary(rc.with_rotation_propagation(base, service="canary-service", delay_seconds=d, wait_seconds=d)) == "satisfied_within_scope"
    assert _canary(rc.with_rotation_propagation(base, service="canary-service", delay_seconds=d, wait_seconds=d - 1)) == "violated"
    assert _canary(rc.with_rotation_propagation(base, service="canary-service", delay_seconds=0)) == "satisfied_within_scope"
    assert "rotation_propagation_seconds" not in json.dumps(base)  # input not mutated


def test_with_rotation_propagation_rejects_unknown_service() -> None:
    with pytest.raises(ValueError):
        rc.with_rotation_propagation(_tc_input(), service="nope", delay_seconds=1)


def test_rotation_window_reports_only_observations() -> None:
    w = rc.rotation_window([(0.4, 200), (2.5, 200), (5.1, 401), (7.2, 401)])
    assert w["window_observed"] and w["last_accepted_seconds"] == 2.5 and w["first_refused_seconds"] == 5.1
    assert not w["reaccepted_after_refusal"]
    closed = rc.rotation_window([(0.5, 401), (2.6, 200)])
    assert not closed["window_observed"] and closed["reaccepted_after_refusal"]
    assert rc.rotation_window([])["window_observed"] is False
