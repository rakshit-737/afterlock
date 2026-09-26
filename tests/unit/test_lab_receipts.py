"""Pure lab logic: expectation modes, repeated-run summaries, network policies, lab-derived labels."""

from __future__ import annotations

import importlib.util
import json
import sys

import pytest

from conftest import ROOT

sys.path.insert(0, str(ROOT / "labs" / "supervisor"))
import receipts as rc  # noqa: E402


def _load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lab_labels = _load("lab_labels", "benchmarks/lab_labels.py")


@pytest.mark.parametrize(
    ("observed", "expect", "result"),
    [
        (200, "answer_ok", True), (201, "answer_ok", True), (401, "answer_ok", False), (0, "answer_ok", False),
        (401, "answer_denied", True), (403, "answer_denied", True), (422, "answer_denied", True),
        (200, "answer_denied", False), (0, "answer_denied", False),  # no answer is never a refusal
        (0, "no_answer", True), (200, "no_answer", False), (401, "no_answer", False),  # any answer means reachable
    ],
)
def test_expectation_modes(observed: int, expect: str, result: bool) -> None:
    assert rc.agrees(observed, expect) is result


def test_unknown_expectation_rejected() -> None:
    with pytest.raises(ValueError):
        rc.agrees(0, "unreachable")


def test_validation_requires_nonempty_and_all_agree() -> None:
    assert rc.validation([]) == "lab_contradicted"
    assert rc.validation([{"agrees": True}]) == "lab_confirmed"
    assert rc.validation([{"agrees": True}, {"agrees": False}]) == "lab_contradicted"


def _run(rotation: float, status: int = 200, agrees: bool = True, extra_step: bool = False) -> dict:
    receipts = [
        {"step": "rotation", "model_prediction": "acknowledged", "observed_http_status": status, "agrees": agrees, "elapsed_seconds": rotation},
        {"step": "isolation", "model_prediction": "unreachable", "observed_http_status": 0, "agrees": True, "probe_reason": "timeout"},
    ]
    if extra_step:
        receipts.append({"step": "extra", "model_prediction": "x", "observed_http_status": 200, "agrees": True})
    return {"validation": rc.validation(receipts), "receipts": receipts}


def test_summary_all_agree_with_timing_stats() -> None:
    s = rc.summarise([_run(12.0), _run(20.5), _run(15.0)], ["a", "b", "c"])
    assert s["all_runs_agree"] is True and s["run_count"] == 3
    assert s["steps"]["rotation"]["timing"]["elapsed_seconds"] == {"n": 3, "min": 12.0, "median": 15.0, "max": 20.5}
    assert s["steps"]["isolation"]["observations_identical"] is True
    assert [r["run"] for r in s["runs"]] == ["a", "b", "c"]


def test_summary_reports_contradiction_and_missing_steps() -> None:
    s = rc.summarise([_run(10.0), _run(10.0, status=0, agrees=False)])
    assert s["all_runs_agree"] is False
    assert s["steps"]["rotation"]["all_agree"] is False
    assert s["steps"]["rotation"]["observed_http_status"] == [200, 0]
    s = rc.summarise([_run(10.0, extra_step=True), _run(10.0)])
    assert s["missing_steps"] == {"extra": ["run-2"]}
    assert s["all_runs_agree"] is False
    assert s["steps"]["extra"]["all_agree"] is False


def test_network_policies_shape() -> None:
    pols = {(p["metadata"]["namespace"], p["metadata"]["name"]): p for p in rc.network_policies("172.18.0.2", 6443)}
    assert pols[("canary", "default-deny-ingress")]["spec"] == {"podSelector": {}, "policyTypes": ["Ingress"]}
    src = pols[("canary", "canary-from-demo")]["spec"]["ingress"][0]["from"]
    assert src == [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "demo"}}}]
    egress = pols[("demo", "attacker-egress")]["spec"]
    assert egress["podSelector"] == {"matchLabels": {"afterlock.dev/actor": "attacker"}}
    assert egress["policyTypes"] == ["Egress"]
    assert {"to": [{"ipBlock": {"cidr": "172.18.0.2/32"}}], "ports": [{"protocol": "TCP", "port": 6443}]} in egress["egress"]
    assert all(p["metadata"]["labels"]["afterlock.dev/lab"] == "true" for p in pols.values())


def test_label_mapping_uses_only_observations() -> None:
    assert lab_labels.label_for("protect-secret", 200) == "violated"
    assert lab_labels.label_for("protect-secret", 422) == "satisfied_within_scope"
    assert lab_labels.label_for("protect-canary", 0) is None
    assert lab_labels.label_for("legitimate:release-canary", 200) == "preserved"
    assert lab_labels.label_for("legitimate:release-canary", 401) == "broken"


def test_derive_is_independent_of_model_fields() -> None:
    step = {"step": "residual-token-still-reads-secret", "observed_http_status": 200}
    a = lab_labels.derive({"r1.json": {"receipts": [{**step, "model_prediction": "violated", "agrees": True}]}})
    b = lab_labels.derive({"r1.json": {"receipts": [{**step, "model_prediction": "satisfied_within_scope", "agrees": False}]}})
    assert a == b
    assert a["labels"]["residual-token"]["protect-secret"]["label"] == "violated"
    assert a["labels"]["residual-token"]["protect-secret"]["evidence"] == [{"receipt": "r1.json", **step}]


def test_derive_disputed_unmapped_and_no_answer() -> None:
    docs = {
        "r1.json": {"receipts": [
            {"step": "s", "replay_case": "c", "objective": "protect-canary", "observed_http_status": 200},
            {"step": "isolation-outsider-cannot-reach-canary", "observed_http_status": 0},
            {"step": "q", "replay_case": "c", "objective": "protect-secret", "observed_http_status": 0},
        ]},
        "r2.json": {"receipts": [{"step": "s", "replay_case": "c", "objective": "protect-canary", "observed_http_status": 401}]},
    }
    out = lab_labels.derive(docs)
    entry = out["labels"]["c"]["protect-canary"]
    assert entry["label"] == "disputed" and entry["observed_labels"] == ["satisfied_within_scope", "violated"]
    assert len(entry["evidence"]) == 2
    reasons = sorted(u["reason"] for u in out["unlabeled"])
    assert reasons == ["no answer observed", "step not mapped to a replay case"]


def test_committed_lab_labels_match_receipts() -> None:
    committed = json.loads((ROOT / "benchmarks/labels/lab-derived.json").read_text())
    assert committed == lab_labels.derive(lab_labels.load_receipts())


def test_benchmark_compares_lab_labels_per_objective() -> None:
    bench = _load("bench_run", "benchmarks/run.py")
    bundle = {"objectives": [{"id": "protect-secret", "status": "violated"}, {"id": "protect-canary", "status": "violated"}],
              "legitimate_operations": [{"id": "release-canary", "preserved": True}]}
    bundles = {(case, mode): bundle for case in ("residual-token", "copied-downstream", "admission-denied", "targeted-containment")
               for mode in bench.MODES}
    out = bench.lab_derived(bundles)
    assert out["available"] is True
    labels = json.loads((ROOT / "benchmarks/labels/lab-derived.json").read_text())["labels"]
    n = sum(len(o) for o in labels.values())
    expected = sum(1 for objs in labels.values() for o, e in objs.items()
                   if e["label"] == ("preserved" if o.startswith("legitimate:") else "violated"))
    for s in out["summary"].values():
        assert s == {"labels": n, "agreement": expected}
