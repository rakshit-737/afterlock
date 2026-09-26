"""Differential tests: production engine vs. independent reference explorer."""

from __future__ import annotations

import copy
import os
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings

import afterlock_reference as ref
from afterlock.engine import VIEW_EVIDENCE, VIEW_POSSIBLE, objective_goal, run_view
from afterlock.model import parse_analysis_input
from afterlock.results import analyze

from conftest import EXPECTED, raw_case
from differential.generators import analysis_inputs

EXAMPLES = int(os.environ.get("AFTERLOCK_DIFFERENTIAL_EXAMPLES", "150"))


def engine_sets(raw: dict[str, Any]) -> dict[str, list[str]]:
    inp = parse_analysis_input(raw)
    out = {}
    for view in (VIEW_EVIDENCE, VIEW_POSSIBLE):
        v = run_view(inp, view)
        out[view] = sorted(o.id for o in inp.objectives if objective_goal(o.kind, o.target) in v.goals_final)
    return out


def assert_agree(raw: dict[str, Any], live: int = 1, max_states: int = 60_000) -> bool:
    r = ref.explore(raw, ref.ReferenceLimits(max_states=max_states, max_live_attacker_workloads_per_sa=live))
    e = engine_sets(raw)
    complete = True
    for view, res in r["views"].items():
        if not res["complete"]:
            complete = False
            continue
        assert e[view] == res["reachable_objectives"], f"{view}: engine {e[view]} vs reference {res['reachable_objectives']}"
    # unsupported semantics must be reported by both
    bundle = analyze(parse_analysis_input(raw))
    eng_unsupported = any(m["kind"].startswith("unsupported") for m in bundle["missing_coverage"])
    ref_unsupported = any(res["unknown"] for res in r["views"].values())
    if complete:
        assert eng_unsupported == ref_unsupported
    return complete


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_semantic_cases_agree(name: str) -> None:
    assert assert_agree(raw_case(name), live=1, max_states=100_000)


@pytest.mark.parametrize("name", ["residual-token", "targeted-containment", "defender-race", "alternative-binding", "copied-downstream"])
def test_semantic_cases_agree_with_two_live_attacker_workloads(name: str) -> None:
    # A wider attacker (two live workloads per service account) must not reach
    # anything the engine's one-representative canonicalization misses.
    assert assert_agree(raw_case(name), live=2, max_states=100_000)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_witnesses_replay_in_reference_checker(name: str) -> None:
    raw = raw_case(name)
    bundle = analyze(parse_analysis_input(raw))
    report = ref.verify_witnesses(raw, bundle)
    assert len(report) == len(bundle["witnesses"])
    for wid, r in report.items():
        assert r["valid"], (wid, r["problems"])


@settings(max_examples=EXAMPLES, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(analysis_inputs())
def test_generated_cases_agree(raw: dict[str, Any]) -> None:
    assert_agree(raw, live=1)


@settings(max_examples=max(EXAMPLES // 3, 10), deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(analysis_inputs(max_actions=2))
def test_generated_witnesses_are_valid(raw: dict[str, Any]) -> None:
    bundle = analyze(parse_analysis_input(raw))
    for wid, r in ref.verify_witnesses(raw, bundle).items():
        assert r["valid"], (wid, r["problems"])


# ------------------------------------------------------------------ metamorphic


@settings(max_examples=max(EXAMPLES // 3, 10), deadline=None)
@given(analysis_inputs())
def test_irrelevant_namespace_does_not_change_conclusions(raw: dict[str, Any]) -> None:
    base = analyze(parse_analysis_input(raw))
    noisy = copy.deepcopy(raw)
    inv = noisy["inventory"]
    inv["service_accounts"].append({"namespace": "unrelated", "name": "x", "uid": "uid-unrelated-x"})
    inv["pods"].append({"namespace": "unrelated", "name": "x", "uid": "pod-unrelated", "service_account": "x"})
    inv["secrets"].append({"namespace": "unrelated", "name": "s", "uid": "sec-unrelated", "version": 3})
    other = analyze(parse_analysis_input(noisy))
    assert base["conclusion"]["model"] == other["conclusion"]["model"]
    assert [o["status"] for o in base["objectives"]] == [o["status"] for o in other["objectives"]]


@settings(max_examples=max(EXAMPLES // 3, 10), deadline=None)
@given(analysis_inputs())
def test_input_order_does_not_change_result(raw: dict[str, Any]) -> None:
    shuffled = copy.deepcopy(raw)
    for key in ("pods", "bindings", "roles", "service_accounts"):
        shuffled["inventory"][key].reverse()
    shuffled["initial_facts"].reverse()
    shuffled["credentials"].reverse()
    a = analyze(parse_analysis_input(raw))
    b = analyze(parse_analysis_input(shuffled))
    strip = lambda x: {k: v for k, v in x.items() if k not in ("input_digest", "result_digest")}  # noqa: E731
    assert strip(a) == strip(b)


@settings(max_examples=max(EXAMPLES // 3, 10), deadline=None)
@given(analysis_inputs())
def test_evidence_view_never_worse_than_possible_view(raw: dict[str, Any]) -> None:
    e = engine_sets(raw)
    assert set(e[VIEW_EVIDENCE]) <= set(e[VIEW_POSSIBLE])


def test_regression_witness_includes_model_controller_creation() -> None:
    """Found by Hypothesis: exec into a pod of an attacker-created controller must
    carry the controller's creation in the witness, or the checker cannot replay it."""
    from differential.generators import API

    raw = {
        "schema": "afterlock.analysis-input/1", "case_id": "regression-exec-model-pod", "cluster_id": "gen", "analysis_time": 1_000_000,
        "profile": {"id": "k8s-1.31-core-v1", "kubernetes_version": "1.31", "api_audiences": [API], "projected_token_ttl_seconds": 3600},
        "inventory": {
            "service_accounts": [{"namespace": "n", "name": "s0", "uid": "u0"}, {"namespace": "n", "name": "s1", "uid": "u1"}],
            "pods": [], "controllers": [],
            "roles": [{"namespace": "n", "name": "r", "rules": [{"verbs": ["create"], "resources": ["deployments", "pods/exec"]}]},
                      {"namespace": "n", "name": "read", "rules": [{"verbs": ["get"], "resources": ["secrets"]}]}],
            "bindings": [{"namespace": "n", "name": "b0", "role_kind": "Role", "role_name": "r", "subjects": [{"kind": "ServiceAccount", "namespace": "n", "name": "s0"}]},
                         {"namespace": "n", "name": "b1", "role_kind": "Role", "role_name": "read", "subjects": [{"kind": "ServiceAccount", "namespace": "n", "name": "s1"}]}],
            "secrets": [{"namespace": "n", "name": "sec0", "uid": "x", "version": 1}], "services": [], "admission_policies": [],
        },
        "credentials": [{"id": "c0", "kind": "sa_token", "username": "system:serviceaccount:n:s0", "sa_uid": "u0", "audience": API}],
        "initial_facts": [{"kind": "possesses_credential", "args": ["c0"], "status": "assumed", "evidence": []}],
        "remediation": [{"kind": "remove_binding", "namespace": "n", "name": "b0"}],
        "objectives": [{"id": "o", "kind": "no_secret_read", "namespace": "n", "secret": "sec0"}],
    }
    bundle = analyze(parse_analysis_input(raw))
    assert bundle["conclusion"]["model"] == "residual_path"
    for r in ref.verify_witnesses(raw, bundle).values():
        assert r["valid"], r["problems"]
    assert_agree(raw, live=1)


def test_regression_possible_history_includes_exec() -> None:
    """Found by Hypothesis (reference at two live workloads): in the possible-history
    phase the engine skipped pods/exec, missing control of Pods that still exist."""
    import json
    from pathlib import Path

    raw = json.loads((Path(__file__).parent / "regression_history_exec.json").read_text())
    assert engine_sets(raw)[VIEW_POSSIBLE] == ["o-sec0", "o-svc0"]
    assert assert_agree(raw, live=2)
    bundle = analyze(parse_analysis_input(raw))
    assert all(r["valid"] for r in ref.verify_witnesses(raw, bundle).values())
