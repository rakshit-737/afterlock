"""Phase 9 adversarial review: engine soundness regressions and a wider differential search.

See docs/security/review-2026-09-26-adversarial-engine.md. Each regression below was a
false containment: the engine (and in one case the reference checker too) reported
``contained_within_scope`` although the written semantics leave access in place.
"""

from __future__ import annotations

import copy
import os
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings

import afterlock_reference as ref
from afterlock.model import ModelError, parse_analysis_input
from afterlock.results import analyze

from differential.adversarial_generators import adversarial_inputs
from differential.test_engine_vs_reference import assert_agree

EXAMPLES = int(os.environ.get("AFTERLOCK_DIFFERENTIAL_EXAMPLES", "150"))
API = "https://kubernetes.default.svc.cluster.local"


def _raw(pods: list[dict[str, Any]], controllers: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """ci may create pods; admin may read secret n/s; the attacker holds ci's token."""
    return {
        "schema": "afterlock.analysis-input/1", "case_id": "adv", "cluster_id": "c", "analysis_time": 1000,
        "profile": {"id": "k8s-1.31-core-v1", "kubernetes_version": "1.31", "api_audiences": [API], "projected_token_ttl_seconds": 3600},
        "inventory": {
            "service_accounts": [{"namespace": "n", "name": "ci", "uid": "u-ci"}, {"namespace": "n", "name": "admin", "uid": "u-ad"}],
            "pods": pods, "controllers": controllers or [],
            "roles": [{"namespace": "n", "name": "cp", "rules": [{"verbs": ["create"], "resources": ["pods"]}]},
                      {"namespace": "n", "name": "rd", "rules": [{"verbs": ["get"], "resources": ["secrets"]}]}],
            "bindings": [
                {"namespace": "n", "name": "b0", "role_kind": "Role", "role_name": "cp", "subjects": [{"kind": "ServiceAccount", "namespace": "n", "name": "ci"}]},
                {"namespace": "n", "name": "b1", "role_kind": "Role", "role_name": "rd", "subjects": [{"kind": "ServiceAccount", "namespace": "n", "name": "admin"}]},
            ],
            "secrets": [{"namespace": "n", "name": "s", "uid": "x", "version": 1}], "services": [], "admission_policies": [],
        },
        "credentials": [{"id": "c0", "kind": "sa_token", "username": "system:serviceaccount:n:ci", "sa_uid": "u-ci", "audience": API}],
        "initial_facts": [{"kind": "possesses_credential", "args": ["c0"], "status": "assumed", "evidence": []}],
        "remediation": [],
        "objectives": [{"id": "o", "kind": "no_secret_read", "namespace": "n", "secret": "s"}],
    }


def test_baseline_attacker_reads_secret_via_created_pod() -> None:
    raw = _raw([])
    assert analyze(parse_analysis_input(raw))["conclusion"]["model"] == "residual_path"
    assert ref.explore(raw)["views"]["evidence_supported"]["reachable_objectives"] == ["o"]


@pytest.mark.parametrize(
    "field,obj",
    [
        ("pods", {"namespace": "n", "name": "decoy", "uid": "model-pod:n:admin:i0", "service_account": "ci"}),
        ("controllers", {"namespace": "n", "name": "decoy", "uid": "model-deploy:n:admin:i0", "service_account": "ci"}),
    ],
)
def test_inventory_objects_cannot_use_reserved_model_uids(field: str, obj: dict[str, Any]) -> None:
    """A-1: an inventory Pod whose UID equals the engine's model UID for (n, admin, i0)
    made the engine skip modelling the attacker's Pod creation and report containment,
    while the reference checker (and the semantics) reach the secret."""
    raw = _raw([])
    raw["inventory"][field] = [obj]
    with pytest.raises(ModelError, match="reserved"):
        parse_analysis_input(raw)


@pytest.mark.parametrize("kind", ["controls_pod", "controls_controller"])
def test_initial_facts_cannot_use_reserved_model_uids(kind: str) -> None:
    raw = _raw([])
    raw["initial_facts"].append({"kind": kind, "args": ["model-pod:n:admin:i0"], "status": "observed", "evidence": []})
    with pytest.raises(ModelError, match="reserved"):
        parse_analysis_input(raw)


def test_historical_pod_cannot_use_reserved_model_uid() -> None:
    raw = _raw([])
    raw["initial_facts"].append({"kind": "historical_pod", "args": ["model-pod:n:admin:i0", "n", "admin"], "status": "observed", "evidence": []})
    with pytest.raises(ModelError, match="reserved"):
        parse_analysis_input(raw)


def test_controller_replacement_does_not_overwrite_an_existing_pod() -> None:
    """A-2: S-WL-2 names replacement Pods ``<controller>-p<k>``. When an unrelated Pod
    already had that UID, both implementations replaced it, so the attacker lost
    control of an admin Pod it still controls. Both reported containment."""
    raw = _raw([{"namespace": "n", "name": "x", "uid": "ctrl-p1", "service_account": "admin"}],
               [{"namespace": "n", "name": "c", "uid": "ctrl", "service_account": "ci"}])
    raw["credentials"] = []
    raw["inventory"]["bindings"] = raw["inventory"]["bindings"][1:]  # no pod creation at all
    raw["initial_facts"] = [{"kind": "controls_pod", "args": ["ctrl-p1"], "status": "observed", "evidence": []}]
    bundle = analyze(parse_analysis_input(raw))
    assert bundle["conclusion"]["model"] == "residual_path"
    assert ref.explore(raw)["views"]["evidence_supported"]["reachable_objectives"] == ["o"]
    assert all(r["valid"] for r in ref.verify_witnesses(raw, bundle).values())
    # the controller still gets its replacement Pod, under a fresh UID
    tl = bundle["timeline"][0]["reconciled_pods"]
    assert len(tl) == 1 and tl[0] != "ctrl-p1" and tl[0].startswith("ctrl-p")


@pytest.mark.parametrize("verb", ["list", "watch"])
def test_list_or_watch_on_secrets_reads_them(verb: str) -> None:
    """A-3: Kubernetes returns Secret data to list and watch. Only ``get`` was modelled,
    so a credential holding only ``list secrets`` was reported as contained."""
    raw = _raw([])
    raw["inventory"]["roles"][1]["rules"] = [{"verbs": [verb], "resources": ["secrets"]}]
    raw["inventory"]["bindings"] = [{"namespace": "n", "name": "b1", "role_kind": "Role", "role_name": "rd",
                                     "subjects": [{"kind": "ServiceAccount", "namespace": "n", "name": "ci"}]}]
    raw["inventory"]["services"] = [{"name": "svc", "source_namespace": "n", "source_secret": "s", "accepted_version": 1}]
    raw["objectives"].append({"id": "d", "kind": "no_downstream_use", "service": "svc"})
    raw["remediation"] = [{"kind": "remove_binding", "namespace": "n", "name": "b1"}]
    bundle = analyze(parse_analysis_input(raw))
    assert {o["id"]: o["status"] for o in bundle["objectives"]} == {"o": "satisfied_within_scope", "d": "violated"}
    assert assert_agree(raw)
    assert all(r["valid"] for r in ref.verify_witnesses(raw, bundle).values())
    raw["remediation"] = []
    assert analyze(parse_analysis_input(raw))["conclusion"]["model"] == "residual_path"
    assert ref.explore(raw)["views"]["evidence_supported"]["reachable_objectives"] == ["d", "o"]


def test_list_with_resource_names_reads_only_named_secrets() -> None:
    """Negative control: a resourceNames-restricted list rule (usable with a
    metadata.name field selector) covers the named Secret only."""
    raw = _raw([])
    raw["inventory"]["secrets"].append({"namespace": "n", "name": "other", "uid": "y", "version": 1})
    raw["inventory"]["roles"][1]["rules"] = [{"verbs": ["list"], "resources": ["secrets"], "resource_names": ["other"]}]
    raw["inventory"]["bindings"] = [{"namespace": "n", "name": "b1", "role_kind": "Role", "role_name": "rd",
                                     "subjects": [{"kind": "ServiceAccount", "namespace": "n", "name": "ci"}]}]
    assert analyze(parse_analysis_input(raw))["conclusion"]["model"] == "contained_within_scope"
    assert assert_agree(raw)


def test_expiry_on_the_interval_boundary_is_expired() -> None:
    """S-TOK-1 is strict (time < expires_at); a wait landing exactly on expiry contains."""
    raw = _raw([])
    raw["inventory"]["bindings"][0] = {"namespace": "n", "name": "b0", "role_kind": "Role", "role_name": "rd",
                                       "subjects": [{"kind": "ServiceAccount", "namespace": "n", "name": "ci"}]}
    raw["credentials"][0]["expires_at"] = 1600
    for seconds, expected in ((599, "residual_path"), (600, "contained_within_scope")):
        r = copy.deepcopy(raw)
        r["remediation"] = [{"kind": "wait", "seconds": seconds}]
        assert analyze(parse_analysis_input(r))["conclusion"]["model"] == expected
        assert assert_agree(r)


@settings(max_examples=EXAMPLES, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
@given(adversarial_inputs())
def test_adversarial_generated_cases_agree(raw: dict[str, Any]) -> None:
    assert_agree(raw, live=1, max_states=20_000)


@settings(max_examples=max(EXAMPLES // 3, 10), deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
@given(adversarial_inputs(max_actions=2))
def test_adversarial_generated_witnesses_are_valid(raw: dict[str, Any]) -> None:
    bundle = analyze(parse_analysis_input(raw))
    for wid, r in ref.verify_witnesses(raw, bundle).items():
        assert r["valid"], (wid, r["problems"])
