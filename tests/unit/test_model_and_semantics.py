from __future__ import annotations

import copy
from typing import Any

import pytest

from afterlock.model import ModelError, digest, parse_analysis_input
from afterlock.semantics import Env, admission_decision, authorizing_bindings, credential_usable

from conftest import case, raw_case
from helpers import statuses, with_

# ---------------------------------------------------------------- model


def test_digest_is_key_order_independent() -> None:
    assert digest({"a": 1, "b": [1, 2]}) == digest({"b": [1, 2], "a": 1})
    assert digest({"a": 1}) != digest({"a": 2})


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda r: r.update(schema="afterlock.analysis-input/2"), "major"),
        (lambda r: r.update(schema="something-else/1"), "schema"),
        (lambda r: r["inventory"]["secrets"][0].update(data={"k": "v"}), "never"),
        (lambda r: r["inventory"]["pods"].append(dict(r["inventory"]["pods"][0], name="dup")), "duplicate"),
        (lambda r: r.update(remediation=[{"kind": "delete_pod", "uid": "model-pod:demo:x:i0"}]), "reserved"),
        (lambda r: r.update(remediation=[{"kind": "format_disk"}]), "unsupported defender action"),
        (lambda r: r.update(remediation=[{"kind": "remove_binding", "name": "x", "shell": "rm -rf /"}]), "unknown fields"),
        (lambda r: r["initial_facts"].append({"kind": "telepathy", "args": [], "status": "observed"}), "fact kind"),
        (lambda r: r["initial_facts"][0].update(status="probably"), "epistemic"),
        (lambda r: r.update(objectives=[]), "objective"),
        (lambda r: r.update(bounds={"max_intervals": 1}, remediation=[{"kind": "wait", "seconds": 1}]), "max_intervals"),
    ],
)
def test_rejects_malformed_input(flagship_raw: dict[str, Any], mutate: Any, message: str) -> None:
    raw = copy.deepcopy(flagship_raw)
    mutate(raw)
    with pytest.raises(ModelError, match=message):
        parse_analysis_input(raw)


# ---------------------------------------------------------------- RBAC


def _env(name: str = "residual-token") -> Env:
    inp = case(name)
    return Env.from_inventory(inp.inventory, inp.analysis_time)


def test_resource_names_rule_never_authorizes_unnamed_requests() -> None:
    env = _env()
    rr = "system:serviceaccount:demo:release-reader"
    assert authorizing_bindings(env, rr, "get", "secrets", "demo", "release-credential") == ["demo/release-reader-secret"]
    assert authorizing_bindings(env, rr, "get", "secrets", "demo", "other") == []
    assert authorizing_bindings(env, rr, "list", "secrets", "demo", None) == []


def test_rolebinding_scopes_clusterrole_to_its_namespace() -> None:
    inp = case("alternative-binding")
    env = Env.from_inventory(inp.inventory, inp.analysis_time)
    ci = "system:serviceaccount:demo:ci-runner"
    assert "<cluster>/ci-launcher" in authorizing_bindings(env, ci, "create", "pods", "other-ns", None)
    assert sorted(authorizing_bindings(env, ci, "create", "pods", "demo", None)) == ["<cluster>/ci-launcher", "demo/ci-pod-creator"]
    del env.bindings[(None, "ci-launcher")]
    assert authorizing_bindings(env, ci, "create", "pods", "other-ns", None) == []


def test_group_subjects() -> None:
    env = _env()
    from afterlock.model import RoleBinding, Subject

    env.bindings[("demo", "all-sa")] = RoleBinding("demo", "all-sa", "Role", "pod-creator", (Subject("Group", "system:serviceaccounts:demo", None),))
    assert authorizing_bindings(env, "system:serviceaccount:demo:release-reader", "create", "pods", "demo", None) == ["demo/all-sa"]
    assert authorizing_bindings(env, "system:serviceaccount:other:x", "create", "pods", "demo", None) == []


# ---------------------------------------------------------------- credentials


def test_credential_usability_reasons() -> None:
    inp = case("residual-token")
    env = Env.from_inventory(inp.inventory, inp.analysis_time)
    cred = inp.credential("observed:pod-attacker-0001:https://kubernetes.default.svc.cluster.local")
    assert credential_usable(env, cred, inp.profile).usable
    del env.pods["pod-attacker-0001"]
    u = credential_usable(env, cred, inp.profile)
    assert not u.usable and "bound pod UID pod-attacker-0001 no longer exists" in u.reasons
    env = Env.from_inventory(inp.inventory, inp.analysis_time)
    from dataclasses import replace

    env.service_accounts[("demo", "release-reader")] = replace(env.service_accounts[("demo", "release-reader")], uid="recreated")
    assert "recreated with a different UID" in credential_usable(env, cred, inp.profile).reasons[0]
    u = credential_usable(env, replace(cred, kind="legacy_secret_token"), inp.profile)
    assert not u.supported


def test_admission_decisions() -> None:
    env = _env("admission-denied")
    ci = "system:serviceaccount:demo:ci-runner"
    assert admission_decision(env, ci, "demo", "release-reader").outcome == "deny"
    assert admission_decision(env, ci, "demo", "ci-runner").outcome == "allow"
    assert admission_decision(env, "someone-else", "demo", "release-reader").outcome == "allow"
    env = _env("admission-unsupported")
    assert admission_decision(env, ci, "demo", "ci-runner").outcome == "unsupported"


# ---------------------------------------------------------------- core properties from the design


def test_acquisition_survives_source_permission_removal(flagship_raw: dict[str, Any]) -> None:
    # Removing the binding that enabled pod creation leaves the created pod's token usable.
    concl, st = statuses(flagship_raw)
    assert concl == "residual_path" and st["protect-secret"] == "violated"


def test_knowledge_is_monotone_usability_is_not(flagship_raw: dict[str, Any]) -> None:
    raw = with_(flagship_raw, remediation=[
        {"kind": "remove_binding", "namespace": "demo", "name": "ci-pod-creator"},
        {"kind": "delete_pods_except", "namespace": "demo", "service_account": "release-reader", "keep_uids": ["pod-release-0001"]},
    ])
    from afterlock.engine import VIEW_EVIDENCE, run_view

    out = run_view(parse_analysis_input(raw), VIEW_EVIDENCE)
    assert ("knows_secret", "demo", "release-credential", "1") in out.derivations  # knowledge persists
    assert ("can_read_secret", "demo", "release-credential") in out.intervals[1].goals
    assert ("can_read_secret", "demo", "release-credential") not in out.intervals[2].goals  # usability revoked


def test_search_limit_never_establishes_containment() -> None:
    raw = with_(raw_case("targeted-containment"), bounds={"max_derivations": 3})
    concl, _ = statuses(raw)
    assert concl in ("unknown", "residual_path")
    assert concl != "contained_within_scope"


def test_unsupported_credential_is_visible(flagship_raw: dict[str, Any]) -> None:
    raw = copy.deepcopy(flagship_raw)
    raw["inventory"]["bindings"] = [b for b in raw["inventory"]["bindings"] if b["name"] != "ci-pod-creator"]
    raw["inventory"]["pods"] = [p for p in raw["inventory"]["pods"] if p["uid"] != "pod-attacker-0001"]
    raw["initial_facts"] = [f for f in raw["initial_facts"] if f["kind"] not in ("knows_secret",)]
    raw["credentials"].append({"id": "legacy", "kind": "legacy_secret_token", "username": "system:serviceaccount:demo:release-reader", "audience": "x"})
    raw["initial_facts"].append({"kind": "possesses_credential", "args": ["legacy"], "status": "assumed", "evidence": []})
    concl, _ = statuses(raw)
    assert concl == "unknown"
