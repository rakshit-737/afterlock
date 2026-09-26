"""S-TOK-1 in the possible-history phase (final audit R1, engine review U-1).

Expiry is evaluated at the time each hypothetical use would occur, not at
analysis time. A seeded token that expired before analysis time was usable at
every earlier point of the history window ``[history_start, analysis_time)``
at which it was unexpired, and whatever it yielded then (Secret knowledge,
control of Pods that still exist) carries forward in the conservative view.

Positive cases, negative controls, the equal-timestamp edges, and a property
test that the engine and the independent reference checker agree for expiry
times before, at, inside and after the history window.
"""

from __future__ import annotations

import copy
import os
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import afterlock_reference as ref
from afterlock.model import ModelError, parse_analysis_input
from afterlock.results import analyze

API = "https://kubernetes.default.svc.cluster.local"
T0 = 1_000_000
EXAMPLES = int(os.environ.get("AFTERLOCK_DIFFERENTIAL_EXAMPLES", "150"))


def _case(expires_at: int | None, history_start: int | None = None, path: str = "read") -> dict[str, Any]:
    """s0's seeded token; s0 may read sec0 (feeding svc0) or exec into p1 (runs as s1, which may read sec0)."""
    rules = {"read": [{"verbs": ["get"], "resources": ["secrets"]}],
             "exec": [{"verbs": ["create"], "resources": ["pods/exec"]}]}[path]
    cred: dict[str, Any] = {"id": "c0", "kind": "sa_token", "username": "system:serviceaccount:n:s0", "sa_uid": "u0", "audience": API}
    if expires_at is not None:
        cred["expires_at"] = expires_at
    raw: dict[str, Any] = {
        "schema": "afterlock.analysis-input/1", "case_id": "history-expiry", "cluster_id": "gen", "analysis_time": T0,
        "profile": {"id": "k8s-1.31-core-v1", "kubernetes_version": "1.31", "api_audiences": [API], "projected_token_ttl_seconds": 3600},
        "inventory": {
            "service_accounts": [{"namespace": "n", "name": "s0", "uid": "u0"}, {"namespace": "n", "name": "s1", "uid": "u1"}],
            "pods": [{"namespace": "n", "name": "p1", "uid": "pod-1", "service_account": "s1"}],
            "controllers": [],
            "roles": [{"namespace": "n", "name": "r0", "rules": rules},
                      {"namespace": "n", "name": "read", "rules": [{"verbs": ["get"], "resources": ["secrets"]}]}],
            "bindings": [
                {"namespace": "n", "name": "b0", "role_kind": "Role", "role_name": "r0", "subjects": [{"kind": "ServiceAccount", "namespace": "n", "name": "s0"}]},
                {"namespace": "n", "name": "b1", "role_kind": "Role", "role_name": "read", "subjects": [{"kind": "ServiceAccount", "namespace": "n", "name": "s1"}]},
            ],
            "secrets": [{"namespace": "n", "name": "sec0", "uid": "x", "version": 1}],
            "services": [{"name": "svc0", "source_namespace": "n", "source_secret": "sec0", "accepted_version": 1}],
            "admission_policies": [],
        },
        "credentials": [cred],
        "initial_facts": [{"kind": "possesses_credential", "args": ["c0"], "status": "observed", "evidence": []}],
        "remediation": [],
        "objectives": [{"id": "o-sec0", "kind": "no_secret_read", "namespace": "n", "secret": "sec0"},
                       {"id": "o-svc0", "kind": "no_downstream_use", "service": "svc0"}],
    }
    if path == "read":
        raw["inventory"]["bindings"].pop()  # s1 cannot read: only the seeded token's own read matters
    if history_start is not None:
        raw["history_start"] = history_start
    return raw


def _statuses(raw: dict[str, Any]) -> dict[str, str]:
    bundle = analyze(parse_analysis_input(raw))
    for r in ref.verify_witnesses(raw, bundle).values():
        assert r["valid"], r["problems"]
    return {o["id"]: o["status"] for o in bundle["objectives"]}


def _reference(raw: dict[str, Any]) -> list[str]:
    res = ref.explore(raw)["views"]["conservative_possible"]
    assert res["complete"]
    return list(res["reachable_objectives"])


def test_expired_before_analysis_but_valid_in_history_yields_downstream_use() -> None:
    raw = _case(T0 - 100)
    # Old behaviour (expiry at analysis time) reported both objectives satisfied.
    assert _statuses(raw) == {"o-sec0": "satisfied_within_scope", "o-svc0": "possibly_violated"}
    assert _reference(raw) == ["o-svc0"]


def test_expired_token_exec_in_history_controls_a_pod_that_still_exists() -> None:
    raw = _case(T0 - 100, path="exec")
    assert _statuses(raw) == {"o-sec0": "possibly_violated", "o-svc0": "possibly_violated"}
    assert _reference(raw) == ["o-sec0", "o-svc0"]


def test_evidence_view_does_not_assume_history() -> None:
    bundle = analyze(parse_analysis_input(_case(T0 - 100)))
    assert all(o["status"] != "violated" for o in bundle["objectives"])


@pytest.mark.parametrize(("expires_at", "history_start", "expected"), [
    (T0 - 100, T0 - 50, []),          # negative control: expired before the window opened
    (T0 - 100, T0 - 100, []),         # edge: expires exactly when the window opens (strict <)
    (T0 - 100, T0 - 101, ["o-svc0"]),  # edge: one second of validity inside the window
    (T0, T0, []),                     # window of zero length at the expiry instant
    (T0, T0 - 1, ["o-svc0"]),
    (T0 + 1, T0, ["o-sec0", "o-svc0"]),  # still valid at analysis time: unchanged behaviour
    (None, T0, ["o-sec0", "o-svc0"]),
])
def test_history_window_boundaries(expires_at: int | None, history_start: int, expected: list[str]) -> None:
    raw = _case(expires_at, history_start)
    got = [k for k, v in _statuses(raw).items() if v in ("violated", "possibly_violated")]
    assert got == expected
    assert _reference(raw) == expected


def test_history_start_is_optional_and_validated() -> None:
    assert _statuses(_case(T0 + 10))["o-svc0"] == "violated"
    with pytest.raises(ModelError):
        parse_analysis_input(_case(T0 - 100, history_start=T0 + 1))
    bad = _case(T0 - 100)
    bad["history_start"] = "yesterday"
    with pytest.raises(ModelError):
        parse_analysis_input(bad)


@settings(max_examples=max(EXAMPLES // 3, 10), deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    st.sampled_from(["read", "exec"]),
    st.one_of(st.none(), st.integers(-3, 3).map(lambda d: T0 - 100 + d), st.integers(-1, 1).map(lambda d: T0 + d)),
    st.one_of(st.none(), st.integers(-3, 3).map(lambda d: T0 - 100 + d), st.just(T0)),
    st.lists(st.sampled_from([{"kind": "wait", "seconds": 50}, {"kind": "remove_binding", "namespace": "n", "name": "b0"},
                              {"kind": "rotate_downstream_credential", "service": "svc0"}]), max_size=2),
)
def test_engine_and_reference_agree_on_history_expiry(path: str, expires_at: int | None, history_start: int | None,
                                                      remediation: list[dict[str, Any]]) -> None:
    raw = _case(expires_at, history_start, path)
    raw["remediation"] = copy.deepcopy(remediation)
    bundle = analyze(parse_analysis_input(raw))
    engine = sorted(o["id"] for o in bundle["objectives"] if o["status"] in ("violated", "possibly_violated"))
    assert engine == _reference(raw)
    for r in ref.verify_witnesses(raw, bundle).values():
        assert r["valid"], r["problems"]
