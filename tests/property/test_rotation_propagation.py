"""S-SEC-5: downstream rotation modelled as a non-instantaneous window.

Positive case, negative control, backward compatibility, and a property test
that the engine and the independent reference checker agree for every delay
and wait combination.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import afterlock_reference as ref
from afterlock.model import ModelError, parse_analysis_input
from afterlock.planner import candidate_actions
from afterlock.results import analyze

from conftest import raw_case


def _with_delay(delay: int | None, extra: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    raw = copy.deepcopy(raw_case("targeted-containment"))
    if delay is not None:
        raw["inventory"]["services"][0]["rotation_propagation_seconds"] = delay
    raw["remediation"] = list(raw["remediation"]) + (extra or [])
    return raw


def _status(bundle: dict[str, Any], oid: str) -> str:
    return {o["id"]: o["status"] for o in bundle["objectives"]}[oid]


def test_absent_field_matches_zero_delay() -> None:
    a = analyze(parse_analysis_input(_with_delay(None)))
    b = analyze(parse_analysis_input(_with_delay(0)))
    assert a["conclusion"] == b["conclusion"]
    assert a["objectives"] == b["objectives"]
    assert a["conclusion"]["model"] == "contained_within_scope"


def test_positive_rotation_without_wait_leaves_copied_credential_usable() -> None:
    raw = _with_delay(55)
    bundle = analyze(parse_analysis_input(raw))
    assert bundle["conclusion"]["model"] == "residual_path"
    assert _status(bundle, "protect-canary") == "violated"
    assert _status(bundle, "protect-secret") == "satisfied_within_scope"
    for r in ref.verify_witnesses(raw, bundle).values():
        assert r["valid"], r["problems"]
    use = [s for w in bundle["witnesses"] for s in w["steps"] if s["rule"] == "R-USE-DOWNSTREAM"]
    assert use and use[-1]["conditions"][0]["version"] == 1


def test_negative_control_waiting_past_propagation_contains() -> None:
    bundle = analyze(parse_analysis_input(_with_delay(55, [{"kind": "wait", "seconds": 55}])))
    assert bundle["conclusion"]["model"] == "contained_within_scope"


def test_wait_shorter_than_propagation_is_not_enough() -> None:
    bundle = analyze(parse_analysis_input(_with_delay(55, [{"kind": "wait", "seconds": 54}])))
    assert _status(bundle, "protect-canary") == "violated"


def test_negative_delay_rejected() -> None:
    with pytest.raises(ModelError):
        parse_analysis_input(_with_delay(-1))


def test_planner_offers_propagation_wait() -> None:
    kinds = {(a.kind, a.opt("seconds")) for a in candidate_actions(parse_analysis_input(_with_delay(55)))}
    assert ("wait", "55") in kinds
    assert all(a.kind != "wait" for a in candidate_actions(parse_analysis_input(_with_delay(None))))


@settings(max_examples=40, deadline=None)
@given(delay=st.integers(0, 120), wait=st.one_of(st.none(), st.integers(1, 150)))
def test_engine_and_reference_agree_on_propagation_window(delay: int, wait: int | None) -> None:
    raw = _with_delay(delay, [{"kind": "wait", "seconds": wait}] if wait else [])
    bundle = analyze(parse_analysis_input(raw))
    expected_open = delay > 0 and (wait or 0) < delay
    assert (_status(bundle, "protect-canary") == "violated") is expected_open
    r = ref.explore(raw, ref.ReferenceLimits(max_states=100_000, max_live_attacker_workloads_per_sa=1))
    for view in ("evidence_supported", "conservative_possible"):
        assert r["views"][view]["complete"]
        eng = sorted(o["id"] for o in bundle["objectives"] if o["status"] in ("violated", "possibly_violated"))
        if view == "conservative_possible":
            assert eng == r["views"][view]["reachable_objectives"]
    for w in ref.verify_witnesses(raw, bundle).values():
        assert w["valid"], w["problems"]
