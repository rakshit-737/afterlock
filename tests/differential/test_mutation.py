"""Mutation checks: deliberately broken semantics must be caught by the suite.

Each mutant removes one consequential check. The hand-authored expectations
and the independent reference checker must each detect it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

import afterlock.engine as engine
import afterlock_reference as ref
from afterlock import semantics
from afterlock.model import parse_analysis_input
from afterlock.results import analyze

from conftest import EXPECTED, raw_case


def _ignore_bound_pod(env: Any, cred: Any, profile: Any) -> semantics.Usability:
    return semantics.credential_usable(env, replace(cred, bound_pod_uid=None), profile)


def _ignore_expiry(env: Any, cred: Any, profile: Any) -> semantics.Usability:
    return semantics.credential_usable(env, replace(cred, expires_at=None), profile)


def _ignore_audience(env: Any, cred: Any, profile: Any) -> semantics.Usability:
    return semantics.credential_usable(env, replace(cred, audience=profile.api_audiences[0]), profile)


def _unsupported_admission_allows(env: Any, creator: str, ns: str, sa: str) -> semantics.AdmissionDecision:
    d = semantics.admission_decision(env, creator, ns, sa)
    return semantics.AdmissionDecision("allow", d.policies) if d.outcome == "unsupported" else d


MUTANTS: dict[str, tuple[str, Callable[..., Any]]] = {
    "ignore-bound-pod": ("credential_usable", _ignore_bound_pod),
    "ignore-expiry": ("credential_usable", _ignore_expiry),
    "ignore-audience": ("credential_usable", _ignore_audience),
    "unsupported-admission-allows": ("admission_decision", _unsupported_admission_allows),
}


def _mismatches() -> list[str]:
    bad = []
    for name, exp in EXPECTED.items():
        b = analyze(parse_analysis_input(raw_case(name)))
        if b["conclusion"]["model"] != exp["conclusion"]:
            bad.append(name)
    return bad


@pytest.mark.parametrize("mutant", sorted(MUTANTS))
def test_mutant_is_killed_by_expectations(mutant: str, monkeypatch: pytest.MonkeyPatch) -> None:
    attr, fn = MUTANTS[mutant]
    monkeypatch.setattr(engine, attr, fn)
    assert _mismatches(), f"mutant {mutant} survived the hand-authored expectations"


@pytest.mark.parametrize("mutant", ["ignore-bound-pod", "ignore-expiry", "ignore-audience"])
def test_mutant_is_killed_by_reference_checker(mutant: str, monkeypatch: pytest.MonkeyPatch) -> None:
    attr, fn = MUTANTS[mutant]
    monkeypatch.setattr(engine, attr, fn)
    caught = False
    for name in EXPECTED:
        raw = raw_case(name)
        b = analyze(parse_analysis_input(raw))
        if any(not r["valid"] for r in ref.verify_witnesses(raw, b).values()):
            caught = True
            break
    assert caught, f"mutant {mutant} produced only witnesses the reference checker accepted"
