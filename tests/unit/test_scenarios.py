"""Hand-authored semantic cases against independently written expectations."""

from __future__ import annotations

import pytest

from afterlock.results import analyze, explain

from conftest import EXPECTED, case


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_expected_outcome(name: str) -> None:
    exp = EXPECTED[name]
    bundle = analyze(case(name))
    assert bundle["conclusion"]["model"] == exp["conclusion"]
    got = {o["id"]: o["status"] for o in bundle["objectives"]}
    assert got == exp["objectives"]
    for op_id, preserved in exp.get("legitimate", {}).items():
        assert {o["id"]: o["preserved"] for o in bundle["legitimate_operations"]}[op_id] is preserved
    assert bundle["conclusion"]["validation"] == "not_executed"
    explain(bundle)  # renders without error


def test_flagship_witness_explains_residual_credential() -> None:
    bundle = analyze(case("residual-token"))
    w = {w["objective"]: w for w in bundle["witnesses"]}["protect-secret"]
    first, last = w["steps"][0], w["steps"][-1]
    assert first["rule"] == "EVIDENCE" and first["status"] == "observed"
    assert first["fact"][1].startswith("observed:pod-attacker-0001")
    assert last["fact"] == ["can_read_secret", "demo", "release-credential"]
    assert last["interval"] == 1  # after the remediation step
    authz = [c for c in last["conditions"] if c["check"] == "authorized"][0]
    assert authz["via"] == ["demo/release-reader-secret"]
    assert "lab-audit#2" in bundle["evidence_references"]


def test_contained_result_states_scope() -> None:
    bundle = analyze(case("targeted-containment"))
    assert bundle["analysis_bounds"]["exhausted"] is True
    assert "fixpoint" in bundle["conclusion"]["scope"]
    assert bundle["witnesses"] == []
    # attacker access during containment is reported separately from eventual containment
    assert [e["interval"] for e in bundle["exposure_during_containment"]] == [0, 1, 2]


def test_unknown_names_the_missing_evidence() -> None:
    bundle = analyze(case("incomplete-telemetry"))
    reasons = [r for o in bundle["objectives"] for r in o["reasons"]]
    assert any("audit-gap-1210" in r for r in reasons)
    bundle = analyze(case("admission-unsupported"))
    assert any(m["kind"] == "unsupported_admission" and m["policies"] == ["opaque-webhook"] for m in bundle["missing_coverage"])


def test_possible_state_residual_is_labelled_as_such() -> None:
    bundle = analyze(case("possible-read"))
    o = {o["id"]: o for o in bundle["objectives"]}["protect-canary"]
    assert o["status"] == "possibly_violated" and o["basis"] == "conservative_possible"
    w = bundle["witnesses"][0]
    assert any(s["interval"] == -1 for s in w["steps"])  # derived in the possible-history phase


def test_determinism() -> None:
    a = analyze(case("defender-race"))
    b = analyze(case("defender-race"))
    assert a == b and a["result_digest"] == b["result_digest"]
