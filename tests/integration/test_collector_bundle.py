"""The Go collector's golden bundle is a valid afterlock.replay/1 bundle.

services/collector/testdata/golden-bundle is written by the collector's own
test (`go test ./internal/bundle -run TestGoldenBundle -update`) and checked
byte-for-byte by `go test ./...`. This test proves the Python loader, envelope
validation and projection accept it. Nothing here is skipped: a missing bundle
is a failure.
"""

from __future__ import annotations

import json

from afterlock.evidence import FORBIDDEN_KEYS, SENSITIVE_PATTERNS, ReplayBundle, project, validate_envelope

from conftest import ROOT

GOLDEN = ROOT / "services" / "collector" / "testdata" / "golden-bundle"


def _load() -> ReplayBundle:
    assert GOLDEN.is_dir(), f"collector golden bundle missing at {GOLDEN}"
    return ReplayBundle.load(GOLDEN)


def test_golden_bundle_loads_with_valid_manifest() -> None:
    bundle = _load()
    assert bundle.manifest["schema"] == "afterlock.replay/1"
    assert bundle.manifest["cluster_id"] == "lab-local"


def test_every_collector_envelope_validates() -> None:
    bundle = _load()
    lines = [line for line in bundle.event_lines if line.strip()]
    assert lines
    for line in lines:
        env, problems = validate_envelope(json.loads(line), bundle.manifest["cluster_id"])
        assert env is not None, problems


def test_projection_accepts_collector_bundle() -> None:
    analysis_input, diag = project(_load())
    assert diag["rejected"] == [] and diag["conflicts"] == [] and diag["duplicates"] == 0
    kinds = {(f["kind"], tuple(f["args"])) for f in analysis_input["initial_facts"]}
    # The correlated Pod create and the Secret read are attributed to the attacker.
    assert ("controls_pod", ("pod-attacker-0001",)) in kinds
    assert ("knows_secret", ("demo", "release-credential", "1")) in kinds
    gap_ids = {g["id"] for g in analysis_input["coverage_gaps"]}
    # Collector gaps (unmodeled impersonation, malformed records, uncorrelated Pod) stay visible.
    assert any(":audit-unmodeled:" in g for g in gap_ids)
    assert any(":pod-uncorrelated:" in g for g in gap_ids)
    assert not any(g.startswith("stale:") for g in gap_ids)


def test_golden_bundle_carries_no_credential_material() -> None:
    for path in GOLDEN.iterdir():
        text = path.read_text("utf-8")
        assert "AFTERLOCK-CANARY" not in text
        for pat in SENSITIVE_PATTERNS:
            assert not pat.search(text), f"{path.name} matches {pat.pattern}"
    for line in _load().event_lines:
        stack = [json.loads(line)]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                assert not {k.lower() for k in value} & FORBIDDEN_KEYS
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
