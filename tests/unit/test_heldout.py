"""Held-out templates: determinism, label independence, and engine agreement."""

from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from afterlock.model import parse_analysis_input
from afterlock.results import analyze

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "datasets/generators/build_heldout_cases.py"
HELDOUT = ROOT / "datasets/heldout"
LABELS = json.loads((HELDOUT / "expected.json").read_text())["cases"]


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_heldout_cases", GENERATOR)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_generator_never_imports_the_production_engine() -> None:
    tree = ast.parse(GENERATOR.read_text())
    names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    names += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert "afterlock_reference" in names
    assert not [n for n in names if n == "afterlock" or n.startswith("afterlock.")]


def test_heldout_build_is_deterministic_and_committed() -> None:
    gen = _load_generator()
    first, second = gen.build(), gen.build()
    assert first == second
    on_disk = {p.relative_to(HELDOUT).as_posix(): p.read_bytes() for p in HELDOUT.rglob("*.json")}
    assert on_disk == first, "datasets/heldout is stale: run python datasets/generators/build_heldout_cases.py"


def test_heldout_labels_are_complete_and_cover_both_outcomes() -> None:
    assert len(LABELS) >= 30
    assert all(v["reference_complete"] for v in LABELS.values())
    conclusions = {v["conclusion"] for v in LABELS.values()}
    assert {"residual_path", "contained_within_scope"} <= conclusions
    assert len({v["template"] for v in LABELS.values()}) >= 5


@pytest.mark.parametrize("case_id", sorted(LABELS))
def test_engine_agrees_with_reference_label(case_id: str) -> None:
    raw = json.loads((HELDOUT / "cases" / f"{case_id}.json").read_text())
    bundle = analyze(parse_analysis_input(raw))
    assert bundle["conclusion"]["model"] == LABELS[case_id]["conclusion"]
    assert {o["id"]: o["status"] for o in bundle["objectives"]} == LABELS[case_id]["objectives"]


def test_committed_benchmark_report_has_no_host_or_timing_fields() -> None:
    text = (ROOT / "benchmarks/reports/semantic-corpus.json").read_text()
    for key in ("median_ms", "platform", "processor", "\"python\""):
        assert key not in text
    assert json.loads(text)["heldout"]["available"]
