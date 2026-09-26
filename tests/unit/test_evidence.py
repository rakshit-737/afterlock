"""Evidence pipeline: integrity, deduplication, ordering, gaps, attribution."""

from __future__ import annotations

import json
import random
import shutil
from pathlib import Path
from typing import Any

import pytest

from afterlock.evidence import BundleError, ReplayBundle, project
from afterlock.model import parse_analysis_input
from afterlock.results import analyze

from conftest import REPLAY


def _copy(tmp_path: Path, name: str = "residual-token") -> Path:
    dst = tmp_path / name
    shutil.copytree(REPLAY / name, dst)
    return dst


def _rewrite(bundle_dir: Path, events: list[dict[str, Any]] | None = None, case: dict[str, Any] | None = None, raw_lines: list[str] | None = None) -> None:
    b = ReplayBundle.load(bundle_dir)
    evs = [json.loads(line) for line in b.event_lines] if events is None else events
    ReplayBundle.write(bundle_dir, case_id=b.manifest["case_id"], cluster_id=b.manifest["cluster_id"], inventory=b.inventory,
                       case=case or b.case, events=evs)
    if raw_lines is not None:
        (bundle_dir / "events.jsonl").write_text("\n".join(raw_lines) + "\n")
        m = json.loads((bundle_dir / "manifest.json").read_text())
        import hashlib

        m["files"]["events.jsonl"] = "sha256:" + hashlib.sha256((bundle_dir / "events.jsonl").read_bytes()).hexdigest()
        (bundle_dir / "manifest.json").write_text(json.dumps(m))


def _events(d: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in ReplayBundle.load(d).event_lines]


def test_checksum_mismatch_is_invalid_input(tmp_path: Path) -> None:
    d = _copy(tmp_path)
    with (d / "events.jsonl").open("a") as fh:
        fh.write("\n")
    with pytest.raises(BundleError, match="checksum"):
        ReplayBundle.load(d)


def test_symlinked_file_rejected(tmp_path: Path) -> None:
    d = _copy(tmp_path)
    (d / "case.json").unlink()
    (d / "case.json").symlink_to(REPLAY / "residual-token" / "case.json")
    with pytest.raises(BundleError, match="symbolic"):
        ReplayBundle.load(d)


def test_duplicates_are_harmless_and_counted(tmp_path: Path) -> None:
    d = _copy(tmp_path)
    evs = _events(d)
    dup = dict(evs[0], ingested_at="2026-01-01T12:05:00Z")  # transport metadata may differ
    _rewrite(d, evs + [dup, evs[1]])
    raw, diag = project(ReplayBundle.load(d))
    base, _ = project(ReplayBundle.load(REPLAY / "residual-token"))
    assert diag["duplicates"] == 2
    assert parse_analysis_input(raw).raw_digest == parse_analysis_input(base).raw_digest


def test_delivery_order_does_not_change_input(tmp_path: Path) -> None:
    d = _copy(tmp_path)
    evs = _events(d)
    base = parse_analysis_input(project(ReplayBundle.load(d))[0]).raw_digest
    rng = random.Random(7)
    for _ in range(5):
        rng.shuffle(evs)
        _rewrite(d, list(evs))
        assert parse_analysis_input(project(ReplayBundle.load(d))[0]).raw_digest == base


def test_conflicting_duplicate_becomes_gap(tmp_path: Path) -> None:
    d = _copy(tmp_path, "targeted-containment")
    evs = _events(d)
    conflict = json.loads(json.dumps(evs[0]))
    conflict["event_id"] = "evt-other"
    conflict["outcome"]["http_status"] = 403
    _rewrite(d, evs + [conflict])
    raw, diag = project(ReplayBundle.load(d))
    assert diag["conflicts"]
    assert analyze(parse_analysis_input(raw))["conclusion"]["model"] == "unknown"


def test_malformed_and_sensitive_records_rejected_and_gap_recorded(tmp_path: Path) -> None:
    d = _copy(tmp_path, "targeted-containment")
    lines = ReplayBundle.load(d).event_lines
    leak = json.loads(lines[0])
    leak["source_sequence"] = 77
    leak["actor"]["note"] = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzeXN0ZW0ifQ.sig"
    _rewrite(d, raw_lines=lines + ["{not json", json.dumps(leak), json.dumps({"schema_version": "1"})])
    raw, diag = project(ReplayBundle.load(d))
    assert len(diag["rejected"]) == 3
    assert "eyJhbGci" not in json.dumps(raw) and "eyJhbGci" not in json.dumps(diag)
    assert analyze(parse_analysis_input(raw))["conclusion"]["model"] == "unknown"


def test_denied_request_confers_nothing(tmp_path: Path) -> None:
    d = _copy(tmp_path)
    evs = _events(d)
    evs[1]["outcome"]["http_status"] = 403  # the secret read was denied
    _rewrite(d, evs)
    raw, _ = project(ReplayBundle.load(d))
    assert not any(f["kind"] == "knows_secret" for f in raw["initial_facts"])


def test_stale_collector_is_a_gap(tmp_path: Path) -> None:
    d = _copy(tmp_path, "targeted-containment")
    evs = [e for e in _events(d) if e["event_type"] != "collector.heartbeat"]
    _rewrite(d, evs)
    raw, _ = project(ReplayBundle.load(d))
    assert any(g["kind"] == "stale_evidence" for g in raw["coverage_gaps"])
    assert analyze(parse_analysis_input(raw))["conclusion"]["model"] == "unknown"


def test_resolved_gap_is_not_counted(tmp_path: Path) -> None:
    d = _copy(tmp_path, "incomplete-telemetry")
    b = ReplayBundle.load(d)
    case = dict(b.case, resolved_gaps=["audit-gap-1210"])
    _rewrite(d, case=case)
    raw, _ = project(ReplayBundle.load(d))
    assert analyze(parse_analysis_input(raw))["conclusion"]["model"] == "contained_within_scope"


def test_unknown_event_type_is_ignored_not_trusted(tmp_path: Path) -> None:
    d = _copy(tmp_path)
    evs = _events(d)
    evs.append(dict(evs[1], source_sequence=500, event_id="x", event_type="vendor.magic"))
    _rewrite(d, evs)
    _, diag = project(ReplayBundle.load(d))
    assert diag["ignored"] and "unsupported event type" in diag["ignored"][0]["reason"]


def test_attribution_uses_uid_not_name(tmp_path: Path) -> None:
    raw, _ = project(ReplayBundle.load(REPLAY / "same-name-recreation"))
    assert ["pod-attacker-0001"] in [f["args"] for f in raw["initial_facts"] if f["kind"] == "controls_pod"]
    assert not any(f["args"] == ["pod-diagnostic-0002"] for f in raw["initial_facts"])


def test_wrong_cluster_events_rejected(tmp_path: Path) -> None:
    d = _copy(tmp_path)
    evs = _events(d)
    evs[0]["cluster_id"] = "prod-cluster"
    _rewrite(d, evs)
    raw, diag = project(ReplayBundle.load(d))
    assert any("cluster_id" in p for r in diag["rejected"] for p in r["problems"])


def test_same_stolen_token_used_twice_projects(tmp_path: Path) -> None:
    """Regression (live lab, 2026-09-26): a second use of the same token raised KeyError."""
    d = _copy(tmp_path)
    evs = _events(d)
    again = dict(evs[1], event_id="evt-demo-0002b", source_sequence=3,
                 observed_at="2026-01-01T12:00:05Z", ingested_at="2026-01-01T12:00:06Z")
    _rewrite(d, evs[:2] + [again] + evs[2:])
    raw, diag = project(ReplayBundle.load(d))
    assert not diag["rejected"]
    assert analyze(parse_analysis_input(raw))["conclusion"]["model"] == "residual_path"
