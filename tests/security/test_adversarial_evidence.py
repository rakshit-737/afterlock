"""Phase 9 adversarial review of evidence ingestion (docs/security/review-2026-09-26-adversarial-engine.md)."""

from __future__ import annotations

import base64
import json
import shutil
import urllib.parse
from pathlib import Path
from typing import Any

import pytest

from afterlock.evidence import BundleError, ReplayBundle, parse_time, project

from conftest import REPLAY

FAKE_JWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZha2UifQ.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJl"


def _copy(tmp_path: Path, name: str = "residual-token") -> Path:
    dst = tmp_path / name
    shutil.copytree(REPLAY / name, dst)
    return dst


def _write(d: Path, *, events: list[dict[str, Any]] | None = None, inventory: dict[str, Any] | None = None,
           case: dict[str, Any] | None = None) -> None:
    b = ReplayBundle.load(d)
    ReplayBundle.write(d, case_id=b.manifest["case_id"], cluster_id=b.manifest["cluster_id"],
                       inventory=inventory if inventory is not None else b.inventory,
                       case=case if case is not None else b.case,
                       events=events if events is not None else [json.loads(x) for x in b.event_lines])


def _events(d: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in ReplayBundle.load(d).event_lines]


def _gap(seq: int, reason: str) -> dict[str, Any]:
    return {"cluster_id": "lab-local", "event_id": f"gap-{seq}", "event_type": "collector.gap", "gap_id": f"g{seq}",
            "observed_at": "2026-01-01T12:10:00Z", "reason": reason, "schema_version": "1", "source_id": "lab-audit",
            "source_sequence": seq}


# ---------------------------------------------------------------- attribution


def test_reads_by_a_pod_of_an_attacker_created_controller_are_attributed(tmp_path: Path) -> None:
    """E-1: the attacker creates a Deployment; its Pod reads the Secret. The read was not
    attributed (only pods/pods-exec creations seeded attribution), so the observed
    knowledge was lost: after the reader's access is revoked, a copied credential that
    the audit log shows was read would be reported as contained."""
    raw, _ = project(ReplayBundle.load(REPLAY / "controller-replacement"))
    facts = {(f["kind"], tuple(f["args"])): f for f in raw["initial_facts"]}
    assert ("knows_secret", ("demo", "release-credential", "1")) in facts
    assert facts[("knows_secret", ("demo", "release-credential", "1"))]["status"] == "observed"


# ---------------------------------------------------------------- timestamps


def test_out_of_range_timestamp_is_a_rejected_record_not_a_crash(tmp_path: Path) -> None:
    d = _copy(tmp_path)
    evs = _events(d)
    evs.append(dict(evs[0], source_sequence=950, event_id="bad-time", observed_at="0001-01-01T00:00:00+01:00"))
    _write(d, events=evs)
    raw, diag = project(ReplayBundle.load(d))
    assert len(diag["rejected"]) == 1
    assert any(g["kind"] == "rejected_evidence" for g in raw["coverage_gaps"])


def test_deeply_nested_event_is_a_rejected_record_not_a_crash(tmp_path: Path) -> None:
    d = _copy(tmp_path)
    b = ReplayBundle.load(d)
    deep = "[" * 20_000 + "]" * 20_000
    (d / "events.jsonl").write_text("\n".join([*b.event_lines, deep]) + "\n")
    import hashlib

    m = json.loads((d / "manifest.json").read_text())
    m["files"]["events.jsonl"] = "sha256:" + hashlib.sha256((d / "events.jsonl").read_bytes()).hexdigest()
    (d / "manifest.json").write_text(json.dumps(m))
    _, diag = project(ReplayBundle.load(d))
    assert len(diag["rejected"]) == 1


def test_parse_time_overflow_is_bundle_error() -> None:
    with pytest.raises(BundleError):
        parse_time("9999-12-31T23:59:59-01:00", "x")


def test_fractional_credential_expiry_is_rounded_up(tmp_path: Path) -> None:
    """Truncating 12:40:00.5 to 12:40:00 would treat the token as expired half a second
    early; a wait landing on 12:40:00 would then claim containment."""
    d = _copy(tmp_path)
    evs = _events(d)
    for e in evs:
        if e.get("actor", {}).get("pod_uid") == "pod-attacker-0001":
            e["actor"]["credential_expires_at"] = "2026-01-01T12:40:00.5Z"
    _write(d, events=evs)
    raw, _ = project(ReplayBundle.load(d))
    cred = next(c for c in raw["credentials"] if c["id"].startswith("observed:pod-attacker-0001"))
    assert cred["expires_at"] == parse_time("2026-01-01T12:40:01Z", "x")


# ---------------------------------------------------------------- redaction


@pytest.mark.parametrize(
    "value",
    [
        base64.b64encode(FAKE_JWT.encode()).decode(),
        base64.urlsafe_b64encode(FAKE_JWT.encode()).decode().rstrip("="),
        urllib.parse.quote(FAKE_JWT, safe=""),
        FAKE_JWT.replace(".", "%2E"),
        base64.b64encode(b"-----BEGIN RSA PRIVATE KEY-----\nMIIE").decode(),
    ],
)
def test_encoded_credentials_in_persisted_fields_are_rejected(tmp_path: Path, value: str) -> None:
    """E-3: a collector.gap reason is copied into coverage_gaps (persisted and exported).
    Encoded credentials passed the plain-text patterns."""
    d = _copy(tmp_path)
    _write(d, events=[*_events(d), _gap(960, f"upstream said {value}")])
    raw, diag = project(ReplayBundle.load(d))
    assert value not in json.dumps(raw) and value not in json.dumps(diag)
    assert len(diag["rejected"]) == 1


@pytest.mark.parametrize("key", ["accessToken", "access_token", "id-token", "bearerToken", "clientSecret", "apiKey", "private_key", "Authorization "])
def test_forbidden_key_variants_are_rejected(tmp_path: Path, key: str) -> None:
    d = _copy(tmp_path)
    evs = _events(d)
    evs.append(dict(evs[1], source_sequence=970, event_id="k", extra={key: "opaque-value"}))
    _write(d, events=evs)
    _, diag = project(ReplayBundle.load(d))
    assert len(diag["rejected"]) == 1


def test_duplicate_json_keys_in_an_event_are_rejected(tmp_path: Path) -> None:
    """Parsers disagree on duplicate keys (first vs last wins); the projector must not
    silently pick one, e.g. a denied outcome followed by a successful one."""
    d = _copy(tmp_path)
    b = ReplayBundle.load(d)
    line = b.event_lines[1]
    dup = line.replace('"outcome":{"http_status":200}', '"outcome":{"http_status":403},"outcome":{"http_status":200}')
    dup = dup.replace('"source_sequence":2', '"source_sequence":980')
    assert dup != line
    (d / "events.jsonl").write_text("\n".join([*b.event_lines, dup]) + "\n")
    import hashlib

    m = json.loads((d / "manifest.json").read_text())
    m["files"]["events.jsonl"] = "sha256:" + hashlib.sha256((d / "events.jsonl").read_bytes()).hexdigest()
    (d / "manifest.json").write_text(json.dumps(m))
    _, diag = project(ReplayBundle.load(d))
    assert len(diag["rejected"]) == 1


def test_credentials_in_inventory_are_rejected(tmp_path: Path) -> None:
    """E-2: inventory.json is copied verbatim into the stored analysis input, but was
    never scanned; a JWT in a Pod annotation reached input.json and exports."""
    d = _copy(tmp_path)
    b = ReplayBundle.load(d)
    inv = json.loads(json.dumps(b.inventory))
    inv["pods"][0]["annotations"] = {"note": FAKE_JWT}
    _write(d, inventory=inv)
    with pytest.raises(BundleError, match="inventory.json"):
        project(ReplayBundle.load(d))


def test_credentials_in_case_are_rejected(tmp_path: Path) -> None:
    d = _copy(tmp_path)
    b = ReplayBundle.load(d)
    case = json.loads(json.dumps(b.case))
    case["objectives"][0]["description"] = "see " + FAKE_JWT
    _write(d, case=case)
    with pytest.raises(BundleError, match="case.json"):
        project(ReplayBundle.load(d))


def test_clean_fixtures_still_project() -> None:
    for d in sorted(REPLAY.iterdir()):
        project(ReplayBundle.load(d))
