"""Pure checks for a collector-produced replay bundle (no I/O beyond reading files).

Used by ``lab.py collect`` after the Go collector has written an
``afterlock.replay/1`` bundle from the live kind lab, and unit tested without a lab:

* ``lab_case``        builds the analyst case for the collected bundle from the
                      hand-authored residual-token case and live UIDs.
* ``scan_for_leaks``  searches every file under a directory for credential values
                      held in the supervisor's memory (raw and base64 forms) and for
                      JWT / private-key / canary patterns. Findings never contain
                      the matched value.
* ``find_event`` / ``inventory_checks`` / ``gap_kinds`` inspect the collected events
                      and inventory.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

JWT = re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
PATTERNS = (
    ("jwt", JWT),
    ("private-key", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("canary", re.compile(rb"AFTERLOCK-CANARY-[A-Za-z0-9]+")),
    ("bearer", re.compile(rb"(?i)bearer\s+[A-Za-z0-9._~+/-]{16,}")),
)
MIN_SECRET_LEN = 8  # shorter "secrets" would match by accident and prove nothing


def _forms(value: str) -> list[tuple[str, bytes]]:
    raw = value.encode()
    return [
        ("value", raw),
        ("base64", base64.b64encode(raw).rstrip(b"=")),
        ("base64url", base64.urlsafe_b64encode(raw).rstrip(b"=")),
    ]


def scan_for_leaks(root: Path, held: Mapping[str, str]) -> list[dict[str, str]]:
    """Return one finding per (file, label, form) where credential material appears.

    ``held`` maps a label (e.g. "ci-token") to a value held in memory. The value
    itself is never included in a finding. Every regular file under ``root`` is
    scanned as bytes; symbolic links are reported, not followed.
    """
    for label, value in held.items():
        if not isinstance(value, str) or len(value) < MIN_SECRET_LEN:
            raise ValueError(f"held value {label!r} is missing or too short to scan for")
    findings: list[dict[str, str]] = []
    files = sorted(p for p in root.rglob("*") if p.is_file() or p.is_symlink())
    if not files:
        raise ValueError(f"{root}: nothing to scan")
    for path in files:
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            findings.append({"file": rel, "kind": "symlink"})
            continue
        data = path.read_bytes()
        for label, value in held.items():
            for form, needle in _forms(value):
                if needle and needle in data:
                    findings.append({"file": rel, "kind": f"held:{label}:{form}"})
        for name, pat in PATTERNS:
            if pat.search(data):
                findings.append({"file": rel, "kind": f"pattern:{name}"})
    return findings


def read_events(lines: Iterable[str]) -> list[dict[str, Any]]:
    return [json.loads(line) for line in lines if line.strip()]


def find_event(events: Iterable[Mapping[str, Any]], *, verb: str, resource: str, namespace: str,
               name: str, username: str | None = None) -> dict[str, Any] | None:
    """The first successful k8s.api.response for verb/resource on namespace/name."""
    for ev in events:
        if ev.get("event_type") != "k8s.api.response":
            continue
        action, target = ev.get("action") or {}, ev.get("target") or {}
        status = (ev.get("outcome") or {}).get("http_status")
        if (action.get("verb"), action.get("resource"), action.get("namespace"), target.get("name")) != (verb, resource, namespace, name):
            continue
        if username is not None and (ev.get("actor") or {}).get("username") != username:
            continue
        if isinstance(status, int) and 200 <= status < 300:
            return dict(ev)
    return None


def gap_kinds(events: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for ev in events:
        if ev.get("event_type") == "collector.gap":
            k = str(ev.get("gap_kind", "unknown"))
            out[k] = out.get(k, 0) + 1
    return out


def inventory_checks(inventory: Mapping[str, Any], events: list[dict[str, Any]], *, namespace: str,
                     attacker_pod: str, attacker_pod_uid: str, attacker_sa: str, creator: str,
                     binding: str) -> dict[str, bool]:
    """Does the collected bundle show the attacker Pod creation and the binding deletion?

    Each check is independent and named, so a receipt can say exactly which failed.
    """
    create = find_event(events, verb="create", resource="pods", namespace=namespace, name=attacker_pod, username=creator)
    target = (create or {}).get("target") or {}
    pods = [p for p in inventory.get("pods", []) if isinstance(p, dict)]
    bindings = [b for b in inventory.get("bindings", []) if isinstance(b, dict)]
    return {
        "pod-create-event-present": create is not None,
        "pod-create-correlated-to-live-uid": target.get("uid") == attacker_pod_uid,
        "pod-create-service-account": target.get("service_account") == attacker_sa,
        "attacker-pod-in-inventory": any(p.get("uid") == attacker_pod_uid and p.get("service_account") == attacker_sa for p in pods),
        "binding-delete-event-present": find_event(events, verb="delete", resource="rolebindings", namespace=namespace, name=binding) is not None,
        "binding-absent-from-inventory": not any(b.get("namespace") == namespace and b.get("name") == binding for b in bindings),
    }


def lab_case(template: Mapping[str, Any], *, ci_username: str, ci_sa_uid: str, release_pod_uid: str,
             analysis_time: str, source_id: str) -> dict[str, Any]:
    """Analyst case for the collected bundle, derived from the hand-authored residual-token case.

    Live UIDs replace the synthetic ones. Downstream services (the canary) are not
    Kubernetes objects the collector observes, so objectives and legitimate operations
    about them are dropped and listed in ``assumptions``; the comparison with the
    hand-authored case is restricted to the Kubernetes objectives.
    """
    objectives = [o for o in template.get("objectives", []) if o.get("kind") != "no_downstream_use"]
    dropped = [o["id"] for o in template.get("objectives", []) if o.get("kind") == "no_downstream_use"]
    legit = []
    for op in template.get("legitimate_operations", []):
        if op.get("kind") == "use_downstream":
            dropped.append(op["id"])
            continue
        legit.append({**op, "pod_uid": release_pod_uid} if "pod_uid" in op else dict(op))
    cred = {"id": "ci-runner-token", "kind": "sa_token", "username": ci_username, "sa_uid": ci_sa_uid,
            "audience": "https://kubernetes.default.svc.cluster.local"}
    return {
        "profile": template["profile"],
        "analysis_time": analysis_time,
        "description": "Live-lab collected bundle for the residual-token scenario (kind, Go collector).",
        "assumptions": [*template.get("assumptions", []),
                        "The seeded CI token is a TokenRequest token not bound to a Pod.",
                        f"Downstream-service items not collected and not analysed: {sorted(dropped)}."],
        "compromised_credentials": [cred],
        "objectives": objectives,
        "legitimate_operations": legit,
        "remediation": list(template.get("remediation", [])),
        "required_sources": [source_id],
        "max_evidence_staleness_seconds": template.get("max_evidence_staleness_seconds", 300),
    }


def compare_conclusions(collected: Mapping[str, Any], reference: Mapping[str, Any]) -> dict[str, Any]:
    """Compare two afterlock.result/1 documents on the objectives both analysed."""
    ours = {o["id"]: o["status"] for o in collected.get("objectives", [])}
    theirs = {o["id"]: o["status"] for o in reference.get("objectives", [])}
    shared = sorted(set(ours) & set(theirs))
    mismatched = {k: {"collected": ours[k], "reference": theirs[k]} for k in shared if ours[k] != theirs[k]}
    model = (collected.get("conclusion") or {}).get("model")
    ref_model = (reference.get("conclusion") or {}).get("model")
    return {
        "collected_conclusion": model,
        "reference_conclusion": ref_model,
        "shared_objectives": shared,
        "mismatched_objectives": mismatched,
        "match": bool(shared) and model == ref_model and not mismatched,
    }
