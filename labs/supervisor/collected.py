"""Pure checks for a collector-produced replay bundle (no I/O beyond reading files).

Used by ``lab.py collect`` after the Go collector has written an
``afterlock.replay/1`` bundle from the live kind lab, and unit tested without a lab:

* ``lab_case``        builds the analyst case for a collected bundle from a
                      hand-authored case (residual-token or targeted-containment)
                      and live UIDs; synthetic UIDs are never carried over.
* ``scan_for_leaks``  searches every file under a directory for credential values
                      held in the supervisor's memory (raw and base64 forms) and for
                      JWT / private-key / canary patterns. Findings never contain
                      the matched value.
* ``find_event`` / ``inventory_checks`` / ``containment_checks`` / ``gap_kinds``
                      inspect the collected events and inventory.
* ``audit_batches``   splits an audit log into webhook EventList batches (second window).
* ``plan_gap_resolution`` / ``resolve_gaps`` / ``compare_containment``
                      compare a post-containment bundle with the targeted-containment
                      case. Coverage gaps make the engine report ``unknown``; only gap
                      kinds with a stated reason in ``GAP_RESOLUTIONS`` may be declared
                      resolved, every other gap blocks the match, and the unresolved
                      (raw) result is always reported next to the resolved one.
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


def downstream_items(template: Mapping[str, Any]) -> dict[str, str]:
    """Case items about downstream services, which the collector cannot observe.

    The canary's accepted credential is not a Kubernetes object the collector lists
    or audits, so these items are dropped from a collected case and reported as
    coverage limitations: {item id or remediation label: kind}.
    """
    out = {o["id"]: o["kind"] for o in template.get("objectives", []) if o.get("kind") == "no_downstream_use"}
    out.update({op["id"]: op["kind"] for op in template.get("legitimate_operations", []) if op.get("kind") == "use_downstream"})
    for a in template.get("remediation", []):
        if a.get("kind") == "rotate_downstream_credential":
            out[f"remediation:rotate_downstream_credential:{a.get('service')}"] = a["kind"]
    return out


def lab_case(template: Mapping[str, Any], *, ci_username: str, ci_sa_uid: str, release_pod_uid: str,
             analysis_time: str, source_id: str, scenario: str = "residual-token") -> dict[str, Any]:
    """Analyst case for a collected bundle, derived from a hand-authored case.

    Live UIDs replace the synthetic ones: every ``pod_uid`` of a legitimate operation
    and every ``keep_uids`` entry of a remediation must be one of the template's
    legitimate-workload Pod UIDs, which map to ``release_pod_uid``; anything else is
    rejected (ValueError) rather than carried over as an invented UID. Downstream
    services (the canary) are not Kubernetes objects the collector observes, so
    objectives, legitimate operations and remediation steps about them are dropped
    and listed in ``assumptions``; the comparison with the hand-authored case is
    restricted to the Kubernetes objectives.
    """
    dropped = downstream_items(template)
    objectives = [o for o in template.get("objectives", []) if o["id"] not in dropped]
    synthetic = {op["pod_uid"] for op in template.get("legitimate_operations", []) if "pod_uid" in op}

    def live(uid: str) -> str:
        if uid not in synthetic:
            raise ValueError(f"template UID {uid!r} has no live counterpart; refusing to invent one")
        return release_pod_uid

    legit = []
    for op in template.get("legitimate_operations", []):
        if op["id"] in dropped:
            continue
        legit.append({**op, "pod_uid": live(op["pod_uid"])} if "pod_uid" in op else dict(op))
    remediation = []
    for a in template.get("remediation", []):
        if a.get("kind") == "rotate_downstream_credential":
            continue
        if "uid" in a:
            raise ValueError(f"remediation {a.get('kind')!r} names a synthetic UID; refusing to invent one")
        remediation.append({**a, "keep_uids": [live(u) for u in a["keep_uids"]]} if "keep_uids" in a else dict(a))
    cred = {"id": "ci-runner-token", "kind": "sa_token", "username": ci_username, "sa_uid": ci_sa_uid,
            "audience": "https://kubernetes.default.svc.cluster.local"}
    return {
        "profile": template["profile"],
        "analysis_time": analysis_time,
        "description": f"Live-lab collected bundle for the {scenario} scenario (kind, Go collector).",
        "assumptions": [*template.get("assumptions", []),
                        "The seeded CI token is a TokenRequest token not bound to a Pod.",
                        f"Downstream-service items not collected and not analysed: {sorted(dropped)}."],
        "compromised_credentials": [cred],
        "objectives": objectives,
        "legitimate_operations": legit,
        "remediation": remediation,
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


# ---------------------------------------------------------------- second window: post-containment bundle


def containment_checks(inventory: Mapping[str, Any], events: list[dict[str, Any]], *, namespace: str,
                       attacker_pod: str, attacker_pod_uid: str, attacker_sa: str, creator: str,
                       binding: str, secret: str, keep_uids: Iterable[str]) -> dict[str, bool]:
    """Does a post-containment bundle show the attack and every Kubernetes containment step?

    The attacker Pod no longer exists, so its UID can only come from correlation the
    collector made while it observed that Pod; the supervisor passes the UID it read live.
    """
    create = find_event(events, verb="create", resource="pods", namespace=namespace, name=attacker_pod, username=creator)
    target = (create or {}).get("target") or {}
    pods = [p for p in inventory.get("pods", []) if isinstance(p, dict)]
    bindings = [b for b in inventory.get("bindings", []) if isinstance(b, dict)]
    keep = set(keep_uids)
    rotated = any(find_event(events, verb=v, resource="secrets", namespace=namespace, name=secret) is not None
                  for v in ("patch", "update"))
    return {
        "pod-create-event-present": create is not None,
        "pod-create-correlated-to-live-uid": target.get("uid") == attacker_pod_uid,
        "pod-create-service-account": target.get("service_account") == attacker_sa,
        "binding-delete-event-present": find_event(events, verb="delete", resource="rolebindings", namespace=namespace, name=binding) is not None,
        "binding-absent-from-inventory": not any(b.get("namespace") == namespace and b.get("name") == binding for b in bindings),
        "attacker-pod-delete-event-present": find_event(events, verb="delete", resource="pods", namespace=namespace, name=attacker_pod) is not None,
        "attacker-pod-absent-from-inventory": not any(p.get("uid") == attacker_pod_uid for p in pods),
        "only-kept-pods-run-as-attacker-sa": all(p.get("uid") in keep for p in pods
                                                 if p.get("namespace") == namespace and p.get("service_account") == attacker_sa),
        "source-secret-rotation-event-present": rotated,
    }


def audit_batches(data: bytes, max_bytes: int = 4 << 20) -> tuple[list[bytes], int]:
    """Split JSON-lines audit data into audit.k8s.io/v1 EventList bodies of about max_bytes.

    Returns (bodies, malformed_line_count). Lines that are not JSON objects are not
    sent (one bad item would make the receiver drop its whole batch); the caller must
    treat a non-zero count as a failed relay, never ignore it.
    """
    head, tail = b'{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[', b"]}"
    bodies: list[bytes] = []
    items: list[bytes] = []
    size = malformed = 0
    for raw in data.splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            ok = isinstance(json.loads(line), dict)
        except (UnicodeDecodeError, json.JSONDecodeError):
            ok = False
        if not ok:
            malformed += 1
            continue
        if items and size + len(line) + 1 > max_bytes:
            bodies.append(head + b",".join(items) + tail)
            items, size = [], 0
        items.append(line)
        size += len(line) + 1
    if items:
        bodies.append(head + b",".join(items) + tail)
    return bodies, malformed


def gap_index(events: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    """gap_id -> gap_kind for every collector.gap event."""
    return {str(ev["gap_id"]): str(ev.get("gap_kind", "unknown")) for ev in events
            if ev.get("event_type") == "collector.gap" and "gap_id" in ev}


# Gap kinds that may be declared resolved for the targeted-containment comparison, each
# with the reason written into the case. Everything else (collector restarts,
# uncorrelated Pods, unsynced inventory, dropped or malformed audit, unmodeled
# admission, stale sources, engine unknowns) blocks the comparison.
GAP_RESOLUTIONS = {
    "audit-before-window": (
        "Resolved gap audit-before-window: audit events before the evidence window are cluster setup and earlier "
        "lab runs; reset deleted every attacker-labelled Pod and the collected inventory shows no Pod running as "
        "the attacker service account other than the kept legitimate workload (supervisor check)."),
    "rbac-rule-unmodeled": (
        "Resolved gap rbac-rule-unmodeled: the skipped rules are non-resource URL rules, which grant no access "
        "to Secrets or Pods and so cannot affect the modeled objectives."),
}


def plan_gap_resolution(missing_coverage: Iterable[Mapping[str, Any]], gaps: Mapping[str, str]) -> dict[str, Any]:
    """Split a result's missing_coverage into resolvable collector gaps and blocking items."""
    resolved: dict[str, str] = {}
    blocking: list[dict[str, Any]] = []
    for m in missing_coverage:
        gid = m.get("id")
        kind = gaps.get(str(gid)) if gid is not None else None
        if m.get("kind") == "observation_gap" and kind in GAP_RESOLUTIONS:
            resolved[str(gid)] = kind
        else:
            blocking.append({"id": gid, "kind": kind or m.get("kind"), "detail": str(m.get("detail", ""))[:200]})
    return {"resolved": resolved, "blocking": blocking}


def resolve_gaps(case: Mapping[str, Any], resolved: Mapping[str, str]) -> dict[str, Any]:
    """The case with the given gaps declared resolved and one stated reason per gap kind."""
    reasons = [GAP_RESOLUTIONS[k] for k in sorted(set(resolved.values()))]
    return {**case, "resolved_gaps": sorted(resolved), "assumptions": [*case.get("assumptions", []), *reasons]}


def compare_containment(raw: Mapping[str, Any], resolved: Mapping[str, Any], reference: Mapping[str, Any],
                        plan: Mapping[str, Any]) -> dict[str, Any]:
    """Compare a post-containment collected result with the hand-authored reference.

    Matches only if (1) no blocking gap or engine unknown remains, (2) the raw result
    (no gap resolved) shows no violated or possibly_violated shared objective, and
    (3) with the resolvable gaps declared resolved, the conclusion and every shared
    objective equal the reference. The raw conclusion is always reported.
    """
    base = compare_conclusions(resolved, reference)
    raw_status = {o["id"]: o["status"] for o in raw.get("objectives", [])}
    raw_violations = {k: raw_status[k] for k in base["shared_objectives"]
                      if raw_status.get(k) in ("violated", "possibly_violated")}
    kinds: dict[str, int] = {}
    for k in plan["resolved"].values():
        kinds[k] = kinds.get(k, 0) + 1
    return {
        **base,
        "raw_conclusion": (raw.get("conclusion") or {}).get("model"),
        "raw_objectives": raw_status,
        "raw_violations": raw_violations,
        "resolved_gap_kinds": kinds,
        "blocking": list(plan["blocking"]),
        "match": base["match"] and not plan["blocking"] and not raw_violations,
    }
