"""Evidence ingestion and projection for replay bundles.

A replay bundle is a directory containing exactly:

  manifest.json   schema, case id, cluster id, SHA-256 of every other file
  inventory.json  metadata-only snapshot of supported Kubernetes objects
  events.jsonl    evidence envelopes (one JSON object per line)
  case.json       objectives, legitimate operations, remediation, seeded compromise

The projector validates, deduplicates, and redaction-checks envelopes, then
builds the canonical ``afterlock.analysis-input/1`` document. Observations
become ``observed`` facts; the seeded compromise is ``assumed``. Missing,
rejected, conflicting or stale evidence becomes an explicit coverage gap —
never a negative security fact.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

from .model import ANALYSIS_INPUT_SCHEMA, canonical_json, parse_analysis_input

REPLAY_SCHEMA = "afterlock.replay/1"
BUNDLE_FILES = ("inventory.json", "events.jsonl", "case.json")
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_DEPTH = 6
MAX_STRING = 512
MAX_EVENTS = 200_000

FORBIDDEN_KEYS = frozenset(
    {
        "token",
        "bearer",
        "authorization",
        "data",
        "stringdata",
        "string_data",
        "password",
        "secret_value",
        "response_body",
        "responseobject",
        "request_body",
        "requestobject",
        "credential_value",
    }
)
SENSITIVE_PATTERNS = (
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"AFTERLOCK-CANARY-[A-Za-z0-9]+"),  # seeded redaction canaries
)

SUPPORTED_EVENT_TYPES = frozenset({"k8s.api.response", "collector.gap", "collector.heartbeat", "lab.receipt"})


class BundleError(ValueError):
    """The bundle cannot be used as analysis input (invalid_input)."""


def parse_time(value: Any, where: str) -> int:
    if not isinstance(value, str) or len(value) > 40:
        raise BundleError(f"{where}: expected RFC 3339 timestamp")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BundleError(f"{where}: invalid timestamp {value!r}") from exc
    if dt.tzinfo is None:
        raise BundleError(f"{where}: timestamp must include a timezone")
    return int(dt.astimezone(UTC).timestamp())


def load_profile(profile_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9.\-]{1,64}", profile_id):
        raise BundleError(f"invalid profile id {profile_id!r}")
    try:
        text = resources.files("afterlock.profiles").joinpath(f"{profile_id}.json").read_text("utf-8")
    except FileNotFoundError as exc:
        raise BundleError(f"unknown semantic profile {profile_id!r}") from exc
    return dict(json.loads(text))


# --------------------------------------------------------------------------
# envelope validation


def _scan(value: Any, path: str, depth: int, problems: list[str]) -> None:
    if depth > MAX_DEPTH:
        problems.append(f"{path}: nesting deeper than {MAX_DEPTH}")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str) or len(k) > 64:
                problems.append(f"{path}: invalid key")
                continue
            if k.lower() in FORBIDDEN_KEYS:
                problems.append(f"{path}.{k}: forbidden field (credential or payload material)")
                continue
            _scan(v, f"{path}.{k}", depth + 1, problems)
    elif isinstance(value, list):
        if len(value) > 256:
            problems.append(f"{path}: list too long")
        for i, v in enumerate(value[:256]):
            _scan(v, f"{path}[{i}]", depth + 1, problems)
    elif isinstance(value, str):
        if len(value) > MAX_STRING:
            problems.append(f"{path}: string longer than {MAX_STRING}")
        for pat in SENSITIVE_PATTERNS:
            if pat.search(value):
                problems.append(f"{path}: value resembles credential material")
                break
    elif value is None or isinstance(value, (bool, int, float)):
        return
    else:  # pragma: no cover - json cannot produce other types
        problems.append(f"{path}: unsupported type")


@dataclass(frozen=True)
class Envelope:
    event_id: str
    source_id: str
    source_sequence: int
    event_type: str
    observed_at: int
    body: Mapping[str, Any]
    content_key: str


def validate_envelope(raw: Any, cluster_id: str) -> tuple[Envelope | None, list[str]]:
    problems: list[str] = []
    if not isinstance(raw, dict):
        return None, ["envelope is not an object"]
    _scan(raw, "$", 0, problems)
    if problems:
        return None, problems
    if raw.get("schema_version") != "1":
        problems.append("unsupported schema_version")
    for key in ("event_id", "source_id", "event_type", "cluster_id"):
        if not isinstance(raw.get(key), str) or not raw.get(key):
            problems.append(f"missing {key}")
    seq = raw.get("source_sequence")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        problems.append("source_sequence must be a non-negative integer")
        seq = -1
    if raw.get("cluster_id") != cluster_id:
        problems.append("cluster_id does not match bundle")
    try:
        observed = parse_time(raw.get("observed_at"), "observed_at")
    except BundleError as exc:
        problems.append(str(exc))
        observed = 0
    if problems:
        return None, problems
    content = {k: v for k, v in raw.items() if k != "ingested_at"}
    return (
        Envelope(raw["event_id"], raw["source_id"], seq, raw["event_type"], observed, raw, canonical_json(content)),
        [],
    )


# --------------------------------------------------------------------------
# bundle loading


def _read_file(root: Path, name: str) -> bytes:
    path = root / name
    if path.is_symlink():
        raise BundleError(f"{name}: symbolic links are not accepted")
    if not path.is_file():
        raise BundleError(f"{name}: missing")
    if path.resolve().parent != root.resolve():
        raise BundleError(f"{name}: path escapes bundle directory")
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise BundleError(f"{name}: larger than {MAX_FILE_BYTES} bytes")
    return path.read_bytes()


def _json(data: bytes, name: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleError(f"{name}: invalid JSON") from exc


@dataclass
class ReplayBundle:
    manifest: dict[str, Any]
    inventory: dict[str, Any]
    case: dict[str, Any]
    event_lines: list[str]

    @classmethod
    def load(cls, directory: str | Path) -> ReplayBundle:
        root = Path(directory)
        if not root.is_dir():
            raise BundleError(f"{directory}: not a directory")
        manifest = _json(_read_file(root, "manifest.json"), "manifest.json")
        if not isinstance(manifest, dict) or manifest.get("schema") != REPLAY_SCHEMA:
            raise BundleError("manifest.json: unsupported replay schema")
        files = manifest.get("files")
        if not isinstance(files, dict) or set(files) != set(BUNDLE_FILES):
            raise BundleError(f"manifest.json: files must list exactly {list(BUNDLE_FILES)}")
        contents = {}
        for name in BUNDLE_FILES:
            data = _read_file(root, name)
            actual = "sha256:" + hashlib.sha256(data).hexdigest()
            if files[name] != actual:
                raise BundleError(f"{name}: checksum mismatch (manifest {files[name]}, actual {actual})")
            contents[name] = data
        inventory = _json(contents["inventory.json"], "inventory.json")
        case = _json(contents["case.json"], "case.json")
        if not isinstance(inventory, dict) or not isinstance(case, dict):
            raise BundleError("inventory.json and case.json must be objects")
        lines = contents["events.jsonl"].decode("utf-8", errors="strict").splitlines()
        if len(lines) > MAX_EVENTS:
            raise BundleError("events.jsonl: too many events")
        return cls(manifest, inventory, case, lines)

    @staticmethod
    def write(directory: str | Path, *, case_id: str, cluster_id: str, inventory: dict[str, Any], case: dict[str, Any], events: list[dict[str, Any]]) -> None:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        blobs = {
            "inventory.json": (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode(),
            "case.json": (json.dumps(case, indent=2, sort_keys=True) + "\n").encode(),
            "events.jsonl": "".join(canonical_json(e) + "\n" for e in events).encode(),
        }
        for name, data in blobs.items():
            (root / name).write_bytes(data)
        manifest = {
            "schema": REPLAY_SCHEMA,
            "case_id": case_id,
            "cluster_id": cluster_id,
            "files": {n: "sha256:" + hashlib.sha256(d).hexdigest() for n, d in blobs.items()},
        }
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


# --------------------------------------------------------------------------
# projection


@dataclass
class Diagnostics:
    accepted: int = 0
    duplicates: int = 0
    rejected: list[dict[str, Any]] = field(default_factory=list)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    ignored: list[dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "duplicates": self.duplicates,
            "rejected": self.rejected,
            "conflicts": self.conflicts,
            "ignored": self.ignored,
        }


def _events(bundle: ReplayBundle, cluster_id: str, diag: Diagnostics) -> list[Envelope]:
    by_key: dict[tuple[str, int], Envelope] = {}
    for lineno, line in enumerate(bundle.event_lines, 1):
        if not line.strip():
            continue
        if len(line.encode()) > MAX_LINE_BYTES:
            diag.rejected.append({"line": lineno, "problems": ["line too long"]})
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            diag.rejected.append({"line": lineno, "problems": ["invalid JSON"]})
            continue
        env, problems = validate_envelope(raw, cluster_id)
        if env is None:
            diag.rejected.append({"line": lineno, "problems": problems[:5]})
            continue
        key = (env.source_id, env.source_sequence)
        prev = by_key.get(key)
        if prev is not None:
            if prev.content_key == env.content_key:
                diag.duplicates += 1
            else:
                diag.conflicts.append({"source_id": key[0], "source_sequence": key[1], "event_ids": sorted({prev.event_id, env.event_id})})
            continue
        by_key[key] = env
        diag.accepted += 1
    # Deterministic order that does not depend on delivery order. Source-reported
    # time is used only for display; kubernetes resourceVersion is never compared.
    return sorted(by_key.values(), key=lambda e: (e.source_id, e.source_sequence))


def _cred_spec(case_cred: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {"id", "kind", "username", "sa_uid", "bound_pod_uid", "audience", "expires_at"}
    extra = set(case_cred) - allowed
    if extra:
        raise BundleError(f"case.json compromised_credentials: unknown fields {sorted(extra)}")
    return dict(case_cred)


def project(bundle: ReplayBundle) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the canonical analysis input. Returns (analysis_input, diagnostics)."""
    m = bundle.manifest
    case = bundle.case
    case_id, cluster_id = m.get("case_id"), m.get("cluster_id")
    if not isinstance(case_id, str) or not isinstance(cluster_id, str):
        raise BundleError("manifest.json: case_id and cluster_id are required")
    profile = load_profile(str(case.get("profile", "")))
    analysis_time = parse_time(case.get("analysis_time"), "case.analysis_time")
    diag = Diagnostics()
    events = _events(bundle, cluster_id, diag)

    pods_by_uid = {p["uid"]: p for p in bundle.inventory.get("pods", []) if isinstance(p, dict) and "uid" in p}
    secrets = {(s["namespace"], s["name"]): s for s in bundle.inventory.get("secrets", []) if isinstance(s, dict)}

    credentials: dict[str, dict[str, Any]] = {}
    facts: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}
    gaps: list[dict[str, Any]] = []
    assumptions: list[str] = list(profile.get("assumptions", [])) + [str(a) for a in case.get("assumptions", [])]

    def add_fact(kind: str, args: tuple[str, ...], status: str, evidence: str, note: str = "") -> None:
        key = (kind, args)
        if key in facts:
            if evidence not in facts[key]["evidence"]:
                facts[key]["evidence"].append(evidence)
                facts[key]["evidence"].sort()
            return
        facts[key] = {"kind": kind, "args": list(args), "status": status, "evidence": [evidence]}
        if note:
            facts[key]["note"] = note

    attacker_users: set[str] = set()
    for c in case.get("compromised_credentials", []):
        spec = _cred_spec(c)
        credentials[spec["id"]] = spec
        attacker_users.add(spec["username"])
        add_fact("possesses_credential", (spec["id"],), "assumed", "case:seeded-compromise")

    attacker_pods: set[str] = set()
    resolved = set(case.get("resolved_gaps", []))
    heartbeats: dict[str, int] = {}

    # Attribution is a fixpoint: an event made with a token bound to an
    # attacker-controlled Pod is attacker activity, which can in turn establish
    # control of further Pods.
    changed = True
    while changed:
        changed = False
        for ev in events:
            if ev.event_type != "k8s.api.response":
                continue
            b = ev.body
            actor = b.get("actor") or {}
            action = b.get("action") or {}
            target = b.get("target") or {}
            outcome = b.get("outcome") or {}
            status = outcome.get("http_status")
            actor_pod = actor.get("pod_uid")
            is_attacker = actor.get("username") in attacker_users or (actor_pod is not None and actor_pod in attacker_pods)
            if not is_attacker or not isinstance(status, int) or not 200 <= status < 300:
                continue
            verb, resource, ns = action.get("verb"), action.get("resource"), action.get("namespace")
            if resource in ("pods", "pods/exec") and verb == "create" and isinstance(target.get("uid"), str):
                if target["uid"] not in attacker_pods:
                    attacker_pods.add(target["uid"])
                    changed = True
    for ev in events:
        b = ev.body
        ref = f"{ev.source_id}#{ev.source_sequence}"
        if ev.event_type == "collector.gap":
            gid = str(b.get("gap_id", ref))
            if gid not in resolved:
                gaps.append({"id": gid, "kind": "observation_gap", "description": str(b.get("reason", "collector reported an observation gap"))[:MAX_STRING], "evidence": [ref]})
            continue
        if ev.event_type == "collector.heartbeat":
            heartbeats[ev.source_id] = max(heartbeats.get(ev.source_id, 0), ev.observed_at)
            continue
        if ev.event_type not in SUPPORTED_EVENT_TYPES:
            diag.ignored.append({"event": ref, "reason": f"unsupported event type {ev.event_type!r}"})
            continue
        if ev.event_type == "lab.receipt":
            diag.ignored.append({"event": ref, "reason": "lab receipts are validation records, not attacker evidence"})
            continue
        actor = b.get("actor") or {}
        action = b.get("action") or {}
        target = b.get("target") or {}
        outcome = b.get("outcome") or {}
        status = outcome.get("http_status")
        actor_pod = actor.get("pod_uid")
        is_attacker = actor.get("username") in attacker_users or (actor_pod is not None and actor_pod in attacker_pods)
        if not is_attacker:
            continue
        if not isinstance(status, int) or not 200 <= status < 300:
            continue  # denied or failed requests confer nothing
        # The request itself proves possession of the credential that made it.
        if actor_pod is not None and actor_pod in attacker_pods:
            aud = actor.get("audience") or profile["api_audiences"][0]
            cid = f"observed:{actor_pod}:{aud}"
            username = actor.get("username")
            sa_uid = actor.get("sa_uid")
            if isinstance(username, str):
                credentials.setdefault(
                    cid,
                    {
                        "id": cid,
                        "kind": "sa_token",
                        "username": username,
                        "sa_uid": sa_uid if isinstance(sa_uid, str) else None,
                        "bound_pod_uid": actor_pod,
                        "audience": aud,
                        # Expiry is not visible in audit metadata; without an explicit
                        # observation we do not assume expiry (conservative).
                        "expires_at": parse_time(actor["credential_expires_at"], "credential_expires_at") if "credential_expires_at" in actor else None,
                    },
                )
                if credentials[cid].get("sa_uid", "") is None:
                    credentials[cid].pop("sa_uid")
                if credentials[cid].get("expires_at", "") is None:
                    credentials[cid].pop("expires_at")
                add_fact("possesses_credential", (cid,), "observed", ref, "credential observed in use")
        verb, resource, ns = action.get("verb"), action.get("resource"), action.get("namespace")
        uid = target.get("uid")
        if verb == "create" and resource in ("pods", "pods/exec") and isinstance(uid, str):
            add_fact("controls_pod", (uid,), "observed", ref)
            if uid not in pods_by_uid:
                sa = target.get("service_account")
                if isinstance(sa, str) and isinstance(ns, str):
                    add_fact("historical_pod", (uid, ns, sa), "observed", ref, "attacker pod no longer in inventory")
                else:
                    gaps.append({"id": f"pod-sa-unknown:{uid}", "kind": "missing_metadata", "description": f"service account of attacker pod {uid} is unknown", "evidence": [ref]})
        elif verb == "create" and resource == "deployments" and isinstance(uid, str):
            add_fact("controls_controller", (uid,), "observed", ref)
        elif verb == "get" and resource == "secrets" and isinstance(ns, str) and isinstance(target.get("name"), str):
            key = (ns, target["name"])
            version = target.get("observed_version")
            note = ""
            if not isinstance(version, int):
                sec = secrets.get(key)
                if sec is None:
                    gaps.append({"id": f"secret-version-unknown:{ns}/{key[1]}", "kind": "missing_metadata", "description": f"version of secret {ns}/{key[1]} read at {ref} is unknown", "evidence": [ref]})
                    continue
                version = sec["version"]
                note = "version not in audit record; assumed equal to inventory version"
            add_fact("knows_secret", (ns, key[1], str(version)), "observed", ref, note)

    staleness = case.get("max_evidence_staleness_seconds")
    if isinstance(staleness, int):
        for src in case.get("required_sources", []):
            last = heartbeats.get(src)
            if last is None or analysis_time - last > staleness:
                gaps.append({"id": f"stale:{src}", "kind": "stale_evidence", "description": f"source {src} has no heartbeat within {staleness}s of analysis time", "evidence": []})
    for r in diag.rejected:
        gaps.append({"id": f"rejected:line{r['line']}", "kind": "rejected_evidence", "description": "an evidence record was rejected: " + "; ".join(r["problems"]), "evidence": []})
    for c in diag.conflicts:
        gaps.append({"id": f"conflict:{c['source_id']}#{c['source_sequence']}", "kind": "conflicting_evidence", "description": f"conflicting records for {c['source_id']}#{c['source_sequence']}", "evidence": c["event_ids"]})

    analysis_input = {
        "schema": ANALYSIS_INPUT_SCHEMA,
        "case_id": case_id,
        "cluster_id": cluster_id,
        "analysis_time": analysis_time,
        "profile": {k: profile[k] for k in ("id", "kubernetes_version", "api_audiences", "projected_token_ttl_seconds")},
        "inventory": bundle.inventory,
        "credentials": sorted(credentials.values(), key=lambda c: c["id"]),
        "initial_facts": sorted(facts.values(), key=lambda f: (f["kind"], f["args"])),
        "remediation": case.get("remediation", []),
        "objectives": case.get("objectives", []),
        "legitimate_operations": case.get("legitimate_operations", []),
        "coverage_gaps": sorted(gaps, key=lambda g: g["id"]),
        "assumptions": assumptions,
        "bounds": case.get("bounds", {}),
    }
    # Validate eagerly so malformed inventory surfaces as invalid_input here.
    parse_analysis_input(analysis_input)
    return analysis_input, diag.to_json()
