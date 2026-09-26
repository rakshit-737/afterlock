"""Immutable domain model for AFTERLOCK analysis inputs.

The model is deliberately free of HTTP, database, and Kubernetes client
imports. It parses the canonical ``afterlock.analysis-input/1`` document
(produced by the evidence projector) into typed, frozen values and rejects
malformed or unsupported input instead of guessing.

Identity rules:
  * Objects are identified by UID. Names are labels and never substitute for
    UIDs when resolving bindings between credentials and objects.
  * Authentication (which identity a credential presents) is separate from
    authorization (what that identity may do) and from possession (whether
    the attacker holds the credential) and from knowledge (information the
    attacker has already learned).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

ANALYSIS_INPUT_SCHEMA = "afterlock.analysis-input/1"
SUPPORTED_SCHEMA_MAJOR = 1
SA_USER_PREFIX = "system:serviceaccount:"

EPISTEMIC_OBSERVED = "observed"
EPISTEMIC_ASSUMED = "assumed"
EPISTEMIC_INFERRED = "inferred"
EPISTEMIC_STATUSES = frozenset({EPISTEMIC_OBSERVED, EPISTEMIC_ASSUMED, EPISTEMIC_INFERRED})

SUPPORTED_ADMISSION_KINDS = frozenset({"service-account-restriction"})
SUPPORTED_CREDENTIAL_KINDS = frozenset({"sa_token"})
DEFENDER_ACTION_KINDS = frozenset(
    {
        "remove_binding",
        "delete_pod",
        "delete_controller",
        "delete_service_account",
        "delete_pods_except",
        "delete_controllers_except",
        "rotate_downstream_credential",
        "wait",
    }
)
OBJECTIVE_KINDS = frozenset({"no_secret_read", "no_downstream_use"})
LEGIT_OP_KINDS = frozenset({"read_secret", "use_downstream"})

MAX_STRING = 512
# UIDs the engine assigns to attacker-created objects it models but has not observed.
MODEL_UID_PREFIXES = ("model-pod:", "model-deploy:")
MAX_COLLECTION = 10_000


class ModelError(ValueError):
    """Raised when input violates the analysis-input contract."""


# --------------------------------------------------------------------------
# canonical serialization


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    """SHA-256 of the canonical JSON form. Identifies content; proves nothing else."""
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sa_username(namespace: str, name: str) -> str:
    return f"{SA_USER_PREFIX}{namespace}:{name}"


def parse_sa_username(username: str) -> tuple[str, str] | None:
    if not username.startswith(SA_USER_PREFIX):
        return None
    rest = username[len(SA_USER_PREFIX) :]
    parts = rest.split(":")
    if len(parts) != 2 or not all(parts):
        return None
    return parts[0], parts[1]


# --------------------------------------------------------------------------
# entities


@dataclass(frozen=True, order=True)
class ServiceAccount:
    namespace: str
    name: str
    uid: str

    @property
    def username(self) -> str:
        return sa_username(self.namespace, self.name)


@dataclass(frozen=True, order=True)
class Pod:
    namespace: str
    name: str
    uid: str
    service_account: str
    token_audiences: tuple[str, ...]
    controller_uid: str | None = None


@dataclass(frozen=True, order=True)
class Controller:
    namespace: str
    name: str
    uid: str
    service_account: str
    token_audiences: tuple[str, ...]


@dataclass(frozen=True, order=True)
class PolicyRule:
    verbs: frozenset[str]
    resources: frozenset[str]
    resource_names: frozenset[str] | None  # None: any name

    def matches(self, verb: str, resource: str, name: str | None) -> bool:
        if "*" not in self.verbs and verb not in self.verbs:
            return False
        if "*" not in self.resources and resource not in self.resources:
            return False
        if self.resource_names is None:
            return True
        # A resourceNames-restricted rule never authorizes a request without a name
        # (e.g. create, list), matching Kubernetes RBAC behavior.
        return name is not None and name in self.resource_names


@dataclass(frozen=True, order=True)
class Role:
    namespace: str | None  # None => ClusterRole
    name: str
    rules: tuple[PolicyRule, ...]


@dataclass(frozen=True, order=True)
class Subject:
    kind: str  # ServiceAccount | User | Group
    name: str
    namespace: str | None


@dataclass(frozen=True, order=True)
class RoleBinding:
    namespace: str | None  # None => ClusterRoleBinding
    name: str
    role_kind: str  # Role | ClusterRole
    role_name: str
    subjects: tuple[Subject, ...]

    @property
    def key(self) -> str:
        return f"{self.namespace or '<cluster>'}/{self.name}"


@dataclass(frozen=True, order=True)
class Secret:
    namespace: str
    name: str
    uid: str
    version: int


@dataclass(frozen=True, order=True)
class DownstreamService:
    name: str
    source_namespace: str
    source_secret: str
    accepted_version: int


@dataclass(frozen=True, order=True)
class AdmissionPolicy:
    namespace: str
    name: str
    kind: str
    # creator username -> allowed service account names ("*" key applies to all creators)
    allowed_service_accounts: tuple[tuple[str, tuple[str, ...]], ...]

    @property
    def supported(self) -> bool:
        return self.kind in SUPPORTED_ADMISSION_KINDS


@dataclass(frozen=True)
class Inventory:
    service_accounts: tuple[ServiceAccount, ...]
    pods: tuple[Pod, ...]
    controllers: tuple[Controller, ...]
    roles: tuple[Role, ...]
    bindings: tuple[RoleBinding, ...]
    secrets: tuple[Secret, ...]
    services: tuple[DownstreamService, ...]
    admission_policies: tuple[AdmissionPolicy, ...]


# --------------------------------------------------------------------------
# attacker-state facts supplied by the projector


@dataclass(frozen=True, order=True)
class CredentialSpec:
    """Metadata about a credential. Never contains the credential value."""

    id: str
    kind: str
    username: str
    sa_uid: str | None
    bound_pod_uid: str | None
    audience: str
    expires_at: int | None  # epoch seconds; None = no modeled expiry


@dataclass(frozen=True, order=True)
class InitialFact:
    """An attacker acquisition established before analysis time.

    kind: possesses_credential | controls_pod | controls_controller |
          knows_secret | historical_pod
    """

    kind: str
    args: tuple[str, ...]
    status: str
    evidence: tuple[str, ...]
    note: str = ""


@dataclass(frozen=True, order=True)
class DefenderAction:
    kind: str
    params: tuple[tuple[str, str], ...]

    def param(self, key: str) -> str:
        for k, v in self.params:
            if k == key:
                return v
        raise ModelError(f"defender action {self.kind} missing parameter {key!r}")

    def opt(self, key: str) -> str | None:
        for k, v in self.params:
            if k == key:
                return v
        return None

    def label(self) -> str:
        inner = ", ".join(f"{k}={v}" for k, v in self.params)
        return f"{self.kind}({inner})"

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind}
        for k, v in self.params:
            if k == "seconds":
                out[k] = int(v)
            elif k == "keep_uids":
                out[k] = [x for x in v.split(",") if x]
            else:
                out[k] = v
        return out


@dataclass(frozen=True, order=True)
class Objective:
    id: str
    kind: str
    target: tuple[str, ...]  # (namespace, secret) or (service,)
    description: str


@dataclass(frozen=True, order=True)
class LegitimateOperation:
    id: str
    kind: str
    pod_uid: str
    target: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class CoverageGap:
    id: str
    kind: str
    description: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class Profile:
    id: str
    kubernetes_version: str
    api_audiences: tuple[str, ...]
    projected_token_ttl_seconds: int


@dataclass(frozen=True)
class Bounds:
    max_intervals: int
    max_derivations: int
    max_states: int


@dataclass(frozen=True)
class AnalysisInput:
    case_id: str
    cluster_id: str
    analysis_time: int
    profile: Profile
    inventory: Inventory
    credentials: tuple[CredentialSpec, ...]
    initial_facts: tuple[InitialFact, ...]
    remediation: tuple[DefenderAction, ...]
    objectives: tuple[Objective, ...]
    legitimate_operations: tuple[LegitimateOperation, ...]
    coverage_gaps: tuple[CoverageGap, ...]
    assumptions: tuple[str, ...]
    bounds: Bounds
    raw_digest: str

    def credential(self, cred_id: str) -> CredentialSpec:
        for c in self.credentials:
            if c.id == cred_id:
                return c
        raise ModelError(f"unknown credential {cred_id!r}")

    def with_remediation(self, actions: Sequence[DefenderAction]) -> AnalysisInput:
        from dataclasses import replace

        return replace(self, remediation=tuple(actions))


# --------------------------------------------------------------------------
# parsing helpers


def _obj(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ModelError(f"{where}: expected object")
    return value


def _list(value: Any, where: str) -> Sequence[Any]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ModelError(f"{where}: expected list")
    if len(value) > MAX_COLLECTION:
        raise ModelError(f"{where}: too many entries")
    return value


def _str(m: Mapping[str, Any], key: str, where: str, *, optional: bool = False) -> str | None:
    v = m.get(key)
    if v is None:
        if optional:
            return None
        raise ModelError(f"{where}: missing string {key!r}")
    if not isinstance(v, str) or not v or len(v) > MAX_STRING:
        raise ModelError(f"{where}: {key!r} must be a non-empty string of at most {MAX_STRING} chars")
    return v


def _req(m: Mapping[str, Any], key: str, where: str) -> str:
    v = _str(m, key, where)
    assert v is not None
    return v


def _int(m: Mapping[str, Any], key: str, where: str, *, optional: bool = False, minimum: int = 0) -> int | None:
    v = m.get(key)
    if v is None:
        if optional:
            return None
        raise ModelError(f"{where}: missing integer {key!r}")
    if isinstance(v, bool) or not isinstance(v, int) or v < minimum:
        raise ModelError(f"{where}: {key!r} must be an integer >= {minimum}")
    return v


def _strs(value: Any, where: str) -> tuple[str, ...]:
    out = []
    for i, item in enumerate(_list(value, where)):
        if not isinstance(item, str) or not item or len(item) > MAX_STRING:
            raise ModelError(f"{where}[{i}]: expected non-empty string")
        out.append(item)
    return tuple(out)


def _unique(items: Sequence[Any], key: Any, where: str) -> None:
    seen: set[Any] = set()
    for it in items:
        k = key(it)
        if k in seen:
            raise ModelError(f"{where}: duplicate identifier {k!r}")
        seen.add(k)


# --------------------------------------------------------------------------
# parsing


def parse_profile(raw: Mapping[str, Any]) -> Profile:
    w = "profile"
    ttl = _int(raw, "projected_token_ttl_seconds", w, minimum=1)
    assert ttl is not None
    auds = _strs(raw.get("api_audiences"), f"{w}.api_audiences")
    if not auds:
        raise ModelError("profile.api_audiences must not be empty")
    return Profile(
        id=_req(raw, "id", w),
        kubernetes_version=_req(raw, "kubernetes_version", w),
        api_audiences=auds,
        projected_token_ttl_seconds=ttl,
    )


def _parse_rule(raw: Any, where: str) -> PolicyRule:
    m = _obj(raw, where)
    verbs = _strs(m.get("verbs"), f"{where}.verbs")
    resources = _strs(m.get("resources"), f"{where}.resources")
    if not verbs or not resources:
        raise ModelError(f"{where}: verbs and resources are required")
    names = m.get("resource_names")
    return PolicyRule(
        verbs=frozenset(verbs),
        resources=frozenset(resources),
        resource_names=None if names is None else frozenset(_strs(names, f"{where}.resource_names")),
    )


def parse_inventory(raw: Mapping[str, Any]) -> Inventory:
    w = "inventory"
    sas = tuple(
        ServiceAccount(_req(m, "namespace", w), _req(m, "name", w), _req(m, "uid", w))
        for m in (_obj(x, f"{w}.service_accounts") for x in _list(raw.get("service_accounts"), w))
    )
    pods = []
    for x in _list(raw.get("pods"), f"{w}.pods"):
        m = _obj(x, f"{w}.pods")
        auds = _strs(m.get("token_audiences"), f"{w}.pods.token_audiences") if "token_audiences" in m else ()
        pods.append(
            Pod(
                _req(m, "namespace", w),
                _req(m, "name", w),
                _req(m, "uid", w),
                _req(m, "service_account", w),
                auds,
                _str(m, "controller_uid", w, optional=True),
            )
        )
    controllers = []
    for x in _list(raw.get("controllers"), f"{w}.controllers"):
        m = _obj(x, f"{w}.controllers")
        auds = _strs(m.get("token_audiences"), f"{w}.controllers.token_audiences") if "token_audiences" in m else ()
        controllers.append(
            Controller(_req(m, "namespace", w), _req(m, "name", w), _req(m, "uid", w), _req(m, "service_account", w), auds)
        )
    roles = []
    for x in _list(raw.get("roles"), f"{w}.roles"):
        m = _obj(x, f"{w}.roles")
        rules = tuple(_parse_rule(r, f"{w}.roles.rules") for r in _list(m.get("rules"), f"{w}.roles.rules"))
        roles.append(Role(_str(m, "namespace", w, optional=True), _req(m, "name", w), rules))
    bindings = []
    for x in _list(raw.get("bindings"), f"{w}.bindings"):
        m = _obj(x, f"{w}.bindings")
        role_kind = _req(m, "role_kind", w)
        if role_kind not in ("Role", "ClusterRole"):
            raise ModelError(f"{w}.bindings: unsupported role_kind {role_kind!r}")
        ns = _str(m, "namespace", w, optional=True)
        if ns is None and role_kind == "Role":
            raise ModelError(f"{w}.bindings: a ClusterRoleBinding cannot reference a Role")
        subjects = []
        for s in _list(m.get("subjects"), f"{w}.bindings.subjects"):
            sm = _obj(s, f"{w}.bindings.subjects")
            kind = _req(sm, "kind", w)
            if kind not in ("ServiceAccount", "User", "Group"):
                raise ModelError(f"{w}.bindings.subjects: unsupported kind {kind!r}")
            sns = _str(sm, "namespace", w, optional=True)
            if kind == "ServiceAccount" and sns is None:
                raise ModelError(f"{w}.bindings.subjects: ServiceAccount subject requires namespace")
            subjects.append(Subject(kind, _req(sm, "name", w), sns))
        bindings.append(RoleBinding(ns, _req(m, "name", w), role_kind, _req(m, "role_name", w), tuple(subjects)))
    secrets = []
    for x in _list(raw.get("secrets"), f"{w}.secrets"):
        m = _obj(x, f"{w}.secrets")
        if "data" in m or "string_data" in m or "stringData" in m:
            raise ModelError(f"{w}.secrets: secret bodies must never be supplied")
        v = _int(m, "version", w, minimum=1)
        assert v is not None
        secrets.append(Secret(_req(m, "namespace", w), _req(m, "name", w), _req(m, "uid", w), v))
    services = []
    for x in _list(raw.get("services"), f"{w}.services"):
        m = _obj(x, f"{w}.services")
        v = _int(m, "accepted_version", w, minimum=1)
        assert v is not None
        services.append(DownstreamService(_req(m, "name", w), _req(m, "source_namespace", w), _req(m, "source_secret", w), v))
    policies = []
    for x in _list(raw.get("admission_policies"), f"{w}.admission_policies"):
        m = _obj(x, f"{w}.admission_policies")
        allowed_raw = m.get("allowed_service_accounts") or {}
        allowed = tuple(
            sorted((str(k), _strs(v, f"{w}.admission_policies.allowed")) for k, v in _obj(allowed_raw, w).items())
        )
        policies.append(AdmissionPolicy(_req(m, "namespace", w), _req(m, "name", w), _req(m, "kind", w), allowed))

    _unique(sas, lambda s: s.uid, f"{w}.service_accounts uid")
    _unique(sas, lambda s: (s.namespace, s.name), f"{w}.service_accounts name")
    _unique(pods, lambda p: p.uid, f"{w}.pods uid")
    _unique(pods, lambda p: (p.namespace, p.name), f"{w}.pods name")
    _unique(controllers, lambda c: c.uid, f"{w}.controllers uid")
    _unique(roles, lambda r: (r.namespace, r.name), f"{w}.roles")
    _unique(bindings, lambda b: (b.namespace, b.name), f"{w}.bindings")
    _unique(secrets, lambda s: (s.namespace, s.name), f"{w}.secrets")
    _unique(services, lambda s: s.name, f"{w}.services")
    ctrl_uids = {c.uid for c in controllers}
    for p in pods:
        if p.controller_uid is not None and p.controller_uid not in ctrl_uids:
            raise ModelError(f"{w}.pods: pod {p.uid} references unknown controller {p.controller_uid}")
    return Inventory(
        tuple(sorted(sas)),
        tuple(sorted(pods)),
        tuple(sorted(controllers)),
        tuple(sorted(roles, key=lambda r: (r.namespace or "", r.name))),
        tuple(sorted(bindings, key=lambda b: (b.namespace or "", b.name))),
        tuple(sorted(secrets)),
        tuple(sorted(services)),
        tuple(sorted(policies)),
    )


_FACT_ARITY = {
    "possesses_credential": 1,
    "controls_pod": 1,
    "controls_controller": 1,
    "knows_secret": 3,  # namespace, name, version
    "historical_pod": 3,  # uid, namespace, service_account (attacker-controlled, possibly deleted)
}


def _parse_action(raw: Any, where: str) -> DefenderAction:
    m = _obj(raw, where)
    kind = _req(m, "kind", where)
    if kind not in DEFENDER_ACTION_KINDS:
        raise ModelError(f"{where}: unsupported defender action {kind!r}")
    required = {
        "remove_binding": ("name",),
        "delete_pod": ("uid",),
        "delete_controller": ("uid",),
        "delete_service_account": ("namespace", "name"),
        "delete_pods_except": ("namespace", "service_account"),
        "delete_controllers_except": ("namespace", "service_account"),
        "rotate_downstream_credential": ("service",),
        "wait": (),
    }[kind]
    params: list[tuple[str, str]] = []
    for key in required:
        params.append((key, _req(m, key, where)))
    if kind in ("delete_pod", "delete_controller") and dict(params)["uid"].startswith(MODEL_UID_PREFIXES):
        raise ModelError(f"{where}: UIDs with prefixes {MODEL_UID_PREFIXES} are reserved for model-created objects")
    if kind in ("delete_pods_except", "delete_controllers_except"):
        keep = sorted(set(_strs(m.get("keep_uids"), f"{where}.keep_uids")))
        if any("," in k for k in keep):
            raise ModelError(f"{where}: keep_uids entries must not contain commas")
        params.append(("keep_uids", ",".join(keep)))
    if kind == "remove_binding":
        ns = _str(m, "namespace", where, optional=True)
        if ns is not None:
            params.append(("namespace", ns))
    if kind == "wait":
        secs = _int(m, "seconds", where, minimum=1)
        params.append(("seconds", str(secs)))
    extra = set(m) - {"kind", "namespace", *required, "seconds", "keep_uids"}
    if extra:
        raise ModelError(f"{where}: unknown fields {sorted(extra)}")
    return DefenderAction(kind, tuple(sorted(params)))


def parse_actions(raw: Any, where: str = "remediation") -> tuple[DefenderAction, ...]:
    return tuple(_parse_action(a, f"{where}[{i}]") for i, a in enumerate(_list(raw, where)))


def parse_analysis_input(raw: Mapping[str, Any]) -> AnalysisInput:
    raw = _obj(raw, "analysis input")
    schema = raw.get("schema")
    if not isinstance(schema, str) or not schema.startswith("afterlock.analysis-input/"):
        raise ModelError("unrecognized schema identifier")
    try:
        major = int(schema.rsplit("/", 1)[1].split(".")[0])
    except ValueError as exc:
        raise ModelError("malformed schema version") from exc
    if major != SUPPORTED_SCHEMA_MAJOR:
        raise ModelError(f"unsupported schema major version {major}")
    w = "analysis input"
    analysis_time = _int(raw, "analysis_time", w)
    assert analysis_time is not None
    profile = parse_profile(_obj(raw.get("profile"), "profile"))
    inventory = parse_inventory(_obj(raw.get("inventory"), "inventory"))

    creds = []
    for x in _list(raw.get("credentials"), "credentials"):
        m = _obj(x, "credentials")
        creds.append(
            CredentialSpec(
                id=_req(m, "id", "credentials"),
                kind=_req(m, "kind", "credentials"),
                username=_req(m, "username", "credentials"),
                sa_uid=_str(m, "sa_uid", "credentials", optional=True),
                bound_pod_uid=_str(m, "bound_pod_uid", "credentials", optional=True),
                audience=_req(m, "audience", "credentials"),
                expires_at=_int(m, "expires_at", "credentials", optional=True),
            )
        )
    _unique(creds, lambda c: c.id, "credentials")
    cred_ids = {c.id for c in creds}

    facts = []
    for x in _list(raw.get("initial_facts"), "initial_facts"):
        m = _obj(x, "initial_facts")
        kind = _req(m, "kind", "initial_facts")
        if kind not in _FACT_ARITY:
            raise ModelError(f"initial_facts: unsupported fact kind {kind!r}")
        args = _strs(m.get("args"), "initial_facts.args")
        if len(args) != _FACT_ARITY[kind]:
            raise ModelError(f"initial_facts: {kind} expects {_FACT_ARITY[kind]} args")
        status = _req(m, "status", "initial_facts")
        if status not in EPISTEMIC_STATUSES:
            raise ModelError(f"initial_facts: unknown epistemic status {status!r}")
        if kind == "possesses_credential" and args[0] not in cred_ids:
            raise ModelError(f"initial_facts: unknown credential {args[0]!r}")
        if kind == "knows_secret":
            try:
                if int(args[2]) < 1:
                    raise ValueError
            except ValueError as exc:
                raise ModelError("initial_facts: knows_secret version must be a positive integer") from exc
        facts.append(
            InitialFact(kind, args, status, _strs(m.get("evidence"), "initial_facts.evidence"), str(m.get("note", ""))[:MAX_STRING])
        )

    objectives = []
    for x in _list(raw.get("objectives"), "objectives"):
        m = _obj(x, "objectives")
        kind = _req(m, "kind", "objectives")
        if kind not in OBJECTIVE_KINDS:
            raise ModelError(f"objectives: unsupported objective kind {kind!r}")
        target = (
            (_req(m, "namespace", "objectives"), _req(m, "secret", "objectives"))
            if kind == "no_secret_read"
            else (_req(m, "service", "objectives"),)
        )
        objectives.append(Objective(_req(m, "id", "objectives"), kind, target, str(m.get("description", ""))[:MAX_STRING]))
    if not objectives:
        raise ModelError("at least one objective is required")
    _unique(objectives, lambda o: o.id, "objectives")

    legit = []
    for x in _list(raw.get("legitimate_operations"), "legitimate_operations"):
        m = _obj(x, "legitimate_operations")
        kind = _req(m, "kind", "legitimate_operations")
        if kind not in LEGIT_OP_KINDS:
            raise ModelError(f"legitimate_operations: unsupported kind {kind!r}")
        target = (
            (_req(m, "namespace", "legitimate_operations"), _req(m, "secret", "legitimate_operations"))
            if kind == "read_secret"
            else (_req(m, "service", "legitimate_operations"),)
        )
        legit.append(
            LegitimateOperation(
                _req(m, "id", "legitimate_operations"),
                kind,
                _req(m, "pod_uid", "legitimate_operations"),
                target,
                str(m.get("description", ""))[:MAX_STRING],
            )
        )
    _unique(legit, lambda o: o.id, "legitimate_operations")

    gaps = []
    for x in _list(raw.get("coverage_gaps"), "coverage_gaps"):
        m = _obj(x, "coverage_gaps")
        gaps.append(
            CoverageGap(
                _req(m, "id", "coverage_gaps"),
                _req(m, "kind", "coverage_gaps"),
                str(m.get("description", ""))[:MAX_STRING],
                _strs(m.get("evidence"), "coverage_gaps.evidence"),
            )
        )

    b = _obj(raw.get("bounds") or {}, "bounds")
    bounds = Bounds(
        max_intervals=_int(b, "max_intervals", "bounds", optional=True, minimum=1) or 64,
        max_derivations=_int(b, "max_derivations", "bounds", optional=True, minimum=1) or 100_000,
        max_states=_int(b, "max_states", "bounds", optional=True, minimum=1) or 200_000,
    )
    remediation = parse_actions(raw.get("remediation"))
    if len(remediation) + 1 > bounds.max_intervals:
        raise ModelError("remediation longer than bounds.max_intervals")

    return AnalysisInput(
        case_id=_req(raw, "case_id", w),
        cluster_id=_req(raw, "cluster_id", w),
        analysis_time=analysis_time,
        profile=profile,
        inventory=inventory,
        credentials=tuple(sorted(creds)),
        initial_facts=tuple(sorted(facts)),
        remediation=remediation,
        objectives=tuple(sorted(objectives)),
        legitimate_operations=tuple(sorted(legit)),
        coverage_gaps=tuple(sorted(gaps, key=lambda g: g.id)),
        assumptions=_strs(raw.get("assumptions"), "assumptions"),
        bounds=bounds,
        raw_digest=digest(raw),
    )
