"""Production capability engine.

The engine evaluates a remediation sequence interval by interval. Interval 0
is the environment at analysis time; interval k is the environment after the
k-th defender action. Between defender actions the attacker performs every
supported transition (the attacker does not pause while the defender works).

Supported attacker transitions only *add* attacker capability, so the
per-interval fixpoint is the join of all attacker interleavings. The
independent reference checker explores interleavings explicitly and is used
as a differential oracle for this claim.

Facts (tuples):
  persistent  ("possesses", cred_id)
              ("controls_pod", pod_uid)
              ("controls_controller", controller_uid)
              ("knows_secret", ns, name, version)        # knowledge: monotone
              ("possesses_downstream", service, version)
  ephemeral   ("can_read_secret", ns, name)              # capability at an interval
              ("can_use_downstream", service)

Every derived fact carries a provenance hyperedge: the rule, the conjunction
of premise facts, and the environmental conditions that were checked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import (
    EPISTEMIC_ASSUMED,
    EPISTEMIC_INFERRED,
    EPISTEMIC_OBSERVED,
    AnalysisInput,
    Controller,
    CredentialSpec,
    Pod,
)
from .semantics import (
    Env,
    admission_decision,
    apply_defender_action,
    authorizing_bindings,
    credential_usable,
    legit_can_read,
    legit_can_use_service,
    model_controller_uid,
    model_pod_uid,
    reconcile_controllers,
    secrets_feeding,
)

Fact = tuple[str, ...]

INITIAL_INTERVAL = -2
HISTORY_INTERVAL = -1

VIEW_EVIDENCE = "evidence_supported"
VIEW_POSSIBLE = "conservative_possible"

MODE_FULL = "full"
MODE_SNAPSHOT = "snapshot_only"
MODE_NO_LIFECYCLE = "history_without_lifecycle"
MODE_FINAL_STATE = "final_state_only"
MODES = (MODE_FULL, MODE_SNAPSHOT, MODE_NO_LIFECYCLE, MODE_FINAL_STATE)

_INITIAL_FACT_NAMES = {
    "possesses_credential": "possesses",
    "controls_pod": "controls_pod",
    "controls_controller": "controls_controller",
    "knows_secret": "knows_secret",
}

PERSISTENT_KINDS = frozenset({"possesses", "controls_pod", "controls_controller", "knows_secret", "possesses_downstream"})


@dataclass(frozen=True)
class Derivation:
    fact: Fact
    rule: str
    interval: int
    premises: tuple[Fact, ...]
    conditions: tuple[dict[str, Any], ...]
    status: str
    evidence: tuple[str, ...] = ()
    note: str = ""

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "fact": list(self.fact),
            "rule": self.rule,
            "interval": self.interval,
            "premises": [list(p) for p in self.premises],
            "conditions": list(self.conditions),
            "status": self.status,
        }
        if self.evidence:
            out["evidence"] = list(self.evidence)
        if self.note:
            out["note"] = self.note
        return out


class BoundsExceeded(Exception):
    pass


@dataclass
class IntervalRecord:
    index: int
    time: int
    action: str | None
    notes: list[str]
    goals: list[Fact]
    reconciled_pods: list[str]


@dataclass
class ViewOutcome:
    view: str
    goals_final: dict[Fact, Derivation]
    derivations: dict[Fact, Derivation]
    credentials: dict[str, CredentialSpec]
    intervals: list[IntervalRecord]
    unknowns: list[dict[str, Any]]
    bounds_exceeded: bool
    final_env: Env
    derivation_count: int

    def witness(self, goal: Fact) -> list[Derivation]:
        """Topologically ordered provenance for ``goal`` (premises first)."""
        out: list[Derivation] = []
        seen: set[Fact] = set()

        def visit(f: Fact, table: dict[Fact, Derivation]) -> None:
            if f in seen:
                return
            seen.add(f)
            d = table.get(f) or self.derivations[f]
            for p in d.premises:
                visit(p, self.derivations)
            out.append(d)

        visit(goal, self.goals_final)
        return out


@dataclass
class _Attacker:
    facts: dict[Fact, Derivation] = field(default_factory=dict)
    creds: dict[str, CredentialSpec] = field(default_factory=dict)


class _Run:
    def __init__(self, inp: AnalysisInput, view: str, mode: str) -> None:
        self.inp = inp
        self.view = view
        self.mode = mode
        self.profile = inp.profile
        self.count = 0
        self.unknowns: dict[str, dict[str, Any]] = {}

    # -- bookkeeping -------------------------------------------------------
    def _tick(self) -> None:
        self.count += 1
        if self.count > self.inp.bounds.max_derivations:
            raise BoundsExceeded()

    def _unknown(self, key: str, record: dict[str, Any]) -> None:
        self.unknowns.setdefault(key, record)

    def _usable(self, env: Env, cred: CredentialSpec) -> tuple[bool, dict[str, Any]]:
        u = credential_usable(env, cred, self.profile)
        if not u.supported:
            self._unknown(
                f"cred:{cred.id}",
                {"kind": "unsupported_credential", "credential": cred.id, "detail": "; ".join(u.reasons)},
            )
            return False, {}
        usable = u.usable
        if self.mode == MODE_NO_LIFECYCLE:
            usable = True  # baseline: ignores expiry, audience and bound-object checks
        cond = {"check": "credential_usable", "credential": cred.id, "time": env.time, "detail": "; ".join(u.reasons)}
        return usable, cond

    # -- initial state ------------------------------------------------------
    def initial(self) -> tuple[_Attacker, list[Fact]]:
        att = _Attacker()
        historical: list[Fact] = []
        for f in self.inp.initial_facts:
            if self.view == VIEW_EVIDENCE and f.status == EPISTEMIC_INFERRED:
                continue
            if self.mode == MODE_SNAPSHOT and not (f.kind == "possesses_credential" and f.status == EPISTEMIC_ASSUMED):
                continue  # snapshot baseline keeps only the seeded compromise
            if f.kind == "historical_pod":
                historical.append(("historical_pod", *f.args))
                continue
            fact: Fact = (_INITIAL_FACT_NAMES[f.kind], *f.args)
            if fact[0] == "possesses":
                att.creds[fact[1]] = self.inp.credential(fact[1])
            att.facts[fact] = Derivation(fact, "EVIDENCE", INITIAL_INTERVAL, (), (), f.status, f.evidence, f.note)
        return att, historical

    # -- closure -------------------------------------------------------------
    def _add(self, att: _Attacker, eph: dict[Fact, Derivation], d: Derivation) -> bool:
        table = eph if d.fact[0] not in PERSISTENT_KINDS else att.facts
        if d.fact in table:
            return False
        self._tick()
        table[d.fact] = d
        return True

    def _controls_live(self, att: _Attacker, env: Env, ns: str, sa: str, kind: str) -> bool:
        """Canonicalization: is there already a live *model-created* workload for (ns, SA)?

        Sound because defender actions cannot address model-created objects
        individually (their UIDs are reserved) and selector-based deletions
        treat all of them alike, so additional copies behave identically.
        Observed attacker workloads never satisfy this check.
        """
        for f in att.facts:
            if f[0] == "controls_pod" and kind == "pod" and f[1].startswith("model-pod:"):
                p = env.pods.get(f[1])
                if p is not None and p.namespace == ns and p.service_account == sa:
                    return True
            if f[0] == "controls_controller" and kind == "controller" and f[1].startswith("model-deploy:"):
                c = env.controllers.get(f[1])
                if c is not None and c.namespace == ns and c.service_account == sa:
                    return True
        return False

    def closure(self, att: _Attacker, env: Env, interval: int) -> dict[Fact, Derivation]:
        eph: dict[Fact, Derivation] = {}
        status = EPISTEMIC_INFERRED
        while True:
            changed = False
            # controlled controllers control their current Pods
            for f in sorted(k for k in att.facts if k[0] == "controls_controller"):
                for puid in sorted(env.pods):
                    p = env.pods[puid]
                    if p.controller_uid == f[1]:
                        d = Derivation(
                            ("controls_pod", puid), "R-CONTROLLER-POD", interval, (f,),
                            ({"check": "pod_owned_by_controller", "pod": puid, "controller": f[1]},), status,
                        )
                        changed |= self._add(att, eph, d)
            # a controlled, existing Pod yields its projected token(s)
            for f in sorted(k for k in att.facts if k[0] == "controls_pod"):
                pod = env.pods.get(f[1])
                if pod is None:
                    continue
                sa = env.service_accounts.get((pod.namespace, pod.service_account))
                if sa is None:
                    continue
                for aud in pod.token_audiences or (self.profile.api_audiences[0],):
                    cid = f"projected:{pod.uid}:{aud}"
                    exp = env.time + self.profile.projected_token_ttl_seconds
                    prev = att.creds.get(cid)
                    if prev is not None and prev.expires_at is not None and prev.expires_at >= exp:
                        continue
                    att.creds[cid] = CredentialSpec(cid, "sa_token", sa.username, sa.uid, pod.uid, aud, exp)
                    fact = ("possesses", cid)
                    d = Derivation(
                        fact, "R-OBTAIN-PROJECTED-TOKEN", interval, (f,),
                        (
                            {"check": "pod_exists", "pod": pod.uid},
                            {"check": "service_account_exists", "namespace": sa.namespace, "name": sa.name, "uid": sa.uid},
                        ),
                        status,
                        note=f"token for audience {aud}, expires {exp}",
                    )
                    self._tick()
                    att.facts[fact] = d
                    changed = True
            # credential-driven API requests
            for f in sorted(k for k in att.facts if k[0] == "possesses"):
                cred = att.creds[f[1]]
                ok, ucond = self._usable(env, cred)
                if not ok:
                    continue
                user = cred.username
                for ns in env.namespaces():
                    via = authorizing_bindings(env, user, "create", "pods", ns, None)
                    if via:
                        changed |= self._create_workloads(att, eph, env, interval, f, ucond, user, ns, via, "pod")
                    via = authorizing_bindings(env, user, "create", "deployments", ns, None)
                    if via:
                        changed |= self._create_workloads(att, eph, env, interval, f, ucond, user, ns, via, "controller")
                for puid in sorted(env.pods):
                    p = env.pods[puid]
                    via = authorizing_bindings(env, user, "create", "pods/exec", p.namespace, p.name)
                    if via:
                        d = Derivation(
                            ("controls_pod", puid), "R-EXEC-POD", interval, (f, *_object_premises(p)),
                            (ucond, _authz(user, "create", "pods/exec", p.namespace, p.name, via)), status,
                        )
                        changed |= self._add(att, eph, d)
                for key in sorted(env.secrets):
                    s = env.secrets[key]
                    via = authorizing_bindings(env, user, "get", "secrets", s.namespace, s.name)
                    if not via:
                        continue
                    conds = (ucond, _authz(user, "get", "secrets", s.namespace, s.name, via),
                             {"check": "secret_version", "namespace": s.namespace, "name": s.name, "version": s.version})
                    changed |= self._add(att, eph, Derivation(("knows_secret", s.namespace, s.name, str(s.version)), "R-READ-SECRET", interval, (f,), conds, status))
                    changed |= self._add(att, eph, Derivation(("can_read_secret", s.namespace, s.name), "R-READ-SECRET", interval, (f,), conds, status))
            # knowledge of a secret is possession of the downstream credential derived from it
            for f in sorted(k for k in att.facts if k[0] == "knows_secret"):
                for svc in secrets_feeding(env, f[1], f[2]):
                    d = Derivation(
                        ("possesses_downstream", svc.name, f[3]), "R-DOWNSTREAM-CREDENTIAL", interval, (f,),
                        ({"check": "service_sources", "service": svc.name, "namespace": f[1], "secret": f[2]},), status,
                    )
                    changed |= self._add(att, eph, d)
            for f in sorted(k for k in att.facts if k[0] == "possesses_downstream"):
                target = env.services.get(f[1])
                if target is not None and str(target.accepted_version) == f[2]:
                    d = Derivation(
                        ("can_use_downstream", target.name), "R-USE-DOWNSTREAM", interval, (f,),
                        ({"check": "service_accepts", "service": target.name, "version": target.accepted_version},), status,
                    )
                    changed |= self._add(att, eph, d)
            if not changed:
                return eph

    def _create_workloads(
        self, att: _Attacker, eph: dict[Fact, Derivation], env: Env, interval: int, cred_fact: Fact,
        ucond: dict[str, Any], user: str, ns: str, via: list[str], kind: str,
    ) -> bool:
        changed = False
        resource = "pods" if kind == "pod" else "deployments"
        for (sns, sname) in sorted(env.service_accounts):
            if sns != ns:
                continue
            if self._controls_live(att, env, ns, sname, kind):
                continue  # canonicalization: one live attacker workload per (ns, SA) suffices
            adm = admission_decision(env, user, ns, sname)
            if adm.outcome == "unsupported":
                self._unknown(
                    f"adm:{ns}:{user}:{sname}:{kind}",
                    {
                        "kind": "unsupported_admission",
                        "namespace": ns,
                        "creator": user,
                        "service_account": sname,
                        "policies": list(adm.policies),
                        "detail": f"cannot evaluate whether {user} may create a {resource[:-1]} running as {sname}",
                    },
                )
                continue
            if adm.outcome == "deny":
                continue
            conds = (
                ucond,
                _authz(user, "create", resource, ns, None, via),
                {"check": "admission_allows", "creator": user, "namespace": ns, "service_account": sname, "policies": list(adm.policies)},
                {"check": "service_account_exists", "namespace": ns, "name": sname},
            )
            if kind == "pod":
                uid = model_pod_uid(ns, sname, interval)
                if uid in env.pods:
                    continue
                env.pods[uid] = Pod(ns, uid, uid, sname, (), None)
                changed |= self._add(att, eph, Derivation(("controls_pod", uid), "R-CREATE-POD", interval, (cred_fact,), conds, EPISTEMIC_INFERRED))
            else:
                cuid = model_controller_uid(ns, sname, interval)
                if cuid in env.controllers:
                    continue
                env.controllers[cuid] = Controller(ns, cuid, cuid, sname, ())
                env.controller_pod_counter[cuid] = -1
                reconcile_controllers(env)  # creates <cuid>-p0
                changed |= self._add(att, eph, Derivation(("controls_controller", cuid), "R-CREATE-CONTROLLER", interval, (cred_fact,), conds, EPISTEMIC_INFERRED))
        return changed


def _object_premises(pod: Pod) -> tuple[Fact, ...]:
    """A pod that exists only because the attacker created it must carry that
    creation in its provenance, or a witness would rely on an unexplained object."""
    if pod.controller_uid is not None and pod.controller_uid.startswith("model-deploy:"):
        return (("controls_controller", pod.controller_uid),)
    if pod.uid.startswith("model-pod:"):
        return (("controls_pod", pod.uid),)
    return ()


def _authz(user: str, verb: str, resource: str, ns: str, name: str | None, via: list[str]) -> dict[str, Any]:
    return {"check": "authorized", "username": user, "verb": verb, "resource": resource, "namespace": ns, "name": name, "via": list(via)}


def run_view(inp: AnalysisInput, view: str, mode: str = MODE_FULL) -> ViewOutcome:
    run = _Run(inp, view, mode)
    att, historical = run.initial()
    env = Env.from_inventory(inp.inventory, inp.analysis_time)
    intervals: list[IntervalRecord] = []
    goals_final: dict[Fact, Derivation] = {}
    bounds_exceeded = False
    try:
        if view == VIEW_POSSIBLE and historical:
            # Possible history: absence of audit records does not prove absence of
            # activity. Before analysis time the attacker could have done anything the
            # (assumed unchanged) environment allowed, including through controlled Pods
            # that have since been deleted. Objects created in this phase are not in the
            # current inventory, so they are discarded (henv is a scratch copy); knowledge,
            # credentials, and control of Pods that still exist carry forward.
            henv = env.clone()
            for _, uid, ns, sa in historical:
                if uid not in henv.pods:
                    henv.pods[uid] = Pod(ns, uid, uid, sa, (), None)
                att.facts.setdefault(
                    ("controls_pod", uid),
                    Derivation(("controls_pod", uid), "EVIDENCE", INITIAL_INTERVAL, (), (), EPISTEMIC_OBSERVED,
                               note="historically controlled pod"),
                )
            run.closure(att, henv, HISTORY_INTERVAL)
        actions = list(inp.remediation)
        if mode in (MODE_FINAL_STATE, MODE_SNAPSHOT):
            # baselines: evaluate only the final configuration, no interleaving
            notes: list[str] = []
            for a in actions:
                notes += apply_defender_action(env, a)
                reconcile_controllers(env)
            eph = run.closure(att, env, 0)
            goals_final = eph
            intervals.append(IntervalRecord(0, env.time, "; ".join(a.label() for a in actions) or None, notes, sorted(eph), []))
        else:
            reconciled = [p.uid for p in reconcile_controllers(env)]
            for i in range(len(actions) + 1):
                notes = []
                label = None
                if i > 0:
                    a = actions[i - 1]
                    label = a.label()
                    notes = apply_defender_action(env, a)
                    reconciled = [p.uid for p in reconcile_controllers(env)]
                eph = run.closure(att, env, i)
                intervals.append(IntervalRecord(i, env.time, label, notes, sorted(eph), reconciled))
                goals_final = eph
                reconciled = []
    except BoundsExceeded:
        bounds_exceeded = True
    return ViewOutcome(
        view=view,
        goals_final=goals_final,
        derivations=att.facts,
        credentials=att.creds,
        intervals=intervals,
        unknowns=[run.unknowns[k] for k in sorted(run.unknowns)],
        bounds_exceeded=bounds_exceeded,
        final_env=env,
        derivation_count=run.count,
    )


# --------------------------------------------------------------------------
# objective and legitimate-operation evaluation


def objective_goal(kind: str, target: tuple[str, ...]) -> Fact:
    if kind == "no_secret_read":
        return ("can_read_secret", target[0], target[1])
    return ("can_use_downstream", target[0])


def legit_status(inp: AnalysisInput, env: Env) -> list[dict[str, Any]]:
    out = []
    for op in inp.legitimate_operations:
        if op.kind == "read_secret":
            ok, why = legit_can_read(env, op.pod_uid, op.target[0], op.target[1])
        else:
            ok, why = legit_can_use_service(env, op.pod_uid, op.target[0])
        out.append({"id": op.id, "kind": op.kind, "preserved": ok, "detail": why, "description": op.description})
    return out


__all__ = [
    "Derivation",
    "ViewOutcome",
    "run_view",
    "objective_goal",
    "legit_status",
    "VIEW_EVIDENCE",
    "VIEW_POSSIBLE",
    "MODES",
    "MODE_FULL",
    "MODE_SNAPSHOT",
    "MODE_NO_LIFECYCLE",
    "MODE_FINAL_STATE",
]
