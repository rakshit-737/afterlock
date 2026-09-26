"""Supported Kubernetes semantics for the ``k8s-1.31-core-v1`` profile.

Every function here states a rule documented in docs/semantics/supported.md.
Anything outside that list is reported as *unsupported*, never silently
treated as allow or deny.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, replace

from .model import (
    SUPPORTED_CREDENTIAL_KINDS,
    AdmissionPolicy,
    Controller,
    CredentialSpec,
    DefenderAction,
    DownstreamService,
    Inventory,
    Pod,
    Profile,
    Role,
    RoleBinding,
    Secret,
    ServiceAccount,
    parse_sa_username,
    sa_username,
)


@dataclass
class Env:
    """Mutable environment snapshot for a single analysis interval.

    Copied (``clone``) between intervals so earlier intervals remain intact.
    """

    time: int
    service_accounts: dict[tuple[str, str], ServiceAccount]
    pods: dict[str, Pod]
    controllers: dict[str, Controller]
    roles: dict[tuple[str | None, str], Role]
    bindings: dict[tuple[str | None, str], RoleBinding]
    secrets: dict[tuple[str, str], Secret]
    services: dict[str, DownstreamService]
    admission: tuple[AdmissionPolicy, ...]
    controller_pod_counter: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_inventory(cls, inv: Inventory, time: int) -> Env:
        return cls(
            time=time,
            service_accounts={(s.namespace, s.name): s for s in inv.service_accounts},
            pods={p.uid: p for p in inv.pods},
            controllers={c.uid: c for c in inv.controllers},
            roles={(r.namespace, r.name): r for r in inv.roles},
            bindings={(b.namespace, b.name): b for b in inv.bindings},
            secrets={(s.namespace, s.name): s for s in inv.secrets},
            services={s.name: s for s in inv.services},
            admission=inv.admission_policies,
        )

    def clone(self) -> Env:
        return Env(
            time=self.time,
            service_accounts=dict(self.service_accounts),
            pods=dict(self.pods),
            controllers=dict(self.controllers),
            roles=dict(self.roles),
            bindings=dict(self.bindings),
            secrets=dict(self.secrets),
            services=dict(self.services),
            admission=self.admission,
            controller_pod_counter=dict(self.controller_pod_counter),
        )

    def namespaces(self) -> list[str]:
        return sorted({ns for ns, _ in self.service_accounts} | {p.namespace for p in self.pods.values()})


# --------------------------------------------------------------------------
# RBAC


def _subject_matches(binding: RoleBinding, username: str) -> bool:
    sa = parse_sa_username(username)
    for s in binding.subjects:
        if s.kind == "ServiceAccount" and sa is not None and (s.namespace, s.name) == sa:
            return True
        if s.kind == "User" and s.name == username:
            return True
        if s.kind == "Group":
            if s.name == "system:authenticated":
                return True
            if sa is not None and s.name in ("system:serviceaccounts", f"system:serviceaccounts:{sa[0]}"):
                return True
    return False


def authorizing_bindings(env: Env, username: str, verb: str, resource: str, namespace: str, name: str | None) -> list[str]:
    """Return keys of bindings that authorize the request; empty list means denied.

    RBAC is purely additive. A RoleBinding grants only in its namespace (even
    when it references a ClusterRole); a ClusterRoleBinding grants everywhere.
    A binding that references a missing role grants nothing.
    """
    grants = []
    for key in sorted(env.bindings, key=lambda k: (k[0] or "", k[1])):
        b = env.bindings[key]
        if b.namespace is not None and b.namespace != namespace:
            continue
        if not _subject_matches(b, username):
            continue
        role_ns = b.namespace if b.role_kind == "Role" else None
        role = env.roles.get((role_ns, b.role_name))
        if role is None:
            continue
        if any(rule.matches(verb, resource, name) for rule in role.rules):
            grants.append(b.key)
    return grants


# --------------------------------------------------------------------------
# credentials


@dataclass(frozen=True)
class Usability:
    usable: bool
    supported: bool
    reasons: tuple[str, ...]


def credential_usable(env: Env, cred: CredentialSpec, profile: Profile) -> Usability:
    """Whether the Kubernetes API would accept ``cred`` at ``env.time``.

    Projected service-account tokens are rejected when expired, when their
    audience is not an API-server audience, when the service account no
    longer exists with the same UID, or when the bound Pod no longer exists
    with the same UID. Name matches never substitute for UID matches.
    """
    if cred.kind not in SUPPORTED_CREDENTIAL_KINDS:
        return Usability(False, False, (f"credential kind {cred.kind!r} is not supported by profile {profile.id}",))
    reasons = []
    ok = True
    if cred.expires_at is not None and env.time >= cred.expires_at:
        ok = False
        reasons.append(f"expired at {cred.expires_at} (analysis time {env.time})")
    if cred.audience not in profile.api_audiences:
        ok = False
        reasons.append(f"audience {cred.audience!r} is not accepted by the API server")
    sa = parse_sa_username(cred.username)
    if sa is None:
        return Usability(False, False, (f"username {cred.username!r} is not a service account",))
    acct = env.service_accounts.get(sa)
    if acct is None:
        ok = False
        reasons.append(f"service account {sa[0]}/{sa[1]} no longer exists")
    elif cred.sa_uid is not None and acct.uid != cred.sa_uid:
        ok = False
        reasons.append(f"service account {sa[0]}/{sa[1]} was recreated with a different UID")
    if cred.bound_pod_uid is not None:
        pod = env.pods.get(cred.bound_pod_uid)
        if pod is None:
            ok = False
            reasons.append(f"bound pod UID {cred.bound_pod_uid} no longer exists")
        elif (pod.namespace, pod.service_account) != sa:
            ok = False
            reasons.append(f"bound pod UID {cred.bound_pod_uid} does not run as {cred.username}")
    if ok:
        reasons.append("unexpired, API audience, service account UID and bound object present")
    return Usability(ok, True, tuple(reasons))


# --------------------------------------------------------------------------
# admission


@dataclass(frozen=True)
class AdmissionDecision:
    outcome: str  # allow | deny | unsupported
    policies: tuple[str, ...]


def admission_decision(env: Env, creator: str, namespace: str, service_account: str) -> AdmissionDecision:
    """Evaluate supported admission policies for a workload the creator submits.

    Only the ``service-account-restriction`` kind is supported. It applies to
    Pods and to workload pod templates submitted by the listed creator. Any
    other policy in the namespace makes the outcome ``unsupported``.
    """
    relevant = [p for p in env.admission if p.namespace == namespace]
    unsupported = [p.name for p in relevant if not p.supported]
    if unsupported:
        return AdmissionDecision("unsupported", tuple(sorted(unsupported)))
    for p in relevant:
        allowed = dict(p.allowed_service_accounts)
        names = allowed.get(creator, allowed.get("*"))
        if names is None:
            continue
        if "*" not in names and service_account not in names:
            return AdmissionDecision("deny", (p.name,))
    return AdmissionDecision("allow", tuple(sorted(p.name for p in relevant)))


# --------------------------------------------------------------------------
# environment transitions


def model_pod_uid(namespace: str, service_account: str, interval: int) -> str:
    return f"model-pod:{namespace}:{service_account}:i{interval}"


def model_controller_uid(namespace: str, service_account: str, interval: int) -> str:
    return f"model-deploy:{namespace}:{service_account}:i{interval}"


def reconcile_controllers(env: Env) -> list[Pod]:
    """Controllers recreate a Pod whenever none of theirs exists.

    Assumption (documented): reconciliation completes before the next
    defender step. Replacement Pods receive new UIDs ``<controller>-p<k>``, taking
    the next ``k`` whose UID no existing Pod has: a replacement never overwrites
    another Pod (which would silently drop that Pod and the control it confers).
    """
    created = []
    for cuid in sorted(env.controllers):
        c = env.controllers[cuid]
        if any(p.controller_uid == cuid for p in env.pods.values()):
            continue
        k = env.controller_pod_counter.get(cuid, 0) + 1
        while f"{cuid}-p{k}" in env.pods:
            k += 1
        env.controller_pod_counter[cuid] = k
        pod = Pod(c.namespace, f"{c.name}-p{k}", f"{cuid}-p{k}", c.service_account, c.token_audiences, cuid)
        env.pods[pod.uid] = pod
        created.append(pod)
    return created


def apply_defender_action(env: Env, action: DefenderAction) -> list[str]:
    """Apply a defender action in place. Returns notes (e.g. no-op warnings)."""
    notes: list[str] = []
    k = action.kind
    if k == "remove_binding":
        key = (action.opt("namespace"), action.param("name"))
        if env.bindings.pop(key, None) is None:
            notes.append(f"no-op: binding {key[0] or '<cluster>'}/{key[1]} not present")
    elif k == "delete_pod":
        if env.pods.pop(action.param("uid"), None) is None:
            notes.append(f"no-op: pod UID {action.param('uid')} not present")
    elif k == "delete_controller":
        uid = action.param("uid")
        if env.controllers.pop(uid, None) is None:
            notes.append(f"no-op: controller UID {uid} not present")
        # Cascading (foreground) deletion of owned Pods is assumed.
        for puid in [p.uid for p in env.pods.values() if p.controller_uid == uid]:
            del env.pods[puid]
    elif k in ("delete_pods_except", "delete_controllers_except"):
        ns, sa = action.param("namespace"), action.param("service_account")
        keep = {x for x in action.param("keep_uids").split(",") if x}
        if k == "delete_pods_except":
            victims = [p.uid for p in env.pods.values() if p.namespace == ns and p.service_account == sa and p.uid not in keep]
            for uid in victims:
                del env.pods[uid]
        else:
            victims = [c.uid for c in env.controllers.values() if c.namespace == ns and c.service_account == sa and c.uid not in keep]
            for uid in victims:
                del env.controllers[uid]
                for puid in [p.uid for p in env.pods.values() if p.controller_uid == uid]:
                    del env.pods[puid]
        if not victims:
            notes.append(f"no-op: nothing matched {action.label()}")
    elif k == "delete_service_account":
        key = (action.param("namespace"), action.param("name"))
        if env.service_accounts.pop(key, None) is None:
            notes.append(f"no-op: service account {key[0]}/{key[1]} not present")
    elif k == "rotate_downstream_credential":
        svc = env.services.get(action.param("service"))
        if svc is None:
            notes.append(f"no-op: service {action.param('service')} not present")
        else:
            key = (svc.source_namespace, svc.source_secret)
            sec = env.secrets.get(key)
            new_version = max(svc.accepted_version, sec.version if sec else 0) + 1
            if sec is not None:
                env.secrets[key] = replace(sec, version=new_version)
            grace = svc.grace
            if svc.rotation_propagation_seconds > 0:
                # S-SEC-5: the previously accepted version keeps working until the
                # rotation has propagated to the service.
                until = env.time + svc.rotation_propagation_seconds
                grace = tuple(sorted({*grace, (svc.accepted_version, until)}))
                notes.append(f"rotation of {svc.name} propagates for {svc.rotation_propagation_seconds}s; version {svc.accepted_version} accepted until {until}")
            env.services[svc.name] = replace(svc, accepted_version=new_version, grace=grace)
    elif k == "wait":
        env.time += int(action.param("seconds"))
    else:  # pragma: no cover - parse_actions rejects unknown kinds
        raise ValueError(k)
    return notes


# --------------------------------------------------------------------------
# legitimate operations


def legit_can_read(env: Env, pod_uid: str, namespace: str, secret: str) -> tuple[bool, str]:
    pod = env.pods.get(pod_uid)
    if pod is None:
        return False, f"pod UID {pod_uid} no longer exists"
    if (pod.namespace, pod.service_account) not in env.service_accounts:
        return False, f"service account {pod.namespace}/{pod.service_account} no longer exists"
    if (namespace, secret) not in env.secrets:
        return False, f"secret {namespace}/{secret} does not exist"
    via = authorizing_bindings(env, sa_username(pod.namespace, pod.service_account), "get", "secrets", namespace, secret)
    if not via:
        return False, f"{pod.service_account} is no longer authorized to get secret {namespace}/{secret}"
    return True, f"authorized via {', '.join(via)}"


def legit_can_use_service(env: Env, pod_uid: str, service: str) -> tuple[bool, str]:
    svc = env.services.get(service)
    if svc is None:
        return False, f"service {service} does not exist"
    ok, why = legit_can_read(env, pod_uid, svc.source_namespace, svc.source_secret)
    if not ok:
        return False, f"cannot obtain current credential: {why}"
    sec = env.secrets[(svc.source_namespace, svc.source_secret)]
    if sec.version != svc.accepted_version:
        return False, f"secret version {sec.version} is not accepted by {service} (accepts {svc.accepted_version})"
    return True, f"reads current version {sec.version}, accepted by {service}"


def secrets_feeding(env: Env, namespace: str, name: str) -> Iterable[DownstreamService]:
    for svc_name in sorted(env.services):
        svc = env.services[svc_name]
        if (svc.source_namespace, svc.source_secret) == (namespace, name):
            yield svc
