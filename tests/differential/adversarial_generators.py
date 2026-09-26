"""Wider generator for adversarial differential search (phase 9 review).

Compared with ``generators.py`` it adds a second namespace, several Pods per
service account, controllers with zero to two Pods, ClusterRoleBindings,
RoleBindings to ClusterRoles, Group and User subjects, bindings to missing
roles, ``resourceNames`` on exec, multiple token audiences, stale SA UIDs,
bound-pod mismatches, expiry times on and next to interval boundaries, two
services sourcing one Secret, and rotation windows equal to waits.

Agreement on generated cases is agreement between two implementations of the
same written semantics, not real-world validation.
"""

from __future__ import annotations

from typing import Any

from hypothesis import strategies as st

API = "https://kubernetes.default.svc.cluster.local"
NSS = ["a", "b"]
SAS = ["s0", "s1"]
T0 = 1_000_000
TTL = 600

RULES: dict[str, dict[str, Any]] = {
    "create-pods": {"verbs": ["create"], "resources": ["pods"]},
    "create-deploy": {"verbs": ["create"], "resources": ["deployments"]},
    "exec-any": {"verbs": ["create"], "resources": ["pods/exec"]},
    "exec-p0": {"verbs": ["create"], "resources": ["pods/exec"], "resource_names": ["p0"]},
    "read-any": {"verbs": ["get"], "resources": ["secrets"]},
    "read-sec0": {"verbs": ["get"], "resources": ["secrets"], "resource_names": ["sec0"]},
    "star": {"verbs": ["*"], "resources": ["*"]},
    "list-secrets": {"verbs": ["list"], "resources": ["secrets"]},
}


def _subject(kind: str, ns: str, sa: str, group_ns: str) -> dict[str, Any]:
    other = [x for x in NSS if x != ns][0]
    return {
        "sa": {"kind": "ServiceAccount", "namespace": ns, "name": sa},
        "sa-other-ns": {"kind": "ServiceAccount", "namespace": other, "name": sa},
        "g-auth": {"kind": "Group", "name": "system:authenticated"},
        "g-sas": {"kind": "Group", "name": "system:serviceaccounts"},
        "g-ns": {"kind": "Group", "name": f"system:serviceaccounts:{group_ns}"},
        "user": {"kind": "User", "name": f"system:serviceaccount:{ns}:{sa}"},
    }[kind]


@st.composite
def adversarial_inputs(draw: Any, max_actions: int = 3) -> dict[str, Any]:
    sas = [{"namespace": ns, "name": s, "uid": f"uid-{ns}-{s}"} for ns in NSS for s in SAS]
    pods: list[dict[str, Any]] = []
    for i in range(draw(st.integers(0, 4))):
        p: dict[str, Any] = {"namespace": draw(st.sampled_from(NSS)), "name": f"p{i}", "uid": f"pod-{i}",
                             "service_account": draw(st.sampled_from(SAS))}
        aud = draw(st.sampled_from([None, None, [API], ["vault"], [API, "vault"], ["vault", API]]))
        if aud is not None:
            p["token_audiences"] = aud
        pods.append(p)
    controllers = []
    for j in range(draw(st.integers(0, 2))):
        ns, sa, cuid = draw(st.sampled_from(NSS)), draw(st.sampled_from(SAS)), f"ctrl-{j}"
        controllers.append({"namespace": ns, "name": f"c{j}", "uid": cuid, "service_account": sa})
        for k in range(draw(st.integers(0, 2))):
            pods.append({"namespace": ns, "name": f"c{j}-x{k}", "uid": f"{cuid}-x{k}", "service_account": sa, "controller_uid": cuid})
    roles: list[dict[str, Any]] = [{"namespace": ns, "name": k, "rules": [v]} for ns in NSS for k, v in RULES.items()]
    roles += [{"namespace": None, "name": f"cr-{k}", "rules": [v]} for k, v in RULES.items()]
    bindings = []
    for i in range(draw(st.integers(1, 5))):
        role = draw(st.sampled_from(list(RULES)))
        kind = draw(st.sampled_from(["rb-role", "rb-clusterrole", "crb", "rb-missing"]))
        ns = draw(st.sampled_from(NSS))
        subj = draw(st.sampled_from(["sa", "sa", "sa", "g-auth", "g-sas", "g-ns", "user", "sa-other-ns"]))
        b: dict[str, Any] = {"name": f"b{i}", "subjects": [_subject(subj, ns, draw(st.sampled_from(SAS)), draw(st.sampled_from(NSS)))]}
        if kind == "rb-role":
            b.update(namespace=ns, role_kind="Role", role_name=role)
        elif kind == "rb-clusterrole":
            b.update(namespace=ns, role_kind="ClusterRole", role_name=f"cr-{role}")
        elif kind == "crb":
            b.update(namespace=None, role_kind="ClusterRole", role_name=f"cr-{role}")
        else:
            b.update(namespace=ns, role_kind="Role", role_name="missing")
        bindings.append(b)
    secrets = [{"namespace": "a", "name": "sec0", "uid": "sec-0", "version": draw(st.integers(1, 2))}]
    if draw(st.booleans()):
        secrets.append({"namespace": "b", "name": "sec0", "uid": "sec-b0", "version": 1})
    services: list[dict[str, Any]] = [{"name": "svc0", "source_namespace": "a", "source_secret": "sec0",
                                       "accepted_version": draw(st.integers(1, 3))}]
    delay = draw(st.sampled_from([0, 0, 1, TTL, 90]))
    if delay:
        services[0]["rotation_propagation_seconds"] = delay
    if draw(st.booleans()):
        services.append({"name": "svc1", "source_namespace": "a", "source_secret": "sec0", "accepted_version": 1,
                         "rotation_propagation_seconds": draw(st.sampled_from([0, 90]))})
    admission: list[dict[str, Any]] = []
    adm = draw(st.sampled_from(["none", "none", "restrict", "restrict-creator", "unsupported-b"]))
    if adm == "restrict":
        admission.append({"namespace": "a", "name": "r", "kind": "service-account-restriction",
                          "allowed_service_accounts": {"*": draw(st.lists(st.sampled_from(SAS), max_size=1, unique=True))}})
    elif adm == "restrict-creator":
        admission.append({"namespace": "a", "name": "r", "kind": "service-account-restriction",
                          "allowed_service_accounts": {"system:serviceaccount:a:s0": ["s0"], "*": ["*"]}})
    elif adm == "unsupported-b":
        admission.append({"namespace": "b", "name": "w", "kind": "validating-webhook"})

    creds, facts = [], []
    for i in range(draw(st.integers(1, 2))):
        ns, sa = draw(st.sampled_from(NSS)), draw(st.sampled_from(SAS))
        own = [p["uid"] for p in pods if (p["namespace"], p["service_account"]) == (ns, sa)]
        bound = draw(st.sampled_from([None, *own, "pod-0"]))
        c: dict[str, Any] = {"id": f"c{i}", "kind": "sa_token", "username": f"system:serviceaccount:{ns}:{sa}",
                             "audience": draw(st.sampled_from([API, API, "vault"]))}
        sa_uid = draw(st.sampled_from([f"uid-{ns}-{sa}", f"uid-{ns}-{sa}", None, "stale"]))
        if sa_uid is not None:
            c["sa_uid"] = sa_uid
        if bound:
            c["bound_pod_uid"] = bound
        if draw(st.booleans()):
            c["expires_at"] = T0 + draw(st.sampled_from([0, 1, 90, TTL - 1, TTL, TTL + 1]))
        creds.append(c)
        facts.append({"kind": "possesses_credential", "args": [c["id"]],
                      "status": draw(st.sampled_from(["assumed", "observed", "inferred"])), "evidence": []})
    for p in pods:
        if draw(st.integers(0, 3)) == 0:
            facts.append({"kind": "controls_pod", "args": [p["uid"]], "status": draw(st.sampled_from(["observed", "inferred"])), "evidence": []})
    for ctl in controllers:
        if draw(st.integers(0, 3)) == 0:
            facts.append({"kind": "controls_controller", "args": [ctl["uid"]], "status": draw(st.sampled_from(["observed", "inferred"])), "evidence": []})
    if draw(st.booleans()):
        facts.append({"kind": "knows_secret", "args": ["a", "sec0", str(draw(st.integers(1, 3)))],
                      "status": draw(st.sampled_from(["observed", "inferred"])), "evidence": []})
    if draw(st.integers(0, 3)) == 0:
        facts.append({"kind": "historical_pod", "args": ["gone-0", draw(st.sampled_from(NSS)), draw(st.sampled_from(SAS))],
                      "status": "observed", "evidence": []})
        facts.append({"kind": "controls_pod", "args": ["gone-0"], "status": "observed", "evidence": []})

    vocab: list[dict[str, Any]] = [{"kind": "remove_binding", "namespace": b["namespace"], "name": b["name"]} if b["namespace"] else
                                   {"kind": "remove_binding", "name": b["name"]} for b in bindings]
    vocab += [{"kind": "delete_pod", "uid": p["uid"]} for p in pods]
    vocab += [{"kind": "delete_controller", "uid": ctl["uid"]} for ctl in controllers]
    vocab += [{"kind": "delete_pods_except", "namespace": ns, "service_account": s, "keep_uids": keep}
              for ns in NSS for s in SAS for keep in ([], ["pod-0"])]
    vocab += [{"kind": "delete_controllers_except", "namespace": ns, "service_account": s, "keep_uids": []} for ns in NSS for s in SAS]
    vocab += [{"kind": "delete_service_account", "namespace": ns, "name": s} for ns in NSS for s in SAS]
    vocab += [{"kind": "rotate_downstream_credential", "service": "svc0"}, {"kind": "rotate_downstream_credential", "service": "svc1"},
              {"kind": "wait", "seconds": 1}, {"kind": "wait", "seconds": 89}, {"kind": "wait", "seconds": 90},
              {"kind": "wait", "seconds": TTL}]
    remediation = draw(st.lists(st.sampled_from(vocab), max_size=max_actions))

    return {
        "schema": "afterlock.analysis-input/1", "case_id": "adversarial", "cluster_id": "gen", "analysis_time": T0,
        "profile": {"id": "k8s-1.31-core-v1", "kubernetes_version": "1.31", "api_audiences": [API], "projected_token_ttl_seconds": TTL},
        "inventory": {"service_accounts": sas, "pods": pods, "controllers": controllers, "roles": roles, "bindings": bindings,
                      "secrets": secrets, "services": services, "admission_policies": admission},
        "credentials": creds, "initial_facts": facts, "remediation": remediation,
        "objectives": [
            {"id": "o-sec0", "kind": "no_secret_read", "namespace": "a", "secret": "sec0"},
            {"id": "o-secb", "kind": "no_secret_read", "namespace": "b", "secret": "sec0"},
            {"id": "o-svc0", "kind": "no_downstream_use", "service": "svc0"},
            {"id": "o-svc1", "kind": "no_downstream_use", "service": "svc1"},
        ],
        "legitimate_operations": [], "coverage_gaps": [], "assumptions": [], "bounds": {},
    }
