"""Seeded generator of small analysis inputs for differential and property tests.

Generated cases are *not* independent real-world validation: they only test
agreement between two implementations of the same written semantics.
"""

from __future__ import annotations

from typing import Any

from hypothesis import strategies as st

API = "https://kubernetes.default.svc.cluster.local"
NS = "n"
SAS = ["s0", "s1", "s2"]
T0 = 1_000_000

RULES = {
    "create-pods": {"verbs": ["create"], "resources": ["pods"]},
    "create-deploy": {"verbs": ["create"], "resources": ["deployments"]},
    "exec": {"verbs": ["create"], "resources": ["pods/exec"]},
    "read-any": {"verbs": ["get"], "resources": ["secrets"]},
    "read-sec0": {"verbs": ["get"], "resources": ["secrets"], "resource_names": ["sec0"]},
    "star": {"verbs": ["*"], "resources": ["*"]},
}


@st.composite
def analysis_inputs(draw: Any, max_actions: int = 3) -> dict[str, Any]:
    sas = [{"namespace": NS, "name": s, "uid": f"uid-{s}"} for s in SAS]
    n_pods = draw(st.integers(0, 3))
    pods = []
    for i in range(n_pods):
        pods.append({
            "namespace": NS, "name": f"p{i}", "uid": f"pod-{i}",
            "service_account": draw(st.sampled_from(SAS)),
            **({"token_audiences": [draw(st.sampled_from([API, "vault"]))]} if draw(st.booleans()) and i == 0 else {}),
        })
    controllers = []
    if draw(st.booleans()) and pods:
        sa = draw(st.sampled_from(SAS))
        controllers.append({"namespace": NS, "name": "c0", "uid": "ctrl-0", "service_account": sa})
        pods.append({"namespace": NS, "name": "c0-p0", "uid": "ctrl-0-p0", "service_account": sa, "controller_uid": "ctrl-0"})
    roles = [{"namespace": NS, "name": k, "rules": [v]} for k, v in RULES.items()]
    roles.append({"namespace": None, "name": "cluster-read", "rules": [RULES["read-any"]]})
    bindings = []
    for i in range(draw(st.integers(1, 4))):
        role = draw(st.sampled_from(list(RULES) + ["cluster-read"]))
        cluster = role == "cluster-read" and draw(st.booleans())
        subj = draw(st.sampled_from(SAS + ["group"]))
        subject = (
            {"kind": "Group", "name": f"system:serviceaccounts:{NS}"} if subj == "group"
            else {"kind": "ServiceAccount", "namespace": NS, "name": subj}
        )
        bindings.append({
            "namespace": None if cluster else NS, "name": f"b{i}",
            "role_kind": "ClusterRole" if role == "cluster-read" else "Role", "role_name": role,
            "subjects": [subject],
        })
    secrets = [{"namespace": NS, "name": "sec0", "uid": "sec-0", "version": 1}]
    if draw(st.booleans()):
        secrets.append({"namespace": NS, "name": "sec1", "uid": "sec-1", "version": 1})
    services = [{"name": "svc0", "source_namespace": NS, "source_secret": "sec0", "accepted_version": 1}]
    admission = []
    adm = draw(st.sampled_from(["none", "restrict", "unsupported"]))
    if adm == "restrict":
        admission.append({"namespace": NS, "name": "r", "kind": "service-account-restriction",
                          "allowed_service_accounts": {"*": draw(st.lists(st.sampled_from(SAS), max_size=2, unique=True))}})
    elif adm == "unsupported":
        admission.append({"namespace": NS, "name": "w", "kind": "validating-webhook"})

    creds, facts = [], []
    for i in range(draw(st.integers(1, 2))):
        sa = draw(st.sampled_from(SAS))
        bound = draw(st.sampled_from([None] + [p["uid"] for p in pods if p["service_account"] == sa]))
        c = {"id": f"c{i}", "kind": "sa_token", "username": f"system:serviceaccount:{NS}:{sa}", "sa_uid": f"uid-{sa}",
             "audience": draw(st.sampled_from([API, API, "vault"]))}
        if bound:
            c["bound_pod_uid"] = bound
        if draw(st.booleans()):
            c["expires_at"] = T0 + draw(st.sampled_from([0, 300, 5000]))
        creds.append(c)
        facts.append({"kind": "possesses_credential", "args": [c["id"]], "status": draw(st.sampled_from(["assumed", "observed", "inferred"])), "evidence": []})
    for p in pods:
        if draw(st.integers(0, 3)) == 0:
            facts.append({"kind": "controls_pod", "args": [p["uid"]], "status": draw(st.sampled_from(["observed", "inferred"])), "evidence": []})
    if draw(st.booleans()):
        facts.append({"kind": "knows_secret", "args": [NS, "sec0", "1"], "status": draw(st.sampled_from(["observed", "inferred"])), "evidence": []})
    if draw(st.integers(0, 3)) == 0:
        facts.append({"kind": "historical_pod", "args": ["gone-0", NS, draw(st.sampled_from(SAS))], "status": "observed", "evidence": []})
        facts.append({"kind": "controls_pod", "args": ["gone-0"], "status": "observed", "evidence": []})

    vocab: list[dict[str, Any]] = [{"kind": "remove_binding", "namespace": b["namespace"], "name": b["name"]} if b["namespace"] else
                                   {"kind": "remove_binding", "name": b["name"]} for b in bindings]
    vocab += [{"kind": "delete_pod", "uid": p["uid"]} for p in pods]
    vocab += [{"kind": "delete_controller", "uid": c["uid"]} for c in controllers]
    vocab += [{"kind": "delete_pods_except", "namespace": NS, "service_account": s, "keep_uids": []} for s in SAS]
    vocab += [{"kind": "delete_controllers_except", "namespace": NS, "service_account": s, "keep_uids": []} for s in SAS]
    vocab += [{"kind": "delete_service_account", "namespace": NS, "name": s} for s in SAS]
    vocab += [{"kind": "rotate_downstream_credential", "service": "svc0"}, {"kind": "wait", "seconds": 1000}]
    remediation = draw(st.lists(st.sampled_from(vocab), max_size=max_actions))

    return {
        "schema": "afterlock.analysis-input/1",
        "case_id": "generated",
        "cluster_id": "gen",
        "analysis_time": T0,
        "profile": {"id": "k8s-1.31-core-v1", "kubernetes_version": "1.31", "api_audiences": [API], "projected_token_ttl_seconds": 3600},
        "inventory": {"service_accounts": sas, "pods": pods, "controllers": controllers, "roles": roles, "bindings": bindings,
                      "secrets": secrets, "services": services, "admission_policies": admission},
        "credentials": creds,
        "initial_facts": facts,
        "remediation": remediation,
        "objectives": [
            {"id": "o-sec0", "kind": "no_secret_read", "namespace": NS, "secret": "sec0"},
            {"id": "o-svc0", "kind": "no_downstream_use", "service": "svc0"},
        ],
        "legitimate_operations": [],
        "coverage_gaps": [],
        "assumptions": [],
        "bounds": {},
    }
