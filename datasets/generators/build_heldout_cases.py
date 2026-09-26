"""Generate the held-out scenario templates in datasets/heldout/.

These templates were written after the production engine and are not used to
develop it: no engine test or fixture reads them except the benchmark and the
held-out agreement check. They vary namespaces, the number of service
accounts, binding kinds (RoleBinding, ClusterRoleBinding, Group subjects),
controllers that recreate pods, several downstream services per Secret,
delayed (non-instantaneous) revocation, and token expiry.

Expectations are derived by the INDEPENDENT reference checker
(packages/afterlock_reference), never by the production engine. This module
must not import ``afterlock``; tests/unit/test_heldout.py enforces it. Labels
from a second implementation of the same written semantics are not
real-world outcomes: they catch implementation disagreement, not semantic error.

Output is a pure function of SEED (``random.Random`` seeded with strings is
stable across platforms and Python versions >= 3.2), written with sorted keys
and LF line endings.

Run:  python datasets/generators/build_heldout_cases.py [--check]
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packages"))

import afterlock_reference as reference  # noqa: E402

SEED = "afterlock-heldout-v1"
INSTANCES = 3
OUT = ROOT / "datasets" / "heldout"
API = "https://kubernetes.default.svc.cluster.local"
T0 = 1_800_000_000
NS_POOL = ["payments", "ingest", "ops", "batch", "edge", "search"]
REF_LIMITS = {"max_states": 150_000, "max_live_attacker_workloads_per_sa": 1}

Case = dict[str, Any]
Template = Callable[[random.Random, int], Iterator[tuple[str, str, Case]]]


def _sa(ns: str, name: str) -> dict[str, str]:
    return {"namespace": ns, "name": name, "uid": f"sa-{ns}-{name}"}


def _pod(ns: str, name: str, sa: str, ctrl: str | None = None) -> dict[str, Any]:
    p: dict[str, Any] = {"namespace": ns, "name": name, "uid": f"pod-{ns}-{name}", "service_account": sa}
    if ctrl:
        p["controller_uid"] = ctrl
    return p


def _user(ns: str, sa: str) -> str:
    return f"system:serviceaccount:{ns}:{sa}"


def _svc(name: str, ns: str, secret: str, delay: int = 0) -> dict[str, Any]:
    s: dict[str, Any] = {"name": name, "source_namespace": ns, "source_secret": secret, "accepted_version": 1}
    if delay:
        s["rotation_propagation_seconds"] = delay
    return s


def _fact(kind: str, *args: str, status: str = "observed") -> dict[str, Any]:
    return {"kind": kind, "args": list(args), "status": status, "evidence": []}


def _doc(case_id: str, inventory: dict[str, Any], creds: list[dict[str, Any]], facts: list[dict[str, Any]],
         objectives: list[dict[str, Any]], remediation: list[dict[str, Any]], description: str) -> Case:
    inv = {"service_accounts": [], "pods": [], "controllers": [], "roles": [], "bindings": [], "secrets": [], "services": [],
           "admission_policies": []}
    inv.update(inventory)
    return {
        "schema": "afterlock.analysis-input/1",
        "case_id": case_id,
        "cluster_id": "heldout",
        "analysis_time": T0,
        "profile": {"id": "k8s-1.31-core-v1", "kubernetes_version": "1.31", "api_audiences": [API], "projected_token_ttl_seconds": 3600},
        "inventory": inv,
        "credentials": creds,
        "initial_facts": facts,
        "remediation": remediation,
        "objectives": objectives,
        "legitimate_operations": [],
        "coverage_gaps": [],
        "assumptions": [description],
        "bounds": {},
    }


def _secret_obj(ns: str, secret: str) -> dict[str, Any]:
    return {"id": f"protect-{ns}-{secret}", "kind": "no_secret_read", "namespace": ns, "secret": secret}


def _svc_obj(name: str) -> dict[str, Any]:
    return {"id": f"protect-{name}", "kind": "no_downstream_use", "service": name}


# --------------------------------------------------------------------------- templates


def crb_escalation(rng: random.Random, i: int) -> Iterator[tuple[str, str, Case]]:
    """Pod creation granted twice: a namespaced RoleBinding and a ClusterRoleBinding."""
    nss = rng.sample(NS_POOL, rng.choice([2, 3]))
    home, target = nss[0], nss[-1]
    decoys = rng.choice([0, 1])
    sas = [_sa(home, "builder"), _sa(target, "vault-sync")] + [_sa(nss[1], f"worker{d}") for d in range(decoys)]
    inv = {
        "service_accounts": sas,
        "pods": [_pod(home, "builder-0", "builder"), _pod(target, "vault-sync-0", "vault-sync")],
        "roles": [
            {"namespace": None, "name": "pod-launcher", "rules": [{"verbs": ["create"], "resources": ["pods"]}]},
            {"namespace": target, "name": "db-reader", "rules": [{"verbs": ["get"], "resources": ["secrets"], "resource_names": ["db-creds"]}]},
        ],
        "bindings": [
            {"namespace": None, "name": "builder-launch", "role_kind": "ClusterRole", "role_name": "pod-launcher",
             "subjects": [{"kind": "ServiceAccount", "namespace": home, "name": "builder"}]},
            {"namespace": home, "name": "builder-local", "role_kind": "ClusterRole", "role_name": "pod-launcher",
             "subjects": [{"kind": "ServiceAccount", "namespace": home, "name": "builder"}]},
            {"namespace": target, "name": "vault-sync-db", "role_kind": "Role", "role_name": "db-reader",
             "subjects": [{"kind": "ServiceAccount", "namespace": target, "name": "vault-sync"}]},
        ],
        "secrets": [{"namespace": target, "name": "db-creds", "uid": f"sec-{target}-db", "version": 1}],
        "services": [_svc("ledger", target, "db-creds")],
    }
    cred = {"id": "builder-token", "kind": "sa_token", "username": _user(home, "builder"), "sa_uid": f"sa-{home}-builder",
            "bound_pod_uid": f"pod-{home}-builder-0", "audience": API}
    facts = [_fact("possesses_credential", "builder-token", status="assumed")]
    objs = [_secret_obj(target, "db-creds"), _svc_obj("ledger")]
    rm_rb = {"kind": "remove_binding", "namespace": home, "name": "builder-local"}
    rm_crb = {"kind": "remove_binding", "name": "builder-launch"}
    purge = {"kind": "delete_pods_except", "namespace": target, "service_account": "vault-sync", "keep_uids": [f"pod-{target}-vault-sync-0"]}
    rotate = {"kind": "rotate_downstream_credential", "service": "ledger"}
    yield "rb-only", "Only the namespaced binding is removed; the ClusterRoleBinding still grants pod creation in the target namespace.", \
        _doc("", inv, [cred], facts, objs, [rm_rb, purge, rotate], "")
    yield "full", "Both grants removed before purging attacker pods and rotating.", \
        _doc("", inv, [cred], facts, objs, [rm_crb, rm_rb, purge, rotate], "")
    yield "purge-first", "Attacker pods purged before the grants are removed; the attacker recreates one in between.", \
        _doc("", inv, [cred], facts, objs, [purge, rm_crb, rm_rb, rotate], "")


def controller_recreate(rng: random.Random, i: int) -> Iterator[tuple[str, str, Case]]:
    """An attacker-controlled Deployment recreates its pod; one Secret feeds 1-2 services."""
    ns = rng.choice(NS_POOL)
    n_svc = rng.choice([1, 2])
    extra_sa = rng.choice([0, 1])
    ctrl = f"deploy-{ns}-reporter"
    sas = [_sa(ns, "reporter")] + [_sa(ns, f"app{k}") for k in range(extra_sa)]
    services = [_svc(f"api-{k}", ns, "report-key") for k in range(n_svc)]
    inv = {
        "service_accounts": sas,
        "pods": [_pod(ns, "reporter-p0", "reporter", ctrl)],
        "controllers": [{"namespace": ns, "name": "reporter", "uid": ctrl, "service_account": "reporter"}],
        "roles": [{"namespace": ns, "name": "key-reader", "rules": [{"verbs": ["get"], "resources": ["secrets"]}]}],
        "bindings": [{"namespace": ns, "name": "reporter-keys", "role_kind": "Role", "role_name": "key-reader",
                      "subjects": [{"kind": "ServiceAccount", "namespace": ns, "name": "reporter"}]}],
        "secrets": [{"namespace": ns, "name": "report-key", "uid": f"sec-{ns}-rk", "version": 1}],
        "services": services,
    }
    facts = [_fact("controls_controller", ctrl)]
    objs = [_secret_obj(ns, "report-key")] + [_svc_obj(s["name"]) for s in services]
    rotate_all = [{"kind": "rotate_downstream_credential", "service": s["name"]} for s in services]
    del_pods = {"kind": "delete_pods_except", "namespace": ns, "service_account": "reporter", "keep_uids": []}
    del_ctrl = {"kind": "delete_controllers_except", "namespace": ns, "service_account": "reporter", "keep_uids": []}
    yield "delete-pods", "Deleting the pods leaves the controller, which recreates one and rereads the rotated key.", \
        _doc("", inv, [], facts, objs, [del_pods, *rotate_all], "")
    yield "delete-controller", "Deleting the controller before rotating every consumer contains the incident.", \
        _doc("", inv, [], facts, objs, [del_ctrl, *rotate_all], "")
    if n_svc > 1:
        yield "partial-rotation", "Only one of two consumers of the key is rotated.", \
            _doc("", inv, [], facts, objs, [del_ctrl, rotate_all[0]], "")


def group_subject(rng: random.Random, i: int) -> Iterator[tuple[str, str, Case]]:
    """Secret access granted both to the SA and to the namespace's service-account group."""
    ns = rng.choice(NS_POOL)
    n_svc = rng.choice([2, 3])
    others = rng.choice([1, 2])
    sas = [_sa(ns, "ci")] + [_sa(ns, f"svc{k}") for k in range(others)]
    services = [_svc(f"downstream-{k}", ns, "shared-token") for k in range(n_svc)]
    inv = {
        "service_accounts": sas,
        "pods": [_pod(ns, "ci-0", "ci")],
        "roles": [{"namespace": ns, "name": "token-reader", "rules": [{"verbs": ["get"], "resources": ["secrets"], "resource_names": ["shared-token"]}]}],
        "bindings": [
            {"namespace": ns, "name": "ci-token", "role_kind": "Role", "role_name": "token-reader",
             "subjects": [{"kind": "ServiceAccount", "namespace": ns, "name": "ci"}]},
            {"namespace": ns, "name": "all-sas-token", "role_kind": "Role", "role_name": "token-reader",
             "subjects": [{"kind": "Group", "name": f"system:serviceaccounts:{ns}"}]},
        ],
        "secrets": [{"namespace": ns, "name": "shared-token", "uid": f"sec-{ns}-st", "version": 1}],
        "services": services,
    }
    cred = {"id": "ci-token", "kind": "sa_token", "username": _user(ns, "ci"), "sa_uid": f"sa-{ns}-ci", "audience": API}
    facts = [_fact("possesses_credential", "ci-token", status="assumed"), _fact("knows_secret", ns, "shared-token", "1")]
    objs = [_secret_obj(ns, "shared-token")] + [_svc_obj(s["name"]) for s in services]
    rotate_all = [{"kind": "rotate_downstream_credential", "service": s["name"]} for s in services]
    rm_sa = {"kind": "remove_binding", "namespace": ns, "name": "ci-token"}
    rm_group = {"kind": "remove_binding", "namespace": ns, "name": "all-sas-token"}
    yield "sa-binding-only", "The SA binding is removed but the group binding still lets the stolen token read the rotated Secret.", \
        _doc("", inv, [cred], facts, objs, [rm_sa, *rotate_all], "")
    yield "both-bindings", "Both bindings removed before rotating every consumer.", \
        _doc("", inv, [cred], facts, objs, [rm_sa, rm_group, *rotate_all], "")
    yield "miss-one-consumer", "Both bindings removed but one consumer keeps the old version.", \
        _doc("", inv, [cred], facts, objs, [rm_sa, rm_group, *rotate_all[:-1]], "")


def delayed_revocation(rng: random.Random, i: int) -> Iterator[tuple[str, str, Case]]:
    """Rotation takes measured time to reach each consumer (S-SEC-5)."""
    ns = rng.choice(NS_POOL)
    n_svc = rng.choice([1, 2])
    delays = [rng.choice([15, 55, 120]) for _ in range(n_svc)]
    services = [_svc(f"consumer-{k}", ns, "signing-key", d) for k, d in enumerate(delays)]
    inv = {
        "service_accounts": [_sa(ns, "signer")],
        "secrets": [{"namespace": ns, "name": "signing-key", "uid": f"sec-{ns}-sk", "version": 1}],
        "services": services,
    }
    facts = [_fact("knows_secret", ns, "signing-key", "1")]
    objs = [_svc_obj(s["name"]) for s in services]
    rotate_all = [{"kind": "rotate_downstream_credential", "service": s["name"]} for s in services]
    longest = max(delays)
    yield "rotate-only", "Rotation acknowledged but not yet propagated at the end of the sequence.", \
        _doc("", inv, [], facts, objs, rotate_all, "")
    yield "wait-short", "Waiting less than the slowest propagation leaves the old credential accepted.", \
        _doc("", inv, [], facts, objs, [*rotate_all, {"kind": "wait", "seconds": longest - 1}], "")
    yield "wait-full", "Waiting for the slowest propagation window contains the copied credential.", \
        _doc("", inv, [], facts, objs, [*rotate_all, {"kind": "wait", "seconds": longest}], "")


def token_expiry(rng: random.Random, i: int) -> Iterator[tuple[str, str, Case]]:
    """A copied token with observed expiry keeps reading a Secret until it expires."""
    ns = rng.choice(NS_POOL)
    ttl = rng.choice([300, 600, 1200])
    inv = {
        "service_accounts": [_sa(ns, "exporter")],
        "pods": [_pod(ns, "exporter-0", "exporter")],
        "roles": [{"namespace": ns, "name": "read", "rules": [{"verbs": ["get"], "resources": ["secrets"]}]}],
        "bindings": [{"namespace": ns, "name": "exporter-read", "role_kind": "Role", "role_name": "read",
                      "subjects": [{"kind": "ServiceAccount", "namespace": ns, "name": "exporter"}]}],
        "secrets": [{"namespace": ns, "name": "export-creds", "uid": f"sec-{ns}-ec", "version": 1}],
    }
    cred = {"id": "copied", "kind": "sa_token", "username": _user(ns, "exporter"), "sa_uid": f"sa-{ns}-exporter",
            "bound_pod_uid": f"pod-{ns}-exporter-0", "audience": API, "expires_at": T0 + ttl}
    facts = [_fact("possesses_credential", "copied")]
    objs = [_secret_obj(ns, "export-creds")]
    yield "wait-before-expiry", "The copied token is still valid after the wait.", \
        _doc("", inv, [cred], facts, objs, [{"kind": "wait", "seconds": ttl - 1}], "")
    yield "wait-past-expiry", "Waiting until the observed expiry stops the copied token.", \
        _doc("", inv, [cred], facts, objs, [{"kind": "wait", "seconds": ttl}], "")
    yield "delete-bound-pod", "Deleting the bound pod invalidates the token before expiry.", \
        _doc("", inv, [cred], facts, objs, [{"kind": "delete_pod", "uid": f"pod-{ns}-exporter-0"}], "")


TEMPLATES: dict[str, Template] = {
    "crb-escalation": crb_escalation,
    "controller-recreate": controller_recreate,
    "group-subject": group_subject,
    "delayed-revocation": delayed_revocation,
    "token-expiry": token_expiry,
}


# --------------------------------------------------------------------------- labels


def reference_label(raw: Case) -> dict[str, Any]:
    """Objective statuses and conclusion from the reference checker alone."""
    r = reference.explore(raw, reference.ReferenceLimits(**REF_LIMITS))
    ev, pv = r["views"]["evidence_supported"], r["views"]["conservative_possible"]
    unknown = bool(ev["unknown"] or pv["unknown"] or raw["coverage_gaps"])
    complete = ev["complete"] and pv["complete"]
    objectives = {}
    for o in raw["objectives"]:
        if o["id"] in ev["reachable_objectives"]:
            objectives[o["id"]] = "violated"
        elif o["id"] in pv["reachable_objectives"]:
            objectives[o["id"]] = "possibly_violated"
        elif unknown or not complete:
            objectives[o["id"]] = "unknown"
        else:
            objectives[o["id"]] = "satisfied_within_scope"
    statuses = set(objectives.values())
    conclusion = ("residual_path" if statuses & {"violated", "possibly_violated"}
                  else "unknown" if "unknown" in statuses else "contained_within_scope")
    return {"conclusion": conclusion, "objectives": objectives, "reference_complete": complete,
            "reference_states": {"evidence_supported": ev["states"], "conservative_possible": pv["states"]}}


def build() -> dict[str, bytes]:
    """Relative path -> file content. Pure function of SEED."""
    files: dict[str, bytes] = {}
    labels: dict[str, Any] = {}
    for template, fn in TEMPLATES.items():
        for i in range(INSTANCES):
            rng = random.Random(f"{SEED}:{template}:{i}")
            for variant, description, doc in fn(rng, i):
                case_id = f"{template}-{i}-{variant}"
                doc["case_id"] = case_id
                doc["assumptions"] = [description]
                files[f"cases/{case_id}.json"] = _dump(doc)
                labels[case_id] = {"template": template, "instance": i, "variant": variant, "description": description,
                                   **reference_label(doc)}
    files["expected.json"] = _dump({
        "_comment": ("Labels derived by packages/afterlock_reference (independent re-implementation), never by the "
                     "production engine. They measure implementation agreement on templates not used during engine "
                     "development, not real-world outcomes."),
        "_generator": "datasets/generators/build_heldout_cases.py",
        "_seed": SEED,
        "_reference_limits": REF_LIMITS,
        "cases": labels,
    })
    return files


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="exit 1 if datasets/heldout differs from a fresh build")
    args = ap.parse_args()
    files = build()
    if args.check:
        on_disk = {p.relative_to(OUT).as_posix(): p.read_bytes() for p in OUT.rglob("*.json")} if OUT.exists() else {}
        if on_disk != files:
            print("datasets/heldout is stale; run python datasets/generators/build_heldout_cases.py")
            return 1
        print(f"datasets/heldout up to date ({len(files)} files)")
        return 0
    if OUT.exists():
        shutil.rmtree(OUT)
    for rel, content in files.items():
        path = OUT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    print(f"wrote {len(files) - 1} held-out cases to {OUT.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
