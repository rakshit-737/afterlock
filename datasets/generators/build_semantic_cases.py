"""Generate the hand-authored semantic replay bundles in datasets/replay/.

Expected outcomes live separately in datasets/fixtures/expected.json and were
written from the scenario descriptions, not from engine output.

All values are synthetic. No real telemetry, tokens, or Secret contents.
Run:  python datasets/generators/build_semantic_cases.py
"""

from __future__ import annotations

import copy
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packages"))

from afterlock.evidence import ReplayBundle  # noqa: E402

CLUSTER = "lab-local"
API_AUD = "https://kubernetes.default.svc.cluster.local"
T_EVENTS = "2026-01-01T12:00:0{}Z"
T_ANALYSIS = "2026-01-01T12:30:00Z"
T_ANALYSIS_EPOCH = 1767270600

CI_USER = "system:serviceaccount:demo:ci-runner"
RR_USER = "system:serviceaccount:demo:release-reader"


def base_inventory() -> dict[str, Any]:
    return {
        "service_accounts": [
            {"namespace": "demo", "name": "ci-runner", "uid": "sa-ci-runner-0001"},
            {"namespace": "demo", "name": "release-reader", "uid": "sa-release-reader-0001"},
        ],
        "pods": [
            {"namespace": "demo", "name": "ci-runner-7f9c", "uid": "pod-ci-0001", "service_account": "ci-runner"},
            {"namespace": "demo", "name": "release-app", "uid": "pod-release-0001", "service_account": "release-reader"},
            {"namespace": "demo", "name": "diagnostic-job", "uid": "pod-attacker-0001", "service_account": "release-reader"},
        ],
        "controllers": [],
        "roles": [
            {"namespace": "demo", "name": "pod-creator", "rules": [{"verbs": ["create", "get", "list"], "resources": ["pods"]}]},
            {
                "namespace": "demo",
                "name": "release-secret-reader",
                "rules": [{"verbs": ["get"], "resources": ["secrets"], "resource_names": ["release-credential"]}],
            },
        ],
        "bindings": [
            {
                "namespace": "demo", "name": "ci-pod-creator", "role_kind": "Role", "role_name": "pod-creator",
                "subjects": [{"kind": "ServiceAccount", "namespace": "demo", "name": "ci-runner"}],
            },
            {
                "namespace": "demo", "name": "release-reader-secret", "role_kind": "Role", "role_name": "release-secret-reader",
                "subjects": [{"kind": "ServiceAccount", "namespace": "demo", "name": "release-reader"}],
            },
        ],
        "secrets": [{"namespace": "demo", "name": "release-credential", "uid": "secret-0001", "version": 1}],
        "services": [{"name": "canary-service", "source_namespace": "demo", "source_secret": "release-credential", "accepted_version": 1}],
        "admission_policies": [],
    }


CI_CRED = {
    "id": "ci-runner-token",
    "kind": "sa_token",
    "username": CI_USER,
    "sa_uid": "sa-ci-runner-0001",
    "bound_pod_uid": "pod-ci-0001",
    "audience": API_AUD,
}

OBJ_SECRET = {"id": "protect-secret", "kind": "no_secret_read", "namespace": "demo", "secret": "release-credential",
              "description": "Prevent further Kubernetes reads of demo/release-credential by modeled attacker credentials."}
OBJ_CANARY = {"id": "protect-canary", "kind": "no_downstream_use", "service": "canary-service",
              "description": "Prevent use of any copied downstream credential against canary-service."}
LEGIT = [
    {"id": "release-read", "kind": "read_secret", "pod_uid": "pod-release-0001", "namespace": "demo", "secret": "release-credential",
     "description": "release-app reads the current release credential."},
    {"id": "release-canary", "kind": "use_downstream", "pod_uid": "pod-release-0001", "service": "canary-service",
     "description": "release-app authenticates to canary-service with the current credential."},
]


def ev(seq: int, **body: Any) -> dict[str, Any]:
    out = {
        "schema_version": "1",
        "event_id": f"evt-demo-{seq:04d}",
        "source_id": "lab-audit",
        "source_sequence": seq,
        "cluster_id": CLUSTER,
        "event_type": "k8s.api.response",
        "observed_at": T_EVENTS.format(seq % 10),
        "ingested_at": T_EVENTS.format((seq + 1) % 10),
        "provenance": {"transport": "authenticated-collector", "payload_class": "metadata-only"},
    }
    out.update(body)
    return out


CREATE_ATTACKER_POD = ev(
    1,
    actor={"username": CI_USER, "pod_uid": "pod-ci-0001"},
    action={"verb": "create", "api_group": "", "resource": "pods", "namespace": "demo"},
    target={"name": "diagnostic-job", "uid": "pod-attacker-0001", "service_account": "release-reader"},
    outcome={"http_status": 201},
)
ATTACKER_READS_SECRET = ev(
    2,
    actor={"username": RR_USER, "pod_uid": "pod-attacker-0001", "sa_uid": "sa-release-reader-0001"},
    action={"verb": "get", "api_group": "", "resource": "secrets", "namespace": "demo"},
    target={"name": "release-credential", "uid": "secret-0001", "observed_version": 1},
    outcome={"http_status": 200},
)
HEARTBEAT = {
    "schema_version": "1", "event_id": "evt-hb-0001", "source_id": "lab-audit", "source_sequence": 99, "cluster_id": CLUSTER,
    "event_type": "collector.heartbeat", "observed_at": "2026-01-01T12:29:30Z",
}

TARGETED = [
    {"kind": "remove_binding", "namespace": "demo", "name": "ci-pod-creator"},
    {"kind": "delete_pods_except", "namespace": "demo", "service_account": "release-reader", "keep_uids": ["pod-release-0001"]},
    {"kind": "rotate_downstream_credential", "service": "canary-service"},
]


def case(remediation: list[dict[str, Any]], *, objectives: list[dict[str, Any]] | None = None,
         creds: list[dict[str, Any]] | None = None, description: str = "") -> dict[str, Any]:
    return {
        "description": description,
        "profile": "k8s-1.31-core-v1",
        "analysis_time": T_ANALYSIS,
        "compromised_credentials": creds if creds is not None else [CI_CRED],
        "objectives": objectives or [OBJ_SECRET, OBJ_CANARY],
        "legitimate_operations": LEGIT,
        "remediation": remediation,
        "assumptions": ["Initial compromise of the CI service account is seeded, not exploited."],
        "required_sources": ["lab-audit"],
        "max_evidence_staleness_seconds": 300,
    }


def build() -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}
    history = [CREATE_ATTACKER_POD, ATTACKER_READS_SECRET, HEARTBEAT]

    cases["residual-token"] = dict(
        inventory=base_inventory(), events=history,
        case=case([{"kind": "remove_binding", "namespace": "demo", "name": "ci-pod-creator"}],
                  description="Flagship: removing the CI pod-creation binding leaves the attacker pod's delegated token and the copied credential usable."),
    )
    cases["targeted-containment"] = dict(
        inventory=base_inventory(), events=history,
        case=case(TARGETED, description="Block recreation first, remove attacker workloads by selector, then rotate the downstream credential."),
    )
    cases["defender-race"] = dict(
        inventory=base_inventory(), events=history,
        case=case([TARGETED[1], TARGETED[0], TARGETED[2]],
                  description="Deleting the attacker pod before blocking recreation lets the attacker recreate it between steps."),
    )
    cases["copied-downstream"] = dict(
        inventory=base_inventory(), events=history,
        case=case(TARGETED[:2], description="Kubernetes access is removed, but the credential already copied still works at the canary service."),
    )
    inv = base_inventory()
    inv["roles"].append({"namespace": None, "name": "workload-launcher", "rules": [{"verbs": ["create"], "resources": ["pods"]}]})
    inv["bindings"].append({"namespace": None, "name": "ci-launcher", "role_kind": "ClusterRole", "role_name": "workload-launcher",
                            "subjects": [{"kind": "ServiceAccount", "namespace": "demo", "name": "ci-runner"}]})
    cases["alternative-binding"] = dict(
        inventory=inv, events=history,
        case=case(TARGETED, description="A second ClusterRoleBinding still grants pod creation after the namespaced binding is removed."),
    )

    inv = base_inventory()
    inv["roles"][0]["rules"].append({"verbs": ["create"], "resources": ["deployments"]})
    inv["controllers"].append({"namespace": "demo", "name": "diagnostic", "uid": "deploy-attacker-0001", "service_account": "release-reader"})
    inv["pods"][2]["controller_uid"] = "deploy-attacker-0001"
    create_deploy = ev(
        3,
        actor={"username": CI_USER, "pod_uid": "pod-ci-0001"},
        action={"verb": "create", "api_group": "apps", "resource": "deployments", "namespace": "demo"},
        target={"name": "diagnostic", "uid": "deploy-attacker-0001"},
        outcome={"http_status": 201},
    )
    cases["controller-replacement"] = dict(
        inventory=inv, events=[create_deploy, ATTACKER_READS_SECRET, HEARTBEAT],
        case=case(TARGETED, description="Deleting the controller-owned attacker pod does not remove the controller that recreates it."),
    )
    cases["controller-contained"] = dict(
        inventory=copy.deepcopy(inv), events=[create_deploy, ATTACKER_READS_SECRET, HEARTBEAT],
        case=case([TARGETED[0],
                   {"kind": "delete_controllers_except", "namespace": "demo", "service_account": "release-reader", "keep_uids": []},
                   TARGETED[1], TARGETED[2]],
                  description="Removing the controller before its pods and rotating the credential contains the incident."),
    )

    denied = ev(
        4,
        actor={"username": CI_USER, "pod_uid": "pod-ci-0001"},
        action={"verb": "create", "api_group": "", "resource": "pods", "namespace": "demo"},
        target={"name": "diagnostic-job", "service_account": "release-reader"},
        outcome={"http_status": 403},
    )
    inv = base_inventory()
    inv["pods"] = inv["pods"][:2]
    inv["admission_policies"].append({"namespace": "demo", "name": "restrict-ci-service-accounts", "kind": "service-account-restriction",
                                      "allowed_service_accounts": {CI_USER: ["ci-runner"]}})
    cases["admission-denied"] = dict(
        inventory=inv, events=[denied, HEARTBEAT],
        case=case([], description="Negative control: admission prevents the CI identity from selecting the release-reader service account."),
    )
    inv = copy.deepcopy(inv)
    inv["admission_policies"] = [{"namespace": "demo", "name": "opaque-webhook", "kind": "validating-webhook"}]
    cases["admission-unsupported"] = dict(
        inventory=inv, events=[denied, HEARTBEAT],
        case=case([], description="An admission webhook the profile cannot evaluate makes pod-creation feasibility unknown."),
    )
    inv = base_inventory()
    inv["pods"] = inv["pods"][:2]
    cases["no-admission-control"] = dict(
        inventory=inv, events=[HEARTBEAT],
        case=case([], description="Positive counterpart: without admission control, pod creation permission yields release-reader access."),
    )

    copied = {"id": "copied-release-token", "kind": "sa_token", "username": RR_USER, "sa_uid": "sa-release-reader-0001",
              "bound_pod_uid": "pod-release-0001", "audience": API_AUD, "expires_at": T_ANALYSIS_EPOCH + 600}
    inv = base_inventory()
    inv["pods"] = inv["pods"][:2]
    inv["bindings"] = inv["bindings"][1:]
    cases["token-expiry-active"] = dict(
        inventory=inv, events=[HEARTBEAT],
        case=case([], objectives=[OBJ_SECRET], creds=[copied], description="A copied, unexpired token still reads the Secret."),
    )
    cases["token-expiry-wait"] = dict(
        inventory=copy.deepcopy(inv), events=[HEARTBEAT],
        case=case([{"kind": "wait", "seconds": 900}], objectives=[OBJ_SECRET], creds=[copied],
                  description="Waiting past the observed expiry stops Kubernetes access through the copied token."),
    )
    vault = dict(copied, id="copied-vault-token", audience="vault")
    vault.pop("expires_at")
    cases["audience-mismatch"] = dict(
        inventory=copy.deepcopy(inv), events=[HEARTBEAT],
        case=case([], objectives=[OBJ_SECRET], creds=[vault], description="A token minted for another audience is rejected by the API server."),
    )

    inv = base_inventory()
    inv["pods"][2] = {"namespace": "demo", "name": "diagnostic-job", "uid": "pod-diagnostic-0002", "service_account": "release-reader"}
    inv["bindings"] = inv["bindings"][1:]
    cases["same-name-recreation"] = dict(
        inventory=inv, events=[CREATE_ATTACKER_POD, ATTACKER_READS_SECRET, HEARTBEAT],
        case=case([], objectives=[OBJ_SECRET],
                  description="A legitimate pod reuses the attacker pod's name with a new UID; the attacker's bound token is not revived."),
    )

    gap = {"schema_version": "1", "event_id": "evt-gap-0001", "source_id": "lab-audit", "source_sequence": 50, "cluster_id": CLUSTER,
           "event_type": "collector.gap", "observed_at": "2026-01-01T12:10:00Z", "gap_id": "audit-gap-1210",
           "reason": "audit webhook backlog dropped events between 12:05 and 12:10"}
    cases["incomplete-telemetry"] = dict(
        inventory=base_inventory(), events=history + [gap],
        case=case(TARGETED, description="The targeted plan would contain the modeled state, but an audit gap prevents establishing it."),
    )

    inv = base_inventory()
    inv["pods"] = inv["pods"][:2]
    inv["bindings"] = inv["bindings"][1:]
    cases["possible-read"] = dict(
        inventory=inv, events=[CREATE_ATTACKER_POD, HEARTBEAT],
        case=case([], description="The attacker pod is gone and no read was observed, but a read was possible while it existed."),
    )
    return cases


def main() -> None:
    out = ROOT / "datasets" / "replay"
    for name, spec in build().items():
        d = out / name
        if d.exists():
            shutil.rmtree(d)
        ReplayBundle.write(d, case_id=name, cluster_id=CLUSTER, inventory=spec["inventory"], case=spec["case"], events=spec["events"])
        print(f"wrote {d.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
