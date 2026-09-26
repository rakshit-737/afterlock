#!/usr/bin/env python3
"""AFTERLOCK lab supervisor: the only component that mutates lab resources.

Semantic spike (design prompt 05): verify against a real API server that
  1. the CI identity can create a Pod running as release-reader,
  2. the Pod's projected token reads the protected Secret,
  3. removing the CI RoleBinding blocks new Pod creation,
  4. the previously obtained token STILL reads the Secret (residual access),
  5. deleting the bound Pod makes the API reject that token (timed, not assumed),
  6. negative control: an admission policy denies the CI identity the release-reader SA,
and, against the synthetic canary relying service (S-SEC-2..4), that
  7. the Secret value the attacker copied authenticates to the canary,
  8. it still does after Kubernetes containment (binding removed, Pod deleted),
  9. rotation at the canary is acknowledged (new value accepted),
 10. the copied value is then rejected, and
 11. the legitimate workload reads the rotated value and still uses the service.

Every observation is compared with the engine's prediction for the matching
replay case and written to labs/receipts/. Tokens and credential values stay in
memory and never appear in receipts or host command lines.

Requires: kind, kubectl, a disposable Docker-capable Linux host.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "labs" / ".state" / "lab.json"
RECEIPTS = ROOT / "labs" / "receipts"
CLUSTER = "afterlock-lab"
CONTEXT = f"kind-{CLUSTER}"
NS = "demo"
POLL_SECONDS = 120
ROTATION_POLL_SECONDS = 180  # mounted Secret volumes refresh on the kubelet sync period
CANARY_URL = "http://canary.canary.svc:8080/use"

sys.path.insert(0, str(ROOT / "packages"))


class LabError(RuntimeError):
    pass


def run(args: list[str], *, stdin: bytes | None = None, check: bool = True) -> str:
    """Run a fixed argument vector (never a shell string)."""
    proc = subprocess.run(args, input=stdin, capture_output=True, timeout=600)
    if check and proc.returncode != 0:
        raise LabError(f"{args[0]} {args[1] if len(args) > 1 else ''} failed: {proc.stderr.decode()[:400]}")
    return proc.stdout.decode()


def kubectl(*args: str, stdin: bytes | None = None, check: bool = True) -> str:
    return run(["kubectl", "--context", CONTEXT, *args], stdin=stdin, check=check)


# ---------------------------------------------------------------- identity


def live_identity() -> dict[str, Any]:
    cfg = json.loads(kubectl("config", "view", "--raw", "--minify", "-o", "json"))
    cluster = cfg["clusters"][0]["cluster"]
    ca = base64.b64decode(cluster["certificate-authority-data"])
    ns = json.loads(kubectl("get", "namespace", NS, "-o", "json", check=False) or "{}")
    return {
        "context": CONTEXT,
        "server": cluster["server"],
        "ca_sha256": hashlib.sha256(ca).hexdigest(),
        "namespace_uid": ns.get("metadata", {}).get("uid"),
        "lab_instance": ns.get("metadata", {}).get("labels", {}).get("afterlock.dev/lab-instance"),
    }


def require_recorded_lab() -> dict[str, Any]:
    if not STATE.is_file():
        raise LabError("no recorded lab; run: scripts/lab create")
    recorded = json.loads(STATE.read_text())
    live = live_identity()
    for key in ("context", "server", "ca_sha256", "namespace_uid", "lab_instance"):
        if recorded.get(key) != live.get(key):
            raise LabError(f"lab identity mismatch on {key}: refusing to act")
    if not live["server"].startswith("https://127.0.0.1:"):
        raise LabError("lab API endpoint is not local: refusing to act")
    return recorded


# ---------------------------------------------------------------- API client (token in memory only)


class Api:
    def __init__(self, identity: dict[str, Any]) -> None:
        cfg = json.loads(kubectl("config", "view", "--raw", "--minify", "-o", "json"))
        ca = base64.b64decode(cfg["clusters"][0]["cluster"]["certificate-authority-data"])
        if hashlib.sha256(ca).hexdigest() != identity["ca_sha256"]:
            raise LabError("CA changed")
        self.server = identity["server"]
        self.ctx = ssl.create_default_context(cadata=ca.decode())

    def request(self, token: str, method: str, path: str, body: dict[str, Any] | None = None) -> int:
        req = urllib.request.Request(
            self.server + path,
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=15) as resp:
                resp.read(0)  # never read or retain response bodies
                return int(resp.status)
        except urllib.error.HTTPError as err:
            return int(err.code)

    def read_secret_value(self, token: str, path: str) -> tuple[int, str | None]:
        """The one place a response body is read: the credential an actor copies.

        The value is returned to the caller's memory only; callers must never log
        or persist it.
        """
        req = urllib.request.Request(self.server + path, headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=15) as resp:
                data = json.loads(resp.read())["data"]["value"]
                return int(resp.status), base64.b64decode(data).decode()
        except urllib.error.HTTPError as err:
            return int(err.code), None


def canary_use(credential: str) -> int:
    """Offer a credential to the canary from the probe Pod; return the HTTP status (0 if unreachable).

    The value travels on stdin, so it is absent from every host command line.
    """
    script = ('read -r c; wget -q -O /dev/null --header "X-Canary-Credential: $c" '
              f'{CANARY_URL} 2>&1; echo "rc=$?"')
    out = kubectl("exec", "-i", "-n", NS, "canary-probe", "--", "sh", "-c", script, stdin=(credential + "\n").encode())
    if out.rstrip().endswith("rc=0"):
        return 200
    m = re.search(r"HTTP/1\.[01] (\d{3})", out)
    return int(m.group(1)) if m else 0


def set_credential(value: str) -> None:
    """Write one synthetic value to both the source Secret and the canary's accepted Secret."""
    for ns, name in ((NS, "release-credential"), ("canary", "canary-accepted")):
        manifest = kubectl("create", "secret", "generic", name, "-n", ns, "--from-file=value=/dev/stdin",
                           "--dry-run=client", "-o", "json", stdin=value.encode())
        kubectl("apply", "-f", "-", stdin=manifest.encode())


def attacker_pod(name: str, sa: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": NS, "labels": {"afterlock.dev/lab": "true", "afterlock.dev/actor": "attacker"}},
        "spec": {
            "serviceAccountName": sa,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "c", "image": "busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662", "command": ["sleep", "3600"],
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
            }],
        },
    }


def pod_token(name: str) -> str:
    """Simulates attacker control of the workload: read its projected token into memory."""
    kubectl("wait", "--for=condition=Ready", f"pod/{name}", "-n", NS, "--timeout=120s")
    return kubectl("exec", "-n", NS, name, "--", "cat", "/var/run/secrets/kubernetes.io/serviceaccount/token").strip()


def predict(case: str, objective: str) -> str:
    from afterlock.evidence import ReplayBundle, project
    from afterlock.model import parse_analysis_input
    from afterlock.results import analyze

    b = analyze(parse_analysis_input(project(ReplayBundle.load(ROOT / "datasets" / "replay" / case))[0]))
    return {o["id"]: o["status"] for o in b["objectives"]}[objective]


def predict_legit(case: str, op: str) -> str:
    from afterlock.evidence import ReplayBundle, project
    from afterlock.model import parse_analysis_input
    from afterlock.results import analyze

    b = analyze(parse_analysis_input(project(ReplayBundle.load(ROOT / "datasets" / "replay" / case))[0]))
    return "preserved" if {o["id"]: o["preserved"] for o in b["legitimate_operations"]}[op] else "broken"


# ---------------------------------------------------------------- commands


def cmd_create() -> None:
    if CLUSTER in run(["kind", "get", "clusters"]).split():
        raise LabError(f"cluster {CLUSTER} already exists; destroy it first")
    run(["kind", "create", "cluster", "--config", str(ROOT / "labs" / "kind" / "cluster.yaml")])
    kubectl("apply", "-f", str(ROOT / "labs" / "manifests" / "residual-token.yaml"))
    instance = secrets.token_hex(8)
    kubectl("label", "namespace", NS, f"afterlock.dev/lab-instance={instance}")
    kubectl("apply", "-f", str(ROOT / "labs" / "manifests" / "canary-service.yaml"))
    fake = "synthetic-" + secrets.token_hex(12)
    set_credential(fake)
    del fake
    for ns, pod in (("canary", "canary"), (NS, "canary-probe"), (NS, "release-app")):
        kubectl("wait", "--for=condition=Ready", f"pod/{pod}", "-n", ns, "--timeout=180s")
    STATE.parent.mkdir(parents=True, exist_ok=True)
    ident = live_identity()
    ident["kubernetes_version"] = json.loads(kubectl("version", "-o", "json"))["serverVersion"]["gitVersion"]
    STATE.write_text(json.dumps(ident, indent=2) + "\n")
    print(f"lab created: {ident['server']} instance {instance} ({ident['kubernetes_version']})")


def cmd_spike() -> None:
    ident = require_recorded_lab()
    api = Api(ident)
    receipts: list[dict[str, Any]] = []
    secret_path = f"/api/v1/namespaces/{NS}/secrets/release-credential"
    pods_path = f"/api/v1/namespaces/{NS}/pods"

    def record(step: str, predicted: str, observed: int, expect_ok: bool, **extra: Any) -> None:
        ok = 200 <= observed < 300
        agrees = observed != 0 and ok == expect_ok  # 0 = no answer, never evidence of rejection
        receipts.append({"step": step, "model_prediction": predicted, "observed_http_status": observed,
                         "agrees": agrees, **extra})
        print(f"  {step}: HTTP {observed} ({'agrees' if agrees else 'CONTRADICTS'} model)")

    ci = kubectl("create", "token", "ci-runner", "-n", NS, "--duration=20m").strip()  # seeded compromise
    record("ci-creates-release-reader-pod", "may_create", api.request(ci, "POST", pods_path, attacker_pod("diagnostic-job", "release-reader")), True)
    stolen = pod_token("diagnostic-job")
    status, copied = api.read_secret_value(stolen, secret_path)
    record("attacker-reads-secret", "violated", status, True)
    if copied is None:
        raise LabError("attacker read failed; downstream steps cannot run")
    record("copied-credential-accepted-by-canary", predict("residual-token", "protect-canary"), canary_use(copied), True)

    kubectl("delete", "rolebinding", "ci-pod-creator", "-n", NS)
    t0 = time.monotonic()
    status = 201
    while time.monotonic() - t0 < POLL_SECONDS:
        status = api.request(ci, "POST", pods_path + "?dryRun=All", attacker_pod("probe", "release-reader"))
        if status == 403:
            break
        time.sleep(1)
    record("ci-creation-blocked-after-binding-removal", "blocked", status, False, elapsed_seconds=round(time.monotonic() - t0, 2))
    record("residual-token-still-reads-secret", predict("residual-token", "protect-secret"), api.request(stolen, "GET", secret_path), True)

    uid = json.loads(kubectl("get", "pod", "diagnostic-job", "-n", NS, "-o", "json"))["metadata"]["uid"]
    kubectl("delete", "pod", "diagnostic-job", "-n", NS, "--wait=true")
    t0 = time.monotonic()
    while time.monotonic() - t0 < POLL_SECONDS:
        status = api.request(stolen, "GET", secret_path)
        if status == 401:
            break
        time.sleep(1)
    record("bound-token-rejected-after-pod-deletion", "rejected", status, False,
           pod_uid=uid, elapsed_seconds_after_deletion_complete=round(time.monotonic() - t0, 2))
    del stolen
    record("copied-credential-survives-kubernetes-containment", predict("copied-downstream", "protect-canary"),
           canary_use(copied), True)

    rotated = "synthetic-" + secrets.token_hex(12)
    set_credential(rotated)
    t0 = time.monotonic()
    status = old_status = 0
    while time.monotonic() - t0 < ROTATION_POLL_SECONDS:
        status, old_status = canary_use(rotated), canary_use(copied)
        if status == 200 and old_status == 401:
            break
        time.sleep(2)
    record("rotation-acknowledged-by-canary", "acknowledged", status, True,
           elapsed_seconds=round(time.monotonic() - t0, 2))
    del rotated
    record("copied-credential-rejected-after-rotation", predict("targeted-containment", "protect-canary"), old_status, False)
    del copied

    legit = kubectl("create", "token", "release-reader", "-n", NS, "--duration=10m").strip()
    status, current = api.read_secret_value(legit, secret_path)
    del legit
    record("legitimate-workload-uses-rotated-credential", predict_legit("targeted-containment", "release-canary"),
           canary_use(current) if status == 200 and current is not None else status, True)
    del current

    kubectl("create", "rolebinding", "ci-pod-creator", "-n", NS, "--role=pod-creator", f"--serviceaccount={NS}:ci-runner")
    kubectl("apply", "-f", str(ROOT / "labs" / "manifests" / "admission-restrict.yaml"))
    time.sleep(5)  # policy propagation; the observed outcome is what counts
    record("negative-control-admission-denies", predict("admission-denied", "protect-secret"),
           api.request(ci, "POST", pods_path + "?dryRun=All", attacker_pod("probe", "release-reader")), False)
    del ci

    validation = "lab_confirmed" if all(r["agrees"] for r in receipts) else "lab_contradicted"
    RECEIPTS.mkdir(parents=True, exist_ok=True)
    out = RECEIPTS / f"spike-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
    out.write_text(json.dumps({"lab": {k: ident[k] for k in ("server", "ca_sha256", "kubernetes_version", "lab_instance")},
                               "validation": validation, "receipts": receipts}, indent=2) + "\n")
    print(f"validation: {validation}; receipt: {out.relative_to(ROOT)}")


def cmd_destroy() -> None:
    require_recorded_lab()
    run(["kind", "delete", "cluster", "--name", CLUSTER])
    STATE.unlink()
    print("lab destroyed")


def cmd_status() -> None:
    print(json.dumps(require_recorded_lab(), indent=2))


def main() -> int:
    cmds = {"create": cmd_create, "spike": cmd_spike, "demo": cmd_spike, "verify": cmd_status, "status": cmd_status, "destroy": cmd_destroy}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        print(f"usage: lab.py {{{','.join(cmds)}}}", file=sys.stderr)
        return 2
    try:
        cmds[sys.argv[1]]()
    except LabError as exc:
        print(f"lab: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
