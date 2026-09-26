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
 11. the legitimate workload reads the rotated value and still uses the service,
and that network isolation holds (verified, not assumed from manifests):
 12. a Pod in a non-allowed namespace gets no answer from the canary, and
 13. attacker Pods get no answer from a non-allowed in-cluster destination,
each after a control showing the destination answers an allowed client.

`reset` restores the post-create state without recreating the cluster, and
`spike --repeat N` runs reset+spike N times, one receipt per run plus a summary.

`collect` runs reset+spike with the Go collector (services/collector) running on the
host under a read-only ServiceAccount token, kills and restarts it mid-spike (fault
injection), and at the residual-token checkpoint (binding removed, attacker Pod alive)
has it ingest the API server audit log and write an afterlock.replay/1 bundle. The
supervisor validates, projects and analyses that bundle, compares the conclusion with
the hand-authored residual-token case, and scans every produced file for the
credential values it holds in memory; the bundle is kept (labs/collected/) only if
that scan is clean.

Every observation is compared with the engine's prediction for the matching
replay case and written to labs/receipts/. Tokens and credential values stay in
memory and never appear in receipts or host command lines.

Requires: kind, kubectl, a disposable Docker-capable Linux host.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
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
OUTSIDER_URL = "http://outsider.outsider.svc:8080/"
# Calico (policy-enforcing CNI). The digest was computed from this exact URL on
# 2026-09-26; install_cni() refuses any manifest that does not match it.
CALICO_URL = "https://raw.githubusercontent.com/projectcalico/calico/v3.29.1/manifests/calico.yaml"
CALICO_SHA256 = "ef325a26cb4e0a2d386d0e512c0cf4fd0fa935ac25777b41b0d3737153025a1c"

sys.path.insert(0, str(ROOT / "packages"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import collected  # noqa: E402
from receipts import agrees, check_receipt, network_policies, summarise, validation  # noqa: E402

# Audit logging (labs/kind/cluster.yaml). The policy is staged here before the
# cluster is created; the API server writes its log into AUDIT_HOST_DIR through
# an extraMount, and the collector reads it from the host.
LAB_HOST_DIR = Path("/tmp/afterlock-lab")
AUDIT_POLICY_SRC = ROOT / "services" / "collector" / "deploy" / "audit-policy.yaml"
AUDIT_LOG_NODE_PATH = "/var/log/kubernetes/audit/audit.log"
NODE_CONTAINER = f"{CLUSTER}-control-plane"
COLLECTED = ROOT / "labs" / "collected"
COLLECTOR_SOURCE_ID = "lab-collector"


class LabError(RuntimeError):
    pass


STDERR_LIMIT = 200
_SECRETISH = re.compile(r"(?i)(token|secret|password|bearer|authorization|data:|stringData|-----BEGIN)|[A-Za-z0-9+/=_\-.]{32,}")


def scrub_stderr(stderr: bytes, *, had_stdin: bool) -> str:
    """Error text safe to print and to land in CI logs.

    Commands that received material on stdin (e.g. ``kubectl apply -f -`` of Secret manifests)
    may echo it back in errors, so their stderr is withheld entirely. Otherwise the text is
    truncated and any line mentioning credential-like content or holding a long opaque
    token-like string is redacted.
    """
    if had_stdin:
        return f"<stderr withheld: {len(stderr)} bytes; command received stdin>"
    lines = stderr.decode("utf-8", "replace").splitlines()
    safe = ["<redacted line>" if _SECRETISH.search(line) else line for line in lines]
    text = " | ".join(safe)
    return text if len(text) <= STDERR_LIMIT else text[:STDERR_LIMIT] + "...(truncated)"


def run(args: list[str], *, stdin: bytes | None = None, check: bool = True, cwd: Path | None = None) -> str:
    """Run a fixed argument vector (never a shell string)."""
    proc = subprocess.run(args, input=stdin, capture_output=True, timeout=600, cwd=cwd)
    if check and proc.returncode != 0:
        detail = scrub_stderr(proc.stderr, had_stdin=stdin is not None)
        raise LabError(f"{args[0]} {args[1] if len(args) > 1 else ''} failed (exit {proc.returncode}): {detail}")
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


def http_probe(ns: str, pod: str, url: str, credential: str = "") -> tuple[int, str]:
    """GET url from inside a lab Pod; return (HTTP status, reason). Status 0 = no HTTP answer.

    The credential (possibly empty) travels on stdin, so it is absent from every host
    command line. reason is one of a fixed set, never raw output.
    """
    script = ('read -r c; wget -q -T 10 -O /dev/null --header "X-Canary-Credential: $c" '
              f'{url} 2>&1; echo "rc=$?"')
    out = kubectl("exec", "-i", "-n", ns, pod, "--", "sh", "-c", script, stdin=(credential + "\n").encode())
    if out.rstrip().endswith("rc=0"):
        return 200, "answered"
    m = re.search(r"HTTP/1\.[01] (\d{3})", out)
    if m:
        return int(m.group(1)), "answered"
    low = out.lower()
    for needle, reason in (("timed out", "timeout"), ("refused", "refused"), ("bad address", "dns")):
        if needle in low:
            return 0, reason
    return 0, "other"


def canary_use(credential: str) -> int:
    """Offer a credential to the canary from the probe Pod; return the HTTP status (0 if unreachable)."""
    return http_probe(NS, "canary-probe", CANARY_URL, credential)[0]


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


def install_cni() -> None:
    """Install Calico from a pinned manifest whose SHA-256 is verified before use.

    The manifest is Kubernetes YAML (data applied through the API), not a script, and
    it is rejected unless its digest matches CALICO_SHA256 exactly.
    """
    with urllib.request.urlopen(CALICO_URL, timeout=60) as resp:
        manifest = resp.read()
    digest = hashlib.sha256(manifest).hexdigest()
    if digest != CALICO_SHA256:
        raise LabError(f"Calico manifest digest mismatch ({digest}); refusing to apply")
    kubectl("apply", "-f", "-", stdin=manifest)
    kubectl("-n", "kube-system", "rollout", "status", "daemonset/calico-node", "--timeout=300s")
    kubectl("wait", "--for=condition=Ready", "node", "--all", "--timeout=300s")


def api_server_endpoint() -> tuple[str, int]:
    """The post-DNAT API server address that pods actually connect to."""
    ep = json.loads(kubectl("get", "endpoints", "kubernetes", "-n", "default", "-o", "json"))
    subset = ep["subsets"][0]
    return subset["addresses"][0]["ip"], int(subset["ports"][0]["port"])


def apply_network_policies() -> None:
    ip, port = api_server_endpoint()
    for policy in network_policies(ip, port):
        kubectl("apply", "-f", "-", stdin=json.dumps(policy).encode())


def wait_fixture_pods() -> None:
    for ns, pod in (("canary", "canary"), (NS, "canary-probe"), (NS, "release-app"), ("outsider", "outsider")):
        kubectl("wait", "--for=condition=Ready", f"pod/{pod}", "-n", ns, "--timeout=180s")


def seed_credential() -> float:
    """Write a fresh synthetic credential and wait until the canary accepts it; return seconds waited."""
    fake = "synthetic-" + secrets.token_hex(12)
    set_credential(fake)
    t0 = time.monotonic()
    while time.monotonic() - t0 < ROTATION_POLL_SECONDS:
        if canary_use(fake) == 200:
            del fake
            return round(time.monotonic() - t0, 2)
        time.sleep(2)
    del fake
    raise LabError("canary did not accept the seeded credential in time")


def stage_audit_policy() -> None:
    """Copy the collector's audit policy to the fixed host path cluster.yaml mounts."""
    (LAB_HOST_DIR / "policy").mkdir(parents=True, exist_ok=True)
    (LAB_HOST_DIR / "audit").mkdir(parents=True, exist_ok=True)
    (LAB_HOST_DIR / "policy" / "audit-policy.yaml").write_bytes(AUDIT_POLICY_SRC.read_bytes())


def read_audit_log() -> bytes:
    """The API server's audit log (Metadata level: no bodies). Host mount first, node fallback.

    The file is created by the API server as root with mode 0600, so on hosts where the
    supervisor is unprivileged it is read through the node container instead.
    """
    try:
        return (LAB_HOST_DIR / "audit" / "audit.log").read_bytes()
    except PermissionError:
        proc = subprocess.run(["docker", "exec", NODE_CONTAINER, "cat", AUDIT_LOG_NODE_PATH],
                              capture_output=True, timeout=120)
        if proc.returncode != 0:
            raise LabError("could not read the API server audit log") from None
        return proc.stdout


# ---------------------------------------------------------------- collector (read-only, metadata only)


class LiveCollector:
    """Runs the Go collector on the host against the lab with a read-only ServiceAccount token.

    Phases during a spike:
      start()      process A: list/watch inventory into a fresh spool
      restart()    fault injection: SIGKILL A mid-spike, start B on the same spool
                   (the collector must record a collector-restart gap)
      finish(...)  SIGTERM B, then process C ingests the API server audit log with the
                   same spool, relists inventory, and writes the replay bundle. The
                   supervisor then validates, analyses and leak-scans it.

    The collector token lives in process memory and, for the collector's lifetime,
    in a 0600 kubeconfig inside a private temporary directory that is removed on
    close(). It is never written into labs/.
    """

    def __init__(self, ident: dict[str, Any]) -> None:
        self.ident = ident
        self.bin = self._binary()
        self.work = Path(tempfile.mkdtemp(prefix="afterlock-collect-"))
        self.secret_dir = Path(tempfile.mkdtemp(prefix="afterlock-collector-kube-"))
        self.spool = self.work / "spool.jsonl"
        self.proc: subprocess.Popen[bytes] | None = None
        self.phase = 0
        self.token = ""
        self.receipts: list[dict[str, Any]] = []
        # Start of the evidence window (RFC3339, whole seconds, floored so it is inclusive).
        # The API server audit log covers the cluster's lifetime, including earlier spike
        # runs that created and deleted Pods with the same names; those are not this case.
        self.since = ""

    @staticmethod
    def _binary() -> Path:
        override = os.environ.get("AFTERLOCK_COLLECTOR_BIN")
        if override:
            path = Path(override)
        else:
            path = ROOT / "labs" / ".state" / "afterlock-collector"
            run(["go", "build", "-trimpath", "-o", str(path), "./cmd/afterlock-collector"], cwd=ROOT / "services" / "collector")
        if not path.is_file():
            raise LabError(f"collector binary not found at {path}")
        return path

    def _grant(self) -> None:
        kubectl("apply", "-f", "-", stdin=kubectl("create", "namespace", "afterlock", "--dry-run=client", "-o", "json").encode())
        kubectl("apply", "-f", str(ROOT / "services" / "collector" / "deploy" / "rbac.yaml"))
        # Secret metadata: the ClusterRole from secret-metadata-rbac.yaml, bound only in
        # the lab namespace (RoleBinding), as that file recommends. A RoleBinding grants
        # nothing cluster-wide, so the collector must list/watch Secrets in that namespace
        # only (--secret-namespaces); a cluster-wide list is forbidden (403).
        role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                "metadata": {"name": "afterlock-collector-secret-metadata"},
                "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["list", "watch"]}]}
        binding = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                   "metadata": {"name": "afterlock-collector-secret-metadata", "namespace": NS},
                   "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "afterlock-collector-secret-metadata"},
                   "subjects": [{"kind": "ServiceAccount", "name": "afterlock-collector", "namespace": "afterlock"}]}
        for doc in (role, binding):
            kubectl("apply", "-f", "-", stdin=json.dumps(doc).encode())
        self.token = kubectl("create", "token", "afterlock-collector", "-n", "afterlock", "--duration=30m").strip()
        cfg = json.loads(kubectl("config", "view", "--raw", "--minify", "-o", "json"))
        kubeconfig = {
            "apiVersion": "v1", "kind": "Config", "current-context": "collector",
            "clusters": [{"name": "lab", "cluster": {"server": self.ident["server"],
                          "certificate-authority-data": cfg["clusters"][0]["cluster"]["certificate-authority-data"]}}],
            "users": [{"name": "afterlock-collector", "user": {"token": self.token}}],
            "contexts": [{"name": "collector", "context": {"cluster": "lab", "user": "afterlock-collector"}}],
        }
        fd = os.open(self.secret_dir / "kubeconfig", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(kubeconfig, fh)

    def _args(self, out: Path, *extra: str) -> list[str]:
        return [str(self.bin), "--kubeconfig", str(self.secret_dir / "kubeconfig"), "--cluster-id", CLUSTER,
                "--source-id", COLLECTOR_SOURCE_ID, "--case-id", "residual-token-live", "--spool", str(self.spool),
                "--secret-metadata", "--secret-namespaces", NS, "--audit-since", self.since,
                "--out", str(out), *extra]

    def _spawn(self) -> None:
        self.phase += 1
        log = open(self.work / f"collector-{self.phase}.log", "wb")  # noqa: SIM115 - owned by the process
        self.proc = subprocess.Popen(self._args(self.work / f"partial-{self.phase}"), stdout=log, stderr=log)
        time.sleep(5)  # initial list; the process must still be running afterwards
        if self.proc.poll() is not None:
            raise LabError(f"collector exited early (phase {self.phase}); see its log in {self.work}")

    def start(self) -> None:
        # The kind node shares the host kernel clock, so host UTC and the API server's
        # stageTimestamp are comparable.
        self.since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._grant()
        self._spawn()

    def restart(self) -> None:
        """Fault injection: kill without a chance to flush, then restart on the same spool."""
        assert self.proc is not None
        self.proc.kill()
        self.proc.wait(timeout=30)
        self._spawn()

    def finish(self, template: dict[str, Any], held: dict[str, str]) -> list[dict[str, Any]]:
        """Stop collection, write the bundle, and check it. Returns receipt entries."""
        from afterlock.evidence import ReplayBundle, project
        from afterlock.model import parse_analysis_input
        from afterlock.results import analyze

        assert self.proc is not None
        self.proc.terminate()
        stopped = self.proc.wait(timeout=60)
        time.sleep(2)  # let the API server flush the audit log
        audit = self.work / "audit.log"
        audit.write_bytes(read_audit_log())
        ci_sa = json.loads(kubectl("get", "serviceaccount", "ci-runner", "-n", NS, "-o", "json"))["metadata"]["uid"]
        release_uid = json.loads(kubectl("get", "pod", "release-app", "-n", NS, "-o", "json"))["metadata"]["uid"]
        attacker_uid = json.loads(kubectl("get", "pod", "diagnostic-job", "-n", NS, "-o", "json"))["metadata"]["uid"]
        case = collected.lab_case(template, ci_username=f"system:serviceaccount:{NS}:ci-runner", ci_sa_uid=ci_sa,
                                  release_pod_uid=release_uid, analysis_time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                  source_id=COLLECTOR_SOURCE_ID)
        (self.work / "case-template.json").write_text(json.dumps(case, indent=2) + "\n")
        bundle_dir = self.work / "bundle"
        self.phase += 1
        proc = subprocess.run(self._args(bundle_dir, "--audit-log", str(audit), "--case", str(self.work / "case-template.json")),
                              capture_output=True, timeout=300)
        audit.unlink()  # raw audit log is not part of the bundle and is not kept
        out: list[dict[str, Any]] = [check_receipt("collector-writes-bundle", proc.returncode == 0, "written",
                                                   restarted_phase_exit_code=stopped, exit_code=proc.returncode)]
        if proc.returncode != 0:
            return out

        # 1. The bundle is a valid afterlock.replay/1 bundle and projects cleanly.
        try:
            bundle = ReplayBundle.load(bundle_dir)
            analysis_input, diag = project(bundle)
            result = analyze(parse_analysis_input(analysis_input))
            problems = {"rejected": len(diag["rejected"]), "conflicts": len(diag["conflicts"])}
            valid = not diag["rejected"] and not diag["conflicts"]
        except Exception as exc:  # noqa: BLE001 - recorded as a failed check, never swallowed silently
            out.append(check_receipt("collected-bundle-validates", False, "valid", error=type(exc).__name__,
                                     **safe_error_detail(exc)))
            return out
        out.append(check_receipt("collected-bundle-validates", valid, "valid", schema=bundle.manifest.get("schema"),
                                 accepted_events=diag["accepted"], **problems))

        # 2. The attacker Pod creation and the binding deletion were collected.
        events = collected.read_events(bundle.event_lines)
        checks = collected.inventory_checks(bundle.inventory, events, namespace=NS, attacker_pod="diagnostic-job",
                                            attacker_pod_uid=attacker_uid, attacker_sa="release-reader",
                                            creator=f"system:serviceaccount:{NS}:ci-runner", binding="ci-pod-creator")
        out.append(check_receipt("collected-inventory-shows-attack-and-containment", all(checks.values()), "present",
                                 checks=checks))

        # 3. Same conclusion as the hand-authored residual-token case.
        reference = analyze(parse_analysis_input(project(ReplayBundle.load(ROOT / "datasets" / "replay" / "residual-token"))[0]))
        cmp = collected.compare_conclusions(result, reference)
        out.append(check_receipt("collected-conclusion-matches-residual-token", cmp["match"], reference["conclusion"]["model"],
                                 replay_case="residual-token", comparison=cmp,
                                 coverage_gaps=len(analysis_input["coverage_gaps"])))

        # 4. Explicit gap for the injected restart.
        kinds = collected.gap_kinds(events)
        out.append(check_receipt("collector-restart-recorded-as-gap", kinds.get("collector-restart", 0) >= 2, "gap_recorded",
                                 gap_kinds=kinds, collector_restarts_injected=2))

        # 5. Leak scan over every file the collector produced (bundles, spool, logs, result).
        (self.work / "analysis-result.json").write_text(json.dumps(result, indent=2) + "\n")
        findings = collected.scan_for_leaks(self.work, {**held, "collector-token": self.token})
        clean = not findings
        out.append(check_receipt("collected-bundle-has-no-credential-material", clean, "no_leak",
                                 findings=findings, scanned_files=sorted(p.relative_to(self.work).as_posix()
                                                                         for p in self.work.rglob("*") if p.is_file())))
        if clean:
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            dest = COLLECTED / f"residual-token-{stamp}"
            dest.mkdir(parents=True)
            for p in sorted(bundle_dir.iterdir()):
                shutil.copyfile(p, dest / p.name)
            shutil.copyfile(self.work / "analysis-result.json", dest / "analysis-result.json")
            out[-1]["bundle"] = dest.relative_to(ROOT).as_posix()
        return out

    def close(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=30)
        self.token = ""
        shutil.rmtree(self.secret_dir, ignore_errors=True)
        shutil.rmtree(self.work, ignore_errors=True)


# ---------------------------------------------------------------- commands


def safe_error_detail(exc: BaseException) -> dict[str, Any]:
    """Where an exception came from, without its message (which may quote evidence values).

    Records the innermost afterlock frames (file:line function) and, for a KeyError, the key
    only when it looks like a schema field name.
    """
    import traceback

    where = [f"{Path(f.filename).name}:{f.lineno} {f.name}" for f in traceback.extract_tb(exc.__traceback__)
             if "afterlock" in f.filename.replace("\\", "/")]
    detail: dict[str, Any] = {"where": where[-3:]}
    if isinstance(exc, KeyError) and exc.args and isinstance(exc.args[0], str) and re.fullmatch(r"[a-z_]{1,40}", exc.args[0]):
        detail["missing_key"] = exc.args[0]
    return detail


def cmd_create(_args: list[str]) -> None:
    if CLUSTER in run(["kind", "get", "clusters"]).split():
        raise LabError(f"cluster {CLUSTER} already exists; destroy it first")
    stage_audit_policy()
    run(["kind", "create", "cluster", "--config", str(ROOT / "labs" / "kind" / "cluster.yaml")])
    install_cni()
    kubectl("apply", "-f", str(ROOT / "labs" / "manifests" / "residual-token.yaml"))
    instance = secrets.token_hex(8)
    kubectl("label", "namespace", NS, f"afterlock.dev/lab-instance={instance}")
    kubectl("apply", "-f", str(ROOT / "labs" / "manifests" / "canary-service.yaml"))
    kubectl("apply", "-f", str(ROOT / "labs" / "manifests" / "isolation-probe.yaml"))
    apply_network_policies()
    fake = "synthetic-" + secrets.token_hex(12)
    set_credential(fake)
    del fake
    wait_fixture_pods()
    STATE.parent.mkdir(parents=True, exist_ok=True)
    ident = live_identity()
    ident["kubernetes_version"] = json.loads(kubectl("version", "-o", "json"))["serverVersion"]["gitVersion"]
    STATE.write_text(json.dumps(ident, indent=2) + "\n")
    print(f"lab created: {ident['server']} instance {instance} ({ident['kubernetes_version']})")


def reset(ident: dict[str, Any]) -> dict[str, Any]:
    """Restore the post-create state without recreating the cluster.

    Deletes attacker pods, removes the admission policy, restores bindings and
    network policies from the manifests, and re-seeds the synthetic credential
    (waiting until the canary accepts it). The recorded identity is re-checked
    afterwards: namespace UIDs must not change.
    """
    t0 = time.monotonic()
    kubectl("delete", "pods", "-n", NS, "-l", "afterlock.dev/actor=attacker", "--wait=true", "--ignore-not-found")
    kubectl("delete", "-f", str(ROOT / "labs" / "manifests" / "admission-restrict.yaml"), "--ignore-not-found")
    kubectl("apply", "-f", str(ROOT / "labs" / "manifests" / "residual-token.yaml"))
    kubectl("apply", "-f", str(ROOT / "labs" / "manifests" / "canary-service.yaml"))
    kubectl("apply", "-f", str(ROOT / "labs" / "manifests" / "isolation-probe.yaml"))
    apply_network_policies()
    wait_fixture_pods()
    seed_wait = seed_credential()
    after = require_recorded_lab()
    if after["namespace_uid"] != ident["namespace_uid"]:
        raise LabError("namespace was recreated during reset")
    return {"elapsed_seconds": round(time.monotonic() - t0, 2), "credential_seed_elapsed_seconds": seed_wait}


def cmd_reset(_args: list[str]) -> None:
    info = reset(require_recorded_lab())
    print(f"lab reset in {info['elapsed_seconds']} s (credential accepted after {info['credential_seed_elapsed_seconds']} s)")


def run_spike(ident: dict[str, Any], collector: LiveCollector | None = None) -> list[dict[str, Any]]:
    api = Api(ident)
    receipts: list[dict[str, Any]] = []
    secret_path = f"/api/v1/namespaces/{NS}/secrets/release-credential"
    pods_path = f"/api/v1/namespaces/{NS}/pods"

    def record(step: str, predicted: str, observed: int, expect: str, case: str | None = None,
               objective: str | None = None, **extra: Any) -> None:
        ok = agrees(observed, expect)
        entry: dict[str, Any] = {"step": step, "model_prediction": predicted, "expect": expect,
                                 "observed_http_status": observed, "agrees": ok}
        if case:
            entry.update(replay_case=case, objective=objective)
        receipts.append({**entry, **extra})
        print(f"  {step}: HTTP {observed} ({'agrees' if ok else 'CONTRADICTS'} model)")

    def predicted(case: str, objective: str) -> dict[str, Any]:
        return {"predicted": predict(case, objective), "case": case, "objective": objective}

    ci = kubectl("create", "token", "ci-runner", "-n", NS, "--duration=20m").strip()  # seeded compromise
    record("ci-creates-release-reader-pod", "may_create", api.request(ci, "POST", pods_path, attacker_pod("diagnostic-job", "release-reader")), "answer_ok")
    stolen = pod_token("diagnostic-job")
    if collector is not None:
        collector.restart()  # fault injection mid-spike: must surface as an explicit gap
    status, copied = api.read_secret_value(stolen, secret_path)
    record("attacker-reads-secret", "violated", status, "answer_ok")
    if copied is None:
        raise LabError("attacker read failed; downstream steps cannot run")
    record("copied-credential-accepted-by-canary", observed=canary_use(copied), expect="answer_ok",
           **predicted("residual-token", "protect-canary"))

    # Network isolation. Each "no_answer" step is preceded by a control showing the
    # target does answer an allowed client, so status 0 is not a broken probe.
    status, reason = http_probe(NS, "canary-probe", CANARY_URL)
    record("isolation-control-canary-answers-demo", "reachable", status, "answer_denied", probe_reason=reason)
    status, reason = http_probe("outsider", "outsider", CANARY_URL)
    record("isolation-outsider-cannot-reach-canary", "unreachable", status, "no_answer", probe_reason=reason)
    status, reason = http_probe(NS, "canary-probe", OUTSIDER_URL)
    record("isolation-control-outsider-answers-demo", "reachable", status, "answer_denied", probe_reason=reason)
    status, reason = http_probe(NS, "diagnostic-job", OUTSIDER_URL)
    record("isolation-attacker-egress-to-outsider-denied", "unreachable", status, "no_answer", probe_reason=reason)

    kubectl("delete", "rolebinding", "ci-pod-creator", "-n", NS)
    t0 = time.monotonic()
    status = 201
    while time.monotonic() - t0 < POLL_SECONDS:
        status = api.request(ci, "POST", pods_path + "?dryRun=All", attacker_pod("probe", "release-reader"))
        if status == 403:
            break
        time.sleep(1)
    record("ci-creation-blocked-after-binding-removal", "blocked", status, "answer_denied", elapsed_seconds=round(time.monotonic() - t0, 2))
    record("residual-token-still-reads-secret", observed=api.request(stolen, "GET", secret_path), expect="answer_ok",
           **predicted("residual-token", "protect-secret"))
    if collector is not None:
        # Checkpoint: the state now matches the residual-token case (binding removed,
        # attacker Pod and its token alive). Collection ends here.
        template = json.loads((ROOT / "datasets" / "replay" / "residual-token" / "case.json").read_text())
        receipts.extend(collector.finish(template, {"ci-token": ci, "stolen-token": stolen, "copied-credential": copied}))

    uid = json.loads(kubectl("get", "pod", "diagnostic-job", "-n", NS, "-o", "json"))["metadata"]["uid"]
    kubectl("delete", "pod", "diagnostic-job", "-n", NS, "--wait=true")
    t0 = time.monotonic()
    while time.monotonic() - t0 < POLL_SECONDS:
        status = api.request(stolen, "GET", secret_path)
        if status == 401:
            break
        time.sleep(1)
    record("bound-token-rejected-after-pod-deletion", "rejected", status, "answer_denied",
           pod_uid=uid, elapsed_seconds_after_deletion_complete=round(time.monotonic() - t0, 2))
    del stolen
    record("copied-credential-survives-kubernetes-containment", observed=canary_use(copied), expect="answer_ok",
           **predicted("copied-downstream", "protect-canary"))

    rotated = "synthetic-" + secrets.token_hex(12)
    set_credential(rotated)
    t0 = time.monotonic()
    status = old_status = 0
    while time.monotonic() - t0 < ROTATION_POLL_SECONDS:
        status, old_status = canary_use(rotated), canary_use(copied)
        if status == 200 and old_status == 401:
            break
        time.sleep(2)
    # The elapsed time is the kubelet mounted-Secret refresh delay; it is recorded, never hidden.
    record("rotation-acknowledged-by-canary", "acknowledged", status, "answer_ok",
           elapsed_seconds=round(time.monotonic() - t0, 2))
    del rotated
    record("copied-credential-rejected-after-rotation", observed=old_status, expect="answer_denied",
           **predicted("targeted-containment", "protect-canary"))
    del copied

    legit = kubectl("create", "token", "release-reader", "-n", NS, "--duration=10m").strip()
    status, current = api.read_secret_value(legit, secret_path)
    del legit
    record("legitimate-workload-uses-rotated-credential", predict_legit("targeted-containment", "release-canary"),
           canary_use(current) if status == 200 and current is not None else status, "answer_ok",
           case="targeted-containment", objective="legitimate:release-canary")
    del current

    kubectl("create", "rolebinding", "ci-pod-creator", "-n", NS, "--role=pod-creator", f"--serviceaccount={NS}:ci-runner")
    kubectl("apply", "-f", str(ROOT / "labs" / "manifests" / "admission-restrict.yaml"))
    time.sleep(5)  # policy propagation; the observed outcome is what counts
    record("negative-control-admission-denies",
           observed=api.request(ci, "POST", pods_path + "?dryRun=All", attacker_pod("probe", "release-reader")),
           expect="answer_denied", **predicted("admission-denied", "protect-secret"))
    del ci
    return receipts


def parse_repeat(args: list[str]) -> int:
    if not args:
        return 1
    if len(args) == 2 and args[0] == "--repeat" and args[1].isdigit() and 1 <= int(args[1]) <= 20:
        return int(args[1])
    raise LabError("usage: lab.py spike [--repeat N] (1 <= N <= 20)")


def cmd_spike(args: list[str]) -> None:
    repeat = parse_repeat(args)
    ident = require_recorded_lab()
    lab = {k: ident[k] for k in ("server", "ca_sha256", "kubernetes_version", "lab_instance")}
    RECEIPTS.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    runs, names = [], []
    for i in range(repeat):
        doc: dict[str, Any] = {"lab": lab}
        if repeat > 1:
            print(f"run {i + 1}/{repeat}: reset")
            doc["run"] = {"index": i + 1, "of": repeat, "reset": reset(ident)}
        receipts = run_spike(ident)
        doc.update(validation=validation(receipts), receipts=receipts)
        out = RECEIPTS / (f"spike-{stamp}.json" if repeat == 1 else f"spike-{stamp}-r{i + 1}.json")
        out.write_text(json.dumps(doc, indent=2) + "\n")
        print(f"validation: {doc['validation']}; receipt: {out.relative_to(ROOT).as_posix()}")
        runs.append(doc)
        names.append(out.name)
    if repeat > 1:
        summary = {"lab": lab, **summarise(runs, names)}
        out = RECEIPTS / f"spike-summary-{stamp}.json"
        out.write_text(json.dumps(summary, indent=2) + "\n")
        print(f"all runs agree: {summary['all_runs_agree']}; summary: {out.relative_to(ROOT).as_posix()}")


def cmd_collect(_args: list[str]) -> None:
    """reset + spike with the Go collector running; writes collect-<ts>.json and, only if
    the leak scan passes, the collected bundle under labs/collected/."""
    ident = require_recorded_lab()
    lab = {k: ident[k] for k in ("server", "ca_sha256", "kubernetes_version", "lab_instance")}
    doc: dict[str, Any] = {"lab": lab, "run": {"reset": reset(ident)}}
    collector = LiveCollector(ident)
    try:
        collector.start()
        receipts = run_spike(ident, collector)
    finally:
        collector.close()
    doc.update(validation=validation(receipts), receipts=receipts)
    RECEIPTS.mkdir(parents=True, exist_ok=True)
    out = RECEIPTS / f"collect-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
    out.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"validation: {doc['validation']}; receipt: {out.relative_to(ROOT).as_posix()}")
    if doc["validation"] != "lab_confirmed":
        raise LabError("collected evidence contradicts the model or failed a check; see the receipt")


def cmd_destroy(_args: list[str]) -> None:
    require_recorded_lab()
    run(["kind", "delete", "cluster", "--name", CLUSTER])
    STATE.unlink()
    print("lab destroyed")


def cmd_status(_args: list[str]) -> None:
    print(json.dumps(require_recorded_lab(), indent=2))


def main() -> int:
    cmds = {"create": cmd_create, "spike": cmd_spike, "demo": cmd_spike, "reset": cmd_reset, "collect": cmd_collect,
            "verify": cmd_status, "status": cmd_status, "destroy": cmd_destroy}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        print(f"usage: lab.py {{{','.join(cmds)}}} [--repeat N]", file=sys.stderr)
        return 2
    try:
        cmds[sys.argv[1]](sys.argv[2:])
    except LabError as exc:
        print(f"lab: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
