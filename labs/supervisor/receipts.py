"""Pure receipt logic for the lab supervisor (no I/O, no Kubernetes access).

Kept separate from lab.py so that expectation modes, receipt summaries, and
network-policy construction can be unit tested without a lab.
"""

from __future__ import annotations

import statistics
from typing import Any

# Expectation modes for one observed step.
#   "answer_ok"     - an HTTP answer in 2xx is expected (access works)
#   "answer_denied" - an HTTP answer >= 300 is expected (access refused by the service)
#   "no_answer"     - no HTTP answer at all is expected (status 0: dropped by the network)
# Status 0 means "no answer". It never counts as a refusal: a refusal must be an
# explicit answer. It only agrees with "no_answer", and every no_answer step must
# be paired with a positive reachability control, because a broken probe also
# yields 0.
EXPECTATIONS = ("answer_ok", "answer_denied", "no_answer")


def agrees(observed: int, expect: str) -> bool:
    if expect not in EXPECTATIONS:
        raise ValueError(f"unknown expectation {expect!r}")
    if expect == "no_answer":
        return observed == 0
    if observed == 0:
        return False
    return (200 <= observed < 300) == (expect == "answer_ok")


# Checks the supervisor performs itself (collected-bundle validation, leak scan,
# gap records) use the same expectation modes as API observations, so validation()
# and summarise() treat them uniformly. They carry "observation": "supervisor-check"
# and a synthetic status: CHECK_PASSED (200) when the check holds, CHECK_FAILED (422)
# when it does not. Status 0 is never used for a check.
CHECK_PASSED = 200
CHECK_FAILED = 422


def check_receipt(step: str, passed: bool, prediction: str, **extra: Any) -> dict[str, Any]:
    observed = CHECK_PASSED if passed else CHECK_FAILED
    return {"step": step, "model_prediction": prediction, "expect": "answer_ok", "observed_http_status": observed,
            "agrees": agrees(observed, "answer_ok"), "observation": "supervisor-check", **extra}


def validation(receipts: list[dict[str, Any]]) -> str:
    return "lab_confirmed" if receipts and all(r["agrees"] for r in receipts) else "lab_contradicted"


def _stats(values: list[float]) -> dict[str, float]:
    return {"n": len(values), "min": min(values), "median": round(statistics.median(values), 2), "max": max(values)}


def summarise(runs: list[dict[str, Any]], names: list[str] | None = None) -> dict[str, Any]:
    """Summarise repeated spike receipts: do all runs agree, and how stable are timings?

    Timing statistics cover every numeric field whose name starts with "elapsed_seconds".
    Nothing is dropped: a step missing from some run is reported under "missing_steps".
    """
    names = names or [f"run-{i + 1}" for i in range(len(runs))]
    steps: dict[str, dict[str, Any]] = {}
    for name, run in zip(names, runs, strict=True):
        for r in run["receipts"]:
            s = steps.setdefault(r["step"], {"model_prediction": set(), "observed_http_status": [], "agrees": [], "runs": [], "timings": {}})
            s["model_prediction"].add(r["model_prediction"])
            s["observed_http_status"].append(r["observed_http_status"])
            s["agrees"].append(bool(r["agrees"]))
            s["runs"].append(name)
            for k, v in r.items():
                if k.startswith("elapsed_seconds") and isinstance(v, int | float):
                    s["timings"].setdefault(k, []).append(float(v))
    out_steps = {}
    for step, s in steps.items():
        out_steps[step] = {
            "model_prediction": sorted(s["model_prediction"]),
            "observed_http_status": s["observed_http_status"],
            "all_agree": all(s["agrees"]) and len(s["agrees"]) == len(runs),
            "observations_identical": len(set(s["observed_http_status"])) == 1,
            "timing": {k: _stats(v) for k, v in s["timings"].items()},
        }
    missing = {step: sorted(set(names) - set(s["runs"])) for step, s in steps.items() if len(s["runs"]) != len(runs)}
    per_run = [{"run": n, "validation": r.get("validation", validation(r["receipts"]))} for n, r in zip(names, runs, strict=True)]
    return {
        "runs": per_run,
        "run_count": len(runs),
        "all_runs_agree": bool(runs) and all(p["validation"] == "lab_confirmed" for p in per_run) and not missing,
        "missing_steps": missing,
        "steps": out_steps,
    }


# ---------------------------------------------------------------- network policy

LAB_LABELS = {"afterlock.dev/lab": "true"}


def network_policies(api_server_ip: str, api_server_port: int = 6443) -> list[dict[str, Any]]:
    """NetworkPolicies for the lab. Enforced only with a policy-enforcing CNI (Calico).

    - canary namespace: default-deny ingress; only pods in namespace demo may reach the
      canary on 8080 (this includes attacker pods: using a copied credential downstream is
      part of the modeled threat).
    - demo namespace: attacker pods (afterlock.dev/actor=attacker) get default-deny egress
      except DNS, the API server endpoint (post-DNAT node address), and the canary.
    """
    def meta(name: str, ns: str) -> dict[str, Any]:
        return {"name": name, "namespace": ns, "labels": dict(LAB_LABELS)}

    dns = {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                   "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
           "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]}
    return [
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta("default-deny-ingress", "canary"),
         "spec": {"podSelector": {}, "policyTypes": ["Ingress"]}},
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta("canary-from-demo", "canary"),
         "spec": {"podSelector": {"matchLabels": {"app": "canary"}}, "policyTypes": ["Ingress"],
                  "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "demo"}}}],
                               "ports": [{"protocol": "TCP", "port": 8080}]}]}},
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta("attacker-egress", "demo"),
         "spec": {"podSelector": {"matchLabels": {"afterlock.dev/actor": "attacker"}}, "policyTypes": ["Egress"],
                  "egress": [
                      dns,
                      {"to": [{"ipBlock": {"cidr": f"{api_server_ip}/32"}}], "ports": [{"protocol": "TCP", "port": api_server_port}]},
                      {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "canary"}},
                               "podSelector": {"matchLabels": {"app": "canary"}}}],
                       "ports": [{"protocol": "TCP", "port": 8080}]},
                  ]}},
    ]
