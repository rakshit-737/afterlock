"""Containment-sequence planner.

Bounded uniform-cost search over sequences of distinct candidate defender
actions. Every candidate sequence is evaluated by the full engine (attacker
interleaving included); nothing is accepted because it merely cuts a known
witness. The first valid sequence popped is minimum-cost among sequences of
length <= ``max_length`` built from the candidate set, which is the only
optimality claim made.
"""

from __future__ import annotations

import heapq
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .model import AnalysisInput, DefenderAction, ModelError, parse_actions, parse_sa_username
from .results import analyze

DEFAULT_COSTS = {
    "remove_binding": 1.0,
    "delete_pod": 1.0,
    "delete_controller": 1.0,
    "delete_pods_except": 2.0,
    "delete_controllers_except": 2.0,
    "rotate_downstream_credential": 3.0,
    "delete_service_account": 4.0,
    "wait": 0.0,  # plus seconds / 900
}


@dataclass(frozen=True)
class PlannerConfig:
    max_length: int = 4
    max_evaluations: int = 5_000
    costs: Mapping[str, float] | None = None


def action_cost(a: DefenderAction, costs: Mapping[str, float]) -> float:
    c = float(costs.get(a.kind, DEFAULT_COSTS[a.kind]))
    if a.kind == "wait":
        c += int(a.param("seconds")) / 900.0
    return c


def _attacker_service_accounts(inp: AnalysisInput) -> set[tuple[str, str]]:
    sas: set[tuple[str, str]] = set()
    pods = {p.uid: p for p in inp.inventory.pods}
    for f in inp.initial_facts:
        if f.kind == "possesses_credential":
            sa = parse_sa_username(inp.credential(f.args[0]).username)
            if sa:
                sas.add(sa)
        elif f.kind == "controls_pod" and f.args[0] in pods:
            p = pods[f.args[0]]
            sas.add((p.namespace, p.service_account))
        elif f.kind == "historical_pod":
            sas.add((f.args[1], f.args[2]))
    # service accounts the attacker's identities could launch workloads as
    namespaces = {ns for ns, _ in sas}
    for s in inp.inventory.service_accounts:
        if s.namespace in namespaces:
            sas.add((s.namespace, s.name))
    return sas


def candidate_actions(inp: AnalysisInput) -> list[DefenderAction]:
    """Generate the approved intervention vocabulary for a case."""
    sas = _attacker_service_accounts(inp)
    attacker_pods = {f.args[0] for f in inp.initial_facts if f.kind == "controls_pod"}
    attacker_ctrls = {f.args[0] for f in inp.initial_facts if f.kind == "controls_controller"}
    legit_pods = {op.pod_uid for op in inp.legitimate_operations}
    raw: list[dict[str, Any]] = []
    for b in inp.inventory.bindings:
        if any(s.kind == "ServiceAccount" and (s.namespace, s.name) in sas for s in b.subjects):
            entry: dict[str, Any] = {"kind": "remove_binding", "name": b.name}
            if b.namespace is not None:
                entry["namespace"] = b.namespace
            raw.append(entry)
    for p in inp.inventory.pods:
        if p.uid in attacker_pods:
            raw.append({"kind": "delete_pod", "uid": p.uid})
    for c in inp.inventory.controllers:
        if c.uid in attacker_ctrls:
            raw.append({"kind": "delete_controller", "uid": c.uid})
    for ns, sa in sorted(sas):
        keep = sorted(p.uid for p in inp.inventory.pods if p.uid in legit_pods and (p.namespace, p.service_account) == (ns, sa))
        raw.append({"kind": "delete_pods_except", "namespace": ns, "service_account": sa, "keep_uids": keep})
        keep_c = sorted(
            {p.controller_uid for p in inp.inventory.pods if p.uid in legit_pods and p.controller_uid and (p.namespace, p.service_account) == (ns, sa)}
        )
        raw.append({"kind": "delete_controllers_except", "namespace": ns, "service_account": sa, "keep_uids": keep_c})
        raw.append({"kind": "delete_service_account", "namespace": ns, "name": sa})
    for s in inp.inventory.services:
        raw.append({"kind": "rotate_downstream_credential", "service": s.name})
        if s.rotation_propagation_seconds > 0:
            # S-SEC-5: a rotation only contains once it has propagated; offer the wait.
            raw.append({"kind": "wait", "seconds": s.rotation_propagation_seconds})
    return sorted(set(parse_actions(raw, "candidates")), key=lambda a: a.label())


def naive_plan(inp: AnalysisInput) -> list[DefenderAction]:
    """Baseline: remove every binding of attacker-associated identities, then delete their workloads."""
    sas = _attacker_service_accounts(inp)
    raw: list[dict[str, Any]] = []
    for b in inp.inventory.bindings:
        if any(s.kind == "ServiceAccount" and (s.namespace, s.name) in sas for s in b.subjects):
            entry: dict[str, Any] = {"kind": "remove_binding", "name": b.name}
            if b.namespace is not None:
                entry["namespace"] = b.namespace
            raw.append(entry)
    for ns, sa in sorted(sas):
        raw.append({"kind": "delete_controllers_except", "namespace": ns, "service_account": sa, "keep_uids": []})
        raw.append({"kind": "delete_pods_except", "namespace": ns, "service_account": sa, "keep_uids": []})
    return list(parse_actions(raw, "naive"))


def _summarize(seq: list[DefenderAction], bundle: dict[str, Any], costs: Mapping[str, float]) -> dict[str, Any]:
    return {
        "actions": [a.to_json() for a in seq],
        "cost": round(sum(action_cost(a, costs) for a in seq), 6),
        "model_conclusion": bundle["conclusion"]["model"],
        "objectives": {o["id"]: o["status"] for o in bundle["objectives"]},
        "legitimate_operations": {op["id"]: op["preserved"] for op in bundle["legitimate_operations"]},
        "exposure_intervals": [e["interval"] for e in bundle["exposure_during_containment"]],
        "result_digest": bundle["result_digest"],
    }


def _valid(bundle: dict[str, Any]) -> bool:
    return bundle["conclusion"]["model"] == "contained_within_scope" and all(op["preserved"] for op in bundle["legitimate_operations"])


def plan(inp: AnalysisInput, config: PlannerConfig | None = None, candidates: list[DefenderAction] | None = None) -> dict[str, Any]:
    cfg = config or PlannerConfig()
    costs = dict(DEFAULT_COSTS)
    costs.update(cfg.costs or {})
    cands = candidates if candidates is not None else candidate_actions(inp)
    if not cands:
        raise ModelError("no candidate actions")

    evaluations = 0
    best: dict[str, Any] | None = None
    best_disruptive: dict[str, Any] | None = None
    incomplete = False
    heap: list[tuple[float, tuple[str, ...], tuple[int, ...]]] = [(0.0, (), ())]
    while heap:
        cost, _, idxs = heapq.heappop(heap)
        seq = [cands[i] for i in idxs]
        if idxs:
            if evaluations >= cfg.max_evaluations:
                incomplete = True
                break
            evaluations += 1
            bundle = analyze(inp.with_remediation(seq))
            if _valid(bundle):
                best = _summarize(seq, bundle, costs)
                break
            if best_disruptive is None and bundle["conclusion"]["model"] == "contained_within_scope":
                best_disruptive = _summarize(seq, bundle, costs)
        if len(idxs) < cfg.max_length:
            for j, a in enumerate(cands):
                if j in idxs:
                    continue
                nxt = idxs + (j,)
                heapq.heappush(heap, (cost + action_cost(a, costs), tuple(cands[k].label() for k in nxt), nxt))

    naive = naive_plan(inp)
    naive_bundle = analyze(inp.with_remediation(naive)) if naive else None
    proposed = analyze(inp)
    if best is not None:
        status = "optimal_within_bounds"
        statement = (
            f"Minimum-cost valid sequence among all orderings of up to {cfg.max_length} distinct candidate actions "
            f"({len(cands)} candidates, {evaluations} sequences evaluated)."
        )
    elif incomplete:
        status = "incomplete_search"
        statement = f"Evaluation cap {cfg.max_evaluations} reached before a valid plan was found. This is not evidence that none exists."
    else:
        status = "no_valid_plan_within_bounds"
        statement = f"No sequence of up to {cfg.max_length} distinct candidate actions satisfied every objective while preserving legitimate operations."
    return {
        "schema": "afterlock.plan/1",
        "case_id": inp.case_id,
        "input_digest": inp.raw_digest,
        "search": {
            "status": status,
            "statement": statement,
            "algorithm": "uniform-cost search over distinct-action sequences; each sequence fully re-analyzed",
            "max_length": cfg.max_length,
            "max_evaluations": cfg.max_evaluations,
            "evaluations": evaluations,
            "candidates": [a.to_json() for a in cands],
            "costs": costs,
        },
        "best_plan": best,
        "cheapest_security_only_plan": best_disruptive,
        "proposed_remediation": _summarize(list(inp.remediation), proposed, costs),
        "naive_containment": _summarize(naive, naive_bundle, costs) if naive_bundle else None,
    }
