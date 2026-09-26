"""Assemble analysis result bundles.

Two independent result dimensions are reported:
  model conclusion   residual_path | contained_within_scope | unknown | invalid_input
  validation status  not_executed | lab_confirmed | lab_contradicted | validation_inconclusive

Missing evidence, unsupported semantics, and exhausted bounds can only ever
produce ``unknown``; they never produce ``contained_within_scope``.
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .engine import (
    MODE_FULL,
    VIEW_EVIDENCE,
    VIEW_POSSIBLE,
    ViewOutcome,
    legit_status,
    objective_goal,
    run_view,
)
from .model import AnalysisInput, digest

RESULT_SCHEMA = "afterlock.result/1"

LIMITATIONS = (
    "Absence of evidence is not evidence of absence: the engine cannot establish that no credential was copied.",
    "Conclusions cover only the supported semantic profile, declared objectives, and stated assumptions.",
    "Previously disclosed information cannot be made unknown; only its usefulness can change.",
    "Control-plane propagation is assumed complete before the next defender step; real propagation needs lab confirmation.",
    "Host, node, or control-plane compromise is outside the model.",
)


def _objective_entry(inp: AnalysisInput, obj: Any, ev: ViewOutcome, pv: ViewOutcome, unknown_reasons: list[str]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    goal = objective_goal(obj.kind, obj.target)
    entry: dict[str, Any] = {"id": obj.id, "kind": obj.kind, "target": list(obj.target), "description": obj.description}
    witness = None
    if goal in ev.goals_final:
        entry.update(status="violated", basis=VIEW_EVIDENCE)
        witness = {"id": f"w-{obj.id}", "objective": obj.id, "view": VIEW_EVIDENCE, "goal": list(goal),
                   "steps": [d.to_json() for d in ev.witness(goal)]}
    elif goal in pv.goals_final:
        entry.update(status="possibly_violated", basis=VIEW_POSSIBLE)
        witness = {"id": f"w-{obj.id}", "objective": obj.id, "view": VIEW_POSSIBLE, "goal": list(goal),
                   "steps": [d.to_json() for d in pv.witness(goal)]}
    elif unknown_reasons:
        entry.update(status="unknown", basis=None, reasons=list(unknown_reasons))
    else:
        entry.update(status="satisfied_within_scope", basis="fixpoint_exhausted")
    if witness is not None:
        entry["witness"] = witness["id"]
    return entry, witness


def _exposure(view: ViewOutcome) -> list[dict[str, Any]]:
    out = []
    for rec in view.intervals[:-1]:
        goals = [list(g) for g in rec.goals if g[0] in ("can_read_secret", "can_use_downstream")]
        if goals:
            out.append({"interval": rec.index, "after_action": rec.action, "time": rec.time, "attacker_capabilities": goals})
    return out


def _timeline(view: ViewOutcome) -> list[dict[str, Any]]:
    return [
        {
            "interval": r.index,
            "time": r.time,
            "defender_action": r.action,
            "notes": r.notes,
            "reconciled_pods": r.reconciled_pods,
            "attacker_capabilities": [list(g) for g in r.goals if g[0] in ("can_read_secret", "can_use_downstream")],
        }
        for r in view.intervals
    ]


def analyze(inp: AnalysisInput, mode: str = MODE_FULL) -> dict[str, Any]:
    ev = run_view(inp, VIEW_EVIDENCE, mode)
    pv = run_view(inp, VIEW_POSSIBLE, mode)

    unknown_reasons: list[str] = []
    missing: list[dict[str, Any]] = []
    for gap in inp.coverage_gaps:
        missing.append({"kind": gap.kind, "id": gap.id, "detail": gap.description, "evidence": list(gap.evidence)})
        unknown_reasons.append(f"coverage gap {gap.id}: {gap.description}")
    seen = set()
    for u in ev.unknowns + pv.unknowns:
        key = tuple(sorted((k, str(v)) for k, v in u.items()))
        if key in seen:
            continue
        seen.add(key)
        missing.append(u)
        unknown_reasons.append(u.get("detail", u["kind"]))
    for v in (ev, pv):
        if v.bounds_exceeded:
            missing.append({"kind": "bounds_exceeded", "view": v.view, "detail": f"derivation cap {inp.bounds.max_derivations} reached"})
            unknown_reasons.append(f"analysis bounds exceeded in {v.view} view; exploration incomplete")

    objectives = []
    witnesses = []
    for obj in inp.objectives:
        entry, w = _objective_entry(inp, obj, ev, pv, unknown_reasons)
        objectives.append(entry)
        if w is not None:
            witnesses.append(w)

    statuses = {o["status"] for o in objectives}
    if statuses & {"violated", "possibly_violated"}:
        conclusion = "residual_path"
    elif "unknown" in statuses:
        conclusion = "unknown"
    else:
        conclusion = "contained_within_scope"

    evidence_refs = sorted({e for w in witnesses for s in w["steps"] for e in s.get("evidence", [])})
    legit = legit_status(inp, ev.final_env)
    exhausted = not (ev.bounds_exceeded or pv.bounds_exceeded)
    bundle: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "engine": {"name": "afterlock", "version": __version__, "mode": mode},
        "case_id": inp.case_id,
        "cluster_id": inp.cluster_id,
        "input_digest": inp.raw_digest,
        "semantic_profile": {"id": inp.profile.id, "kubernetes_version": inp.profile.kubernetes_version},
        "analysis_time": inp.analysis_time,
        "remediation": [a.to_json() for a in inp.remediation],
        "conclusion": {
            "model": conclusion,
            "validation": "not_executed",
            "scope": (
                "Finite projection explored to fixpoint for every interval of the remediation sequence "
                "under the supported semantic profile; no statement is made about unsupported semantics, "
                "undeclared objectives, or activity outside the evidence boundary."
                if exhausted
                else "Exploration incomplete: bounds were exceeded. This is not a containment result."
            ),
        },
        "objectives": objectives,
        "witnesses": witnesses,
        "exposure_during_containment": _exposure(ev),
        "legitimate_operations": legit,
        "timeline": _timeline(ev),
        "assumptions": list(inp.assumptions),
        "evidence_references": evidence_refs,
        "missing_coverage": missing,
        "analysis_bounds": {
            "intervals": len(inp.remediation) + 1,
            "max_intervals": inp.bounds.max_intervals,
            "max_derivations": inp.bounds.max_derivations,
            "derivations_used": {VIEW_EVIDENCE: ev.derivation_count, VIEW_POSSIBLE: pv.derivation_count},
            "exhausted": exhausted,
        },
        "limitations": list(LIMITATIONS),
        "note": "result_digest identifies this content; it proves neither completeness nor truth.",
    }
    bundle["result_digest"] = digest(bundle)
    return bundle


# --------------------------------------------------------------------------
# human-readable explanation


def _fact_text(f: list[str]) -> str:
    k = f[0]
    if k == "possesses":
        return f"attacker possesses credential {f[1]}"
    if k == "controls_pod":
        return f"attacker controls pod UID {f[1]}"
    if k == "controls_controller":
        return f"attacker controls controller UID {f[1]}"
    if k == "knows_secret":
        return f"attacker knows secret {f[1]}/{f[2]} version {f[3]}"
    if k == "possesses_downstream":
        return f"attacker holds downstream credential for {f[1]} (version {f[2]})"
    if k == "can_read_secret":
        return f"attacker can read secret {f[1]}/{f[2]}"
    if k == "can_use_downstream":
        return f"attacker can authenticate to {f[1]}"
    return " ".join(f)


def _interval_text(i: int) -> str:
    if i == -2:
        return "before analysis (evidence)"
    if i == -1:
        return "before analysis (possible history)"
    if i == 0:
        return "at analysis time, before remediation"
    return f"after remediation step {i}"


def explain(bundle: dict[str, Any]) -> str:
    c = bundle["conclusion"]
    headline = {
        "residual_path": "Containment FAILS in the modeled state.",
        "contained_within_scope": "No supported attack continuation found within scope.",
        "unknown": "Containment CANNOT be established.",
        "invalid_input": "Input rejected.",
    }[c["model"]]
    lines = [f"AFTERLOCK {bundle['case_id']}: {headline}",
             f"  model conclusion: {c['model']}   validation: {c['validation']}",
             f"  profile: {bundle['semantic_profile']['id']}   input: {bundle['input_digest'][:23]}…"]
    if bundle["remediation"]:
        lines.append("  remediation sequence:")
        for i, a in enumerate(bundle["remediation"], 1):
            params = ", ".join(f"{k}={v}" for k, v in a.items() if k != "kind")
            lines.append(f"    {i}. {a['kind']}({params})")
    else:
        lines.append("  remediation sequence: (none)")
    lines.append("")
    wmap = {w["id"]: w for w in bundle["witnesses"]}
    for o in bundle["objectives"]:
        lines.append(f"Objective {o['id']} [{o['status']}]: {o['description'] or o['kind']}")
        if "witness" in o:
            w = wmap[o["witness"]]
            lines.append(f"  witness ({w['view']}):")
            for s in w["steps"]:
                src = f" evidence={','.join(s['evidence'])}" if s.get("evidence") else ""
                lines.append(f"    - {_fact_text(s['fact'])}  [{s['rule']}, {_interval_text(s['interval'])}, {s['status']}{src}]")
                for cond in s["conditions"]:
                    if cond["check"] == "authorized":
                        lines.append(f"        authorized: {cond['verb']} {cond['resource']} in {cond['namespace']} via {', '.join(cond['via'])}")
                    elif cond["check"] == "credential_usable":
                        lines.append(f"        credential usable: {cond['detail']}")
        for r in o.get("reasons", []):
            lines.append(f"  missing: {r}")
        lines.append("")
    if bundle["exposure_during_containment"]:
        lines.append("Exposure during containment (attacker may act between steps):")
        for e in bundle["exposure_during_containment"]:
            caps = "; ".join(_fact_text(g) for g in e["attacker_capabilities"])
            lines.append(f"  interval {e['interval']} ({e['after_action'] or 'before remediation'}): {caps}")
        lines.append("")
    if bundle["legitimate_operations"]:
        lines.append("Legitimate operations after remediation:")
        for op in bundle["legitimate_operations"]:
            lines.append(f"  {op['id']}: {'preserved' if op['preserved'] else 'BROKEN'} — {op['detail']}")
        lines.append("")
    if bundle["missing_coverage"]:
        lines.append("Missing coverage / unsupported:")
        for m in bundle["missing_coverage"]:
            lines.append(f"  - {m['kind']}: {m.get('detail', '')}")
        lines.append("")
    lines.append(f"Scope: {c['scope']}")
    lines.append(f"Result digest: {bundle['result_digest']} (identifies content; not a proof)")
    return "\n".join(lines)
