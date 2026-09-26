"""Derive outcome labels for replay cases from live-lab receipts.

Non-circular by construction: a label is computed ONLY from the observed HTTP
status of a lab step. The receipt's model_prediction and agrees fields are
never read, so these labels do not depend on engine output.

Mapping from observation to label, per objective:
  2xx                -> "violated"               (the protected thing was reached)
  explicit >= 300    -> "satisfied_within_scope" (refused, within the lab's scope)
  0 (no answer)      -> no label (absence of an answer is not evidence)
Legitimate operations: 2xx -> "preserved", explicit refusal -> "broken".
Conflicting observations for one (case, objective) yield "disputed", with every
receipt kept.

Usage: python benchmarks/lab_labels.py
Writes benchmarks/labels/lab-derived.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RECEIPTS = ROOT / "labs" / "receipts"
OUT = ROOT / "benchmarks" / "labels" / "lab-derived.json"

# For receipts written before steps carried replay_case/objective (lab.py records
# them now). Mirrors the predict() calls in labs/supervisor/lab.py.
LEGACY_STEP_CASES = {
    "copied-credential-accepted-by-canary": ("residual-token", "protect-canary"),
    "residual-token-still-reads-secret": ("residual-token", "protect-secret"),
    "copied-credential-survives-kubernetes-containment": ("copied-downstream", "protect-canary"),
    "copied-credential-rejected-after-rotation": ("targeted-containment", "protect-canary"),
    "legitimate-workload-uses-rotated-credential": ("targeted-containment", "legitimate:release-canary"),
    "negative-control-admission-denies": ("admission-denied", "protect-secret"),
}


def label_for(objective: str, status: int) -> str | None:
    if status == 0:
        return None
    ok = 200 <= status < 300
    if objective.startswith("legitimate:"):
        return "preserved" if ok else "broken"
    return "violated" if ok else "satisfied_within_scope"


def derive(receipts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """receipts: {receipt file name: receipt document}."""
    labels: dict[str, dict[str, Any]] = {}
    unlabeled: list[dict[str, Any]] = []
    for fname in sorted(receipts):
        for r in receipts[fname].get("receipts", []):
            case, objective = r.get("replay_case"), r.get("objective")
            if not case:
                case, objective = LEGACY_STEP_CASES.get(r["step"], (None, None))
            ref = {"receipt": fname, "step": r["step"], "observed_http_status": r["observed_http_status"]}
            if not case or not objective:
                unlabeled.append({**ref, "reason": "step not mapped to a replay case"})
                continue
            lab = label_for(objective, r["observed_http_status"])
            if lab is None:
                unlabeled.append({**ref, "reason": "no answer observed"})
                continue
            entry = labels.setdefault(case, {}).setdefault(objective, {"observations": [], "evidence": []})
            entry["observations"].append(lab)
            entry["evidence"].append(ref)
    for objs in labels.values():
        for entry in objs.values():
            seen = sorted(set(entry.pop("observations")))
            entry["label"] = seen[0] if len(seen) == 1 else "disputed"
            if len(seen) > 1:
                entry["observed_labels"] = seen
    return {
        "_comment": "Derived from observed HTTP statuses in labs/receipts only; model predictions are not read. "
                    "Regenerate with python benchmarks/lab_labels.py. Do not edit by hand.",
        "label_source": "live-lab observations",
        "receipts": sorted(receipts),
        "labels": {c: dict(sorted(o.items())) for c, o in sorted(labels.items())},
        "unlabeled": unlabeled,
    }


def load_receipts(directory: Path = RECEIPTS) -> dict[str, dict[str, Any]]:
    # Per-run receipts only; spike-summary-*.json files are aggregates, not observations.
    return {p.name: json.loads(p.read_text()) for p in sorted(directory.glob("spike-*.json"))
            if not p.name.startswith("spike-summary-")}


def main() -> None:
    out = derive(load_receipts())
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2) + "\n")
    n = sum(len(o) for o in out["labels"].values())
    print(f"{n} lab-derived labels over {len(out['labels'])} cases from {len(out['receipts'])} receipts -> {OUT.relative_to(ROOT).as_posix()}")


if __name__ == "__main__":
    main()
