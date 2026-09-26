"""Baseline and ablation comparison over the hand-authored semantic corpus.

IMPORTANT: labels come from datasets/fixtures/expected.json, which are
hand-written expectations, not independent lab executions. These numbers
measure agreement with written semantics, not real-world effectiveness.
A second, separate label set comes from live-lab receipts
(benchmarks/labels/lab-derived.json, built by benchmarks/lab_labels.py from
observed HTTP statuses only). It covers few cases and objectives and is
reported on its own; it is never merged with the hand-authored labels.
A third label set covers the held-out templates (datasets/heldout/, built by
datasets/generators/build_heldout_cases.py). Its labels come from the
independent reference checker, so they measure engine-vs-reference agreement
on scenarios not used during engine development, not real-world accuracy.

The committed reports contain no timings, host details or Python version, so
they are byte-identical across platforms. Latencies go to
benchmarks/reports/timings.local.json, which is not committed.

Usage: python benchmarks/run.py [--repeat N]
Writes benchmarks/reports/semantic-corpus.{json,md} and timings.local.json.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages"))

from afterlock import __version__  # noqa: E402
from afterlock.engine import MODE_FULL, MODES  # noqa: E402
from afterlock.evidence import ReplayBundle, project  # noqa: E402
from afterlock.model import AnalysisInput, parse_analysis_input  # noqa: E402
from afterlock.results import analyze  # noqa: E402

LAB_LABELS = ROOT / "benchmarks/labels/lab-derived.json"
HELDOUT = ROOT / "datasets/heldout"
REPORTS = ROOT / "benchmarks/reports"


def lab_derived(bundles: dict[tuple[str, str], dict]) -> dict:
    """Compare each mode's per-objective prediction with lab-derived labels (if any)."""
    if not LAB_LABELS.is_file():
        return {"available": False}
    doc = json.loads(LAB_LABELS.read_text())
    rows = []
    for case, objs in sorted(doc["labels"].items()):
        for objective, entry in sorted(objs.items()):
            row = {"case": case, "objective": objective, "label": entry["label"], "evidence": len(entry["evidence"]), "predicted": {}}
            for mode in MODES:
                b = bundles.get((case, mode))
                if b is None:
                    continue
                if objective.startswith("legitimate:"):
                    ops = {o["id"]: o["preserved"] for o in b["legitimate_operations"]}
                    op = objective.split(":", 1)[1]
                    row["predicted"][mode] = ("preserved" if ops[op] else "broken") if op in ops else "absent"
                else:
                    row["predicted"][mode] = {o["id"]: o["status"] for o in b["objectives"]}.get(objective, "absent")
            rows.append(row)
    decided = [r for r in rows if r["label"] != "disputed"]
    summary = {mode: {"labels": len(decided), "agreement": sum(r["predicted"].get(mode) == r["label"] for r in decided)} for mode in MODES}
    return {"available": True, "label_source": doc["label_source"], "receipts": doc["receipts"],
            "disputed": sum(r["label"] == "disputed" for r in rows), "summary": summary, "rows": rows}


def _mode_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    claimed = [x for x in rows if x["predicted"] == "contained_within_scope"]
    residual = [x for x in rows if x["expected"] == "residual_path"]
    return {
        "cases": len(rows),
        "agreement": sum(x["predicted"] == x["expected"] for x in rows),
        "containment_claims": len(claimed),
        "false_containment_claims": sum(x["expected"] != "contained_within_scope" for x in claimed),
        "residual_recall": f"{sum(x['predicted'] == 'residual_path' for x in residual)}/{len(residual)}",
        "decisions": sum(x["predicted"] != "unknown" for x in rows),
        "deterministic": all(x["deterministic"] for x in rows),
    }


def _run(inp: AnalysisInput, mode: str, repeat: int, timings: dict[str, float], key: str) -> tuple[dict[str, Any], bool]:
    times, digests = [], set()
    b: dict[str, Any] = {}
    for _ in range(repeat):
        t = time.perf_counter()
        b = analyze(inp, mode)
        times.append(time.perf_counter() - t)
        digests.add(b["result_digest"])
    timings[key] = round(statistics.median(times) * 1000, 3)
    return b, len(digests) == 1


def heldout(repeat: int, timings: dict[str, float]) -> dict[str, Any]:
    """Engine modes vs reference-derived labels on the held-out templates."""
    labels_path = HELDOUT / "expected.json"
    if not labels_path.is_file():
        return {"available": False}
    doc = json.loads(labels_path.read_text())
    rows = []
    for case, exp in sorted(doc["cases"].items()):
        inp = parse_analysis_input(json.loads((HELDOUT / "cases" / f"{case}.json").read_text()))
        for mode in MODES:
            b, det = _run(inp, mode, repeat, timings, f"heldout/{case}/{mode}")
            objs = {o["id"]: o["status"] for o in b["objectives"]}
            rows.append({"case": case, "template": exp["template"], "mode": mode, "expected": exp["conclusion"],
                         "predicted": b["conclusion"]["model"], "objectives_agree": objs == exp["objectives"], "deterministic": det})
    summary = {}
    for mode in MODES:
        r = [x for x in rows if x["mode"] == mode]
        summary[mode] = _mode_summary(r) | {"objective_level_agreement": sum(x["objectives_agree"] for x in r)}
    by_template = {}
    for t in sorted({r["template"] for r in rows}):
        by_template[t] = {}
        for m in MODES:
            sel = [x for x in rows if x["template"] == t and x["mode"] == m]
            by_template[t][m] = f"{sum(x['predicted'] == x['expected'] for x in sel)}/{len(sel)}"
    disagreements = [x["case"] for x in rows if x["mode"] == MODE_FULL and not (x["objectives_agree"] and x["predicted"] == x["expected"])]
    return {"available": True, "label_source": "independent reference checker (packages/afterlock_reference)",
            "seed": doc["_seed"], "summary": summary, "by_template": by_template, "disagreements_full": disagreements, "rows": rows}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeat", type=int, default=5)
    args = ap.parse_args()
    expected = {k: v for k, v in json.loads((ROOT / "datasets/fixtures/expected.json").read_text()).items() if not k.startswith("_")}
    rows = []
    timings: dict[str, float] = {}
    bundles: dict[tuple[str, str], dict] = {}
    for name, exp in sorted(expected.items()):
        inp = parse_analysis_input(project(ReplayBundle.load(ROOT / "datasets/replay" / name))[0])
        for mode in MODES:
            b, det = _run(inp, mode, args.repeat, timings, f"hand-authored/{name}/{mode}")
            bundles[(name, mode)] = b
            rows.append({"case": name, "mode": mode, "expected": exp["conclusion"], "predicted": b["conclusion"]["model"],
                         "deterministic": det})
    summary = {mode: _mode_summary([x for x in rows if x["mode"] == mode]) for mode in MODES}
    env = {"afterlock": __version__, "repeat": args.repeat}
    lab = lab_derived(bundles)
    held = heldout(args.repeat, timings)
    out = {"label_source": "hand-authored expectations (not lab-validated)", "environment": env, "summary": summary, "rows": rows,
           "lab_derived": lab, "heldout": held}
    (REPORTS / "semantic-corpus.json").write_bytes((json.dumps(out, indent=2) + "\n").encode())
    local = {"note": "Median engine latency in ms per case and mode. Host-dependent; not committed; not a performance claim.",
             "python": platform.python_version(), "platform": platform.platform(), "processor": platform.processor() or "unknown",
             "median_ms": timings}
    (REPORTS / "timings.local.json").write_bytes((json.dumps(local, indent=2, sort_keys=True) + "\n").encode())
    lines = [
        "# Semantic corpus: baselines and ablations",
        "",
        "Generated by `python benchmarks/run.py`. **Labels are hand-authored expectations, not independent lab outcomes.**",
        f"AFTERLOCK {env['afterlock']}, {args.repeat} repetitions per case and mode (determinism check only; no timings).",
        "",
        "| Mode | Cases | Agreement | Containment claims | False containment claims | Residual recall | Conclusive | Deterministic |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for mode, s in summary.items():
        lines.append(f"| `{mode}` | {s['cases']} | {s['agreement']} | {s['containment_claims']} | {s['false_containment_claims']} | "
                     f"{s['residual_recall']} | {s['decisions']} | {s['deterministic']} |")
    lines += ["", "## Per case", "", "| Case | Expected | full | snapshot_only | history_without_lifecycle | final_state_only |", "|---|---|---|---|---|---|"]
    for name in sorted(expected):
        by = {x["mode"]: x["predicted"] for x in rows if x["case"] == name}
        lines.append(f"| {name} | {expected[name]['conclusion']} | " + " | ".join(by[m] for m in MODES) + " |")
    lines += ["", "## Lab-derived labels (separate label set)", ""]
    if not lab["available"]:
        lines.append("No lab-derived labels (run `python benchmarks/lab_labels.py` after a live-lab run).")
    else:
        lines += [f"Labels from observed live-lab HTTP statuses in {len(lab['receipts'])} receipts "
                  "(`benchmarks/labels/lab-derived.json`); model predictions are not used to build them. "
                  f"Few objectives are covered; disputed labels: {lab['disputed']}.", "",
                  "| Case | Objective | Lab label | Receipts | " + " | ".join(MODES) + " |", "|---|---|---|---|" + "---|" * len(MODES)]
        for r in lab["rows"]:
            lines.append(f"| {r['case']} | {r['objective']} | {r['label']} | {r['evidence']} | "
                         + " | ".join(r["predicted"].get(m, "-") for m in MODES) + " |")
        lines += ["", "| Mode | Agreement with lab labels |", "|---|---|"]
        lines += [f"| `{m}` | {s['agreement']}/{s['labels']} |" for m, s in lab["summary"].items()]
    lines += ["", "## Held-out templates (separate label set)", ""]
    if not held["available"]:
        lines.append("No held-out set (run `python datasets/generators/build_heldout_cases.py`).")
    else:
        lines += [f"{held['summary'][MODE_FULL]['cases']} cases from `datasets/heldout/` (seed `{held['seed']}`), from templates not "
                  "used during engine development. **Labels come from the independent reference checker, not from lab outcomes**: "
                  "the `full` row is engine-vs-reference agreement; the other rows are baselines and ablations scored against the "
                  "same labels.", "",
                  "| Mode | Cases | Conclusion agreement | Objective-level agreement | Containment claims | False containment claims "
                  "| Residual recall | Deterministic |", "|---|---|---|---|---|---|---|---|"]
        for mode, s in held["summary"].items():
            lines.append(f"| `{mode}` | {s['cases']} | {s['agreement']} | {s['objective_level_agreement']} | {s['containment_claims']} | "
                         f"{s['false_containment_claims']} | {s['residual_recall']} | {s['deterministic']} |")
        lines += ["", "| Template | " + " | ".join(MODES) + " |", "|---|" + "---|" * len(MODES)]
        for t, by_mode in held["by_template"].items():
            lines.append(f"| {t} | " + " | ".join(by_mode[m] for m in MODES) + " |")
        lines += ["", "Engine/reference disagreements (full mode): "
                  + (", ".join(held["disagreements_full"]) if held["disagreements_full"] else "none") + "."]
    lines += ["", "Latencies are written to `benchmarks/reports/timings.local.json` (not committed); they are not a performance claim.", ""]
    (REPORTS / "semantic-corpus.md").write_bytes("\n".join(lines).encode())
    print("\n".join(lines[:14]))


if __name__ == "__main__":
    main()
