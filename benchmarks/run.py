"""Baseline and ablation comparison over the hand-authored semantic corpus.

IMPORTANT: labels come from datasets/fixtures/expected.json, which are
hand-written expectations, not independent lab executions. These numbers
measure agreement with written semantics, not real-world effectiveness.
A second, separate label set comes from live-lab receipts
(benchmarks/labels/lab-derived.json, built by benchmarks/lab_labels.py from
observed HTTP statuses only). It covers few cases and objectives and is
reported on its own; it is never merged with the hand-authored labels.

Usage: python benchmarks/run.py [--repeat N]
Writes benchmarks/reports/semantic-corpus.{json,md}.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages"))

from afterlock import __version__  # noqa: E402
from afterlock.engine import MODES  # noqa: E402
from afterlock.evidence import ReplayBundle, project  # noqa: E402
from afterlock.model import parse_analysis_input  # noqa: E402
from afterlock.results import analyze  # noqa: E402

LAB_LABELS = ROOT / "benchmarks/labels/lab-derived.json"


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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeat", type=int, default=5)
    args = ap.parse_args()
    expected = {k: v for k, v in json.loads((ROOT / "datasets/fixtures/expected.json").read_text()).items() if not k.startswith("_")}
    rows = []
    bundles: dict[tuple[str, str], dict] = {}
    for name, exp in sorted(expected.items()):
        inp = parse_analysis_input(project(ReplayBundle.load(ROOT / "datasets/replay" / name))[0])
        for mode in MODES:
            times, digests = [], set()
            for _ in range(args.repeat):
                t = time.perf_counter()
                b = analyze(inp, mode)
                times.append(time.perf_counter() - t)
                digests.add(b["result_digest"])
            bundles[(name, mode)] = b
            rows.append({"case": name, "mode": mode, "expected": exp["conclusion"], "predicted": b["conclusion"]["model"],
                         "deterministic": len(digests) == 1, "median_ms": round(statistics.median(times) * 1000, 3)})
    summary = {}
    for mode in MODES:
        r = [x for x in rows if x["mode"] == mode]
        claimed = [x for x in r if x["predicted"] == "contained_within_scope"]
        residual = [x for x in r if x["expected"] == "residual_path"]
        summary[mode] = {
            "cases": len(r),
            "agreement": sum(x["predicted"] == x["expected"] for x in r),
            "containment_claims": len(claimed),
            "false_containment_claims": sum(x["expected"] != "contained_within_scope" for x in claimed),
            "residual_recall": f"{sum(x['predicted'] == 'residual_path' for x in residual)}/{len(residual)}",
            "decisions": sum(x["predicted"] != "unknown" for x in r),
            "deterministic": all(x["deterministic"] for x in r),
        }
    env = {"python": platform.python_version(), "platform": platform.platform(), "processor": platform.processor() or "unknown",
           "afterlock": __version__, "repeat": args.repeat}
    lab = lab_derived(bundles)
    out = {"label_source": "hand-authored expectations (not lab-validated)", "environment": env, "summary": summary, "rows": rows,
           "lab_derived": lab}
    (ROOT / "benchmarks/reports/semantic-corpus.json").write_text(json.dumps(out, indent=2) + "\n")
    lines = [
        "# Semantic corpus: baselines and ablations",
        "",
        "Generated by `python benchmarks/run.py`. **Labels are hand-authored expectations, not independent lab outcomes.**",
        f"Environment: Python {env['python']}, {env['platform']}, {args.repeat} repetitions per case and mode.",
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
    lines += ["", "Median engine latency per case is in the JSON report; it is not a performance claim.", ""]
    (ROOT / "benchmarks/reports/semantic-corpus.md").write_text("\n".join(lines))
    print("\n".join(lines[:14]))


if __name__ == "__main__":
    main()
