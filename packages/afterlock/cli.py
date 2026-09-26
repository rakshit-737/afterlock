"""AFTERLOCK command-line interface.

The CLI is an adapter: it reads files, calls the pure engine, and writes
results. It never contacts a Kubernetes cluster.

Local state lives in $AFTERLOCK_HOME (default ./.afterlock):
  cases/<case_id>/input.json        canonical analysis input
  cases/<case_id>/diagnostics.json  ingestion diagnostics
  results/<case_id>-<n>.json        result bundles
  latest                            path of the most recent result
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .engine import MODE_FULL, MODES
from .evidence import BundleError, ReplayBundle, project
from .model import ModelError, canonical_json, parse_analysis_input
from .planner import PlannerConfig, plan
from .results import analyze, explain

CASE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def _home() -> Path:
    return Path(os.environ.get("AFTERLOCK_HOME", ".afterlock"))


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _case_dir(case_id: str) -> Path:
    if not CASE_ID.match(case_id):
        raise SystemExit(f"invalid case id {case_id!r}")
    return _home() / "cases" / case_id


def _load_input(case_id: str) -> dict[str, Any]:
    path = _case_dir(case_id) / "input.json"
    if not path.is_file():
        raise SystemExit(f"case {case_id!r} not imported (run: afterlock replay import <bundle>)")
    return dict(json.loads(path.read_text()))


def _store_result(case_id: str, bundle: dict[str, Any]) -> Path:
    results = _home() / "results"
    results.mkdir(parents=True, exist_ok=True)
    n = len([r for r in results.glob(f"{case_id}-*.json") if not r.name.endswith(".verification.json")]) + 1
    path = results / f"{case_id}-{n:04d}.json"
    _write_json(path, bundle)
    (_home() / "latest").write_text(str(path) + "\n")
    return path


def _resolve_result(arg: str | None, latest: bool) -> Path:
    if latest or arg is None:
        ptr = _home() / "latest"
        if not ptr.is_file():
            raise SystemExit("no results yet (run: afterlock analyze --case <id>)")
        return Path(ptr.read_text().strip())
    return Path(arg)


# --------------------------------------------------------------------------


def cmd_version(_: argparse.Namespace) -> int:
    print(f"afterlock {__version__}")
    return 0


def cmd_capabilities(_: argparse.Namespace) -> int:
    caps = {
        "version": __version__,
        "semantic_profiles": ["k8s-1.31-core-v1"],
        "profile_conformance": "unverified (live kind suite not yet executed)",
        "analysis_modes": list(MODES),
        "result_dimensions": {
            "model": ["residual_path", "contained_within_scope", "unknown", "invalid_input"],
            "validation": ["not_executed", "lab_confirmed", "lab_contradicted", "validation_inconclusive"],
        },
        "execution_profiles": {
            "portable": "implemented",
            "application_integration": "partial (in-memory API; PostgreSQL persistence not implemented)",
            "live_lab": "scripts prepared; not executed in this environment",
        },
        "production_mutation": False,
    }
    print(json.dumps(caps, indent=2))
    return 0


def cmd_replay_import(ns: argparse.Namespace) -> int:
    try:
        bundle = ReplayBundle.load(ns.bundle)
        analysis_input, diag = project(bundle)
    except (BundleError, ModelError) as exc:
        print(f"invalid_input: {exc}", file=sys.stderr)
        return 2
    case_id = analysis_input["case_id"]
    d = _case_dir(case_id)
    _write_json(d / "input.json", analysis_input)
    _write_json(d / "diagnostics.json", diag)
    print(f"imported case {case_id}: {diag['accepted']} events accepted, {diag['duplicates']} duplicates, "
          f"{len(diag['rejected'])} rejected, {len(diag['conflicts'])} conflicts, "
          f"{len(analysis_input['coverage_gaps'])} coverage gaps")
    return 0


def _analysis_input(ns: argparse.Namespace) -> dict[str, Any]:
    if getattr(ns, "bundle", None):
        try:
            raw, _ = project(ReplayBundle.load(ns.bundle))
        except (BundleError, ModelError) as exc:
            raise SystemExit(f"invalid_input: {exc}") from exc
        return raw
    if not ns.case:
        raise SystemExit("specify --case or --bundle")
    return _load_input(ns.case)


def cmd_analyze(ns: argparse.Namespace) -> int:
    raw = _analysis_input(ns)
    if ns.remediation:
        raw = dict(raw)
        raw["remediation"] = json.loads(Path(ns.remediation).read_text())
    try:
        inp = parse_analysis_input(raw)
    except ModelError as exc:
        print(json.dumps({"conclusion": {"model": "invalid_input", "validation": "not_executed"}, "error": str(exc)}))
        return 2
    bundle = analyze(inp, ns.mode)
    if ns.bundle:
        print(json.dumps(bundle, indent=2, sort_keys=True))
        return 0
    path = _store_result(inp.case_id, bundle)
    obj = ", ".join(f"{o['id']}={o['status']}" for o in bundle["objectives"])
    print(f"{inp.case_id}: {bundle['conclusion']['model']} ({obj})")
    print(f"result: {path}")
    return 0


def cmd_explain(ns: argparse.Namespace) -> int:
    path = _resolve_result(ns.result, ns.latest)
    print(explain(json.loads(path.read_text())))
    return 0


def cmd_verify(ns: argparse.Namespace) -> int:
    """Independent check: witness replay plus reference exploration agreement."""
    import afterlock_reference as ref

    path = _resolve_result(ns.result, ns.latest)
    bundle = json.loads(path.read_text())
    raw = _load_input(bundle["case_id"])
    raw = dict(raw)
    raw["remediation"] = bundle["remediation"]
    if parse_analysis_input(raw).raw_digest != bundle["input_digest"]:
        print("input digest mismatch: stored case differs from the analyzed input", file=sys.stderr)
        return 2
    witnesses = ref.verify_witnesses(raw, bundle)
    exploration = ref.explore(raw, ref.ReferenceLimits(max_states=ns.max_states))
    disagreements = []
    for view in ("evidence_supported", "conservative_possible"):
        v = exploration["views"][view]
        ref_set = set(v["reachable_objectives"])
        eng_set = {
            o["id"] for o in bundle["objectives"]
            if (o["status"] == "violated") or (view == "conservative_possible" and o["status"] == "possibly_violated")
        }
        if not v["complete"]:
            continue
        if ref_set != eng_set:
            disagreements.append({"view": view, "engine": sorted(eng_set), "reference": sorted(ref_set)})
    record = {
        "result": str(path),
        "result_digest": bundle["result_digest"],
        "witnesses": witnesses,
        "reference_exploration": exploration,
        "disagreements": disagreements,
        "verdict": (
            "checker_disagrees" if disagreements or not all(w["valid"] for w in witnesses.values())
            else "checker_agrees" if all(exploration["views"][v]["complete"] for v in exploration["views"])
            else "checker_incomplete"
        ),
        "note": "Agreement with the reference checker is model-level verification, not lab validation.",
    }
    out = path.with_suffix(".verification.json")
    _write_json(out, record)
    print(f"verification: {record['verdict']}  witnesses valid: "
          f"{sum(w['valid'] for w in witnesses.values())}/{len(witnesses)}  record: {out}")
    return 0 if record["verdict"] != "checker_disagrees" else 1


def cmd_plan(ns: argparse.Namespace) -> int:
    raw = _analysis_input(ns)
    inp = parse_analysis_input(raw)
    result = plan(inp, PlannerConfig(max_length=ns.max_length, max_evaluations=ns.max_evaluations))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_export(ns: argparse.Namespace) -> int:
    raw = _load_input(ns.case)
    out = Path(ns.out)
    out.mkdir(parents=True, exist_ok=True)
    files = {"input.json": raw}
    results = sorted((_home() / "results").glob(f"{ns.case}-*.json"))
    results = [r for r in results if not r.name.endswith(".verification.json")]
    for r in results:
        files[f"results/{r.name}"] = json.loads(r.read_text())
    manifest = {"schema": "afterlock.export/1", "case_id": ns.case, "files": {}}
    for name, value in files.items():
        data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        (out / name).parent.mkdir(parents=True, exist_ok=True)
        (out / name).write_bytes(data)
        manifest["files"][name] = "sha256:" + hashlib.sha256(data).hexdigest()
    _write_json(out / "manifest.json", manifest)
    print(f"exported {len(files)} files to {out}")
    return 0


def cmd_canonical(ns: argparse.Namespace) -> int:
    raw = _analysis_input(ns)
    print(canonical_json(raw))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="afterlock", description="History-aware containment verification (research-grade).")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("version").set_defaults(fn=cmd_version)
    sub.add_parser("capabilities").set_defaults(fn=cmd_capabilities)

    rp = sub.add_parser("replay").add_subparsers(dest="replay_cmd", required=True)
    imp = rp.add_parser("import")
    imp.add_argument("bundle")
    imp.set_defaults(fn=cmd_replay_import)

    a = sub.add_parser("analyze")
    a.add_argument("--case")
    a.add_argument("--bundle", help="analyze a replay bundle directly and print the result bundle")
    a.add_argument("--remediation", help="JSON file with a remediation action list overriding the case")
    a.add_argument("--mode", choices=MODES, default=MODE_FULL)
    a.set_defaults(fn=cmd_analyze)

    for name, fn in (("explain", cmd_explain), ("verify", cmd_verify)):
        e = sub.add_parser(name)
        e.add_argument("result", nargs="?")
        e.add_argument("--latest", action="store_true")
        if name == "verify":
            e.add_argument("--max-states", type=int, default=200_000)
        e.set_defaults(fn=fn)

    pl = sub.add_parser("plan")
    pl.add_argument("--case")
    pl.add_argument("--bundle")
    pl.add_argument("--max-length", type=int, default=4)
    pl.add_argument("--max-evaluations", type=int, default=5_000)
    pl.set_defaults(fn=cmd_plan)

    ex = sub.add_parser("export")
    ex.add_argument("--case", required=True)
    ex.add_argument("--out", required=True)
    ex.set_defaults(fn=cmd_export)

    c = sub.add_parser("canonical-input")
    c.add_argument("--case")
    c.add_argument("--bundle")
    c.set_defaults(fn=cmd_canonical)
    return p


def main(argv: list[str] | None = None) -> int:
    ns = build_parser().parse_args(argv)
    return int(ns.fn(ns))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
