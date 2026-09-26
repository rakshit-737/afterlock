"""Seeded canary values must never reach any exported surface."""

from __future__ import annotations

import ast
import json
import shutil
from pathlib import Path

from afterlock.cli import main as cli_main
from afterlock.evidence import ReplayBundle, project
from afterlock.model import parse_analysis_input
from afterlock.results import analyze, explain

from conftest import REPLAY, ROOT

CANARY = "AFTERLOCK-CANARY-7f3a9c"
FAKE_JWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZha2UifQ.eyJzdWIiOiJmYWtlIn0.c2ln"


def test_canaries_never_reach_outputs(tmp_path: Path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    d = tmp_path / "b"
    shutil.copytree(REPLAY / "residual-token", d)
    b = ReplayBundle.load(d)
    events = [json.loads(line) for line in b.event_lines]
    leaky = [
        dict(events[0], source_sequence=900, event_id="leak-1", actor={"username": CANARY}),
        dict(events[0], source_sequence=901, event_id="leak-2", token=FAKE_JWT),
        dict(events[1], source_sequence=902, event_id="leak-3", target={"name": "release-credential", "data": {"password": CANARY}}),
        dict(events[1], source_sequence=903, event_id="leak-4", annotations={"x": FAKE_JWT}),
    ]
    ReplayBundle.write(d, case_id="residual-token", cluster_id="lab-local", inventory=b.inventory, case=b.case, events=events + leaky)

    raw, diag = project(ReplayBundle.load(d))
    bundle = analyze(parse_analysis_input(raw))
    surfaces = [json.dumps(raw), json.dumps(diag), json.dumps(bundle), explain(bundle)]

    monkeypatch.setenv("AFTERLOCK_HOME", str(tmp_path / "home"))
    assert cli_main(["replay", "import", str(d)]) == 0
    assert cli_main(["analyze", "--case", "residual-token"]) == 0
    assert cli_main(["explain", "--latest"]) == 0
    assert cli_main(["export", "--case", "residual-token", "--out", str(tmp_path / "export")]) == 0
    surfaces.append(capsys.readouterr().out)
    for f in (tmp_path / "home").rglob("*"):
        if f.is_file():
            surfaces.append(f.read_text())
    for f in (tmp_path / "export").rglob("*"):
        if f.is_file():
            surfaces.append(f.read_text())
    for s in surfaces:
        assert CANARY not in s
        assert FAKE_JWT not in s
    # every leaky record is rejected (forbidden field or credential-like value) and becomes a coverage gap
    assert len(diag["rejected"]) == 4
    assert bundle["conclusion"]["model"] == "residual_path"
    assert all(CANARY not in json.dumps(r) for r in diag["rejected"])


def test_domain_packages_do_not_import_adapters() -> None:
    forbidden = {"fastapi", "pydantic", "sqlalchemy", "psycopg", "kubernetes", "requests", "httpx", "subprocess", "pickle"}
    for path in (ROOT / "packages" / "afterlock").glob("*.py"):
        if path.name == "cli.py":
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            assert not (set(names) & forbidden), f"{path.name} imports {set(names) & forbidden}"


def test_reference_checker_is_independent_of_engine() -> None:
    src = (ROOT / "packages" / "afterlock_reference" / "__init__.py").read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mod = node.module if isinstance(node, ast.ImportFrom) else node.names[0].name
            assert not (mod or "").startswith("afterlock"), "reference checker must not import afterlock"
