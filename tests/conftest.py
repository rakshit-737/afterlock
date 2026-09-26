from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT / "packages", ROOT / "services" / "api", ROOT / "services" / "worker", ROOT / "tests"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import pytest  # noqa: E402

from afterlock.evidence import ReplayBundle, project  # noqa: E402
from afterlock.model import AnalysisInput, parse_analysis_input  # noqa: E402

REPLAY = ROOT / "datasets" / "replay"
EXPECTED: dict[str, Any] = {k: v for k, v in json.loads((ROOT / "datasets" / "fixtures" / "expected.json").read_text()).items() if not k.startswith("_")}


def raw_case(name: str) -> dict[str, Any]:
    raw, _ = project(ReplayBundle.load(REPLAY / name))
    return raw


def case(name: str) -> AnalysisInput:
    return parse_analysis_input(raw_case(name))


@pytest.fixture
def flagship_raw() -> dict[str, Any]:
    return raw_case("residual-token")
