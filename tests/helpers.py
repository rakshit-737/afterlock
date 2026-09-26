from __future__ import annotations

import copy
from typing import Any

from afterlock.model import parse_analysis_input
from afterlock.results import analyze


def with_(raw: dict[str, Any], **changes: Any) -> dict[str, Any]:
    out = copy.deepcopy(raw)
    out.update(changes)
    return out


def statuses(raw: dict[str, Any], mode: str = "full") -> tuple[str, dict[str, str]]:
    b = analyze(parse_analysis_input(raw), mode)
    return b["conclusion"]["model"], {o["id"]: o["status"] for o in b["objectives"]}
