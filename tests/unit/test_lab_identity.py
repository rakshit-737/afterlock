"""Lab supervisor refuses non-local endpoints (phase 9 adversarial review, finding L-1)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from conftest import ROOT


def _lab():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("lab_supervisor_identity_test", ROOT / "labs" / "supervisor" / "lab.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _identity(server: str) -> dict[str, Any]:
    return {"context": "kind-afterlock-lab", "server": server, "ca_sha256": "ab" * 32, "namespace_uid": "ns-uid", "lab_instance": "i"}


@pytest.mark.parametrize(
    "server",
    [
        "https://127.0.0.1:6443@lab.example.com",  # userinfo: the host is lab.example.com
        "https://127.0.0.1:6443@10.0.0.5:6443",
        "https://127.0.0.1:6443.example.com",
        "https://127.0.0.1:x/",
        "http://127.0.0.1:6443",
    ],
)
def test_non_local_endpoint_is_refused_even_if_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, server: str) -> None:
    lab = _lab()
    state = tmp_path / "lab.json"
    state.write_text(json.dumps(_identity(server)))
    monkeypatch.setattr(lab, "STATE", state)
    monkeypatch.setattr(lab, "live_identity", lambda: _identity(server))
    with pytest.raises(lab.LabError, match="not local"):
        lab.require_recorded_lab()


def test_local_endpoint_is_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lab = _lab()
    state = tmp_path / "lab.json"
    state.write_text(json.dumps(_identity("https://127.0.0.1:41234")))
    monkeypatch.setattr(lab, "STATE", state)
    monkeypatch.setattr(lab, "live_identity", lambda: _identity("https://127.0.0.1:41234"))
    assert lab.require_recorded_lab()["server"] == "https://127.0.0.1:41234"
