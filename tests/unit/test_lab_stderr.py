"""LabError messages must not carry credential material from subprocess stderr (review finding 8)."""

from __future__ import annotations

import importlib.util
import sys

import pytest

from conftest import ROOT


def _lab():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("lab_supervisor_under_test", ROOT / "labs" / "supervisor" / "lab.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lab = _lab()


def test_stderr_withheld_when_command_received_stdin() -> None:
    err = b'Error from server: Secret "x" is invalid: data.token: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMyJ9.payload"'
    out = lab.scrub_stderr(err, had_stdin=True)
    assert "eyJ" not in out and "token" not in out and str(len(err)) in out


def test_credential_like_lines_redacted_and_output_truncated() -> None:
    err = b"error: context not found\nAuthorization: Bearer abc\n" + b"x" * 5 + b" " + b"A" * 40 + b"\n" + b"y " * 400
    out = lab.scrub_stderr(err, had_stdin=False)
    assert "context not found" in out
    assert "Bearer" not in out and "A" * 40 not in out
    assert len(out) <= lab.STDERR_LIMIT + len("...(truncated)")


def test_run_raises_scrubbed_laberror() -> None:
    code = "import sys; sys.stderr.write('secret: ' + 'Q'*50); sys.exit(3)"
    with pytest.raises(lab.LabError) as info:
        lab.run([sys.executable, "-c", code], stdin=b"apiVersion: v1\nkind: Secret\n")
    assert "Q" * 50 not in str(info.value) and "exit 3" in str(info.value)
    with pytest.raises(lab.LabError) as info:
        lab.run([sys.executable, "-c", code])
    assert "Q" * 50 not in str(info.value)
