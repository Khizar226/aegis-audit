"""Test suite for aegis-audit."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegis_audit.cli import app
from aegis_audit.store import AuditLog

runner = CliRunner()


@pytest.fixture
def logdir(tmp_path: Path) -> Path:
    d = tmp_path / ".aegis"
    assert runner.invoke(app, ["init", "-d", str(d)]).exit_code == 0
    for msg in ["User login", "AI read file.txt", "AI executed rm -rf /tmp/x", "AI opened PR #42", "User logout"]:
        assert runner.invoke(app, ["log", msg, "-d", str(d)]).exit_code == 0
    return d


def log_path(d: Path) -> Path:
    return d / "audit.jsonl"


def verify(d: Path):
    return runner.invoke(app, ["verify", "-d", str(d)])


def test_init_creates_keys(tmp_path: Path) -> None:
    d = tmp_path / "k"
    res = runner.invoke(app, ["init", "-d", str(d)])
    assert res.exit_code == 0
    assert (d / "private.pem").exists() and (d / "public.pem").exists()


def test_init_refuses_to_overwrite(logdir: Path) -> None:
    assert runner.invoke(app, ["init", "-d", str(logdir)]).exit_code == 1


def test_valid_log_verifies(logdir: Path) -> None:
    res = verify(logdir)
    assert res.exit_code == 0, res.output
    assert "Log integrity verified" in res.output


def test_entries_have_timestamp_and_user(logdir: Path) -> None:
    for line in AuditLog(logdir).read_lines():
        ev = line["event"]
        assert ev["timestamp"].endswith("+00:00")
        assert ev["user"]


def test_single_character_tamper_detected(logdir: Path) -> None:
    p = log_path(logdir)
    raw = p.read_text(encoding="utf-8")
    i = raw.index("rm -rf")
    p.write_text(raw[:i] + "r" + raw[i + 1 :].replace("m -rf", "M -rf", 1), encoding="utf-8")
    res = verify(logdir)
    assert res.exit_code == 1
    assert "TAMPER DETECTED" in res.output


@pytest.mark.xfail(
    strict=True,
    reason="FINDING-1: v1 only authenticates the LAST line's root/signature; earlier lines' "
    "merkle_root/signature fields are never checked. Fixed in Phase 3.",
)
def test_flip_one_char_in_middle_of_file(logdir: Path) -> None:
    p = log_path(logdir)
    data = bytearray(p.read_bytes())
    mid = len(data) // 2
    # flip a character inside a JSON string value near the middle
    while chr(data[mid]) not in "abcdefghijklmnopqrstuvwxyz0123456789":
        mid += 1
    data[mid] = ord("x") if data[mid] != ord("x") else ord("y")
    p.write_bytes(bytes(data))
    assert verify(logdir).exit_code == 1


def test_signature_tamper_detected(logdir: Path) -> None:
    import json

    p = log_path(logdir)
    lines = p.read_text(encoding="utf-8").splitlines()
    last = json.loads(lines[-1])
    sig = last["signature"]
    last["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    lines[-1] = json.dumps(last)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify(logdir).exit_code == 1
