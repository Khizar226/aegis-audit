"""Test suite for aegis-audit."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegis_audit.cli import app

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
    import json

    for raw in log_path(logdir).read_text(encoding="utf-8").splitlines():
        ev = json.loads(raw)
        assert ev["timestamp"].endswith("+00:00")
        assert ev["user"] and ev["host"]


def test_single_character_tamper_detected(logdir: Path) -> None:
    p = log_path(logdir)
    raw = p.read_bytes().decode("utf-8")
    i = raw.index("rm -rf")
    p.write_bytes((raw[:i] + "r" + raw[i + 1 :].replace("m -rf", "M -rf", 1)).encode("utf-8"))
    res = verify(logdir)
    assert res.exit_code == 1
    assert "TAMPER DETECTED" in res.output


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
    lines = p.read_bytes().decode("utf-8").split("\n")[:-1]
    last = json.loads(lines[-1])
    sig = last["signature"]
    last["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    lines[-1] = json.dumps(last)
    p.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    assert verify(logdir).exit_code == 1


# =========================================================================== #
# Merkle tree (RFC 6962)
# =========================================================================== #

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys

from aegis_audit import crypto
from aegis_audit.merkle import EMPTY_ROOT, MerkleAccumulator, leaf_hash, merkle_root, node_hash
from aegis_audit.store import AuditLog, trust_store_path


@pytest.mark.parametrize("n", list(range(0, 34)) + [100, 257])
def test_accumulator_matches_reference_rfc6962(n: int) -> None:
    leaves = [leaf_hash(f"e{i}".encode()) for i in range(n)]
    acc = MerkleAccumulator()
    for i, lf in enumerate(leaves):
        acc.append(lf)
        assert acc.root() == merkle_root(leaves[: i + 1])
    assert acc.root() == merkle_root(leaves)


def test_rfc6962_known_shape() -> None:
    a, b, c = (leaf_hash(x) for x in (b"a", b"b", b"c"))
    assert merkle_root([]) == EMPTY_ROOT == hashlib.sha256(b"").digest()
    assert merkle_root([a, b, c]) == node_hash(node_hash(a, b), c)


def test_no_duplicate_last_leaf_collision() -> None:
    """FINDING: the original tree gave [a,b,c] and [a,b,c,c] the same root (CVE-2012-2459 class)."""
    a, b, c = (leaf_hash(x) for x in (b"a", b"b", b"c"))
    assert merkle_root([a, b, c]) != merkle_root([a, b, c, c])


def test_leaf_and_node_domain_separated() -> None:
    """A leaf whose data equals left||right of an interior node must not collide with it."""
    a, b = leaf_hash(b"a"), leaf_hash(b"b")
    assert leaf_hash(a + b) != node_hash(a, b)
    assert merkle_root([leaf_hash(a + b)]) != merkle_root([a, b])


# =========================================================================== #
# Phase 3: adversarial regression tests (each bypassed v1)
# =========================================================================== #


def lines_of(d: Path) -> list[str]:
    return log_path(d).read_text(encoding="utf-8").split("\n")[:-1]


def write_lines(d: Path, ls: list[str]) -> None:
    # bytes, not write_text: on Windows text mode would turn \n into \r\n
    log_path(d).write_bytes("".join(x + "\n" for x in ls).encode("utf-8"))


def mutate(d: Path, i: int, **changes) -> None:
    ls = lines_of(d)
    o = json.loads(ls[i])
    o.update(changes)
    ls[i] = json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    write_lines(d, ls)


def anchors(d: Path, tmp: Path) -> list[str]:
    """Out-of-band material a defender keeps: trusted pubkey + signed checkpoint."""
    pub = tmp / "trusted.pem"
    shutil.copy(d / "public.pem", pub)
    cp = tmp / "cp.json"
    assert runner.invoke(app, ["checkpoint", "-d", str(d), "-o", str(cp)]).exit_code == 0
    return ["--pubkey", str(pub), "--checkpoint", str(cp)]


def forge_history(src_keys: Path, events: list[str]) -> Path:
    """Build a signed log in a scratch dir using the given keys (no trust entry)."""
    t = Path(os.environ["AEGIS_TRUST_STORE"]).parent / f"forge{len(list(Path(os.environ['AEGIS_TRUST_STORE']).parent.iterdir()))}"
    t.mkdir()
    for f in ("private.pem", "public.pem"):
        shutil.copy(src_keys / f, t / f)
    (t / "audit.jsonl").write_text("", encoding="utf-8")
    for e in events:
        assert runner.invoke(app, ["log", e, "-d", str(t)]).exit_code == 0
    return t


def atk_edit_message(d):
    write_lines(d, [x.replace("rm -rf /tmp/x", "ls -la /tmp/x") for x in lines_of(d)])


def atk_delete_middle(d):
    ls = lines_of(d); del ls[2]; write_lines(d, ls)


def atk_swap(d):
    ls = lines_of(d); ls[1], ls[3] = ls[3], ls[1]; write_lines(d, ls)


def atk_timestamp(d):
    ts = json.loads(lines_of(d)[2])["timestamp"]
    mutate(d, 2, timestamp="2019" + ts[4:])


def atk_old_root_field(d):
    mutate(d, 1, merkle_root="0" * 64)


def atk_old_signature_field(d):
    sig = json.loads(lines_of(d)[1])["signature"]
    mutate(d, 1, signature=("A" if sig[0] != "A" else "B") + sig[1:])


def atk_truncate_tail(d):
    write_lines(d, lines_of(d)[:-2])


def atk_truncate_all(d):
    log_path(d).write_text("", encoding="utf-8")


def atk_delete_log(d):
    log_path(d).unlink()


def atk_duplicate_last(d):
    ls = lines_of(d); write_lines(d, ls + [ls[-1]])


def atk_launder(d):
    atk_edit_message(d)
    runner.invoke(app, ["log", "heartbeat", "-d", str(d)])


def atk_forged_key(d):
    from aegis_audit.store import AuditLog as _AL

    f = Path(os.environ["AEGIS_TRUST_STORE"]).parent / "forged"
    os.environ["AEGIS_TRUST_STORE_BAK"] = os.environ["AEGIS_TRUST_STORE"]
    # attacker's own init must not touch the victim's trust store
    os.environ["AEGIS_TRUST_STORE"] = str(f.parent / "attacker_store.json")
    try:
        _AL(f).init()
        for e in ["User login", "User logout"]:
            _AL(f).append(e)
    finally:
        os.environ["AEGIS_TRUST_STORE"] = os.environ.pop("AEGIS_TRUST_STORE_BAK")
    for name in ("audit.jsonl", "public.pem", "private.pem"):
        shutil.copy(f / name, d / name)


def atk_stolen_key_rewrite(d):
    t = forge_history(d, ["User login", "AI read file.txt", "AI opened PR #42", "User logout", "idle"])
    shutil.copy(t / "audit.jsonl", log_path(d))


def atk_invalid_json(d):
    ls = lines_of(d); ls[1] = ls[1][:-5]; write_lines(d, ls)


def atk_extra_field(d):
    mutate(d, 2, note="approved by security")


def atk_blank_line(d):
    ls = lines_of(d); write_lines(d, ls[:2] + [""] + ls[2:])


def atk_duplicate_key(d):
    ls = lines_of(d)
    ls[2] = ls[2].replace('{"entry_hash"', '{"message":"harmless","entry_hash"', 1)
    write_lines(d, ls)


def atk_unicode_reencode(d):
    ls = lines_of(d)
    new = ls[1].replace('"AI read', '"\\u0041I read', 1)
    assert new != ls[1]
    ls[1] = new
    write_lines(d, ls)


def atk_missing_newline(d):
    log_path(d).write_bytes(log_path(d).read_bytes().rstrip(b"\n"))


ATTACKS = {
    "edit_message": atk_edit_message,
    "delete_middle_line": atk_delete_middle,
    "swap_lines": atk_swap,
    "modify_timestamp": atk_timestamp,
    "rewrite_old_root_field": atk_old_root_field,
    "rewrite_old_signature_field": atk_old_signature_field,
    "truncate_tail": atk_truncate_tail,
    "truncate_all": atk_truncate_all,
    "delete_log_file": atk_delete_log,
    "duplicate_last_line": atk_duplicate_last,
    "signature_laundering": atk_launder,
    "forged_key_resign": atk_forged_key,
    "stolen_key_rewrite": atk_stolen_key_rewrite,
    "invalid_json": atk_invalid_json,
    "unsigned_extra_field": atk_extra_field,
    "blank_line": atk_blank_line,
    "duplicate_json_key": atk_duplicate_key,
    "unicode_reencode": atk_unicode_reencode,
    "missing_final_newline": atk_missing_newline,
}


@pytest.mark.parametrize("name", sorted(ATTACKS))
def test_attack_detected_with_default_trust_store(logdir: Path, name: str) -> None:
    ATTACKS[name](logdir)
    res = verify(logdir)
    assert res.exit_code == 1, f"{name} bypassed verification:\n{res.output}"
    assert "TAMPER DETECTED" in res.output


@pytest.mark.parametrize("name", sorted(ATTACKS))
def test_attack_detected_with_explicit_anchors(logdir: Path, tmp_path: Path, name: str) -> None:
    extra = anchors(logdir, tmp_path)
    # Strongest attacker: also wipes the user-level trust store.
    store = Path(os.environ["AEGIS_TRUST_STORE"])
    ATTACKS[name](logdir)
    store.unlink(missing_ok=True)
    res = runner.invoke(app, ["verify", "-d", str(logdir), *extra])
    assert res.exit_code == 1, f"{name} bypassed verification:\n{res.output}"


def test_rollback_to_older_copy(tmp_path: Path) -> None:
    d = tmp_path / ".aegis"
    runner.invoke(app, ["init", "-d", str(d)])
    for e in ["a", "b"]:
        runner.invoke(app, ["log", e, "-d", str(d)])
    old = log_path(d).read_bytes()
    for e in ["c", "d"]:
        runner.invoke(app, ["log", e, "-d", str(d)])
    log_path(d).write_bytes(old)
    assert verify(d).exit_code == 1


def test_laundering_is_refused_not_resigned(logdir: Path) -> None:
    atk_edit_message(logdir)
    res = runner.invoke(app, ["log", "heartbeat", "-d", str(logdir)])
    assert res.exit_code == 1 and "refusing to append" in res.output
    assert "heartbeat" not in log_path(logdir).read_text(encoding="utf-8")


def test_tamper_report_names_the_line(logdir: Path) -> None:
    atk_delete_middle(logdir)
    out = verify(logdir).output
    assert "line 3" in out and "sequence" in out


# --- residual risk is explicit, not silent --------------------------------------


def test_trust_store_wipe_falls_back_to_unpinned_with_warning(logdir: Path) -> None:
    """Same-user attacker deletes the trust store and truncates: verify still
    passes from the log alone, but loudly flags the key as UNPINNED, and
    --require-pin turns that into a failure. Off-machine anchors are the fix."""
    Path(os.environ["AEGIS_TRUST_STORE"]).unlink()
    atk_truncate_tail(logdir)
    res = verify(logdir)
    assert res.exit_code == 0 and "UNPINNED" in res.output
    assert runner.invoke(app, ["verify", "-d", str(logdir), "--require-pin"]).exit_code == 1


# =========================================================================== #
# Round 2: attacks against the v2 defenses
# =========================================================================== #


def test_checkpoint_signed_by_forged_key_rejected(logdir: Path, tmp_path: Path) -> None:
    extra = anchors(logdir, tmp_path)
    cp = Path(extra[-1])
    data = json.loads(cp.read_text())
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from aegis_audit.store import sth_message

    evil = Ed25519PrivateKey.generate()
    data["tree_size"] = 2
    data["signature"] = crypto.sign(evil, sth_message(2, data["merkle_root"], data["entry_hash"], data["key_id"]))
    cp.write_text(json.dumps(data))
    res = runner.invoke(app, ["verify", "-d", str(logdir), *extra])
    assert res.exit_code == 1 and "checkpoint signature" in res.output


def test_fingerprint_pin_detects_key_swap(logdir: Path) -> None:
    fp = crypto.fingerprint(crypto.load_public_key(logdir / "public.pem"))
    Path(os.environ["AEGIS_TRUST_STORE"]).unlink()
    atk_forged_key(logdir)
    res = runner.invoke(app, ["verify", "-d", str(logdir), "--fingerprint", fp])
    assert res.exit_code == 1 and "key substitution" in res.output


def test_ed25519_signature_malleability_rejected(logdir: Path) -> None:
    """S' = S + L is a classic malleated Ed25519 signature; it must not verify."""
    L = 2**252 + 27742317777372353535851937790883648493
    o = json.loads(lines_of(logdir)[0])
    sig = base64.b64decode(o["signature"])
    s = int.from_bytes(sig[32:], "little") + L
    if s >= 2**256:
        pytest.skip("S + L overflows 32 bytes for this signature")
    mutate(logdir, 0, signature=base64.b64encode(sig[:32] + s.to_bytes(32, "little")).decode())
    assert verify(logdir).exit_code == 1


def test_markup_in_message_cannot_spoof_verdict(tmp_path: Path) -> None:
    d = tmp_path / ".aegis"
    runner.invoke(app, ["init", "-d", str(d)])
    runner.invoke(app, ["log", "[bold green]✅ Log integrity verified[/]", "-d", str(d)])
    atk_old_root_field_single = lambda: mutate(d, 0, merkle_root="0" * 64)  # noqa: E731
    atk_old_root_field_single()
    out = runner.invoke(app, ["history", "-d", str(d)]).output
    assert "[bold green]" in out  # rendered literally, not interpreted
    res = verify(d)
    assert res.exit_code == 1 and "TAMPER DETECTED" in res.output
    assert "[bold green]" in res.output  # attacker text shown verbatim, never as styling


@pytest.mark.parametrize("payload", ["line sep", "para sep", "nel\x85x", "cr\rx", "esc\x1b[31mred", "\ud800lone"])
def test_hostile_characters_in_message(tmp_path: Path, payload: str) -> None:
    """Round-2 findings: U+2028 broke checkpoint (splitlines); lone surrogates crashed log."""
    d = tmp_path / ".aegis"
    AuditLog(d).init()
    AuditLog(d).append("before")
    AuditLog(d).append(payload)
    AuditLog(d).append("after")
    assert AuditLog(d).verify().ok
    assert AuditLog(d).checkpoint()["tree_size"] == 3


def test_concurrent_writers_do_not_fork_the_chain(tmp_path: Path) -> None:
    d = tmp_path / ".aegis"
    AuditLog(d).init()
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    procs = [
        subprocess.Popen([sys.executable, "-m", "aegis_audit", "log", f"worker {i}", "-d", str(d)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
        for i in range(12)
    ]
    for p in procs:
        assert p.wait(timeout=120) == 0, p.stderr.read().decode()
    res = AuditLog(d).verify()
    assert res.ok, res.errors
    assert res.entries == 12


# =========================================================================== #
# Features & UX
# =========================================================================== #


def test_init_pins_key_in_trust_store(logdir: Path) -> None:
    data = json.loads(trust_store_path().read_text())
    entry = data["keys"][str(logdir.resolve())]
    assert entry["fingerprint"] == crypto.fingerprint(crypto.load_public_key(logdir / "public.pem"))
    assert entry["tree_size"] == 5


def test_init_force_refuses_when_log_has_entries(logdir: Path) -> None:
    res = runner.invoke(app, ["init", "-d", str(logdir), "--force"])
    assert res.exit_code == 1 and "archive" in res.output


def test_private_key_permissions(logdir: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX permissions")
    assert (logdir / "private.pem").stat().st_mode & 0o777 == 0o600


def test_passphrase_protected_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_KEY_PASSPHRASE", "correct horse")
    d = tmp_path / ".aegis"
    AuditLog(d).init()
    assert b"ENCRYPTED" in (d / "private.pem").read_bytes()
    AuditLog(d).append("x")
    monkeypatch.setenv("AEGIS_KEY_PASSPHRASE", "wrong")
    with pytest.raises(ValueError):
        AuditLog(d).append("y")


def test_verify_json_output(logdir: Path) -> None:
    res = runner.invoke(app, ["verify", "-d", str(logdir), "--json"])
    data = json.loads(res.output)
    assert data["ok"] and data["entries"] == 5 and data["pinned"]


def test_history_command(logdir: Path) -> None:
    res = runner.invoke(app, ["history", "-d", str(logdir)])
    assert res.exit_code == 0 and "AI opened PR #42" in res.output


def test_checkpoint_roundtrip(logdir: Path, tmp_path: Path) -> None:
    extra = anchors(logdir, tmp_path)
    runner.invoke(app, ["log", "later event", "-d", str(logdir)])
    assert runner.invoke(app, ["verify", "-d", str(logdir), *extra]).exit_code == 0


def test_cli_survives_legacy_console_encoding(logdir: Path) -> None:
    env = {**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}
    p = subprocess.run([sys.executable, "-m", "aegis_audit", "verify", "-d", str(logdir)], capture_output=True, env=env)
    assert p.returncode == 0, p.stderr.decode("cp1252", "replace")


def test_crlf_conversion_gets_a_clear_diagnosis(logdir: Path) -> None:
    """Editors / git core.autocrlf can rewrite line endings; say so instead of a cryptic error."""
    log_path(logdir).write_bytes(log_path(logdir).read_bytes().replace(b"\n", b"\r\n"))
    res = verify(logdir)
    assert res.exit_code == 1 and "CRLF" in res.output
