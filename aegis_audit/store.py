"""Audit log storage: append, read and verify the JSONL log."""

from __future__ import annotations

import getpass
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import crypto
from .merkle import build_merkle_tree

DEFAULT_DIR = Path(".aegis")
LOG_FILE = "audit.jsonl"


def canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - platform dependent
        return "unknown"


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    root: str | None
    errors: list[str] = field(default_factory=list)
    history: list[tuple[int, str, str]] = field(default_factory=list)  # (index, timestamp, root)


class AuditLog:
    def __init__(self, directory: Path = DEFAULT_DIR) -> None:
        self.dir = directory
        self.path = directory / LOG_FILE

    def read_lines(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def append(self, message: str) -> dict:
        priv = crypto.load_private_key(self.dir / crypto.PRIVATE_KEY_FILE)
        entries = self.read_lines()
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": current_user(),
            "message": message,
        }
        leaves = [canonical(e["event"]) for e in entries] + [canonical(event)]
        root = build_merkle_tree(leaves)
        line = {"event": event, "merkle_root": root, "signature": crypto.sign(priv, root.encode())}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return line

    def verify(self) -> VerifyResult:
        pub = crypto.load_public_key(self.dir / crypto.PUBLIC_KEY_FILE)
        try:
            entries = self.read_lines()
        except json.JSONDecodeError as exc:
            return VerifyResult(False, 0, None, [f"malformed JSON: {exc}"])
        if not entries:
            return VerifyResult(True, 0, None)
        history = [(i, e["event"]["timestamp"], e["merkle_root"]) for i, e in enumerate(entries)]
        root = build_merkle_tree([canonical(e["event"]) for e in entries])
        last = entries[-1]
        errors = []
        if root != last["merkle_root"]:
            errors.append("recomputed Merkle root does not match the signed root")
        if not crypto.verify_signature(pub, last["merkle_root"].encode(), last["signature"]):
            errors.append("signature on the latest root is invalid")
        return VerifyResult(not errors, len(entries), root, errors, history)
