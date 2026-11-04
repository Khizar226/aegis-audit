"""Audit log storage: append, verify and checkpoint the JSONL log.

Each line is one event plus a *signed tree head* (STH) covering every event
up to and including it:

    payload  = {v, seq, timestamp, user, host, message, prev_hash}
    entry    = H(0x00 || canonical(payload))           (RFC 6962 leaf hash)
    root_n   = RFC 6962 Merkle root over entry_0..entry_n
    STH_n    = Ed25519("aegis-audit:v2:sth:" || canonical({tree_size, merkle_root, entry_hash, key_id}))

``prev_hash`` links each entry to the previous one, so the log is both a
hash chain and a Merkle tree, and every line is independently authenticated.
"""

from __future__ import annotations

import contextlib
import getpass
import json
import os
import socket
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import crypto
from .merkle import MerkleAccumulator, leaf_hash

FORMAT_VERSION = 2
DEFAULT_DIR = Path(".aegis")
LOG_FILE = "audit.jsonl"
LOCK_FILE = ".lock"
GENESIS_HASH = "0" * 64
STH_CONTEXT = b"aegis-audit:v2:sth:"

PAYLOAD_KEYS = ("v", "seq", "timestamp", "user", "host", "message", "prev_hash")
LINE_KEYS = frozenset(PAYLOAD_KEYS + ("entry_hash", "tree_size", "merkle_root", "key_id", "signature"))
CHECKPOINT_KEYS = frozenset({"v", "tree_size", "merkle_root", "entry_hash", "key_id", "signature", "timestamp"})
MAX_ERRORS = 20


class TamperError(RuntimeError):
    """Raised when an operation would build on a log that fails verification."""


def canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sth_message(tree_size: int, merkle_root: str, entry_hash: str, key_id: str) -> bytes:
    body = {"tree_size": tree_size, "merkle_root": merkle_root, "entry_hash": entry_hash, "key_id": key_id}
    return STH_CONTEXT + canonical(body).encode("utf-8")


def trust_store_path() -> Path:
    """User-level trust store, deliberately OUTSIDE the audit directory."""
    override = os.environ.get("AEGIS_TRUST_STORE")
    if override:
        return Path(override)
    if os.name == "nt":  # pragma: no cover
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "aegis-audit" / "trusted_keys.json"


def _load_trust_store() -> dict:
    p = trust_store_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) and isinstance(data.get("keys"), dict) else {"version": 1, "keys": {}}
    except (OSError, json.JSONDecodeError):
        return {"version": 1, "keys": {}}


def trusted_fingerprint_for(directory: Path) -> str | None:
    return trust_entry_for(directory).get("fingerprint")


def trust_entry_for(directory: Path) -> dict:
    entry = _load_trust_store()["keys"].get(str(directory.resolve()))
    return entry if isinstance(entry, dict) else {}


def pin_in_trust_store(directory: Path, fingerprint: str) -> Path:
    return _write_trust_entry(
        directory,
        {"fingerprint": fingerprint, "pinned_at": datetime.now(timezone.utc).isoformat(timespec="seconds")},
    )


def record_high_water_mark(directory: Path, tree_size: int, merkle_root: str) -> None:
    """Remember the newest signed tree head outside the audit directory."""
    entry = trust_entry_for(directory)
    if entry:
        entry.update({"tree_size": tree_size, "merkle_root": merkle_root})
        _write_trust_entry(directory, entry)


def _write_trust_entry(directory: Path, entry: dict) -> Path:
    p = trust_store_path()
    data = _load_trust_store()
    data["keys"][str(directory.resolve())] = entry
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, p)
    return p


def _escape_surrogates(s: str) -> str:
    """Lone surrogates can't be UTF-8 encoded. Bytes smuggled in via
    surrogateescape (U+DC80-DCFF) become \\xNN; any other surrogate \\uXXXX."""
    if not any(0xD800 <= ord(c) <= 0xDFFF for c in s):
        return s
    out = []
    for c in s:
        o = ord(c)
        if 0xDC80 <= o <= 0xDCFF:
            out.append(f"\\x{o - 0xDC00:02x}")
        elif 0xD800 <= o <= 0xDFFF:
            out.append(f"\\u{o:04x}")
        else:
            out.append(c)
    return "".join(out)


def current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - platform dependent
        return "unknown"


@contextlib.contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    """Exclusive inter-process lock so concurrent agents can't fork the chain."""
    fh = open(path, "a+b")
    try:
        if os.name == "nt":  # pragma: no cover - exercised on Windows CI
            import msvcrt

            fh.seek(0)
            while True:
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    continue
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        if os.name == "nt":  # pragma: no cover
            import msvcrt

            fh.seek(0)
            with contextlib.suppress(OSError):
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        fh.close()


@dataclass
class HistoryRow:
    seq: int
    timestamp: str
    user: str
    message: str
    merkle_root: str


@dataclass
class VerifyResult:
    ok: bool
    entries: int = 0
    root: str | None = None
    key_id: str | None = None
    pinned: bool = False
    pin_source: str = ""
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    history: list[HistoryRow] = field(default_factory=list)


class AuditLog:
    def __init__(self, directory: Path = DEFAULT_DIR) -> None:
        self.dir = directory
        self.path = directory / LOG_FILE

    # ------------------------------------------------------------------ init
    def init(self, force: bool = False) -> tuple[Path, Path]:
        if (self.dir / crypto.PRIVATE_KEY_FILE).exists() and not force:
            raise FileExistsError(f"keys already exist in {self.dir}")
        if force and self.path.exists() and self.path.stat().st_size > 0:
            raise FileExistsError(
                f"{self.path} already contains signed entries; archive it before generating a new key"
            )
        existing = trusted_fingerprint_for(self.dir)
        if existing and not force:
            raise FileExistsError(
                f"trust store already pins a key for {self.dir.resolve()}; use --force to replace it"
            )
        paths = crypto.generate_keypair(self.dir)
        self.path.touch(exist_ok=True)
        pin_in_trust_store(self.dir, crypto.fingerprint(crypto.load_public_key(paths[1])))
        return paths

    # ---------------------------------------------------------------- append
    def append(self, message: str) -> dict:
        # Red-team fix: undecodable bytes from argv/tool output arrive as lone
        # surrogates and crashed the encoder (denial of logging). Keep them,
        # visibly, as \xNN escapes.
        message = _escape_surrogates(message)
        priv = crypto.load_private_key(self.dir / crypto.PRIVATE_KEY_FILE)
        pub = priv.public_key()
        key_id = crypto.fingerprint(pub)
        with _file_lock(self.dir / LOCK_FILE):
            # Red-team fix ("signature laundering"): never sign on top of a log
            # that does not verify, or an attacker's edit gets re-signed.
            state, acc, prev_hash = self._verify_lines(pub, collect_history=True)
            entry = trust_entry_for(self.dir)
            if entry.get("fingerprint") == key_id and isinstance(entry.get("tree_size"), int):
                state.errors.extend(
                    _check_anchor(state, entry["tree_size"], entry.get("merkle_root"), "trust-store high-water mark")
                )
                state.ok = not state.errors
            if not state.ok:
                raise TamperError("refusing to append: " + "; ".join(state.errors[:3]))
            seq = state.entries
            payload = {
                "v": FORMAT_VERSION,
                "seq": seq,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                "user": current_user(),
                "host": socket.gethostname(),
                "message": message,
                "prev_hash": prev_hash,
            }
            entry = leaf_hash(canonical(payload).encode("utf-8"))
            acc.append(entry)
            line = {
                **payload,
                "entry_hash": entry.hex(),
                "tree_size": seq + 1,
                "merkle_root": acc.root().hex(),
                "key_id": key_id,
            }
            line["signature"] = crypto.sign(
                priv, sth_message(line["tree_size"], line["merkle_root"], line["entry_hash"], key_id)
            )
            with self.path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(canonical(line) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            if trusted_fingerprint_for(self.dir) == key_id:
                record_high_water_mark(self.dir, line["tree_size"], line["merkle_root"])
        return line

    # ---------------------------------------------------------------- verify
    def resolve_trust(
        self, pubkey: Path | None = None, fingerprint_pin: str | None = None
    ) -> tuple[Ed25519PublicKey, str, list[str]]:
        """Return ``(public_key, pin_source, errors)``; ``pin_source`` is "" if unpinned.

        Red-team fix ("forged key"): the public key next to the log is only as
        trustworthy as the directory. Trust comes, in order, from ``--pubkey``
        (a copy kept elsewhere), ``--fingerprint`` / AEGIS_TRUSTED_FINGERPRINT,
        or the user-level trust store written by ``init``.
        """
        errors: list[str] = []
        pin = (fingerprint_pin or os.environ.get("AEGIS_TRUSTED_FINGERPRINT") or "").strip().lower()
        source = "--fingerprint" if pin else ""
        if pubkey is not None:
            pub = crypto.load_public_key(pubkey)
            source = source or "--pubkey"
        else:
            pub = crypto.load_public_key(self.dir / crypto.PUBLIC_KEY_FILE)
            if not pin:
                stored = trusted_fingerprint_for(self.dir)
                if stored:
                    pin, source = stored, "trust store"
        if pin and crypto.fingerprint(pub) != pin:
            errors.append(
                f"public key fingerprint {crypto.fingerprint(pub)[:16]}… does not match the pinned "
                f"fingerprint {pin[:16]}… from {source} (key substitution)"
            )
        return pub, source, errors

    def verify(
        self,
        pubkey: Path | None = None,
        fingerprint_pin: str | None = None,
        checkpoint: Path | None = None,
    ) -> VerifyResult:
        try:
            pub, pin_source, trust_errors = self.resolve_trust(pubkey, fingerprint_pin)
        except (OSError, ValueError) as exc:
            return VerifyResult(False, errors=[f"cannot load public key: {exc}"])

        res, _, _ = self._verify_lines(pub, collect_history=True)
        res.pinned = bool(pin_source)
        res.pin_source = pin_source
        res.errors[:0] = trust_errors
        if not pin_source:
            res.warnings.append(
                "public key was read from the log directory and is not pinned; an attacker with write "
                "access could substitute it. Pin it with --pubkey or --fingerprint."
            )
        entry = trust_entry_for(self.dir) if pubkey is None else {}
        if res.ok and entry.get("fingerprint") == res.key_id and isinstance(entry.get("tree_size"), int):
            res.errors.extend(_check_anchor(res, entry["tree_size"], entry.get("merkle_root"), "trust-store high-water mark"))
        if checkpoint is not None and not res.errors:
            res.errors.extend(self._check_checkpoint(checkpoint, pub, res))
        elif res.ok and res.entries == 0:
            res.warnings.append("log is empty; truncation can only be detected with --checkpoint")
        res.ok = not res.errors
        return res

    def _verify_lines(
        self, pub: Ed25519PublicKey, collect_history: bool
    ) -> tuple[VerifyResult, MerkleAccumulator, str]:
        """Verify every line; also return the Merkle state needed to append."""
        res = VerifyResult(ok=False)
        res.key_id = key_id = crypto.fingerprint(pub)
        acc, prev_hash = MerkleAccumulator(), GENESIS_HASH

        def fail(msg: str) -> tuple[VerifyResult, MerkleAccumulator, str]:
            res.errors.append(msg)
            return res, acc, prev_hash

        if not self.path.exists():
            return fail(f"audit log {self.path} is missing (deleted?)")
        try:
            text = self.path.read_bytes().decode("utf-8")
        except UnicodeDecodeError as exc:
            return fail(f"log is not valid UTF-8: {exc}")
        if text and not text.endswith("\n"):
            return fail("last line is incomplete (truncated write or tampering)")

        last_ts: datetime | None = None
        for i, raw in enumerate(text.split("\n")[:-1] if text else []):
            n = i + 1
            if len(res.errors) >= MAX_ERRORS:
                res.errors.append("too many errors; stopping")
                break
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                return fail(f"line {n}: not valid JSON ({exc.msg})")
            # Red-team fix: exact canonical form. Rejects extra/unsigned fields,
            # duplicate keys (parser ambiguity), blank lines and re-formatting.
            if not isinstance(obj, dict) or set(obj) != LINE_KEYS:
                return fail(f"line {n}: unexpected or missing fields")
            if raw.endswith("\r") and canonical(obj) == raw[:-1]:
                return fail(
                    f"line {n}: CRLF line ending; the file was rewritten (editor or git core.autocrlf). "
                    "Restore the original bytes"
                )
            if canonical(obj) != raw:
                return fail(f"line {n}: not in canonical form (duplicate keys, extra whitespace or re-encoding)")
            if obj["v"] != FORMAT_VERSION or type(obj["seq"]) is not int or type(obj["tree_size"]) is not int:
                return fail(f"line {n}: bad version or counters")
            if not all(isinstance(obj[k], str) for k in ("timestamp", "user", "host", "message", "prev_hash")):
                return fail(f"line {n}: bad field types")

            if obj["seq"] != i:
                res.errors.append(f"line {n}: sequence number {obj['seq']} != {i} (line deleted, inserted or reordered)")
            if obj["prev_hash"] != prev_hash:
                res.errors.append(f"line {n}: hash chain broken (previous entry altered, removed or reordered)")
            payload = {k: obj[k] for k in PAYLOAD_KEYS}
            entry = leaf_hash(canonical(payload).encode("utf-8"))
            if entry.hex() != obj["entry_hash"]:
                res.errors.append(f"line {n}: event content does not match its hash (modified)")
            acc.append(entry)
            root = acc.root().hex()
            if obj["tree_size"] != i + 1 or obj["merkle_root"] != root:
                res.errors.append(f"line {n}: signed tree head does not match recomputed Merkle root")
            if obj["key_id"] != key_id:
                res.errors.append(f"line {n}: signed by a different key ({obj['key_id'][:16]}…)")
            elif not crypto.verify_signature(
                pub, sth_message(obj["tree_size"], obj["merkle_root"], obj["entry_hash"], obj["key_id"]), obj["signature"]
            ):
                res.errors.append(f"line {n}: invalid Ed25519 signature")
            try:
                ts = datetime.fromisoformat(obj["timestamp"])
                if ts.utcoffset() is None or ts.utcoffset().total_seconds() != 0:
                    res.errors.append(f"line {n}: timestamp is not UTC")
                elif last_ts is not None and ts < last_ts:
                    res.warnings.append(f"line {n}: timestamp earlier than previous entry (clock skew?)")
                last_ts = ts
            except ValueError:
                res.errors.append(f"line {n}: unparseable timestamp")

            prev_hash = obj["entry_hash"]
            res.entries = n
            if collect_history:
                res.history.append(HistoryRow(i, obj["timestamp"], obj["user"], obj["message"], obj["merkle_root"]))

        res.root = acc.root().hex()
        res.ok = not res.errors
        return res, acc, prev_hash

    # ------------------------------------------------------------ checkpoint
    def checkpoint(self) -> dict:
        """Latest signed tree head, for storage OUTSIDE the attacker's reach."""
        res = self.verify()
        if not res.ok:
            raise TamperError("refusing to checkpoint a log that fails verification: " + "; ".join(res.errors[:3]))
        if res.entries == 0:
            raise ValueError("log is empty")
        # split on "\n" only: str.splitlines() also splits on U+2028/U+0085/\r inside messages
        last = json.loads(self.path.read_bytes().decode("utf-8").split("\n")[-2])
        return {
            "v": FORMAT_VERSION,
            "tree_size": last["tree_size"],
            "merkle_root": last["merkle_root"],
            "entry_hash": last["entry_hash"],
            "key_id": last["key_id"],
            "signature": last["signature"],
            "timestamp": last["timestamp"],
        }

    def _check_checkpoint(self, path: Path, pub: Ed25519PublicKey, res: VerifyResult) -> list[str]:
        """Red-team fix: truncation / rollback / full rewrite with a stolen key
        are undetectable from the log alone; a checkpoint kept elsewhere is not."""
        try:
            cp = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return [f"cannot read checkpoint: {exc}"]
        if not isinstance(cp, dict) or set(cp) != CHECKPOINT_KEYS:
            return ["checkpoint has unexpected fields"]
        if cp["key_id"] != crypto.fingerprint(pub) or not crypto.verify_signature(
            pub, sth_message(cp["tree_size"], cp["merkle_root"], cp["entry_hash"], cp["key_id"]), cp["signature"]
        ):
            return ["checkpoint signature is not valid for the trusted key"]
        return _check_anchor(res, cp["tree_size"], cp["merkle_root"], "checkpoint")


def _check_anchor(res: VerifyResult, size: int, root: str | None, label: str) -> list[str]:
    """The log must contain the anchored tree head as a prefix."""
    if res.entries < size:
        return [f"log has {res.entries} entries but the {label} attests {size} (truncation or rollback)"]
    row = res.history[size - 1] if size > 0 and len(res.history) >= size else None
    if size > 0 and (row is None or row.merkle_root != root):
        return [f"Merkle root at entry {size} differs from the {label} (history rewritten)"]
    return []
