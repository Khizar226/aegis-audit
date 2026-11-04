"""Ed25519 key management and signing."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PRIVATE_KEY_FILE = "private.pem"
PUBLIC_KEY_FILE = "public.pem"
PASSPHRASE_ENV = "AEGIS_KEY_PASSPHRASE"


def _passphrase() -> bytes | None:
    value = os.environ.get(PASSPHRASE_ENV)
    return value.encode() if value else None


def generate_keypair(directory: Path) -> tuple[Path, Path]:
    """Create ``private.pem`` (mode 0600, encrypted if AEGIS_KEY_PASSPHRASE is set) and ``public.pem``."""
    directory.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    pw = _passphrase()
    enc = serialization.BestAvailableEncryption(pw) if pw else serialization.NoEncryption()
    priv_path, pub_path = directory / PRIVATE_KEY_FILE, directory / PUBLIC_KEY_FILE
    priv_bytes = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    if priv_path.exists():
        priv_path.unlink()
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(priv_bytes)
    pub_path.write_bytes(public_pem(priv.public_key()))
    return priv_path, pub_path


def public_pem(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=_passphrase())
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path} is not an Ed25519 public key")
    return key


def fingerprint(pub: Ed25519PublicKey) -> str:
    """SHA-256 of the raw 32-byte public key, hex. Used as ``key_id``."""
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def sign(priv: Ed25519PrivateKey, message: bytes) -> str:
    return base64.b64encode(priv.sign(message)).decode("ascii")


def verify_signature(pub: Ed25519PublicKey, message: bytes, signature_b64: str) -> bool:
    try:
        sig = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError):
        return False
    try:
        pub.verify(sig, message)
        return True
    except InvalidSignature:
        return False
