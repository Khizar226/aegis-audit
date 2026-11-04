"""SHA-256 Merkle tree."""

from __future__ import annotations

import hashlib


def hash_data(data: str) -> str:
    """Hash a string using SHA-256."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def build_merkle_tree(leaves: list[str]) -> str:
    """Build a Merkle tree over ``leaves`` and return the root hash (hex)."""
    if not leaves:
        return hash_data("")
    hashes = [hash_data(leaf) for leaf in leaves]
    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
        hashes = [hash_data(hashes[i] + hashes[i + 1]) for i in range(0, len(hashes), 2)]
    return hashes[0]
