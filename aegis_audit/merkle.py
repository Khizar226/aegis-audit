"""RFC 6962 (Certificate Transparency) Merkle tree over SHA-256.

Red-team fixes over the original implementation:

* **Domain separation.** Leaves are hashed as ``H(0x00 || data)`` and interior
  nodes as ``H(0x01 || left || right)``, so a leaf can never be confused with
  an interior node (second-preimage attack).
* **No last-leaf duplication.** The original duplicated the last hash on odd
  levels, so ``[a, b, c]`` and ``[a, b, c, c]`` had the same root
  (CVE-2012-2459 class). RFC 6962 instead splits at the largest power of two
  smaller than ``n``.
"""

from __future__ import annotations

import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def merkle_root(leaf_hashes: list[bytes]) -> bytes:
    """Reference RFC 6962 MTH over already-hashed leaves (recursive, O(n))."""
    n = len(leaf_hashes)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaf_hashes[0]
    k = 1 << ((n - 1).bit_length() - 1)  # largest power of two < n
    return node_hash(merkle_root(leaf_hashes[:k]), merkle_root(leaf_hashes[k:]))


class MerkleAccumulator:
    """Append-only RFC 6962 tree: O(log n) memory, root after every append.

    Keeps the roots of the perfect subtrees that make up the current tree
    (like a binary counter). The tree root folds them right to left, which is
    exactly RFC 6962's split-at-largest-power-of-two definition.
    """

    def __init__(self) -> None:
        self._stack: list[tuple[int, bytes]] = []  # (subtree size, subtree root)
        self.size = 0

    def append(self, leaf: bytes) -> None:
        size, h = 1, leaf
        while self._stack and self._stack[-1][0] == size:
            left_size, left = self._stack.pop()
            h, size = node_hash(left, h), size + left_size
        self._stack.append((size, h))
        self.size += 1

    def root(self) -> bytes:
        if not self._stack:
            return EMPTY_ROOT
        acc = self._stack[-1][1]
        for _, h in reversed(self._stack[:-1]):
            acc = node_hash(h, acc)
        return acc
