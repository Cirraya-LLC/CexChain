# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""RFC 9162 Merkle trees under the ledger's hash (spec sections 6 and 8).

The log, and each record's field commitments, are RFC 9162 trees: a leaf is
HASH(0x00 || data) and a node HASH(0x01 || left || right). The verification
algorithms below are those of RFC 9162 sections 2.1.3.2 (inclusion) and
2.1.4.2 (consistency).
"""

from __future__ import annotations


def leaf_hash(h, data: bytes) -> bytes:
    return h(b"\x00" + data)


def node_hash(h, left: bytes, right: bytes) -> bytes:
    return h(b"\x01" + left + right)


def tree_hash(h, leaves: list[bytes]) -> bytes:
    """MTH(D[n]) (RFC 9162 section 2.1.1)."""
    n = len(leaves)
    if n == 0:
        return h(b"")
    if n == 1:
        return leaf_hash(h, leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(h, tree_hash(h, leaves[:k]), tree_hash(h, leaves[k:]))


def root_from_inclusion(h, index: int, size: int, leaf: bytes, path: list[bytes]) -> bytes | None:
    """The root an inclusion path leads to, or None if the path cannot be
    one for this index and size (RFC 9162 section 2.1.3.2)."""
    if index >= size or size < 1:
        return None
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = node_hash(h, p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(h, r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        return None
    return r


def verify_inclusion(h, index: int, size: int, leaf: bytes, path: list[bytes], root: bytes) -> bool:
    return root_from_inclusion(h, index, size, leaf, path) == root


def verify_consistency(h, first: int, second: int, first_root: bytes, second_root: bytes,
                       proof: list[bytes]) -> bool:
    """RFC 9162 section 2.1.4.2. Equal sizes need equal roots and an empty
    proof."""
    if first < 1 or first > second:
        return False
    if first == second:
        return not proof and first_root == second_root
    if not proof:
        return False
    path = list(proof)
    if first & (first - 1) == 0:  # an exact power of two
        path.insert(0, first_root)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(h, c, fr)
            sr = node_hash(h, c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(h, sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0
