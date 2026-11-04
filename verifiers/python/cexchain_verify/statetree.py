# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""The state: a compact sparse Merkle tree keyed by object id (spec
section 9).

    empty subtree            HASH("")
    subtree of one object    HASH(0x00 || state-leaf)
    any other subtree        HASH(0x01 || left || right)
    state-leaf = [kind, id, history]

An id is read as 256 bits, most significant first: bit d chooses the branch
at depth d. A proof lists the siblings from the root down to the leaf; the
verifier folds them bottom-up.
"""

from __future__ import annotations

from . import cbor

ACTOR, DELEGATION, RECORD, CONTRACT, INSTANCE = 1, 2, 3, 4, 5
KIND_NAMES = {ACTOR: "actor", DELEGATION: "delegation", RECORD: "record", CONTRACT: "contract",
              INSTANCE: "instance"}
MAX_SIBLINGS = 256


def bit(identifier: bytes, depth: int) -> int:
    return (identifier[depth // 8] >> (7 - depth % 8)) & 1


def leaf_hash(h, leaf: list) -> bytes:
    return h(b"\x00" + cbor.encode(leaf))


def root_from_proof(h, leaf: list, siblings: list[bytes]) -> bytes:
    """The root that a state proof [leaf, siblings] leads to."""
    identifier = leaf[1]
    node = leaf_hash(h, leaf)
    for depth in range(len(siblings) - 1, -1, -1):
        sibling = siblings[depth]
        if bit(identifier, depth):
            node = h(b"\x01" + sibling + node)
        else:
            node = h(b"\x01" + node + sibling)
    return node


def root_of(h, leaves: list[list], depth: int = 0) -> bytes:
    """The root over a whole set of leaves (used by tests)."""
    if not leaves:
        return h(b"")
    if len(leaves) == 1:
        return leaf_hash(h, leaves[0])
    left = [leaf for leaf in leaves if bit(leaf[1], depth) == 0]
    right = [leaf for leaf in leaves if bit(leaf[1], depth) == 1]
    return h(b"\x01" + root_of(h, left, depth + 1) + root_of(h, right, depth + 1))
