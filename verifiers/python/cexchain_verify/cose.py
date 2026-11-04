# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""COSE_Sign1 in the CexChain profile (spec sections 2 and 8; RFC 9052).

Signed objects are tagged (tag 18) COSE_Sign1 messages with a protected
header holding exactly alg (1), content type (3), and kid (4), an empty
unprotected header, and an attached payload. Receipts (section 8, RFC 9942)
differ: their protected header is exactly {1: alg, 4: kid, 395: vds}, the
unprotected header is {396: {-1: [inclusion proof]}}, and the payload is
detached (it is the Merkle root at the proof's tree size).
"""

from __future__ import annotations

from dataclasses import dataclass

from . import cbor
from .errors import VerifyError

COSE_SIGN1_TAG = 18

STATEMENT_TYPE = "application/cexchain-statement+cbor"
CHECKPOINT_TYPE = "application/cexchain-checkpoint+cbor"
COSIGNATURE_TYPE = "application/cexchain-cosignature+cbor"
STATE_TYPE = "application/cexchain-state+cbor"

# RFC 9942 header parameters.
VDS_LABEL = 395
PROOFS_LABEL = 396
INCLUSION_PROOFS = -1


@dataclass
class Sign1:
    alg: int
    kid: bytes
    protected: bytes
    payload: bytes | None
    signature: bytes
    content_type: str | None = None

    def to_be_signed(self, payload: bytes | None = None) -> bytes:
        """The Sig_structure (RFC 9052 section 4.4), empty external_aad."""
        body = self.payload if payload is None else payload
        return cbor.encode(["Signature1", self.protected, b"", body])


@dataclass
class Receipt(Sign1):
    vds: int = 0
    tree_size: int = 0
    leaf_index: int = 0
    path: list | None = None


def _int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _envelope(data, what: str):
    if not isinstance(data, bytes):
        raise VerifyError(f"{what} is not a byte string")
    value = cbor.decode(data)
    if not isinstance(value, cbor.Tag) or value.tag != COSE_SIGN1_TAG:
        raise VerifyError(f"{what} is not a tagged COSE_Sign1")
    body = value.value
    if not (isinstance(body, list) and len(body) == 4):
        raise VerifyError(f"{what} is not a COSE_Sign1 array of four")
    protected, unprotected, payload, signature = body
    if not isinstance(protected, bytes) or not protected:
        raise VerifyError(f"{what} has no protected header")
    if not isinstance(signature, bytes):
        raise VerifyError(f"{what} has no signature")
    header = cbor.decode(protected)
    if not isinstance(header, dict):
        raise VerifyError(f"{what}'s protected header is not a map")
    return header, protected, unprotected, payload, signature


def parse_sign1(data: bytes, content_type: str, what: str) -> Sign1:
    """A signed statement, checkpoint, cosignature, or state commitment."""
    header, protected, unprotected, payload, signature = _envelope(data, what)
    if set(header) != {1, 3, 4}:
        raise VerifyError(f"{what}'s protected header must hold exactly alg, content type, and kid")
    alg, ct, kid = header[1], header[3], header[4]
    if not _int(alg):
        raise VerifyError(f"{what}'s alg is not an integer")
    if ct != content_type:
        raise VerifyError(f"{what} has content type {ct!r}, not {content_type!r}")
    if not (isinstance(kid, bytes) and len(kid) == 32):
        raise VerifyError(f"{what}'s kid is not 32 bytes")
    if unprotected != {}:
        raise VerifyError(f"{what}'s unprotected header is not empty")
    if not isinstance(payload, bytes):
        raise VerifyError(f"{what} has no attached payload")
    return Sign1(alg=alg, kid=kid, protected=protected, payload=payload, signature=signature,
                 content_type=ct)


def parse_receipt(data: bytes, what: str = "a receipt") -> Receipt:
    """An RFC 9942 COSE inclusion receipt in the profile of section 8."""
    header, protected, unprotected, payload, signature = _envelope(data, what)
    if set(header) != {1, 4, VDS_LABEL}:
        raise VerifyError(f"{what}'s protected header must hold exactly alg, kid, and vds")
    alg, kid, vds = header[1], header[4], header[VDS_LABEL]
    if not _int(alg) or not _int(vds):
        raise VerifyError(f"{what}'s alg or vds is not an integer")
    if not (isinstance(kid, bytes) and len(kid) == 32):
        raise VerifyError(f"{what}'s kid is not 32 bytes")
    if payload is not None:
        raise VerifyError(f"{what}'s payload is not detached")
    if not (isinstance(unprotected, dict) and set(unprotected) == {PROOFS_LABEL}):
        raise VerifyError(f"{what}'s unprotected header must hold exactly its proofs (396)")
    proofs = unprotected[PROOFS_LABEL]
    if not (isinstance(proofs, dict) and set(proofs) == {INCLUSION_PROOFS}):
        raise VerifyError(f"{what} must carry exactly an inclusion proof (-1)")
    listed = proofs[INCLUSION_PROOFS]
    if not (isinstance(listed, list) and len(listed) == 1 and isinstance(listed[0], bytes)):
        raise VerifyError(f"{what} must carry exactly one inclusion proof")
    proof = cbor.decode(listed[0])
    if not (isinstance(proof, list) and len(proof) == 3 and _int(proof[0]) and _int(proof[1])
            and proof[0] >= 0 and proof[1] >= 0 and isinstance(proof[2], list)
            and all(isinstance(p, bytes) and len(p) == 32 for p in proof[2])):
        raise VerifyError(f"{what}'s inclusion proof is not [tree size, leaf index, path]")
    if len(proof[2]) > 64:
        raise VerifyError(f"{what}'s inclusion path is too long")
    return Receipt(alg=alg, kid=kid, protected=protected, payload=None, signature=signature, vds=vds,
                   tree_size=proof[0], leaf_index=proof[1], path=proof[2])
