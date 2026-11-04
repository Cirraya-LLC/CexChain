# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Proof of presence (spec section 7, and the presence-proof notes in the
CDDL).

    challenge = HASH("CexChain presence v1" || kid || P)

where kid is the statement's COSE kid and P the payload encoded without key
8. A passkey (WebAuthn) proof is an assertion over the challenge; a hardware
key's proof is its signature over the challenge itself.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from . import cbor, crypto, protocol
from .errors import VerifyError

PRESENCE_CONTEXT = b"CexChain presence v1"
FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04

_ORIGIN = re.compile(r"(https?)://([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?")


@dataclass
class PresenceResult:
    method: str  # "webauthn" (a passkey) or "hardware-key"
    user_verified: bool
    origin: str
    rp_id: str
    label: str | None


def challenge(h, statement: protocol.Statement) -> bytes:
    without_proof = {k: v for k, v in statement.payload.items() if k != 8}
    return h(PRESENCE_CONTEXT + statement.sign1.kid + cbor.encode(without_proof))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def origin_belongs(origin: str, rp_id: str) -> bool:
    """An origin belongs to the relying party: https and the id or a
    subdomain of it; http or https for "localhost"."""
    match = _ORIGIN.fullmatch(origin)
    if match is None:
        return False
    scheme, host = match.group(1), match.group(2).lower()
    rp = rp_id.lower()
    if scheme == "http" and rp != "localhost":
        return False
    return host == rp or host.endswith("." + rp)


def _check_client_data(client_data: bytes, expected_challenge: bytes, rp_id: str) -> str:
    """The limited verification algorithm of WebAuthn Level 3, with the byte
    layout the CDDL fixes. Returns the origin."""
    prefix = b'{"type":"webauthn.get","challenge":"' + b64url(expected_challenge).encode() + b'","origin":"'
    if not client_data.startswith(prefix):
        raise VerifyError("a passkey assertion is not over this statement's challenge")
    rest = client_data[len(prefix):]
    end = rest.find(b'"')
    if end < 0:
        raise VerifyError("a passkey assertion's client data is malformed")
    origin_bytes, tail = rest[:end], rest[end + 1:]
    if b"\\" in origin_bytes:
        raise VerifyError("a passkey assertion's origin is malformed")
    try:
        origin = origin_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise VerifyError("a passkey assertion's origin is malformed") from e
    if tail != b"}" and not (tail.startswith(b',"crossOrigin":false') and tail.endswith(b"}")):
        raise VerifyError("a passkey assertion is cross-origin or its client data is malformed")
    if not origin_belongs(origin, rp_id):
        raise VerifyError(f"a passkey assertion's origin {origin!r} does not belong to {rp_id!r}")
    return origin


def verify(h, statement: protocol.Statement, credentials: list) -> PresenceResult:
    """Checks the statement's proof against the signer's credentials (those
    registered when it is registered)."""
    proof = statement.presence
    credential = next((c for c in credentials if c.id == proof.credential_id), None)
    if credential is None:
        raise VerifyError("the proof of presence names a credential the person does not have")
    expected = challenge(h, statement)
    if credential.hardware:
        if proof.authenticator_data is not None:
            raise VerifyError("a hardware key's proof carries WebAuthn data")
        if not crypto.verify_signature(credential.key, expected, proof.signature):
            raise VerifyError("the hardware key's proof of presence does not verify")
        # A hardware key's proof counts as user-verified (section 7).
        return PresenceResult(method="hardware-key", user_verified=True, origin="", rp_id="",
                              label=credential.label)
    if proof.authenticator_data is None:
        raise VerifyError("a passkey's proof lacks its WebAuthn data")
    auth = proof.authenticator_data
    if auth[:32] != crypto.sha256(credential.rp_id.encode("utf-8")):
        raise VerifyError("a passkey assertion is for another relying party")
    flags = auth[32]
    if not flags & FLAG_USER_PRESENT:
        raise VerifyError("a passkey assertion lacks the user-present flag")
    origin = _check_client_data(proof.client_data, expected, credential.rp_id)
    signed = auth + crypto.sha256(proof.client_data)
    if credential.key.alg == crypto.ESP256:
        ok = (not crypto.is_weak(credential.key)
              and crypto.verify_es256_der(credential.key.key, signed, proof.signature))
    else:
        ok = crypto.verify_signature(credential.key, signed, proof.signature)
    if not ok:
        raise VerifyError("a passkey assertion's signature does not verify")
    return PresenceResult(method="webauthn", user_verified=bool(flags & FLAG_USER_VERIFIED), origin=origin,
                          rp_id=credential.rp_id, label=credential.label)
