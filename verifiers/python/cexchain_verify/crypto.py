# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Hashes, public keys, and signature verification (spec section 3).

Nothing cryptographic is implemented here: Ed25519, ECDSA P-256, and ML-DSA
come from the `cryptography` package, SHA-256 and SM3 from `hashlib` (SM3
through OpenSSL), and SM2 from the `openssl` command-line tool, which the
`cryptography` package lacks. This module only checks encodings and sizes and
calls those implementations.
"""

from __future__ import annotations

import functools
import hashlib
import os
import subprocess
import tempfile
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from . import cbor
from .errors import VerifyError

# COSE algorithm identifiers (section 3).
ED25519 = -19
ESP256 = -9
SM2_SM3 = -65537
MLDSA44 = -48
MLDSA65 = -49
MLDSA87 = -50

SHA256 = -16
SM3 = -65538

ALGORITHM_NAMES = {
    ED25519: "Ed25519",
    ESP256: "ESP256",
    SM2_SM3: "SM2-SM3",
    MLDSA44: "ML-DSA-44",
    MLDSA65: "ML-DSA-65",
    MLDSA87: "ML-DSA-87",
}
HASH_NAMES = {SHA256: "SHA-256", SM3: "SM3"}
_HASHLIB = {SHA256: "sha256", SM3: "sm3"}

# Public key and signature sizes (section 3; FIPS 204 for ML-DSA).
_KEY_SIZES = {ED25519: 32, ESP256: 65, SM2_SM3: 65, MLDSA44: 1312, MLDSA65: 1952, MLDSA87: 2592}
_SIGNATURE_SIZES = {ED25519: 64, ESP256: 64, SM2_SM3: 64, MLDSA44: 2420, MLDSA65: 3309, MLDSA87: 4627}

# SM2 signatures use the default distinguishing identifier (section 3).
SM2_DISTINGUISHING_ID = "1234567812345678"

# The order of the P-256 group, for the low-S rule (section 3).
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Ed25519: the field prime, and the y coordinates of the points of small
# order (the eight-torsion subgroup: the identity y = 1, the point of order 2
# y = -1, the points of order 4 y = 0, and those of order 8). A key is weak if
# it encodes one of those points, or if its y is not reduced (y >= p).
_ED25519_P = 2**255 - 19
_ED25519_Y8 = int.from_bytes(bytes.fromhex(
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), "little")
_ED25519_SMALL_ORDER_Y = {0, 1, _ED25519_P - 1, _ED25519_Y8, _ED25519_P - _ED25519_Y8}


def openssl_binary() -> str:
    return os.environ.get("CEXCHAIN_OPENSSL", "openssl")


# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------

def hash_function(alg: int):
    """The ledger hash (section 3): SHA-256 or SM3, as a function."""
    name = _HASHLIB.get(alg)
    if name is None:
        raise VerifyError(f"unknown hash algorithm {alg}")
    try:
        hashlib.new(name)
    except ValueError as e:
        raise VerifyError(f"this Python's hashlib lacks {HASH_NAMES[alg]}") from e
    return lambda data: hashlib.new(name, bytes(data)).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Public keys: [alg, key bytes] (section 3)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PublicKey:
    alg: int
    key: bytes

    @property
    def encoded(self) -> bytes:
        return cbor.encode([self.alg, self.key])

    @property
    def name(self) -> str:
        return ALGORITHM_NAMES[self.alg]

    def kid(self, hash_fn) -> bytes:
        """kid = HASH(deterministic-CBOR([alg, key])) (section 3)."""
        return hash_fn(self.encoded)


def parse_public_key(value, what: str = "a public key") -> PublicKey:
    """Checks the encoding [alg, key] and the key's size and form. It does
    not reject weak keys: see is_weak."""
    if not (isinstance(value, list) and len(value) == 2 and isinstance(value[0], int)
            and not isinstance(value[0], bool) and isinstance(value[1], bytes)):
        raise VerifyError(f"{what} is not [alg, key bytes]")
    alg, key = value
    if alg not in _KEY_SIZES:
        raise VerifyError(f"{what} uses an unknown signature algorithm ({alg})")
    if len(key) != _KEY_SIZES[alg]:
        raise VerifyError(f"{what} has the wrong size for {ALGORITHM_NAMES[alg]}")
    if alg in (ESP256, SM2_SM3) and key[0] != 0x04:
        raise VerifyError(f"{what} is not an uncompressed SEC 1 point")
    return PublicKey(alg, key)


def is_weak(public: PublicKey) -> bool:
    """A key no verifier should accept: an Ed25519 key of small order or not
    canonically encoded, or an elliptic-curve point that is not on its curve.
    (The specification says "weak" without defining it; this is what this
    verifier takes it to mean.)"""
    if public.alg == ED25519:
        y = int.from_bytes(public.key, "little") & ((1 << 255) - 1)
        return y >= _ED25519_P or y in _ED25519_SMALL_ORDER_Y
    if public.alg == ESP256:
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public.key)
        except ValueError:
            return True
        return False
    if public.alg == SM2_SM3:
        return not _sm2_point_valid(public.key)
    try:
        _mldsa_key(public)
    except ValueError:
        return True
    return False


def _mldsa_key(public: PublicKey):
    from cryptography.hazmat.primitives.asymmetric import mldsa
    cls = {MLDSA44: mldsa.MLDSA44PublicKey, MLDSA65: mldsa.MLDSA65PublicKey,
           MLDSA87: mldsa.MLDSA87PublicKey}[public.alg]
    return cls.from_public_bytes(public.key)


# ---------------------------------------------------------------------------
# SM2 through the openssl command line
# ---------------------------------------------------------------------------

def _sm2_spki(point: bytes) -> bytes:
    """A DER SubjectPublicKeyInfo for an SM2 point: id-ecPublicKey with the
    SM2 curve (1.2.156.10197.1.301)."""
    algorithm = bytes.fromhex("3013" "06072a8648ce3d0201" "06082a811ccf5501822d")
    bit_string = b"\x03\x42\x00" + point
    body = algorithm + bit_string
    return b"\x30" + bytes([len(body)]) + body


@functools.lru_cache(maxsize=1024)
def _sm2_point_valid(point: bytes) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "key.der")
        with open(path, "wb") as f:
            f.write(_sm2_spki(point))
        done = subprocess.run([openssl_binary(), "pkey", "-pubin", "-inform", "DER", "-in", path, "-noout"],
                              capture_output=True)
        return done.returncode == 0


@functools.lru_cache(maxsize=4096)
def _sm2_verify(point: bytes, message: bytes, signature: bytes) -> bool:
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r == 0 or s == 0:
        return False
    with tempfile.TemporaryDirectory() as tmp:
        key_path, message_path, signature_path = (os.path.join(tmp, n) for n in ("key.der", "m", "sig"))
        with open(key_path, "wb") as f:
            f.write(_sm2_spki(point))
        with open(message_path, "wb") as f:
            f.write(message)
        with open(signature_path, "wb") as f:
            f.write(encode_dss_signature(r, s))
        done = subprocess.run(
            [openssl_binary(), "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", key_path,
             "-rawin", "-digest", "sm3", "-in", message_path, "-sigfile", signature_path,
             "-pkeyopt", f"distid:{SM2_DISTINGUISHING_ID}"],
            capture_output=True)
        return done.returncode == 0


# ---------------------------------------------------------------------------
# Signatures in their fixed wire format (section 3)
# ---------------------------------------------------------------------------

def verify_signature(public: PublicKey, message: bytes, signature: bytes) -> bool:
    """True if `signature`, in CexChain's wire format for the key's
    algorithm, is valid over `message`. Weak keys never verify."""
    if not isinstance(signature, bytes) or len(signature) != _SIGNATURE_SIZES[public.alg]:
        return False
    if is_weak(public):
        return False
    try:
        if public.alg == ED25519:
            ed25519.Ed25519PublicKey.from_public_bytes(public.key).verify(signature, message)
            return True
        if public.alg == ESP256:
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            if s > _P256_ORDER // 2:  # ESP256 signatures MUST be in low-S form
                return False
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public.key)
            key.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
            return True
        if public.alg == SM2_SM3:
            return _sm2_verify(public.key, bytes(message), signature)
        _mldsa_key(public).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_es256_der(point: bytes, message: bytes, der_signature: bytes) -> bool:
    """WebAuthn ES256: a DER ECDSA signature, either S (section 7)."""
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        key.verify(der_signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
