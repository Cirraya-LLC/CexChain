#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Generates CexChain test vectors using implementations independent of CexChain.

Requirements: Python 3.11+, the packages in requirements.txt, and an OpenSSL 3.5+
command-line tool (used for SM2, which the Python cryptography package lacks).

Usage:
    python3 tools/testvectors/generate.py [--openssl /path/to/openssl]

Writes JSON files into testvectors/. Deterministic algorithms reproduce the same
vectors on every run. Randomized ones (ECDSA, SM2, ML-DSA) produce different but
equally valid vectors.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tempfile

import cbor2

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "testvectors"

SM2_DISTINGUISHING_ID = "1234567812345678"

# COSE algorithm identifiers (IANA registry; SM2/SM3 use CexChain private-use values).
COSE = {
    "SHA-256": -16,
    "SHA-384": -43,
    "SHA-512": -44,
    "SM3": -65538,
    "ESP256": -9,
    "Ed25519": -19,
    "ML-DSA-44": -48,
    "ML-DSA-65": -49,
    "ML-DSA-87": -50,
    "SM2-SM3": -65537,
}

MESSAGES = [
    b"",
    b"abc",
    b"CexChain verifiable records",
    bytes(range(256)) * 4,
]


def write(name: str, description: str, vectors: list[dict]) -> None:
    OUT.mkdir(exist_ok=True)
    document = {"description": description, "vectors": vectors}
    (OUT / name).write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote {len(vectors)} vectors to testvectors/{name}")


def flip_first_bit(data: bytes) -> bytes:
    return bytes([data[0] ^ 0x01]) + data[1:]


# ---------------------------------------------------------------------------
# Pure-Python verifiers. ECDSA and SM2 vectors are produced through OpenSSL
# (Python cryptography bundles it; SM2 uses the CLI), so each one is also
# checked here with textbook arithmetic that shares no code with OpenSSL.
# Curve parameters: FIPS 186 / SEC 2 (P-256) and GB/T 32918.5 (SM2).
# ---------------------------------------------------------------------------


class Curve:
    def __init__(self, p, a, b, gx, gy, n):
        self.p, self.a, self.b, self.g, self.n = p, a, b, (gx, gy), n

    def add(self, p1, p2):
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        if p1[0] == p2[0] and (p1[1] + p2[1]) % self.p == 0:
            return None
        if p1 == p2:
            slope = (3 * p1[0] * p1[0] + self.a) * pow(2 * p1[1], -1, self.p) % self.p
        else:
            slope = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, self.p) % self.p
        x = (slope * slope - p1[0] - p2[0]) % self.p
        return (x, (slope * (p1[0] - x) - p1[1]) % self.p)

    def mul(self, k, point):
        result = None
        while k:
            if k & 1:
                result = self.add(result, point)
            point = self.add(point, point)
            k >>= 1
        return result

    def point(self, sec1: bytes):
        assert len(sec1) == 65 and sec1[0] == 4
        x, y = int.from_bytes(sec1[1:33], "big"), int.from_bytes(sec1[33:], "big")
        assert (y * y - x * x * x - self.a * x - self.b) % self.p == 0, "point not on curve"
        return (x, y)


P256 = Curve(
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
)
SM2_CURVE = Curve(
    0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
    0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
    0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
    0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
    0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0,
    0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123,
)


def ecdsa_p256_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    c = P256
    q = c.point(public)
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not (0 < r < c.n and 0 < s < c.n):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, c.n)
    point = c.add(c.mul(e * w % c.n, c.g), c.mul(r * w % c.n, q))
    return point is not None and point[0] % c.n == r


def sm2_verify(public: bytes, message: bytes, signature: bytes, distinguishing_id: bytes) -> bool:
    c = SM2_CURVE
    q = c.point(public)
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not (0 < r < c.n and 0 < s < c.n):
        return False
    be = lambda v: v.to_bytes(32, "big")
    z = hashlib.new("sm3", (len(distinguishing_id) * 8).to_bytes(2, "big") + distinguishing_id
                    + be(c.a) + be(c.b) + be(c.g[0]) + be(c.g[1]) + be(q[0]) + be(q[1])).digest()
    e = int.from_bytes(hashlib.new("sm3", z + message).digest(), "big")
    t = (r + s) % c.n
    if t == 0:
        return False
    point = c.add(c.mul(s, c.g), c.mul(t, q))
    return point is not None and (e + point[0]) % c.n == r


def raw_rs(der: bytes, low_s: bool = False) -> bytes:
    """Converts a DER signature to r || s. With low_s, normalizes s <= n/2 (ESP256)."""
    r, s = decode_dss_signature(der)
    if low_s and s > P256.n // 2:
        s = P256.n - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def high_s(signature: bytes) -> bytes:
    s = int.from_bytes(signature[32:], "big")
    return signature[:32] + (P256.n - s).to_bytes(32, "big")


# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------

KNOWN_DIGESTS = {
    ("SHA-256", b"abc"): "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ("SM3", b"abc"): "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
}


def generate_hashes() -> None:
    names = {"SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512", "SM3": "sm3"}
    vectors = []
    for alg, hashlib_name in names.items():
        for message in MESSAGES:
            digest = hashlib.new(hashlib_name, message).hexdigest()
            known = KNOWN_DIGESTS.get((alg, message))
            assert known is None or known == digest, f"{alg} known answer mismatch"
            vectors.append(
                {"algorithm": COSE[alg], "name": alg, "message": message.hex(), "digest": digest}
            )
    write("hashes.json", "Hash outputs computed with Python hashlib.", vectors)


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

# RFC 8032 section 7.1, tests 1 and 2.
RFC8032 = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
]


def signature_vector(alg: str, public_key: bytes, message: bytes, signature: bytes, source: str) -> list[dict]:
    """Returns the valid vector plus variants with a modified message and signature."""
    base = {"algorithm": COSE[alg], "name": alg, "public_key": public_key.hex(), "source": source}
    tampered_message = flip_first_bit(message) if message else b"\x00"
    return [
        {**base, "message": message.hex(), "signature": signature.hex(), "valid": True},
        {**base, "message": tampered_message.hex(), "signature": signature.hex(), "valid": False},
        {**base, "message": message.hex(), "signature": flip_first_bit(signature).hex(), "valid": False},
    ]


def invalid_vector(alg: str, public_key: bytes, message: bytes, signature: bytes, reason: str,
                   expected_error: str = "verification_failed") -> dict:
    return {"algorithm": COSE[alg], "name": alg, "public_key": public_key.hex(), "message": message.hex(),
            "signature": signature.hex(), "valid": False, "expected_error": expected_error, "source": reason}


ED25519_L = 2**252 + 27742317777372353535851937790883648493

# Small-order and non-canonical Ed25519 public keys (see tools/crypto/derive_constants.py).
# Lenient verifiers accept the signature R = identity, S = 0 under the identity key for
# every message.
ED25519_WEAK_KEYS = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # y = p
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # y = p + 1
]


def ed25519_vectors() -> list[dict]:
    vectors = []
    for seed_hex, public_hex, message_hex, signature_hex in RFC8032:
        key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
        public = key.public_key().public_bytes_raw()
        message = bytes.fromhex(message_hex)
        signature = key.sign(message)
        assert public.hex() == public_hex, "RFC 8032 public key mismatch"
        assert signature.hex() == signature_hex, "RFC 8032 signature mismatch"
        vectors += signature_vector("Ed25519", public, message, signature, "RFC 8032 section 7.1")
        # The same signature with S + L: still a group-equivalent scalar, but not reduced.
        unreduced = signature[:32] + (int.from_bytes(signature[32:], "little") + ED25519_L).to_bytes(32, "little")
        vectors.append(invalid_vector("Ed25519", public, message, unreduced, "S >= L (not reduced)"))
    identity_signature = bytes([1]) + bytes(63)
    for key in ED25519_WEAK_KEYS:
        vectors.append(invalid_vector("Ed25519", bytes.fromhex(key), b"any message", identity_signature,
                                      "small-order or non-canonical public key", "invalid_argument"))
    return vectors


def esp256_vectors() -> list[dict]:
    key = ec.derive_private_key(0x0C3A_7D1E_55AA_1234_9876_FEDC_BA98_7654_3210_0123_4567_89AB_CDEF_0F1E_2D3C_4B5A, ec.SECP256R1())
    public = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    vectors = []
    for message in MESSAGES:
        signature = raw_rs(key.sign(message, ec.ECDSA(hashes.SHA256())), low_s=True)
        assert ecdsa_p256_verify(public, message, signature), "pure-Python ECDSA check failed"
        assert ecdsa_p256_verify(public, message, high_s(signature)), "high-S form must also be mathematically valid"
        vectors += signature_vector("ESP256", public, message, signature, "Python cryptography, low-S")
        vectors.append(invalid_vector("ESP256", public, message, high_s(signature), "high-S form of a valid signature"))
    return vectors


def mldsa_vectors() -> list[dict]:
    classes = {
        "ML-DSA-44": mldsa.MLDSA44PrivateKey,
        "ML-DSA-65": mldsa.MLDSA65PrivateKey,
        "ML-DSA-87": mldsa.MLDSA87PrivateKey,
    }
    vectors = []
    for alg, cls in classes.items():
        key = cls.generate()
        public = key.public_key().public_bytes_raw()
        for message in MESSAGES[:2]:
            vectors += signature_vector(alg, public, message, key.sign(message), "Python cryptography")
    return vectors


def sm2_vectors(openssl: str) -> list[dict]:
    vectors = []
    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        key = work / "sm2.pem"
        subprocess.run([openssl, "genpkey", "-algorithm", "SM2", "-out", str(key)], check=True, capture_output=True)
        spki = subprocess.run(
            [openssl, "pkey", "-in", str(key), "-pubout", "-outform", "DER"], check=True, capture_output=True
        ).stdout
        public = spki[-65:]  # SubjectPublicKeyInfo ends with the uncompressed point.
        assert public[0] == 0x04
        for i, message in enumerate(MESSAGES):
            message_file = work / f"m{i}.bin"
            message_file.write_bytes(message)
            der = subprocess.run(
                [openssl, "pkeyutl", "-sign", "-rawin", "-digest", "sm3", "-inkey", str(key),
                 "-in", str(message_file), "-pkeyopt", f"distid:{SM2_DISTINGUISHING_ID}"],
                check=True, capture_output=True,
            ).stdout
            signature = raw_rs(der)
            assert sm2_verify(public, message, signature, SM2_DISTINGUISHING_ID.encode()), "pure-Python SM2 check failed"
            assert not sm2_verify(public, message, signature, b""), "SM2 must bind the distinguishing ID"
            vectors += signature_vector("SM2-SM3", public, message, signature, "OpenSSL command-line tool")
    return vectors


def generate_signatures(openssl: str) -> None:
    vectors = ed25519_vectors() + esp256_vectors() + sm2_vectors(openssl) + mldsa_vectors()
    write(
        "signatures.json",
        "Signatures in CexChain wire encoding (ECDSA and SM2 as r||s; ESP256 in low-S form). Each "
        "valid vector is followed by variants with a modified message and a modified signature. "
        "ESP256 and SM2 vectors are also checked by pure-Python verifiers. Invalid vectors may carry "
        "expected_error (default verification_failed).",
        vectors,
    )


# ---------------------------------------------------------------------------
# Merkle trees (RFC 9162 section 2.1)
# ---------------------------------------------------------------------------

# Leaves and roots from the Certificate Transparency / Trillian reference data.
REFERENCE_LEAVES = [
    "", "00", "10", "2021", "3031", "40414243", "5051525354555657",
    "606162636465666768696a6b6c6d6e6f",
]
REFERENCE_SHA256_ROOTS = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


def split_point(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


class MerkleOracle:
    """A direct transcription of the RFC 9162 recursive definitions."""

    def __init__(self, hashlib_name: str):
        self.name = hashlib_name

    def h(self, data: bytes) -> bytes:
        return hashlib.new(self.name, data).digest()

    def mth(self, d: list[bytes]) -> bytes:
        n = len(d)
        if n == 0:
            return self.h(b"")
        if n == 1:
            return self.h(b"\x00" + d[0])
        k = split_point(n)
        return self.h(b"\x01" + self.mth(d[:k]) + self.mth(d[k:]))

    def path(self, m: int, d: list[bytes]) -> list[bytes]:
        n = len(d)
        if n == 1:
            return []
        k = split_point(n)
        if m < k:
            return self.path(m, d[:k]) + [self.mth(d[k:])]
        return self.path(m - k, d[k:]) + [self.mth(d[:k])]

    def subproof(self, m: int, d: list[bytes], complete: bool) -> list[bytes]:
        n = len(d)
        if m == n:
            return [] if complete else [self.mth(d)]
        k = split_point(n)
        if m <= k:
            return self.subproof(m, d[:k], complete) + [self.mth(d[k:])]
        return self.subproof(m - k, d[k:], False) + [self.mth(d[:k])]


def generate_merkle(alg: str, hashlib_name: str, file_name: str) -> None:
    oracle = MerkleOracle(hashlib_name)
    entries = [bytes.fromhex(x) for x in REFERENCE_LEAVES]
    entries += [f"CexChain entry {i}".encode() for i in range(len(entries), 13)]

    roots = [oracle.mth(entries[:n]).hex() for n in range(len(entries) + 1)]
    if alg == "SHA-256":
        assert roots[: len(REFERENCE_SHA256_ROOTS)] == REFERENCE_SHA256_ROOTS, "reference roots mismatch"

    inclusion = []
    consistency = []
    for n in range(1, len(entries) + 1):
        for m in range(n):
            inclusion.append({"index": m, "tree_size": n, "proof": [p.hex() for p in oracle.path(m, entries[:n])]})
        for m in range(1, n + 1):
            proof = [] if m == n else oracle.subproof(m, entries[:n], True)
            consistency.append({"old_size": m, "new_size": n, "proof": [p.hex() for p in proof]})

    document = {
        "description": f"RFC 9162 Merkle tree vectors with {alg}, from a direct Python transcription "
        "of the RFC's recursive definitions. The first eight entries are the Certificate "
        "Transparency reference leaves.",
        "algorithm": COSE[alg],
        "name": alg,
        "entries": [e.hex() for e in entries],
        "roots": roots,
        "inclusion": inclusion,
        "consistency": consistency,
    }
    OUT.mkdir(exist_ok=True)
    (OUT / file_name).write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote {len(inclusion)} inclusion and {len(consistency)} consistency proofs to testvectors/{file_name}")


# ---------------------------------------------------------------------------
# COSE_Sign1 (RFC 9052 section 4.2)
# ---------------------------------------------------------------------------

COSE_ED25519_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"


def cose_sign1(alg: str, sign, kid: bytes, payload: bytes, aad: bytes, detached: bool) -> bytes:
    """Builds a tagged COSE_Sign1 with cbor2. Integer-keyed maps of this size encode
    identically under RFC 7049 and RFC 8949 canonical ordering."""
    protected = cbor2.dumps({1: COSE[alg], 4: kid}, canonical=True)
    to_be_signed = cbor2.dumps(["Signature1", protected, aad, payload])
    signature = sign(to_be_signed)
    body = [protected, {}, None if detached else payload, signature]
    return cbor2.dumps(cbor2.CBORTag(18, body), canonical=True)


def generate_cose(openssl: str) -> None:
    vectors = []

    def add(alg, public, sign, kid, payload, aad=b"", detached=False, **extra):
        message = cose_sign1(alg, sign, kid, payload, aad, detached)
        vectors.append({
            "algorithm": COSE[alg], "name": alg, "public_key": public.hex(), "kid": kid.hex(),
            "payload": payload.hex(), "external_aad": aad.hex(), "detached": detached,
            "message": message.hex(), **extra,
        })

    ed = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(COSE_ED25519_SEED))
    ed_public = ed.public_key().public_bytes_raw()
    for payload, aad, detached in [(b"CexChain statement", b"", False),
                                   (b"", b"", False),
                                   (b"CexChain statement", b"context", False),
                                   (b"detached document", b"", True)]:
        add("Ed25519", ed_public, ed.sign, b"ed-key", payload, aad, detached, seed=COSE_ED25519_SEED)

    p256 = ec.generate_private_key(ec.SECP256R1())
    p256_public = p256.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    def esp256_sign(message: bytes) -> bytes:
        signature = raw_rs(p256.sign(message, ec.ECDSA(hashes.SHA256())), low_s=True)
        assert ecdsa_p256_verify(p256_public, message, signature)
        return signature

    add("ESP256", p256_public, esp256_sign, b"p256-key", b"CexChain statement")

    ml = mldsa.MLDSA65PrivateKey.generate()
    add("ML-DSA-65", ml.public_key().public_bytes_raw(), ml.sign, b"mldsa-key", b"CexChain statement")

    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        key = work / "sm2.pem"
        subprocess.run([openssl, "genpkey", "-algorithm", "SM2", "-out", str(key)], check=True, capture_output=True)
        spki = subprocess.run([openssl, "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
                              check=True, capture_output=True).stdout

        def sm2_sign(message: bytes) -> bytes:
            (work / "tbs.bin").write_bytes(message)
            der = subprocess.run(
                [openssl, "pkeyutl", "-sign", "-rawin", "-digest", "sm3", "-inkey", str(key),
                 "-in", str(work / "tbs.bin"), "-pkeyopt", f"distid:{SM2_DISTINGUISHING_ID}"],
                check=True, capture_output=True).stdout
            signature = raw_rs(der)
            assert sm2_verify(spki[-65:], message, signature, SM2_DISTINGUISHING_ID.encode())
            return signature

        add("SM2-SM3", spki[-65:], sm2_sign, b"sm2-key", b"CexChain statement")

    write("cose-sign1.json",
          "Tagged COSE_Sign1 messages built with cbor2 and independent signers. Protected header "
          "is {1: alg, 4: kid}; unprotected header is empty. Ed25519 messages are deterministic "
          "and must be reproduced byte for byte.",
          vectors)


# ---------------------------------------------------------------------------
# PKCS #8 private keys (throwaway test keys; never use them for anything else)
# ---------------------------------------------------------------------------


def swap_public_point(der: bytes, own: bytes, other: bytes) -> bytes:
    """Replaces the public point embedded in a PKCS #8 EC key with another key's point."""
    assert der.count(own) == 1, "embedded public key not found exactly once"
    return der.replace(own, other)


def generate_pkcs8(openssl: str) -> None:
    pkcs8 = dict(encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.PKCS8,
                 encryption_algorithm=serialization.NoEncryption())
    point = dict(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)
    vectors = []

    def add(name, der, valid, alg=None, public=b"", expected_error=None):
        vector = {"name": name, "der": der.hex(), "valid": valid}
        if valid:
            vector.update(algorithm=COSE[alg], public_key=public.hex())
        else:
            vector["expected_error"] = expected_error
        vectors.append(vector)

    ed = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(RFC8032[0][0]))
    add("Ed25519 from the RFC 8032 test 1 seed", ed.private_bytes(**pkcs8), True, "Ed25519",
        ed.public_key().public_bytes_raw())

    a, b = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    a_der, a_point, b_point = a.private_bytes(**pkcs8), a.public_key().public_bytes(**point), b.public_key().public_bytes(**point)
    add("ESP256", a_der, True, "ESP256", a_point)
    add("ESP256 private key with another key's public key", swap_public_point(a_der, a_point, b_point),
        False, expected_error="invalid_argument")
    add("ESP256 as SEC 1 ECPrivateKey instead of PKCS #8",
        a.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL,
                        serialization.NoEncryption()), False, expected_error="invalid_argument")
    add("ESP256 PKCS #8 with a trailing byte", a_der + b"\x00", False, expected_error="invalid_argument")
    add("ESP256 PKCS #8 truncated", a_der[:-1], False, expected_error="invalid_argument")

    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        keys = []
        for name in ("a", "b"):
            sec1 = work / f"{name}.sec1.der"
            path = work / f"{name}.der"
            # genpkey writes SM2 keys in DER as SEC 1 ECPrivateKey; convert explicitly.
            subprocess.run([openssl, "genpkey", "-algorithm", "SM2", "-outform", "DER", "-out", str(sec1)],
                           check=True, capture_output=True)
            subprocess.run([openssl, "pkcs8", "-topk8", "-nocrypt", "-inform", "DER", "-in", str(sec1),
                            "-outform", "DER", "-out", str(path)], check=True, capture_output=True)
            spki = subprocess.run([openssl, "pkey", "-inform", "DER", "-in", str(path), "-pubout", "-outform", "DER"],
                                  check=True, capture_output=True).stdout
            keys.append((path.read_bytes(), spki[-65:], sec1.read_bytes()))
        (sm2_a, sm2_a_point, sm2_a_sec1), (_, sm2_b_point, _) = keys
        assert sm2_a[:3] == bytes([0x30, 0x81, sm2_a[2]]) and sm2_a[3:6] == bytes([0x02, 0x01, 0x00]), "not PKCS #8"
        add("SM2", sm2_a, True, "SM2-SM3", sm2_a_point)
        add("SM2 private key with another key's public key", swap_public_point(sm2_a, sm2_a_point, sm2_b_point),
            False, expected_error="invalid_argument")
        add("SM2 as SEC 1 ECPrivateKey instead of PKCS #8", sm2_a_sec1, False, expected_error="invalid_argument")

    write("pkcs8.json",
          "Unencrypted PKCS #8 private keys: valid keys with their expected public keys, and invalid inputs "
          "that must be rejected. These are throwaway test keys.",
          vectors)


# ---------------------------------------------------------------------------
# Protocol v0.1 objects (spec/cexchain.cddl)
# ---------------------------------------------------------------------------
#
# A deterministic CBOR encoder written here from RFC 8949 section 4.2.1 rather
# than relying on cbor2's canonical mode, which sorts map keys length-first
# (RFC 7049) instead of bytewise.


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    for info, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([(major << 5) | info]) + n.to_bytes(width, "big")
    raise ValueError("integer too large")


def dcbor(value) -> bytes:
    if isinstance(value, bool) or value is None:
        return {False: b"\xf4", True: b"\xf5", None: b"\xf6"}[value]
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        return _head(2, len(value)) + bytes(value)
    if isinstance(value, str):
        data = value.encode("utf-8")
        return _head(3, len(data)) + data
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(dcbor(v) for v in value)
    if isinstance(value, dict):
        items = sorted((dcbor(k), dcbor(v)) for k, v in value.items())
        assert len({k for k, _ in items}) == len(items), "duplicate key"
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    if isinstance(value, cbor2.CBORTag):
        return _head(6, value.tag) + dcbor(value.value)
    raise TypeError(type(value))


STATEMENT_TYPE = "application/cexchain-statement+cbor"
CHECKPOINT_TYPE = "application/cexchain-checkpoint+cbor"
COSIGNATURE_TYPE = "application/cexchain-cosignature+cbor"
STATE_TYPE = "application/cexchain-state+cbor"
HASHES = {-16: "sha256", -65538: "sm3"}
VDS = {-16: 1, -65538: -65537}


class Ledger:
    def __init__(self, hash_id: int):
        self.hash_id = hash_id

    def h(self, data: bytes) -> bytes:
        return hashlib.new(HASHES[self.hash_id], data).digest()

    def kid(self, key) -> bytes:
        return self.h(dcbor([COSE["Ed25519"], key.public_key().public_bytes_raw()]))

    def sign(self, key, protected: dict, payload: bytes, unprotected=None, detached=False) -> bytes:
        protected_bytes = dcbor({1: COSE["Ed25519"], **protected})
        signature = key.sign(dcbor(["Signature1", protected_bytes, b"", payload]))
        body = [protected_bytes, unprotected or {}, None if detached else payload, signature]
        return dcbor(cbor2.CBORTag(18, body))

    def statement(self, key, payload: dict):
        payload_bytes = dcbor(payload)
        protected = {3: STATEMENT_TYPE, 4: self.kid(key)}
        protected_bytes = dcbor({1: COSE["Ed25519"], **protected})
        statement_id = self.h(dcbor(["Signature1", protected_bytes, b"", payload_bytes]))
        return self.sign(key, protected, payload_bytes), statement_id

    def merkle(self) -> MerkleOracle:
        return MerkleOracle(HASHES[self.hash_id])


def ed_public(key) -> list:
    return [COSE["Ed25519"], key.public_key().public_bytes_raw()]


# A record type of a user's own (spec v0.9, section 6): the generic lifecycle.
# Revision v0.9 removed the built-in industry types the v0.1, v0.2, and v0.4
# vectors used (cexchain.certificate/1, cexchain.delivery/1); they were
# regenerated with these, and nothing else in them changed.
USER_TYPE = "example.document/1"
USER_TYPE_2 = "example.note/1"


def generate_protocol() -> None:
    seeds = {name: hashlib.sha256(f"CexChain test key: {name}".encode()).hexdigest()
             for name in ("org_root", "log", "witness", "person", "agent")}
    keys = {name: ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)) for name, seed in seeds.items()}
    t0 = 1_791_244_800_000  # 2026-10-06T00:00:00Z

    def nonce(i: int) -> bytes:
        return bytes([i]) * 16

    ledgers = []
    for hash_id in (-16, -65538):
        lg = Ledger(hash_id)
        statements = []

        def add(name, signer, payload):
            encoded, statement_id = lg.statement(keys[signer], payload)
            statements.append({"name": name, "signer": signer, "encoded": encoded.hex(),
                               "payload": dcbor(payload).hex(), "statement_id": statement_id.hex()})
            return statement_id

        genesis = {0: 1, 1: 1, 5: t0, 6: nonce(1), 7: {
            1: hash_id, 2: "Cirraya Test Org", 3: ed_public(keys["org_root"]), 4: ed_public(keys["log"])}}
        ledger_id = add("genesis", "org_root", genesis)
        org = ledger_id

        person = add("register person", "org_root", {0: 1, 1: 2, 2: ledger_id, 3: org, 5: t0 + 1, 6: nonce(2), 7: {
            1: 1, 2: "Quality Inspector", 3: ed_public(keys["person"])}})
        delegation = add("delegate to person", "org_root", {0: 1, 1: 5, 2: ledger_id, 3: org, 5: t0 + 2, 6: nonce(3), 7: {
            1: person, 2: {1: [2, 16, 17, 18, 19], 2: [USER_TYPE, USER_TYPE_2],
                           4: t0 + 86_400_000, 5: True}}})
        agent = add("register agent", "person", {0: 1, 1: 2, 2: ledger_id, 3: person, 4: delegation, 5: t0 + 3, 6: nonce(4), 7: {
            1: 2, 2: "Drafting Agent", 3: ed_public(keys["agent"]), 4: person,
            5: {1: "claude-opus-5-5", 2: "2026-09", 3: "cexchain-mcp/0.1"}}})

        salt = lambda i: bytes([0xA0 + i]) * 16
        fields = [
            ["product", salt(1), "Stainless steel flange DN50"],
            ["batch", salt(2), "B-2026-1006-07"],
            ["standard", salt(3), "GB/T 9119-2010"],
            ["result", salt(4), "pass"],
            ["tested_units", salt(5), 120],
        ]
        ordered = sorted(fields, key=lambda f: f[0].encode())
        leaves = [dcbor(f) for f in ordered]
        oracle = lg.merkle()
        field_root = oracle.mth(leaves)
        attachment_salt = bytes([0x5A]) * 16
        attachment_content = b"%PDF-1.7 test report"
        record = add("register record", "agent", {0: 1, 1: 16, 2: ledger_id, 3: agent, 5: t0 + 4, 6: nonce(5), 7: {
            1: USER_TYPE, 2: field_root, 3: len(leaves),
            4: [["report.pdf", "application/pdf", len(attachment_content), lg.h(attachment_salt + attachment_content)]],
            5: {"issuer": "Cirraya Test Org", "product": "Stainless steel flange DN50"}},
            9: {1: "claude-opus-5-5", 2: "2026-09", 3: lg.h(b"inspection data"), 4: [["cexchain_issue", lg.h(b"tool v1")]]}})
        add("endorse record", "person", {0: 1, 1: 17, 2: ledger_id, 3: person, 4: delegation, 5: t0 + 5, 6: nonce(6), 7: {
            1: record, 2: "inspector"}})
        add("transition record", "person", {0: 1, 1: 18, 2: ledger_id, 3: person, 4: delegation, 5: t0 + 6, 6: nonce(7), 7: {
            1: record, 2: "issued", 3: "confirmed"}})
        add("revoke record", "org_root", {0: 1, 1: 19, 2: ledger_id, 3: org, 5: t0 + 7, 6: nonce(8), 7: {
            1: record, 2: "superseded"}})

        entries = []
        for i, st in enumerate(statements):
            entries.append(dcbor({1: bytes.fromhex(st["statement_id"]), 2: t0 + 1000 + i, 3: bytes.fromhex(st["encoded"])}))
        tree = lg.merkle()
        root = tree.mth(entries)
        checkpoint_payload = dcbor({1: ledger_id, 2: hash_id, 3: len(entries), 4: root, 5: t0 + 5000})
        checkpoint = lg.sign(keys["log"], {3: CHECKPOINT_TYPE, 4: lg.kid(keys["log"])}, checkpoint_payload)
        cosignature = lg.sign(keys["witness"], {3: COSIGNATURE_TYPE, 4: lg.kid(keys["witness"])}, checkpoint_payload)

        receipts = []
        for index in (0, 4, len(entries) - 1):
            path = tree.path(index, entries)
            proof = dcbor([len(entries), index, path])
            receipt = lg.sign(keys["log"], {4: lg.kid(keys["log"]), 395: VDS[hash_id]}, root,
                              unprotected={396: {-1: [proof]}}, detached=True)
            receipts.append({"index": index, "encoded": receipt.hex()})

        disclosed = "result"
        disclosed_index = [f[0] for f in ordered].index(disclosed)
        ledgers.append({
            "hash": hash_id,
            "ledger_id": ledger_id.hex(),
            "statements": statements,
            "log_entries": [e.hex() for e in entries],
            "root": root.hex(),
            "checkpoint": checkpoint.hex(),
            "cosignature": cosignature.hex(),
            "receipts": receipts,
            "record_fields": [{"name": f[0], "salt": f[1].hex(), "value": f[2]} for f in fields],
            "field_root": field_root.hex(),
            "disclosure": {"name": disclosed, "leaf": leaves[disclosed_index].hex(), "index": disclosed_index,
                           "path": [p.hex() for p in oracle.path(disclosed_index, leaves)]},
            "attachment": {"salt": attachment_salt.hex(), "content": attachment_content.hex(),
                           "commitment": lg.h(attachment_salt + attachment_content).hex()},
        })

    document = {
        "description": "CexChain protocol v0.1 objects built by an independent Python encoder from "
                       "spec/cexchain.cddl: every statement's encoding, log entries, a checkpoint and "
                       "its cosignature, receipts, and a record's field commitments. The statements show "
                       "encodings only, not a history the ledger rules accept. The record's type is a "
                       "user's, example.document/1 (regenerated in v0.9, which removed the built-in "
                       "industry types). All signatures are Ed25519 (deterministic), so every object "
                       "must be reproduced byte for byte. Keys are throwaway test keys: "
                       "seed = SHA-256(\"CexChain test key: <name>\").",
        "seeds": seeds,
        "ledgers": ledgers,
    }
    (OUT / "protocol-v0.1.json").write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote protocol vectors for {len(ledgers)} ledgers to testvectors/protocol-v0.1.json")


# ---------------------------------------------------------------------------
# Protocol v0.2 additions: proof of presence, the state commitment, cosign
# requests (spec/cexchain.cddl, revision v0.2)
# ---------------------------------------------------------------------------

def b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def id_bit(identifier: bytes, depth: int) -> int:
    return (identifier[depth // 8] >> (7 - depth % 8)) & 1


def smt_root(lg: Ledger, leaves: list, depth: int = 0) -> bytes:
    """Compact sparse Merkle tree; leaves are [kind, id, history] sorted by id."""
    if not leaves:
        return lg.h(b"")
    if len(leaves) == 1:
        return lg.h(b"\x00" + dcbor(leaves[0]))
    left = [leaf for leaf in leaves if id_bit(leaf[1], depth) == 0]
    right = [leaf for leaf in leaves if id_bit(leaf[1], depth) == 1]
    return lg.h(b"\x01" + smt_root(lg, left, depth + 1) + smt_root(lg, right, depth + 1))


def smt_proof(lg: Ledger, leaves: list, identifier: bytes) -> list[bytes]:
    siblings, current, depth = [], leaves, 0
    while len(current) > 1:
        left = [leaf for leaf in current if id_bit(leaf[1], depth) == 0]
        right = [leaf for leaf in current if id_bit(leaf[1], depth) == 1]
        if id_bit(identifier, depth):
            siblings.append(smt_root(lg, left, depth + 1))
            current = right
        else:
            siblings.append(smt_root(lg, right, depth + 1))
            current = left
        depth += 1
    return siblings


def generate_protocol_v02() -> None:
    seeds = {name: hashlib.sha256(f"CexChain test key: {name}".encode()).hexdigest()
             for name in ("org_root", "log", "witness", "person", "agent", "passkey", "ukey")}
    keys = {name: ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)) for name, seed in seeds.items()}
    t0 = 1_791_244_800_000

    def nonce(i: int) -> bytes:
        return bytes([i]) * 16

    ledgers = []
    for hash_id in (-16, -65538):
        lg = Ledger(hash_id)
        statements = []

        def add(name, signer, payload):
            encoded, statement_id = lg.statement(keys[signer], payload)
            statements.append({"name": name, "signer": signer, "encoded": encoded.hex(),
                               "payload": dcbor(payload).hex(), "statement_id": statement_id.hex()})
            return statement_id

        ledger_id = add("genesis", "org_root", {0: 1, 1: 1, 5: t0, 6: nonce(1), 7: {
            1: hash_id, 2: "Cirraya Test Org", 3: ed_public(keys["org_root"]), 4: ed_public(keys["log"])}})
        org = ledger_id
        person = add("register person", "org_root", {0: 1, 1: 2, 2: ledger_id, 3: org, 5: t0 + 1, 6: nonce(2), 7: {
            1: 1, 2: "Quality Inspector", 3: ed_public(keys["person"])}})
        delegation = add("delegate to person, presence required", "org_root",
                         {0: 1, 1: 5, 2: ledger_id, 3: org, 5: t0 + 2, 6: nonce(3), 7: {
                             1: person, 2: {1: [17], 4: t0 + 86_400_000, 6: True}}})
        record = add("register record", "org_root", {0: 1, 1: 16, 2: ledger_id, 3: org, 5: t0 + 3, 6: nonce(4), 7: {
            1: USER_TYPE, 2: lg.h(b"fields"), 3: 1}})

        # The organization registers the person's passkey (an Ed25519 credential)
        # and USB key (a hardware key: no relying party, presence method 2).
        credential_id = bytes(range(16))
        credential = {1: "localhost", 2: credential_id, 3: ed_public(keys["passkey"]), 4: "test passkey"}
        ukey_id = hashlib.sha256(dcbor(ed_public(keys["ukey"]))).digest()
        ukey_credential = {2: ukey_id, 3: ed_public(keys["ukey"]), 4: "test UKey", 5: 2}
        add("register passkey and UKey", "org_root", {0: 1, 1: 7, 2: ledger_id, 3: org, 5: t0 + 4, 6: nonce(5),
                                                      7: {1: person, 2: [credential, ukey_credential]}})

        # The person endorses with a WebAuthn assertion over the presence challenge.
        endorse = {0: 1, 1: 17, 2: ledger_id, 3: person, 4: delegation, 5: t0 + 5, 6: nonce(6), 7: {
            1: record, 2: "inspector"}}
        # Bound to the signing key's id, so a rotated key cannot reuse the proof.
        challenge = lg.h(b"CexChain presence v1" + lg.kid(keys["person"]) + dcbor(endorse))
        authenticator_data = hashlib.sha256(b"localhost").digest() + b"\x05" + (7).to_bytes(4, "big")
        client_data = ('{"type":"webauthn.get","challenge":"' + b64url(challenge) +
                       '","origin":"http://localhost:43210","crossOrigin":false}').encode()
        signature = keys["passkey"].sign(authenticator_data + hashlib.sha256(client_data).digest())
        endorse[8] = {1: credential_id, 2: authenticator_data, 3: client_data, 4: signature}
        add("endorse with proof of presence", "person", endorse)

        # The person approves with the UKey: its key signs the challenge itself.
        approve = {0: 1, 1: 17, 2: ledger_id, 3: person, 4: delegation, 5: t0 + 6, 6: nonce(8), 7: {
            1: record, 2: "approver"}}
        ukey_challenge = lg.h(b"CexChain presence v1" + lg.kid(keys["person"]) + dcbor(approve))
        approve[8] = {1: ukey_id, 4: keys["ukey"].sign(ukey_challenge)}
        add("approve with a hardware key", "person", approve)
        add("revoke person", "org_root", {0: 1, 1: 4, 2: ledger_id, 3: org, 5: t0 + 7, 6: nonce(7), 7: {
            1: person, 2: "left"}})

        entries = [dcbor({1: bytes.fromhex(st["statement_id"]), 2: t0 + 1000 + i, 3: bytes.fromhex(st["encoded"])})
                   for i, st in enumerate(statements)]

        # The state after every statement: [kind, id, history].
        leaves = sorted([
            [1, org, [0]],
            [1, person, [1, 4, 7]],
            [2, delegation, [2]],
            [3, record, [3, 5, 6]],
        ], key=lambda leaf: leaf[1])
        state_root = smt_root(lg, leaves)
        proofs = [{"kind": leaf[0], "id": leaf[1].hex(), "history": leaf[2],
                   "siblings": [s.hex() for s in smt_proof(lg, leaves, leaf[1])]} for leaf in leaves]

        # When checkpointing, the ledger appends its state commitment, signed
        # with the log key, as the next log entry.
        commitment_index = len(entries)
        commitment_payload = dcbor({1: ledger_id, 2: hash_id, 3: commitment_index, 4: state_root, 5: t0 + 4000})
        commitment_protected = {3: STATE_TYPE, 4: lg.kid(keys["log"])}
        commitment = lg.sign(keys["log"], commitment_protected, commitment_payload)
        commitment_id = lg.h(dcbor(["Signature1", dcbor({1: COSE["Ed25519"], **commitment_protected}), b"",
                                    commitment_payload]))
        entries.append(dcbor({1: commitment_id, 2: t0 + 1000 + commitment_index, 4: commitment}))
        oracle = lg.merkle()
        root = oracle.mth(entries)

        checkpoint_payload = dcbor({1: ledger_id, 2: hash_id, 3: len(entries), 4: root, 5: t0 + 5000})
        checkpoint = lg.sign(keys["log"], {3: CHECKPOINT_TYPE, 4: lg.kid(keys["log"])}, checkpoint_payload)
        old_size = 4
        consistency = oracle.subproof(old_size, entries, True)
        cosign_request = dcbor({1: checkpoint, 2: old_size, 3: consistency})

        ledgers.append({
            "hash": hash_id,
            "ledger_id": ledger_id.hex(),
            "statements": statements,
            "log_entries": [e.hex() for e in entries],
            "presence": {"challenge": challenge.hex(), "credential": dcbor(credential).hex(),
                         "statement_index": 5, "user_verified": True},
            "hardware_presence": {"challenge": ukey_challenge.hex(), "credential": dcbor(ukey_credential).hex(),
                                  "statement_index": 6},
            "state_root": state_root.hex(),
            "state_commitment": {"index": commitment_index, "id": commitment_id.hex(), "encoded": commitment.hex()},
            "state_proofs": proofs,
            "checkpoint": checkpoint.hex(),
            "cosign_request": cosign_request.hex(),
        })

    document = {
        "description": "CexChain protocol objects added in specification revision v0.2, built by an "
                       "independent Python encoder from spec/cexchain.cddl: a passkey and hardware key "
                       "registration (actor-set-presence), statements with proof of presence (an Ed25519 "
                       "WebAuthn assertion; a hardware key's signature over the challenge), a delegation that requires presence, the state commitment (root, "
                       "proofs, and the log entry that carries it), and a cosign request. The record's type is "
                       "a user's, example.document/1, with the generic lifecycle (regenerated in v0.9, which "
                       "removed the built-in industry types). All signatures are "
                       "Ed25519 (deterministic), so every object must be reproduced byte for byte. Keys "
                       "are throwaway test keys: seed = SHA-256(\"CexChain test key: <name>\").",
        "seeds": seeds,
        "ledgers": ledgers,
    }
    (OUT / "protocol-v0.2.json").write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote protocol vectors for {len(ledgers)} ledgers to testvectors/protocol-v0.2.json")


# ---------------------------------------------------------------------------
# Protocol v0.3 additions: access across organizations (spec/cexchain.cddl,
# revision v0.3), with HPKE (RFC 9180) implemented here from the RFC
# ---------------------------------------------------------------------------

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    import hmac
    return hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    import hmac
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def hpke_seal_base(pk_r: bytes, sk_e: bytes, info: bytes, aad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """RFC 9180 base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM,
    with the ephemeral key given (as the RFC's own test vectors do)."""
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    def labeled_extract(salt, label, ikm, suite):
        return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)

    def labeled_expand(prk, label, info_, length, suite):
        return hkdf_expand(prk, length.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info_, length)

    eph = x25519.X25519PrivateKey.from_private_bytes(sk_e)
    enc = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    dh = eph.exchange(x25519.X25519PublicKey.from_public_bytes(pk_r))
    kem_suite = b"KEM" + (0x0020).to_bytes(2, "big")
    eae_prk = labeled_extract(b"", b"eae_prk", dh, kem_suite)
    shared_secret = labeled_expand(eae_prk, b"shared_secret", enc + pk_r, 32, kem_suite)
    suite = b"HPKE" + (0x0020).to_bytes(2, "big") + (0x0001).to_bytes(2, "big") + (0x0002).to_bytes(2, "big")
    context = b"\x00" + labeled_extract(b"", b"psk_id_hash", b"", suite) + \
        labeled_extract(b"", b"info_hash", info, suite)
    secret = labeled_extract(shared_secret, b"secret", b"", suite)
    key = labeled_expand(secret, b"key", context, 32, suite)
    nonce = labeled_expand(secret, b"base_nonce", context, 12, suite)
    return enc, AESGCM(key).encrypt(nonce, plaintext, aad)


def generate_protocol_v03() -> None:
    from cryptography.hazmat.primitives.asymmetric import x25519

    def seed(name: str) -> bytes:
        return hashlib.sha256(f"CexChain test key: {name}".encode()).digest()

    factory_ledger = hashlib.sha256(b"factory ledger").digest()
    bank_ledger = hashlib.sha256(b"bank ledger").digest()
    record = hashlib.sha256(b"certificate").digest()
    request_id = hashlib.sha256(b"request").digest()
    grant_id = hashlib.sha256(b"grant").digest()
    recipient = x25519.X25519PrivateKey.from_private_bytes(seed("recipient"))
    recipient_public = recipient.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    recipient_pkcs8 = recipient.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption())

    request = {"ledger": factory_ledger, "record": record, "purpose": "loan collateral check",
               "until": 1_792_108_800_000, "recipient": recipient_public,
               "fields": ["product", "result"], "attachments": ["report.pdf"]}
    grant = {"ledger": bank_ledger, "request": request_id, "record": record, "fields": ["result"],
             "attachments": ["report.pdf"], "until": 1_791_676_800_000, "recipient": recipient_public}
    receipt = {"ledger": factory_ledger, "grant": grant_id,
               "delivery": hashlib.sha256(b"delivery").digest()}

    # The delivery's bundles are opaque here: their own format has its own vectors.
    record_bundle = b"record evidence bundle"
    grant_bundle = b"grant evidence bundle"
    contents = dcbor({1: record_bundle, 2: {"report.pdf": b"%PDF-1.7 test report"}})
    enc, ciphertext = hpke_seal_base(recipient_public, seed("ephemeral"), b"CexChain delivery v1",
                                     grant_id, contents)
    delivery = dcbor({1: 1, 2: grant_bundle, 3: {1: enc, 2: ciphertext}})

    def hexed(value):
        if isinstance(value, bytes):
            return value.hex()
        if isinstance(value, list):
            return value
        return value

    document = {
        "description": "CexChain protocol objects added in specification revision v0.3 (access across "
                       "organizations), built by an independent Python encoder from spec/cexchain.cddl: the "
                       "metadata of access requests, grants, and receipts, and a delivery whose contents are "
                       "sealed with HPKE (RFC 9180, implemented here from the RFC; base mode, X25519, "
                       "HKDF-SHA256, AES-256-GCM) using a fixed ephemeral key. Keys are throwaway test keys: "
                       "seed = SHA-256(\"CexChain test key: <name>\").",
        "access_request": {"metadata": dcbor(request).hex(), "values": {k: hexed(v) for k, v in request.items()}},
        "access_grant": {"metadata": dcbor(grant).hex(), "values": {k: hexed(v) for k, v in grant.items()}},
        "access_receipt": {"metadata": dcbor(receipt).hex(), "values": {k: hexed(v) for k, v in receipt.items()}},
        "delivery": {
            "encoded": delivery.hex(),
            "grant_bundle": grant_bundle.hex(),
            "contents": contents.hex(),
            "record_bundle": record_bundle.hex(),
            "attachments": {"report.pdf": b"%PDF-1.7 test report".hex()},
            "grant_id": grant_id.hex(),
            "info": "CexChain delivery v1",
            "recipient_pkcs8": recipient_pkcs8.hex(),
            "recipient_public_key": recipient_public.hex(),
            "encapsulated_key": enc.hex(),
        },
    }
    (OUT / "protocol-v0.3.json").write_text(json.dumps(document, indent=2) + "\n")
    print("wrote protocol vectors to testvectors/protocol-v0.3.json")


# ---------------------------------------------------------------------------
# Protocol v0.4 additions: rotating the log key and the organization's root
# key (spec/cexchain.cddl, revision v0.4)
# ---------------------------------------------------------------------------

def generate_protocol_v04() -> None:
    names = ("org_root", "log", "log_2", "root_2", "person")
    seeds = {name: hashlib.sha256(f"CexChain test key: {name}".encode()).hexdigest() for name in names}
    keys = {name: ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)) for name, seed in seeds.items()}
    t0 = 1_791_244_800_000

    def nonce(i: int) -> bytes:
        return bytes([0x40 + i]) * 16

    ledgers = []
    for hash_id in (-16, -65538):
        lg = Ledger(hash_id)
        statements = []

        def add(name, signer, payload):
            encoded, statement_id = lg.statement(keys[signer], payload)
            statements.append({"name": name, "signer": signer, "encoded": encoded.hex(),
                               "payload": dcbor(payload).hex(), "statement_id": statement_id.hex()})
            return statement_id

        ledger_id = add("genesis", "org_root", {0: 1, 1: 1, 5: t0, 6: nonce(1), 7: {
            1: hash_id, 2: "Cirraya Rotation Org", 3: ed_public(keys["org_root"]), 4: ed_public(keys["log"])}})
        org = ledger_id
        person = add("register person", "org_root", {0: 1, 1: 2, 2: ledger_id, 3: org, 5: t0 + 1, 6: nonce(2), 7: {
            1: 1, 2: "Quality Inspector", 3: ed_public(keys["person"])}})
        # Type 8: the organization replaces the log key, signing with its root key.
        add("rotate the log key", "org_root", {0: 1, 1: 8, 2: ledger_id, 3: org, 5: t0 + 2, 6: nonce(3), 7: {
            1: ed_public(keys["log_2"])}})
        # actor-rotate-key on the organization itself: the root key.
        add("rotate the root key", "org_root", {0: 1, 1: 3, 2: ledger_id, 3: org, 5: t0 + 3, 6: nonce(4), 7: {
            1: org, 2: ed_public(keys["root_2"])}})
        record = add("register record with the new root key", "root_2",
                     {0: 1, 1: 16, 2: ledger_id, 3: org, 5: t0 + 4, 6: nonce(5), 7: {
                         1: USER_TYPE, 2: lg.h(b"fields"), 3: 1}})
        log_rotation, root_rotation = 2, 3

        entries = [dcbor({1: bytes.fromhex(st["statement_id"]), 2: t0 + 1000 + i, 3: bytes.fromhex(st["encoded"])})
                   for i, st in enumerate(statements)]
        oracle = lg.merkle()

        # A checkpoint of the first two entries: the rotation at index 2 is not
        # below size 2, so the genesis log key signs it.
        before_payload = dcbor({1: ledger_id, 2: hash_id, 3: 2, 4: oracle.mth(entries[:2]), 5: t0 + 1500})
        before = lg.sign(keys["log"], {3: CHECKPOINT_TYPE, 4: lg.kid(keys["log"])}, before_payload)

        # The organization's leaf lists both rotations.
        leaves = sorted([
            [1, org, [0, log_rotation, root_rotation]],
            [1, person, [1]],
            [3, record, [4]],
        ], key=lambda leaf: leaf[1])
        state_root = smt_root(lg, leaves)
        proofs = [{"kind": leaf[0], "id": leaf[1].hex(), "history": leaf[2],
                   "siblings": [s.hex() for s in smt_proof(lg, leaves, leaf[1])]} for leaf in leaves]

        # The state commitment at index 5 and the checkpoint of size 6: the new
        # log key is in effect for both.
        commitment_index = len(entries)
        commitment_payload = dcbor({1: ledger_id, 2: hash_id, 3: commitment_index, 4: state_root, 5: t0 + 4000})
        commitment_protected = {3: STATE_TYPE, 4: lg.kid(keys["log_2"])}
        commitment = lg.sign(keys["log_2"], commitment_protected, commitment_payload)
        commitment_id = lg.h(dcbor(["Signature1", dcbor({1: COSE["Ed25519"], **commitment_protected}), b"",
                                    commitment_payload]))
        entries.append(dcbor({1: commitment_id, 2: t0 + 1000 + commitment_index, 4: commitment}))
        root = oracle.mth(entries)
        checkpoint_payload = dcbor({1: ledger_id, 2: hash_id, 3: len(entries), 4: root, 5: t0 + 5000})
        checkpoint = lg.sign(keys["log_2"], {3: CHECKPOINT_TYPE, 4: lg.kid(keys["log_2"])}, checkpoint_payload)

        # A cosign request from size 2, with both rotations and their inclusion
        # paths against the new checkpoint.
        rotations = [[i, entries[i], oracle.path(i, entries)] for i in (log_rotation, root_rotation)]
        cosign_request = dcbor({1: checkpoint, 2: 2, 3: oracle.subproof(2, entries, True), 4: rotations})

        ledgers.append({
            "hash": hash_id,
            "ledger_id": ledger_id.hex(),
            "statements": statements,
            "log_entries": [e.hex() for e in entries],
            "log_keys": [{"index": 0, "key": ed_public(keys["log"])[1].hex()},
                         {"index": log_rotation, "key": ed_public(keys["log_2"])[1].hex()}],
            "root_keys": [{"index": 0, "key": ed_public(keys["org_root"])[1].hex()},
                          {"index": root_rotation, "key": ed_public(keys["root_2"])[1].hex()}],
            "state_root": state_root.hex(),
            "state_commitment": {"index": commitment_index, "id": commitment_id.hex(), "encoded": commitment.hex()},
            "state_proofs": proofs,
            "checkpoint_before": before.hex(),
            "checkpoint": checkpoint.hex(),
            "cosign_request": {"encoded": cosign_request.hex(), "old_size": 2,
                               "old_root": oracle.mth(entries[:2]).hex()},
        })

    document = {
        "description": "CexChain protocol objects added in specification revision v0.4 (key rotation), built "
                       "by an independent Python encoder from spec/cexchain.cddl: the log key rotated with "
                       "ledger-rotate-log-key (statement type 8) and the organization's root key with "
                       "actor-rotate-key on itself, a statement under the new root key, the organization's "
                       "state leaf with both rotations, the state commitment and checkpoint signed by the new "
                       "log key, an earlier checkpoint signed by the first log key, and a cosign request "
                       "carrying both rotations with inclusion paths (key 4). The record's type is a user's, "
                       "example.document/1 (regenerated in v0.9, which removed the built-in industry types). "
                       "All signatures are Ed25519 "
                       "(deterministic). Keys are throwaway test keys: seed = SHA-256(\"CexChain test key: "
                       "<name>\").",
        "seeds": seeds,
        "ledgers": ledgers,
    }
    (OUT / "protocol-v0.4.json").write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote protocol vectors for {len(ledgers)} ledgers to testvectors/protocol-v0.4.json")


# ---------------------------------------------------------------------------
# Protocol v0.6 additions: contracts (spec section 15): contract-deploy,
# contract-call, contract-retire, scope key 7, the contract input and output,
# contract consents, contract evidence
# ---------------------------------------------------------------------------

CONTRACT_CONSENT = "cexchain.contract-consent/1"


def oracle_contract(w, entry_name="cexchain_call") -> bytes:
    """The test contract. Its arguments decide its output, so that vectors
    reach every outcome:
      - a byte string: the output is its content;
      - a text string: it aborts, with the text as the reason;
      - anything else: it accepts, with HASH(input) as the state, which checks
        the input's bytes end to end.
    The input is a map whose first key is 1, the function, so the arguments
    (key 2) follow the function's name, which must be shorter than 24 bytes.
    Imports: input_size 0, input_read 1, output_write 2, hash 3, abort 4."""
    # Function 5: a string's header at p -> (start of its content, length),
    # for lengths below 65,536.
    header = {"params": ["i32"], "results": ["i32", "i32"], "locals": ["i32"], "body": [
        ("local.get", 0), ("i32.load8_u", 0), ("i32.const", 31), ("i32.and",), ("local.set", 1),
        ("local.get", 1), ("i32.const", 24), ("i32.lt_u",),
        ("if", None),
        ("local.get", 0), ("i32.const", 1), ("i32.add",), ("local.get", 1), ("return",),
        ("end",),
        ("local.get", 1), ("i32.const", 24), ("i32.eq",),
        ("if", None),
        ("local.get", 0), ("i32.const", 2), ("i32.add",), ("local.get", 0), ("i32.load8_u", 1), ("return",),
        ("end",),
        ("local.get", 0), ("i32.const", 3), ("i32.add",),
        ("local.get", 0), ("i32.load8_u", 1), ("i32.const", 8), ("i32.shl",),
        ("local.get", 0), ("i32.load8_u", 2), ("i32.or",),
    ]}
    # Function 6, the entry. Locals: input size, the arguments' offset, their
    # major type.
    prefix = [0x82, 0x01, 0xA1, 0x01, 0x58, 0x20]  # [1, {1: h'<32 bytes>'}]
    entry = {"locals": ["i32", "i32", "i32"], "body": [
        ("call", 0), ("local.set", 0),
        ("i32.const", 0), ("call", 1),
        ("i32.const", 2), ("i32.load8_u", 0), ("i32.const", 31), ("i32.and",), ("i32.const", 4), ("i32.add",),
        ("local.set", 1),
        ("local.get", 1), ("i32.load8_u", 0), ("i32.const", 5), ("i32.shr_u",), ("local.set", 2),
        ("local.get", 2), ("i32.const", 2), ("i32.eq",),
        ("if", None),
        ("local.get", 1), ("call", 5), ("call", 2), ("return",),
        ("end",),
        ("local.get", 2), ("i32.const", 3), ("i32.eq",),
        ("if", None),
        ("local.get", 1), ("call", 5), ("call", 4), ("return",),
        ("end",),
        *[x for i, b in enumerate(prefix) for x in (("local.get", 0), ("i32.const", b), ("i32.store8", i))],
        ("i32.const", 0), ("local.get", 0), ("local.get", 0), ("i32.const", 6), ("i32.add",), ("call", 3),
        ("local.get", 0), ("i32.const", 38), ("call", 2),
    ]}
    return w.assemble([header, entry], imports=["input_size", "input_read", "output_write", "hash", "abort"],
                      memory=(4, 4), entry_name=entry_name)


# Requests (v0.8): at most 16 per call, 64 open per instance, params of at
# most 4,096 bytes, deadlines at most 366 days after the call.
MAX_REQUESTS, MAX_OPEN, MAX_PARAMS, MAX_DEADLINE = 16, 64, 4096, 366 * 86_400_000
REQUEST_KIND = re.compile(r"[a-z][a-z0-9._-]{0,63}")


def check_contract_output(output: bytes, home: bytes, children: bool = False, requests: bool = False):
    """Section 15's rules for an output: ("accept", map), ("needs", ledgers),
    or ("malformed", why). `children`: the accept may create children (key 6,
    v0.7); `requests`: it may make requests (key 7, v0.8)."""
    try:
        value = cbor2.loads(output)
        if dcbor(value) != output:
            return "malformed", "not deterministic CBOR"
    except Exception:  # noqa: BLE001 - any decoding failure
        return "malformed", "not CBOR"

    def size(v, depth):
        """(data items, nesting levels) of a decoded value."""
        if isinstance(v, list):
            inner = [size(x, depth + 1) for x in v]
        elif isinstance(v, dict):
            inner = [size(x, depth + 1) for kv in v.items() for x in kv]
        elif isinstance(v, cbor2.CBORTag):
            inner = [size(v.value, depth + 1)]
        else:
            return 1, depth
        return 1 + sum(n for n, _ in inner), max([depth + 1] + [d for _, d in inner])

    items, levels = size(value, 0)
    if items > 131_072 or levels > 32:
        return "malformed", "beyond the CBOR limits"

    def text(v, lo, hi):
        return isinstance(v, str) and lo <= len(v.encode()) <= hi

    def ledger(v):
        return isinstance(v, bytes) and len(v) == 32

    if not isinstance(value, list) or len(value) != 2 or value[0] not in (1, 2) or isinstance(value[0], bool):
        return "malformed", "not [1, accept] or [2, needs]"
    if value[0] == 2:
        needs = value[1]
        if (not isinstance(needs, list) or not 1 <= len(needs) <= 16 or not all(map(ledger, needs))
                or any(a >= b for a, b in zip(needs, needs[1:])) or home in needs):
            return "malformed", "bad needs"
        return "needs", needs
    accept = value[1]
    allowed = {1, 2, 3, 4, 5} | ({6} if children else set()) | ({7} if requests else set())
    if not isinstance(accept, dict) or 1 not in accept or not set(accept) <= allowed:
        return "malformed", "bad accept keys"

    def parties(p):
        return (isinstance(p, dict) and 1 <= len(p) <= 64
                and all(text(k, 1, 64) and ledger(v) for k, v in p.items()))

    if len(dcbor(accept[1])) > 65_536:
        return "malformed", "state too large"
    if 2 in accept and not text(accept[2], 1, 64):
        return "malformed", "bad status"
    if 3 in accept and not parties(accept[3]):
        return "malformed", "bad parties"
    if 6 in accept:
        kids = accept[6]
        if not isinstance(kids, list) or not 1 <= len(kids) <= 16:
            return "malformed", "bad children"
        for kid in kids:
            if not isinstance(kid, dict) or 1 not in kid or not set(kid) <= {1, 2, 3}:
                return "malformed", "bad child keys"
            if len(dcbor(kid[1])) > 65_536:
                return "malformed", "child state too large"
            if 2 in kid and not text(kid[2], 1, 64):
                return "malformed", "bad child status"
            if 3 in kid and not parties(kid[3]):
                return "malformed", "bad child parties"
    if 7 in accept:
        asked = accept[7]
        if not isinstance(asked, list) or not 1 <= len(asked) <= MAX_REQUESTS:
            return "malformed", "bad requests"
        for request in asked:
            if not isinstance(request, dict) or set(request) != {1, 2, 3, 4}:
                return "malformed", "bad request keys"
            if not isinstance(request[1], str) or not REQUEST_KIND.fullmatch(request[1]):
                return "malformed", "bad request kind"
            if len(dcbor(request[2])) > MAX_PARAMS:
                return "malformed", "params too large"
            if not isinstance(request[3], int) or isinstance(request[3], bool) or not 0 <= request[3] < 2**64:
                return "malformed", "bad deadline"
            if not text(request[4], 1, 64):
                return "malformed", "bad reply"
    if 4 in accept:
        e = accept[4]
        if (not isinstance(e, list) or not 1 <= len(e) <= 64
                or not all(isinstance(x, list) and len(x) == 2 and text(x[0], 1, 64) for x in e)):
            return "malformed", "bad events"
    if 5 in accept and accept[5] is not True:
        return "malformed", "final must be true"
    return "accept", accept


def generate_protocol_v06() -> None:
    import wasm_ref as w

    names = ("org_root", "log", "registrar", "clerk", "agent")
    seeds = {name: hashlib.sha256(f"CexChain test key: {name}".encode()).hexdigest() for name in names}
    keys = {name: ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)) for name, seed in seeds.items()}
    t0 = 1_791_244_800_000
    day = 86_400_000
    model = "claude-opus-5-5"
    parties = {name: hashlib.sha256(f"{name} ledger".encode()).digest() for name in ("supplier", "bank", "buyer")}
    code = oracle_contract(w)
    module = w.load(code)
    no_entry = oracle_contract(w, entry_name=None)

    ledgers = []
    for hash_id in (-16, -65538):
        lg = Ledger(hash_id)
        hash_name = HASHES[hash_id]
        statements, refused, consents, runs = [], [], [], []
        counter = [0]
        contracts, instances = {}, {}
        signers = {}  # actor id -> the signer map a contract sees

        def payload(signer_actor, body_type, body, delegation=None, provenance=None):
            counter[0] += 1
            out = {0: 1, 1: body_type, 2: ledger_id, 3: signer_actor, 5: t0 + counter[0],
                   6: bytes([counter[0]]) * 16, 7: body}
            if delegation is not None:
                out[4] = delegation
            if provenance is not None:
                out[9] = {1: provenance}
            return out

        def add(name, signer, p):
            encoded, statement_id = lg.statement(keys[signer], p)
            statements.append({"name": name, "signer": signer, "encoded": encoded.hex(),
                               "payload": dcbor(p).hex(), "statement_id": statement_id.hex()})
            return statement_id

        def refuse(name, signer, p, malformed=False):
            """`malformed`: the body breaks the CDDL, so the statement does not
            even parse; otherwise the ledger rules refuse it."""
            encoded, _ = lg.statement(keys[signer], p)
            refused.append({"name": name, "signer": signer, "encoded": encoded.hex(),
                            "payload": dcbor(p).hex(), "after": len(statements), "malformed": malformed})

        def contract_input(p, now):
            body = p[7]
            inp = {1: body[3], 2: body[4], 3: ledger_id, 6: [p[3], signers[p[3]]], 7: now}
            if 2 in body:
                inst = instances[body[2]]
                inp[4] = inst["contract"]
                view = {1: body[2], 2: inst["head"], 3: inst["state"]}
                if inst["status"] is not None:
                    view[4] = inst["status"]
                if inst["parties"]:
                    view[5] = inst["parties"]
                inp[5] = view
            else:
                inp[4] = body[1]
            if 6 in body:
                inp[8] = [[ref[0], ref[3]] for ref in body[6]]
            return dcbor(inp)

        def run_call(name, p, now, expect):
            """Runs the contract as the home would at `now`; returns the accept."""
            inp = contract_input(p, now)
            outcome, output, fuel, reason = w.run(module, inp, hash_name)
            verdict = check_contract_output(output, ledger_id)[0] if outcome == "ok" else outcome
            assert verdict == expect, f"{name}: {verdict}, expected {expect}"
            runs.append({"name": name, "after": len(statements), "input": inp.hex(), "outcome": outcome,
                         "output": output.hex(),
                         "fuel": fuel, "verdict": verdict, **({"reason": reason.hex()} if reason else {})})
            return check_contract_output(output, ledger_id)[1] if verdict == "accept" else None

        def call(name, signer, actor, body, delegation, provenance=None):
            """A call the contract accepts: registered, and applied."""
            p = payload(actor, 22, body, delegation, provenance)
            accept = run_call(name, p, t0 + 1000 + len(statements), "accept")
            statement_id = add(name, signer, p)
            index = len(statements) - 1
            if 2 in body:
                inst = instances[body[2]]
            else:
                inst = instances[statement_id] = {"contract": body[1], "parties": {}, "status": None}
            inst.update(head=index, state=accept[1], final=accept.get(5, False))
            if 2 in accept:
                inst["status"] = accept[2]
            if 3 in accept:
                inst["parties"] = accept[3]
            return statement_id

        def refused_call(name, signer, actor, body, delegation, expect=None, provenance=None, malformed=False):
            """A call the rules refuse; `expect` names what the contract does if
            the rules let it run."""
            p = payload(actor, 22, body, delegation, provenance)
            if expect is not None:
                run_call(name, p, t0 + 1000 + len(statements), expect)
            refuse(name, signer, p, malformed)

        def consent(party, instance, function, args, head, signer, reference=None):
            metadata = {"ledger": ledger_id, "instance": instance, "function": function,
                        "arguments": lg.h(dcbor(args)), "head": head, "until": t0 + 7 * day}
            if reference is not None:
                metadata["reference"] = reference
            tag = f"consent {len(consents)}: {party} to {function} of {instance.hex()[:16]} at {head}".encode()
            record = hashlib.sha256(b"consent record: " + tag).digest()
            bundle = b"consent evidence bundle: " + tag
            consents.append({"party": party, "ledger": parties[party].hex(), "record": record.hex(),
                             "metadata": dcbor(metadata).hex(), "bundle": bundle.hex(),
                             "bundle_hash": lg.h(bundle).hex(), "signer": dcbor(signer).hex()})
            return [parties[party], record, lg.h(bundle), signer]

        def on(instance, function, args, head, refs=None, reference=None):
            body = {2: instance, 3: function, 4: args, 5: head}
            if refs:
                body[6] = sorted(refs, key=lambda r: r[0])
            if reference is not None:
                body[7] = reference
            return body

        def output(value) -> bytes:
            return dcbor(value)

        genesis = {0: 1, 1: 1, 5: t0, 6: bytes([0xE0]) * 16, 7: {
            1: hash_id, 2: "Cirraya Contract Home", 3: ed_public(keys["org_root"]), 4: ed_public(keys["log"])}}
        encoded, ledger_id = lg.statement(keys["org_root"], genesis)
        statements.append({"name": "genesis", "signer": "org_root", "encoded": encoded.hex(),
                           "payload": dcbor(genesis).hex(), "statement_id": ledger_id.hex()})
        org = ledger_id
        signers[org] = {1: 0}
        supplier, bank = parties["supplier"], parties["bank"]

        registrar = add("register the registrar", "org_root", payload(org, 2, {
            1: 3, 2: "Contract Registrar", 3: ed_public(keys["registrar"])}))
        signers[registrar] = {1: 3}
        clerk = add("register a clerk", "org_root", payload(org, 2, {
            1: 1, 2: "Contracts Clerk", 3: ed_public(keys["clerk"])}))
        signers[clerk] = {1: 1}
        agent = add("register an agent", "org_root", payload(org, 2, {
            1: 2, 2: "Procurement Agent", 3: ed_public(keys["agent"]), 4: clerk, 5: {1: model}}))
        signers[agent] = {1: 2, 3: model}

        # Deploys, by the organization.
        interface = {"propose": 1, "sign": 2, "update": 2, "close": 2}
        refuse("deploy bytes that are not WebAssembly", "org_root", payload(org, 21, {
            1: b"\0asm\x01", 2: interface, 3: "wasm", 4: "hand"}))
        refuse("deploy a module without cexchain_call", "org_root", payload(org, 21, {
            1: no_entry, 2: interface, 3: "wasm", 4: "hand"}))
        refuse("deploy an interface that creates nothing", "org_root", payload(org, 21, {
            1: code, 2: {"update": 2}, 3: "wasm", 4: "hand"}), malformed=True)
        refuse("deploy a function with an empty name", "org_root", payload(org, 21, {
            1: code, 2: {"": 1}, 3: "wasm", 4: "hand"}), malformed=True)
        refuse("deploy a function of kind 3", "org_root", payload(org, 21, {
            1: code, 2: {"propose": 1, "update": 3}, 3: "wasm", 4: "hand"}), malformed=True)
        refuse("deploy in an empty language", "org_root", payload(org, 21, {
            1: code, 2: interface, 3: "", 4: "hand"}), malformed=True)
        k1 = add("deploy the test contract", "org_root", payload(org, 21, {
            1: code, 2: interface, 3: "wasm", 4: "tools/testvectors/generate.py 1",
            5: b"hand-assembled: see oracle_contract in tools/testvectors/generate.py", 6: "Oracle test contract"}))
        contracts[k1] = {"retired": False}
        k2 = add("deploy it again with a smaller interface", "org_root", payload(org, 21, {
            1: code, 2: {"propose": 1, "update": 2}, 3: "wasm", 4: "tools/testvectors/generate.py 1"}))
        contracts[k2] = {"retired": False}

        # Delegations: the registrar for calls on the first contract only; the
        # clerk for everything about contracts; the agent, under the clerk, for
        # calls on the second contract.
        d_registrar = add("delegate calls on the first contract to the registrar", "org_root", payload(org, 5, {
            1: registrar, 2: {1: [5, 22], 5: True, 7: [k1]}}))
        d_clerk = add("delegate contracts to the clerk", "org_root", payload(org, 5, {
            1: clerk, 2: {1: [5, 21, 22, 23], 5: True}}))
        refuse("the registrar delegates calls on another contract", "registrar", payload(registrar, 5, {
            1: agent, 2: {1: [22], 7: [k2]}}, d_registrar))
        refuse("the registrar delegates calls on any contract", "registrar", payload(registrar, 5, {
            1: agent, 2: {1: [22]}}, d_registrar))
        d_agent = add("the clerk delegates calls on the second contract to the agent", "clerk", payload(clerk, 5, {
            1: agent, 2: {1: [22], 7: [k2]}}, d_clerk))

        def by_registrar(name, body):
            return call(name, "registrar", registrar, body, d_registrar)

        def refused_by_registrar(name, body, expect=None, malformed=False):
            refused_call(name, "registrar", registrar, body, d_registrar, expect, malformed=malformed)

        # Instance A: proposed with three parties, the home among them.
        terms = {"amount": 12_500_000, "currency": "CNY", "goods": "Copper cathode, 100 t"}
        proposal = output([1, {1: terms, 2: "proposed",
                               3: {"buyer": ledger_id, "supplier": supplier, "bank": bank}}])
        refused_by_registrar("create with a consent", {1: k1, 3: "propose", 4: proposal, 6: [
            consent("supplier", k1, "propose", proposal, 0, {1: 1})]})
        refused_by_registrar("create with a function that acts on an instance", {1: k1, 3: "sign", 4: proposal})
        refused_by_registrar("create with a function outside the interface", {1: k1, 3: "launch", 4: proposal})
        refused_by_registrar("create on a contract that does not exist", {1: lg.h(b"nothing"), 3: "propose",
                                                                           4: proposal})
        refused_by_registrar("create with a head", {1: k1, 3: "propose", 4: proposal, 5: 0}, malformed=True)
        a = by_registrar("propose an agreement", {1: k1, 3: "propose", 4: proposal})
        refused_by_registrar("create naming an instance too", {1: k1, 2: a, 3: "propose", 4: proposal},
                             malformed=True)

        # The supplier signs (a person, with a hardware key): the state becomes
        # the hash of the input.
        head = instances[a]["head"]
        by_registrar("the supplier signs", on(a, "sign", None, head, refs=[
            consent("supplier", a, "sign", None, head, {1: 1, 2: 2})], reference="PO-2026-0815"))
        old, head = head, instances[a]["head"]
        refused_by_registrar("call with an old head", on(a, "sign", None, old, refs=[
            consent("supplier", a, "sign", None, old, {1: 1, 2: 2})]))
        refused_by_registrar("call without a head", {2: a, 3: "update", 4: None}, malformed=True)
        refused_by_registrar("call a creating function on an instance", on(a, "propose", None, head))
        refused_by_registrar("call an instance that does not exist", on(lg.h(b"nothing"), "update", None, head))
        two = [consent("supplier", a, "update", None, head, {1: 1}), consent("bank", a, "update", None, head, {1: 0})]
        descending = sorted(two, key=lambda r: r[0], reverse=True)
        refused_by_registrar("call with consents out of order", {**on(a, "update", None, head), 6: descending},
                             malformed=True)
        refused_by_registrar("call with two consents from one ledger", {**on(a, "update", None, head),
                                                                         6: [two[0], two[0]]}, malformed=True)
        refused_by_registrar("call with a consent from the home", on(a, "update", None, head, refs=[
            [ledger_id, lg.h(b"home consent"), lg.h(b"home bundle"), {1: 0}]]))
        refused_by_registrar("the contract asks for the bank's consent", on(a, "update", output([2, [bank]]), head),
                             expect="needs")
        refused_by_registrar("the contract rejects the call", on(a, "update", "the amount exceeds the credit line",
                                                                 head), expect="aborted")
        malformed = {
            "an accept without a state": output([1, {2: "effective"}]),
            "an empty status": output([1, {1: 0, 2: ""}]),
            "an unknown outcome": output([3, 0]),
            "unsorted map keys": bytes.fromhex("8201a2026165010" + "0"),
            "a trailing byte": output([1, {1: 0}]) + b"\0",
            "empty needs": output([2, []]),
            "needs the home": output([2, [ledger_id]]),
            "final false": output([1, {1: 0, 5: False}]),
            "a party that is not a ledger id": output([1, {1: 0, 3: {"bank": b"short"}}]),
            "an empty output": b"",
        }
        for what, out in malformed.items():
            refused_by_registrar(f"the contract writes {what}", on(a, "update", out, head), expect="malformed")
        refused_call("the agent calls the first contract", "agent", agent, on(a, "update", None, head), d_agent,
                     provenance=model)

        # The supplier (passkey) and the bank (an agent) consent to the
        # agreement taking effect.
        effective = output([1, {1: {**terms, "signed": True}, 2: "effective",
                                4: [["signed", {"by": ["supplier", "bank"]}], ["effective", None]]}])
        by_registrar("the agreement takes effect", on(a, "update", effective, head, refs=[
            consent("supplier", a, "update", effective, head, {1: 1, 2: 1}),
            consent("bank", a, "update", effective, head, {1: 2, 3: "risk-model-7"}, reference="Credit line 0042")]))
        head = instances[a]["head"]

        # Instance B, on the second contract, created by the agent.
        b = call("the agent proposes on the second contract", "agent", agent, {1: k2, 3: "propose", 4: None},
                 d_agent, provenance=model)
        refuse("retire without authority", "registrar", payload(registrar, 23, {1: k2}, d_registrar))
        add("the clerk retires the second contract", "clerk", payload(clerk, 23, {1: k2, 2: "superseded"}, d_clerk))
        contracts[k2]["retired"] = True
        refuse("retire it again", "clerk", payload(clerk, 23, {1: k2}, d_clerk))
        refuse("retire a contract that does not exist", "clerk", payload(clerk, 23, {1: lg.h(b"nothing")}, d_clerk))
        refused_call("create on a retired contract", "agent", agent, {1: k2, 3: "propose", 4: None}, d_agent,
                     provenance=model)
        call("the agent updates its instance of the retired contract", "agent", agent,
             on(b, "update", None, instances[b]["head"]), d_agent, provenance=model)

        # A closes, and takes no more calls.
        by_registrar("close the agreement", on(a, "close", output([1, {1: "done", 2: "settled", 5: True}]), head))
        refused_by_registrar("call a final instance", on(a, "update", None, instances[a]["head"]))

        def pins(instance):
            out = []
            for st in statements:
                p = cbor2.loads(bytes.fromhex(st["payload"]))
                if p[1] == 22 and p[7].get(2) == instance:
                    out += [ref[2] for ref in p[7].get(6, [])]
            return out

        bundle_by_hash = {bytes.fromhex(c["bundle_hash"]): bytes.fromhex(c["bundle"]) for c in consents}
        instance_bundle = b"the agreement's evidence bundle"
        evidence = dcbor({0: 1, 1: instance_bundle, 2: [bundle_by_hash[h] for h in pins(a)]})

        ledgers.append({
            "hash": hash_id,
            "ledger_id": ledger_id.hex(),
            "parties": {name: value.hex() for name, value in parties.items()},
            "statements": statements,
            "refused": refused,
            "runs": runs,
            "consents": consents,
            "contracts": [{"id": k.hex(), "retired": v["retired"]} for k, v in contracts.items()],
            "instances": [{"id": k.hex(), "contract": v["contract"].hex(), "head": v["head"],
                           "state": dcbor(v["state"]).hex(), "status": v["status"],
                           "parties": {r: l.hex() for r, l in v["parties"].items()}, "final": v["final"]}
                          for k, v in instances.items()],
            "contract_evidence": {"encoded": evidence.hex(), "instance_bundle": instance_bundle.hex(),
                                  "pins": [h.hex() for h in pins(a)]},
        })

    document = {
        "description": "CexChain protocol objects added in specification revision v0.6 (contracts), built by an "
                       "independent Python encoder from spec/cexchain.cddl and run by the reference interpreter "
                       "tools/testvectors/wasm_ref.py. The test contract (oracle_contract in "
                       "tools/testvectors/generate.py) outputs the content of byte-string arguments, aborts with "
                       "text arguments, and otherwise accepts with HASH(input) as the state. A home ledger "
                       "deploys it twice; a registrar (a device, scope key 7: the first contract), a clerk (a "
                       "person), and an agent (under the clerk, scope key 7: the second contract) create and call "
                       "instances, citing consents from other ledgers; the clerk retires the second contract. "
                       "Statements are registered at t0 + 1000 + index; refused statements either break the CDDL "
                       "(`malformed`: they do not parse) or are validated against "
                       "the state after the first `after` statements, at t0 + 1000 + after. `runs` lists every "
                       "contract run, after the first `after` statements: the input the home builds, and the "
                       "outcome, output, fuel, and verdict "
                       "(accept, needs, malformed, or the trap). `instances` gives each instance's final state "
                       "(encoded), status, parties, head, and finality. Consent records and bundles of other "
                       "ledgers are opaque bytes; a citation pins HASH(bundle) under the home's hash. Signatures "
                       "are Ed25519 (deterministic); keys are throwaway: seed = SHA-256(\"CexChain test key: "
                       "<name>\").",
        "t0": 1_791_244_800_000,
        "contract": code.hex(),
        "seeds": seeds,
        "ledgers": ledgers,
    }
    (OUT / "protocol-v0.6.json").write_text(json.dumps(document, indent=1) + "\n")
    print(f"wrote protocol vectors for {len(ledgers)} ledgers to testvectors/protocol-v0.6.json: "
          f"{len(ledgers[0]['statements'])} statements, {len(ledgers[0]['refused'])} refused, "
          f"{len(ledgers[0]['runs'])} contract runs")


# ---------------------------------------------------------------------------
# Protocol v0.7 additions: instances created by a call (spec section 15,
# "Instances created by a call"): accept key 6, child ids, instance-view key
# 6, the depth limit, children's state leaves, and evidence for a child
# ---------------------------------------------------------------------------

MAX_DEPTH = 8


def encode_log_entry(statement_id: bytes, registered_at: int, statement: bytes | None = None,
                     commitment: bytes | None = None) -> bytes:
    entry = {1: statement_id, 2: registered_at}
    if statement is not None:
        entry[3] = statement
    else:
        entry[4] = commitment
    return dcbor(entry)


def append_state_commitment(lg: Ledger, log_key, ledger_id: bytes, entries: list, leaves: list,
                            timestamp: int) -> bytes:
    """Appends the commitment to `leaves` (the state after every entry) as the
    next log entry; returns its id."""
    index = len(entries)
    payload = dcbor({1: ledger_id, 2: lg.hash_id, 3: index, 4: smt_root(lg, leaves), 5: timestamp})
    protected = {3: STATE_TYPE, 4: lg.kid(log_key)}
    commitment = lg.sign(log_key, protected, payload)
    commitment_id = lg.h(dcbor(["Signature1", dcbor({1: COSE["Ed25519"], **protected}), b"", payload]))
    entries.append(encode_log_entry(commitment_id, timestamp, commitment=commitment))
    return commitment_id


def sign_log_checkpoint(lg: Ledger, log_key, ledger_id: bytes, entries: list, timestamp: int) -> tuple[bytes, bytes]:
    root = lg.merkle().mth(entries)
    payload = dcbor({1: ledger_id, 2: lg.hash_id, 3: len(entries), 4: root, 5: timestamp})
    return lg.sign(log_key, {3: CHECKPOINT_TYPE, 4: lg.kid(log_key)}, payload), root


def make_bundle(lg: Ledger, log_key, entries: list, checkpoint: bytes, root: bytes, subject: bytes,
                indices, proofs: list) -> bytes:
    """An evidence bundle: the entries at `indices` with their receipts
    against the checkpoint over every entry, and the state proofs
    ([leaf, siblings] each, in the order given)."""
    tree = lg.merkle()
    listed = []
    for index in sorted(indices):
        proof = dcbor([len(entries), index, tree.path(index, entries)])
        receipt = lg.sign(log_key, {4: lg.kid(log_key), 395: VDS[lg.hash_id]}, root,
                          unprotected={396: {-1: [proof]}}, detached=True)
        listed.append([entries[index], receipt])
    bundle = {0: 1, 1: subject, 2: listed, 3: checkpoint}
    if proofs:
        bundle[7] = proofs
    return dcbor(bundle)


class PartyLedger:
    """Another organization's ledger. Its organization registers contract
    consents itself (signer kind 0), each followed by a state commitment and
    a checkpoint, and gives each consent's complete evidence bundle."""

    def __init__(self, name: str, hash_id: int, t0: int):
        self.lg = Ledger(hash_id)
        self.name = name
        self.root_key, self.log_key = (ed25519.Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(f"CexChain test key: {name} {role}".encode()).digest()) for role in ("root", "log"))
        self.t0 = t0
        genesis = {0: 1, 1: 1, 5: t0, 6: bytes([0xE1]) * 16, 7: {
            1: hash_id, 2: name, 3: ed_public(self.root_key), 4: ed_public(self.log_key)}}
        encoded, self.id = self.lg.statement(self.root_key, genesis)
        self.entries = [encode_log_entry(self.id, t0, encoded)]
        self.leaves = {self.id: [1, self.id, [0]]}
        self.consents = 0

    def consent(self, metadata: dict) -> tuple[bytes, bytes]:
        """Registers a cexchain.contract-consent/1 record; returns its id and
        its evidence bundle."""
        self.consents += 1
        index = len(self.entries)
        now = self.t0 + 10 * index
        leaf = dcbor(["note", bytes([0xC0 + self.consents]) * 16, f"consent {self.consents}"])
        payload = {0: 1, 1: 16, 2: self.id, 3: self.id, 5: now, 6: bytes([0xD0 + self.consents]) * 16, 7: {
            1: CONTRACT_CONSENT, 2: self.lg.merkle().mth([leaf]), 3: 1, 5: metadata}}
        encoded, record = self.lg.statement(self.root_key, payload)
        self.entries.append(encode_log_entry(record, now, encoded))
        self.leaves[record] = [3, record, [index]]
        leaves = sorted(self.leaves.values(), key=lambda x: x[1])
        append_state_commitment(self.lg, self.log_key, self.id, self.entries, leaves, now + 1)
        checkpoint, root = sign_log_checkpoint(self.lg, self.log_key, self.id, self.entries, now + 1)
        proofs = [[self.leaves[i], smt_proof(self.lg, leaves, i)] for i in (record, self.id)]
        bundle = make_bundle(self.lg, self.log_key, self.entries, checkpoint, root, record,
                             [0, index, len(self.entries) - 1], proofs)
        return record, bundle


def generate_protocol_v07() -> None:
    import wasm_ref as w
    import test_contracts

    names = ("org_root", "log", "registrar", "clerk")
    seeds = {name: hashlib.sha256(f"CexChain test key: {name}".encode()).hexdigest() for name in names}
    keys = {name: ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)) for name, seed in seeds.items()}
    t0 = 1_791_331_200_000  # 2026-10-07T00:00:00Z
    day = 86_400_000
    split_code, oracle_code = test_contracts.split_contract(), oracle_contract(w)
    modules = {}

    ledgers = []
    for hash_id in (-16, -65538):
        lg = Ledger(hash_id)
        hash_name = HASHES[hash_id]
        statements, payloads, refused, runs, consents, children = [], [], [], [], [], []
        contracts, instances, actors, delegations = {}, {}, {}, {}
        signers = {}  # actor id -> the signer map a contract sees
        party = {name: PartyLedger(name, hash_id, t0) for name in ("Supplier", "Tier-2 A", "Tier-3 C")}
        others = {name: hashlib.sha256(f"{name} ledger".encode()).digest() for name in ("Tier-2 B", "Tier-3 D", "Bank")}
        ledger_of = {**{name: p.id for name, p in party.items()}, **others}
        bundle_of = {}  # HASH(bundle) under the home's hash -> bundle

        def payload(signer_actor, body_type, body, delegation=None):
            n = len(statements) + len(refused) + 1
            out = {0: 1, 1: body_type, 2: ledger_id, 3: signer_actor, 5: t0 + n, 6: n.to_bytes(16, "big"), 7: body}
            if delegation is not None:
                out[4] = delegation
            return out

        def add(name, signer, p):
            encoded, statement_id = lg.statement(keys[signer], p)
            statements.append({"name": name, "signer": signer, "encoded": encoded.hex(),
                               "payload": dcbor(p).hex(), "statement_id": statement_id.hex()})
            payloads.append(p)
            return statement_id

        def refuse(name, signer, p, why, malformed=False):
            """`malformed`: the body breaks the CDDL, so the statement does not
            even parse; otherwise the ledger rules refuse it (`why`)."""
            encoded, _ = lg.statement(keys[signer], p)
            refused.append({"name": name, "signer": signer, "encoded": encoded.hex(), "payload": dcbor(p).hex(),
                            "after": len(statements), "malformed": malformed, "why": why})

        def view(instance_id):
            inst = instances[instance_id]
            out = {1: instance_id, 2: inst["head"], 3: inst["state"]}
            if inst["status"] is not None:
                out[4] = inst["status"]
            if inst["parties"]:
                out[5] = inst["parties"]
            if inst["parent"] is not None:
                out[6] = [inst["parent"], inst["depth"]]
            return out

        def contract_input(p, now):
            body = p[7]
            inp = {1: body[3], 2: body[4], 3: ledger_id, 6: [p[3], signers[p[3]]], 7: now}
            if 2 in body:
                inp[4] = instances[body[2]]["contract"]
                inp[5] = view(body[2])
            else:
                inp[4] = body[1]
            if 6 in body:
                inp[8] = [[ref[0], ref[3]] for ref in body[6]]
            return dcbor(inp)

        def rule(p):
            """The section 15 rules that do not need the contract's output, as
            far as these vectors reach; None when they hold."""
            body = p[7]
            if 2 in body:
                inst = instances.get(body[2])
                if inst is None:
                    return "no such instance"
                if inst["final"]:
                    return "final"
                if body[5] != inst["head"]:
                    return "head"
                contract = inst["contract"]
            else:
                contract = body[1]
                if contracts[contract]["retired"]:
                    return "retired"
            scope = delegations[p[4]]["scope"] if 4 in p else None
            if scope is not None and (22 not in scope[1] or (7 in scope and contract not in scope[7])):
                return "authority"
            return None

        def run_call(name, p, now, expect):
            """Runs the contract as the home would at `now`; returns the accept."""
            body = p[7]
            contract = instances[body[2]]["contract"] if 2 in body else body[1]
            inp = contract_input(p, now)
            outcome, output, fuel, reason = w.run(modules[contract], inp, hash_name)
            checked = check_contract_output(output, ledger_id, children=True) if outcome == "ok" else (outcome,)
            verdict = checked[0]
            assert verdict == expect, f"{name}: {verdict}, expected {expect}"
            runs.append({"name": name, "after": len(statements), "contract": contract.hex(), "input": inp.hex(),
                         "outcome": outcome, "output": output.hex(), "fuel": fuel, "verdict": verdict,
                         **({"reason": reason.hex()} if reason else {})})
            return checked[1] if verdict == "accept" else None

        def children_rule(p, accept):
            if 6 not in accept:
                return None
            body = p[7]
            contract = instances[body[2]]["contract"] if 2 in body else body[1]
            if contracts[contract]["retired"]:
                return "retired"
            if 2 in body and instances[body[2]]["depth"] >= MAX_DEPTH:
                return "depth"
            return None

        def call(name, signer, actor, body, delegation):
            """A call the rules and the contract accept: registered, and
            applied, children included."""
            p = payload(actor, 22, body, delegation)
            assert rule(p) is None, (name, rule(p))
            now = t0 + 1000 + len(statements)
            accept = run_call(name, p, now, "accept")
            assert children_rule(p, accept) is None, name
            statement_id = add(name, signer, p)
            index = len(statements) - 1
            if 2 in body:
                target = body[2]
            else:
                target = statement_id
                instances[target] = {"contract": body[1], "parties": {}, "status": None, "history": [],
                                     "parent": None, "depth": 0, "created_by": None, "position": None}
            inst = instances[target]
            inst.update(head=index, state=accept[1], final=accept.get(5, False))
            inst["history"].append(index)
            if 2 in accept:
                inst["status"] = accept[2]
            if 3 in accept:
                inst["parties"] = accept[3]
            made = []
            for position, child in enumerate(accept.get(6, [])):
                child_id = lg.h(dcbor([statement_id, position]))
                assert child_id not in instances
                instances[child_id] = {"contract": inst["contract"], "head": index, "state": child[1],
                                       "status": child.get(2), "parties": child.get(3, {}), "final": False,
                                       "history": [index], "parent": target, "depth": inst["depth"] + 1,
                                       "created_by": index, "position": position}
                children.append({"call": statement_id.hex(), "position": position, "id": child_id.hex()})
                made.append(child_id)
            return statement_id, made

        def refused_call(name, signer, actor, body, delegation, why, expect=None, malformed=False):
            """A call that is refused: by the rules before the contract runs
            (`why`, no `expect`), or after it, `expect` naming its verdict:
            refused for that verdict, or (an accept) by the children rules."""
            p = payload(actor, 22, body, delegation)
            if not malformed:
                assert rule(p) == (why if expect is None else None), (name, rule(p))
            if expect is not None:
                accept = run_call(name, p, t0 + 1000 + len(statements), expect)
                if accept is not None:
                    assert children_rule(p, accept) == why, (name, children_rule(p, accept))
            refuse(name, signer, p, why, malformed)

        def consent(party_name, instance, function, args, head):
            """A consent from a party ledger: its record, evidence bundle, and
            the call's citation of it."""
            metadata = {"ledger": ledger_id, "instance": instance, "function": function,
                        "arguments": lg.h(dcbor(args)), "head": head, "until": t0 + 7 * day}
            record, bundle = party[party_name].consent(metadata)
            digest = lg.h(bundle)
            bundle_of[digest] = bundle
            signer = {1: 0}
            consents.append({"party": party_name, "ledger": party[party_name].id.hex(), "record": record.hex(),
                             "metadata": dcbor(metadata).hex(), "bundle": bundle.hex(), "bundle_hash": digest.hex(),
                             "signer": dcbor(signer).hex()})
            return [party[party_name].id, record, digest, signer]

        def on(instance, function, args, refs=None, head=None):
            body = {2: instance, 3: function, 4: args, 5: instances[instance]["head"] if head is None else head}
            if refs:
                body[6] = sorted(refs, key=lambda r: r[0])
            return body

        genesis = {0: 1, 1: 1, 5: t0, 6: bytes([0xE0]) * 16, 7: {
            1: hash_id, 2: "Cirraya Split Home", 3: ed_public(keys["org_root"]), 4: ed_public(keys["log"])}}
        encoded, ledger_id = lg.statement(keys["org_root"], genesis)
        statements.append({"name": "genesis", "signer": "org_root", "encoded": encoded.hex(),
                           "payload": dcbor(genesis).hex(), "statement_id": ledger_id.hex()})
        payloads.append(genesis)
        org = ledger_id
        home = ledger_id
        signers[org] = {1: 0}

        def actor(name, signer_key, kind, label):
            actor_id = add(name, "org_root", payload(org, 2, {1: kind, 2: label, 3: ed_public(keys[signer_key])}))
            actors[actor_id] = {"index": len(statements) - 1}
            signers[actor_id] = {1: kind}
            return actor_id

        registrar = actor("register the registrar", "registrar", 3, "Contract Registrar")
        clerk = actor("register a clerk", "clerk", 1, "Contracts Clerk")

        def deploy(name, code, interface, label):
            contract_id = add(name, "org_root", payload(org, 21, {
                1: code, 2: interface, 3: "wasm", 4: "tools/testvectors 1",
                5: b"hand-assembled: see tools/testvectors/test_contracts.py and generate.py", 6: label}))
            contracts[contract_id] = {"history": [len(statements) - 1], "retired": False}
            modules[contract_id] = w.load(code)
            return contract_id

        k_split = deploy("deploy the splitting contract", split_code, test_contracts.SPLIT_FUNCTIONS,
                         "Splitting receivable")
        k_oracle = deploy("deploy the oracle contract", oracle_code, {"propose": 1, "update": 2},
                          "Oracle test contract")

        def delegate(name, grantee, scope):
            d = add(name, "org_root", payload(org, 5, {1: grantee, 2: scope}))
            delegations[d] = {"index": len(statements) - 1, "grantor": org, "parent": None, "scope": scope}
            return d

        d_registrar = delegate("delegate calls on both contracts to the registrar", registrar,
                               {1: [22], 7: sorted([k_split, k_oracle])})
        d_clerk = delegate("delegate calls on the oracle contract to the clerk", clerk, {1: [22], 7: [k_oracle]})

        def by_registrar(name, body):
            return call(name, "registrar", registrar, body, d_registrar)

        def refused_by_registrar(name, body, why, expect=None, malformed=False):
            refused_call(name, "registrar", registrar, body, d_registrar, why, expect, malformed)

        supplier, tier2_a, tier2_b = ledger_of["Supplier"], ledger_of["Tier-2 A"], ledger_of["Tier-2 B"]
        tier3_c, tier3_d, bank = ledger_of["Tier-3 C"], ledger_of["Tier-3 D"], ledger_of["Bank"]

        # The receivable R1, split twice: tier 1 to tier 2, then tier 2 to
        # tier 3; a tier-3 part moves on.
        r1, _ = by_registrar("issue a receivable", {1: k_split, 3: "issue", 4: [supplier, 1_000_000]})
        parts = [[tier2_a, 600_000], [tier2_b, 400_000]]
        refused_by_registrar("split without the holder's consent", on(r1, "split", parts), "contract", "needs")
        refused_by_registrar("split into parts that do not add up", on(r1, "split", [[tier2_a, 600_000]], refs=[
            consent("Supplier", r1, "split", [[tier2_a, 600_000]], instances[r1]["head"])]), "contract", "aborted")
        refused_by_registrar("split with a part of zero", on(r1, "split", [[tier2_a, 0], [tier2_b, 1_000_000]]),
                             "contract", "aborted")
        split1, (a, b) = by_registrar("split the receivable in two", on(r1, "split", parts, refs=[
            consent("Supplier", r1, "split", parts, instances[r1]["head"])]))
        refused_by_registrar("transfer the split receivable", on(r1, "transfer", bank), "final")
        refused_by_registrar("transfer a third part, which the split did not make",
                             on(lg.h(dcbor([split1, 2])), "transfer", bank, head=instances[a]["head"]),
                             "no such instance")
        refused_by_registrar("split a part at its parent's old head",
                             on(a, "split", [[tier3_c, 600_000]], head=instances[r1]["history"][0]), "head")
        refused_call("the clerk, delegated for the oracle contract only, transfers a part", "clerk", clerk,
                     on(b, "transfer", bank), d_clerk, "authority")
        parts = [[tier3_c, 250_000], [tier3_d, 350_000]]
        _, (c, d) = by_registrar("split a tier-2 part", on(a, "split", parts, refs=[
            consent("Tier-2 A", a, "split", parts, instances[a]["head"])]))
        by_registrar("transfer a tier-3 part to the bank", on(c, "transfer", bank, refs=[
            consent("Tier-3 C", c, "transfer", bank, instances[c]["head"])]))
        refused_by_registrar("transfer it again at its old head", on(c, "transfer", tier3_c,
                             head=instances[c]["history"][0]), "head")

        # R2, never split: its evidence verifies under the rules of v0.6.
        r2, _ = by_registrar("issue a second receivable", {1: k_split, 3: "issue", 4: [supplier, 5_000]})
        by_registrar("transfer the second receivable to the bank", on(r2, "transfer", bank, refs=[
            consent("Supplier", r2, "transfer", bank, instances[r2]["head"])]))

        # R3, held by the home (no consents), split one part at a time down
        # to the depth limit.
        r3, _ = by_registrar("issue a receivable to the home", {1: k_split, 3: "issue", 4: [home, 100]})
        level = r3
        for depth in range(1, MAX_DEPTH + 1):
            _, (level,) = by_registrar(f"split it to depth {depth}", on(level, "split", [[home, 100]]))
        refused_by_registrar("split at depth 8", on(level, "split", [[home, 100]]), "depth", "accept")
        by_registrar("transfer the part at depth 8", on(level, "transfer", supplier))

        # R4: 17 parts are too many; 16 are allowed.
        r4, _ = by_registrar("issue a receivable of 17", {1: k_split, 3: "issue", 4: [home, 17]})
        refused_by_registrar("split into 17 parts", on(r4, "split", [[ledger_of["Bank"], 1]] * 17),
                             "contract", "malformed")
        sixteen = [[bytes([0x60 + i]) * 32, 1] for i in range(15)] + [[bank, 2]]
        by_registrar("split into 16 parts", on(r4, "split", sixteen))

        # The oracle contract: a creation that makes children, malformed
        # children, a parent that carries on, a call on a child, and a retire.
        def out(value) -> bytes:
            return dcbor(value)

        o1, (o1c0, o1c1) = call("the clerk creates an instance with two children", "clerk", clerk, {
            1: k_oracle, 3: "propose", 4: out([1, {1: "parent", 2: "open", 3: {"buyer": home}, 6: [
                {1: "first"}, {1: {"second": 2}, 2: "draft", 3: {"bank": bank, "buyer": home}}]}])}, d_clerk)
        malformed = {
            "no children": out([1, {1: 0, 6: []}]),
            "17 children": out([1, {1: 0, 6: [{1: i} for i in range(17)]}]),
            "children that are not an array": out([1, {1: 0, 6: {1: 0}}]),
            "a child without a state": out([1, {1: 0, 6: [{2: "draft"}]}]),
            "a child with events": out([1, {1: 0, 6: [{1: 0, 4: [["made", None]]}]}]),
            "a final child": out([1, {1: 0, 6: [{1: 0, 5: True}]}]),
            "a child with an empty status": out([1, {1: 0, 6: [{1: 0, 2: ""}]}]),
            "a child with no parties": out([1, {1: 0, 6: [{1: 0, 3: {}}]}]),
            "a child whose party is not a ledger id": out([1, {1: 0, 6: [{1: 0, 3: {"bank": b"short"}}]}]),
            "a child that is not a map": out([1, {1: 0, 6: [0]}]),
        }
        for what, output in malformed.items():
            refused_by_registrar(f"the contract writes {what}", on(o1, "update", output), "contract", "malformed")
        _, (o1c2,) = by_registrar("the parent makes a third child and carries on", on(o1, "update", out(
            [1, {1: "parent, again", 4: [["child", 2]], 6: [{1: "third", 2: "draft"}]}])))
        by_registrar("the parent carries on", on(o1, "update", None))
        by_registrar("a call on the first child, which sees its parent", on(o1c0, "update", None))
        add("retire the oracle contract", "org_root", payload(org, 23, {1: k_oracle, 2: "superseded"}))
        contracts[k_oracle]["history"].append(len(statements) - 1)
        contracts[k_oracle]["retired"] = True
        refused_by_registrar("make a child on a retired contract", on(o1, "update", out([1, {1: 0, 6: [{1: 0}]}])),
                             "retired", "accept")
        by_registrar("the parent carries on after the retire", on(o1, "update", None))
        by_registrar("its second child carries on too", on(o1c1, "update", out([1, {1: "done", 5: True}])))

        # The state, its commitment, and the checkpoint over everything.
        entries = [encode_log_entry(bytes.fromhex(st["statement_id"]), t0 + 1000 + i, bytes.fromhex(st["encoded"]))
                   for i, st in enumerate(statements)]
        leaves = {org: [1, org, [0]]}
        for actor_id, info in actors.items():
            leaves[actor_id] = [1, actor_id, [info["index"]]]
        for d_id, info in delegations.items():
            leaves[d_id] = [2, d_id, [info["index"]]]
        for k_id, info in contracts.items():
            leaves[k_id] = [4, k_id, info["history"]]
        for i_id, info in instances.items():
            leaves[i_id] = [5, i_id, info["history"]]
        sorted_leaves = sorted(leaves.values(), key=lambda x: x[1])
        commitment_index = len(entries)
        commitment_id = append_state_commitment(lg, keys["log"], ledger_id, entries, sorted_leaves,
                                                t0 + 1000 + commitment_index)
        checkpoint, root = sign_log_checkpoint(lg, keys["log"], ledger_id, entries, t0 + 1000 + commitment_index)

        def instance_evidence(subject):
            """The subject's evidence bundle (section 11), with its ancestors'
            histories up to each creating call, and its contract evidence."""
            inst = instances[subject]
            events = set(inst["history"])
            node = inst
            while node["parent"] is not None:
                parent = instances[node["parent"]]
                events |= {i for i in parent["history"] if i <= node["created_by"]}
                node = parent
            events = sorted(events)
            involved = []

            def involve(object_id):
                if object_id not in involved:
                    involved.append(object_id)

            involve(subject)
            involve(inst["contract"])
            for i in events:
                p = payloads[i]
                involve(p[3])
                delegation = p.get(4)
                while delegation is not None:
                    involve(delegation)
                    involve(delegations[delegation]["grantor"])
                    delegation = delegations[delegation]["parent"]
            needed = {0, commitment_index, *events}
            for object_id in involved:
                needed |= set(leaves[object_id][2])
            work = sorted(needed - {0, commitment_index})
            while work:
                p = payloads[work.pop()]
                deps = []
                if p[3] != org:
                    deps.append(actors[p[3]]["index"])
                if 4 in p:
                    deps.append(delegations[p[4]]["index"])
                body = p[7]
                if p[1] == 2 and 4 in body:
                    deps.append(actors[body[4]]["index"])
                elif p[1] == 5:
                    deps.append(actors[body[1]]["index"])
                elif p[1] == 22:
                    contract = body[1] if 1 in body else instances[body[2]]["contract"]
                    deps.append(contracts[contract]["history"][0])
                elif p[1] == 23:
                    deps.append(contracts[body[1]]["history"][0])
                for dep in deps:
                    if dep not in needed:
                        needed.add(dep)
                        work.append(dep)
            proofs = [[leaves[i], smt_proof(lg, sorted_leaves, i)] for i in involved]
            bundle = make_bundle(lg, keys["log"], entries, checkpoint, root, subject, needed, proofs)
            pins = []
            for i in events:
                for ref in payloads[i][7].get(6, []) if payloads[i][1] == 22 else []:
                    if ref[2] not in pins:
                        pins.append(ref[2])
            evidence = {0: 1, 1: bundle}
            if pins:
                evidence[2] = [bundle_of[h] for h in pins]
            ancestors = []
            node = inst
            while node["parent"] is not None:
                ancestors.insert(0, {"id": node["parent"].hex(), "until": node["created_by"]})
                node = instances[node["parent"]]
            return {"subject": subject.hex(), "depth": inst["depth"], "ancestors": ancestors, "events": events,
                    "entries": sorted(needed), "involved": [i.hex() for i in involved],
                    "pins": [h.hex() for h in pins],
                    "contract_evidence": dcbor(evidence).hex()}

        ledgers.append({
            "hash": hash_id,
            "ledger_id": ledger_id.hex(),
            "parties": {name: value.hex() for name, value in ledger_of.items()},
            "statements": statements,
            "refused": refused,
            "runs": runs,
            "consents": consents,
            "children": children,
            "contracts": [{"id": k.hex(), "retired": v["retired"], "history": v["history"]}
                          for k, v in contracts.items()],
            "instances": [{"id": k.hex(), "contract": v["contract"].hex(), "head": v["head"],
                           "state": dcbor(v["state"]).hex(), "status": v["status"],
                           "parties": {r: l.hex() for r, l in v["parties"].items()}, "final": v["final"],
                           "history": v["history"], "depth": v["depth"],
                           "parent": v["parent"].hex() if v["parent"] is not None else None,
                           "created_by": v["created_by"], "position": v["position"]}
                          for k, v in instances.items()],
            "log_entries": [e.hex() for e in entries],
            "state_leaves": [{"kind": leaf[0], "id": leaf[1].hex(), "history": leaf[2]} for leaf in sorted_leaves],
            "state_root": smt_root(lg, sorted_leaves).hex(),
            "state_commitment": {"index": commitment_index, "id": commitment_id.hex()},
            "checkpoint": checkpoint.hex(),
            "evidence": {
                "never split": instance_evidence(r2),
                "tier-3 part": instance_evidence(c),
                "child of a parent that carried on": instance_evidence(o1c0),
            },
        })

    document = {
        "description": "CexChain protocol objects added in specification revision v0.7 (instances created by a "
                       "call), built by an independent Python encoder from spec/cexchain.cddl and run by the "
                       "reference interpreter tools/testvectors/wasm_ref.py. Two hand-assembled contracts: the "
                       "splitting contract (split_contract in tools/testvectors/test_contracts.py: a receivable "
                       "[amount, tier] held by {holder}, which splits into child parts and needs the holder's "
                       "consent unless the holder is the home) and the v0.6 oracle contract (its byte-string "
                       "arguments are its output; text aborts; anything else accepts with HASH(input) as the "
                       "state). A registrar (a device; scope key 7: both contracts) and a clerk (a person; the "
                       "oracle contract only) make calls; consents come from real party ledgers (on the home's "
                       "hash), each with its complete evidence bundle. Statements are registered at t0 + 1000 + "
                       "index; refused statements either break the CDDL (`malformed`) or are validated against "
                       "the state after the first `after` statements, at t0 + 1000 + after; `why` names the "
                       "rule (final, head, authority, depth, retired) or `contract` when the contract's run "
                       "refuses it (its run says how). `runs` lists every contract run: the contract, the "
                       "input the home builds (a child's instance view has key 6, [parent, depth]), and the "
                       "outcome, output, fuel, and verdict. `children` lists each child's id, HASH([call, "
                       "position]). `instances` gives each instance's final state (encoded), status, parties, "
                       "head, finality, history, depth, parent, creating call's index, and position. "
                       "`log_entries` holds the whole log, ending with the state commitment over "
                       "`state_leaves`; `checkpoint` covers it. `evidence` holds the contract evidence (with "
                       "the instance's evidence bundle) of three instances: one never split, a tier-3 part "
                       "(with its ancestors' histories up to each split), and a child whose parent carried on "
                       "after creating it; each with its depth, its ancestors (and the index of the call that "
                       "made the next generation), the calls it shows (`events`), the log indices it holds "
                       "(`entries`), the objects it proves (`involved`: the instance, its contract, then each "
                       "event's signer, delegations, and grantors, in log order), and the consent bundles' "
                       "hashes (`pins`). Signatures are Ed25519 (deterministic); keys are throwaway: seed = "
                       "SHA-256(\"CexChain test key: <name>\"), and for party ledgers \"<name> root\" and "
                       "\"<name> log\".",
        "t0": t0,
        "max_depth": MAX_DEPTH,
        "contracts": {"split": split_code.hex(), "oracle": oracle_code.hex()},
        "seeds": seeds,
        "ledgers": ledgers,
    }
    (OUT / "protocol-v0.7.json").write_text(json.dumps(document, indent=1) + "\n")
    first = ledgers[0]
    print(f"wrote protocol vectors for {len(ledgers)} ledgers to testvectors/protocol-v0.7.json: "
          f"{len(first['statements'])} statements, {len(first['refused'])} refused, {len(first['runs'])} "
          f"contract runs, {len(first['children'])} children, {len(first['consents'])} consents")


# ---------------------------------------------------------------------------
# Protocol v0.8 additions: requests and answers (spec section 15, "Requests
# and answers"): accept key 7, request ids, contract-call key 8, input key 9,
# scope keys 8 and 9, the limits, answers on final instances, and evidence
# showing requests
# ---------------------------------------------------------------------------

def request_id(lg: Ledger, call: bytes, position: int) -> bytes:
    """HASH(deterministic-CBOR(["request", call, position])) (request-id-input)."""
    return lg.h(dcbor(["request", call, position]))


def generate_protocol_v08() -> None:
    import wasm_ref as w
    import test_contracts

    names = ("org_root", "log", "clerk", "agent", "executor", "billing", "keeper")
    seeds = {name: hashlib.sha256(f"CexChain test key: {name}".encode()).hexdigest() for name in names}
    keys = {name: ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)) for name, seed in seeds.items()}
    t0 = 1_792_022_400_000  # 2026-10-15T00:00:00Z
    minute, hour, day = 60_000, 3_600_000, 86_400_000
    model = "claude-opus-5-5"
    code = test_contracts.request_contract()
    module = w.load(code)
    checks = test_contracts.check_requests(code)
    interface = test_contracts.REQUEST_FUNCTIONS

    ledgers = []
    for hash_id in (-16, -65538):
        lg = Ledger(hash_id)
        hash_name = HASHES[hash_id]
        statements, payloads, times, refused, runs, consents, children = [], [], [], [], [], [], []
        contracts, instances, actors, delegations, requests = {}, {}, {}, {}, {}
        signers = {}  # actor id -> the signer map a contract sees
        disclosures = []
        clock = [t0 + 1000]
        customer = PartyLedger("Customer", hash_id, t0)
        bank = hashlib.sha256(b"Bank ledger").digest()
        bundle_of = {}  # HASH(bundle) under the home's hash -> bundle

        def payload(signer_actor, body_type, body, delegation=None, provenance=None):
            n = len(statements) + len(refused) + 1
            out = {0: 1, 1: body_type, 2: ledger_id, 3: signer_actor, 5: clock[0] - 500, 6: n.to_bytes(16, "big"),
                   7: body}
            if delegation is not None:
                out[4] = delegation
            if provenance is not None:
                out[9] = {1: provenance}
            return out

        def add(name, signer, p):
            """Registers the statement now; the clock then moves a minute on."""
            encoded, statement_id = lg.statement(keys[signer], p)
            statements.append({"name": name, "signer": signer, "encoded": encoded.hex(), "payload": dcbor(p).hex(),
                               "statement_id": statement_id.hex(), "registered_at": clock[0]})
            payloads.append(p)
            times.append(clock[0])
            clock[0] += minute
            return statement_id

        def refuse(name, signer, p, why, malformed=False):
            """`malformed`: the body breaks the CDDL, so the statement does not
            even parse; otherwise the ledger rules refuse it at `at` (`why`)."""
            encoded, _ = lg.statement(keys[signer], p)
            refused.append({"name": name, "signer": signer, "encoded": encoded.hex(), "payload": dcbor(p).hex(),
                            "after": len(statements), "at": clock[0], "malformed": malformed, "why": why})

        def view(instance_id):
            inst = instances[instance_id]
            out = {1: instance_id, 2: inst["head"], 3: inst["state"]}
            if inst["status"] is not None:
                out[4] = inst["status"]
            if inst["parties"]:
                out[5] = inst["parties"]
            if inst["parent"] is not None:
                out[6] = [inst["parent"], inst["depth"]]
            return out

        def request_view(answer):
            r = requests[answer[0]]
            return {1: answer[0], 2: r["kind"], 3: r["params"], 4: r["deadline"], 5: r["asked_at"], 6: answer[1]}

        def contract_input(p, now):
            body = p[7]
            inp = {1: body[3], 2: body[4], 3: ledger_id, 6: [p[3], signers[p[3]]], 7: now}
            if 2 in body:
                inp[4] = instances[body[2]]["contract"]
                inp[5] = view(body[2])
            else:
                inp[4] = body[1]
            if 6 in body:
                inp[8] = [[ref[0], ref[3]] for ref in body[6]]
            if 8 in body:
                inp[9] = request_view(body[8])
            return dcbor(inp)

        def subset(child_scope, parent_scope, key):
            return key not in parent_scope or (key in child_scope and set(child_scope[key]) <= set(parent_scope[key]))

        def rules(p, now):
            """Every rule of sections 5 and 15 that refuses the statement before
            its contract runs, as far as these vectors reach."""
            body, fails = p[7], []
            scope = delegations[p[4]]["scope"] if 4 in p else None
            if p[1] == 5:
                if scope is not None:
                    granted = body[2]
                    if not (5 in scope and 5 in scope[1] and set(granted[1]) <= set(scope[1])
                            and all(subset(granted, scope, key) for key in (7, 8, 9))):
                        fails.append("narrowing")
                return fails
            if p[1] != 22:
                return fails
            answer, request = body.get(8), None
            if 2 in body:
                inst = instances.get(body[2])
                if inst is None:
                    return ["no such instance"]
                if inst["final"] and answer is None:
                    fails.append("final")
                if body[5] != inst["head"]:
                    fails.append("head")
                contract = inst["contract"]
                if interface.get(body[3]) != 2:
                    fails.append("function")
                if answer is not None:
                    request = requests.get(answer[0])
                    if request is None:
                        fails.append("no such request")
                    elif request["instance"] != body[2]:
                        fails.append("other instance")
                    else:
                        if request["status"] is not None:
                            fails.append("answered")
                        if body[3] != request["reply"]:
                            fails.append("answer function")
                        if answer[1] == 3 and now < request["deadline"]:
                            fails.append("early")
                    if 6 in body:
                        fails.append("consents")
            else:
                contract = body[1]
                if contracts[contract]["retired"]:
                    fails.append("retired")
                if interface.get(body[3]) != 1 or 6 in body:
                    fails.append("creation")
            if scope is not None:
                if (22 not in scope[1] or (7 in scope and contract not in scope[7])
                        or (8 in scope and body[3] not in scope[8])
                        or (9 in scope and (request is None or request["kind"] not in scope[9]))):
                    fails.append("authority")
            return fails

        def accept_rules(p, accept, now):
            """The rules that refuse an accepted call for what its accept does."""
            body, fails = p[7], []
            inst = instances[body[2]] if 2 in body else None
            if 6 in accept:
                contract = inst["contract"] if inst else body[1]
                if contracts[contract]["retired"]:
                    fails.append("retired")
                if inst is not None and inst["depth"] >= MAX_DEPTH:
                    fails.append("depth")
            if inst is not None and inst["final"] and (6 in accept or 7 in accept):
                fails.append("final")
            if 7 in accept:
                if any(not now < r[3] <= now + MAX_DEADLINE for r in accept[7]):
                    fails.append("deadline")
                if any(interface.get(r[4]) != 2 for r in accept[7]):
                    fails.append("reply")
                still_open = len(inst["open"]) - (1 if 8 in body else 0) if inst else 0
                if still_open + len(accept[7]) > MAX_OPEN:
                    fails.append("open")
            return fails

        def run_call(name, p, now, expect):
            """Runs the contract as the home would at `now`; returns the accept."""
            inp = contract_input(p, now)
            outcome, output, fuel, reason = w.run(module, inp, hash_name)
            checked = (check_contract_output(output, ledger_id, children=True, requests=True)
                       if outcome == "ok" else (outcome,))
            verdict = checked[0]
            assert verdict == expect, f"{name}: {verdict}, expected {expect}"
            runs.append({"name": name, "after": len(statements), "at": now, "input": inp.hex(), "outcome": outcome,
                         "output": output.hex(), "fuel": fuel, "verdict": verdict,
                         **({"reason": reason.hex()} if reason else {})})
            return checked[1] if verdict == "accept" else None

        def call(name, signer, actor, body, delegation, provenance=None):
            """A call the rules and the contract accept: registered, and
            applied, answers, children, and requests included."""
            p = payload(actor, 22, body, delegation, provenance)
            now = clock[0]
            assert rules(p, now) == [], (name, rules(p, now))
            accept = run_call(name, p, now, "accept")
            assert accept_rules(p, accept, now) == [], (name, accept_rules(p, accept, now))
            statement_id = add(name, signer, p)
            index = len(statements) - 1
            if 2 in body:
                target = body[2]
            else:
                target = statement_id
                instances[target] = {"contract": body[1], "parties": {}, "status": None, "history": [],
                                     "parent": None, "depth": 0, "created_by": None, "position": None,
                                     "final": False, "open": []}
            inst = instances[target]
            if 8 in body:
                request = requests[body[8][0]]
                request.update(status=body[8][1], answered_by=index, answered_at=now)
                inst["open"].remove(body[8][0])
            inst.update(head=index, state=accept[1], final=inst["final"] or accept.get(5, False))
            inst["history"].append(index)
            if 2 in accept:
                inst["status"] = accept[2]
            if 3 in accept:
                inst["parties"] = accept[3]
            made = []
            for position, child in enumerate(accept.get(6, [])):
                child_id = lg.h(dcbor([statement_id, position]))
                instances[child_id] = {"contract": inst["contract"], "head": index, "state": child[1],
                                       "status": child.get(2), "parties": child.get(3, {}), "final": False,
                                       "history": [index], "parent": target, "depth": inst["depth"] + 1,
                                       "created_by": index, "position": position, "open": []}
                children.append({"call": statement_id.hex(), "position": position, "id": child_id.hex()})
                made.append(child_id)
            asked = []
            for position, r in enumerate(accept.get(7, [])):
                rid = request_id(lg, statement_id, position)
                assert rid not in requests
                requests[rid] = {"instance": target, "call": index, "call_id": statement_id, "position": position,
                                 "kind": r[1], "params": r[2], "deadline": r[3], "reply": r[4], "asked_at": now,
                                 "status": None, "answered_by": None, "answered_at": None}
                inst["open"].append(rid)
                asked.append(rid)
            return statement_id, made, asked

        def refused_call(name, signer, actor, body, delegation, why, expect=None, malformed=False, provenance=None):
            """A call that is refused: by the rules before the contract runs
            (`why`, no `expect`), or after it, `expect` naming its verdict:
            refused for that verdict (`why` is then "contract"), or, for an
            accept, by the rules on what it does."""
            p = payload(actor, 22, body, delegation, provenance)
            now = clock[0]
            if not malformed:
                assert rules(p, now) == ([why] if expect is None else []), (name, rules(p, now))
            if expect is not None:
                accept = run_call(name, p, now, expect)
                if accept is not None:
                    assert accept_rules(p, accept, now) == [why], (name, accept_rules(p, accept, now))
                else:
                    assert why == "contract", name
            refuse(name, signer, p, why, malformed)

        def consent(party, instance, function, args, head):
            """A consent from a party ledger: its record, evidence bundle, and
            the call's citation of it."""
            metadata = {"ledger": ledger_id, "instance": instance, "function": function,
                        "arguments": lg.h(dcbor(args)), "head": head, "until": t0 + 7 * day}
            record, bundle = party.consent(metadata)
            digest = lg.h(bundle)
            bundle_of[digest] = bundle
            signer = {1: 0}
            consents.append({"party": party.name, "ledger": party.id.hex(), "record": record.hex(),
                             "metadata": dcbor(metadata).hex(), "bundle": bundle.hex(), "bundle_hash": digest.hex(),
                             "signer": dcbor(signer).hex()})
            return [party.id, record, digest, signer]

        def on(instance, function, args, refs=None, head=None, answer=None):
            body = {2: instance, 3: function, 4: args, 5: instances[instance]["head"] if head is None else head}
            if refs:
                body[6] = sorted(refs, key=lambda r: r[0])
            if answer is not None:
                body[8] = answer
            return body

        def response(name, text):
            """An outside system's response, kept by the executor: the answer
            carries HASH(salt || response) under the home's hash."""
            salt = hashlib.sha256(f"salt: {name}".encode()).digest()[:16]
            raw = text.encode()
            digest = lg.h(salt + raw)
            disclosures.append({"name": name, "salt": salt.hex(), "response": raw.hex(), "digest": digest.hex()})
            return digest

        genesis = {0: 1, 1: 1, 5: t0, 6: bytes([0xE0]) * 16, 7: {
            1: hash_id, 2: "Cirraya Service Home", 3: ed_public(keys["org_root"]), 4: ed_public(keys["log"])}}
        encoded, ledger_id = lg.statement(keys["org_root"], genesis)
        statements.append({"name": "genesis", "signer": "org_root", "encoded": encoded.hex(),
                           "payload": dcbor(genesis).hex(), "statement_id": ledger_id.hex(), "registered_at": clock[0]})
        payloads.append(genesis)
        times.append(clock[0])
        clock[0] += minute
        org = ledger_id
        signers[org] = {1: 0}

        def actor(name, signer_key, kind, label, responsible=None):
            body = {1: kind, 2: label, 3: ed_public(keys[signer_key])}
            if responsible is not None:
                body.update({4: responsible, 5: {1: model}})
            actor_id = add(name, "org_root", payload(org, 2, body))
            actors[actor_id] = {"index": len(statements) - 1, "responsible": responsible}
            signers[actor_id] = {1: kind, 3: model} if kind == 2 else {1: kind}
            return actor_id

        clerk = actor("register a clerk", "clerk", 1, "Service Desk Clerk")
        agent = actor("register a notice agent", "agent", 2, "Notice Agent", responsible=clerk)
        executor = actor("register the panel executor", "executor", 3, "Panel Executor")
        billing = actor("register the billing executor", "billing", 3, "Billing Executor")
        keeper = actor("register the keeper", "keeper", 3, "Keeper")

        k = add("deploy the requesting contract", "org_root", payload(org, 21, {
            1: code, 2: interface, 3: "wasm", 4: "tools/testvectors 1",
            5: b"hand-assembled: see request_contract in tools/testvectors/test_contracts.py", 6: "Requesting contract"}))
        contracts[k] = {"history": [len(statements) - 1], "retired": False}

        def delegate(name, signer, grantor, grantee, scope, under=None):
            p = payload(grantor, 5, {1: grantee, 2: scope}, under)
            assert rules(p, clock[0]) == [], name
            d = add(name, signer, p)
            delegations[d] = {"index": len(statements) - 1, "grantor": grantor, "parent": under, "scope": scope}
            return d

        def refused_grant(name, signer, grantor, grantee, scope, under=None, malformed=False):
            p = payload(grantor, 5, {1: grantee, 2: scope}, under)
            if not malformed:
                assert rules(p, clock[0]) == ["narrowing"], name
            refuse(name, signer, p, "malformed" if malformed else "narrowing", malformed)

        kinds = ["invoice", "provision", "reclaim", "suspend"]
        d_clerk = delegate("delegate the requesting contract to the clerk", "org_root", org, clerk,
                           {1: [5, 22], 5: True, 7: [k]})
        d_agent = delegate("the clerk lets the agent answer notices", "clerk", clerk, agent,
                           {1: [22], 7: [k], 8: ["result"], 9: ["notify"]}, d_clerk)
        d_exec = delegate("let the panel executor answer its kinds", "org_root", org, executor,
                          {1: [5, 22], 5: True, 7: [k], 8: ["result"], 9: kinds})
        d_billing = delegate("the panel executor lets the billing executor answer invoices", "executor", executor,
                             billing, {1: [22], 7: [k], 8: ["result"], 9: ["invoice"]}, d_exec)
        for what, scope in (("key 8 wider than its grantor's", {1: [22], 7: [k], 8: ["ask", "result"], 9: ["invoice"]}),
                            ("no key 8 under a grantor with one", {1: [22], 7: [k], 9: ["invoice"]}),
                            ("key 9 wider than its grantor's", {1: [22], 7: [k], 8: ["result"], 9: ["invoice", "notify"]}),
                            ("no key 9 under a grantor with one", {1: [22], 7: [k], 8: ["result"]})):
            refused_grant(f"the panel executor delegates with {what}", "executor", executor, billing, scope, d_exec)
        d_keeper = delegate("let the keeper fire rules and expire requests", "org_root", org, keeper,
                            {1: [22], 7: [k], 8: ["result", "when.due"]})
        for what, scope in (("an empty key 8", {1: [22], 8: []}),
                            ("key 8 out of order", {1: [22], 8: ["when.due", "result"]}),
                            ("key 8 naming a function twice", {1: [22], 8: ["result", "result"]}),
                            ("key 8 with an empty name", {1: [22], 8: [""]}),
                            ("key 8 with a name of 65 bytes", {1: [22], 8: ["f" * 65]}),
                            ("an empty key 9", {1: [22], 9: []}),
                            ("key 9 with an upper-case kind", {1: [22], 9: ["Invoice"]}),
                            ("key 9 with a kind that starts with a digit", {1: [22], 9: ["1st"]}),
                            ("key 9 naming a kind twice", {1: [22], 9: ["invoice", "invoice"]}),
                            ("key 9 with a kind of 65 bytes", {1: [22], 9: ["k" * 65]}),
                            ("key 9 that is not text", {1: [22], 9: [1]})):
            refused_grant(f"a scope with {what}", "org_root", org, keeper, scope, malformed=True)

        def by_clerk(name, body):
            return call(name, "clerk", clerk, body, d_clerk)

        def refused_by_clerk(name, body, why, expect=None, malformed=False):
            refused_call(name, "clerk", clerk, body, d_clerk, why, expect, malformed)

        def by_executor(name, body):
            return call(name, "executor", executor, body, d_exec)

        def by_agent(name, body):
            return call(name, "agent", agent, body, d_agent, provenance=model)

        def by_keeper(name, body):
            return call(name, "keeper", keeper, body, d_keeper)

        def raw(accept) -> bytes:
            """Arguments the contract writes as its output."""
            return dcbor([1, accept])

        def asked(kind, params, deadline, reply="result"):
            return {1: kind, 2: params, 3: deadline, 4: reply}

        # S1, a service: a device, an agent, a chain of two delegations, a
        # keeper, and a person answer; a failure is retried; one expires, one
        # comes late; two stay open, one of them overdue.
        s1, _, (r1,) = by_clerk("open a service, asking for it to be provisioned", {1: k, 3: "open", 4: [
            ["provision", {"plan": "vps-2c4g", "region": "hk"}, day]]})
        terms = [["invoice", {"bill": 1, "currency": "HKD", "total": 12_500}, 3 * day],
                 ["notify", {"about": "welcome", "to": customer.id}, day],
                 ["collect", {"bill": 1, "total": 12_500}, 30 * day]]
        _, _, (r2, r3, r4) = by_clerk("ask for an invoice, a welcome notice, and the payment, with the customer's consent",
                                      on(s1, "ask", terms, refs=[consent(customer, s1, "ask", terms,
                                                                         instances[s1]["head"])]))
        refused_by_clerk("answer with a function that is not the request's reply", on(s1, "ask", None, answer=[r1, 1]),
                         "answer function")
        refused_by_clerk("answer citing a consent", on(s1, "result", None, answer=[r1, 1], refs=[
            [bank, lg.h(b"bank consent"), lg.h(b"bank consent bundle"), {1: 0}]]), "consents")
        refused_by_clerk("expire a request before its deadline", on(s1, "result", None, answer=[r1, 3]), "early")
        refused_by_clerk("answer a request that does not exist", on(s1, "result", None, answer=[lg.h(b"nothing"), 1]),
                         "no such request")
        for what, answer in (("without a status", [r1]), ("with status 0", [r1, 0]), ("with status 4", [r1, 4]),
                             ("naming a short id", [b"short", 1]), ("that is a map", {1: r1, 2: 1}),
                             ("with a third item", [r1, 1, 0])):
            refused_by_clerk(f"an answer {what}", on(s1, "result", None, answer=answer), "malformed", malformed=True)
        refused_by_clerk("an answer on a creation", {1: k, 3: "open", 4: None, 8: [r1, 1]}, "malformed",
                         malformed=True)
        by_executor("the panel executor reports the server provisioned", on(s1, "result", {
            "digest": response("provision", '{"id":"vm-4711","state":"running"}'), "ref": "vm-4711"}, answer=[r1, 1]))
        refused_call("the panel executor answers it again", "executor", executor,
                     on(s1, "result", None, answer=[r1, 1]), d_exec, "answered")
        refused_call("the panel executor answers a notice, a kind outside its key 9", "executor", executor,
                     on(s1, "result", None, answer=[r3, 1]), d_exec, "authority")
        refused_call("the panel executor calls its reply without answering", "executor", executor,
                     on(s1, "result", None), d_exec, "authority")
        refused_call("the panel executor calls ask, outside its keys 8 and 9", "executor", executor,
                     on(s1, "ask", []), d_exec, "authority")
        stale = instances[s1]["head"]
        _, _, (r5,) = by_agent("the agent reports the notice failed, and asks again", on(s1, "result", [
            ["notify", {"about": "welcome", "attempt": 2, "to": customer.id}, day]], answer=[r3, 2]))
        refused_call("the billing executor answers at the head before the agent's answer", "billing", billing,
                     on(s1, "result", None, head=stale, answer=[r2, 1]), d_billing, "head")
        call("the billing executor reports the invoice issued", "billing", billing, on(s1, "result", {
            "digest": response("invoice", '{"invoice_id":"INV-2026-0001","total":"125.00"}'), "ref": "INV-2026-0001",
            "total": 12_500}, answer=[r2, 1]), d_billing)
        refused_by_clerk("the contract rejects an answer", on(s1, "result", "no payment has arrived", answer=[r4, 1]),
                         "contract", "aborted")
        refused_by_clerk("the contract asks for consents for an answer",
                         on(s1, "result", dcbor([2, [customer.id]]), answer=[r4, 1]), "contract", "needs")
        _, _, (r6,) = by_keeper("the keeper fires a rule that asks for a suspension", on(s1, "when.due", [
            ["suspend", {"reason": "overdue"}, day]]))
        refused_call("the keeper calls ask, outside its key 8", "keeper", keeper, on(s1, "ask", []), d_keeper,
                     "authority")
        refused_call("the keeper expires the second notice before its deadline", "keeper", keeper,
                     on(s1, "result", None, answer=[r5, 3]), d_keeper, "early")
        clock[0] += 2 * day
        by_keeper("the keeper expires the second notice", on(s1, "result", None, answer=[r5, 3]))
        by_executor("the panel executor reports the suspension, late", on(s1, "result", {
            "digest": response("suspend", '{"id":"vm-4711","state":"suspended"}'), "ref": "vm-4711"},
            answer=[r6, 1]))

        # S2: a final instance takes answers to its open requests, and
        # nothing else.
        s2, _, _ = by_clerk("open a second service", {1: k, 3: "open", 4: None})
        now = clock[0]
        _, _, (r9, r10) = by_clerk("end it, asking for its address to be reclaimed and a notice", on(s2, "ask", raw({
            1: "ended", 2: "terminated", 5: True, 7: [
                asked("reclaim", {"ip": "203.0.113.9"}, now + day),
                asked("notify", {"about": "terminated", "to": customer.id}, now + day)]})))
        refused_by_clerk("call the final instance without answering", on(s2, "ask", []), "final")
        refused_call("answer on the final instance, asking again", "executor", executor, on(s2, "result", [
            ["reclaim", {"ip": "203.0.113.9"}, day]], answer=[r9, 1]), d_exec, "final", "accept")
        refused_call("answer on the final instance, creating a child", "executor", executor, on(s2, "result", raw({
            1: 0, 6: [{1: 0}]}), answer=[r9, 1]), d_exec, "final", "accept")
        by_executor("the panel executor reports the address reclaimed, after the end",
                    on(s2, "result", {"ref": "203.0.113.9"}, answer=[r9, 1]))
        refused_call("the panel executor answers the reclaim again", "executor", executor,
                     on(s2, "result", None, answer=[r9, 1]), d_exec, "answered")
        by_agent("the agent reports the notice sent, after the end", on(s2, "result", {"channel": "email"},
                                                                         answer=[r10, 1]))

        # S3: the limits, 16 requests per call and 64 open.
        s3, _, _ = by_clerk("open a third service", {1: k, 3: "open", 4: None})
        refused_by_clerk("ask for 17 requests in one call", on(s3, "ask", [["ping", i, 7 * day] for i in range(17)]),
                         "contract", "malformed")
        pings = []
        for batch in range(4):
            pings += by_clerk(f"ask for 16 requests ({batch + 1} of 4)", on(s3, "ask", [
                ["ping", 16 * batch + i, 7 * day] for i in range(16)]))[2]
        refused_by_clerk("ask for a 65th open request", on(s3, "ask", [["ping", 64, 7 * day]]), "open", "accept")
        by_clerk("answer a request at the limit, asking one more", on(s3, "result", [["ping", 65, 7 * day]],
                                                                       answer=[pings[0], 1]))
        refused_by_clerk("ask for a 65th open request again", on(s3, "ask", [["ping", 66, 7 * day]]), "open",
                         "accept")

        # S4: what a request may be.
        s4, _, _ = by_clerk("open a fourth service", {1: k, 3: "open", 4: None})
        now = clock[0]
        for what, accept, why in (
                ("a deadline at the call's registration time", {1: 0, 7: [asked("check", None, now)]}, "deadline"),
                ("a deadline more than 366 days ahead", {1: 0, 7: [asked("check", None, now + MAX_DEADLINE + 1)]},
                 "deadline"),
                ("a reply that creates instances", {1: 0, 7: [asked("check", None, now + day, "open")]}, "reply"),
                ("a reply outside the interface", {1: 0, 7: [asked("check", None, now + day, "close")]}, "reply")):
            refused_by_clerk(f"ask with {what}", on(s4, "ask", raw(accept)), why, "accept")
        good = asked("check", None, now + day)
        for what, accept in (
                ("no requests", {1: 0, 7: []}),
                ("requests that are not an array", {1: 0, 7: {1: good}}),
                ("a request that is not a map", {1: 0, 7: [["check", None, now + day, "result"]]}),
                ("a request without a reply", {1: 0, 7: [{1: "check", 2: None, 3: now + day}]}),
                ("a request with a fifth key", {1: 0, 7: [{**good, 5: 0}]}),
                ("an empty kind", {1: 0, 7: [{**good, 1: ""}]}),
                ("an upper-case kind", {1: 0, 7: [{**good, 1: "Invoice"}]}),
                ("a kind that starts with a digit", {1: 0, 7: [{**good, 1: "1st"}]}),
                ("a kind with a space", {1: 0, 7: [{**good, 1: "panel suspend"}]}),
                ("a kind of 65 bytes", {1: 0, 7: [{**good, 1: "k" * 65}]}),
                ("a kind that is not text", {1: 0, 7: [{**good, 1: 7}]}),
                ("params of 4,097 bytes", {1: 0, 7: [{**good, 2: bytes(4094)}]}),
                ("a deadline that is text", {1: 0, 7: [{**good, 3: "tomorrow"}]}),
                ("a negative deadline", {1: 0, 7: [{**good, 3: -1}]}),
                ("an empty reply", {1: 0, 7: [{**good, 4: ""}]}),
                ("a reply of 65 bytes", {1: 0, 7: [{**good, 4: "r" * 65}]}),
                ("a child with requests", {1: 0, 6: [{1: 0, 7: [good]}]})):
            refused_by_clerk(f"the contract writes {what}", on(s4, "ask", raw(accept)), "contract", "malformed")
        assert len(dcbor(bytes(4093))) == MAX_PARAMS
        _, _, (_, _, r13, _) = by_clerk("ask at the limits: the earliest and latest deadlines, a kind of 64 bytes, "
                                        "params of 4,096 bytes, another reply", on(s4, "ask", raw({1: "limits", 7: [
                                            asked("check", None, now + 1),
                                            asked("k" * 64, bytes(4093), now + MAX_DEADLINE),
                                            asked("panel.suspend-2_b", {"plan": "vps-1c1g"}, now + day, "when.due"),
                                            asked("ping", [], now + day)]})))
        refused_by_clerk("answer a request whose reply is another function", on(s4, "result", None, answer=[r13, 1]),
                         "answer function")
        refused_by_clerk("answer another instance's request", on(s4, "result", None, answer=[r4, 1]),
                         "other instance")
        by_clerk("answer it with its reply", on(s4, "when.due", None, answer=[r13, 1]))

        # S5: a creation that creates a child and makes a request, which is
        # the new instance's, not the child's.
        now = clock[0]
        s5, (c1,), (r14,) = by_clerk("open a fifth service with a part, asking for a notice", {1: k, 3: "open", 4: raw({
            1: "parent", 6: [{1: "part", 2: "draft"}],
            7: [asked("notify", {"about": "parts", "to": customer.id}, now + day)]})})
        refused_by_clerk("answer the parent's request on its part", on(c1, "result", None, answer=[r14, 1]),
                         "other instance")
        _, _, (r15,) = by_clerk("ask on the part", on(c1, "ask", [["provision", {"plan": "vps-1c1g"}, day]]))
        by_executor("the panel executor provisions the part", on(c1, "result", {"ref": "vm-4712"}, answer=[r15, 1]))

        # S1 again: two more requests; a person answers one by hand, and the
        # other is overdue at the checkpoint.
        _, _, (_, r8) = by_clerk("ask for an address to be reclaimed within the hour, and a review",
                                 on(s1, "ask", [["reclaim", {"ip": "203.0.113.7"}, hour], ["review", {"bill": 1}, 7 * day]]))
        by_clerk("the clerk answers the review by hand", on(s1, "result", {"note": "checked"}, answer=[r8, 1]))
        clock[0] += 3 * hour

        # The state, its commitment, and the checkpoint over everything.
        entries = [encode_log_entry(bytes.fromhex(st["statement_id"]), times[i], bytes.fromhex(st["encoded"]))
                   for i, st in enumerate(statements)]
        leaves = {org: [1, org, [0]]}
        for actor_id, info in actors.items():
            leaves[actor_id] = [1, actor_id, [info["index"]]]
        for d_id, info in delegations.items():
            leaves[d_id] = [2, d_id, [info["index"]]]
        for k_id, info in contracts.items():
            leaves[k_id] = [4, k_id, info["history"]]
        for i_id, info in instances.items():
            leaves[i_id] = [5, i_id, info["history"]]
        sorted_leaves = sorted(leaves.values(), key=lambda x: x[1])
        checkpoint_time = clock[0]
        commitment_index = len(entries)
        commitment_id = append_state_commitment(lg, keys["log"], ledger_id, entries, sorted_leaves, checkpoint_time)
        checkpoint, root = sign_log_checkpoint(lg, keys["log"], ledger_id, entries, checkpoint_time)

        def request_json(rid):
            r = requests[rid]
            late = None if r["answered_at"] is None else max(0, r["answered_at"] - r["deadline"])
            return {"id": rid.hex(), "instance": r["instance"].hex(), "call": r["call"], "call_id": r["call_id"].hex(),
                    "position": r["position"], "kind": r["kind"], "params": dcbor(r["params"]).hex(),
                    "deadline": r["deadline"], "reply": r["reply"], "asked_at": r["asked_at"], "status": r["status"],
                    "answered_by": r["answered_by"], "answered_at": r["answered_at"], "late_by": late,
                    "overdue": r["status"] is None and checkpoint_time >= r["deadline"]}

        def instance_evidence(subject):
            """The subject's evidence bundle (section 11), with its ancestors'
            histories up to each creating call, its contract evidence, and
            what its report shows of requests and answers."""
            inst = instances[subject]
            events = set(inst["history"])
            node = inst
            while node["parent"] is not None:
                parent = instances[node["parent"]]
                events |= {i for i in parent["history"] if i <= node["created_by"]}
                node = parent
            events = sorted(events)
            involved = []

            def involve(object_id):
                if object_id not in involved:
                    involved.append(object_id)

            involve(subject)
            involve(inst["contract"])
            for i in events:
                p = payloads[i]
                involve(p[3])
                if actors.get(p[3], {}).get("responsible") is not None:
                    involve(actors[p[3]]["responsible"])
                delegation = p.get(4)
                while delegation is not None:
                    involve(delegation)
                    involve(delegations[delegation]["grantor"])
                    delegation = delegations[delegation]["parent"]
            needed = {0, commitment_index, *events}
            for object_id in involved:
                needed |= set(leaves[object_id][2])
            work = sorted(needed - {0, commitment_index})
            while work:
                p = payloads[work.pop()]
                deps = []
                if p[3] != org:
                    deps.append(actors[p[3]]["index"])
                if 4 in p:
                    deps.append(delegations[p[4]]["index"])
                body = p[7]
                if p[1] == 2 and 4 in body:
                    deps.append(actors[body[4]]["index"])
                elif p[1] == 5:
                    deps.append(actors[body[1]]["index"])
                elif p[1] == 22:
                    contract = body[1] if 1 in body else instances[body[2]]["contract"]
                    deps.append(contracts[contract]["history"][0])
                elif p[1] == 23:
                    deps.append(contracts[body[1]]["history"][0])
                for dep in deps:
                    if dep not in needed:
                        needed.add(dep)
                        work.append(dep)
            proofs = [[leaves[i], smt_proof(lg, sorted_leaves, i)] for i in involved]
            bundle = make_bundle(lg, keys["log"], entries, checkpoint, root, subject, needed, proofs)
            pins = []
            for i in events:
                for ref in payloads[i][7].get(6, []) if payloads[i][1] == 22 else []:
                    if ref[2] not in pins:
                        pins.append(ref[2])
            evidence = {0: 1, 1: bundle}
            if pins:
                evidence[2] = [bundle_of[h] for h in pins]
            ancestors = []
            node = inst
            while node["parent"] is not None:
                ancestors.insert(0, {"id": node["parent"].hex(), "until": node["created_by"]})
                node = instances[node["parent"]]
            calls = []
            for i in events:
                body = payloads[i][7]
                target = body[2] if 2 in body else bytes.fromhex(statements[i]["statement_id"])
                made = [rid.hex() for rid, r in requests.items() if r["call"] == i]
                answer = None
                if 8 in body:
                    r = requests[body[8][0]]
                    answer = {"request": body[8][0].hex(), "status": body[8][1],
                              "late_by": max(0, times[i] - r["deadline"]), "actor": payloads[i][3].hex(),
                              "signer": dcbor(signers[payloads[i][3]]).hex(),
                              "delegation": payloads[i][4].hex() if 4 in payloads[i] else None}
                calls.append({"index": i, "instance": target.hex(), "requests": made, "answer": answer})
            own = [rid for rid, r in requests.items() if r["instance"] == subject]
            return {"subject": subject.hex(), "depth": inst["depth"], "ancestors": ancestors, "events": events,
                    "entries": sorted(needed), "involved": [i.hex() for i in involved],
                    "pins": [h.hex() for h in pins], "calls": calls, "requests": [rid.hex() for rid in own],
                    "open": [rid.hex() for rid in own if requests[rid]["status"] is None],
                    "overdue": [rid.hex() for rid in own
                                if requests[rid]["status"] is None and checkpoint_time >= requests[rid]["deadline"]],
                    "contract_evidence": dcbor(evidence).hex()}

        ledgers.append({
            "hash": hash_id,
            "ledger_id": ledger_id.hex(),
            "parties": {"Customer": customer.id.hex(), "Bank": bank.hex()},
            "actors": {name: value.hex() for name, value in (("clerk", clerk), ("agent", agent), ("executor", executor),
                                                             ("billing", billing), ("keeper", keeper))},
            "contract": k.hex(),
            "statements": statements,
            "refused": refused,
            "runs": runs,
            "consents": consents,
            "children": children,
            "requests": [request_json(rid) for rid in requests],
            "disclosures": disclosures,
            "instances": [{"id": i.hex(), "contract": v["contract"].hex(), "head": v["head"],
                           "state": dcbor(v["state"]).hex(), "status": v["status"],
                           "parties": {r: l.hex() for r, l in v["parties"].items()}, "final": v["final"],
                           "history": v["history"], "depth": v["depth"],
                           "parent": v["parent"].hex() if v["parent"] is not None else None,
                           "created_by": v["created_by"], "position": v["position"],
                           "open": [rid.hex() for rid in v["open"]]}
                          for i, v in instances.items()],
            "log_entries": [e.hex() for e in entries],
            "state_leaves": [{"kind": leaf[0], "id": leaf[1].hex(), "history": leaf[2]} for leaf in sorted_leaves],
            "state_root": smt_root(lg, sorted_leaves).hex(),
            "state_commitment": {"index": commitment_index, "id": commitment_id.hex()},
            "checkpoint": checkpoint.hex(),
            "checkpoint_time": checkpoint_time,
            "evidence": {
                "a service": instance_evidence(s1),
                "a final instance answered": instance_evidence(s2),
                "a part whose parent asked": instance_evidence(c1),
            },
        })

    document = {
        "description": "CexChain protocol objects added in specification revision v0.8 (requests and answers), "
                       "built by an independent Python encoder from spec/cexchain.cddl and run by the reference "
                       "interpreter tools/testvectors/wasm_ref.py. The requesting contract (request_contract in "
                       "tools/testvectors/test_contracts.py, interface `interface`) writes byte-string arguments as "
                       "its output, aborts with text arguments, makes one request {1: kind, 2: params, 3: time + "
                       "after, 4: \"result\"} per [kind, params, after] in array arguments, and otherwise makes "
                       "none; for an answer (input key 9) its state becomes [status, request] and it records the "
                       "event [done|failed|expired, kind]; otherwise the state stays (null for a creation). A clerk "
                       "(a person), a notice agent (an AI agent under the clerk; scope keys 8 [result] and 9 "
                       "[notify]), a panel executor (a device; keys 8 [result] and 9 [invoice, provision, reclaim, "
                       "suspend]), a billing executor (under the panel executor; key 9 [invoice]), and a keeper (key 8 "
                       "[result, when.due]) call five instances: a service whose requests are answered done, failed, "
                       "and expired, on time and late, with two left open, one overdue; a final instance that takes "
                       "answers; one at the limit of 64 open requests; one that tries what a request may be; and one "
                       "whose creation makes a request and a part. Each statement registers at its `registered_at` "
                       "(the log entries carry it); refused statements either break the CDDL (`malformed`) or are "
                       "validated against the state after the first `after` statements, at `at`; `why` names the rule "
                       "(answered, early, answer function, consents, no such request, other instance, final, head, "
                       "authority, narrowing, deadline, reply, open) or `contract` when the contract's run refuses it "
                       "(its run says how). `runs` lists every contract run: the input the home builds (key 9 for an "
                       "answer), and the outcome, output, fuel, and verdict. `requests` lists every request: its id, "
                       "HASH([\"request\", call, position]), its instance, the requesting call's index and statement "
                       "id, its position, kind, params (encoded), deadline, reply, the time it was asked at, and its "
                       "answer (status, index, time, and how late), and whether it is overdue at the checkpoint. "
                       "`instances` gives each instance's final state, status, parties, head, finality, history, "
                       "depth, parent, and its open requests. `disclosures` holds outside responses an executor kept, "
                       "with their salts and HASH(salt || response), which answers carry. `log_entries` holds the "
                       "whole log, ending with the state commitment over `state_leaves`; `checkpoint` (signed at "
                       "`checkpoint_time`) covers it. `evidence` holds signed contract evidence for three instances "
                       "(as in protocol-v0.7.json: entries, involved objects, consent pins) and what a report shows: "
                       "per call, the requests it made and its answer (request, status, lateness, actor, signer, "
                       "delegation); the instance's requests, the open ones, and those overdue at the checkpoint. "
                       "`contract_checks` counts the inputs on which the contract agreed with an independent model. "
                       "Signatures are Ed25519 (deterministic); keys are throwaway: seed = SHA-256(\"CexChain test "
                       "key: <name>\"), and for the customer's ledger \"Customer root\" and \"Customer log\".",
        "t0": t0,
        "limits": {"requests": MAX_REQUESTS, "open": MAX_OPEN, "params": MAX_PARAMS, "deadline": MAX_DEADLINE},
        "contract": code.hex(),
        "interface": interface,
        "contract_checks": checks,
        "seeds": seeds,
        "ledgers": ledgers,
    }
    (OUT / "protocol-v0.8.json").write_text(json.dumps(document, indent=1) + "\n")
    first = ledgers[0]
    print(f"wrote protocol vectors for {len(ledgers)} ledgers to testvectors/protocol-v0.8.json: "
          f"{len(first['statements'])} statements, {len(first['refused'])} refused, {len(first['runs'])} "
          f"contract runs, {len(first['requests'])} requests, {checks} contract checks")


# ---------------------------------------------------------------------------
# Protocol v0.9: the generic core (spec sections 4 to 6): a user's record
# types with the generic lifecycle, the four mechanism types with theirs, the
# reserved "cexchain." prefix, and statement type 20 reserved
# ---------------------------------------------------------------------------

# Statement types v0.9 defines; 20 (asset-action, v0.5) is reserved.
STATEMENT_TYPES_V09 = (1, 2, 3, 4, 5, 6, 7, 8, 16, 17, 18, 19, 21, 22, 23)
# A claim (v0.14, section 6): a condition on another record's fields.
CLAIM = "cexchain.claim/1"
# The mechanism types: initial state and transitions. None defines a role.
# Revisions v0.9 to v0.13 define the first four, and their vectors keep to
# them (MECHANISM_TYPES_V09); v0.14 adds claims.
MECHANISM_TYPES = {
    "cexchain.access-request/1": ("requested", {("requested", "withdrawn")}),
    "cexchain.access-grant/1": ("granted", set()),
    "cexchain.access-receipt/1": ("received", set()),
    CONTRACT_CONSENT: ("given", {("given", "withdrawn")}),
    CLAIM: ("confirmed", set()),
}
MECHANISM_TYPES_V09 = {kind: lifecycle for kind, lifecycle in MECHANISM_TYPES.items() if kind != CLAIM}
RESERVED_PREFIX = "cexchain."
# The types earlier revisions built in, which v0.9 removed.
REMOVED_TYPES = ("cexchain.certificate/1", "cexchain.delivery/1", "cexchain.agreement/1",
                 "cexchain.receivable/1", "cexchain.warehouse-receipt/1", "cexchain.asset-consent/1")


def generate_protocol_v09() -> None:
    names = ("org_root", "log", "clerk")
    seeds = {name: hashlib.sha256(f"CexChain test key: {name}".encode()).hexdigest() for name in names}
    keys = {name: ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)) for name, seed in seeds.items()}
    t0 = 1_792_108_800_000  # 2026-10-16T00:00:00Z
    minute, day = 60_000, 86_400_000
    peer = hashlib.sha256(b"Peer ledger").digest()

    ledgers = []
    for hash_id in (-16, -65538):
        lg = Ledger(hash_id)
        statements, payloads, refused = [], [], []
        actors, delegations, records = {}, {}, {}
        clock = [t0 + 1000]

        def payload(signer_actor, body_type, body, delegation=None):
            n = len(statements) + len(refused) + 1
            out = {0: 1, 1: body_type, 5: clock[0] - 500, 6: n.to_bytes(16, "big"), 7: body}
            if signer_actor is not None:  # absent only in genesis
                out[2] = ledger_id
                out[3] = signer_actor
            if delegation is not None:
                out[4] = delegation
            return out

        def well_formed(p):
            """The CDDL of v0.9, as far as these vectors reach: a known
            statement type, and a scope naming only known types."""
            if p[1] not in STATEMENT_TYPES_V09:
                return False
            return p[1] != 5 or all(t in STATEMENT_TYPES_V09 for t in p[7][2][1])

        def rules(p):
            """Every rule of section 5 that refuses a record statement, as far
            as these vectors reach (the signers are always authorized)."""
            body, fails = p[7], []
            if p[1] == 16:
                kind = body[1]
                if kind.startswith(RESERVED_PREFIX) and kind not in MECHANISM_TYPES_V09:
                    fails.append("reserved type")
                return fails
            if p[1] not in (17, 18, 19):
                return fails
            record = records.get(body[1])
            if record is None:
                return ["no such record"]
            if record["revoked"]:
                fails.append("revoked")
            mechanism = MECHANISM_TYPES_V09.get(record["type"])
            if p[1] == 17:
                if mechanism is not None:
                    fails.append("role")
                if any(actor == p[3] and role == body[2] for actor, role, _ in record["endorsements"]):
                    fails.append("repeated")
            elif p[1] == 18:
                if record["state"] != body[2]:
                    fails.append("state")
                if mechanism is None or (body[2], body[3]) not in mechanism[1]:
                    fails.append("transition")
            return fails

        def add(name, signer, p):
            """Registers the statement now, under the rules; the clock then
            moves a minute on."""
            assert well_formed(p) and rules(p) == [], (name, rules(p))
            encoded, statement_id = lg.statement(keys[signer], p)
            index = len(statements)
            statements.append({"name": name, "signer": signer, "encoded": encoded.hex(), "payload": dcbor(p).hex(),
                               "statement_id": statement_id.hex(), "registered_at": clock[0]})
            payloads.append(p)
            clock[0] += minute
            body = p[7]
            if p[1] == 1:
                actors[statement_id] = [index]
            elif p[1] == 2:
                actors[statement_id] = [index]
            elif p[1] == 5:
                delegations[statement_id] = [index]
            elif p[1] == 16:
                initial = MECHANISM_TYPES_V09[body[1]][0] if body[1] in MECHANISM_TYPES_V09 else "registered"
                records[statement_id] = {"type": body[1], "state": initial, "revoked": False, "endorsements": [],
                                         "history": [index], "registrant": p[3]}
            elif p[1] in (17, 18, 19):
                record = records[body[1]]
                record["history"].append(index)
                if p[1] == 17:
                    record["endorsements"].append((p[3], body[2], index))
                elif p[1] == 18:
                    record["state"] = body[3]
                else:
                    record["revoked"] = True
            return statement_id

        def refuse(name, signer, p, why):
            """`malformed` when the statement breaks the CDDL, so it does not
            even parse; otherwise the rules refuse it after the statements so
            far, at `at`, for the one rule `why` names."""
            malformed = why == "unknown type"
            if malformed:
                assert not well_formed(p), name
            else:
                assert well_formed(p) and rules(p) == [why], (name, rules(p))
            encoded, _ = lg.statement(keys[signer], p)
            refused.append({"name": name, "signer": signer, "encoded": encoded.hex(), "payload": dcbor(p).hex(),
                            "after": len(statements), "at": clock[0], "malformed": malformed, "why": why})

        def fields(*values):
            leaves = [dcbor([name, bytes([0xB0 + i]) * 16, value])
                      for i, (name, value) in enumerate(sorted(values, key=lambda f: f[0].encode()))]
            return lg.merkle().mth(leaves), len(leaves)

        ledger_id = None
        ledger_id = add("genesis", "org_root", payload(None, 1, {
            1: hash_id, 2: "Example Household", 3: ed_public(keys["org_root"]), 4: ed_public(keys["log"])}))
        org = ledger_id
        clerk = add("register a person", "org_root", payload(org, 2, {1: 1, 2: "Clerk", 3: ed_public(keys["clerk"])}))
        delegation = add("delegate records to the person", "org_root", payload(org, 5, {
            1: clerk, 2: {1: [16, 17, 18, 19]}}))

        # A record of a user's own type: the generic lifecycle.
        root, count = fields(("title", "Camera lent to a neighbour"), ("until", "2026-11-01"))
        document = add("register a record of a user's type", "clerk", payload(clerk, 16, {
            1: USER_TYPE, 2: root, 3: count, 5: {"title": "Lent camera"}}, delegation))
        refuse("a transition on a user's type", "clerk", payload(clerk, 18, {
            1: document, 2: "registered", 3: "returned"}, delegation), "transition")
        refuse("statement type 20, a v0.5 freeze", "org_root", payload(org, 20, {
            1: document, 2: "freeze", 3: 3, 7: "court order 7"}), "unknown type")
        refuse("statement type 20, a v0.5 transfer with a consent", "org_root", payload(org, 20, {
            1: document, 2: "transfer", 3: 3, 4: peer, 6: [[peer, lg.h(b"consent"), lg.h(b"bundle")]]}),
            "unknown type")
        refuse("a scope naming statement type 20", "org_root", payload(org, 5, {
            1: clerk, 2: {1: [16, 20]}}), "unknown type")
        add("endorse it as reviewer", "clerk", payload(clerk, 17, {1: document, 2: "reviewer"}, delegation))
        refuse("endorse it as reviewer again", "clerk", payload(clerk, 17, {
            1: document, 2: "reviewer"}, delegation), "repeated")
        add("the organization endorses it as approver", "org_root", payload(org, 17, {1: document, 2: "approver"}))
        add("endorse it in a role of the person's choosing", "clerk", payload(clerk, 17, {
            1: document, 2: "neighbour's witness"}, delegation))

        # The mechanism types, each through its lifecycle.
        root, count = fields(("note", "approve the booking"),)
        consent = add("register a contract consent", "org_root", payload(org, 16, {
            1: CONTRACT_CONSENT, 2: root, 3: count, 5: {
                "ledger": peer, "instance": lg.h(b"instance"), "function": "approve", "head": 4,
                "arguments": lg.h(dcbor(None)), "until": t0 + 7 * day}}))
        refuse("endorse a contract consent", "org_root", payload(org, 17, {1: consent, 2: "witness"}), "role")
        add("withdraw the consent", "org_root", payload(org, 18, {1: consent, 2: "given", 3: "withdrawn"}))
        refuse("withdraw the consent again", "org_root", payload(org, 18, {
            1: consent, 2: "given", 3: "withdrawn"}), "state")
        refuse("give a withdrawn consent again", "org_root", payload(org, 18, {
            1: consent, 2: "withdrawn", 3: "given"}), "transition")
        root, count = fields(("note", "ask for the record"),)
        request = add("register an access request", "clerk", payload(clerk, 16, {
            1: "cexchain.access-request/1", 2: root, 3: count, 5: {
                "ledger": peer, "record": lg.h(b"their record"), "purpose": "check the dates",
                "until": t0 + 30 * day, "recipient": bytes([0x42]) * 32}}, delegation))
        add("withdraw the access request", "clerk", payload(clerk, 18, {
            1: request, 2: "requested", 3: "withdrawn"}, delegation))
        root, count = fields(("note", "grant the record"),)
        grant = add("register an access grant", "org_root", payload(org, 16, {
            1: "cexchain.access-grant/1", 2: root, 3: count, 5: {
                "ledger": peer, "request": lg.h(b"their request"), "record": document, "fields": ["title"],
                "attachments": [], "until": t0 + 30 * day, "recipient": bytes([0x43]) * 32}}))
        refuse("a transition on an access grant", "org_root", payload(org, 18, {
            1: grant, 2: "granted", 3: "withdrawn"}), "transition")
        add("end the grant by revoking it", "org_root", payload(org, 19, {1: grant, 2: "no longer needed"}))
        root, count = fields(("note", "receipt"),)
        add("register an access receipt", "clerk", payload(clerk, 16, {
            1: "cexchain.access-receipt/1", 2: root, 3: count, 5: {
                "ledger": peer, "grant": lg.h(b"their grant"), "delivery": lg.h(b"delivery")}}, delegation))

        # The prefix is the nine bytes "cexchain.": a type that merely starts
        # with "cexchain" is a user's.
        root, count = fields(("text", "shopping list"),)
        add("register a record whose type starts with cexchain but not the prefix", "clerk", payload(clerk, 16, {
            1: "cexchain-example.note/1", 2: root, 3: count}, delegation))

        # The removed types, an invented one, and a version the protocol
        # does not define: all reserved. The asset types carry the metadata
        # v0.5 required, so the prefix is the only rule they break.
        asset_metadata = {
            "cexchain.receivable/1": {"holder": peer, "amount": 100_000, "currency": "HKD", "due": t0 + 90 * day},
            "cexchain.warehouse-receipt/1": {"holder": peer, "quantity": 10, "unit": "t"},
        }
        for kind in REMOVED_TYPES + ("cexchain.document/1", "cexchain.access-request/2"):
            root, count = fields(("text", kind),)
            body = {1: kind, 2: root, 3: count}
            if kind in asset_metadata:
                body[5] = asset_metadata[kind]
            refuse(f"register a record of type {kind}", "clerk", payload(clerk, 16, body, delegation),
                   "reserved type")

        add("revoke the user's record", "org_root", payload(org, 19, {1: document, 2: "returned"}))
        refuse("endorse a revoked record", "clerk", payload(clerk, 17, {1: document, 2: "late"}, delegation),
               "revoked")
        refuse("revoke a revoked record", "org_root", payload(org, 19, {1: document}), "revoked")

        # The log, the state over every object, its commitment, and a
        # checkpoint over all of it.
        entries = [encode_log_entry(bytes.fromhex(st["statement_id"]), st["registered_at"], bytes.fromhex(st["encoded"]))
                   for st in statements]
        leaves = [[1, a, h] for a, h in actors.items()] + [[2, d, h] for d, h in delegations.items()] + \
                 [[3, r, v["history"]] for r, v in records.items()]
        sorted_leaves = sorted(leaves, key=lambda leaf: leaf[1])
        commitment_index = len(entries)
        commitment_time = clock[0]
        commitment_id = append_state_commitment(lg, keys["log"], ledger_id, entries, sorted_leaves, commitment_time)
        checkpoint_time = commitment_time + 1000
        checkpoint, _ = sign_log_checkpoint(lg, keys["log"], ledger_id, entries, checkpoint_time)

        ledgers.append({
            "hash": hash_id,
            "ledger_id": ledger_id.hex(),
            "statements": statements,
            "refused": refused,
            "records": [{"id": r.hex(), "type": v["type"], "state": v["state"], "revoked": v["revoked"],
                         "registrant": v["registrant"].hex(), "history": v["history"],
                         "endorsements": [{"actor": a.hex(), "role": role, "index": i}
                                          for a, role, i in v["endorsements"]]}
                        for r, v in records.items()],
            "log_entries": [e.hex() for e in entries],
            "state_leaves": [{"kind": leaf[0], "id": leaf[1].hex(), "history": leaf[2]} for leaf in sorted_leaves],
            "state_root": smt_root(lg, sorted_leaves).hex(),
            "state_commitment": {"index": commitment_index, "id": commitment_id.hex()},
            "checkpoint": checkpoint.hex(),
            "checkpoint_time": checkpoint_time,
        })

    document = {
        "description": "CexChain protocol objects of specification revision v0.9 (the generic core), built by an "
                       "independent Python encoder from spec/cexchain.cddl. A ledger whose organization is a "
                       "household registers a person and delegates record statements to them. The person "
                       "registers a record of a user's own type (example.document/1), which takes endorsements "
                       "in any role, once per actor and role, no transition, and is revoked: the generic "
                       "lifecycle. The four mechanism types go through their lifecycles: a contract consent and "
                       "an access request are withdrawn (record-transition), an access grant is ended by "
                       "revocation, an access receipt stays received; none takes an endorsement. A type that "
                       "merely starts with \"cexchain\" (cexchain-example.note/1) is a user's. Each statement "
                       "registers at its `registered_at` (the log entries carry it). `refused` statements either "
                       "break the CDDL (`malformed`: statement type 20, reserved since v0.9, and a scope naming "
                       "it; `why` is \"unknown type\") or are validated against the state after the first "
                       "`after` statements, at `at`, and break exactly one rule, which `why` names: \"reserved "
                       "type\" (a registration of a type with the prefix \"cexchain.\" that is not a mechanism "
                       "type: the six types v0.9 removed, an invented one, and a version the protocol does not "
                       "define; the asset types carry the metadata v0.5 required), \"transition\" (not in the "
                       "type's lifecycle), \"state\" (not the record's current state), \"role\" (a mechanism "
                       "type defines none), \"repeated\" (the same actor and role again), \"revoked\" (a revoked "
                       "record takes nothing more). `records` gives each record's type, state, revocation, "
                       "registrant, history, and endorsements. `log_entries` holds the whole log, ending with "
                       "the state commitment over `state_leaves`; `checkpoint` (signed at `checkpoint_time`) "
                       "covers it. Signatures are Ed25519 (deterministic); keys are throwaway: seed = "
                       "SHA-256(\"CexChain test key: <name>\").",
        "t0": t0,
        "statement_types": list(STATEMENT_TYPES_V09),
        "mechanism_types": [{"type": kind, "initial": initial, "transitions": sorted([list(t) for t in transitions])}
                            for kind, (initial, transitions) in MECHANISM_TYPES_V09.items()],
        "generic_lifecycle": {"initial": "registered", "transitions": [], "roles": "any"},
        "reserved_prefix": RESERVED_PREFIX,
        "removed_types": list(REMOVED_TYPES),
        "seeds": seeds,
        "ledgers": ledgers,
    }
    (OUT / "protocol-v0.9.json").write_text(json.dumps(document, indent=1) + "\n")
    first = ledgers[0]
    reasons = sorted({r["why"] for r in first["refused"]})
    print(f"wrote protocol vectors for {len(ledgers)} ledgers to testvectors/protocol-v0.9.json: "
          f"{len(first['statements'])} statements, {len(first['refused'])} refused ({', '.join(reasons)}), "
          f"{len(first['records'])} records")


# ---------------------------------------------------------------------------
# Protocol v0.10: versions (spec sections 5, 6, 9, and 11): a registration
# that supersedes a record, in both records' histories
# ---------------------------------------------------------------------------

FORM_1 = "example.org.form/1"
FORM_2 = "example.org.form/2"


def generate_protocol_v10() -> None:
    names = ("org_root", "log", "clerk", "typist")
    seeds = {name: hashlib.sha256(f"CexChain test key: {name}".encode()).hexdigest() for name in names}
    keys = {name: ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)) for name, seed in seeds.items()}
    t0 = 1_793_491_200_000  # 2026-11-01T00:00:00Z
    minute, day = 60_000, 86_400_000
    peer = hashlib.sha256(b"Peer ledger").digest()

    ledgers = []
    for hash_id in (-16, -65538):
        lg = Ledger(hash_id)
        statements, refused = [], []
        actors, delegations, records, scopes = {}, {}, {}, {}
        clock = [t0 + 1000]

        def payload(signer_actor, body_type, body, delegation=None):
            n = len(statements) + len(refused) + 1
            out = {0: 1, 1: body_type, 5: clock[0] - 500, 6: n.to_bytes(16, "big"), 7: body}
            if signer_actor is not None:  # absent only in genesis
                out[2] = ledger_id
                out[3] = signer_actor
            if delegation is not None:
                out[4] = delegation
            return out

        def well_formed(p):
            """The CDDL of v0.10, as far as these vectors reach: key 6 of a
            registration is an id (32 bytes)."""
            return p[1] != 16 or 6 not in p[7] or (isinstance(p[7][6], bytes) and len(p[7][6]) == 32)

        def rules(p):
            """Every rule of section 5 that refuses these record statements:
            the version rules of v0.10, and the generic lifecycle's."""
            body, fails = p[7], []
            if p[1] == 16:
                kind = body[1]
                if kind.startswith(RESERVED_PREFIX) and kind not in MECHANISM_TYPES_V09:
                    fails.append("reserved type")
                if 6 in body:
                    if kind in MECHANISM_TYPES_V09:
                        fails.append("mechanism")
                    old = records.get(body[6])
                    if old is None:
                        fails.append("no such record")
                    else:
                        if old["type"] in MECHANISM_TYPES_V09:
                            fails.append("mechanism")
                        if old["superseded_by"] is not None:
                            fails.append("superseded")
                        scope = scopes.get(p.get(4))
                        if scope is not None and 2 in scope and old["type"] not in scope[2]:
                            fails.append("scope")
                return fails
            if p[1] not in (17, 19):
                return fails
            record = records.get(body[1])
            if record is None:
                return ["no such record"]
            if record["revoked"]:
                fails.append("revoked")
            if p[1] == 17 and any(a == p[3] and role == body[2] for a, role, _ in record["endorsements"]):
                fails.append("repeated")
            return fails

        def add(name, signer, p):
            """Registers the statement now, under the rules; the clock then
            moves a minute on."""
            assert well_formed(p) and rules(p) == [], (name, rules(p))
            encoded, statement_id = lg.statement(keys[signer], p)
            index = len(statements)
            statements.append({"name": name, "signer": signer, "encoded": encoded.hex(), "payload": dcbor(p).hex(),
                               "statement_id": statement_id.hex(), "registered_at": clock[0]})
            clock[0] += minute
            body = p[7]
            if p[1] in (1, 2):
                actors[statement_id] = [index]
            elif p[1] == 5:
                delegations[statement_id] = [index]
                scopes[statement_id] = body[2]
            elif p[1] == 16:
                initial = MECHANISM_TYPES_V09[body[1]][0] if body[1] in MECHANISM_TYPES_V09 else "registered"
                records[statement_id] = {"type": body[1], "state": initial, "revoked": False, "endorsements": [],
                                         "history": [index], "registrant": p[3], "supersedes": body.get(6),
                                         "superseded_by": None}
                if 6 in body:
                    # A statement about both records.
                    old = records[body[6]]
                    old["superseded_by"] = statement_id
                    old["history"].append(index)
            elif p[1] in (17, 19):
                record = records[body[1]]
                record["history"].append(index)
                if p[1] == 17:
                    record["endorsements"].append((p[3], body[2], index))
                else:
                    record["revoked"] = True
            return statement_id

        def refuse(name, signer, p, why):
            """`malformed` when the statement breaks the CDDL, so it does not
            even parse; otherwise the rules refuse it after the statements so
            far, at `at`, for the one rule `why` names."""
            malformed = why == "malformed"
            if malformed:
                assert not well_formed(p), name
            else:
                assert well_formed(p) and rules(p) == [why], (name, rules(p))
            encoded, _ = lg.statement(keys[signer], p)
            refused.append({"name": name, "signer": signer, "encoded": encoded.hex(), "payload": dcbor(p).hex(),
                            "after": len(statements), "at": clock[0], "malformed": malformed, "why": why})

        def fields(*values):
            leaves = [dcbor([name, bytes([0xC0 + i]) * 16, value])
                      for i, (name, value) in enumerate(sorted(values, key=lambda f: f[0].encode()))]
            return lg.merkle().mth(leaves), len(leaves)

        def form(version, kind, signer_actor, delegation, supersedes=None):
            root, count = fields(("text", f"the form, version {version}"), ("issued", f"2026-11-0{version}"))
            body = {1: kind, 2: root, 3: count, 5: {"title": "Day student application", "version": version}}
            if supersedes is not None:
                body[6] = supersedes
            return payload(signer_actor, 16, body, delegation)

        ledger_id = None
        ledger_id = add("genesis", "org_root", payload(None, 1, {
            1: hash_id, 2: "Example School", 3: ed_public(keys["org_root"]), 4: ed_public(keys["log"])}))
        org = ledger_id
        clerk = add("register the clerk", "org_root", payload(org, 2, {1: 1, 2: "Clerk", 3: ed_public(keys["clerk"])}))
        typist = add("register the typist", "org_root", payload(org, 2, {
            1: 1, 2: "Typist", 3: ed_public(keys["typist"])}))
        clerks = add("delegate both forms to the clerk", "org_root", payload(org, 5, {
            1: clerk, 2: {1: [16, 17, 19], 2: [FORM_1, FORM_2]}}))
        typists = add("delegate only the second form to the typist", "org_root", payload(org, 5, {
            1: typist, 2: {1: [16], 2: [FORM_2]}}))

        # A chain of versions, across two types.
        v1 = add("register version 1", "clerk", form(1, FORM_1, clerk, clerks))
        v2 = add("version 2 supersedes version 1", "clerk", form(2, FORM_1, clerk, clerks, v1))
        refuse("supersede version 1 again", "clerk", form(9, FORM_2, clerk, clerks, v1), "superseded")
        refuse("the typist supersedes version 2, of a type outside its scope", "typist",
               form(3, FORM_2, typist, typists, v2), "scope")
        v3 = add("version 3, of the second type, supersedes version 2", "clerk", form(3, FORM_2, clerk, clerks, v2))
        # A superseded record keeps its lifecycle: endorsed and revoked later.
        add("endorse version 1 after it was superseded", "clerk", payload(clerk, 17, {1: v1, 2: "archivist"}, clerks))
        add("revoke version 3", "org_root", payload(org, 19, {1: v3, 2: "printed with the wrong date"}))
        # A revoked record can still be superseded, here by the organization.
        v4 = add("the organization's version 4 supersedes the revoked version 3", "org_root",
                 form(4, FORM_2, org, None, v3))
        add("revoke version 1 after it was superseded", "org_root", payload(org, 19, {1: v1, 2: "archived"}))
        refuse("supersede version 1, revoked and superseded, again", "org_root", form(8, FORM_2, org, None, v1),
               "superseded")
        refuse("supersede a record that does not exist", "clerk",
               form(5, FORM_2, clerk, clerks, lg.h(b"no such record")), "no such record")
        refuse("supersede with an id of 16 bytes", "clerk", form(5, FORM_2, clerk, clerks, bytes(16)), "malformed")

        # The mechanism types take no part.
        root, count = fields(("note", "approve the booking"),)
        consent_body = {1: CONTRACT_CONSENT, 2: root, 3: count, 5: {
            "ledger": peer, "instance": lg.h(b"instance"), "function": "approve", "head": 4,
            "arguments": lg.h(dcbor(None)), "until": t0 + 7 * day}}
        consent = add("register a contract consent", "org_root", payload(org, 16, consent_body))
        refuse("a form supersedes the consent", "org_root", form(5, FORM_2, org, None, consent), "mechanism")
        refuse("a consent supersedes version 4", "org_root", payload(org, 16, {**consent_body, 6: v4}),
               "mechanism")
        v5 = add("version 5 supersedes version 4", "clerk", form(5, FORM_2, clerk, clerks, v4))

        entries = [encode_log_entry(bytes.fromhex(st["statement_id"]), st["registered_at"], bytes.fromhex(st["encoded"]))
                   for st in statements]
        leaves = [[1, a, h] for a, h in actors.items()] + [[2, d, h] for d, h in delegations.items()] + \
                 [[3, r, v["history"]] for r, v in records.items()]
        sorted_leaves = sorted(leaves, key=lambda leaf: leaf[1])
        commitment_index = len(entries)
        commitment_time = clock[0]
        commitment_id = append_state_commitment(lg, keys["log"], ledger_id, entries, sorted_leaves, commitment_time)
        checkpoint_time = commitment_time + 1000
        checkpoint, _ = sign_log_checkpoint(lg, keys["log"], ledger_id, entries, checkpoint_time)

        ledgers.append({
            "hash": hash_id,
            "ledger_id": ledger_id.hex(),
            "statements": statements,
            "refused": refused,
            "versions": [v.hex() for v in (v1, v2, v3, v4, v5)],
            "records": [{"id": r.hex(), "type": v["type"], "state": v["state"], "revoked": v["revoked"],
                         "registrant": v["registrant"].hex(), "history": v["history"],
                         "supersedes": v["supersedes"].hex() if v["supersedes"] else None,
                         "superseded_by": v["superseded_by"].hex() if v["superseded_by"] else None,
                         "endorsements": [{"actor": a.hex(), "role": role, "index": i}
                                          for a, role, i in v["endorsements"]]}
                        for r, v in records.items()],
            "log_entries": [e.hex() for e in entries],
            "state_leaves": [{"kind": leaf[0], "id": leaf[1].hex(), "history": leaf[2]} for leaf in sorted_leaves],
            "state_root": smt_root(lg, sorted_leaves).hex(),
            "state_commitment": {"index": commitment_index, "id": commitment_id.hex()},
            "checkpoint": checkpoint.hex(),
            "checkpoint_time": checkpoint_time,
        })

    document = {
        "description": "CexChain protocol objects of specification revision v0.10 (versions), built by an "
                       "independent Python encoder from spec/cexchain.cddl. A school's ledger registers a clerk, "
                       "delegated record statements on both of its form types (example.org.form/1 and /2), and a "
                       "typist, delegated registrations of the second type only. Five versions of a form form "
                       "one chain (`versions`, oldest first): each registration names the record it supersedes "
                       "(key 6), across the two types; version 1 is endorsed and revoked after it was "
                       "superseded; version 3 is revoked, and the organization's version 4 supersedes it all "
                       "the same. The superseding registration is in both records' histories, so the state "
                       "leaves list it twice. `refused` statements either break the CDDL (`malformed`: an id of "
                       "16 bytes in key 6) or are validated against the state after the first `after` "
                       "statements, at `at`, and break exactly one rule, which `why` names: \"superseded\" (the "
                       "record has a newer version already), \"scope\" (the signer's delegation does not cover "
                       "the superseded record's type), \"no such record\", \"mechanism\" (a mechanism type, "
                       "here a contract consent, on either side). `records` gives each record's type, state, "
                       "revocation, registrant, history, endorsements, and the records it supersedes and that "
                       "superseded it. `log_entries` holds the whole log, ending with the state commitment over "
                       "`state_leaves`; `checkpoint` (signed at `checkpoint_time`) covers it. Signatures are "
                       "Ed25519 (deterministic); keys are throwaway: seed = SHA-256(\"CexChain test key: "
                       "<name>\").",
        "t0": t0,
        "seeds": seeds,
        "ledgers": ledgers,
    }
    (OUT / "protocol-v0.10.json").write_text(json.dumps(document, indent=1) + "\n")
    first = ledgers[0]
    reasons = sorted({r["why"] for r in first["refused"]})
    print(f"wrote protocol vectors for {len(ledgers)} ledgers to testvectors/protocol-v0.10.json: "
          f"{len(first['statements'])} statements, {len(first['refused'])} refused ({', '.join(reasons)}), "
          f"{len(first['records'])} records")


def generate_protocol_v11(openssl: str) -> None:
    """Time-stamp tokens over checkpoints (spec v0.11): a time-stamp
    authority's root and certificate made with `cryptography`, its tokens made
    by OpenSSL's command-line responder over the payloads of the v0.10
    vectors' checkpoints."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    v10 = json.loads((OUT / "protocol-v0.10.json").read_text())
    root_key = ec.derive_private_key(int.from_bytes(hashlib.sha256(b"CexChain test key: tsa_root").digest(), "big")
                                     % (2**255), ec.SECP256R1())
    tsa_key = ec.derive_private_key(int.from_bytes(hashlib.sha256(b"CexChain test key: tsa").digest(), "big")
                                    % (2**255), ec.SECP256R1())
    start = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    end = datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA Root")])
    tsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA")])
    root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
            .public_key(root_key.public_key()).serial_number(1).not_valid_before(start).not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(root_key, hashes.SHA256()))
    tsa = (x509.CertificateBuilder().subject_name(tsa_name).issuer_name(root_name)
           .public_key(tsa_key.public_key()).serial_number(2).not_valid_before(start).not_valid_after(end)
           .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
           .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
           .sign(root_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    cases = []
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        (d / "root.pem").write_bytes(root.public_bytes(pem))
        (d / "tsa.pem").write_bytes(tsa.public_bytes(pem))
        (d / "tsa.key").write_bytes(tsa_key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                           serialization.NoEncryption()))
        (d / "serial").write_text("01\n")
        (d / "tsa.cnf").write_text(
            "[ tsa ]\ndefault_tsa = c\n[ c ]\n"
            f"serial = {d / 'serial'}\nsigner_cert = {d / 'tsa.pem'}\ncerts = {d / 'root.pem'}\n"
            f"signer_key = {d / 'tsa.key'}\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\n"
            "digests = sha256, sm3\naccuracy = secs:1\nclock_precision_digits = 3\ness_cert_id_alg = sha256\n")
        for lg in v10["ledgers"]:
            checkpoint = bytes.fromhex(lg["checkpoint"])
            sign1 = cbor2.loads(checkpoint)
            sign1 = sign1.value if isinstance(sign1, cbor2.CBORTag) else sign1
            payload = sign1[2]
            name = HASHES[lg["hash"]]
            imprint = hashlib.new(name, payload).digest()
            subprocess.run([openssl, "ts", "-query", "-digest", imprint.hex(), f"-{name}", "-cert",
                            "-out", str(d / "q")], check=True, capture_output=True)
            subprocess.run([openssl, "ts", "-reply", "-config", str(d / "tsa.cnf"), "-queryfile", str(d / "q"),
                            "-token_out", "-out", str(d / "token")], check=True, capture_output=True)
            text = subprocess.run([openssl, "ts", "-reply", "-in", str(d / "token"), "-token_in", "-text"],
                                  check=True, capture_output=True, text=True).stdout
            stamped = re.search(r"Time stamp: (.+) GMT", text).group(1)
            when = datetime.datetime.strptime(" ".join(stamped.split()), "%b %d %H:%M:%S.%f %Y")
            time_ms = int(when.replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)
            cases.append({
                "hash": lg["hash"],
                "ledger_id": lg["ledger_id"],
                "checkpoint": checkpoint.hex(),
                "imprint": imprint.hex(),
                "token": (d / "token").read_bytes().hex(),
                "time": time_ms,
                "accuracy": 1000,
                "authority": "CN=Test TSA",
            })
    document = {
        "description": "Time-stamp tokens of specification revision v0.11: RFC 3161 TimeStampTokens over the "
                       "payloads of the signed checkpoints of protocol-v0.10.json, one per ledger (SHA-256 and "
                       "SM3). `imprint` is the ledger's hash of the checkpoint's COSE payload, which the token's "
                       "message imprint must equal; `time` (Unix milliseconds) and `accuracy` (milliseconds) are "
                       "the token's genTime and accuracy; `authority` is its signing certificate's subject "
                       "(RFC 4514). The authority's certificate (`certificate`, critical id-kp-timeStamping) is "
                       "issued by `root`, which a verifier trusts; both are made by Python's `cryptography` on "
                       "throwaway P-256 keys, valid 2020-2040, and the tokens by OpenSSL's `openssl ts -reply` "
                       "(signer digest SHA-256, ESSCertIDv2). A token is valid only for its own checkpoint: the "
                       "other ledger's token stamps another payload.",
        "root": root.public_bytes(pem).decode(),
        "certificate": tsa.public_bytes(pem).decode(),
        "cases": cases,
    }
    (OUT / "protocol-v0.11.json").write_text(json.dumps(document, indent=1) + "\n")
    print(f"wrote {len(cases)} time-stamp tokens to testvectors/protocol-v0.11.json")


def generate_protocol_v13() -> None:
    """Open witness networks (spec v0.13): the SHA-256 checkpoint of
    protocol-v0.10.json as a C2SP checkpoint note under the ledger's origin,
    signed with a note key, and cosigned by two network witnesses (Ed25519,
    signature type 0x04; ML-DSA-44, type 0x06), written from c2sp.org's
    texts with Python's `cryptography`; and signed-note's own example."""
    import base64
    import struct

    v10 = json.loads((OUT / "protocol-v0.10.json").read_text())
    lg = next(entry for entry in v10["ledgers"] if entry["hash"] == -16)
    checkpoint = bytes.fromhex(lg["checkpoint"])
    sign1 = cbor2.loads(checkpoint)
    sign1 = sign1.value if isinstance(sign1, cbor2.CBORTag) else sign1
    payload = cbor2.loads(sign1[2])
    size, root = payload[3], payload[4]
    origin = "cirraya.com/cexchain/" + lg["ledger_id"]
    note = f"{origin}\n{size}\n{base64.b64encode(root).decode()}\n"

    def b64(data: bytes) -> str:
        return base64.b64encode(data).decode()

    def key_id(name: str, kind: int, public: bytes) -> bytes:
        return hashlib.sha256(name.encode() + b"\n" + bytes([kind]) + public).digest()[:4]

    def vkey(name: str, kind: int, public: bytes) -> str:
        return f"{name}+{key_id(name, kind, public).hex()}+{b64(bytes([kind]) + public)}"

    def seeded(name: str) -> ed25519.Ed25519PrivateKey:
        return ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"CexChain test key: {name}".encode()).digest())

    raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
    note_key = seeded("note")
    note_public = note_key.public_key().public_bytes(*raw)
    signed_note = note + "\n" + f"\u2014 {origin} {b64(key_id(origin, 1, note_public) + note_key.sign(note.encode()))}\n"

    seen = 1_794_000_000  # the witnesses' time, POSIX seconds

    def ed25519_cosignature(key, name: str, text: str, at: int) -> bytes:
        public = key.public_key().public_bytes(*raw)
        message = f"cosignature/v1\ntime {at}\n{text}".encode()
        return key_id(name, 4, public) + struct.pack(">Q", at) + key.sign(message)

    def subtree(name: str, at: int, tree_size: int, tree_root: bytes) -> bytes:
        return (b"subtree/v1\n\0" + bytes([len(name)]) + name.encode() + struct.pack(">Q", at) +
                bytes([len(origin)]) + origin.encode() + struct.pack(">QQ", 0, tree_size) + tree_root)

    ed_name, ml_name = "witness.example/ed25519", "witness.example/ml-dsa-44"
    ed_key = seeded("network witness ed25519")
    ml_key = mldsa.MLDSA44PrivateKey.generate()
    ed_public = ed_key.public_key().public_bytes(*raw)
    ml_public = ml_key.public_key().public_bytes_raw()
    ed_bytes = ed25519_cosignature(ed_key, ed_name, note, seen)
    ml_bytes = key_id(ml_name, 6, ml_public) + struct.pack(">Q", seen) + ml_key.sign(subtree(ml_name, seen, size, root))
    other_note = f"{origin}\n{size + 1}\n{b64(root)}\n"
    cases = [
        {"name": "ed25519", "description": "an Ed25519 cosignature of the note", "vkey": vkey(ed_name, 4, ed_public),
         "cosigner": ed_name, "bytes": ed_bytes.hex(), "time": seen, "valid": True},
        {"name": "ml-dsa-44", "description": "an ML-DSA-44 cosignature of the note (a CosignedSubtree from 0)",
         "vkey": vkey(ml_name, 6, ml_public), "cosigner": ml_name, "bytes": ml_bytes.hex(), "time": seen,
         "valid": True},
        {"name": "another-size", "description": "an Ed25519 cosignature of a note of another size",
         "vkey": vkey(ed_name, 4, ed_public), "cosigner": ed_name,
         "bytes": ed25519_cosignature(ed_key, ed_name, other_note, seen).hex(), "time": seen, "valid": False},
        {"name": "another-time", "description": "the Ed25519 cosignature with its time changed",
         "vkey": vkey(ed_name, 4, ed_public), "cosigner": ed_name,
         "bytes": (ed_bytes[:4] + struct.pack(">Q", seen + 1) + ed_bytes[12:]).hex(), "time": seen + 1,
         "valid": False},
    ]
    anchor = cbor2.dumps({1: checkpoint, 4: [[ed_name, ed_bytes], [ml_name, ml_bytes]]}, canonical=True)
    document = {
        "description": "Open witness networks of specification revision v0.13 (section 10.2), written from "
                       "c2sp.org's signed-note, tlog-checkpoint, tlog-cosignature, and tlog-witness with Python's "
                       "`cryptography`. `note` is the checkpoint note of the SHA-256 ledger of protocol-v0.10.json "
                       "(its signed checkpoint is `checkpoint`): the origin cirraya.com/cexchain/ followed by the "
                       "ledger id in hex, the tree size, and the root in base64. `signed_note` adds the note key's "
                       "log signature (Ed25519, type 0x01, key name the origin; its verifier key is `note_vkey`), "
                       "and `add_checkpoint` is the body of a first add-checkpoint (old size 0, no proof). Each "
                       "case is a witness's verifier key and the bytes of its note signature (key ID, 8-byte "
                       "time, signature); `valid` says whether they verify against `note`. `anchor` is an "
                       "evidence anchor (key 1 the checkpoint, key 4 the two valid cosignatures). `c2sp_example` "
                       "is signed-note's own example: its verifier key verifies its note. Keys are throwaway: "
                       "Ed25519 seed = SHA-256(\"CexChain test key: <name>\"); the ML-DSA-44 key is random, so "
                       "its bytes change each time the vectors are made.",
        "ledger_id": lg["ledger_id"],
        "checkpoint": checkpoint.hex(),
        "origin": origin,
        "note": note,
        "note_vkey": vkey(origin, 1, note_public),
        "signed_note": signed_note,
        "add_checkpoint": f"old 0\n\n{signed_note}",
        "cases": cases,
        "anchor": anchor.hex(),
        "c2sp_example": {
            "vkey": "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k",
            "note": "This is an example message.\n",
            "signature": "Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=",
        },
    }
    (OUT / "protocol-v0.13.json").write_text(json.dumps(document, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {len(cases)} network cosignatures to testvectors/protocol-v0.13.json")


# ---------------------------------------------------------------------------
# Protocol v0.14: claims (spec sections 5, 6, and 11): a cexchain.claim/1
# record says that, in another record of the ledger (its source), a condition
# on fields holds or does not, without disclosing them
# ---------------------------------------------------------------------------

CLAIM_REQUIRED = ("source", "condition", "holds", "as_of")
CLAIM_OPTIONAL = ("until", "subject", "for")
CLAIM_ORDERED = (">", ">=", "<", "<=")
CLAIM_OPS = CLAIM_ORDERED + ("=", "!=", "between", "in", "exists")
CLAIM_VALUE_TYPES = ("number", "money", "date", "text")
# The operators' English words (section 11, "A claim in words"); between,
# in, and exists have words of their own.
CLAIM_WORDS = {">": "is above", ">=": "is at least", "<": "is below", "<=": "is at most", "=": "is",
               "!=": "is not"}
CLAIM_DECIMAL = re.compile(r"-?[0-9]+(\.[0-9]+)?")
CLAIM_CURRENCY = re.compile(r"[A-Z]{3}")
CLAIM_DATE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})")
EMPLOYMENT = "example.org.employment/1"


def _cbor_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and -2**64 <= v < 2**64


def claim_value_ok(kind: str, v) -> bool:
    """One value of a claim term's type (section 6)."""
    if kind == "number":
        return _cbor_int(v) or (isinstance(v, str) and len(v) <= 40 and CLAIM_DECIMAL.fullmatch(v) is not None)
    if kind == "money":
        return (isinstance(v, list) and len(v) == 3 and _cbor_int(v[0]) and isinstance(v[1], str)
                and CLAIM_CURRENCY.fullmatch(v[1]) is not None and _cbor_int(v[2]) and 0 <= v[2] <= 4)
    if kind == "date":
        match = CLAIM_DATE.fullmatch(v) if isinstance(v, str) else None
        if match is None:
            return False
        year, month, day = (int(x) for x in match.groups())
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        return 1 <= month <= 12 and 1 <= day <= (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30,
                                                  31)[month - 1]
    return isinstance(v, str) and 1 <= len(v.encode()) <= 256


def claim_magnitude(kind: str, v):
    """What a value of the type is, to order and compare: a number exactly,
    money with its currency, a date as its text (YYYY-MM-DD orders so)."""
    import fractions
    if kind == "number":
        return fractions.Fraction(v)
    if kind == "money":
        return v[1], fractions.Fraction(v[0], 10 ** v[2])
    return v


def claim_term_problem(term) -> str | None:
    if not (isinstance(term, list) and len(term) == 4):
        return "term"
    field, op, kind, value = term
    if not (isinstance(field, str) and 1 <= len(field.encode()) <= 64):
        return "field"
    if not (isinstance(op, str) and op in CLAIM_OPS):
        return "operator"
    if not (isinstance(kind, str) and kind in CLAIM_VALUE_TYPES):
        return "type"
    # The order operators take numbers, money, and dates; exists takes text.
    if (op in CLAIM_ORDERED + ("between",) and kind == "text") or (op == "exists" and kind != "text"):
        return "operator and type"
    if op == "exists":
        return None if value is None else "value"
    if op == "between":
        if not (isinstance(value, list) and len(value) == 2):
            return "value"
        values = value
    elif op == "in":
        if not (isinstance(value, list) and 1 <= len(value) <= 64):
            return "value"
        values = value
    else:
        if value is None:
            return "value"
        values = [value]
    if not all(claim_value_ok(kind, v) for v in values):
        return kind
    if op == "between":
        low, high = (claim_magnitude(kind, v) for v in values)
        if kind == "money" and low[0] != high[0]:
            return "order"
        if low > high:
            return "order"
    if op == "in":
        magnitudes = [claim_magnitude(kind, v) for v in values]
        if len(set(magnitudes)) != len(magnitudes):
            return "distinct"
    return None


def claim_problem(metadata) -> str | None:
    """Why a claim's metadata (record key 5) is not a `claim` of the CDDL with
    the prose's limits (section 6), or None. The ledger refuses other keys."""
    if not isinstance(metadata, dict):
        return "no metadata"
    keys = set(metadata)
    if keys - set(CLAIM_REQUIRED) - set(CLAIM_OPTIONAL):
        return "unknown key"
    if set(CLAIM_REQUIRED) - keys:
        return "missing key"
    m = metadata
    if not (isinstance(m["source"], bytes) and len(m["source"]) == 32):
        return "source"
    if not (isinstance(m["condition"], list) and 1 <= len(m["condition"]) <= 16):
        return "condition"
    for term in m["condition"]:
        problem = claim_term_problem(term)
        if problem is not None:
            return problem
    if not isinstance(m["holds"], bool):
        return "holds"
    if not (_cbor_int(m["as_of"]) and m["as_of"] >= 0):
        return "as_of"
    if "until" in m and not (_cbor_int(m["until"]) and m["until"] > m["as_of"]):
        return "until"
    if "subject" in m and not (isinstance(m["subject"], str) and 1 <= len(m["subject"].encode()) <= 256):
        return "subject"
    if "for" in m and not (isinstance(m["for"], list) and len(m["for"]) == 2
                           and all(isinstance(x, bytes) and len(x) == 32 for x in m["for"])):
        return "for"
    return None


def claim_value_words(kind: str, v) -> str:
    """A value as a report writes it (section 11, "A claim in words")."""
    if kind == "number":
        return str(v)  # an integer in decimal digits, a decimal text as is
    if kind == "money":
        amount, currency, scale = v
        whole, part = divmod(abs(amount), 10 ** scale)
        words = f"{currency} {'-' if amount < 0 else ''}{whole:,}"
        return words + (f".{part:0{scale}d}" if scale else "")
    if kind == "date":
        return v
    return f'"{v}"'


def claim_words(condition: list) -> str:
    """A claim's condition as one line of English (section 11)."""
    terms = []
    for field, op, kind, value in condition:
        if op == "exists":
            terms.append(f"{field} is given")
        elif op == "between":
            terms.append(f"{field} is between {claim_value_words(kind, value[0])} and "
                         f"{claim_value_words(kind, value[1])}")
        elif op == "in":
            terms.append(f"{field} is one of " + ", ".join(claim_value_words(kind, v) for v in value))
        else:
            terms.append(f"{field} {CLAIM_WORDS[op]} {claim_value_words(kind, value)}")
    return " and ".join(terms)


SPEC_CLAIM_EXAMPLE = [["monthly_salary", ">", "money", [3000000, "HKD", 2]],
                      ["status", "in", "text", ["staff", "contractor"]]]
SPEC_CLAIM_WORDS = 'monthly_salary is above HKD 30,000.00 and status is one of "staff", "contractor"'


def claim_metadata_cases(t0: int) -> tuple[list, list]:
    """Claim metadata on its own: (valid cases, refused cases)."""
    source = hashlib.sha256(b"CexChain claim source").digest()
    request = [hashlib.sha256(b"Peer ledger").digest(), hashlib.sha256(b"an access request").digest()]
    day = 86_400_000

    def meta(condition, **extra):
        out = {"source": source, "condition": condition, "holds": True, "as_of": t0}
        out.update(extra)
        return out

    valid, refused = [], []

    def ok(name, metadata, words=None):
        assert claim_problem(metadata) is None, (name, claim_problem(metadata))
        text = claim_words(metadata["condition"])
        assert words is None or text == words, (name, text, words)
        valid.append({"name": name, "metadata": dcbor(metadata).hex(), "condition": metadata["condition"],
                      "text": text})

    def bad(name, metadata, why):
        assert claim_problem(metadata) == why, (name, claim_problem(metadata), why)
        refused.append({"name": name, "metadata": dcbor(metadata).hex(), "why": why})

    ok("the specification's example, with until and subject",
       meta(SPEC_CLAIM_EXAMPLE, until=t0 + 30 * day, subject="Chan Tai Man"), SPEC_CLAIM_WORDS)
    ok("each order operator on numbers, integers and decimal texts",
       meta([["age", ">=", "number", 18], ["score", "<", "number", "99.5"], ["balance", "<=", "number", -250],
             ["rate", ">", "number", "-0.75"], ["code", "<", "number", "007.50"]]),
       "age is at least 18 and score is below 99.5 and balance is at most -250 and rate is above -0.75 and "
       "code is below 007.50")
    ok("equality on every type",
       meta([["grade", "=", "text", "A"], ["band", "!=", "number", 3], ["deposit", "=", "money", [0, "USD", 2]],
             ["joined", "!=", "date", "2024-02-29"]]),
       'grade is "A" and band is not 3 and deposit is USD 0.00 and joined is not 2024-02-29')
    ok("between, both bounds included, of numbers, dates, and money",
       meta([["floor", "between", "number", [5, 5]], ["height", "between", "number", [1, "1.5"]],
             ["start", "between", "date", ["2000-02-29", "2026-12-31"]],
             ["salary", "between", "money", [[2000000, "HKD", 2], [4000000, "HKD", 2]]]]),
       "floor is between 5 and 5 and height is between 1 and 1.5 and start is between 2000-02-29 and 2026-12-31 "
       "and salary is between HKD 20,000.00 and HKD 40,000.00")
    ok("in, of every type",
       meta([["status", "in", "text", ["staff"]], ["level", "in", "number", [1, 2, "3.5"]],
             ["fee", "in", "money", [[100, "EUR", 0], [250, "EUR", 0]]],
             ["review", "in", "date", ["2026-03-31", "2026-09-30"]]]),
       'status is one of "staff" and level is one of 1, 2, 3.5 and fee is one of EUR 100, EUR 250 and review is '
       'one of 2026-03-31, 2026-09-30')
    ok("exists, a claim that does not hold, answering an access request",
       meta([["licence_number", "exists", "text", None]], holds=False, **{"for": request}),
       "licence_number is given")
    ok("money: groups of three, signs, and scales 0 to 4",
       meta([["a", ">", "money", [123456789012, "JPY", 0]], ["b", "<", "money", [-5, "USD", 2]],
             ["c", ">=", "money", [5, "CHF", 4]], ["d", "<=", "money", [-100000, "GBP", 0]],
             ["e", "=", "money", [1000, "HKD", 3]], ["f", "!=", "money", [-123456, "CNY", 1]],
             ["g", ">", "money", [999, "SGD", 0]]]),
       "a is above JPY 123,456,789,012 and b is below USD -0.05 and c is at least CHF 0.0005 and d is at most "
       "GBP -100,000 and e is HKD 1.000 and f is not CNY -12,345.6 and g is above SGD 999")
    ok("the largest and smallest integers",
       meta([["n", "<=", "number", 2**64 - 1], ["m", ">=", "number", -2**64],
             ["big", "<", "money", [2**64 - 1, "HKD", 2]]]),
       "n is at most 18446744073709551615 and m is at least -18446744073709551616 and big is below "
       "HKD 184,467,440,737,095,516.15")
    ok("text as it is, between double quotes, and names in any script",
       meta([["name", "=", "text", 'Chan "Tai Man"'], ["名字", "!=", "text", "陳大文"]],
            subject="陳大文 (Chan Tai Man)"),
       'name is "Chan "Tai Man"" and 名字 is not "陳大文"')
    sixteen = [[f"field_{i:02d}", ">", "number", i] for i in range(16)]
    ok("sixteen terms", meta(sixteen))
    limits = [["f" * 64, "=", "text", "t" * 256], ["d", "=", "number", "-" + "9" * 19 + "." + "9" * 19],
              ["v", "in", "number", list(range(64))]]
    assert len(limits[1][3]) == 40
    ok("sizes at their limits: a 64-byte field, a 256-byte text, a 40-character decimal, 64 values in, and a "
       "256-byte subject", meta(limits, subject="s" * 256))
    ok("until one millisecond after as_of", meta([["x", "=", "number", 0]], until=t0 + 1))

    base = meta([["x", "=", "number", 1]])

    def but(**changes):
        out = dict(base)
        for k, v in changes.items():
            if v is None:
                del out[k]
            else:
                out[k] = v
        return out

    def term(t):
        return but(condition=[t])

    bad("an unknown key", but(note="hello"), "unknown key")
    bad("a misspelt optional key", but(unti=t0 + day), "unknown key")
    for key in CLAIM_REQUIRED:
        bad(f"no {key}", but(**{key: None}), "missing key")
    bad("a source of 31 bytes", but(source=source[:31]), "source")
    bad("a source as text", but(source=source.hex()), "source")
    bad("no terms", but(condition=[]), "condition")
    bad("seventeen terms", but(condition=sixteen + [["x", "=", "number", 1]]), "condition")
    bad("a condition that is one term, not a list of terms", but(condition=["x", "=", "number", 1]), "term")
    bad("a term of three elements", term(["x", "=", "number"]), "term")
    bad("a term of five elements", term(["x", "=", "number", 1, 2]), "term")
    bad("an empty field name", term(["", "=", "number", 1]), "field")
    bad("a field name of 65 bytes", term(["f" * 65, "=", "number", 1]), "field")
    bad("a field name as bytes", term([b"x", "=", "number", 1]), "field")
    for op in ("==", "≥", "BETWEEN", "contains", ""):
        bad(f"the operator {op!r}", term(["x", op, "number", 1]), "operator")
    for kind in ("percent", "integer", "Text", "string"):
        bad(f"the type {kind!r}", term(["x", "=", kind, 1]), "type")
    for op in CLAIM_ORDERED:
        bad(f"{op} on text", term(["x", op, "text", "b"]), "operator and type")
    bad("exists on a number", term(["x", "exists", "number", None]), "operator and type")
    bad("exists on a date", term(["x", "exists", "date", None]), "operator and type")
    bad("exists with a value", term(["x", "exists", "text", "yes"]), "value")
    bad("= with null", term(["x", "=", "number", None]), "value")
    bad("> with null", term(["x", ">", "date", None]), "value")
    bad("between with one value", term(["x", "between", "number", 5]), "value")
    bad("between with three values", term(["x", "between", "number", [1, 2, 3]]), "value")
    bad("in with no values", term(["x", "in", "number", []]), "value")
    bad("in with 65 values", term(["x", "in", "number", list(range(65))]), "value")
    bad("in with one value, not a list", term(["x", "in", "text", "staff"]), "value")
    for v in ("1e5", "1.", ".5", "+1", "1,000", "１", " 1", "1 ", "1.2.3", "-", "", "0x10"):
        bad(f"the number {v!r}", term(["x", "=", "number", v]), "number")
    bad("a decimal text of 41 characters", term(["x", "=", "number", "1" * 20 + "." + "1" * 20]), "number")
    bad("a number that is true", term(["x", "=", "number", True]), "number")
    bad("a number as bytes", term(["x", "=", "number", b"\x01"]), "number")
    bad("a number as money", term(["x", "=", "number", [100, "HKD", 2]]), "number")
    for v, what in (([100, "hkd", 2], "a lower-case currency"), ([100, "HKDD", 2], "a four-letter currency"),
                    ([100, "HK", 2], "a two-letter currency"), ([100, "HKD", 5], "a scale of 5"),
                    ([100, "HKD", -1], "a scale of -1"), (["100", "HKD", 2], "an amount as text"),
                    ([100, "HKD"], "no scale"), ([100, "HKD", 2, 0], "four elements"),
                    (100, "an integer"), ([100, "ＨＫＤ", 2], "a currency in full-width letters"),
                    ([True, "HKD", 2], "an amount that is true")):
        bad(f"money: {what}", term(["x", "=", "money", v]), "money")
    for v in ("2026-02-30", "2025-02-29", "1900-02-29", "2026-13-01", "2026-00-10", "2026-01-00", "2026-04-31",
              "2026-1-01", "20260101", "2026-01-01T00:00:00Z", "2026/01/01", "２０２６-01-01"):
        bad(f"the date {v!r}", term(["x", "=", "date", v]), "date")
    bad("a date as an integer", term(["x", "=", "date", 20260101]), "date")
    bad("an empty text", term(["x", "=", "text", ""]), "text")
    bad("a text of 257 bytes", term(["x", "=", "text", "t" * 257]), "text")
    bad("a text as bytes", term(["x", "=", "text", b"staff"]), "text")
    bad("a text that is a number", term(["x", "=", "text", 5]), "text")
    bad("one of the in values is not text", term(["x", "in", "text", ["staff", 5]]), "text")
    bad("between numbers, low above high", term(["x", "between", "number", [10, 5]]), "order")
    bad("between a decimal and an integer, low above high", term(["x", "between", "number", ["1.5", 1]]),
        "order")
    bad("between dates, low above high", term(["x", "between", "date", ["2026-12-31", "2026-01-01"]]), "order")
    bad("between money of one currency, low above high (4.00 and 3)",
        term(["x", "between", "money", [[400, "HKD", 2], [3, "HKD", 0]]]), "order")
    bad("in with a text twice", term(["x", "in", "text", ["staff", "contractor", "staff"]]), "distinct")
    bad("in with a date twice", term(["x", "in", "date", ["2026-01-01", "2026-01-01"]]), "distinct")
    bad("in with an integer twice", term(["x", "in", "number", [1, 2, 1]]), "distinct")
    bad("holds as an integer", but(holds=1), "holds")
    bad("holds as text", but(holds="true"), "holds")
    bad("a negative as_of", but(as_of=-1), "as_of")
    bad("as_of as text", but(as_of="2026-11-10"), "as_of")
    bad("until equal to as_of", but(until=t0), "until")
    bad("until before as_of", but(until=t0 - 1), "until")
    bad("until as text", but(until="2026-12-10"), "until")
    bad("an empty subject", but(subject=""), "subject")
    bad("a subject of 257 bytes", but(subject="s" * 257), "subject")
    bad("a subject as bytes", but(subject=b"Chan"), "subject")
    bad("for with one id", but(**{"for": request[:1]}), "for")
    bad("for with three ids", but(**{"for": request + [source]}), "for")
    bad("for with an id of 16 bytes", but(**{"for": [request[0], request[1][:16]]}), "for")
    bad("for as a map", but(**{"for": {"ledger": request[0], "record": request[1]}}), "for")
    return valid, refused


def generate_protocol_v14() -> None:
    names = ("org_root", "log", "clerk")
    seeds = {name: hashlib.sha256(f"CexChain test key: {name}".encode()).hexdigest() for name in names}
    keys = {name: ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)) for name, seed in seeds.items()}
    t0 = 1_794_268_800_000  # 2026-11-10T00:00:00Z
    minute, second, day = 60_000, 1_000, 86_400_000
    peer = hashlib.sha256(b"Peer ledger").digest()
    valid_metadata, refused_metadata = claim_metadata_cases(t0)

    ledgers = []
    for hash_id in (-16, -65538):
        lg = Ledger(hash_id)
        statements, refused = [], []
        actors, delegations, records = {}, {}, {}
        clock = [t0 + 1000]

        def payload(signer_actor, body_type, body, delegation=None):
            n = len(statements) + len(refused) + 1
            out = {0: 1, 1: body_type, 5: clock[0] - 500, 6: n.to_bytes(16, "big"), 7: body}
            if signer_actor is not None:  # absent only in genesis
                out[2] = ledger_id
                out[3] = signer_actor
            if delegation is not None:
                out[4] = delegation
            return out

        def rules(p):
            """Every rule of section 5 that refuses these record statements:
            the generic lifecycle's, the mechanism types', the version rules
            of v0.10, and the claim rules of v0.14 (section 6). The signers
            are always authorized."""
            body, fails = p[7], []
            if p[1] == 16:
                kind = body[1]
                if kind.startswith(RESERVED_PREFIX) and kind not in MECHANISM_TYPES:
                    fails.append("reserved type")
                if 6 in body:
                    if kind in MECHANISM_TYPES:
                        fails.append("mechanism")
                    old = records.get(body[6])
                    if old is None:
                        fails.append("no such record")
                    else:
                        if old["type"] in MECHANISM_TYPES:
                            fails.append("mechanism")
                        if old["superseded_by"] is not None:
                            fails.append("superseded")
                if kind == CLAIM:
                    problem = claim_problem(body.get(5))
                    if problem is not None:
                        fails.append(problem)
                    else:
                        claim = body[5]
                        if claim["as_of"] > clock[0]:
                            fails.append("as_of after registration")
                        source = records.get(claim["source"])
                        if source is None:
                            fails.append("no such source")
                        else:
                            if source["type"] in MECHANISM_TYPES:
                                fails.append("source of a mechanism type")
                            if source["revoked"]:
                                fails.append("source revoked")
                            if source["superseded_by"] is not None:
                                fails.append("source superseded")
                return fails
            if p[1] not in (17, 18, 19):
                return fails
            record = records.get(body[1])
            if record is None:
                return ["no such record"]
            if record["revoked"]:
                fails.append("revoked")
            mechanism = MECHANISM_TYPES.get(record["type"])
            if p[1] == 17:
                if mechanism is not None:
                    fails.append("role")
                if any(actor == p[3] and role == body[2] for actor, role, _ in record["endorsements"]):
                    fails.append("repeated")
            elif p[1] == 18:
                if record["state"] != body[2]:
                    fails.append("state")
                if mechanism is None or (body[2], body[3]) not in mechanism[1]:
                    fails.append("transition")
            return fails

        def add(name, signer, p):
            """Registers the statement now, under the rules; the clock then
            moves a minute on."""
            assert rules(p) == [], (name, rules(p))
            if p[1] == 5:  # the CDDL's scope: statement and record types strictly ascending
                scope = p[7][2]
                assert scope[1] == sorted(set(scope[1])) and scope.get(2, []) == sorted(set(scope.get(2, [])),
                                                                                        key=str.encode), scope
            encoded, statement_id = lg.statement(keys[signer], p)
            index = len(statements)
            statements.append({"name": name, "signer": signer, "encoded": encoded.hex(), "payload": dcbor(p).hex(),
                               "statement_id": statement_id.hex(), "registered_at": clock[0]})
            clock[0] += minute
            body = p[7]
            if p[1] in (1, 2):
                actors[statement_id] = [index]
            elif p[1] == 5:
                delegations[statement_id] = [index]
            elif p[1] == 16:
                kind = body[1]
                initial = MECHANISM_TYPES[kind][0] if kind in MECHANISM_TYPES else "registered"
                records[statement_id] = {"type": kind, "state": initial, "revoked": False, "endorsements": [],
                                         "history": [index], "registrant": p[3], "supersedes": body.get(6),
                                         "superseded_by": None, "claim": body[5] if kind == CLAIM else None}
                if 6 in body:
                    # A statement about both records (v0.10). A claim's
                    # registration is about the claim only.
                    old = records[body[6]]
                    old["superseded_by"] = statement_id
                    old["history"].append(index)
            elif p[1] in (17, 18, 19):
                record = records[body[1]]
                record["history"].append(index)
                if p[1] == 17:
                    record["endorsements"].append((p[3], body[2], index))
                elif p[1] == 18:
                    record["state"] = body[3]
                else:
                    record["revoked"] = True
            return statement_id

        def refuse(name, signer, p, why):
            """The rules refuse it after the statements so far, at `at`, for
            the one rule `why` names. (Every refused statement here parses:
            a claim's metadata is checked by the ledger rules.)"""
            assert rules(p) == [why], (name, rules(p))
            encoded, _ = lg.statement(keys[signer], p)
            refused.append({"name": name, "signer": signer, "encoded": encoded.hex(), "payload": dcbor(p).hex(),
                            "after": len(statements), "at": clock[0], "why": why})

        def fields(*values):
            leaves = [dcbor([name, bytes([0xD0 + i]) * 16, value])
                      for i, (name, value) in enumerate(sorted(values, key=lambda f: f[0].encode()))]
            return lg.merkle().mth(leaves), len(leaves)

        def employee(signer_actor, delegation, name, salary, status, supersedes=None):
            root, count = fields(("name", name), ("monthly_salary", salary), ("status", status),
                                 ("start_date", "2024-03-01"))
            body = {1: EMPLOYMENT, 2: root, 3: count, 5: {"department": "Accounts"}}
            if supersedes is not None:
                body[6] = supersedes
            return payload(signer_actor, 16, body, delegation)

        def claim(signer_actor, delegation, metadata, supersedes=None):
            root, count = fields(("basis", "the payroll of 2026-10"),)
            body = {1: CLAIM, 2: root, 3: count}
            if metadata is not None:
                body[5] = metadata
            if supersedes is not None:
                body[6] = supersedes
            return payload(signer_actor, 16, body, delegation)

        def condition_on(source, condition, **extra):
            """A claim's metadata, evaluated half a minute before now."""
            out = {"source": source, "condition": condition, "holds": True, "as_of": clock[0] - 30 * second}
            out.update(extra)
            return out

        ledger_id = None
        ledger_id = add("genesis", "org_root", payload(None, 1, {
            1: hash_id, 2: "Example Employer", 3: ed_public(keys["org_root"]), 4: ed_public(keys["log"])}))
        org = ledger_id
        clerk = add("register the clerk", "org_root", payload(org, 2, {
            1: 1, 2: "HR Clerk", 3: ed_public(keys["clerk"])}))
        clerks = add("delegate employment records and claims to the clerk", "org_root", payload(org, 5, {
            1: clerk, 2: {1: [16, 17, 18, 19], 2: [CLAIM, EMPLOYMENT]}}))

        # A claim on a live record of a generic type, in the specification's
        # words.
        s1 = add("register an employment record", "clerk",
                 employee(clerk, clerks, "Chan Tai Man", [3500000, "HKD", 2], "staff"))
        c1 = add("the clerk claims the specification's example of it", "clerk", claim(clerk, clerks, condition_on(
            s1, SPEC_CLAIM_EXAMPLE, until=t0 + 30 * day, subject="Chan Tai Man")))
        # A claim's lifecycle: confirmed, no transitions, no endorsements.
        refuse("endorse the claim", "clerk", payload(clerk, 17, {1: c1, 2: "reviewer"}, clerks), "role")
        refuse("move the claim to withdrawn", "clerk", payload(clerk, 18, {1: c1, 2: "confirmed", 3: "withdrawn"},
                                                                 clerks), "transition")
        # The claim rules.
        refuse("a claim on a record that does not exist", "clerk", claim(clerk, clerks, condition_on(
            lg.h(b"no such record"), SPEC_CLAIM_EXAMPLE)), "no such source")
        refuse("a claim on a mechanism record, the first claim", "clerk", claim(clerk, clerks, condition_on(
            c1, [["source", "exists", "text", None]])), "source of a mechanism type")
        refuse("a claim evaluated after its registration", "clerk", claim(clerk, clerks, {
            **condition_on(s1, SPEC_CLAIM_EXAMPLE), "as_of": clock[0] + 1}), "as_of after registration")
        refuse("a claim whose metadata has an unknown key", "clerk", claim(clerk, clerks, {
            **condition_on(s1, SPEC_CLAIM_EXAMPLE), "note": "informal"}), "unknown key")
        refuse("a claim without metadata", "clerk", claim(clerk, clerks, None), "no metadata")
        refuse("a claim whose condition is malformed (exists on a number)", "clerk", claim(clerk, clerks,
               condition_on(s1, [["monthly_salary", "exists", "number", None]])), "operator and type")
        refuse("a claim that supersedes a record", "clerk", claim(clerk, clerks, condition_on(
            s1, SPEC_CLAIM_EXAMPLE), supersedes=s1), "mechanism")
        refuse("a record that supersedes the claim", "clerk",
               employee(clerk, clerks, "Chan Tai Man", [3600000, "HKD", 2], "staff", supersedes=c1), "mechanism")
        # The organization's claim, with no end, that does not hold, and that
        # answers an access request.
        c2 = add("the organization claims a condition that does not hold", "org_root", claim(org, None, condition_on(
            s1, [["start_date", "<=", "date", "2024-01-31"], ["grade", "exists", "text", None]], holds=False,
            **{"for": [peer, hashlib.sha256(b"their request").digest()]})))

        # A superseded record is no source; its newer version is.
        s2 = add("register a second employee's record", "clerk",
                 employee(clerk, clerks, "Lee Siu Ming", [2800000, "HKD", 2], "contractor"))
        s3 = add("a new version supersedes it", "clerk",
                 employee(clerk, clerks, "Lee Siu Ming", [3100000, "HKD", 2], "staff", supersedes=s2))
        refuse("a claim on the superseded version", "clerk", claim(clerk, clerks, condition_on(
            s2, [["status", "=", "text", "contractor"]])), "source superseded")
        c3 = add("a claim on the new version, until two minutes later", "clerk", claim(clerk, clerks, {
            **condition_on(s3, [["monthly_salary", "between", "money", [[2000000, "HKD", 2], [4000000, "HKD", 2]]],
                                ["start_date", ">=", "date", "2024-01-01"]]), "until": clock[0] + 2 * minute}))

        # A revoked record is no source.
        s4 = add("register a third employee's record", "clerk",
                 employee(clerk, clerks, "Wong Mei Ling", [4200000, "HKD", 2], "staff"))
        add("the organization revokes it", "org_root", payload(org, 19, {1: s4, 2: "entered twice"}))
        refuse("a claim on the revoked record", "clerk", claim(clerk, clerks, condition_on(
            s4, [["status", "=", "text", "staff"]])), "source revoked")

        # Later: the new version is replaced, the first claim withdrawn, and
        # the first record revoked. The claims stay; their sources' status
        # changes.
        s5 = add("the organization's version supersedes the second record's", "org_root",
                 employee(org, None, "Lee Siu Ming", [3300000, "HKD", 2], "staff", supersedes=s3))
        add("the clerk withdraws the first claim by revoking it", "clerk", payload(clerk, 19, {
            1: c1, 2: "issued for the wrong month"}, clerks))
        refuse("revoke the first claim again", "clerk", payload(clerk, 19, {1: c1}, clerks), "revoked")
        add("the organization revokes the first record", "org_root", payload(org, 19, {1: s1, 2: "left"}))
        c4 = add("a claim on the latest version", "clerk", claim(clerk, clerks, condition_on(
            s5, [["status", "!=", "text", "contractor"], ["monthly_salary", "in", "money",
                                                           [[3300000, "HKD", 2], [3400000, "HKD", 2]]]],
            subject="Lee Siu Ming")))
        refuse("a claim on the first record, revoked since", "clerk", claim(clerk, clerks, condition_on(
            s1, SPEC_CLAIM_EXAMPLE)), "source revoked")

        entries = [encode_log_entry(bytes.fromhex(st["statement_id"]), st["registered_at"], bytes.fromhex(st["encoded"]))
                   for st in statements]
        leaves = [[1, a, h] for a, h in actors.items()] + [[2, d, h] for d, h in delegations.items()] + \
                 [[3, r, v["history"]] for r, v in records.items()]
        sorted_leaves = sorted(leaves, key=lambda leaf: leaf[1])
        commitment_index = len(entries)
        commitment_time = clock[0]
        commitment_id = append_state_commitment(lg, keys["log"], ledger_id, entries, sorted_leaves, commitment_time)
        checkpoint_time = commitment_time + 1000
        checkpoint, _ = sign_log_checkpoint(lg, keys["log"], ledger_id, entries, checkpoint_time)

        def claim_json(c):
            source = records[c["source"]]
            status = "revoked" if source["revoked"] else "replaced" if source["superseded_by"] else "live"
            return {"source": c["source"].hex(), "source_type": source["type"], "source_status": status,
                    "condition": c["condition"], "text": claim_words(c["condition"]), "holds": c["holds"],
                    "as_of": c["as_of"], "until": c.get("until"),
                    "lapsed": "until" in c and checkpoint_time > c["until"], "subject": c.get("subject"),
                    "for": [x.hex() for x in c["for"]] if "for" in c else None}

        statuses = {claim_json(records[c]["claim"])["source_status"] for c in (c1, c2, c3, c4)}
        assert statuses == {"live", "revoked", "replaced"}, statuses
        assert claim_json(records[c3]["claim"])["lapsed"] and not claim_json(records[c4]["claim"])["lapsed"]
        ledgers.append({
            "hash": hash_id,
            "ledger_id": ledger_id.hex(),
            "statements": statements,
            "refused": refused,
            "claims": [c.hex() for c in (c1, c2, c3, c4)],
            "records": [{"id": r.hex(), "type": v["type"], "state": v["state"], "revoked": v["revoked"],
                         "registrant": v["registrant"].hex(), "history": v["history"],
                         "supersedes": v["supersedes"].hex() if v["supersedes"] else None,
                         "superseded_by": v["superseded_by"].hex() if v["superseded_by"] else None,
                         "claim": claim_json(v["claim"]) if v["claim"] is not None else None}
                        for r, v in records.items()],
            "log_entries": [e.hex() for e in entries],
            "state_leaves": [{"kind": leaf[0], "id": leaf[1].hex(), "history": leaf[2]} for leaf in sorted_leaves],
            "state_root": smt_root(lg, sorted_leaves).hex(),
            "state_commitment": {"index": commitment_index, "id": commitment_id.hex()},
            "checkpoint": checkpoint.hex(),
            "checkpoint_time": checkpoint_time,
        })

    document = {
        "description": "CexChain protocol objects of specification revision v0.14 (claims), built by an "
                       "independent Python encoder from spec/README.md and spec/cexchain.cddl. `claim_type` is the "
                       "fifth mechanism type's lifecycle (initial state \"confirmed\", no transitions, no roles; "
                       "withdrawn by revoking it). `claim_metadata` holds claim metadata (record key 5) on its "
                       "own: `valid` cases, each its deterministic CBOR (`metadata`), its condition as JSON, and "
                       "the condition in words (`text`, section 11, \"A claim in words\"), the specification's "
                       "own example first; `refused` cases, each breaking one rule of the `claim` CDDL or its "
                       "limits in section 6, which `why` names: \"unknown key\", \"missing key\", \"source\" "
                       "(not a 32-byte id), \"condition\" (not 1 to 16 terms), \"term\" (not [field, op, type, "
                       "value]), \"field\" (not 1 to 64 bytes of text), \"operator\", \"type\", \"operator and "
                       "type\" (an order operator on text, exists on another type), \"value\" (not the shape the "
                       "operator takes: one value, [low, high], 1 to 64 values, or null for exists), \"number\", "
                       "\"money\", \"date\", \"text\" (a value that is not one of the type), \"order\" (between "
                       "with low above high), \"distinct\" (in with a value twice), \"holds\", \"as_of\", "
                       "\"until\" (not after as_of), \"subject\", \"for\". `ledgers` holds an employer's ledger "
                       "for each hash: the organization delegates employment records "
                       "(example.org.employment/1) and claims to a clerk, who registers records and claims on "
                       "them. Each statement registers at its `registered_at` (the log entries carry it). "
                       "`refused` statements are validated against the state after the first `after` statements, "
                       "at `at`, and break exactly one rule, which `why` names: \"role\" and \"transition\" (a "
                       "claim takes neither), \"no such source\", \"source of a mechanism type\" (here another "
                       "claim), \"source revoked\", \"source superseded\", \"as_of after registration\", "
                       "\"mechanism\" (a claim neither supersedes nor is superseded), \"revoked\" (a revoked "
                       "claim takes nothing more), \"no metadata\", and the metadata rules above (\"unknown "
                       "key\", \"operator and type\"); every refused statement parses, since a claim's metadata "
                       "is checked by the ledger rules. A claim's registration is a statement about the claim "
                       "only: its source's history does not list it. `claims` lists the accepted claims, and "
                       "`records` gives each record's type, state, revocation, registrant, history, versions, "
                       "and, for a claim, what a report states of it (section 11) at the checkpoint: its source, "
                       "the source's type and status (\"live\", \"revoked\", or \"replaced\" by a newer "
                       "version), the condition and its words, holds, as_of and until (ms), whether "
                       "`checkpoint_time` is past until (`lapsed`), the subject, and the access request it "
                       "answers (`for`). `log_entries` holds the whole log, ending with the state commitment "
                       "over `state_leaves`; `checkpoint` (signed at `checkpoint_time`) covers it. Signatures are "
                       "Ed25519 (deterministic); keys are throwaway: seed = SHA-256(\"CexChain test key: "
                       "<name>\").",
        "t0": t0,
        "claim_type": {"type": CLAIM, "initial": MECHANISM_TYPES[CLAIM][0], "transitions": [], "roles": []},
        "mechanism_types": [{"type": kind, "initial": initial, "transitions": sorted([list(t) for t in transitions])}
                            for kind, (initial, transitions) in MECHANISM_TYPES.items()],
        "claim_words": {**{op: f"{words} V" for op, words in CLAIM_WORDS.items()}, "between": "is between L and H",
                        "in": "is one of V1, V2", "exists": "is given", "joined_by": " and "},
        "claim_metadata": {"valid": valid_metadata, "refused": refused_metadata},
        "seeds": seeds,
        "ledgers": ledgers,
    }
    (OUT / "protocol-v0.14.json").write_text(json.dumps(document, indent=1, ensure_ascii=False) + "\n")
    first = ledgers[0]
    reasons = sorted({r["why"] for r in first["refused"]})
    print(f"wrote protocol vectors for {len(ledgers)} ledgers to testvectors/protocol-v0.14.json: "
          f"{len(valid_metadata)} claim metadata, {len(refused_metadata)} refused; {len(first['statements'])} "
          f"statements, {len(first['refused'])} refused ({', '.join(reasons)}), {len(first['records'])} records")


# ---------------------------------------------------------------------------
# Protocol v0.15: asking about a condition (spec section 12): an access
# request may ask whether a condition holds in a record instead of asking for
# its data, and the granter answers with a claim whose "for" names it
# ---------------------------------------------------------------------------

ACCESS_REQUEST_COMMON = ("ledger", "record", "purpose", "until")
# The data form's keys; the other form (v0.15) has "condition" instead.
ACCESS_REQUEST_DATA = ("recipient", "fields", "attachments")
ACCESS_REQUEST_KEYS = ACCESS_REQUEST_COMMON + ACCESS_REQUEST_DATA + ("condition",)


def _id32(v) -> bool:
    return isinstance(v, bytes) and len(v) == 32


def access_names_ok(v) -> bool:
    """`access-names` (v0.15): at most 256 names, each a non-empty text, none
    twice in the list."""
    return (isinstance(v, list) and len(v) <= 256 and all(isinstance(x, str) and x for x in v)
            and len(set(v)) == len(v))


def access_request_problem(metadata) -> str | None:
    """Why an access request's metadata (record key 5) is not an
    `access-request` of the CDDL with the prose's limits (sections 12 and 6),
    or None. Parties refuse other keys, a key that is not text among them; a
    key whose value is not of its type, null included, breaks that key's
    rule."""
    if not isinstance(metadata, dict):
        return "no metadata"
    keys = set(metadata)
    if keys - set(ACCESS_REQUEST_KEYS):
        return "unknown key"
    if set(ACCESS_REQUEST_COMMON) - keys:
        return "missing key"
    # A reader refuses a request that has a condition and any of the data
    # form's keys, or has neither a condition nor a recipient. A key counts
    # by its presence: an empty list of fields is still a list of fields.
    if "condition" in keys and keys & set(ACCESS_REQUEST_DATA):
        return "both forms"
    if "condition" not in keys and "recipient" not in keys:
        return "neither form"
    m = metadata
    for key in ("ledger", "record"):
        if not _id32(m[key]):
            return key
    if not (isinstance(m["purpose"], str) and m["purpose"]):
        return "purpose"
    if not (_cbor_int(m["until"]) and m["until"] > 0):
        return "until"
    if "condition" in m:
        # 1 to 16 terms of a claim's condition, checked as a claim's are.
        condition = m["condition"]
        if not (isinstance(condition, list) and 1 <= len(condition) <= 16):
            return "condition"
        if any(claim_term_problem(t) is not None for t in condition):
            return "condition"
        return None
    if not _id32(m["recipient"]):
        return "recipient"
    for key in ("fields", "attachments"):
        if key in m and not access_names_ok(m[key]):
            return "names"
    return None


def claim_answer_problem(claim: dict, requester_ledger: bytes, request_id: bytes, request: dict) -> str | None:
    """Why a claim does not answer an access request under items 3 and 4 of
    the acceptance in section 12 ("Asking about a condition"), or None. Both
    metadata are valid; the other items need the claim's evidence."""
    if "condition" not in request:
        return "data request"
    if "for" not in claim:
        return "no for"
    ledger, record = claim["for"]
    if ledger != requester_ledger:
        return "for ledger"
    if record != request_id:
        return "for request"
    if claim["source"] != request["record"]:
        return "source"
    # Term for term and in the same deterministic encoding (item 4): one
    # value written another way (2 and "2.0", HKD 100 at scale 0 and at scale
    # 2), or the values of "in" in another order, is another condition,
    # though a claim's "in" counts such values as one.
    if [dcbor(t) for t in claim["condition"]] != [dcbor(t) for t in request["condition"]]:
        return "condition"
    return None


def access_request_cases(t0: int, recipient: bytes) -> tuple[list, list]:
    """Access request metadata on its own, of both forms: (valid, refused)."""
    granter = bytes([0x22]) * 32
    record = bytes([0x33]) * 32
    day = 86_400_000

    def common(**extra):
        out = {"ledger": granter, "record": record, "purpose": "tenancy application", "until": t0 + 30 * day}
        out.update(extra)
        return out

    def data(**extra):
        return common(**{"recipient": recipient, **extra})

    def asking(condition, **extra):
        return common(condition=condition, **extra)

    valid, refused = [], []

    def ok(name, metadata):
        assert access_request_problem(metadata) is None, (name, access_request_problem(metadata))
        m = metadata
        condition = m.get("condition")
        valid.append({"name": name, "metadata": dcbor(m).hex(), "ledger": m["ledger"].hex(),
                      "record": m["record"].hex(), "purpose": m["purpose"], "until": m["until"],
                      "recipient": m["recipient"].hex() if "recipient" in m else None,
                      "fields": m.get("fields"), "attachments": m.get("attachments"),
                      "condition": dcbor(condition).hex() if condition is not None else None,
                      "text": claim_words(condition) if condition is not None else None})

    def bad(name, metadata, why):
        assert access_request_problem(metadata) == why, (name, access_request_problem(metadata), why)
        refused.append({"name": name, "metadata": dcbor(metadata).hex(), "why": why})

    salary = [["monthly_salary", ">", "money", [3000000, "HKD", 2]]]
    sixteen = [[f"field_{i:02d}", ">", "number", i] for i in range(16)]

    ok("data: everything (no fields or attachments named)", data())
    ok("data: some fields and an attachment", data(fields=["product", "result"], attachments=["report.pdf"]))
    ok("data: fields only", data(fields=["monthly_salary"]))
    ok("data: attachments only", data(attachments=["contract.pdf", "payslip-2026-10.pdf"]))
    ok("data: empty lists, so no field and no attachment", data(fields=[], attachments=[]))
    many = [f"name_{i:03d}" for i in range(257)]
    ok("data: 256 fields and 256 attachments, the most a list holds",
       data(fields=many[:256], attachments=[f"{n}.pdf" for n in many[:256]]))
    ok("data: names in any script, a purpose in Chinese, and the largest until",
       data(fields=["名字", "地址"], attachments=["身份證明.pdf"], purpose="租務申請", until=2**64 - 1))
    ok("data: until 1 ms", data(until=1))
    ok("condition: the specification's question, one term", asking(salary))
    ok("condition: the specification's claim example, money and in", asking(SPEC_CLAIM_EXAMPLE))
    ok("condition: each order operator on numbers, integers and decimal texts",
       asking([["age", ">=", "number", 18], ["score", "<", "number", "99.5"], ["balance", "<=", "number", -250],
               ["rate", ">", "number", "-0.75"]]))
    ok("condition: equality on every type",
       asking([["grade", "=", "text", "A"], ["band", "!=", "number", 3], ["deposit", "=", "money", [0, "USD", 2]],
               ["joined", "!=", "date", "2024-02-29"]]))
    ok("condition: between, of numbers, dates, and money",
       asking([["floor", "between", "number", [5, 5]], ["height", "between", "number", [1, "1.5"]],
               ["start", "between", "date", ["2000-02-29", "2026-12-31"]],
               ["salary", "between", "money", [[2000000, "HKD", 2], [4000000, "HKD", 2]]]]))
    ok("condition: in, of every type",
       asking([["status", "in", "text", ["staff"]], ["level", "in", "number", [1, 2, "3.5"]],
               ["fee", "in", "money", [[100, "EUR", 0], [250, "EUR", 0]]],
               ["review", "in", "date", ["2026-03-31", "2026-09-30"]]]))
    ok("condition: exists", asking([["licence_number", "exists", "text", None]]))
    ok("condition: money with signs and scales 0 to 4",
       asking([["a", ">", "money", [123456789012, "JPY", 0]], ["b", "<", "money", [-5, "USD", 2]],
               ["c", ">=", "money", [5, "CHF", 4]], ["d", "<=", "money", [-100000, "GBP", 0]],
               ["e", "=", "money", [1000, "HKD", 3]]]))
    ok("condition: dates under each order operator",
       asking([["start_date", "<=", "date", "2025-11-01"], ["birth_date", "<", "date", "2008-02-29"],
               ["review", ">", "date", "2026-12-31"], ["joined", ">=", "date", "2000-01-01"]]))
    ok("condition: text as it is, in any script",
       asking([["名字", "=", "text", "陳大文"], ["district", "!=", "text", 'Kowloon "City"']]))
    ok("condition: sixteen terms", asking(sixteen))
    ok("condition: sizes at their limits: a 64-byte field, a 256-byte text, a 40-character decimal, 64 values in",
       asking([["f" * 64, "=", "text", "t" * 256], ["d", "=", "number", "-" + "9" * 19 + "." + "9" * 19],
               ["v", "in", "number", list(range(64))]]))
    ok("condition: the largest and smallest integers, and the largest until",
       asking([["n", "<=", "number", 2**64 - 1], ["m", ">=", "number", -2**64],
               ["big", "<", "money", [2**64 - 1, "HKD", 2]]], until=2**64 - 1))

    def without(metadata, key):
        out = dict(metadata)
        del out[key]
        return out

    bad("both forms: a condition and a recipient", asking(salary, recipient=recipient), "both forms")
    bad("both forms: a condition and fields", asking(salary, fields=["monthly_salary"]), "both forms")
    bad("both forms: a condition and attachments", asking(salary, attachments=["payslip.pdf"]), "both forms")
    bad("both forms: a condition and an empty list of fields", asking(salary, fields=[]), "both forms")
    bad("neither form: no condition and no recipient", common(), "neither form")
    bad("neither form: fields and attachments without a recipient",
        common(fields=["monthly_salary"], attachments=["payslip.pdf"]), "neither form")
    bad("condition: no terms", asking([]), "condition")
    bad("condition: seventeen terms", asking(sixteen + [["x", "=", "number", 1]]), "condition")
    bad("condition: one term, not a list of terms", asking(salary[0]), "condition")
    bad("condition: a map, not a list of terms", asking({"monthly_salary": [3000000, "HKD", 2]}), "condition")
    bad("condition: a term of three elements", asking([["x", "=", "number"]]), "condition")
    bad("condition: an empty field name", asking([["", "=", "number", 1]]), "condition")
    bad("condition: the operator '=='", asking([["x", "==", "number", 1]]), "condition")
    bad("condition: the type 'integer'", asking([["x", "=", "integer", 1]]), "condition")
    bad("condition: > on text", asking([["x", ">", "text", "b"]]), "condition")
    bad("condition: exists with a value", asking([["x", "exists", "text", "yes"]]), "condition")
    bad("condition: between, low above high", asking([["x", "between", "number", [10, 5]]]), "condition")
    bad("condition: between amounts of two currencies",
        asking([["x", "between", "money", [[100, "HKD", 2], [200, "USD", 2]]]]), "condition")
    bad("condition: in with one value twice, as values (1 and \"1.0\")",
        asking([["x", "in", "number", [1, "1.0"]]]), "condition")
    bad("condition: a date that does not exist", asking([["x", "=", "date", "2026-02-30"]]), "condition")
    bad("condition: a decimal text of 41 characters",
        asking([["x", "=", "number", "1" * 20 + "." + "1" * 20]]), "condition")
    bad("condition: money in a lower-case currency", asking([["x", "=", "money", [100, "hkd", 2]]]), "condition")
    bad("condition: a valid term after an invalid one",
        asking([salary[0], ["x", "<", "text", "b"]]), "condition")
    bad("an unknown key in a request for data", data(note="hello"), "unknown key")
    bad("an integer key", {**data(), 1: "hello"}, "unknown key")
    bad("a key as bytes, in a request about a condition", {**asking(salary), b"note": "hello"}, "unknown key")
    bad("a misspelt key in a request for data", data(field=["monthly_salary"]), "unknown key")
    bad("a claim's key in a request about a condition", asking(salary, holds=True), "unknown key")
    for key in ACCESS_REQUEST_COMMON:
        bad(f"no {key}, in a request for data", without(data(), key), "missing key")
        bad(f"no {key}, in a request about a condition", without(asking(salary), key), "missing key")
    bad("a recipient of 31 bytes", data(recipient=recipient[:31]), "recipient")
    bad("a recipient of 33 bytes", data(recipient=recipient + b"\x00"), "recipient")
    bad("an empty recipient", data(recipient=b""), "recipient")
    bad("a recipient as text", data(recipient=recipient.hex()), "recipient")
    # A key whose value is not of its type, null included, is refused.
    bad("a null recipient", data(recipient=None), "recipient")
    bad("a null condition", asking(None), "condition")
    bad("null fields", data(fields=None), "names")
    bad("null attachments", data(attachments=None), "names")
    bad("a null ledger", data(ledger=None), "ledger")
    bad("a null record, in a request about a condition", asking(salary, record=None), "record")
    bad("a null purpose", data(purpose=None), "purpose")
    bad("a null until", data(until=None), "until")
    bad("a ledger of 31 bytes", data(ledger=granter[:31]), "ledger")
    bad("a ledger of 33 bytes, in a request about a condition", asking(salary, ledger=granter + b"\x00"), "ledger")
    bad("a ledger as text", data(ledger=granter.hex()), "ledger")
    bad("a record of 31 bytes", data(record=record[:31]), "record")
    bad("an empty record, in a request about a condition", asking(salary, record=b""), "record")
    bad("a record as text", data(record=record.hex()), "record")
    bad("an empty purpose", data(purpose=""), "purpose")
    bad("an empty purpose, in a request about a condition", asking(salary, purpose=""), "purpose")
    bad("a purpose as bytes", data(purpose=b"tenancy application"), "purpose")
    bad("a purpose as an integer", data(purpose=1), "purpose")
    bad("until 0", data(until=0), "until")
    bad("until 0, in a request about a condition", asking(salary, until=0), "until")
    bad("a negative until", data(until=-1), "until")
    bad("until as text", data(until="2026-12-10"), "until")
    bad("until that is true", data(until=True), "until")
    bad("fields as text, not a list", data(fields="monthly_salary"), "names")
    bad("fields with a name as bytes", data(fields=["product", b"result"]), "names")
    bad("fields with a name as an integer", data(fields=[1]), "names")
    bad("fields with a list in them", data(fields=[["product"]]), "names")
    bad("fields with a name twice", data(fields=["product", "result", "product"]), "names")
    bad("attachments as text, not a list", data(attachments="report.pdf"), "names")
    bad("attachments with a name as bytes", data(attachments=[b"report.pdf"]), "names")
    bad("attachments as a map", data(attachments={"report.pdf": True}), "names")
    bad("fields with an empty name", data(fields=["product", ""]), "names")
    bad("attachments with an empty name", data(attachments=[""]), "names")
    bad("attachments with a name twice", data(attachments=["report.pdf", "photo.jpg", "report.pdf"]), "names")
    bad("257 fields", data(fields=many), "names")
    bad("257 attachments", data(attachments=[f"{n}.pdf" for n in many]), "names")
    return valid, refused


def claim_answer_cases(t0: int, recipient: bytes) -> list:
    """Claims checked as answers to access requests (section 12, acceptance
    items 3 and 4)."""
    requester = bytes([0x11]) * 32
    granter = bytes([0x22]) * 32
    record = bytes([0x33]) * 32
    request_id = bytes([0x44]) * 32
    hour, day = 3_600_000, 86_400_000
    asked = [["monthly_salary", ">", "money", [3000000, "HKD", 2]],
             ["status", "in", "text", ["staff", "contractor"]],
             ["start_date", "<=", "date", "2025-11-01"],
             ["years_employed", ">=", "number", 2],
             ["review_date", "=", "date", "2026-03-31"]]

    def request(condition=None, **extra):
        """A request about `condition` (by default `asked`), or, given a
        recipient, a request for data."""
        out = {"ledger": granter, "record": record, "purpose": "tenancy application", "until": t0 + 30 * day}
        if "recipient" not in extra:
            out["condition"] = condition if condition is not None else asked
        out.update(extra)
        return out

    def claim(condition=None, **changes):
        out = {"source": record, "condition": condition if condition is not None else asked, "holds": True,
               "as_of": t0 + hour, "for": [requester, request_id]}
        for k, v in changes.items():
            if v is None:
                del out[k]
            else:
                out[k] = v
        return out

    cases = []

    def case(name, c, r, why):
        assert claim_problem(c) is None, (name, claim_problem(c))
        assert access_request_problem(r) is None, (name, access_request_problem(r))
        assert claim_answer_problem(c, requester, request_id, r) == why, (
            name, claim_answer_problem(c, requester, request_id, r), why)
        cases.append({"name": name, "requester_ledger": requester.hex(), "request_id": request_id.hex(),
                      "request": dcbor(r).hex(), "claim": dcbor(c).hex(), "accepted": why is None, "why": why})

    def swapped(i, j):
        out = list(asked)
        out[i], out[j] = out[j], out[i]
        return out

    def replaced(i, term):
        out = list(asked)
        out[i] = term
        return out

    exists = [["licence_number", "exists", "text", None]]
    sixteen = [[f"field_{i:02d}", ">", "number", i] for i in range(16)]
    case("it holds", claim(), request(), None)
    case("it does not hold", claim(holds=False), request(), None)
    case("with a subject and an until before the request's",
         claim(subject="Chan Tai Man", until=t0 + 7 * day), request(), None)
    # The claim's until is the granter's choice, before or after the
    # request's; its as_of is the granter's word, which the requester does not
    # check.
    case("with an until after the request's", claim(until=t0 + 90 * day), request(), None)
    case("as of a year before the request's until", claim(as_of=t0 - 335 * day), request(), None)
    case("a request of one term, exists", claim(exists), request(exists), None)
    case("a request of sixteen terms", claim(sixteen), request(sixteen), None)
    case("the request asks for data: everything", claim(), request(recipient=recipient), "data request")
    case("the request asks for data: the fields the claim is about",
         claim(asked[:1]), request(recipient=recipient, fields=["monthly_salary"]), "data request")
    case("no for", claim(**{"for": None}), request(), "no for")
    case("for names the granter's ledger", claim(**{"for": [granter, request_id]}), request(), "for ledger")
    case("for names a third ledger", claim(**{"for": [bytes([0x55]) * 32, request_id]}), request(), "for ledger")
    case("for names another request", claim(**{"for": [requester, bytes([0x45]) * 32]}), request(),
         "for request")
    case("for names the record asked about as the request", claim(**{"for": [requester, record]}), request(),
         "for request")
    case("another source", claim(source=bytes([0x34]) * 32), request(), "source")
    case("the request's id as the source", claim(source=request_id), request(), "source")
    case("fewer terms", claim(asked[:4]), request(), "condition")
    case("one term more", claim(asked + [["grade", "=", "text", "A"]]), request(), "condition")
    case("the terms in another order", claim(swapped(0, 1)), request(), "condition")
    case("another value", claim(replaced(0, ["monthly_salary", ">", "money", [2000000, "HKD", 2]])), request(),
         "condition")
    case("another operator", claim(replaced(0, ["monthly_salary", ">=", "money", [3000000, "HKD", 2]])),
         request(), "condition")
    case("another field", claim(replaced(0, ["monthly_income", ">", "money", [3000000, "HKD", 2]])), request(),
         "condition")
    case("another type, the same text", claim(replaced(4, ["review_date", "=", "text", "2026-03-31"])),
         request(), "condition")
    case("the in values in another order",
         claim(replaced(1, ["status", "in", "text", ["contractor", "staff"]])), request(), "condition")
    case("the same amount at another scale (HKD 30,000 at scale 0, asked at scale 2)",
         claim(replaced(0, ["monthly_salary", ">", "money", [30000, "HKD", 0]])), request(), "condition")
    case("the same amount at another scale, the specification's pair ([100, \"HKD\", 0] and [10000, \"HKD\", 2])",
         claim([["deposit", "=", "money", [100, "HKD", 0]]]), request([["deposit", "=", "money", [10000, "HKD", 2]]]),
         "condition")
    case("the same number written another way (\"2.0\" for 2)",
         claim(replaced(3, ["years_employed", ">=", "number", "2.0"])), request(), "condition")
    return cases


def generate_protocol_v15() -> None:
    from cryptography.hazmat.primitives.asymmetric import x25519

    t0 = 1_794_268_800_000  # 2026-11-10T00:00:00Z
    # The recipient key of a request for data: the X25519 key of protocol-v0.3.json.
    key = x25519.X25519PrivateKey.from_private_bytes(hashlib.sha256(b"CexChain test key: recipient").digest())
    recipient = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    valid, refused = access_request_cases(t0, recipient)
    answers = claim_answer_cases(t0, recipient)
    document = {
        "description": "CexChain protocol objects of specification revision v0.15 (asking about a condition), "
                       "built by an independent Python encoder from spec/README.md (sections 6 and 12) and "
                       "spec/cexchain.cddl. `access_requests` holds the metadata (record key 5) of "
                       "cexchain.access-request/1 records on its own. `valid` cases are of both forms, a request "
                       "for data (a recipient key, and optional fields and attachments) and a request about a "
                       "condition (1 to 16 terms of a claim's condition): each its deterministic CBOR "
                       "(`metadata`) and its values, `recipient` (hex), `fields`, and `attachments` null when "
                       "absent, `condition` the deterministic CBOR of the condition array alone (hex) and `text` "
                       "the condition in words (section 11, \"A claim in words\"), both null in a request for "
                       "data. `refused` cases each break one rule, which `why` names: \"both forms\" (a "
                       "condition with a recipient, fields, or attachments; a key counts by its presence, so an "
                       "empty list too), \"neither form\" (no condition and no recipient), \"condition\" (not 1 to "
                       "16 terms, or a term the claim rules of section 6 refuse), \"unknown key\" (a text key "
                       "the CDDL does not name, or a key that is not text), \"missing key\" (ledger, record, "
                       "purpose, or until, in either form), \"recipient\", \"ledger\", \"record\" (not 32 "
                       "bytes), \"purpose\" (empty, or not text), \"until\" (0, or not an unsigned integer), "
                       "\"names\" (fields or attachments not `access-names`: a list of at most 256 non-empty "
                       "texts, none twice). A key whose value is not of its type, null included, breaks that "
                       "key's rule. `answers` holds claims checked as answers to access requests, under items 3 and "
                       "4 of the acceptance in section 12: each the requester's ledger, the request's id, the "
                       "request's metadata and the claim's (both valid, the claim's as section 6 checks it), and "
                       "whether the claim answers the request (`accepted`); when not, `why` names the one rule "
                       "broken: \"data request\" (the request asks for data, and no claim answers it), \"no "
                       "for\", \"for ledger\" (for names another ledger than the requester's), \"for request\" "
                       "(another request), \"source\" (another record than the one asked about), \"condition\" "
                       "(not the request's, term for term in the same deterministic encoding: fewer or more "
                       "terms, in another order, another field, operator, type, or value, and equal values "
                       "encoded otherwise, such as money at another scale or a number written another way). "
                       "Accepted answers include a claim whose until is after the request's and one as of long "
                       "before it: neither is checked. "
                       "Items 1, 2, and 5 (the claim's evidence, its being live and not lapsed, and its "
                       "source's) need evidence bundles, which these cases leave out. Ids are fixed: the "
                       "requester's ledger 11..11, the ledger asked 22..22, the record 33..33, the request 44..44 "
                       "(hex); the recipient key is the X25519 key of seed SHA-256(\"CexChain test key: "
                       "recipient\"), that of protocol-v0.3.json.",
        "access_requests": {"valid": valid, "refused": refused},
        "answers": answers,
    }
    (OUT / "protocol-v0.15.json").write_text(json.dumps(document, indent=1, ensure_ascii=False) + "\n")
    accepted = sum(1 for a in answers if a["accepted"])
    print(f"wrote protocol vectors to testvectors/protocol-v0.15.json: {len(valid)} access requests, "
          f"{len(refused)} refused; {len(answers)} answers, {accepted} accepted")


# ---------------------------------------------------------------------------
# Protocol v0.16: trust nodes (spec sections 6, 11, and 16): memberships, the
# sixth mechanism type, and membership proofs in evidence bundles (key 9)
# ---------------------------------------------------------------------------

MEMBERSHIP = "cexchain.membership/1"
MEMBERSHIP_INITIAL = "active"
# The transitions in the specification's order (section 6, "Mechanism types").
MEMBERSHIP_TRANSITIONS = (("active", "suspended"), ("suspended", "active"), ("active", "ended"),
                          ("suspended", "ended"))
# The six mechanism types of v0.16, in the specification's table order.
# MECHANISM_TYPES stays as protocol-v0.14.json lists it.
MECHANISM_TYPES_V16 = {**MECHANISM_TYPES, MEMBERSHIP: (MEMBERSHIP_INITIAL, set(MEMBERSHIP_TRANSITIONS))}
MEMBERSHIP_REQUIRED = ("member", "kind", "name", "verified")
MEMBERSHIP_OPTIONAL = ("registration", "jurisdiction", "until")
MEMBERSHIP_KINDS = ("organization", "person")
JURISDICTION = re.compile(r"[A-Z]{2}(-[A-Z0-9]{1,3})?")
MAX_MEMBERSHIP_PROOFS = 16
NOTICE = "example.org.notice/1"
LISTING = "example.org.listing/1"
DIPLOMA = "example.org.diploma/1"
_ABSENT = object()


def _text_bytes(v, low: int, high: int) -> bool:
    return isinstance(v, str) and low <= len(v.encode("utf-8")) <= high


def membership_problem(metadata) -> str | None:
    """Why a membership's metadata (record key 5) is not a `membership` of
    the CDDL with the prose's limits (section 6), or None. The ledger refuses
    other keys, a key that is not text among them; a key whose value is not
    of its type, null included, breaks that key's rule."""
    if not isinstance(metadata, dict):
        return "no metadata"
    if any(not isinstance(k, str) for k in metadata) or set(metadata) - set(MEMBERSHIP_REQUIRED + MEMBERSHIP_OPTIONAL):
        return "unknown key"
    if set(MEMBERSHIP_REQUIRED) - set(metadata):
        return "missing key"
    m = metadata
    if not _id32(m["member"]):
        return "member"
    if not (isinstance(m["kind"], str) and m["kind"] in MEMBERSHIP_KINDS):
        return "kind"
    if not _text_bytes(m["name"], 1, 256):
        return "name"
    if not isinstance(m["verified"], bool):
        return "verified"
    if "registration" in m and not _text_bytes(m["registration"], 1, 64):
        return "registration"
    if "jurisdiction" in m and not (isinstance(m["jurisdiction"], str) and JURISDICTION.fullmatch(m["jurisdiction"])):
        return "jurisdiction"
    if "until" in m and not (_cbor_int(m["until"]) and m["until"] > 0):
        return "until"
    return None


def membership_standing(registered_at: int, until, changes: list, t: int) -> str:
    """Where a membership stood at time t (section 11, step 9), from its
    registration time, its until (None if it has none), and its changes in
    log order, each (registration time, the state it moved to, or "" for the
    revocation). A proof's history ends at its checkpoint, so for a t after
    it this is the state as of the checkpoint, with until applied."""
    if t < registered_at:
        return "not_yet"
    if any(to == "" and at <= t for at, to in changes):
        return "revoked"
    if until is not None and t > until:
        return "lapsed"
    state = MEMBERSHIP_INITIAL
    for at, to in changes:
        if to and at <= t:
            state = to
    return state


def membership_metadata_json(m: dict) -> dict:
    """A membership's values, its optional keys only when present."""
    out = {"member": m["member"].hex(), "kind": m["kind"], "name": m["name"], "verified": m["verified"]}
    for key in MEMBERSHIP_OPTIONAL:
        if key in m:
            out[key] = m[key]
    return out


def membership_metadata_cases(t0: int) -> tuple[list, list]:
    """Membership metadata on its own: (valid, refused)."""
    year = 365 * 86_400_000
    # The specification's example (section 6): "ledger 1a2b... is Kowloon
    # Example School, company 12345678, Hong Kong, checked".
    member = bytes([0x1A, 0x2B]) + hashlib.sha256(b"Kowloon Example School").digest()[2:]
    example = {"member": member, "kind": "organization", "name": "Kowloon Example School", "verified": True,
               "registration": "12345678", "jurisdiction": "HK"}
    valid, refused = [], []

    def ok(name, metadata):
        assert membership_problem(metadata) is None, (name, membership_problem(metadata))
        valid.append({"name": name, "metadata": dcbor(metadata).hex(), "membership": membership_metadata_json(metadata)})

    def bad(name, metadata, why):
        assert membership_problem(metadata) == why, (name, membership_problem(metadata), why)
        refused.append({"name": name, "why": why, "metadata": dcbor(metadata).hex()})

    def but(**changes):
        out = dict(example)
        for key, value in changes.items():
            if value is _ABSENT:
                out.pop(key, None)
            else:
                out[key] = value
        return out

    person = {"member": hashlib.sha256(b"Chan Tai Man's ledger").digest(), "kind": "person", "name": "Chan Tai Man",
              "verified": False}
    ok("the specification's example: a verified organization, its company number, Hong Kong", example)
    ok("the example with until, a year on", but(until=t0 + year))
    ok("a person, self-declared, no optional key", person)
    ok("a self-declared organization in a subdivision of digits (CN-44)",
       but(verified=False, registration=_ABSENT, jurisdiction="CN-44"))
    ok("a subdivision of three letters (GB-ENG)", but(jurisdiction="GB-ENG"))
    ok("a subdivision of one letter (ES-M)", but(jurisdiction="ES-M"))
    ok("a subdivision of letters and digits (FR-75C)", but(jurisdiction="FR-75C"))
    ok("a name in Chinese", but(name="九龍示範學校"))
    ok("a name of 1 byte", but(name="K"))
    ok("a name of 256 bytes", but(name="n" * 256))
    ok("a name of 256 bytes: 85 three-byte characters and one byte", but(name="學" * 85 + "x"))
    ok("a registration of 1 byte", but(registration="1"))
    ok("a registration of 64 bytes", but(registration="R" * 64))
    ok("until 1, the least", but(until=1))
    ok("until 2^64 - 1, the largest", but(until=2**64 - 1))

    bad("an unknown key (note)", but(note="seen in person"), "unknown key")
    bad("a key that is not text (1)", {**example, 1: "x"}, "unknown key")
    bad("a key that is a byte string (member, as bytes)", {**example, b"member": member}, "unknown key")
    for key in MEMBERSHIP_REQUIRED:
        bad(f"without {key}", but(**{key: _ABSENT}), "missing key")
    bad("an empty map", {}, "missing key")
    bad("member as null", but(member=None), "member")
    bad("member as text (its hex)", but(member=member.hex()), "member")
    bad("member of 31 bytes", but(member=member[:31]), "member")
    bad("member of 33 bytes", but(member=member + b"\x00"), "member")
    bad("member as an array of the id", but(member=[member]), "member")
    bad("kind as null", but(kind=None), "kind")
    bad("kind as an integer", but(kind=0), "kind")
    bad("kind company", but(kind="company"), "kind")
    bad("kind Organization, capitalized", but(kind="Organization"), "kind")
    bad("kind agent, an actor kind", but(kind="agent"), "kind")
    bad("name as null", but(name=None), "name")
    bad("name as bytes", but(name=b"Kowloon Example School"), "name")
    bad("an empty name", but(name=""), "name")
    bad("a name of 257 bytes", but(name="n" * 257), "name")
    bad("a name of 86 three-byte characters (258 bytes)", but(name="學" * 86), "name")
    bad("verified as null", but(verified=None), "verified")
    bad("verified as 1", but(verified=1), "verified")
    bad("verified as the text true", but(verified="true"), "verified")
    bad("registration as null", but(registration=None), "registration")
    bad("registration as an integer", but(registration=12345678), "registration")
    bad("an empty registration", but(registration=""), "registration")
    bad("a registration of 65 bytes", but(registration="R" * 65), "registration")
    bad("jurisdiction as null", but(jurisdiction=None), "jurisdiction")
    bad("jurisdiction as bytes", but(jurisdiction=b"HK"), "jurisdiction")
    bad("jurisdiction in lower case (hk)", but(jurisdiction="hk"), "jurisdiction")
    bad("jurisdiction in mixed case (Hk)", but(jurisdiction="Hk"), "jurisdiction")
    bad("jurisdiction of 1 letter (H)", but(jurisdiction="H"), "jurisdiction")
    bad("jurisdiction of 3 letters (HKG)", but(jurisdiction="HKG"), "jurisdiction")
    bad("jurisdiction with a trailing - (HK-)", but(jurisdiction="HK-"), "jurisdiction")
    bad("jurisdiction with a subdivision of 4 characters (CN-4444)", but(jurisdiction="CN-4444"), "jurisdiction")
    bad("jurisdiction with _ for - (CN_44)", but(jurisdiction="CN_44"), "jurisdiction")
    bad("jurisdiction with a lower-case subdivision (CN-ab)", but(jurisdiction="CN-ab"), "jurisdiction")
    bad("jurisdiction with a trailing newline", but(jurisdiction="HK\n"), "jurisdiction")
    bad("jurisdiction with a trailing space", but(jurisdiction="HK "), "jurisdiction")
    bad("an empty jurisdiction", but(jurisdiction=""), "jurisdiction")
    bad("until as null", but(until=None), "until")
    bad("until 0", but(until=0), "until")
    bad("until negative", but(until=-1), "until")
    bad("until as text", but(until="2027-11-11"), "until")
    bad("until as true", but(until=True), "until")
    bad("an array, not a map", [member, "organization", "Kowloon Example School", True], "no metadata")
    bad("a text, not a map", "Kowloon Example School", "no metadata")
    bad("null, not a map", None, "no metadata")
    return valid, refused


def membership_standing_cases(t0: int) -> list:
    """Where memberships stood at given times (section 11, step 9)."""
    minute, day = 60_000, 86_400_000
    r = t0 + 10 * minute
    cases = []

    def case(name, until, changes, expected):
        for t, want in expected:
            got = membership_standing(r, until, changes, t)
            assert got == want, (name, t - r, got, want)
        cases.append({"name": name, "registered_at": r, "until": until,
                      "changes": [{"at": at, "to": to} for at, to in changes],
                      "cases": [{"t": t, "standing": want} for t, want in expected]})

    case("suspended, resumed, and ended", None,
         [(r + 10 * minute, "suspended"), (r + 20 * minute, "active"), (r + 30 * minute, "ended")],
         [(r - 1, "not_yet"), (r, "active"), (r + 5 * minute, "active"), (r + 10 * minute - 1, "active"),
          (r + 10 * minute, "suspended"), (r + 15 * minute, "suspended"), (r + 20 * minute, "active"),
          (r + 30 * minute - 1, "active"), (r + 30 * minute, "ended"), (r + day, "ended")])
    case("suspended, then revoked; until between them", r + 15 * minute,
         [(r + 10 * minute, "suspended"), (r + 20 * minute, "")],
         [(r, "active"), (r + 10 * minute, "suspended"), (r + 15 * minute, "suspended"),
          (r + 15 * minute + 1, "lapsed"), (r + 20 * minute - 1, "lapsed"), (r + 20 * minute, "revoked"),
          (r + day, "revoked")])
    case("until, and nothing else", r + 60 * minute, [],
         [(r - 1, "not_yet"), (r, "active"), (r + 60 * minute - 1, "active"), (r + 60 * minute, "active"),
          (r + 60 * minute + 1, "lapsed"), (r + day, "lapsed")])
    case("ended, then lapsed", r + 50 * minute, [(r + 10 * minute, "ended")],
         [(r + 10 * minute - 1, "active"), (r + 10 * minute, "ended"), (r + 50 * minute, "ended"),
          (r + 50 * minute + 1, "lapsed")])
    case("revoked while active, no until", None, [(r + 10 * minute, "")],
         [(r - 1, "not_yet"), (r + 10 * minute - 1, "active"), (r + 10 * minute, "revoked"), (r + day, "revoked")])
    case("ended, lapsed, then revoked", r + 20 * minute, [(r + 10 * minute, "ended"), (r + 40 * minute, "")],
         [(r + 15 * minute, "ended"), (r + 20 * minute, "ended"), (r + 30 * minute, "lapsed"),
          (r + 40 * minute, "revoked")])
    case("until before the registration: not yet a member, then lapsed", r - 5 * minute, [],
         [(r - 5 * minute - 1, "not_yet"), (r - 5 * minute, "not_yet"), (r - 1, "not_yet"), (r, "lapsed")])
    case("a transition at the registration time", None, [(r, "suspended")],
         [(r - 1, "not_yet"), (r, "suspended"), (r + day, "suspended")])
    case("two transitions at one time: the later in the log counts", None,
         [(r + 10 * minute, "suspended"), (r + 10 * minute, "ended")],
         [(r + 10 * minute - 1, "active"), (r + 10 * minute, "ended")])
    case("revoked at its registration time", None, [(r, "")], [(r - 1, "not_yet"), (r, "revoked")])
    case("until 1 ms after the registration", r + 1, [], [(r, "active"), (r + 1, "active"), (r + 2, "lapsed")])
    return cases


def membership_replay(t0: int) -> dict:
    """A trust node's log, for each hash, replayed under the ledger rules
    (sections 5 and 6), in the format of protocol-v0.14.json's ledgers."""
    names = ("org_root", "log", "registrar")
    seeds = {name: hashlib.sha256(f"CexChain test key: {name}".encode()).hexdigest() for name in names}
    keys = {name: ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)) for name, seed in seeds.items()}
    minute, day = 60_000, 86_400_000
    school = bytes([0x1A, 0x2B]) + hashlib.sha256(b"Kowloon Example School").digest()[2:]
    person = hashlib.sha256(b"Chan Tai Man's ledger").digest()
    kindergarten = hashlib.sha256(b"Example Kindergarten's ledger").digest()

    ledgers = []
    for hash_id in (-16, -65538):
        lg = Ledger(hash_id)
        statements, refused = [], []
        actors, delegations, records = {}, {}, {}
        clock = [t0 + 1000]

        def payload(signer_actor, body_type, body, delegation=None):
            n = len(statements) + len(refused) + 1
            out = {0: 1, 1: body_type, 5: clock[0] - 500, 6: n.to_bytes(16, "big"), 7: body}
            if signer_actor is not None:  # absent only in genesis
                out[2] = ledger_id
                out[3] = signer_actor
            if delegation is not None:
                out[4] = delegation
            return out

        def rules(p):
            """Every rule of section 5 that refuses these record statements:
            the generic lifecycle's, the mechanism types', the version rules
            of v0.10, and the membership rules of v0.16 (section 6). The
            signers are always authorized."""
            body, fails = p[7], []
            if p[1] == 16:
                kind = body[1]
                if kind.startswith(RESERVED_PREFIX) and kind not in MECHANISM_TYPES_V16:
                    fails.append("reserved type")
                if 6 in body:
                    if kind in MECHANISM_TYPES_V16:
                        fails.append("mechanism")
                    old = records.get(body[6])
                    if old is None:
                        fails.append("no such record")
                    else:
                        if old["type"] in MECHANISM_TYPES_V16:
                            fails.append("mechanism")
                        if old["superseded_by"] is not None:
                            fails.append("superseded")
                if kind == MEMBERSHIP:
                    problem = membership_problem(body.get(5))
                    if problem is not None:
                        fails.append(problem)
                    elif body[5]["member"] == ledger_id:
                        fails.append("own ledger")
                return fails
            if p[1] not in (17, 18, 19):
                return fails
            record = records.get(body[1])
            if record is None:
                return ["no such record"]
            if record["revoked"]:
                fails.append("revoked")
            mechanism = MECHANISM_TYPES_V16.get(record["type"])
            if p[1] == 17:
                if mechanism is not None:
                    fails.append("role")
                if any(actor == p[3] and role == body[2] for actor, role, _ in record["endorsements"]):
                    fails.append("repeated")
            elif p[1] == 18:
                if record["state"] != body[2]:
                    fails.append("state")
                if mechanism is None or (body[2], body[3]) not in mechanism[1]:
                    fails.append("transition")
            return fails

        def add(name, signer, p):
            """Registers the statement now, under the rules; the clock then
            moves a minute on."""
            assert rules(p) == [], (name, rules(p))
            if p[1] == 5:  # the CDDL's scope: statement and record types strictly ascending
                scope = p[7][2]
                assert scope[1] == sorted(set(scope[1])) and scope.get(2, []) == sorted(set(scope.get(2, [])),
                                                                                        key=str.encode), scope
            encoded, statement_id = lg.statement(keys[signer], p)
            index, now = len(statements), clock[0]
            statements.append({"name": name, "signer": signer, "encoded": encoded.hex(), "payload": dcbor(p).hex(),
                               "statement_id": statement_id.hex(), "registered_at": now})
            clock[0] += minute
            body = p[7]
            if p[1] in (1, 2):
                actors[statement_id] = [index]
            elif p[1] == 5:
                delegations[statement_id] = [index]
            elif p[1] == 16:
                kind = body[1]
                initial = MECHANISM_TYPES_V16[kind][0] if kind in MECHANISM_TYPES_V16 else "registered"
                records[statement_id] = {"type": kind, "state": initial, "revoked": False, "endorsements": [],
                                         "history": [index], "registrant": p[3], "supersedes": body.get(6),
                                         "superseded_by": None, "registered_at": now, "changes": [],
                                         "membership": body[5] if kind == MEMBERSHIP else None}
                if 6 in body:
                    old = records[body[6]]
                    old["superseded_by"] = statement_id
                    old["history"].append(index)
            elif p[1] in (17, 18, 19):
                # A membership's transitions and revocation are statements
                # about the membership only.
                record = records[body[1]]
                record["history"].append(index)
                if p[1] == 17:
                    record["endorsements"].append((p[3], body[2], index))
                elif p[1] == 18:
                    record["state"] = body[3]
                    record["changes"].append((now, body[3]))
                else:
                    record["revoked"] = True
                    record["changes"].append((now, ""))
            return statement_id

        def refuse(name, signer, p, why):
            """The rules refuse it after the statements so far, at `at`, for
            the one rule `why` names. (Every refused statement here parses:
            a membership's metadata is checked by the ledger rules.)"""
            assert rules(p) == [why], (name, rules(p))
            encoded, _ = lg.statement(keys[signer], p)
            refused.append({"name": name, "signer": signer, "encoded": encoded.hex(), "payload": dcbor(p).hex(),
                            "after": len(statements), "at": clock[0], "why": why})

        def fields(*values):
            leaves = [dcbor([name, bytes([0xD0 + i]) * 16, value])
                      for i, (name, value) in enumerate(sorted(values, key=lambda f: f[0].encode()))]
            return lg.merkle().mth(leaves), len(leaves)

        def membership(signer_actor, delegation, metadata, supersedes=None):
            root, count = fields(("checked", "business registration certificate seen"), ("checked_on", "2026-11-11"))
            body = {1: MEMBERSHIP, 2: root, 3: count}
            if metadata is not None:
                body[5] = metadata
            if supersedes is not None:
                body[6] = supersedes
            return payload(signer_actor, 16, body, delegation)

        def notice(signer_actor, delegation, supersedes=None):
            root, count = fields(("text", "Members are listed at the registry's office."),)
            body = {1: NOTICE, 2: root, 3: count, 5: {"topic": "listing"}}
            if supersedes is not None:
                body[6] = supersedes
            return payload(signer_actor, 16, body, delegation)

        def transition(record, frm, to):
            return payload(registrar, 18, {1: record, 2: frm, 3: to}, registrars)

        ledger_id = None
        ledger_id = add("genesis", "org_root", payload(None, 1, {
            1: hash_id, 2: "HK Trust Ltd", 3: ed_public(keys["org_root"]), 4: ed_public(keys["log"])}))
        org = ledger_id
        registrar = add("register the registrar", "org_root", payload(org, 2, {
            1: 1, 2: "Membership Registrar", 3: ed_public(keys["registrar"])}))
        registrars = add("delegate memberships and notices to the registrar", "org_root", payload(org, 5, {
            1: registrar, 2: {1: [16, 17, 18, 19], 2: [MEMBERSHIP, NOTICE]}}))
        checked = {"member": school, "kind": "organization", "name": "Kowloon Example School", "verified": True,
                   "registration": "12345678", "jurisdiction": "HK", "until": t0 + 365 * day}

        m1 = add("the registrar registers the school's membership, checked", "registrar",
                 membership(registrar, registrars, checked))
        # A membership takes no endorsement, and its metadata is the ledger's
        # to check.
        refuse("endorse the membership", "registrar", payload(registrar, 17, {1: m1, 2: "reviewer"}, registrars),
               "role")
        refuse("a membership naming the trust node's own ledger", "registrar",
               membership(registrar, registrars, {**checked, "member": ledger_id}), "own ledger")
        refuse("a membership without metadata", "registrar", membership(registrar, registrars, None), "no metadata")
        refuse("a membership whose jurisdiction is in lower case", "registrar",
               membership(registrar, registrars, {**checked, "jurisdiction": "hk"}), "jurisdiction")
        refuse("a membership whose metadata has an unknown key", "registrar",
               membership(registrar, registrars, {**checked, "note": "seen in person"}), "unknown key")
        refuse("a membership without verified", "registrar", membership(registrar, registrars, {
            k: v for k, v in checked.items() if k != "verified"}), "missing key")
        refuse("a membership of kind company", "registrar",
               membership(registrar, registrars, {**checked, "kind": "company"}), "kind")
        refuse("a membership whose until is 0", "registrar",
               membership(registrar, registrars, {**checked, "until": 0}), "until")
        m2 = add("the organization registers a person's membership, self-declared", "org_root", membership(org, None, {
            "member": person, "kind": "person", "name": "Chan Tai Man", "verified": False}))

        # The lifecycle: suspended, resumed, ended.
        add("the registrar suspends the school's membership", "registrar", transition(m1, "active", "suspended"))
        refuse("suspend it again, from active", "registrar", transition(m1, "active", "suspended"), "state")
        refuse("move it from suspended to suspended", "registrar", transition(m1, "suspended", "suspended"),
               "transition")
        refuse("move it to another mechanism type's state (withdrawn)", "registrar",
               transition(m1, "suspended", "withdrawn"), "transition")
        add("the registrar resumes it", "registrar", transition(m1, "suspended", "active"))
        add("the registrar ends it: the school did not renew", "registrar", transition(m1, "active", "ended"))
        refuse("resume the ended membership", "registrar", transition(m1, "ended", "active"), "transition")
        refuse("suspend the ended membership", "registrar", transition(m1, "ended", "suspended"), "transition")

        # No versions: a membership neither supersedes nor is superseded.
        n1 = add("the registrar registers a notice, a record of a generic type", "registrar",
                 notice(registrar, registrars))
        refuse("a notice that supersedes the person's membership", "registrar",
               notice(registrar, registrars, supersedes=m2), "mechanism")
        refuse("a membership that supersedes the notice", "registrar",
               membership(registrar, registrars, checked, supersedes=n1), "mechanism")

        # A renewal is a new membership, judged by its own history.
        m3 = add("a renewal: a new membership of the school", "registrar",
                 membership(registrar, registrars, {**checked, "until": t0 + 2 * 365 * day}))
        add("the registrar suspends the renewal", "registrar", transition(m3, "active", "suspended"))
        add("and ends it while suspended", "registrar", transition(m3, "suspended", "ended"))
        m4 = add("a kindergarten's membership, until the largest time", "registrar", membership(
            registrar, registrars, {"member": kindergarten, "kind": "organization", "name": "Example Kindergarten",
                                    "verified": True, "jurisdiction": "GB-ENG", "until": 2**64 - 1}))
        m5 = add("the organization registers a membership that lapses two minutes on", "org_root", membership(
            org, None, {"member": kindergarten, "kind": "organization", "name": "Example Kindergarten",
                        "verified": False, "until": clock[0] + 2 * minute}))
        add("the organization revokes the person's membership for cause", "org_root",
            payload(org, 19, {1: m2, 2: "forged papers"}))
        refuse("suspend the revoked membership", "registrar", transition(m2, "active", "suspended"), "revoked")
        refuse("revoke it again", "org_root", payload(org, 19, {1: m2}), "revoked")

        entries = [encode_log_entry(bytes.fromhex(st["statement_id"]), st["registered_at"], bytes.fromhex(st["encoded"]))
                   for st in statements]
        leaves = [[1, a, h] for a, h in actors.items()] + [[2, d, h] for d, h in delegations.items()] + \
                 [[3, r, v["history"]] for r, v in records.items()]
        sorted_leaves = sorted(leaves, key=lambda leaf: leaf[1])
        commitment_index = len(entries)
        commitment_time = clock[0]
        commitment_id = append_state_commitment(lg, keys["log"], ledger_id, entries, sorted_leaves, commitment_time)
        checkpoint_time = commitment_time + 1000
        checkpoint, _ = sign_log_checkpoint(lg, keys["log"], ledger_id, entries, checkpoint_time)

        def membership_json(v):
            m = v["membership"]
            return {"member": m["member"].hex(), "kind": m["kind"], "name": m["name"], "verified": m["verified"],
                    "registration": m.get("registration"), "jurisdiction": m.get("jurisdiction"),
                    "until": m.get("until"), "registered_at": v["registered_at"],
                    "at_checkpoint": membership_standing(v["registered_at"], m.get("until"), v["changes"],
                                                         checkpoint_time)}

        standings = {m: membership_json(records[m])["at_checkpoint"] for m in (m1, m2, m3, m4, m5)}
        assert list(standings.values()) == ["ended", "revoked", "ended", "active", "lapsed"], standings
        ledgers.append({
            "hash": hash_id,
            "ledger_id": ledger_id.hex(),
            "statements": statements,
            "refused": refused,
            "memberships": [m.hex() for m in (m1, m2, m3, m4, m5)],
            "records": [{"id": r.hex(), "type": v["type"], "state": v["state"], "revoked": v["revoked"],
                         "registrant": v["registrant"].hex(), "history": v["history"],
                         "supersedes": v["supersedes"].hex() if v["supersedes"] else None,
                         "superseded_by": v["superseded_by"].hex() if v["superseded_by"] else None,
                         "membership": membership_json(v) if v["membership"] is not None else None}
                        for r, v in records.items()],
            "log_entries": [e.hex() for e in entries],
            "state_leaves": [{"kind": leaf[0], "id": leaf[1].hex(), "history": leaf[2]} for leaf in sorted_leaves],
            "state_root": smt_root(lg, sorted_leaves).hex(),
            "state_commitment": {"index": commitment_index, "id": commitment_id.hex()},
            "checkpoint": checkpoint.hex(),
            "checkpoint_time": checkpoint_time,
        })
    return {"t0": t0, "seeds": seeds, "ledgers": ledgers}


def membership_bundle_cases(t0: int) -> tuple[list, list]:
    """Member ledgers' evidence bundles carrying membership proofs (key 9),
    each proof a trust node's complete evidence of a membership: (valid,
    refused). The ledgers are written by hand with evidence_suite's Forge."""
    import evidence_suite as es

    minute, second, day = 60_000, 1_000, 86_400_000

    def at(forge, offset):
        forge.time = t0 + offset

    def member_of(forge, by, delegation, metadata, offset):
        at(forge, offset)
        return forge.record(by, MEMBERSHIP, delegation=delegation, metadata=metadata,
                            fields={"checked": "business registration certificate seen"})

    def change(forge, m, frm, to, by, delegation, offset):
        at(forge, offset)
        forge.about(18, m, {2: frm, 3: to}, by, delegation)

    def revoke(forge, m, reason, by, delegation, offset):
        at(forge, offset)
        forge.about(19, m, {2: reason}, by, delegation)

    def commit(forge, offset):
        at(forge, offset)
        forge.commit()

    def proof(forge, m, size=None):
        """A membership's evidence bundle over the first `size` entries (all
        by default), and what it shows: the history up to its checkpoint."""
        size = len(forge.entries) if size is None else size
        history = [i for i in forge.leaves[m][2] if i < size]
        changes = []
        for i in history[1:]:
            p = forge.info[i]["payload"]
            changes.append((forge.times[i], p[7][3] if p[1] == 18 else ""))
        facts = {"forge": forge, "membership": m, "registered_at": forge.times[history[0]],
                 "metadata": forge.info[history[0]]["payload"][7].get(5), "changes": changes,
                 "checkpoint_time": forge.times[size - 1] + second}
        return dcbor(forge.bundle(m, size=size)), facts

    # The member: a school. And a person's own ledger, another member.
    school = es.Forge("Kowloon Example School", t0=t0)
    person = es.Forge("Chan Tai Man", t0=t0)
    # The trust nodes: one with a registrar, an SM3 one, one with many
    # memberships of the school, and one that registers what the ledger rules
    # refuse.
    node = es.Forge("HK Trust Ltd", t0=t0)
    other = es.Forge("Guangdong Trust Registry", hash_id=-65538, t0=t0)
    many = es.Forge("Many Memberships Trust", t0=t0)
    careless = es.Forge("Careless Trust", t0=t0)
    # A ledger that lists itself, which the ledger rules refuse.
    selfish = es.Forge("Self-Listed School", t0=t0)

    checked = {"member": school.id, "kind": "organization", "name": "Kowloon Example School", "verified": True,
               "registration": "12345678", "jurisdiction": "HK"}

    at(node, 1 * minute)
    registrar = node.actor(es.PERSON, "Membership Registrar", es.Key("HK Trust Ltd registrar"))
    registrars = node.grant(registrar, {1: [16, 18, 19], 2: [MEMBERSHIP, LISTING]})
    m1 = member_of(node, registrar, registrars, {**checked, "until": t0 + 365 * day}, 10 * minute)
    m7 = member_of(node, node.org, None, checked, 11 * minute)
    m5 = member_of(node, registrar, registrars, {**checked, "until": t0 + 50 * minute}, 12 * minute)
    m8 = member_of(node, registrar, registrars, {"member": person.id, "kind": "person", "name": "Chan Tai Man",
                                                 "verified": True, "jurisdiction": "HK"}, 13 * minute)
    at(node, 14 * minute)
    listing = node.record(registrar, LISTING, delegation=registrars, metadata=checked,
                          fields={"listed": "the members' list"})
    commit(node, 30 * minute)
    p1, p5a, p8, p_listing = proof(node, m1), proof(node, m5), proof(node, m8), proof(node, listing)
    change(node, m1, "active", "suspended", registrar, registrars, 40 * minute)
    p_incomplete = proof(node, m1)  # its checkpoint ends with the suspension, not a state commitment
    assert len(node.entries) - 1 not in node.snapshots
    commit(node, 41 * minute)
    p1b = proof(node, m1)
    change(node, m1, "suspended", "active", registrar, registrars, 45 * minute)
    revoke(node, m7, "forged papers", node.org, None, 60 * minute)
    change(node, m1, "active", "ended", registrar, registrars, 65 * minute)
    commit(node, 70 * minute)
    p1c, p5b, p7 = proof(node, m1), proof(node, m5), proof(node, m7)

    m2 = member_of(other, other.org, None, {"member": school.id, "kind": "organization",
                                            "name": "Kowloon Example School", "verified": False,
                                            "jurisdiction": "CN-44"}, 15 * minute)
    commit(other, 16 * minute)
    p2 = proof(other, m2)

    renewals = [member_of(many, many.org, None, {**checked, "registration": f"{12345600 + k}"}, (1 + k) * minute)
                for k in range(MAX_MEMBERSHIP_PROOFS + 1)]
    commit(many, 18 * minute)
    p_many = [proof(many, m) for m in renewals]

    bad = member_of(careless, careless.org, None, {**checked, "jurisdiction": "hk"}, 8 * minute)
    commit(careless, 9 * minute)
    p_bad = proof(careless, bad)

    at(school, 5 * minute)
    d0 = school.record(school.org, DIPLOMA, fields={"name": "Lee Siu Ming", "awarded": "2026-11-11"})
    at(school, 20 * minute)
    d1 = school.record(school.org, DIPLOMA, fields={"name": "Chan Tai Man", "awarded": "2026-11-11"})
    at(school, 120 * minute)
    d2 = school.record(school.org, DIPLOMA, fields={"name": "Wong Mei Ling", "awarded": "2026-11-11"})
    commit(school, 121 * minute)

    at(person, 25 * minute)
    profile = person.record(person.org, "example.org.profile/1", fields={"display_name": "Chan Tai Man"})
    commit(person, 26 * minute)

    at(selfish, 20 * minute)
    selfish_diploma = selfish.record(selfish.org, DIPLOMA, fields={"name": "Ho Ka Yan"})
    own = member_of(selfish, selfish.org, None, {**checked, "member": selfish.id, "name": "Self-Listed School"},
                    21 * minute)
    commit(selfish, 22 * minute)
    p_own = proof(selfish, own)

    def bundle(forge, record, proofs) -> bytes:
        b = forge.bundle(record)
        b[9] = proofs
        return dcbor(b)

    def report(facts, record_time, trust):
        forge, meta = facts["forge"], facts["metadata"]
        names = {f.id: n for f, n in trust}

        def standing(t):
            return membership_standing(facts["registered_at"], meta.get("until"), facts["changes"], t)

        return {"trust_node": forge.id.hex(), "trusted": forge.id in names, "trust_node_name": names.get(forge.id),
                "membership": facts["membership"].hex(), "kind": meta["kind"], "name": meta["name"],
                "verified": meta["verified"], "registration": meta.get("registration"),
                "jurisdiction": meta.get("jurisdiction"), "until": meta.get("until"),
                "registered_at": facts["registered_at"], "record_time": record_time,
                "at_record": standing(record_time), "checkpoint_time": facts["checkpoint_time"],
                "at_checkpoint": standing(facts["checkpoint_time"])}

    valid, refused = [], []

    def ok(name, forge, record, proofs, trust, expected):
        """`expected`: (at_record, at_checkpoint) of each proof, as the
        story says, checked against the computed report."""
        record_time = forge.times[forge.index[record]]
        memberships = [report(f, record_time, trust) for _, f in proofs]
        assert [(m["at_record"], m["at_checkpoint"]) for m in memberships] == expected, (name, memberships)
        valid.append({"name": name, "bundle": bundle(forge, record, [p for p, _ in proofs]).hex(),
                      "ledger": forge.id.hex(), "trust_nodes": [{"ledger": f.id.hex(), "name": n} for f, n in trust],
                      "memberships": memberships})

    def bad(name, why, forge, record, proofs):
        refused.append({"name": name, "why": why, "bundle": bundle(forge, record, proofs).hex(),
                        "ledger": forge.id.hex()})

    hk, gd = (node, "HK Trust"), (other, "Guangdong Registry")
    ok("one proof from a trust node the verifier trusts, named by its list (the node calls itself HK Trust Ltd)",
       school, d1, [p1], [hk], [("active", "active")])
    ok("the same bundle with an empty trust list: reported, not trusted, no name", school, d1, [p1], [],
       [("active", "active")])
    ok("the same bundle, trusting another trust node only", school, d1, [p1], [gd], [("active", "active")])
    ok("suspended after the record was registered", school, d1, [p1b], [hk], [("active", "suspended")])
    ok("a record registered before the membership", school, d0, [p1], [hk], [("not_yet", "active")])
    ok("two proofs from two trust nodes, one of SM3 and self-declared, both trusted", school, d1, [p1, p2],
       [hk, gd], [("active", "active"), ("active", "active")])
    ok("two proofs in the other order, one trust node trusted", school, d1, [p2, p1], [gd],
       [("active", "active"), ("active", "active")])
    ok("ended by the proof's checkpoint", school, d1, [p1c], [hk], [("active", "ended")])
    ok("revoked by the proof's checkpoint", school, d1, [p7], [hk], [("active", "revoked")])
    ok("lapsed by the proof's checkpoint", school, d1, [p5b], [hk], [("active", "lapsed")])
    ok("a record registered after the proof's checkpoint: as of the checkpoint (the later suspension unseen)",
       school, d2, [p1], [hk], [("active", "active")])
    ok("a record registered after the proof's checkpoint and after until: lapsed then, active at the checkpoint",
       school, d2, [p5a], [hk], [("lapsed", "active")])
    ok("a record registered after the membership ended", school, d2, [p1c], [hk], [("ended", "ended")])
    ok("a person's membership, on the person's own ledger", person, profile, [p8], [hk], [("active", "active")])
    ok("sixteen proofs, the most, of sixteen memberships", school, d1, p_many[:MAX_MEMBERSHIP_PROOFS],
       [(many, "Many Memberships")], [("active", "active")] * MAX_MEMBERSHIP_PROOFS)

    nested = cbor2.loads(p1[0])
    assert dcbor(nested) == p1[0]
    nested[9] = [p2[0]]
    damaged = cbor2.loads(p1[0])
    damaged[3] = damaged[3][:-1] + bytes([damaged[3][-1] ^ 0x01])
    bad("a proof naming another member (a person's ledger)", "another member", school, d1, [p8[0]])
    bad("a valid proof, then one naming another member", "another member", school, d1, [p1[0], p8[0]])
    bad("a proof that carries membership proofs of its own", "nested", school, d1, [dcbor(nested)])
    bad("two proofs of one membership, at two checkpoints", "twice", school, d1, [p1[0], p1b[0]])
    bad("one proof twice", "twice", school, d1, [p1[0], p1[0]])
    bad("a proof that is not complete: its checkpoint ends with a transition", "incomplete", school, d1,
        [p_incomplete[0]])
    bad("a proof of a record of another type that carries a membership's metadata", "not a membership", school, d1,
        [p_listing[0]])
    bad("a damaged proof: its checkpoint's signature", "does not verify", school, d1, [dcbor(damaged)])
    bad("a proof whose membership the ledger rules refuse (jurisdiction hk)", "metadata", school, d1, [p_bad[0]])
    bad("a membership a ledger registered of itself", "own ledger", selfish, selfish_diploma, [p_own[0]])
    bad("seventeen proofs", "too many", school, d1, [p for p, _ in p_many])
    bad("an empty list of proofs", "empty", school, d1, [])
    bad("a proof that is a map, not a byte string", "not bytes", school, d1, [cbor2.loads(p1[0])])
    return valid, refused


def generate_protocol_v16() -> None:
    t0 = 1_794_355_200_000  # 2026-11-11T00:00:00Z
    valid_metadata, refused_metadata = membership_metadata_cases(t0)
    standings = membership_standing_cases(t0)
    replay = membership_replay(t0)
    valid_bundles, refused_bundles = membership_bundle_cases(t0)

    def lifecycle(kind):
        initial, transitions = MECHANISM_TYPES_V16[kind]
        ordered = MEMBERSHIP_TRANSITIONS if kind == MEMBERSHIP else sorted(transitions)
        return {"type": kind, "initial": initial, "transitions": [list(t) for t in ordered]}

    document = {
        "description": "CexChain protocol objects of specification revision v0.16 (trust nodes), built by an "
                       "independent Python encoder from spec/README.md (sections 6 and 11) and spec/cexchain.cddl. "
                       "Times are milliseconds since the epoch. `mechanism_types` lists the six mechanism types "
                       "in the specification's table order, each with its initial state and transitions (the "
                       "membership's in the table's order, the others' sorted). `membership_metadata` holds "
                       "membership metadata (record key 5 of a cexchain.membership/1 record) on its own: `valid` "
                       "cases, each its deterministic CBOR (`metadata`) and its values (`membership`: the member's "
                       "ledger id in hex, and the optional keys only when present), the specification's example "
                       "first; `refused` cases, each breaking one rule of the `membership` CDDL or its limits in "
                       "section 6, which `why` names: \"no metadata\" (not a map), \"unknown key\" (a text key "
                       "the CDDL does not name, or a key that is not text), \"missing key\", and the key whose "
                       "rule is broken: \"member\" (not a 32-byte id), \"kind\" (not organization or person), "
                       "\"name\" (not 1 to 256 bytes of text), \"verified\" (not a boolean), \"registration\" "
                       "(not 1 to 64 bytes of text), \"jurisdiction\" (not two upper-case letters, optionally "
                       "followed by - and 1 to 3 upper-case letters or digits, the whole text), \"until\" (not an "
                       "unsigned integer above 0). A key whose value is not of its type, null included, breaks "
                       "that key's rule. `standings` holds where a membership stood at given times (section 11, "
                       "step 9): each its registration time, its until (null if none), and its changes in log "
                       "order, each its registration time and the state it moved to (\"suspended\", "
                       "\"active\", \"ended\", or \"\" for the revocation), then cases of a time `t` and the "
                       "standing there: \"not_yet\" (t before the registration), else \"revoked\" (revoked at or "
                       "before t), else \"lapsed\" (t after until), else the state the last change at or before t "
                       "left (of two at one time, the later in the log), or \"active\". `replay` holds a trust "
                       "node's log for each hash, in the format of protocol-v0.14.json's ledgers: the "
                       "organization (HK Trust Ltd) delegates memberships and notices (example.org.notice/1) to "
                       "a registrar; each statement registers at its `registered_at`; `refused` statements are "
                       "validated against the state after the first `after` statements, at `at`, and break "
                       "exactly one rule, which `why` names: \"role\" (a membership takes no endorsement), "
                       "\"own ledger\" (a member that is the trust node's own ledger id), \"no metadata\", the "
                       "metadata rules above (\"jurisdiction\", \"unknown key\", \"missing key\", \"kind\", "
                       "\"until\"), \"state\" (a transition not from the current state), \"transition\" (one the "
                       "type does not allow: ended takes none, and states of other types are none of a "
                       "membership's), \"mechanism\" (a membership neither supersedes nor is superseded), "
                       "\"revoked\" (a revoked membership takes nothing more); every refused statement parses. A "
                       "membership's registration and transitions are statements about the membership only. "
                       "`memberships` lists the accepted memberships; `records` gives each record's type, state, "
                       "revocation, registrant, history, and versions, and, for a membership, its values (null "
                       "for an absent optional key), its registration time, and its standing at "
                       "`checkpoint_time` (`at_checkpoint`). `log_entries` holds the whole log, ending with the "
                       "state commitment over `state_leaves`; `checkpoint` (signed at `checkpoint_time`) covers "
                       "it; keys are seed = SHA-256(\"CexChain test key: <name>\"), `seeds`. `bundles` holds "
                       "member ledgers' evidence bundles carrying membership proofs (key 9), written by hand "
                       "(tools/testvectors/evidence_suite.py's Forge; keys are seed = SHA-256(\"CexChain test "
                       "key: evidence <ledger name> root\"), \"... log\", and \"CexChain test key: evidence HK "
                       "Trust Ltd registrar\"). Each `valid` case is a bundle (`bundle`, hex) of the member "
                       "ledger `ledger`, the verifier's trust list (`trust_nodes`, each a ledger id and the name "
                       "the verifier gives it), and what the report states of each proof, in the bundle's order "
                       "(`memberships`): the trust node's ledger id, whether it is trusted, the name the list "
                       "gives it (null when untrusted: never the trust node's own name), the membership's id, "
                       "kind, name, verified, registration, jurisdiction, and until (null when absent), its "
                       "registration time (`registered_at`), the registration time of the bundle's record "
                       "(`record_time`) and the standing then (`at_record`), and the proof's checkpoint's time "
                       "(`checkpoint_time`) and the standing then (`at_checkpoint`). Every valid bundle is "
                       "complete, and so is every proof in it. Each `refused` case is a bundle that fails for the "
                       "one rule of step 9 or of key 9 that `why` names: \"another member\" (a proof's "
                       "membership names another ledger), \"nested\" (a proof carries key 9), \"twice\" (two "
                       "proofs of one membership: the same ledger and record), \"incomplete\" (a proof whose "
                       "checkpoint does not end with a state commitment), \"not a membership\" (a proof of a "
                       "record of another type, with a membership's metadata), \"does not verify\" (a damaged "
                       "proof), \"metadata\" and \"own ledger\" (a proof whose log the ledger rules refuse: a "
                       "membership's metadata of the wrong shape, a membership of the trust node's own ledger), "
                       "\"too many\" (17 proofs), \"empty\" (key 9 an empty list), \"not bytes\" (a proof that "
                       "is not a byte string). A refused bundle fails whatever the trust list.",
        "mechanism_types": [lifecycle(kind) for kind in MECHANISM_TYPES_V16],
        "membership_metadata": {"valid": valid_metadata, "refused": refused_metadata},
        "standings": standings,
        "replay": replay,
        "bundles": {"valid": valid_bundles, "refused": refused_bundles},
    }
    (OUT / "protocol-v0.16.json").write_text(json.dumps(document, indent=1, ensure_ascii=False) + "\n")
    first = replay["ledgers"][0]
    reasons = sorted({r["why"] for r in first["refused"]})
    print(f"wrote protocol vectors to testvectors/protocol-v0.16.json: {len(valid_metadata)} membership metadata, "
          f"{len(refused_metadata)} refused; {len(standings)} standings; {len(replay['ledgers'])} ledgers of "
          f"{len(first['statements'])} statements, {len(first['refused'])} refused ({', '.join(reasons)}); "
          f"{len(valid_bundles)} bundles, {len(refused_bundles)} refused")


# ---------------------------------------------------------------------------
# Contract execution (spec section 14): the deterministic WebAssembly profile,
# from the independent reference interpreter in wasm_ref.py
# ---------------------------------------------------------------------------

def generate_vm_v1() -> None:
    import random
    import struct
    import wasm_ref as w

    modules, runs = [], []

    def add_module(name, wasm, refused=None):
        try:
            module = w.load(wasm)
            outcome = None
        except w.Refused as e:
            module, outcome = None, str(e)
        if refused is not None:
            assert module is None, f"{name} should be refused ({refused})"
        else:
            assert module is not None, f"{name} was refused: {outcome}"
        modules.append({"name": name, "wasm": wasm.hex(), "valid": module is not None,
                        **({"refused_because": outcome} if module is None else {})})
        return module

    def add_run(name, module_name, module, input_=b"", hash_name="sha256"):
        outcome, output, fuel, reason = w.run(module, input_, hash_name)
        runs.append({"name": name, "module": module_name, "input": input_.hex(), "hash": hash_name,
                     "outcome": outcome, "output": output.hex(), "fuel": fuel,
                     **({"reason": reason.hex()} if outcome == "aborted" else {})})

    def out_i64(expr):
        # Computes an i64 and writes its 8 bytes.
        return [("i32.const", 0), *expr, ("i64.store",), ("i32.const", 0), ("i32.const", 8), ("call", 0)]

    def out_i32(expr):
        return [("i32.const", 0), *expr, ("i32.store",), ("i32.const", 0), ("i32.const", 4), ("call", 0)]

    def expr_module(name, body, locals_=(), **kw):
        wasm = w.assemble([{"body": body, "locals": list(locals_)}], imports=["output_write"], **kw)
        m = add_module(name, wasm)
        add_run(name, name, m)

    # --- Host functions --------------------------------------------------------
    echo = w.assemble([{"locals": ["i32"], "body": [
        ("call", 0), ("local.set", 0), ("i32.const", 0), ("call", 1),
        ("i32.const", 0), ("local.get", 0), ("call", 2)]}],
        imports=["input_size", "input_read", "output_write"])
    m = add_module("echo", echo)
    for i, data in enumerate([b"", b"hello", bytes(range(256)) * 3]):
        add_run(f"echo {i}", "echo", m, data)
    hasher = w.assemble([{"locals": ["i32"], "body": [
        ("call", 0), ("local.set", 0), ("i32.const", 64), ("call", 1),
        ("i32.const", 64), ("local.get", 0), ("i32.const", 0), ("call", 2),
        ("i32.const", 0), ("i32.const", 32), ("call", 3)]}],
        imports=["input_size", "input_read", "hash", "output_write"])
    m = add_module("hash", hasher)
    for h in ("sha256", "sm3"):
        add_run(f"hash {h}", "hash", m, b"CexChain contract input", h)
    aborts = w.assemble([{"body": [("i32.const", 0), ("i32.const", 2000), ("call", 0)]}],
                        imports=["abort"], data=[(0, b"refused: " + b"x" * 1500)])
    m = add_module("abort", aborts)
    add_run("abort with a long reason", "abort", m)
    twice = w.assemble([{"body": [("i32.const", 0), ("i32.const", 1), ("call", 0),
                                  ("i32.const", 0), ("i32.const", 1), ("call", 0)]}], imports=["output_write"])
    add_run("output twice", "output twice", add_module("output twice", twice))
    big = w.assemble([{"body": [("i32.const", 0), ("i32.const", (1 << 20) + 1), ("call", 0)]}],
                     imports=["output_write"], memory=(16, 16))
    add_run("output too large", "output too large", add_module("output too large", big))
    oob = w.assemble([{"body": [("i32.const", 65530), ("i32.const", 7), ("call", 0)]}], imports=["output_write"])
    add_run("output out of bounds", "output out of bounds", add_module("output out of bounds", oob))
    silent = w.assemble([{"body": [("nop",)]}])
    add_run("no output", "no output", add_module("no output", silent))

    # --- Integer edge cases ------------------------------------------------------
    I64MIN, I32MIN = 1 << 63, 1 << 31
    cases = {
        "i32 div_s overflow": out_i32([("i32.const", I32MIN), ("i32.const", 0xFFFFFFFF), ("i32.div_s",)]),
        "i64 div_s overflow": out_i64([("i64.const", I64MIN), ("i64.const", (1 << 64) - 1), ("i64.div_s",)]),
        "i32 rem_s min by -1": out_i32([("i32.const", I32MIN), ("i32.const", 0xFFFFFFFF), ("i32.rem_s",)]),
        "i64 rem_s min by -1": out_i64([("i64.const", I64MIN), ("i64.const", (1 << 64) - 1), ("i64.rem_s",)]),
        "i32 div_u by zero": out_i32([("i32.const", 7), ("i32.const", 0), ("i32.div_u",)]),
        "i64 rem_u by zero": out_i64([("i64.const", 7), ("i64.const", 0), ("i64.rem_u",)]),
        "i32 div_s rounds to zero": out_i32([("i32.const", (-7) & 0xFFFFFFFF), ("i32.const", 2), ("i32.div_s",)]),
        "i32 rem_s sign": out_i32([("i32.const", (-7) & 0xFFFFFFFF), ("i32.const", 2), ("i32.rem_s",)]),
        "i32 shl by 33": out_i32([("i32.const", 1), ("i32.const", 33), ("i32.shl",)]),
        "i64 shr_s by 65": out_i64([("i64.const", I64MIN), ("i64.const", 65), ("i64.shr_s",)]),
        "i64 shr_u by 64": out_i64([("i64.const", I64MIN), ("i64.const", 64), ("i64.shr_u",)]),
        "i32 rotl": out_i32([("i32.const", 0x80000001), ("i32.const", 1), ("i32.rotl",)]),
        "i64 rotr by 0": out_i64([("i64.const", 0x0123456789ABCDEF), ("i64.const", 0), ("i64.rotr",)]),
        "i64 rotr by 4": out_i64([("i64.const", 0x0123456789ABCDEF), ("i64.const", 4), ("i64.rotr",)]),
        "i32 clz of 0": out_i32([("i32.const", 0), ("i32.clz",)]),
        "i64 ctz of 0": out_i64([("i64.const", 0), ("i64.ctz",)]),
        "i64 popcnt": out_i64([("i64.const", 0xF0F0F0F0F0F0F0F1), ("i64.popcnt",)]),
        "i32 mul wraps": out_i32([("i32.const", 0x10000), ("i32.const", 0x10001), ("i32.mul",)]),
        "i64 sub wraps": out_i64([("i64.const", 0), ("i64.const", 1), ("i64.sub",)]),
        "i64 extend_i32_s": out_i64([("i32.const", 0x80000000), ("i64.extend_i32_s",)]),
        "i64 extend_i32_u": out_i64([("i32.const", 0x80000000), ("i64.extend_i32_u",)]),
        "i32 wrap": out_i32([("i64.const", 0x1234567887654321), ("i32.wrap_i64",)]),
        "i32 extend8_s": out_i32([("i32.const", 0x180), ("i32.extend8_s",)]),
        "i32 extend16_s": out_i32([("i32.const", 0x18000), ("i32.extend16_s",)]),
        "i64 extend32_s": out_i64([("i64.const", 0x80000000), ("i64.extend32_s",)]),
        "i64 lt_s vs lt_u": out_i32([("i64.const", I64MIN), ("i64.const", 1), ("i64.lt_s",),
                                     ("i64.const", I64MIN), ("i64.const", 1), ("i64.lt_u",), ("i32.add",)]),
        "i32 ge_u": out_i32([("i32.const", 0xFFFFFFFF), ("i32.const", 1), ("i32.ge_u",)]),
        "unreachable": [("unreachable",)],
    }
    for name, body in cases.items():
        expr_module(name, body)

    # --- Control -------------------------------------------------------------------
    sum_loop = [
        ("i32.const", 0), ("i32.load",), ("local.set", 0),
        ("block", None), ("loop", None),
        ("local.get", 0), ("i32.eqz",), ("br_if", 1),
        ("local.get", 1), ("local.get", 0), ("i64.extend_i32_u",), ("i64.add",), ("local.set", 1),
        ("local.get", 0), ("i32.const", 1), ("i32.sub",), ("local.set", 0),
        ("br", 0),
        ("end",), ("end",),
        ("i32.const", 8), ("local.get", 1), ("i64.store",),
        ("i32.const", 8), ("i32.const", 8), ("call", 2)]
    loop_mod = w.assemble([{"locals": ["i32", "i64"], "body": [("i32.const", 0), ("call", 1)] + sum_loop}],
                          imports=["input_size", "input_read", "output_write"])
    m = add_module("sum loop", loop_mod)
    for n in (0, 1, 10, 1000, 1_000_000):
        add_run(f"sum loop {n}", "sum loop", m, struct.pack("<I", n))

    # Blocks with values, multi-value, br_table, select, if/else, return.
    control = w.assemble([{"locals": ["i32"], "body": [
        ("i32.const", 0), ("call", 0), ("i32.const", 0), ("i32.load",), ("local.set", 0),
        ("i32.const", 16),
        ("block", 3),  # type 3 is [] -> [i32 i64]: after the imports' and the function's types
        ("i32.const", 1), ("i64.const", 2),
        ("end",),
        ("drop",), ("i32.const", 10), ("i32.add",),
        ("block", "i32"), ("block", "i32"), ("block", "i32"),
        ("i32.const", 100), ("local.get", 0), ("br_table", [0, 1], 2),
        ("end",), ("i32.const", 1), ("i32.add",),
        ("end",), ("i32.const", 2), ("i32.add",),
        ("end",), ("i32.const", 3), ("i32.add",),
        ("i32.add",),
        ("local.get", 0), ("i32.const", 1), ("i32.and",),
        ("if", "i32"), ("i32.const", 1000), ("else",), ("i32.const", 2000), ("end",),
        ("i32.add",),
        ("i32.const", 7), ("i32.const", 9), ("local.get", 0), ("select",), ("i32.add",),
        ("i32.const", 7), ("i32.const", 9), ("local.get", 0), ("select_t", "i32"), ("i32.add",),
        ("i32.store",),
        ("i32.const", 16), ("i32.const", 4), ("call", 1)]}],
        imports=["input_read", "output_write"], extra_types=[([], ["i32", "i64"])])
    m = add_module("control", control)
    for k in range(4):
        add_run(f"control {k}", "control", m, struct.pack("<I", k))

    # Recursion: depth and the stack budget.
    rec = w.assemble([
        {"params": ["i32"], "results": ["i32"], "body": [
            ("local.get", 0), ("i32.eqz",), ("if", "i32"), ("i32.const", 0), ("else",),
            ("local.get", 0), ("i32.const", 1), ("i32.sub",), ("call", 2), ("i32.const", 1), ("i32.add",),
            ("end",)]},
        {"body": [("i32.const", 0), ("call", 0), ("i32.const", 0), ("i32.const", 0), ("i32.load",),
                  ("call", 2), ("i32.store",), ("i32.const", 0), ("i32.const", 4), ("call", 1)]}],
        imports=["input_read", "output_write"])
    m = add_module("recursion", rec)
    for n in (10, 254, 255, 300):
        add_run(f"recursion {n}", "recursion", m, struct.pack("<I", n))
    heavy = w.assemble([
        {"params": ["i32"], "locals": ["i64"] * 4000, "body": [
            ("local.get", 0), ("if", None), ("local.get", 0), ("i32.const", 1), ("i32.sub",), ("call", 1),
            ("end",)]},
        {"body": [("i32.const", 0), ("call", 0), ("i32.const", 0), ("i32.load",), ("call", 1)]}],
        imports=["input_read"])
    m = add_module("stack budget", heavy)
    for n in (20, 40):
        add_run(f"stack budget {n}", "stack budget", m, struct.pack("<I", n))

    # Memory: widths and signs, bounds, growth, bulk operations.
    mem = w.assemble([{"body": [
        ("i32.const", 0), ("i64.const", 0x8182838485868788), ("i64.store",),
        ("i32.const", 16), ("i32.const", 0), ("i64.load8_s",), ("i64.store",),
        ("i32.const", 24), ("i32.const", 1), ("i64.load16_u", 0), ("i64.store",),
        ("i32.const", 32), ("i32.const", 0), ("i64.load32_s", 4), ("i64.store",),
        ("i32.const", 40), ("i32.const", 2), ("i32.load16_s",), ("i32.store",),
        ("i32.const", 44), ("memory.size",), ("i32.store",),
        ("i32.const", 48), ("i32.const", 2), ("memory.grow",), ("i32.store",),
        ("i32.const", 52), ("i32.const", 2), ("memory.grow",), ("i32.store",),
        ("i32.const", 56), ("memory.size",), ("i32.store",),
        ("i32.const", 60), ("i32.const", 0xAB), ("i32.const", 8), ("memory.fill",),
        ("i32.const", 68), ("i32.const", 0), ("i32.const", 8), ("memory.copy",),
        ("i32.const", 76), ("i32.const", 1), ("i32.const", 4), ("memory.init", 0),
        ("data.drop", 0),
        ("i32.const", 0), ("i32.const", 80), ("call", 0)]}],
        imports=["output_write"], memory=(1, 4), data=[(None, b"WXYZ!")], data_count=True)
    add_run("memory", "memory", add_module("memory", mem))
    for name, body in {
        "load out of bounds": [("i32.const", 65533), ("i32.load",), ("drop",)],
        "store at the edge": [("i32.const", 65532), ("i32.const", 1), ("i32.store",),
                              ("i32.const", 65533), ("i32.const", 1), ("i32.store",)],
        "offset overflow": [("i32.const", 0xFFFFFFF0), ("i64.load", 0x20), ("drop",)],
        "init after drop": [("data.drop", 0), ("i32.const", 0), ("i32.const", 0), ("i32.const", 1),
                            ("memory.init", 0)],
        "init of nothing after drop": [("data.drop", 0), ("i32.const", 0), ("i32.const", 0),
                                       ("i32.const", 0), ("memory.init", 0)],
        "grow beyond the maximum": [("i32.const", 0), ("i32.const", 16), ("memory.grow",), ("i32.store",),
                                    ("i32.const", 0), ("i32.const", 4), ("call", 0)],
        "copy out of bounds": [("i32.const", 65000), ("i32.const", 0), ("i32.const", 1000), ("memory.copy",)],
    }.items():
        wasm = w.assemble([{"body": body}], imports=["output_write"], data=[(None, b"Q")], data_count=True)
        add_run(name, name, add_module(name, wasm))

    # Fuel charged by size: growth, and bulk operations until the fuel runs out.
    grow = w.assemble([{"body": [
        ("i32.const", 0), ("i32.const", 15), ("memory.grow",), ("i32.store",),
        ("i32.const", 4), ("memory.size",), ("i32.store",),
        ("i32.const", 0), ("i32.const", 8), ("call", 0)]}], imports=["output_write"], memory=(1, 16))
    add_run("grow fifteen pages", "grow fifteen pages", add_module("grow fifteen pages", grow))
    fill = w.assemble([{"body": [
        ("loop", None), ("i32.const", 0), ("i32.const", 7), ("i32.const", 65536), ("memory.fill",),
        ("br", 0), ("end",)]}])
    add_run("fill until out of fuel", "fill until out of fuel", add_module("fill until out of fuel", fill))

    # Indirect calls.
    ind = w.assemble([
        {"params": ["i32"], "results": ["i32"], "body": [("local.get", 0), ("i32.const", 1), ("i32.add",)]},
        {"params": ["i64"], "results": ["i64"], "body": [("local.get", 0)]},
        {"body": [("i32.const", 0), ("call", 0),
                  ("i32.const", 4), ("i32.const", 41), ("i32.const", 0), ("i32.load",),
                  ("call_indirect", 2), ("i32.store",), ("i32.const", 4), ("i32.const", 4), ("call", 1)]}],
        imports=["input_read", "output_write"], table=(4, 4), elems=[(0, [2, 3]), (3, [2])])
    m = add_module("indirect", ind)
    for i in range(5):
        add_run(f"indirect {i}", "indirect", m, struct.pack("<I", i))

    # Globals.
    glob = w.assemble([{"body": [
        ("global.get", 0), ("i32.const", 5), ("i32.add",), ("global.set", 0),
        ("i32.const", 0), ("global.get", 0), ("i32.store",),
        ("i32.const", 8), ("global.get", 1), ("i64.store",),
        ("i32.const", 0), ("i32.const", 16), ("call", 0)]}],
        imports=["output_write"], globals_=[("i32", True, 37), ("i64", False, -5 & ((1 << 64) - 1))])
    add_run("globals", "globals", add_module("globals", glob))

    # Validation edge cases that are valid (the appendix algorithm).
    edge = {
        # Labels of different types meet in unreachable code (WebAssembly's "meet-bottom").
        "br_table meeting at the bottom": [("raw", b"\x02\x7e\x02\x7f\x00\x41\x01\x0e\x01\x00\x01"
                                                   b"\x0b\x1a\x42\x00\x0b\x1a")],
        "polymorphic stack": [("raw", b"\x00\x6a\x1a\x42\x01\x7c\x1a")],
        "branch out of unreachable code": [("block", None), ("unreachable",), ("br", 0), ("end",)],
    }
    for name, body in edge.items():
        wasm = w.assemble([{"body": body}], imports=["output_write"])
        add_run(name, name, add_module(name, wasm))
    # The validation limits, at and just beyond the boundary: control frames
    # (the function's own included), and the operand stack's height, here
    # reached with calls that return 16 values each.
    for blocks, ok in ((1023, True), (1024, False)):
        name = f"{blocks} nested blocks"
        wasm = w.assemble([{"body": [("block", None)] * blocks + [("end",)] * blocks}])
        m = add_module(name, wasm, refused=None if ok else name)
        if ok:
            add_run(name, name, m)
    sixteen = {"results": ["i32"] * 16, "body": [("i32.const", 0)] * 16}
    for extra, ok in ((15, True), (16, False)):
        height = 4095 * 16 + extra
        name = f"operand stack of {height}"
        wasm = w.assemble([sixteen, {"body": [("call", 0)] * 4095 + [("i32.const", 0)] * extra
                                     + [("return",)]}])
        m = add_module(name, wasm, refused=None if ok else name)
        if ok:
            add_run(name, name, m)

    # Blocks and loops with parameters (type 2 is [i32] -> [i32]).
    params = w.assemble([{"locals": ["i32"], "body": [
        ("i32.const", 0),
        ("i32.const", 5), ("loop", 2),
        ("i32.const", 1), ("i32.sub",), ("local.tee", 0), ("local.get", 0), ("br_if", 0),
        ("end",),
        ("i32.const", 7), ("block", 2), ("i32.const", 3), ("i32.add",), ("br", 0), ("end",),
        ("i32.add",), ("i32.store",),
        ("i32.const", 0), ("i32.const", 4), ("call", 0)]}],
        imports=["output_write"], extra_types=[(["i32"], ["i32"])])
    add_run("block and loop parameters", "block and loop parameters",
            add_module("block and loop parameters", params))

    # --- Modules outside the profile -------------------------------------------------
    good = w.assemble([{"body": [("nop",)]}])

    def body_bytes(raw):
        return w.assemble([{"body": [("raw", raw)]}])

    refused = {
        "float local": w.assemble([{"locals": ["f32"], "body": [("nop",)]}]),
        "float parameter": w.assemble([{"params": ["f64"], "body": [("nop",)]},
                                       {"body": [("nop",)]}]),
        "f64.const": body_bytes(b"\x44" + bytes(8) + b"\x1a"),
        "f32.add": body_bytes(b"\x43" + bytes(4) + b"\x43" + bytes(4) + b"\x92\x1a"),
        "SIMD": body_bytes(b"\xfd\x0c" + bytes(16) + b"\x1a"),
        "atomics": body_bytes(b"\xfe\x03\x00"),
        "saturating truncation": body_bytes(b"\x43" + bytes(4) + b"\xfc\x00\x1a"),
        "table.grow": w.assemble([{"body": [("raw", b"\xd0\x70\x41\x01\xfc\x0f\x00\x1a")]}], table=(1, 2)),
        "ref.null": body_bytes(b"\xd0\x70\x1a"),
        "tail call": body_bytes(b"\x12\x00"),
        "start section": w.assemble([{"body": [("nop",)]}], raw_sections=[(8, b"\x00")]),
        "import from another module": w.assemble([{"body": [("nop",)]}], imports=["input_size"]).replace(
            b"\x08cexchain", b"\x08cexchai_"),
        "unknown host function": w.assemble([{"body": [("nop",)]}], imports=["input_size"]).replace(
            b"\x0ainput_size", b"\x0ainput_sizz"),
        "memory of 17 pages": w.assemble([{"body": [("nop",)]}], memory=(1, 17)),
        "memory without maximum, 17 pages": w.assemble([{"body": [("nop",)]}], memory=(17, None)),
        "table of 1025": w.assemble([{"body": [("nop",)]}], table=(1025, None)),
        "no memory export": w.assemble([{"body": [("nop",)]}], memory=None),
        "no cexchain_call": w.assemble([{"body": [("nop",)]}], entry_name="main"),
        "cexchain_call with a parameter": w.assemble([{"params": ["i32"], "body": [("nop",)]}]),
        "duplicate export": w.assemble([{"body": [("nop",)]}],
                                       exports_extra=[w.name_("memory") + b"\x02\x00"]),
        "data out of bounds": w.assemble([{"body": [("nop",)]}], data=[(65535, b"ab")]),
        "element out of bounds": w.assemble([{"body": [("nop",)]}], table=(1, 1), elems=[(1, [0])]),
        "memory.init without data count": w.assemble([{"body": [
            ("i32.const", 0), ("i32.const", 0), ("i32.const", 0), ("memory.init", 0)]}], data=[(None, b"x")]),
        "type mismatch": body_bytes(b"\x41\x01\x42\x01\x6a\x1a"),
        "unknown local": body_bytes(b"\x20\x05\x1a"),
        "alignment too large": body_bytes(b"\x41\x00\x28\x03\x00\x1a"),
        "immutable global set": w.assemble([{"body": [("i32.const", 1), ("global.set", 0)]}],
                                           globals_=[("i32", False, 0)]),
        "too many locals": w.assemble([{"locals": ["i32"] * 4097, "body": [("nop",)]}]),
        "br_table arity mismatch": body_bytes(
            b"\x02\x7f\x02\x40\x41\x00\x0e\x01\x00\x01\x0b\x41\x00\x0b\x1a"),
        "if without else changes type": body_bytes(b"\x41\x01\x04\x7f\x41\x01\x0b\x1a"),
        "u32 too long": w.assemble([{"body": [("nop",)]}], entry_name=None, exports_extra=[
            w.name_("cexchain_call") + b"\x00\x80\x80\x80\x80\x80\x00"]),
        "u32 too large": w.assemble([{"body": [("nop",)]}], entry_name=None, exports_extra=[
            w.name_("cexchain_call") + b"\x00\x80\x80\x80\x80\x10"]),
    }
    for name, wasm in refused.items():
        add_module(name, wasm, refused=name)

    # --- Random integer programs (differential) -----------------------------------------
    rng = random.Random(20261011)
    binops32 = ["i32." + o for o in w._BIN]
    binops64 = ["i64." + o for o in w._BIN]
    unops = ["clz", "ctz", "popcnt"]
    cmps = [c for c in w._I32_CMP if c != "eqz"]

    def gen(t, depth):
        """Code that pushes one value of type t."""
        r = rng.random()
        if depth <= 0 or r < 0.25:
            if rng.random() < 0.5:
                return [("local.get", rng.randrange(4) + (0 if t == "i32" else 4))]
            v = rng.choice([0, 1, 2, 31, 32, 63, 64, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
                            rng.getrandbits(32 if t == "i32" else 64)])
            return [(t + ".const", v & (w.MASK32 if t == "i32" else w.MASK64))]
        if r < 0.55:
            op = rng.choice(binops32 if t == "i32" else binops64)
            divisor = gen(t, depth - 1)
            if op.split(".")[1] in ("div_s", "div_u", "rem_s", "rem_u") and rng.random() < 0.9:
                divisor += [(t + ".const", 1), (t + ".or",)]  # mostly nonzero, so programs run on
            return gen(t, depth - 1) + divisor + [(op,)]
        if r < 0.62:
            return gen(t, depth - 1) + [(t + "." + rng.choice(unops),)]
        if r < 0.70:
            if t == "i32":
                u = rng.choice(["i32", "i64"])
                return gen(u, depth - 1) + gen(u, depth - 1) + [(u + "." + rng.choice(cmps),)]
            return gen("i32", depth - 1) + [(rng.choice(["i64.extend_i32_s", "i64.extend_i32_u"]),)]
        if r < 0.75:
            if t == "i32":
                return gen("i64", depth - 1) + [("i32.wrap_i64",)]
            return gen("i64", depth - 1) + [(rng.choice(["i64.extend8_s", "i64.extend16_s", "i64.extend32_s"]),)]
        if r < 0.82:
            return gen(t, depth - 1) + gen(t, depth - 1) + gen("i32", depth - 1) + [("select",)]
        if r < 0.90:
            return gen("i32", depth - 1) + [("if", t)] + gen(t, depth - 1) + [("else",)] + gen(t, depth - 1) + [("end",)]
        if r < 0.95:
            # A block that may leave early with a value.
            return ([("block", t)] + gen(t, depth - 1) + gen("i32", depth - 1) + [("br_if", 0)] + [("drop",)]
                    + gen(t, depth - 1) + [("end",)])
        addr = rng.randrange(0, 512)
        load = rng.choice(["i32.load", "i32.load8_s", "i32.load16_u"] if t == "i32"
                          else ["i64.load", "i64.load8_u", "i64.load32_s"])
        return [("i32.const", addr), (load,)]

    def statement(depth):
        r = rng.random()
        if r < 0.5 or depth <= 0:
            i = rng.randrange(8)
            return gen("i32" if i < 4 else "i64", 3) + [("local.set", i)]
        if r < 0.75:
            t = rng.choice(["i32", "i64"])
            return [("i32.const", rng.randrange(0, 512))] + gen(t, 2) + [(t + ".store",)]
        # A bounded loop, its counter in a local of its own: 8 + depth.
        n = rng.randrange(1, 12)
        counter = 8 + depth
        body = [("i32.const", n), ("local.set", counter), ("loop", None)]
        for _ in range(rng.randrange(1, 4)):
            body += statement(depth - 1)
        body += [("local.get", counter), ("i32.const", 1), ("i32.sub",), ("local.tee", counter),
                 ("br_if", 0), ("end",)]
        return body

    for k in range(400):
        body = [("i32.const", 0), ("call", 0)]  # the input (64 bytes) at address 0
        for i in range(4):
            body += [("i32.const", 4 * i), ("i32.load",), ("local.set", i)]
        for i in range(4):
            body += [("i32.const", 16 + 8 * i), ("i64.load",), ("local.set", 4 + i)]
        for _ in range(rng.randrange(3, 12)):
            body += statement(2)
        for i in range(4):
            body += [("i32.const", 512 + 4 * i), ("local.get", i), ("i32.store",)]
        for i in range(4):
            body += [("i32.const", 528 + 8 * i), ("local.get", 4 + i), ("i64.store",)]
        # The output is the hash of the 560 bytes written, to keep the vectors small.
        body += [("i32.const", 0), ("i32.const", 560), ("i32.const", 600), ("call", 1),
                 ("i32.const", 600), ("i32.const", 32), ("call", 2)]
        wasm = w.assemble([{"locals": ["i32"] * 4 + ["i64"] * 4 + ["i32"] * 3, "body": body}],
                          imports=["input_read", "hash", "output_write"])
        name = f"random {k}"
        m = add_module(name, wasm)
        for j, hash_name in enumerate(("sha256", "sm3")):
            add_run(f"{name}.{j}", name, m, rng.randbytes(64), hash_name)

    document = {
        "description": "CexChain contract execution (spec section 14): modules in and out of the "
                       "deterministic WebAssembly profile, and invocations of cexchain_call with their "
                       "outcome (ok, or the trap's name), output, fuel used, and abort reason. Built by "
                       "the independent reference interpreter tools/testvectors/wasm_ref.py; the random "
                       "programs (seeded) check every implementation against it, fuel included.",
        "fuel": w.FUEL,
        "modules": modules,
        "runs": runs,
    }
    (OUT / "vm-v1.json").write_text(json.dumps(document, indent=1) + "\n")
    outcomes = {}
    for r in runs:
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
    print(f"wrote {len(modules)} modules and {len(runs)} runs to testvectors/vm-v1.json: {outcomes}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--openssl", default="openssl", help="OpenSSL 3.5+ command-line tool")
    args = parser.parse_args()
    generate_hashes()
    generate_signatures(args.openssl)
    generate_merkle("SHA-256", "sha256", "merkle-sha256.json")
    generate_merkle("SM3", "sm3", "merkle-sm3.json")
    generate_cose(args.openssl)
    generate_pkcs8(args.openssl)
    generate_protocol()
    generate_protocol_v02()
    generate_protocol_v03()
    generate_protocol_v04()
    generate_protocol_v06()
    generate_protocol_v07()
    generate_protocol_v08()
    generate_protocol_v09()
    generate_protocol_v10()
    generate_protocol_v11(args.openssl)
    generate_protocol_v13()
    generate_protocol_v14()
    generate_protocol_v15()
    generate_protocol_v16()
    generate_vm_v1()
    import evidence_suite
    evidence_suite.generate(args.openssl)


if __name__ == "__main__":
    main()
