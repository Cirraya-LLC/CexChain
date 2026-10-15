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
            carries HASH(salt || response) under the home's hash (P8)."""
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
# The mechanism types: initial state and transitions. None defines a role.
MECHANISM_TYPES = {
    "cexchain.access-request/1": ("requested", {("requested", "withdrawn")}),
    "cexchain.access-grant/1": ("granted", set()),
    "cexchain.access-receipt/1": ("received", set()),
    CONTRACT_CONSENT: ("given", {("given", "withdrawn")}),
}
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
                if kind.startswith(RESERVED_PREFIX) and kind not in MECHANISM_TYPES:
                    fails.append("reserved type")
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
                initial = MECHANISM_TYPES[body[1]][0] if body[1] in MECHANISM_TYPES else "registered"
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
                            for kind, (initial, transitions) in MECHANISM_TYPES.items()],
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
    generate_vm_v1()


if __name__ == "__main__":
    main()
