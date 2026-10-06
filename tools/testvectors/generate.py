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
# Protocol v0.1 objects (spec/cexchain-v0.1.cddl)
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
            1: person, 2: {1: [2, 16, 17, 18, 19], 2: ["cexchain.certificate/1", "cexchain.delivery/1"],
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
            1: "cexchain.certificate/1", 2: field_root, 3: len(leaves),
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
                       "spec/cexchain-v0.1.cddl. All signatures are Ed25519 (deterministic), so every "
                       "object must be reproduced byte for byte. Keys are throwaway test keys: "
                       "seed = SHA-256(\"CexChain test key: <name>\").",
        "seeds": seeds,
        "ledgers": ledgers,
    }
    (OUT / "protocol-v0.1.json").write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote protocol vectors for {len(ledgers)} ledgers to testvectors/protocol-v0.1.json")


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


if __name__ == "__main__":
    main()
