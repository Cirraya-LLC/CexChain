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
                       "spec/cexchain.cddl. All signatures are Ed25519 (deterministic), so every "
                       "object must be reproduced byte for byte. Keys are throwaway test keys: "
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
            1: "cexchain.certificate/1", 2: lg.h(b"fields"), 3: 1}})

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
                       "proofs, and the log entry that carries it), and a cosign request. All signatures are "
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
                         1: "cexchain.certificate/1", 2: lg.h(b"fields"), 3: 1}})
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
                       "carrying both rotations with inclusion paths (key 4). All signatures are Ed25519 "
                       "(deterministic). Keys are throwaway test keys: seed = SHA-256(\"CexChain test key: "
                       "<name>\").",
        "seeds": seeds,
        "ledgers": ledgers,
    }
    (OUT / "protocol-v0.4.json").write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote protocol vectors for {len(ledgers)} ledgers to testvectors/protocol-v0.4.json")


# ---------------------------------------------------------------------------
# Protocol v0.5 additions: ownership assets (spec/cexchain.cddl, revision
# v0.5): asset-action statements, asset metadata, consents, asset evidence
# ---------------------------------------------------------------------------

RECEIVABLE = "cexchain.receivable/1"
WAREHOUSE_RECEIPT = "cexchain.warehouse-receipt/1"


def generate_protocol_v05() -> None:
    names = ("org_root", "log", "registrar")
    seeds = {name: hashlib.sha256(f"CexChain test key: {name}".encode()).hexdigest() for name in names}
    keys = {name: ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)) for name, seed in seeds.items()}
    t0 = 1_791_244_800_000
    day = 86_400_000
    # The parties' ledgers. Their consent records and bundles are opaque here:
    # bundles have their own vectors, and only their hashes enter the home's log.
    parties = {name: hashlib.sha256(f"{name} ledger".encode()).digest() for name in ("supplier", "bank", "buyer")}

    ledgers = []
    for hash_id in (-16, -65538):
        lg = Ledger(hash_id)
        statements, refused, consents = [], [], []
        counter = [0]

        def payload(signer_actor, body_type, body, delegation=None):
            counter[0] += 1
            out = {0: 1, 1: body_type, 2: ledger_id, 3: signer_actor, 5: t0 + counter[0],
                   6: bytes([counter[0]]) * 16, 7: body}
            if delegation is not None:
                out[4] = delegation
            return out

        def add(name, signer, p):
            encoded, statement_id = lg.statement(keys[signer], p)
            statements.append({"name": name, "signer": signer, "encoded": encoded.hex(),
                               "payload": dcbor(p).hex(), "statement_id": statement_id.hex()})
            return statement_id

        def refuse(name, signer, p):
            encoded, _ = lg.statement(keys[signer], p)
            refused.append({"name": name, "signer": signer, "encoded": encoded.hex(),
                            "payload": dcbor(p).hex(), "after": len(statements)})

        def consent(party, asset, action, head, to=None, quantity=None, reference=None):
            metadata = {"ledger": ledger_id, "asset": asset, "action": action, "head": head,
                        "until": t0 + 7 * day}
            if to is not None:
                metadata["to"] = to
            if quantity is not None:
                metadata["quantity"] = quantity
            if reference is not None:
                metadata["reference"] = reference
            tag = f"{party} consents to {action} of {asset.hex()[:16]} at {head}".encode()
            record = hashlib.sha256(b"consent record: " + tag).digest()
            bundle = b"consent evidence bundle: " + tag
            consents.append({"party": party, "ledger": parties[party].hex(), "record": record.hex(),
                             "metadata": dcbor(metadata).hex(), "bundle": bundle.hex(),
                             "bundle_hash": lg.h(bundle).hex()})
            return [parties[party], record, lg.h(bundle)]

        def action(asset, name, head, to=None, quantity=None, refs=None, reference=None):
            body = {1: asset, 2: name, 3: head}
            if to is not None:
                body[4] = to
            if quantity is not None:
                body[5] = quantity
            if refs:
                body[6] = sorted(refs, key=lambda r: r[0])
            if reference is not None:
                body[7] = reference
            return body

        genesis = {0: 1, 1: 1, 5: t0, 6: bytes([0xE0]) * 16, 7: {
            1: hash_id, 2: "Cirraya Asset Home", 3: ed_public(keys["org_root"]), 4: ed_public(keys["log"])}}
        encoded, ledger_id = lg.statement(keys["org_root"], genesis)
        statements.append({"name": "genesis", "signer": "org_root", "encoded": encoded.hex(),
                           "payload": dcbor(genesis).hex(), "statement_id": ledger_id.hex()})
        org = ledger_id
        supplier, bank, buyer = parties["supplier"], parties["bank"], parties["buyer"]

        registrar = add("register the registrar", "org_root", payload(org, 2, {
            1: 3, 2: "Asset Registrar", 3: ed_public(keys["registrar"])}))
        delegation = add("delegate asset actions to the registrar", "org_root", payload(org, 5, {
            1: registrar, 2: {1: [20], 2: [RECEIVABLE, WAREHOUSE_RECEIPT]}}))

        def by_registrar(name, body):
            return add(name, "registrar", payload(registrar, 20, body, delegation))

        def refused_by_registrar(name, body):
            refuse(name, "registrar", payload(registrar, 20, body, delegation))

        def by_org(name, body):
            return add(name, "org_root", payload(org, 20, body))

        receivable_meta = {"holder": supplier, "amount": 12_500_000, "currency": "CNY", "due": t0 + 90 * day,
                           "title": "Receivable for PO-2026-0815"}
        refuse("a receivable held by its home", "org_root", payload(org, 16, {
            1: RECEIVABLE, 2: lg.h(b"fields"), 3: 1, 5: {**receivable_meta, "holder": ledger_id}}))
        refuse("a receivable in a lower-case currency", "org_root", payload(org, 16, {
            1: RECEIVABLE, 2: lg.h(b"fields"), 3: 1, 5: {**receivable_meta, "currency": "cny"}}))
        refuse("a receivable without an amount", "org_root", payload(org, 16, {
            1: RECEIVABLE, 2: lg.h(b"fields"), 3: 1,
            5: {k: v for k, v in receivable_meta.items() if k != "amount"}}))
        refuse("a warehouse receipt of nothing", "org_root", payload(org, 16, {
            1: WAREHOUSE_RECEIPT, 2: lg.h(b"fields"), 3: 1, 5: {"holder": supplier, "quantity": 0, "unit": "t"}}))
        receivable = add("register a receivable", "org_root", payload(org, 16, {
            1: RECEIVABLE, 2: lg.h(b"receivable fields"), 3: 4, 5: receivable_meta}))
        r_reg = len(statements) - 1
        receipt = add("register a warehouse receipt", "org_root", payload(org, 16, {
            1: WAREHOUSE_RECEIPT, 2: lg.h(b"receipt fields"), 3: 3,
            5: {"holder": supplier, "quantity": 100, "unit": "t", "goods": "Copper cathode, grade A"}}))
        w_reg = len(statements) - 1
        add("endorse the receipt as inspector (not a change of its head)", "org_root",
            payload(org, 17, {1: receipt, 2: "inspector"}))

        # The receivable is pledged to the bank: the supplier and the bank consent.
        by_registrar("pledge the receivable to the bank", action(receivable, "pledge", r_reg, to=bank, refs=[
            consent("supplier", receivable, "pledge", r_reg, to=bank),
            consent("bank", receivable, "pledge", r_reg, to=bank, reference="Loan contract SCF-2026-0042")]))
        r_head = len(statements) - 1
        refused_by_registrar("pledge the pledged receivable again", action(receivable, "pledge", r_head, to=buyer,
                             refs=[consent("supplier", receivable, "pledge", r_head, to=buyer),
                                   consent("buyer", receivable, "pledge", r_head, to=buyer)]))
        refused_by_registrar("pledge it with the head before the pledge", action(receivable, "pledge", r_reg, to=buyer,
                             refs=[consent("supplier", receivable, "pledge", r_reg, to=buyer),
                                   consent("buyer", receivable, "pledge", r_reg, to=buyer)]))
        refuse("revoke an asset", "org_root", payload(org, 19, {1: receivable, 2: "issued in error"}))
        refuse("transition an asset as a record", "org_root", payload(org, 18, {
            1: receivable, 2: "pledged", 3: "active"}))

        # The receipt: pledged, then 40 t redeemed under the pledge.
        by_registrar("pledge the receipt to the bank", action(receipt, "pledge", w_reg, to=bank, refs=[
            consent("supplier", receipt, "pledge", w_reg, to=bank),
            consent("bank", receipt, "pledge", w_reg, to=bank)]))
        w_head = len(statements) - 1
        refused_by_registrar("redeem more than remains", action(receipt, "redeem", w_head, quantity=101, refs=[
            consent("supplier", receipt, "redeem", w_head, quantity=101),
            consent("bank", receipt, "redeem", w_head, quantity=101)]))
        refused_by_registrar("redeem a pledged receipt without the pledgee", action(
            receipt, "redeem", w_head, quantity=40, refs=[consent("supplier", receipt, "redeem", w_head, quantity=40)]))
        refuse("pay a warehouse receipt", "org_root", payload(org, 20, action(receipt, "pay", w_head)))
        by_org("redeem 40 t under the pledge", action(receipt, "redeem", w_head, quantity=40, refs=[
            consent("supplier", receipt, "redeem", w_head, quantity=40),
            consent("bank", receipt, "redeem", w_head, quantity=40)]))
        w_head = len(statements) - 1

        # The receivable is frozen under a court order, then unfrozen.
        by_org("freeze the receivable", action(receivable, "freeze", r_head,
                                               reference="Court order (2026) 0101 Zhi Bao 1234"))
        r_head = len(statements) - 1
        refused_by_registrar("release a frozen receivable", action(receivable, "release", r_head, refs=[
            consent("bank", receivable, "release", r_head)]))
        refuse("freeze it twice", "org_root", payload(org, 20, action(receivable, "freeze", r_head)))
        by_org("unfreeze the receivable", action(receivable, "unfreeze", r_head))
        r_head = len(statements) - 1
        refused_by_registrar("release consented by the holder, not the pledgee", action(
            receivable, "release", r_head, refs=[consent("supplier", receivable, "release", r_head)]))
        by_registrar("release the receivable", action(receivable, "release", r_head, refs=[
            consent("bank", receivable, "release", r_head)]))
        r_head = len(statements) - 1

        # Transferred to the buyer, paid, disputed, paid again, confirmed.
        refused_by_registrar("transfer without the new holder's consent", action(
            receivable, "transfer", r_head, to=buyer, refs=[consent("supplier", receivable, "transfer", r_head, to=buyer)]))
        refused_by_registrar("transfer to the home ledger", action(receivable, "transfer", r_head, to=ledger_id, refs=[
            consent("supplier", receivable, "transfer", r_head, to=ledger_id)]))
        refused_by_registrar("transfer to the holder", action(receivable, "transfer", r_head, to=supplier, refs=[
            consent("supplier", receivable, "transfer", r_head, to=supplier)]))
        by_registrar("transfer the receivable to the buyer", action(receivable, "transfer", r_head, to=buyer, refs=[
            consent("supplier", receivable, "transfer", r_head, to=buyer),
            consent("buyer", receivable, "transfer", r_head, to=buyer)]))
        r_head = len(statements) - 1
        refuse("pay with a consent", "org_root", payload(org, 20, action(receivable, "pay", r_head, refs=[
            consent("buyer", receivable, "pay", r_head)])))
        by_org("pay the receivable", action(receivable, "pay", r_head, reference="CNAPS 2026101500001"))
        r_head = len(statements) - 1
        by_registrar("the payee disputes the payment", action(receivable, "dispute", r_head, refs=[
            consent("buyer", receivable, "dispute", r_head, reference="Nothing received")]))
        r_head = len(statements) - 1
        by_org("pay again", action(receivable, "pay", r_head, reference="CNAPS 2026101600007"))
        r_head = len(statements) - 1
        by_registrar("the payee confirms", action(receivable, "confirm", r_head, refs=[
            consent("buyer", receivable, "confirm", r_head)]))
        r_head = len(statements) - 1
        refused_by_registrar("pledge a settled receivable", action(receivable, "pledge", r_head, to=bank, refs=[
            consent("buyer", receivable, "pledge", r_head, to=bank),
            consent("bank", receivable, "pledge", r_head, to=bank)]))

        # The receipt: released, the rest redeemed.
        by_registrar("release the receipt", action(receipt, "release", w_head, refs=[
            consent("bank", receipt, "release", w_head)]))
        w_head = len(statements) - 1
        by_org("redeem the remaining 60 t", action(receipt, "redeem", w_head, quantity=60, refs=[
            consent("supplier", receipt, "redeem", w_head, quantity=60)]))
        w_head = len(statements) - 1

        # A second receivable: pledged, the pledge enforced, then cancelled by
        # its new holder.
        second = add("register a second receivable", "org_root", payload(org, 16, {
            1: RECEIVABLE, 2: lg.h(b"second receivable fields"), 3: 2,
            5: {"holder": supplier, "amount": 880_000, "currency": "CNY", "due": t0 + 60 * day}}))
        s_head = len(statements) - 1
        by_registrar("pledge the second receivable", action(second, "pledge", s_head, to=bank, refs=[
            consent("supplier", second, "pledge", s_head, to=bank),
            consent("bank", second, "pledge", s_head, to=bank)]))
        s_head = len(statements) - 1
        by_org("the bank enforces its pledge", action(second, "enforce", s_head, refs=[
            consent("bank", second, "enforce", s_head, reference="Default notice 2026-11-30")]))
        s_head = len(statements) - 1
        by_registrar("its new holder cancels it", action(second, "cancel", s_head, refs=[
            consent("bank", second, "cancel", s_head)]))
        s_head = len(statements) - 1

        def pins(asset):
            out = []
            for st in statements:
                body = cbor2.loads(bytes.fromhex(st["payload"]))[7]
                if cbor2.loads(bytes.fromhex(st["payload"]))[1] == 20 and body[1] == asset:
                    out += [ref[2] for ref in body.get(6, [])]
            return out

        bundle_by_hash = {bytes.fromhex(c["bundle_hash"]): bytes.fromhex(c["bundle"]) for c in consents}
        asset_bundle = b"the receivable's evidence bundle"
        evidence = dcbor({0: 1, 1: asset_bundle, 2: [bundle_by_hash[h] for h in pins(receivable)]})

        ledgers.append({
            "hash": hash_id,
            "ledger_id": ledger_id.hex(),
            "parties": {name: value.hex() for name, value in parties.items()},
            "statements": statements,
            "refused": refused,
            "consents": consents,
            "assets": [
                {"name": "receivable", "id": receivable.hex(), "type": RECEIVABLE, "state": "settled",
                 "holder": buyer.hex(), "pledgee": None, "payee": buyer.hex(), "quantity": 12_500_000,
                 "head": r_head},
                {"name": "warehouse receipt", "id": receipt.hex(), "type": WAREHOUSE_RECEIPT, "state": "redeemed",
                 "holder": supplier.hex(), "pledgee": None, "payee": None, "quantity": 0, "head": w_head},
                {"name": "second receivable", "id": second.hex(), "type": RECEIVABLE, "state": "cancelled",
                 "holder": bank.hex(), "pledgee": None, "payee": None, "quantity": 880_000, "head": s_head},
            ],
            "asset_evidence": {"encoded": evidence.hex(), "asset_bundle": asset_bundle.hex(),
                               "pins": [h.hex() for h in pins(receivable)]},
        })

    document = {
        "description": "CexChain protocol objects added in specification revision v0.5 (ownership assets), "
                       "built by an independent Python encoder from spec/cexchain.cddl: a home ledger whose "
                       "registrar (a device with a delegation for statement type 20) and organization take a "
                       "receivable and a warehouse receipt through every asset action, citing consents from "
                       "three other ledgers; statements the ledger rules must refuse, each to be validated "
                       "against the state after the first `after` statements, registered at "
                       "t0 + 1000 + index; the consents' metadata; the expected final state of each asset; "
                       "and asset evidence. Consent records and evidence bundles of other ledgers are opaque "
                       "bytes here (bundles have their own vectors): a consent reference pins HASH(bundle) "
                       "under the home's hash. All signatures are Ed25519 (deterministic). Keys are throwaway "
                       "test keys: seed = SHA-256(\"CexChain test key: <name>\").",
        "seeds": seeds,
        "ledgers": ledgers,
    }
    (OUT / "protocol-v0.5.json").write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote protocol vectors for {len(ledgers)} ledgers to testvectors/protocol-v0.5.json")


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
    generate_protocol_v05()


if __name__ == "__main__":
    main()
