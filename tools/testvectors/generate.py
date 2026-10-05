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


def raw_rs(der: bytes) -> bytes:
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


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
    return vectors


def esp256_vectors() -> list[dict]:
    key = ec.derive_private_key(0x0C3A_7D1E_55AA_1234_9876_FEDC_BA98_7654_3210_0123_4567_89AB_CDEF_0F1E_2D3C_4B5A, ec.SECP256R1())
    public = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    vectors = []
    for message in MESSAGES:
        signature = raw_rs(key.sign(message, ec.ECDSA(hashes.SHA256())))
        vectors += signature_vector("ESP256", public, message, signature, "Python cryptography")
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
            vectors += signature_vector("SM2-SM3", public, message, raw_rs(der), "OpenSSL command-line tool")
    return vectors


def generate_signatures(openssl: str) -> None:
    vectors = ed25519_vectors() + esp256_vectors() + sm2_vectors(openssl) + mldsa_vectors()
    write(
        "signatures.json",
        "Signatures in CexChain wire encoding (ECDSA and SM2 as r||s). Each valid vector is "
        "followed by variants with a modified message and a modified signature.",
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
    add("ESP256", p256_public, lambda m: raw_rs(p256.sign(m, ec.ECDSA(hashes.SHA256()))), b"p256-key", b"CexChain statement")

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
            return raw_rs(der)

        add("SM2-SM3", spki[-65:], sm2_sign, b"sm2-key", b"CexChain statement")

    write("cose-sign1.json",
          "Tagged COSE_Sign1 messages built with cbor2 and independent signers. Protected header "
          "is {1: alg, 4: kid}; unprotected header is empty. Ed25519 messages are deterministic "
          "and must be reproduced byte for byte.",
          vectors)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--openssl", default="openssl", help="OpenSSL 3.5+ command-line tool")
    args = parser.parse_args()
    generate_hashes()
    generate_signatures(args.openssl)
    generate_merkle("SHA-256", "sha256", "merkle-sha256.json")
    generate_merkle("SM3", "sm3", "merkle-sm3.json")
    generate_cose(args.openssl)


if __name__ == "__main__":
    main()
