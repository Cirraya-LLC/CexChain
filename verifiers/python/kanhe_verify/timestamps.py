# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""RFC 3161 time-stamp tokens over checkpoints (spec sections 10.1 and 11,
step 8).

A token is a DER CMS SignedData whose TSTInfo's messageImprint is the
ledger's hash of a checkpoint's payload. The `openssl` command line verifies
the CMS signature (with the token's own signing certificate) and, for the
roots a verifier trusts, the whole RFC 3161 check: the chain at the token's
time, the critical id-kp-timeStamping usage, and the signing-certificate
attribute (RFC 5816). Only the DER structure is read here, to learn the
token's imprint, time, and accuracy.
"""

from __future__ import annotations

import calendar
import hashlib
import os
import subprocess
import tempfile
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import crypto
from .errors import UsageError, VerifyError

# Message imprint algorithms, by the ledger's hash (DER-encoded OIDs).
IMPRINT_OIDS = {
    crypto.SHA256: bytes.fromhex("608648016503040201"),  # 2.16.840.1.101.3.4.2.1
    crypto.SM3: bytes.fromhex("2a811ccf55018311"),  # 1.2.156.10197.1.401
}
OID_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")  # 1.2.840.113549.1.7.2
OID_TSTINFO = bytes.fromhex("2a864886f70d0109100104")  # 1.2.840.113549.1.9.16.1.4

# The clock rule's allowance for two honest clocks (section 10.1).
CLOCK_ALLOWANCE_MS = 60_000


@dataclass
class TokenInfo:
    time_ms: int
    accuracy_ms: int
    authority: str  # the signing certificate's subject (RFC 4514)
    authority_id: bytes  # SHA-256 of its SubjectPublicKeyInfo
    trusted: bool


# ---------------------------------------------------------------------------
# A small DER reader (X.690), enough for ContentInfo and TSTInfo
# ---------------------------------------------------------------------------

def _der(data: bytes, pos: int = 0):
    """Reads one TLV: returns (tag byte, value, position after it)."""
    if pos + 2 > len(data):
        raise VerifyError("a time-stamp token is truncated")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise VerifyError("a time-stamp token uses a high tag number")
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        width = length & 0x7F
        if width == 0 or width > 4 or pos + width > len(data):
            raise VerifyError("a time-stamp token has a malformed length")
        length = int.from_bytes(data[pos:pos + width], "big")
        pos += width
    if pos + length > len(data):
        raise VerifyError("a time-stamp token is truncated")
    return tag, data[pos:pos + length], pos + length


def _children(value: bytes) -> list:
    out, pos = [], 0
    while pos < len(value):
        tag, inner, pos = _der(value, pos)
        out.append((tag, inner))
    return out


def _econtent(token: bytes) -> bytes:
    """The encapsulated content of a ContentInfo holding SignedData, which
    must be a TSTInfo."""
    tag, content_info, end = _der(token)
    if tag != 0x30 or end != len(token):
        raise VerifyError("a time-stamp token is not a DER ContentInfo")
    parts = _children(content_info)
    if len(parts) != 2 or parts[0] != (0x06, OID_SIGNED_DATA) or parts[1][0] != 0xA0:
        raise VerifyError("a time-stamp token is not CMS SignedData")
    tag, signed_data, _ = _der(parts[1][1])
    fields = _children(signed_data)
    if tag != 0x30 or len(fields) < 3 or fields[2][0] != 0x30:
        raise VerifyError("a time-stamp token's SignedData is malformed")
    encap = _children(fields[2][1])
    if len(encap) != 2 or encap[0] != (0x06, OID_TSTINFO) or encap[1][0] != 0xA0:
        raise VerifyError("a time-stamp token does not hold a TSTInfo")
    tag, octets, _ = _der(encap[1][1])
    if tag != 0x04:
        raise VerifyError("a time-stamp token's TSTInfo is not an OCTET STRING")
    return octets


def _integer(value: bytes) -> int:
    return int.from_bytes(value, "big", signed=True)


def _parse_tstinfo(tstinfo: bytes):
    """Returns (imprint OID, imprint, genTime in ms, accuracy in ms)."""
    tag, body, _ = _der(tstinfo)
    if tag != 0x30:
        raise VerifyError("a TSTInfo is not a SEQUENCE")
    fields = _children(body)
    if len(fields) < 5 or fields[0][0] != 0x02 or fields[1][0] != 0x06 or fields[2][0] != 0x30:
        raise VerifyError("a TSTInfo is malformed")
    imprint = _children(fields[2][1])
    if len(imprint) != 2 or imprint[0][0] != 0x30 or imprint[1][0] != 0x04:
        raise VerifyError("a TSTInfo's message imprint is malformed")
    algorithm = _children(imprint[0][1])
    if not algorithm or algorithm[0][0] != 0x06:
        raise VerifyError("a TSTInfo's imprint algorithm is malformed")
    gen_time = fields[4]
    if gen_time[0] != 0x18:
        raise VerifyError("a TSTInfo's genTime is not a GeneralizedTime")
    accuracy_ms = 0
    if len(fields) > 5 and fields[5][0] == 0x30:
        for tag, value in _children(fields[5][1]):
            if tag == 0x02:
                accuracy_ms += _integer(value) * 1000
            elif tag == 0x80:
                accuracy_ms += _integer(value)
            elif tag == 0x81:
                accuracy_ms += -(-_integer(value) // 1000)  # micros, rounded up
    return algorithm[0][1], imprint[1][1], _generalized_time_ms(gen_time[1]), accuracy_ms


def _generalized_time_ms(value: bytes) -> int:
    text = value.decode("ascii")
    if not text.endswith("Z") or len(text) < 15:
        raise VerifyError("a TSTInfo's genTime is not in UTC")
    whole, fraction = text[:14], text[14:-1]
    if not whole.isdigit() or (fraction and not (fraction[0] == "." and fraction[1:].isdigit())):
        raise VerifyError("a TSTInfo's genTime is malformed")
    seconds = calendar.timegm((int(whole[0:4]), int(whole[4:6]), int(whole[6:8]), int(whole[8:10]),
                               int(whole[10:12]), int(whole[12:14]), 0, 0, 0))
    millis = int((fraction[1:] + "000")[:3]) if fraction else 0
    return seconds * 1000 + millis


# ---------------------------------------------------------------------------
# Trust roots and tokens
# ---------------------------------------------------------------------------

def load_roots(paths: list[str]) -> bytes:
    """Root certificates (PEM or DER) as one PEM bundle for openssl."""
    pem = b""
    for path in paths:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            raise UsageError(f"cannot read {path}") from e
        try:
            if b"-----BEGIN" in data:
                certs = x509.load_pem_x509_certificates(data)
            else:
                certs = [x509.load_der_x509_certificate(data)]
        except ValueError as e:
            raise UsageError(f"{path} is not a certificate (PEM or DER)") from e
        for cert in certs:
            pem += cert.public_bytes(serialization.Encoding.PEM)
    return pem


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run([crypto.openssl_binary()] + args, capture_output=True)


def check_token(token: bytes, imprint: bytes, hash_alg: int, roots_pem: bytes) -> TokenInfo:
    """Section 11, step 8: the token verifies with its signing certificate
    and stamps `imprint` under the ledger's hash; it is trusted if it passes
    RFC 3161 verification under one of the roots."""
    tstinfo = _econtent(token)
    oid, stamped, time_ms, accuracy_ms = _parse_tstinfo(tstinfo)
    if oid != IMPRINT_OIDS[hash_alg]:
        raise VerifyError("a time-stamp token's imprint is not under the ledger's hash")
    if stamped != imprint:
        raise VerifyError("a time-stamp token does not stamp its anchor's checkpoint")
    with tempfile.TemporaryDirectory() as tmp:
        token_path, content_path, signer_path, roots_path = (
            os.path.join(tmp, n) for n in ("token.der", "content.der", "signer.pem", "roots.pem"))
        with open(token_path, "wb") as f:
            f.write(token)
        done = _run(["cms", "-verify", "-noverify", "-binary", "-inform", "DER", "-in", token_path,
                     "-out", content_path, "-signer", signer_path])
        if done.returncode != 0 or not os.path.exists(signer_path):
            raise VerifyError("a time-stamp token does not verify with its signing certificate")
        with open(content_path, "rb") as f:
            if f.read() != tstinfo:
                raise VerifyError("a time-stamp token's signed content is not its TSTInfo")
        with open(signer_path, "rb") as f:
            signers = x509.load_pem_x509_certificates(f.read())
        if len(signers) != 1:
            raise VerifyError("a time-stamp token has more than one signer")
        signer = signers[0]
        spki = signer.public_key().public_bytes(serialization.Encoding.DER,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
        trusted = False
        if roots_pem:
            with open(roots_path, "wb") as f:
                f.write(roots_pem)
            done = _run(["ts", "-verify", "-token_in", "-in", token_path, "-digest", imprint.hex(),
                         "-CAfile", roots_path, "-attime", str(time_ms // 1000)])
            trusted = done.returncode == 0
    return TokenInfo(time_ms=time_ms, accuracy_ms=accuracy_ms, authority=signer.subject.rfc4514_string(),
                     authority_id=hashlib.sha256(spki).digest(), trusted=trusted)
