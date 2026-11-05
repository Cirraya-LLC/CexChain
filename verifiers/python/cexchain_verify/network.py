# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Open witness networks (spec section 10.2, v0.13): a SHA-256 ledger's
checkpoints as C2SP checkpoint notes, and the cosignatures that the
witnesses of open networks make of them.

- The origin: "cirraya.com/cexchain/" followed by the ledger id in 64
  lowercase hexadecimal digits, derived, never chosen.
- The checkpoint note: three lines, each ending in a newline: the origin,
  the tree size in decimal, and the root in base64 (RFC 4648 section 4, with
  padding).
- Key IDs, the first four bytes of SHA-256(name || 0x0A || type || public
  key), and verifier keys, <name>+<key ID in 8 hex digits>+<base64(type ||
  public key)> (c2sp.org/signed-note).
- Cosignatures (c2sp.org/tlog-cosignature): a 4-byte key ID, an 8-byte
  big-endian POSIX time T, and the signature: Ed25519 (type 0x04) over
  "cosignature/v1", a newline, "time T", a newline, and the note; or
  ML-DSA-44 (type 0x06, FIPS 204's pure form, empty context) over the
  CosignedSubtree from 0 to the tree size.

Nothing cryptographic is implemented here: Ed25519 and ML-DSA come from the
`cryptography` package (through crypto.py), SHA-256 from `hashlib`. This
module only builds the messages that are signed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import struct
from dataclasses import dataclass

from . import crypto
from .errors import VerifyError

ORIGIN_PREFIX = "cirraya.com/cexchain/"

# Signature types (c2sp.org/signed-note).
NOTE_ED25519 = 0x01  # a log's own signature of its note (the ledger's note key)
COSIGNATURE_ED25519 = 0x04  # cosignature/v1
COSIGNATURE_MLDSA44 = 0x06  # a CosignedSubtree, signed with ML-DSA-44
COSIGNATURE_TYPES = (COSIGNATURE_ED25519, COSIGNATURE_MLDSA44)
_ALGORITHMS = {NOTE_ED25519: crypto.ED25519, COSIGNATURE_ED25519: crypto.ED25519,
               COSIGNATURE_MLDSA44: crypto.MLDSA44}

# A cosignature's bytes: the key ID, then the time, then the signature.
KEY_ID_SIZE = 4
PREFIX_SIZE = 12


def valid_name(name) -> bool:
    """A witness's or a key's name: 1 to 255 bytes of UTF-8 (the CDDL's
    size of a note-cosignature's name; a CosignedSubtree gives the name one
    length byte), with no Unicode space and no '+' (c2sp.org/signed-note),
    and no control character below U+0020."""
    if not isinstance(name, str):
        return False
    try:
        size = len(name.encode("utf-8"))
    except UnicodeEncodeError:  # a lone surrogate, from a command line
        return False
    return 1 <= size <= 255 and not any(ord(c) < 0x20 or c.isspace() or c == "+" for c in name)


def origin(ledger_id: bytes) -> str:
    """The ledger's name in an open network (section 10.2)."""
    return ORIGIN_PREFIX + ledger_id.hex()


def checkpoint_note(note_origin: str, size: int, root: bytes) -> str:
    """The checkpoint note of a checkpoint of `size` and `root`
    (c2sp.org/tlog-checkpoint, with no extension lines)."""
    return f"{note_origin}\n{size}\n{base64.b64encode(root).decode()}\n"


def key_id(name: str, kind: int, public: bytes) -> bytes:
    return hashlib.sha256(name.encode("utf-8") + b"\n" + bytes([kind]) + public).digest()[:KEY_ID_SIZE]


def _canonical_base64(text: str) -> bytes | None:
    """Padded standard base64 (RFC 4648 section 4) in its only form: no
    other character, no missing or extra padding, no unused bits set."""
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    return data if base64.b64encode(data).decode() == text else None


@dataclass(frozen=True)
class VerifierKey:
    """A verifier key: whose it is (the name), its key ID, its signature
    type, and the public key."""
    name: str
    key_id: bytes
    kind: int
    public: crypto.PublicKey

    @property
    def text(self) -> str:
        encoded = base64.b64encode(bytes([self.kind]) + self.public.key).decode()
        return f"{self.name}+{self.key_id.hex()}+{encoded}"


def parse_verifier_key(text: str, kinds=tuple(_ALGORITHMS)) -> VerifierKey:
    """<name>+<key ID>+<base64(type || public key)>. The base64 may itself
    hold '+', and a name may not, so the text splits at its first two. The
    key ID is 8 lowercase hexadecimal digits, and must be the key's."""
    name, plus, rest = text.partition("+")
    hex_id, plus2, encoded = rest.partition("+")
    if not (plus and plus2):
        raise VerifyError("a verifier key is not <name>+<key ID>+<key>")
    if not valid_name(name):
        raise VerifyError("a verifier key's name is not a key name (1 to 255 bytes, no space, no '+')")
    if len(hex_id) != 8 or any(c not in "0123456789abcdef" for c in hex_id):
        raise VerifyError("a verifier key's key ID is not 8 lowercase hexadecimal digits")
    data = _canonical_base64(encoded)
    if not data:
        raise VerifyError("a verifier key's key is not padded base64 of a signature type and a public key")
    kind, public = data[0], data[1:]
    if kind not in kinds:
        allowed = " or ".join(f"0x{k:02x}" for k in kinds)
        raise VerifyError(f"a verifier key of signature type 0x{kind:02x}, not {allowed}")
    key = crypto.parse_public_key([_ALGORITHMS[kind], public], "a verifier key's public key")
    if key_id(name, kind, public).hex() != hex_id:
        raise VerifyError("a verifier key's key ID is not that of its name and key")
    return VerifierKey(name=name, key_id=bytes.fromhex(hex_id), kind=kind, public=key)


def parse_witness_key(text: str) -> VerifierKey:
    """A network witness's verifier key: of a cosignature's type, 0x04
    (Ed25519) or 0x06 (ML-DSA-44)."""
    return parse_verifier_key(text, COSIGNATURE_TYPES)


def cosignature_key_id(data: bytes) -> bytes:
    return data[:KEY_ID_SIZE]


def cosignature_time(data: bytes) -> int:
    """The witness's time T, in POSIX seconds."""
    return int.from_bytes(data[KEY_ID_SIZE:PREFIX_SIZE], "big")


def cosigned_message(vkey: VerifierKey, note_origin: str, size: int, root: bytes, time: int) -> bytes:
    """What a witness of `vkey` signs to cosign the checkpoint note of
    `size` and `root` at its time `time`."""
    if vkey.kind == COSIGNATURE_ED25519:
        return f"cosignature/v1\ntime {time}\n".encode() + checkpoint_note(note_origin, size, root).encode()
    if vkey.kind == COSIGNATURE_MLDSA44:
        name, log = vkey.name.encode("utf-8"), note_origin.encode("utf-8")
        return (b"subtree/v1\n\0" + bytes([len(name)]) + name + struct.pack(">Q", time)
                + bytes([len(log)]) + log + struct.pack(">QQ", 0, size) + root)
    raise VerifyError(f"signature type 0x{vkey.kind:02x} makes no cosignature")


def verify_cosignature(vkey: VerifierKey, note_origin: str, size: int, root: bytes, data: bytes) -> bool:
    """True if `data` (key ID, time, signature) is the cosignature of the
    witness of `vkey` of the checkpoint note of `size` and `root`."""
    if len(data) < PREFIX_SIZE or cosignature_key_id(data) != vkey.key_id:
        return False
    message = cosigned_message(vkey, note_origin, size, root, cosignature_time(data))
    return crypto.verify_signature(vkey.public, message, data[PREFIX_SIZE:])


def verify_note_signature(vkey: VerifierKey, note: str, data: bytes) -> bool:
    """A note signature of type 0x01 (a log's): the key ID, then an Ed25519
    signature of the note's text. Verifiers of evidence never need it (the
    note key is no part of evidence); the test vectors carry one."""
    if vkey.kind != NOTE_ED25519 or len(data) < KEY_ID_SIZE or data[:KEY_ID_SIZE] != vkey.key_id:
        return False
    return crypto.verify_signature(vkey.public, note.encode("utf-8"), data[KEY_ID_SIZE:])


__all__ = ["COSIGNATURE_TYPES", "VerifierKey", "checkpoint_note", "cosignature_time", "key_id", "origin",
           "parse_verifier_key", "parse_witness_key", "valid_name", "verify_cosignature", "verify_note_signature"]
