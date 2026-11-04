# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Damages evidence bundles for tests: both verifiers must refuse what the
damage breaks, and agree on what it does not.

Usage: python3 mutate.py IN OUT OPERATION [ARGUMENT]

Operations (indices are positions in the bundle's lists, from 0):
  flip OFFSET              flip the lowest bit of the byte at OFFSET
  drop-entry N             leave out the bundle's N-th entry (with its receipt)
  drop-last-entry          leave out the last entry (the state commitment, usually)
  swap-receipts N          exchange the receipts of the N-th and (N+1)-th entries
  drop-proof N             leave out the N-th state proof
  drop-proofs              leave out every state proof
  drop-cosignatures        leave out every cosignature
  break-cosignature N      flip a bit of the N-th cosignature's signature
  duplicate-cosignature N  list the N-th cosignature twice
  drop-disclosures         leave out the field disclosures
  duplicate-disclosure N   list the N-th disclosure twice
  drop-anchors             leave out the anchors
  add-anchor TOKEN_FILE    anchor the bundle's own checkpoint with this time-stamp token
  add-cosignatures-of B    add the cosignatures another bundle B carries (of its checkpoint)
  subject HEX              name another record as the bundle's subject

python3 mutate.py IN --imprint prints the imprint a time-stamp token over the
bundle's checkpoint must carry (the ledger's hash of its payload), and the
hash's name for `openssl ts -query`.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from cexchain_verify import cbor, crypto  # noqa: E402


def _flip_signature(cose_bytes: bytes) -> bytes:
    message = cbor.decode(cose_bytes)
    body = list(message.value)
    signature = bytearray(body[3])
    signature[0] ^= 0x01
    body[3] = bytes(signature)
    return cbor.encode(cbor.Tag(message.tag, body))


def mutate(data: bytes, operation: str, argument: str | None) -> bytes:
    if operation == "flip":
        out = bytearray(data)
        out[int(argument)] ^= 0x01
        return bytes(out)
    bundle = cbor.decode(data)
    n = int(argument) if argument is not None and argument.isdigit() else None
    if operation == "drop-entry":
        del bundle[2][n]
    elif operation == "drop-last-entry":
        del bundle[2][-1]
    elif operation == "swap-receipts":
        bundle[2][n][1], bundle[2][n + 1][1] = bundle[2][n + 1][1], bundle[2][n][1]
    elif operation == "drop-proof":
        del bundle[7][n]
        if not bundle[7]:
            del bundle[7]
    elif operation == "drop-proofs":
        bundle.pop(7, None)
    elif operation == "drop-cosignatures":
        bundle.pop(4, None)
    elif operation == "break-cosignature":
        bundle[4][n] = _flip_signature(bundle[4][n])
    elif operation == "duplicate-cosignature":
        bundle[4].append(bundle[4][n])
    elif operation == "drop-disclosures":
        bundle.pop(5, None)
    elif operation == "duplicate-disclosure":
        bundle[5].append(bundle[5][n])
    elif operation == "drop-anchors":
        bundle.pop(8, None)
    elif operation == "add-anchor":
        token = pathlib.Path(argument).read_bytes()
        bundle.setdefault(8, []).append({1: bundle[3], 2: [token]})
    elif operation == "add-cosignatures-of":
        other = cbor.decode(pathlib.Path(argument).read_bytes())
        bundle.setdefault(4, []).extend(other.get(4, []))
    elif operation == "subject":
        bundle[1] = bytes.fromhex(argument)
    else:
        raise SystemExit(f"unknown operation {operation}")
    return cbor.encode(bundle)


def imprint(data: bytes) -> str:
    bundle = cbor.decode(data)
    genesis = cbor.decode(cbor.decode(cbor.decode(bundle[2][0][0])[3]).value[2])
    hash_alg = genesis[7][1]
    payload = cbor.decode(bundle[3]).value[2]
    return f"{crypto.hash_function(hash_alg)(payload).hex()} {'sha256' if hash_alg == crypto.SHA256 else 'sm3'}"


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[2] == "--imprint":
        print(imprint(pathlib.Path(argv[1]).read_bytes()))
        return 0
    if len(argv) not in (4, 5):
        print(__doc__, file=sys.stderr)
        return 1
    data = pathlib.Path(argv[1]).read_bytes()
    pathlib.Path(argv[2]).write_bytes(mutate(data, argv[3], argv[4] if len(argv) == 5 else None))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
