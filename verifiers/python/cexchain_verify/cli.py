# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""The command line: python3 -m cexchain_verify BUNDLE [options].

Exit codes, as `cexchain verify` uses them: 0 verified, 1 usage error, 2 an
input file could not be read, 3 not verified.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import cbor, crypto, report, timestamps
from .errors import UsageError, VerifyError
from .evidence import verify_bundle

EXIT_VERIFIED, EXIT_USAGE, EXIT_INPUT, EXIT_NOT_VERIFIED = 0, 1, 2, 3


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"usage error: {message}", file=sys.stderr)
        sys.exit(EXIT_USAGE)


def _parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="python3 -m cexchain_verify",
        description="Verify a CexChain evidence bundle about a record, offline, independently of the "
                    "reference implementation (spec section 11). Contract evidence is not supported yet.",
        epilog="Exit codes: 0 verified, 1 usage error, 2 an input file could not be read, 3 not verified.")
    p.add_argument("bundle", metavar="BUNDLE", help="the evidence bundle (CBOR)")
    p.add_argument("--ledger-id", metavar="HEX", help="the issuer's ledger id (64 hex digits), learned out of band")
    p.add_argument("--witness", metavar="PUBKEY_FILE", action="append", default=[],
                   help="trust this witness's public key file (CBOR [alg, key]) [repeatable]")
    p.add_argument("--min-witnesses", metavar="N", type=int, default=0,
                   help="fail unless at least N trusted witnesses cosigned")
    p.add_argument("--tsa-root", metavar="CERT_FILE", action="append", default=[],
                   help="trust time-stamp authorities under this root certificate (PEM or DER) [repeatable]")
    p.add_argument("--min-timestamps", metavar="N", type=int, default=0,
                   help="fail unless at least N trusted time-stamp authorities stamped it")
    p.add_argument("--attachment", metavar="NAME=FILE", action="append", default=[],
                   help="check an attachment's content [repeatable]")
    p.add_argument("--json", action="store_true", help="print machine-readable JSON")
    return p


def _read(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise UsageError(f"cannot read {path}") from e


def _witness_key(path: str) -> crypto.PublicKey:
    data = _read(path)
    try:
        return crypto.parse_public_key(cbor.decode(data), f"the witness key in {path}")
    except VerifyError as e:
        raise UsageError(f"{path} is not a public key file: {e}") from e


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    ledger_id = None
    if args.ledger_id is not None:
        try:
            ledger_id = bytes.fromhex(args.ledger_id)
        except ValueError:
            ledger_id = b""
        if len(ledger_id) != 32:
            print("usage error: --ledger-id takes a full ledger id, 64 hex digits", file=sys.stderr)
            return EXIT_USAGE
    contents = {}
    for item in args.attachment:
        name, sep, path = item.partition("=")
        if not sep or not name or not path:
            print("usage error: --attachment takes NAME=FILE", file=sys.stderr)
            return EXIT_USAGE
        contents[name] = path
    try:
        data = _read(args.bundle)
        witnesses = [_witness_key(path) for path in args.witness]
        roots = timestamps.load_roots(args.tsa_root)
        files = {name: _read(path) for name, path in contents.items()}
    except UsageError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_INPUT

    try:
        result = verify_bundle(data, ledger_id=ledger_id, witnesses=witnesses, tsa_roots_pem=roots,
                               attachments=files)
    except VerifyError as e:
        if args.json:
            print(json.dumps({"verified": False, "error": str(e)}, indent=2, ensure_ascii=False))
        else:
            print(f"VERIFICATION FAILED: {e}")
        return EXIT_NOT_VERIFIED

    # The bundle verifies; what the verifier was asked to require beside it
    # may still fail it, with the full report shown.
    document = report.to_json(result)
    failure = None
    if any(status == "mismatch" for _, _, _, status in result.attachments):
        failure = "an attachment does not match its commitment"
        document["error"] = failure
    elif result.witnesses_trusted < args.min_witnesses:
        failure = f"{result.witnesses_trusted} trusted witness cosignatures, {args.min_witnesses} required"
        document["error"] = failure
    elif result.trusted_authorities < args.min_timestamps:
        failure = (f"{result.trusted_authorities} trusted time-stamp authorities, "
                   f"{args.min_timestamps} required")
        document["error"] = failure
    if failure is not None:
        document["verified"] = False
    if args.json:
        print(json.dumps(document, indent=2, ensure_ascii=False))
    else:
        print(report.to_text(result))
        if failure is not None:
            print(f"\nVERIFICATION FAILED: {failure}")
    return EXIT_NOT_VERIFIED if failure is not None else EXIT_VERIFIED
