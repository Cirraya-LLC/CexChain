# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""The command line, mirroring the reference implementation's two commands:

    python3 -m cexchain_verify BUNDLE [options]             as `cexchain verify`
    python3 -m cexchain_verify contract FILE [options]      as `cexchain contract verify`

Exit codes, as those commands use them: 0 verified, 1 usage error, 2 an
input file could not be read (or an output file written), 3 not verified.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import cbor, contract_report, crypto, report, timestamps
from .contract_evidence import verify_contract_evidence
from .errors import UsageError, VerifyError
from .evidence import verify_bundle

EXIT_VERIFIED, EXIT_USAGE, EXIT_INPUT, EXIT_NOT_VERIFIED = 0, 1, 2, 3
EPILOG = "Exit codes: 0 verified, 1 usage error, 2 an input file could not be read, 3 not verified."


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"usage error: {message}", file=sys.stderr)
        sys.exit(EXIT_USAGE)


def _common(p: argparse.ArgumentParser, issuer: str):
    p.add_argument("--ledger-id", metavar="HEX", help=f"the {issuer}'s ledger id (64 hex digits), learned out of band")
    p.add_argument("--witness", metavar="PUBKEY_FILE", action="append", default=[],
                   help="trust this witness's public key file (CBOR [alg, key]) [repeatable]")
    p.add_argument("--min-witnesses", metavar="N", type=int, default=0,
                   help="fail unless at least N trusted witnesses cosigned")
    p.add_argument("--tsa-root", metavar="CERT_FILE", action="append", default=[],
                   help="trust time-stamp authorities under this root certificate (PEM or DER) [repeatable]")
    p.add_argument("--min-timestamps", metavar="N", type=int, default=0,
                   help="fail unless at least N trusted time-stamp authorities stamped it")


def _bundle_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="python3 -m cexchain_verify",
        description="Verify a CexChain evidence bundle about a record or an instance, offline, independently of "
                    "the reference implementation (spec section 11). For an instance's contract evidence, with "
                    "its consents and every call's outcome, use: python3 -m cexchain_verify contract FILE.",
        epilog=EPILOG)
    p.add_argument("bundle", metavar="BUNDLE", help="the evidence bundle (CBOR)")
    _common(p, "issuer")
    p.add_argument("--attachment", metavar="NAME=FILE", action="append", default=[],
                   help="check an attachment's content [repeatable]")
    p.add_argument("--json", action="store_true", help="print machine-readable JSON")
    return p


def _contract_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="python3 -m cexchain_verify contract",
        description="Verify an instance's contract evidence offline (spec section 15): replay its calls, running "
                    "the contract again on each, check every consent a call cites on the consenting party's own "
                    "ledger, and derive the requests the calls made with their answers. A Bo contract's source "
                    "is not rebuilt here: the code is checked as run (--deploy-out writes the deploy, for bo "
                    "rebuild).",
        epilog=EPILOG)
    p.add_argument("evidence", metavar="FILE", help="the contract evidence (CBOR)")
    _common(p, "home")
    p.add_argument("--require-presence", action="store_true",
                   help="fail unless a person proved presence for each consent")
    p.add_argument("--require-answered", action="store_true",
                   help="fail if a request is still open past its deadline at the checkpoint's time")
    p.add_argument("--deploy-out", metavar="FILE", help="write the deploy the evidence carries here, as a deploy file")
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


def _ledger_id(text: str | None) -> bytes | None:
    if text is None:
        return None
    try:
        value = bytes.fromhex(text)
    except ValueError:
        value = b""
    if len(value) != 32:
        raise UsageError("--ledger-id takes a full ledger id, 64 hex digits")
    return value


def _not_verified(args, error: VerifyError) -> int:
    if args.json:
        print(json.dumps({"verified": False, "error": str(error)}, indent=2, ensure_ascii=False))
    else:
        print(f"VERIFICATION FAILED: {error}")
    return EXIT_NOT_VERIFIED


def _finish(args, document: dict, text: str, failure: str | None) -> int:
    """Prints the full report, failed by what the verifier was asked to
    require beside the evidence, if anything."""
    if failure is not None:
        document["verified"] = False
        document["error"] = failure
    if args.json:
        print(json.dumps(document, indent=2, ensure_ascii=False))
    else:
        print(text)
        if failure is not None:
            print(f"\nVERIFICATION FAILED: {failure}")
    return EXIT_NOT_VERIFIED if failure is not None else EXIT_VERIFIED


def _required(result, args) -> str | None:
    """--min-witnesses and --min-timestamps, on a bundle's report."""
    if result.witnesses_trusted < args.min_witnesses:
        return f"{result.witnesses_trusted} trusted witness cosignatures, {args.min_witnesses} required"
    if result.trusted_authorities < args.min_timestamps:
        return f"{result.trusted_authorities} trusted time-stamp authorities, {args.min_timestamps} required"
    return None


def _bundle_main(argv: list[str]) -> int:
    args = _bundle_parser().parse_args(argv)
    contents = {}
    for item in args.attachment:
        name, sep, path = item.partition("=")
        if not sep or not name or not path:
            print("usage error: --attachment takes NAME=FILE", file=sys.stderr)
            return EXIT_USAGE
        contents[name] = path
    try:
        ledger_id = _ledger_id(args.ledger_id)
    except UsageError as e:
        print(f"usage error: {e}", file=sys.stderr)
        return EXIT_USAGE
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
        return _not_verified(args, e)
    failure = _required(result, args)
    if any(status == "mismatch" for _, _, _, status in result.attachments):
        failure = "an attachment does not match its commitment"
    return _finish(args, report.to_json(result), report.to_text(result), failure)


def _contract_main(argv: list[str]) -> int:
    args = _contract_parser().parse_args(argv)
    try:
        ledger_id = _ledger_id(args.ledger_id)
    except UsageError as e:
        print(f"usage error: {e}", file=sys.stderr)
        return EXIT_USAGE
    try:
        data = _read(args.evidence)
        witnesses = [_witness_key(path) for path in args.witness]
        roots = timestamps.load_roots(args.tsa_root)
    except UsageError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_INPUT
    try:
        result = verify_contract_evidence(data, ledger_id=ledger_id, witnesses=witnesses, tsa_roots_pem=roots)
    except VerifyError as e:
        return _not_verified(args, e)
    if args.deploy_out is not None:
        try:
            with open(args.deploy_out, "wb") as f:
                f.write(result.deploy_file())
        except OSError:
            print(f"error: cannot write {args.deploy_out}", file=sys.stderr)
            return EXIT_INPUT
    failure = _required(result.bundle, args)
    if failure is None and args.require_presence:
        for consents in result.consents.values():
            missing = [c for c in consents if c.registration.presence is None]
            if missing:
                failure = (f"a consent of {missing[0].report.ledger.name} was given without proof of a "
                           "person's presence")
                break
    if failure is None and args.require_answered:
        overdue = [q for q in result.open_requests() if result.overdue(q)]
        if overdue:
            failure = (f"{len(overdue)} request(s) still open past their deadline at the checkpoint: "
                       + ", ".join(f"{q.id.hex()[:12]} ({q.kind})" for q in overdue))
    return _finish(args, contract_report.to_json(result), contract_report.to_text(result), failure)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "contract":
        return _contract_main(argv[1:])
    return _bundle_main(argv)
