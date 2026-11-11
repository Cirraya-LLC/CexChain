# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""An independent verifier of Kanhe evidence, written from the protocol
specification (spec/README.md and spec/kanhe.cddl) only.

It verifies evidence bundles (spec section 11), a record's or an instance's:
deterministic CBOR, COSE_Sign1, the log and its receipts, checkpoints and the
log key in effect, a replay of the ledger rules (contracts included: every
call's contract runs again, section 14), proof of presence, disclosures and
attachments, state proofs (completeness), witness cosignatures, RFC 3161
time-stamp tokens, open witness networks' cosignatures of checkpoint
notes (section 10.2), and membership proofs from trust nodes (v0.16, bundle
key 9). And it verifies an instance's contract evidence (section
15): its bundle, every consent its calls cite, and the requests and answers
the calls derive.

Usage: python3 -m kanhe_verify BUNDLE [options], or
python3 -m kanhe_verify contract FILE [options]; see --help.
"""

__all__ = ["VerifyError", "verify_bundle", "verify_contract_evidence"]

from .errors import VerifyError


def __getattr__(name: str):
    # The verifiers load on first use, so that the interpreter
    # (kanhe_verify.wasm), which the vector tools share, needs only the
    # standard library.
    if name == "verify_bundle":
        from .evidence import verify_bundle
        return verify_bundle
    if name == "verify_contract_evidence":
        from .contract_evidence import verify_contract_evidence
        return verify_contract_evidence
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
