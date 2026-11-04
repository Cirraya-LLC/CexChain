# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""An independent verifier of CexChain evidence bundles, written from the
protocol specification (spec/README.md and spec/cexchain.cddl) only.

It verifies the evidence bundle of a record (spec section 11): deterministic
CBOR, COSE_Sign1, the log and its receipts, checkpoints and the log key in
effect, a replay of the ledger rules, proof of presence, disclosures and
attachments, state proofs (completeness), witness cosignatures, and RFC 3161
time-stamp tokens. Contract evidence (sections 14 and 15) is not supported
yet and is refused cleanly.

Usage: python3 -m cexchain_verify BUNDLE [options]; see --help.
"""

__all__ = ["VerifyError", "verify_bundle"]

from .errors import VerifyError
from .evidence import verify_bundle
