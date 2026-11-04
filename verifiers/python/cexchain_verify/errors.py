# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Errors raised while verifying."""


class VerifyError(Exception):
    """The evidence does not verify. The message says why, for people."""


class Unsupported(VerifyError):
    """The evidence is of a kind this verifier does not handle yet."""


class UsageError(Exception):
    """The command line or an input file given beside the bundle is wrong."""
