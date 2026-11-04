# An independent verifier, in Python

A second verifier of CexChain evidence, written from the specification alone:
[the protocol in prose](../../spec/README.md), [`spec/cexchain.cddl`](../../spec/cexchain.cddl),
and the test vectors in [`testvectors/`](../../testvectors/). It shares no code with the C++
implementation, and its authors did not read it. A protocol that only one program can verify is
defined by that program. A second one, written from the text, shows that the text is enough, and
every place where the two disagree is a place where the text needs fixing.

It verifies a record's evidence bundle (spec section 11), every step:

- deterministic CBOR and COSE_Sign1;
- the log, its receipts and checkpoints, under the log key in effect at each size;
- a replay of the ledger rules: actors, delegations, key rotations, revocations, versions;
- proof of presence, by passkey or hardware key;
- disclosed fields and attachments;
- completeness against the state commitment;
- witness cosignatures;
- RFC 3161 time-stamp tokens and the clock rule.

Contract evidence (sections 14 and 15) is not supported yet: it is refused with an error that
says so.

## Running it

Python 3.11 or later, with the packages in [`requirements.txt`](requirements.txt). `openssl`
3.5 or later must be on `PATH`, for SM2 and for time-stamp tokens; `CEXCHAIN_OPENSSL` names
another binary.

```sh
python3 -m venv .venv && .venv/bin/pip install -r verifiers/python/requirements.txt
PYTHONPATH=verifiers/python .venv/bin/python -m cexchain_verify evidence.cbor --ledger-id <ledger-id>
```

The options and the exit codes are those of `cexchain verify`:

- options: `--ledger-id`, `--witness`, `--min-witnesses`, `--tsa-root`, `--min-timestamps`,
  `--attachment NAME=FILE`, `--json`;
- exit codes: 0 verified, 1 a usage error, 2 an input file that cannot be read, 3 not verified.

The JSON report has the same fields as `cexchain verify --json`.

Nothing cryptographic is implemented here:

- Ed25519, ECDSA P-256, and ML-DSA come from the `cryptography` package;
- SHA-256 and SM3 come from `hashlib`;
- SM2 and the CMS signatures of time-stamp tokens come from the `openssl` command line.

## Tests

[`tests/verifiers/python_verifier.sh`](../../tests/verifiers/python_verifier.sh) is CTest's
`verifier_python_end_to_end`. It builds ledgers with the command line and hands every bundle to
both verifiers, which must reach the same verdict and report the same facts. The ledgers cover
many algorithms and actors:

- SHA-256 and SM3 ledgers;
- Ed25519, ESP256, SM2, and ML-DSA keys;
- an AI agent, delegation chains, and key rotations;
- witnesses, time-stamp authorities, and hardware keys on SoftHSM.

It also checks other inputs:

- damaged bundles, which must fail in both;
- bundles packed from the test vectors, which must verify in both;
- ledgers forged at the specification's edges (`tests/probes.py`), where both must agree when the
  specification decides the outcome. Where it does not, they are printed but do not fail.

The verifier's own unit tests (`tests/test_vectors.py`) run against `testvectors/`.

CTest finds the Python as `CEXCHAIN_PYTHON`, or `python3`; without the packages the test is
skipped. CI installs them in `/opt/python-verifier` and names it, so there the test cannot be
skipped.
