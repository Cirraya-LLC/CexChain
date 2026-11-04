# An independent verifier, in Python

A second verifier of CexChain evidence, written from the specification alone:
[the protocol in prose](../../spec/README.md), [`spec/cexchain.cddl`](../../spec/cexchain.cddl),
and the test vectors in [`testvectors/`](../../testvectors/). It shares no code with the C++
implementation, and its authors did not read it. A protocol that only one program can verify is
defined by that program. A second one, written from the text, shows that the text is enough, and
every place where the two disagree is a place where the text needs fixing.

It verifies an evidence bundle (spec section 11), a record's or an instance's, every step:

- deterministic CBOR and COSE_Sign1;
- the log, its receipts and checkpoints, under the log key in effect at each size;
- a replay of the ledger rules: actors, delegations, key rotations, revocations, versions, and
  contracts (below);
- proof of presence, by passkey or hardware key;
- disclosed fields and attachments;
- completeness against the state commitment;
- witness cosignatures;
- RFC 3161 time-stamp tokens and the clock rule.

And it verifies an instance's contract evidence (sections 14 and 15):

- deploys, calls, and retires under their ledger rules: the code loads in the deterministic
  WebAssembly profile, interfaces, heads, function kinds, consent citations, scope keys 7 to 9;
- every call's contract run again, on the contract input the home built, its output read as a
  contract output: states, statuses, parties, events, finality;
- instances created by a call: their ids, depth (at most 8), and a part's ancestors' calls up to
  each one that created the next generation;
- requests and answers: their ids, deadlines, replies, at most 64 open per instance, answers
  done, failed, or expired (only once due), at most once, late or on time, and the open requests
  overdue at the checkpoint;
- completeness with state leaves of kinds 4 and 5: the instance, its contract, and everyone its
  calls and its ancestors' calls involve;
- every consent a call cites: its bundle verified completely for the party's ledger, as any
  record's, a live `cexchain.contract-consent/1` record whose terms are the call's, not lapsed when
  the call was registered, signed as the call claims; no bundle without a citation, no citation
  without a bundle.

The interpreter, `cexchain_verify/wasm.py`, is the specification's reference interpreter,
written from it independently of the C++ implementation; the vector tools use it through
[`tools/testvectors/wasm_ref.py`](../../tools/testvectors/wasm_ref.py), and
`testvectors/vm-v1.json` holds its runs. A Bo contract's source is not rebuilt (there is no Bo
compiler here): like `cexchain contract verify`, it checks the code as run, and `--deploy-out`
writes the deploy for `bo rebuild`.

## Running it

Python 3.11 or later, with the packages in [`requirements.txt`](requirements.txt). `openssl`
3.5 or later must be on `PATH`, for SM2 and for time-stamp tokens; `CEXCHAIN_OPENSSL` names
another binary.

```sh
python3 -m venv .venv && .venv/bin/pip install -r verifiers/python/requirements.txt
PYTHONPATH=verifiers/python .venv/bin/python -m cexchain_verify evidence.cbor --ledger-id <ledger-id>
PYTHONPATH=verifiers/python .venv/bin/python -m cexchain_verify contract deal.cbor --ledger-id <home-id>
```

Its two commands mirror the reference implementation's, with the same options, exit codes, and
JSON fields:

| This verifier | Mirrors | Options besides `--json` |
|---|---|---|
| `python3 -m cexchain_verify BUNDLE` | `cexchain verify` | `--ledger-id`, `--witness`, `--min-witnesses`, `--tsa-root`, `--min-timestamps`, `--attachment NAME=FILE` |
| `python3 -m cexchain_verify contract FILE` | `cexchain contract verify` | `--ledger-id`, `--witness`, `--min-witnesses`, `--tsa-root`, `--min-timestamps`, `--require-presence`, `--require-answered`, `--deploy-out FILE` |

Exit codes: 0 verified, 1 a usage error, 2 an input file that cannot be read (or a
`--deploy-out` file that cannot be written), 3 not verified.

The first command verifies any evidence bundle, an instance's included (it reports it as a
record without a type, its calls as its events); contract evidence, which wraps an instance's
bundle with its consents, takes the second. A command of its own keeps each one's options and
errors exactly those of the command it mirrors, and a file is never verified as what it is not.

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

Contract evidence is compared with `cexchain contract verify --json` the same way, field by
field:

- parts split across a SHA-256 and an SM3 party, with consents of an organization, a person, a
  device, an AI agent under a chain of delegations, and (on SoftHSM) a person present with a
  hardware key; a retired contract; witnesses and time-stamps on the home and on a consent;
- requests answered done, failed, and expired, on time and late, by executors under scope keys 8
  and 9, an AI agent, a keeper, and a person; a final instance that takes an answer; requests
  overdue at the checkpoint, with `--require-answered`;
- an SM3 home whose contract hashes its input, children without parties, and arguments of every
  kind of CBOR value;
- the contract evidence the examples (`examples/`) leave behind: Bo contracts with time rules,
  keepers, executors, consents through MCP, and parts;
- the signed contract evidence of `protocol-v0.7.json` and `protocol-v0.8.json` (and that of
  `protocol-v0.6.json`, whose bundles are opaque bytes, which must fail);
- damaged contract evidence (entries, proofs, consents left out, repeated, or unpinned; flipped
  bytes), which must fail in both;
- home and party ledgers forged at the contract rules' edges (`tests/contract_probes.py`).

It also checks other inputs:

- damaged bundles, which must fail in both;
- bundles packed from the test vectors, which must verify in both;
- ledgers forged at the specification's edges (`tests/probes.py`, `tests/contract_probes.py`),
  where both must agree when the specification decides the outcome. Where it does not, they are
  printed but do not fail.

The verifier's own unit tests run against `testvectors/`: `tests/test_vectors.py` for records,
and `tests/test_contracts.py` for the profile (`vm-v1.json`), contracts, parts, requests and
answers (`protocol-v0.6.json` to `protocol-v0.8.json`: every statement, every refused one, every
contract run's input and outcome, the state, and the signed evidence), and Bo's calls
(`bo-v1.json`: each call's input as the ledger encodes it, and its outcome).

CTest finds the Python as `CEXCHAIN_PYTHON`, or `python3`; without the packages the test is
skipped. CI installs them in `/opt/python-verifier` and names it, so there the test cannot be
skipped.
