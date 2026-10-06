# CexChain

**Verifiable records for business, built for the age of AI agents.**

CexChain is a ledger protocol and node for trust between organizations. Every document, asset, and action can be independently verified by anyone, without relying on a platform operator. The action can come from a person or an AI agent.

> **Status:** early development (specification v0.2, [`spec/cexchain.cddl`](spec/cexchain.cddl)). Interfaces and formats may still change.

## Why

- Certificates, invoices, agreements, and quality reports move between companies as scans, stamps, and phone calls. Verifying them is slow, and disputes are hard to settle.
- AI makes forging documents nearly free, and AI agents increasingly act on behalf of companies. Looking genuine no longer proves anything. Cryptographic provenance does.

## Design principles

- **Verifiable, not just "on chain."**
  - Tamper-evident history: a Merkle log with inclusion and consistency proofs.
  - Non-repudiation: every action is signed.
  - Independent verification: any third party can check a record without trusting its issuer's database.
- **Sovereign first.**
  - A single organization gets value on day one.
  - External witnesses co-sign checkpoints, so history can be neither rewritten nor forked.
  - Ledgers federate later.
- **Documents stay off-chain.** The ledger holds salted commitments, signatures, state transitions, grants, and access records. Content is encrypted and stored separately.
- **People and AI agents are first-class actors.**
  - Every action records who acted and under whose delegated authority.
  - Delegated scope can only narrow.
  - Human actions carry proof of presence. An action without it is attributed to a machine.
- **Crypto agility.** These algorithm families can coexist in one ledger, chosen per signature:
  - international algorithms (Ed25519, ECDSA P-256)
  - Chinese national standards (SM2, SM3, SM4)
  - post-quantum algorithms (ML-DSA, SLH-DSA)
- **Standards-aligned.** Deterministic CBOR, COSE, RFC 9162 Merkle trees, IETF SCITT, W3C Verifiable Credentials, MCP, and A2A.
- **Deterministic core.** No floating point, no unordered iteration, and injected time and randomness. This makes deterministic simulation testing possible.

## Components

| Component | Description |
|---|---|
| `core` | Deterministic CBOR, COSE, Merkle proofs, protocol objects, ledger rules, and the offline evidence verifier. Portable C++23 that builds to WebAssembly. |
| `verifier` | Verification reports (text and JSON) shared by the command line and the browser verifier; `verifier/wasm` is the browser page |
| `crypto/openssl` | Cryptographic backend: SHA-2, SM3, Ed25519, ESP256, SM2, ML-DSA |
| `ledger` | Ledger node: crash-safe storage, rule engine, checkpoints, receipts, evidence export (C++26) |
| `cli` | `cexchain` command-line tool: full control of keys, ledgers, actors, delegations, records, proofs, and evidence |
| `cexchain mcp` | MCP server through which an AI agent acts under its own key and delegation |

## Quick start

```sh
# Private keys are encrypted (PKCS #8, scrypt + AES-256). Passphrases come from
# a prompt, --passphrase-file, or $CEXCHAIN_PASSPHRASE.
cexchain key generate --out root.key
cexchain key generate --out log.key
export CEXCHAIN_LEDGER=./ledger
cexchain init --org "Example Factory" --root-key root.key --log-key log.key

# Alice generates her own key and sends only its public half.
cexchain key generate --out alice.key && cexchain key public alice.key --out alice.pub

# Register her as an inspector and let her issue certificates.
cexchain actor add --as root.key --kind person --name "Alice" --key alice.pub
cexchain delegation grant --as root.key --to <alice-id> \
    --allow record-register,record-endorse --record-types cexchain.certificate/1 --days 30

# Issue a certificate; field values stay private until disclosed.
cexchain record issue --as alice.key --type cexchain.certificate/1 \
    --field product="Flange DN50" --field result=pass --attach report.pdf
cexchain record history <record-id>

# Checkpoint, export evidence with one field disclosed, and verify it anywhere.
cexchain checkpoint create --log-key log.key
cexchain export <record-id> --log-key log.key --disclose result --with-attachments --out evidence.cbor
cexchain verify evidence.cbor --ledger-id <ledger-id> --attachment report.pdf=report.pdf
```

The verification report shows every event in the record's history, who performed it (person or
AI agent, with the agent's model and accountable person), under whose delegation, which fields
were disclosed, and whether attachments match.

The report also proves that it shows everything. Each checkpoint commits to the complete history of
every actor, delegation, and record, in a sparse Merkle tree. A bundle proves the history of the
record and of everyone involved against that commitment. So nobody can hand over evidence that
quietly leaves out a later revocation, of the record or of the person who signed it.

## Command line

The `cexchain` tool controls every part of a ledger:

| Area | Commands |
|---|---|
| Keys | `key generate`, `key show`, `key public`, `key passphrase` |
| Ledger | `init`, `status`, `audit`, `log list`, `log show`, `log export` |
| Actors | `actor add`, `actor list`, `actor show`, `actor revoke`, `actor rotate-key`, `actor set-presence`, `presence enroll` |
| Delegations | `delegation grant`, `delegation list`, `delegation show`, `delegation revoke` |
| Records | `record issue`, `record list`, `record show`, `record history`, `record fields`, `record endorse`, `record transition`, `record revoke`, `record types` |
| Proofs | `checkpoint create`, `checkpoint list`, `checkpoint show`, `checkpoint cosign-request`, `checkpoint add-cosignature`, `proof inclusion`, `proof consistency`, `proof state`, `receipt` |
| Witnesses | `witness add-log`, `witness cosign`, `witness status`, `witness remove-log` |
| Evidence | `export`, `verify`, `inspect`, `qr` |
| Vault | `vault status`, `vault keygen`, `vault rekey` |
| AI agents | `mcp` |

- Every command takes `--help`, and `--json` for scripting.
- `cexchain help --json` describes every command and option in machine-readable form.
- `source <(cexchain completion bash)` (or `zsh`) enables tab completion.
- IDs can be shortened to any unique prefix of 8 or more hex digits.
- Exit codes: 0 for success, 1 for a usage error, 2 for a failure, and 3 when evidence or a ledger fails verification.

Private field values never sit on disk in the clear. They are sealed with HPKE (RFC 9180: X25519,
HKDF-SHA256, AES-256-GCM) to the ledger's vault key, and each sealed file is bound to its ledger and
record. Anyone who may issue records, AI agents included, can add to the vault, but only holders of
the vault private key can read it. The vault private key can be kept off the ledger host
(`vault keygen`, `init --vault-public-key`) and rotated at any time (`vault rekey`).

## Proof of presence

A signature shows that a key was used, not that a person was there. CexChain therefore attributes
actions to machines by default, and treats an action as a person's only when it carries proof of
presence: a WebAuthn assertion from the person's passkey (Touch ID, Windows Hello, a phone, or a
security key) that approves exactly that statement.

```sh
# The person: create a passkey; only its public data goes into the file.
cexchain presence enroll --out alice.passkey --name "Alice"
# The organization: register it. (A stolen signing key cannot enroll a thief's passkey.)
cexchain actor set-presence <alice-id> --as root.key --credential alice.passkey
# Require presence for what matters...
cexchain delegation grant --as root.key --to <alice-id> --allow record-endorse --require-presence
# ...and confirm with the passkey when acting.
cexchain record endorse <record-id> --as alice.key --role inspector --presence
```

Every verification report shows, for each step a person took, whether they proved presence. The
browser verifier shows it too.

## Witnesses

A ledger's operator could, in principle, rewrite its history or show different histories to
different parties. Witnesses make that detectable. A witness is an independent party, such as a
customer, an auditor, or a regulator. It remembers the last checkpoint it cosigned for each
ledger, and it cosigns a new one only if a consistency proof shows the new history extends the
old (the C2SP witness model).

```sh
# The witness, once: follow the ledger (its id and log key come from the operator).
cexchain witness add-log --dir witness --ledger-id <ledger-id> --log-key log.pub
# The operator, after each checkpoint:
cexchain checkpoint cosign-request --witness witness.pub --out request.cbor
# The witness: check consistency, then cosign. A forked or rewritten ledger is refused.
cexchain witness cosign request.cbor --dir witness --key witness.key --out cosignature.cbor
# The operator: store it. Exported evidence now carries it.
cexchain checkpoint add-cosignature cosignature.cbor --witness witness.pub
# Anyone: require witnesses they trust.
cexchain verify evidence.cbor --witness witness.pub --min-witnesses 1
```

## Browser verifier

Anyone can check evidence without installing anything. `cexchain-verify.html` is one self-contained
page: the same verification code as `cexchain verify`, compiled to WebAssembly together with
OpenSSL. It runs entirely in the browser and uploads nothing. It works offline, even opened from
disk, and it can be hosted on any static web server.

```sh
tools/wasm/build.sh            # needs Emscripten; writes build/wasm/cexchain-verify.html
```

Publish a record's evidence bundle, then print a QR code on the document:

```sh
cexchain qr <record-id> --bundle-url https://example.com/evidence/cert-1006.cbor \
    --verifier-url https://example.com/verify.html --out cert-1006-qr.svg
```

Scanning the code opens the verifier with the ledger id, the record id, and the bundle's location.
The page refuses evidence about another record or from another ledger, and shows who did what,
person or AI agent, under whose authority.

## AI agents (MCP)

`cexchain mcp --ledger DIR --as AGENT_KEY` runs a Model Context Protocol server over stdio
(revision 2026-07-28, with fallback to earlier revisions). The agent can look up its identity and
delegations, query and issue records, endorse, move records through their lifecycle, and verify
evidence from others. Every action is signed with the agent's own key, refused by the ledger if
its delegation does not cover it, and recorded with provenance: its model, a hash of the inputs it
acted on, and the digest of the tool it used. Verification reports show all of this. MCP clients
start the server without a terminal, so give it the agent key's passphrase with
`--passphrase-file` or `CEXCHAIN_PASSPHRASE`.

## Building

Requirements:

- GCC 16 (primary) or a recent Clang (tested with Clang 23)
- CMake 3.28+ and Ninja
- OpenSSL 3.5+

```sh
cmake --preset gcc-debug
cmake --build --preset gcc-debug
ctest --preset gcc-debug
```

Other presets: `gcc-release`, `clang-debug`, `clang-asan` (AddressSanitizer + UndefinedBehaviorSanitizer), and `clang-fuzz` (libFuzzer targets).

The browser verifier is tested against evidence from the native tool. A Node.js test requires its
report to match `cexchain verify --json` exactly, and a Chromium test drives the page:

```sh
tools/wasm/build.sh
(cd tests/browser && npm ci && npx playwright install chromium)
tests/browser/run.sh build/gcc-debug/cli/cexchain build/wasm
```

Fuzz targets cover every parser of untrusted input:

```sh
cmake --preset clang-fuzz && cmake --build --preset clang-fuzz
./build/clang-fuzz/fuzz/cbor_decode_fuzz -max_total_time=300
```

Test vectors in `testvectors/` come from implementations independent of CexChain. `tools/testvectors/generate.py` regenerates them.

On macOS, Homebrew's LLVM is keg-only. To use it with the Clang presets, add a `CMakeUserPresets.json` that inherits a Clang preset and sets `CMAKE_CXX_COMPILER` to `/opt/homebrew/opt/llvm/bin/clang++`. Homebrew's `openssl@3` is detected automatically.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Copyright 2026 Cirraya.
