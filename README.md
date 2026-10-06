# CexChain

**Verifiable records for business, built for the age of AI agents.**

CexChain is a ledger protocol and node for trust between organizations. Every document, asset, and action can be independently verified by anyone, without relying on a platform operator. The action can come from a person or an AI agent.

> **Status:** early development (protocol v0.1). Interfaces and formats may still change.

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
| `core` | Deterministic CBOR, COSE, Merkle proofs, protocol objects, ledger rules, and the offline evidence verifier. Portable C++23 that can be built to WebAssembly. |
| `crypto/openssl` | Cryptographic backend: SHA-2, SM3, Ed25519, ESP256, SM2, ML-DSA |
| `ledger` | Ledger node: crash-safe storage, rule engine, checkpoints, receipts, evidence export (C++26) |
| `cli` | `cexchain` command-line tool: keys, ledger, actors, delegation, records, evidence |
| `mcp` | MCP server and gateway for AI agents (planned) |

## Quick start

```sh
cexchain key generate --out root.key
cexchain key generate --out log.key
cexchain key generate --out alice.key
cexchain init --ledger ./ledger --org "Example Factory" --root-key root.key --log-key log.key

# Register an inspector and let her issue certificates.
cexchain actor add --ledger ./ledger --as root.key --kind person --name "Alice" --key alice.key
cexchain delegate --ledger ./ledger --as root.key --to <alice-id> \
    --allow record-register,record-endorse --record-types cexchain.certificate/1 --days 30

# Issue a certificate; field values stay private until disclosed.
cexchain issue --ledger ./ledger --as alice.key --type cexchain.certificate/1 \
    --field product="Flange DN50" --field result=pass --attach report.pdf

# Checkpoint, export evidence with one field disclosed, and verify it anywhere.
cexchain checkpoint --ledger ./ledger --log-key log.key
cexchain export --ledger ./ledger --log-key log.key --record <record-id> \
    --disclose result --with-attachments --out evidence.cbor
cexchain verify evidence.cbor --ledger-id <ledger-id> --attachment report.pdf=report.pdf
```

The verification report shows every event in the record's history, who performed it (person or
AI agent, with the agent's model and accountable person), under whose delegation, which fields
were disclosed, and whether attachments match. Run `cexchain --help` for every command.

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
