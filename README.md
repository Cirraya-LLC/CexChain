# CexChain

**Verifiable records for business, built for the age of AI agents.**

CexChain is a ledger protocol and node for trust between organizations. Every document, asset, and action can be independently verified by anyone, without relying on a platform operator. The action can come from a person or an AI agent.

> **Status:** early development. Interfaces and formats are unstable and will change.

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

## Planned components

| Component | Description |
|---|---|
| `core` | Encoding, hashing, signature verification, Merkle proofs. Portable C++23 that can be built to WebAssembly. |
| `node` | Ledger node: records, assets, actors, delegation, checkpoints (C++26) |
| `cli` | Issue, sign, verify, and export evidence bundles |
| `verifier` | Standalone offline verifier for evidence bundles |
| `mcp` | MCP server and gateway for AI agents |

## Building

Not available yet. Planned requirements: GCC 16 or a recent Clang, CMake, Ninja, and OpenSSL 3.5 or later.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Copyright 2026 Cirraya.
