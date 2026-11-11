# The chain

The protocol and everything that keeps, serves, and verifies a ledger, with the `kanhe`
program that controls it. The chain knows no contract language and no application: a contract
is WebAssembly code with the source its deploy carries, as given, and the
[Bo compiler](../bo/README.md), the [web console](../apps/console/README.md), and the
[search index](../apps/index/README.md) are built on top of it. The build checks the direction
(`cmake/KanheLayers.cmake`): nothing here links the language, an application, or SQLite.

| Library | What it holds |
|---|---|
| `core` | Deterministic CBOR, COSE, Merkle proofs, the protocol's objects, the ledger's rules, the contract interpreter, and the offline evidence verifier. Portable C++23, with no dependencies, that builds to WebAssembly |
| `crypto/openssl` | The cryptographic backend: SHA-2, SM3, Ed25519, ESP256, SM2, ML-DSA |
| `crypto/pkcs11` | Keys on PKCS #11 tokens: USB keys (UKey), smart cards, and HSMs, loaded at run time |
| `verifier` | Verification reports (text and JSON) shared by the command line and the browser; `verifier/wasm` is the browser verifier's page |
| `ledger` | The ledger: crash-safe storage, the rule engine, checkpoints, receipts, evidence, backups (C++26) |
| `node` | The HTTP API server and client (Asio), API tokens, replicas, clusters (Raft), the registrar, the keeper, and executors; applications attach to it as extensions (C++26) |
| `client` | What a program does with a ledger: opening one, or a verified mirror of a server's, building, signing, and submitting statements, records and their vault, contract calls and consents, requests, peers, and JSON views. Shared by the command line and the console (C++26) |
| `cli` | The `kanhe` program, its MCP server (`kanhe mcp`), and the command-line base all four programs share: options, `--help`, `--json`, completion |

The protocol itself is defined by its specification, [`spec/`](../spec/README.md), and the
vectors in [`testvectors/`](../testvectors/), not by this code.
