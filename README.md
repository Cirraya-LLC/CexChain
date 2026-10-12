# CexChain

**Verifiable records for business, built for the age of AI agents.**

CexChain is a ledger protocol and node for trust between organizations. Every document, asset, and action can be independently verified by anyone, without relying on a platform operator. The action can come from a person or an AI agent.

> **Status:** early development (specification v0.5: [the protocol in prose](spec/README.md), [`spec/cexchain.cddl`](spec/cexchain.cddl)). Interfaces and formats may still change.

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
| `crypto/pkcs11` | Keys on PKCS #11 tokens: USB keys (UKey), smart cards, and HSMs, loaded at run time |
| `ledger` | Ledger node: crash-safe storage, rule engine, checkpoints, receipts, evidence export, backups (C++26) |
| `node` | HTTP API server and client (Asio), API tokens, and replicas (C++26) |
| `cli` | `cexchain` command-line tool: full control of keys, ledgers, actors, delegations, records, assets, contracts, proofs, and evidence |
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

The report also proves that it shows everything. Before each checkpoint, the ledger appends to its
own log a signed commitment (a sparse Merkle root) to the complete history of every actor,
delegation, and record. A bundle proves the history of the record and of everyone involved against
that commitment. So nobody can hand over evidence that quietly leaves out a later revocation, of the
record or of the person who signed it. Because the commitment lives in the witnessed, append-only
log, a false one could never be withdrawn, and replaying the log exposes it.

## Command line

The `cexchain` tool controls every part of a ledger:

| Area | Commands |
|---|---|
| Keys | `key generate`, `key show`, `key public`, `key passphrase` |
| Ledger | `init`, `status`, `audit`, `log list`, `log show`, `log export`, `ledger keys`, `ledger genesis`, `ledger rotate-log-key`, `ledger rotate-root-key` |
| Actors | `actor add`, `actor list`, `actor show`, `actor revoke`, `actor rotate-key`, `actor set-presence`, `presence enroll` |
| Delegations | `delegation grant`, `delegation list`, `delegation show`, `delegation revoke` |
| Records | `record issue`, `record list`, `record show`, `record history`, `record fields`, `record endorse`, `record transition`, `record revoke`, `record types` |
| Proofs | `checkpoint create`, `checkpoint list`, `checkpoint show`, `checkpoint cosign-request`, `checkpoint add-cosignature`, `proof inclusion`, `proof consistency`, `proof state`, `receipt` |
| Witnesses | `witness add-log`, `witness cosign`, `witness status`, `witness remove-log` |
| Evidence | `export`, `verify`, `inspect`, `qr` |
| Vault | `vault status`, `vault keygen`, `vault rekey` |
| AI agents | `mcp` |
| Server | `serve`, `token create`, `token list`, `token show`, `token revoke` |
| Clusters | `cluster init`, `cluster join`, `cluster add`, `cluster status`, `cluster remove`, `cluster step-down` |
| Replicas | `replica init`, `replica sync`, `replica status`, `replica promote` |
| Backups | `backup create`, `backup verify`, `backup restore` |
| Other organizations | `peer add`, `peer list`, `peer show`, `peer remove`, `access request`, `access send`, `access inbox`, `access grant`, `access fetch`, `access accept`, `access receipt`, `access list` |
| Ownership assets | `asset issue`, `asset show`, `asset list`, `asset record`, `asset evidence`, `asset consent`, `asset withdraw`, `asset send`, `asset fetch`, `asset verify` |
| Contracts | `contract deploy`, `contract show`, `contract list`, `contract retire`, `contract create`, `contract call`, `contract instance`, `contract instances`, `contract evidence`, `contract propose`, `contract pending`, `contract consent`, `contract withdraw`, `contract send`, `contract fetch`, `contract verify` |

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

USB keys (UKey) and smart cards work too, through PKCS #11: the token's key signs the statement's
presence challenge after the person enters the PIN. Hardware keys may use any signature algorithm
CexChain supports, SM2 included.

```sh
# Generate a key on the token and enroll it (or enroll a key the vendor's tools created).
cexchain key generate --pkcs11 "pkcs11:token=UKey;object=alice-presence?module-path=/path/to/vendor.so" \
    --alg esp256 --out alice-ukey.pub
cexchain presence enroll --pkcs11 "pkcs11:token=UKey;object=alice-presence?module-path=/path/to/vendor.so" \
    --label "Alice's UKey" --out alice.ukey
cexchain actor set-presence <alice-id> --as root.key --credential alice.ukey
# Confirm with the token when acting; the PIN comes from a prompt or $CEXCHAIN_PKCS11_PIN.
cexchain record endorse <record-id> --as alice.key --role inspector \
    --presence-key "pkcs11:token=UKey;object=alice-presence?module-path=/path/to/vendor.so"
```

Every verification report shows, for each step a person took, whether they proved presence and
how (a passkey or a hardware key). The browser verifier shows it too.

## Keys on tokens and HSMs

Wherever a command takes a key file, it also takes an RFC 7512 PKCS #11 URI, so an organization's
root key can stay in an HSM and a person's signing key on a USB key. Keys generated with
`key generate --pkcs11` are marked sensitive and never leave the token. ESP256 and Ed25519 work
with any PKCS #11 module; SM2 needs the vendor's mechanism number in the URI
(`?x-sm2-mechanism=<hex>`), since SM2 is not part of the PKCS #11 standard. Every signature a
token returns is checked before it is used.

## Rotating the organization's keys

The organization can replace its root key and the ledger's log key, for instance when a key is
retired or to move to post-quantum signatures (ML-DSA). Each rotation is a statement signed by
the root key in effect. The new log key signs every checkpoint, receipt, and state commitment
after the rotation; older checkpoints stay valid under the key that signed them. Evidence bundles
carry the rotations, and verifiers, witnesses, and replicas follow them.

```sh
cexchain ledger keys                                         # both histories, with log indices
cexchain ledger rotate-log-key --as root.key --new-key log2.key
cexchain checkpoint create --log-key log2.key                # the old key no longer checkpoints
cexchain ledger rotate-root-key --as root.key --new-key root2.key
# A server can hold both log keys across the switch.
cexchain serve --log-key log.key --log-key log2.key
```

## Witnesses

A ledger's operator could, in principle, rewrite its history or show different histories to
different parties. Witnesses make that detectable. A witness is an independent party, such as a
customer, an auditor, or a regulator. It remembers the last checkpoint it cosigned for each
ledger, and it cosigns a new one only if a consistency proof shows the new history extends the
old (the C2SP witness model).

```sh
# The operator, once: the genesis entry, which fixes the ledger id and its first keys.
cexchain ledger genesis --out genesis.entry
# The witness, once: follow the ledger, checked against the id learned from the operator.
# (From the genesis entry, the witness follows key rotations too.)
cexchain witness add-log --dir witness --genesis genesis.entry --ledger-id <ledger-id>
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
page: the same verification code as `cexchain verify`, `asset verify`, and `contract verify`,
compiled to WebAssembly together with OpenSSL and the contract interpreter. It takes a record's
evidence bundle, an asset's evidence, or a contract instance's evidence, which it checks by running
the contract again on every call. It runs entirely in the browser and uploads nothing. It works
offline, even opened from disk, and it can be hosted on any static web server.

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

## Running a ledger as a service

`cexchain serve` exposes a ledger over HTTP (API v1, described by `cexchain serve --help`). Signed
statements are the authorization: the server only checks API tokens, which gate access because
statements reveal business metadata. The server holds the ledger's lock only while it writes, so
every other command keeps working on the same ledger.

The server is built for many clients at once. Connections are spread over a pool of I/O threads
(`--threads`, one per core by default), and reads run on all of them in parallel. Writes queue for a
single writer, which commits everything that queued during the previous sync as one group: one
lock, one sync, and signatures checked on every core. Readers only ever see durable entries.
`cexchain-bench http` measures it.

```sh
cexchain token create app --scope submit,read --out app.token   # shown once; only its hash is kept
cexchain token create replica --scope read --out replica.token
cexchain serve --listen 0.0.0.0:8080 --log-key log.key --tls-cert cert.pem --tls-key key.pem

# Elsewhere: a replica copies the ledger and re-validates every entry and checkpoint it copies.
CEXCHAIN_TOKEN=$(cat replica.token) cexchain replica init --from https://ledger.example.com \
    --ledger-id LEDGER_ID --ledger ./replica
cexchain replica sync --ledger ./replica --follow
cexchain serve --ledger ./replica --listen 0.0.0.0:8080       # read-only, for verifiers and reports

# Backups: one file, re-validated on restore. Sign them with the log key: a restore takes what no
# checkpoint covers (the newest entries, tokens, the vault) only from a signed backup.
cexchain backup create --ledger ./replica --out ledger.cxb --log-key log.key
cexchain backup verify ledger.cxb
cexchain backup restore ledger.cxb --ledger ./restored
```

A replica copies only what the log key signed: each checkpoint is checked first, and the entries
it covers must lead to its root before any is taken, so a replica trails its primary by the
checkpoint interval. It stops (exit 3) at the first entry that does not validate, and refuses
histories that were rolled back, so a compromised primary cannot rewrite a replica's copy. If the primary is lost,
stop it for good and run `cexchain replica promote`; witnesses would detect two primaries signing.
Operations: `GET /healthz`, Prometheus metrics at `GET /metrics`, an access log in JSON lines on
stderr, automatic checkpoints (`--checkpoint-interval`), and graceful shutdown on SIGTERM. The
`Dockerfile` builds a small image that runs as a non-root user with the ledger in `/data`.

## Working through a server

Most commands also run against a server instead of a ledger directory: pass `--server URL` (or set
`$CEXCHAIN_SERVER`) with an API token (`--token-file`, or `$CEXCHAIN_TOKEN`). The client keeps a
mirror of the ledger in its cache and brings it up to date first, re-validating every entry and
checkpoint, so everything it shows was verified on this machine; a server that rolls back or forks
what the client saw before is refused. Statements are signed here and sent to the server, so keys
never leave the client. A record's private data is sealed here to the server's vault key and sent
with the record.

```sh
export CEXCHAIN_SERVER=https://ledger.example.com CEXCHAIN_TOKEN=$(cat app.token)
cexchain status --ledger-id LEDGER_ID        # the first use pins the ledger the URL serves
cexchain record issue --as alice.key --type cexchain.certificate/1 --field result=pass
cexchain checkpoint create                    # the server signs (admin token); the client checks
cexchain export RECORD --disclose result --vault-key vault.key --out evidence.cbor
```

The ledger id must be given on first use of an `http://` URL. Commands that administer the server's
own files and keys (`init`, `serve`, `token`, `replica`, `backup`, `vault`, `peer`, `access`, `mcp`)
run where the ledger is.

## Clusters and failover

Three (or five) nodes can keep one ledger with Raft. The leader takes the writes; each group of
statements is acknowledged only once a majority holds it durably, and every member applies it to
its own ledger, so their files are identical. If the leader fails, the others elect a new one within
seconds, and no acknowledged write is lost. Followers serve reads and send writers to the leader.

```sh
# The founder, from a fully checkpointed ledger:
cexchain cluster init --ledger ./node1 --id 1 --raft node1:7001 --api https://node1:8443
cexchain serve --cluster --ledger ./node1 --log-key log.key --listen 0.0.0.0:8443 ...
# Each other member copies the ledger, runs, and is added by the leader:
cexchain cluster join --ledger ./node2 --from https://node1:8443 --id 2 --raft node2:7001 \
    --api https://node2:8443 --secret-file secret
cexchain serve --cluster --ledger ./node2 --log-key log.key --listen 0.0.0.0:8443 ...
cexchain cluster add --server https://node1:8443 --id 2 --raft node2:7001 --api https://node2:8443
cexchain cluster status --server https://node2:8443
```

Members authenticate every Raft message with the cluster's shared secret. Each member holds the log
key (in its own HSM, or a key file) to sign checkpoints while it leads. A member's files belong to
it while it runs: use the command line with `--server`. `deploy/cluster/compose.yaml` runs a
three-member cluster on one Docker host.

## Working with other organizations

Two organizations, each with its own ledger, can share records without a platform between them.
A bank that asks a factory for a quality certificate, for example:

```sh
# Each side pins the other's ledger by its id, learned through a channel they trust.
cexchain peer add bank --ledger-id <bank-ledger-id> --url https://ledger.bank.example --token-file bank.token
cexchain peer add factory --ledger-id <factory-ledger-id> --url https://ledger.factory.example ...

# The bank asks (a request record on its own ledger, with a key made for this request).
cexchain access request --peer factory --record <id> --purpose "loan collateral check" \
    --fields result --attachments report.pdf --as officer.key --log-key log.key --send

# The factory sees who asked and under whose authority, and grants (a grant record on its ledger).
cexchain access inbox
cexchain access grant <request> --as approver.key --log-key log.key --attach report.pdf=report.pdf

# The bank fetches and checks everything against the factory's ledger, then acknowledges
# (a receipt record on its ledger, sent back).
cexchain access fetch --peer factory --request <request> --out delivery.cbor
cexchain access accept delivery.cbor --as officer.key --log-key log.key --save-dir received --send
```

Each step is a record on the acting organization's own ledger, so delegations decide who may
request, grant, or acknowledge, and proof of presence shows when a person approved. Each side
checks the other's step with the offline evidence verifier, pinned to the peer's ledger id. The
delivery holds the grant's evidence and the record's, with only the granted fields and attachments,
sealed with HPKE to the request's key. The recipient checks every field and file against the
record's commitments. Revoking a grant (`record revoke`) stops future deliveries, and receipts make
access accountable. The same exchange works with files instead of the API (`--out`, then
`access grant FILE`, `access accept FILE`, `access receipt FILE`).

Two organizations can also witness each other's ledgers. `cexchain serve --witness-dir DIR
--witness-key KEY` cosigns a peer's checkpoints online, and the peer runs
`cexchain checkpoint cosign-request --peer NAME --send`. No third party is needed for neither side
to be able to rewrite its history unseen.

## Receivables and warehouse receipts

An ownership asset lives on its issuer's ledger, its home: a receivable on the debtor's, a
warehouse receipt on the warehouse's. It changes hands only with the consent of every party
involved, each given on that party's own ledger, so the home cannot move it alone, and it refuses
a second pledge outright. A core enterprise, its supplier, and a bank:

```sh
# The core enterprise issues a receivable to its supplier (a peer), and runs a registrar:
# a device actor with a delegation for asset actions, which records each action once all
# its parties have consented.
cexchain asset issue receivable --holder supplier --amount 125000.00 --currency CNY \
    --due 2027-01-06 --field contract=PO-2026-0815 --field invoice=INV-77 --as clerk.key
cexchain serve --log-key log.key --registrar-key registrar.key ...

# The supplier asks to pledge it to the bank, and the bank agrees: each consents on its
# own ledger, and sends the consent to the core enterprise's server.
cexchain asset consent --peer core --asset <id> --action pledge --to bank \
    --as cfo.key --log-key log.key --send
cexchain asset consent --peer core --asset <id> --action pledge --to <bank-ledger-id> \
    --evidence asset.cbor --reference "Loan SCF-2026-0042" --as officer.key --log-key log.key --send

# The bank funds once its pledge is in a checkpoint cosigned by witnesses it trusts.
cexchain asset fetch --peer core --asset <id> --out pledged.cbor
cexchain asset verify pledged.cbor --ledger-id <core-ledger-id> --witness regulator.pub --min-witnesses 1
```

Each consent names exact terms, among them the asset's *head* (its latest change), so it applies
only to the asset as its party saw it, and only once. Actions: transfer, pledge, release, enforce,
redeem (in part), pay and confirm or dispute, freeze and unfreeze (the home's own word, e.g. under a
court order), and cancel. Without a registrar, the home's people record actions with the consents
as files (`asset record pledge <id> --to bank --consent s.cbor --consent b.cbor`). `asset verify`
checks the asset's evidence offline and prints its chain of title: who consented to each action,
under whose authority, and whether a person proved presence. Lenders that share a witness (a
regulator, say) are protected against a home that would show each of them a different history.

## Contracts

A contract is a WebAssembly module deployed on a ledger, its home, that governs *instances*:
agreements, orders, bills. The home records a call on an instance only if the contract, run on the
call, accepts it. Parties on other ledgers consent on their own ledgers, and anyone holding an
instance's evidence runs the contract again on every call. Contracts run in a deterministic,
integer-only profile with metered fuel, so every verifier, the browser included, reaches the same
result. A core enterprise, its supplier, and a bank:

```sh
# The core enterprise deploys a contract and proposes an agreement; the contract names the parties.
cexchain contract deploy agreement.wasm --function propose=create --function sign=call \
    --function close=call --compiler "bo 1.0" --source agreement.bo --name "Supply agreement" --as cto.key
cexchain contract create <contract> propose --args '{"price": 98000, "currency": "CNY"}' --as clerk.key

# Its registrar records calls that need other parties' consents: a device with a delegation
# for calls on this contract only.
cexchain delegation grant --as root.key --to <registrar> --allow contract-call --contracts <contract>
cexchain serve --log-key log.key --registrar-key registrar.key ...

# The supplier proposes signing it; the contract names whose consents it needs. Each party sees
# the call's terms and consents on its own ledger; the last consent gets the call recorded.
cexchain contract propose <instance> sign --peer core --args '{"price": 98000}'
cexchain contract pending --peer core
cexchain contract consent --peer core --call <call> --as cfo.key --log-key log.key --send

# Anyone: verify the instance offline, every call run again and every consent checked.
cexchain contract fetch --peer core --instance <instance> --out agreement.cbor
cexchain contract verify agreement.cbor --ledger-id <core-ledger-id>
```

Arguments are written in CBOR diagnostic notation: JSON without floating point, plus byte strings
(`h'00ff'`), keys of any type, and tags (`--args-cbor FILE` takes them encoded). `contract call
--dry-run` shows what the contract would do. A consent names exact terms, among them the instance's
*head* and a digest of the arguments, so it applies to one call, once. Without a registrar, the
home's people record calls with consents as files (`contract call <instance> sign --consent
s.cbor --consent b.cbor`). `contract verify` shows each call, its outcome, and who consented: a
person who proved presence, a key alone, or an AI agent and its model. The browser verifier shows
the same report. Delegations can be limited
to contracts (`delegation grant --contracts`), and `contract retire` stops new instances while
existing ones carry on.

## AI agents (MCP)

`cexchain mcp --ledger DIR --as AGENT_KEY` runs a Model Context Protocol server over stdio
(revision 2026-07-28, with fallback to earlier revisions). The agent can look up its identity and
delegations, query and issue records, endorse, move records through their lifecycle, read assets
and contract instances, and verify evidence from others. Every action is signed with the agent's own key, refused by the ledger if
its delegation does not cover it, and recorded with provenance: its model, a hash of the inputs it
acted on, and the digest of the tool it used. Verification reports show all of this. MCP clients
start the server without a terminal, so give it the agent key's passphrase with
`--passphrase-file` or `CEXCHAIN_PASSPHRASE`.

## Building

Requirements:

- GCC 16 (primary) or a recent Clang (tested with Clang 23)
- CMake 3.28+ and Ninja
- OpenSSL 3.5+
- Optional: the p11-kit headers, for keys on tokens (PKCS #11), and SoftHSM to test them

```sh
cmake --preset gcc-debug
cmake --build --preset gcc-debug
ctest --preset gcc-debug
```

Other presets: `gcc-release`, `clang-debug`, `clang-asan` (AddressSanitizer + UndefinedBehaviorSanitizer), and `clang-fuzz` (libFuzzer targets).

The browser verifier is tested against evidence from the native tool. A Node.js test requires its
report to match `cexchain verify --json` (and `asset verify --json`, `contract verify --json`)
exactly, and a Chromium test drives the page:

```sh
tools/wasm/build.sh
(cd tests/browser && npm ci && npx playwright install chromium)
tests/browser/run.sh build/gcc-debug/cli/cexchain build/wasm
```

`tests/cli/serve.sh` runs a server, a replica, and backups end to end; `tests/node/` covers the
HTTP parser and the API over real sockets, including a primary that serves a forged history.

Fuzz targets cover every parser of untrusted input. `make_seeds` writes valid objects (evidence bundles, access records, signed backups, passkey registrations, requests) to start each corpus from, so mutations reach the checks behind the signatures:

```sh
cmake --preset clang-fuzz && cmake --build --preset clang-fuzz
./build/clang-fuzz/fuzz/make_seeds corpus
./build/clang-fuzz/fuzz/protocol_parse_fuzz corpus/protocol_parse_fuzz -max_total_time=300
```

Test vectors in `testvectors/` come from implementations independent of CexChain. `tools/testvectors/generate.py` regenerates them.

On macOS, Homebrew's LLVM is keg-only. To use it with the Clang presets, add a `CMakeUserPresets.json` that inherits a Clang preset and sets `CMAKE_CXX_COMPILER` to `/opt/homebrew/opt/llvm/bin/clang++`. Homebrew's `openssl@3` is detected automatically.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Copyright 2026 Cirraya.
