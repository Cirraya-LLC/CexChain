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
| `bo` | The Bo contract language's compiler (in progress): language packs, the lexer, the parser, the checker, the WebAssembly emitter with its runtime, lowering a first subset of Bo, the contract text, the formatter (one contract in any language), and the source bundle a deploy records, rebuilt by verifiers. C++26 with static reflection and contracts, built with GCC 16; its front end (everything that reads source) also builds with Clang, for fuzzing |
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
| Contracts | `contract deploy`, `contract show`, `contract list`, `contract retire`, `contract create`, `contract call`, `contract instance`, `contract instances`, `contract evidence`, `contract propose`, `contract pending`, `contract consent`, `contract withdraw`, `contract send`, `contract fetch`, `contract verify`, `contract explain` |
| Bo language | `bo check`, `bo build`, `bo explain`, `bo fmt`, `bo test`, `bo stdlib list`, `bo stdlib show`, `bo packs list`, `bo packs show`, `bo packs check` (in builds with the Bo compiler); `contract deploy --bo` |

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
# The core enterprise deploys a contract written in Bo and proposes an agreement, naming the parties.
cexchain contract deploy --bo agreement.bo --as cto.key
cexchain contract create <contract> create --args '{"fields": {"price": 9800000, ...}, "parties": {...}}' --as clerk.key

# Its registrar records calls that need other parties' consents: a device with a delegation
# for calls on this contract only.
cexchain delegation grant --as root.key --to <registrar> --allow contract-call --contracts <contract>
cexchain serve --log-key log.key --registrar-key registrar.key ...

# The supplier proposes signing it; the contract names whose consents it needs. Each party sees
# the call's terms and consents on its own ledger; the last consent gets the call recorded.
cexchain contract propose <instance> sign --peer core
cexchain contract pending --peer core
cexchain contract consent --peer core --call <call> --as cfo.key --log-key log.key --send

# Anyone: verify the instance offline, every call run again, every consent checked, and the
# contract's code rebuilt from the Bo source its deploy carries.
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
existing ones carry on. `contract deploy WASM --function NAME=KIND --compiler TEXT` deploys a
module built some other way. `deploy/demo/supply-agreement.sh` walks through such an agreement,
written in Bo (`deploy/demo/supply-agreement.bo`), on one machine, narrated, with the bank's AI
agent consenting through MCP.

A call may also create instances of its contract, its *parts* (spec v0.7), such as a receivable
split among suppliers: up to 16 per call, at most 8 generations deep. A part is an instance like
any other, held by its own parties: they propose calls on it, consent to them, and fetch its
evidence, which carries its ancestors' calls up to each split, consents and all. So a bank that
takes a tier-3 part verifies its whole chain offline:

```sh
cexchain contract propose <receivable> split --peer core --args "[[h'<tier-2 ledger>', 600], [h'<supplier ledger>', 400]]"
cexchain contract instances --parent <receivable>    # the parts its calls created
cexchain contract instance <part>                    # its parent, depth, position, and ancestors
cexchain contract fetch --peer core --instance <tier-3 part> --out part.cbor
cexchain contract verify part.cbor --ledger-id <core-ledger-id>   # its ancestors first, then its own calls
```

The ledger refuses a call that creates parts on a retired contract or at depth 8; `--dry-run` and
the registrar give the ledger's reason before anything is signed.

## The Bo language

Bo is the language contracts are written in: a few keywords in English, Traditional Chinese
(Hong Kong usage), and Simplified Chinese, freely mixed, and built-in business words (pledge,
renew, suspend) with fixed meanings. Its compiler is being built: it reads every source through
*language packs*, then lexes, parses, checks, and compiles a first subset of the language to
contract code, which `contract deploy --bo` deploys with its source. Each pack maps Bo's concepts (`kw.can`,
`act.pledge`, `unit.GB`) to one language's spellings, with its reading rules (words that attach
without a space, as in `可質押` or `每GB`; full-width punctuation; `萬` and `億`; date forms), its
messages, and the sentences of the contract text. A pack never changes what runs: the same
contract compiles to the same code through any of them.

```sh
cexchain bo packs list                          # the official packs and their digests
cexchain bo packs show zh-Hant-HK               # its reading rules, keywords, and words
cexchain bo packs check company.pack            # a pack of your own, alone and with the official ones
cexchain bo packs check company.pack --language zh-Hant-HK   # messages in Traditional Chinese
cexchain bo check contract.bo                   # problems, as FILE:LINE:COLUMN: error: message (code)
cexchain bo check contract.bo --stage lex       # its tokens: 可質押 is kw.can + act.pledge
cexchain bo check contract.bo --stage parse     # its tree, the same in every language
cexchain bo check contract.bo --stage model     # its checked model, with what each rule inferred
```

The lexer reads a word only by the packs' fixed rules and never guesses: a run of characters
with two readings is an error asking for a space. So `可質押`, `can pledge`, and `可pledge` give
the same concepts; `可用率` stays one name; `500萬` is 5,000,000, `HKD 0.10` exact money, and
`5,000` an error (write `5_000`). Invisible characters are refused, and so are names that only
look alike (a Cyrillic `рау` beside `pay`), so the text the parties read is the text that runs.

The parser turns the tokens into a tree of concepts and names, so a contract gives the same tree
whatever language it is written in. Words whose argument sits on different sides in different
languages meet there: `7 days before due` and `到期前 7日`, `consent of bank` and `經 銀行 同意`.

```
can pledge to bank                     可質押 予 銀行
  over 5_000_000 requires in person      超過 5_000_000 須親身確認

can act.pledge to=role.bank            (the tree of both)
  requires cond.in_person guard=(cond.over 5000000)
```

Clauses are `contract`, `parties`, a kind and its fields (`asset Receivable`), `can` with `by`,
`to`, and `with`, `when`, and `test`; an action's block holds `requires`, `if`/`otherwise`,
`each`, `reject`, `FIELD = VALUE`, and state changes (`active -> suspended`). `=` sets a field at
the start of an action's line and compares inside a condition. Ambiguity is an error, never a
guess: `a < b < c`, or `monthly HKD 120 * 12` (which words does `*` take?), ask for a rewrite, and
`可提款` is read as `可` + `提款` only when the contract declares `提款` and not `可提款`.

The checker reads the tree into a model: the parties, the one kind of instance and its fields,
the states, the actions, and the time rules, with every name resolved and every expression typed.
Money never mixes currencies, quantities never mix dimensions (TB and GB convert; TB and items do
not), months never mix with days, and every value is exact in its smallest unit (cents, bytes,
millionths of a rate): `HKD 0.001` is an error, never a rounding. Lists are bounded, actions never
recurse, and every state must be reachable. Whatever Bo infers rather than reads carries the id of
the fixed rule that inferred it, which the contract text spells out:

```
asset Receivable                       party role.bank bound=act.pledge{R3}
  amount HKD                           field field.holder instance party = role.supplier{R2}
  holder supplier                      state state.active first{R4}
can pledge to bank                     can act.pledge standard to=role.bank agents=delegation{R14}
  over 5_000_000 requires in person      consent role.bank{R3}
                                         requires cond.in_person{R13} guard=(cond.over (money cur.HKD 5000000){R6})
```

The bank is bound to a ledger by the pledge, with its consent (R3); the holder starts as the
supplier and may change (R2); `over 5_000_000` takes the unit of the action's one amount (R6); in
person asks the starter's presence (R13); an AI agent may act within its delegation unless the
action says it only proposes (R14). Clauses that ask the outside world to act (notify, or
suspending a service) are accepted with a warning: executors come in a later step.

Packs are files in CBOR diagnostic notation; `bo/packs/` holds the official ones. A pack's digest
is the hash of its canonical CBOR, and a deploy records the packs its source was read with, so
anyone can rebuild the contract from the source and compare. Bo never guesses: one spelling with
two meanings, in one pack or across the packs a source is read with, is an error, and so is a
word that an attaching rule could split into two others.

The compiler uses C++26 static reflection and contracts, which GCC 16 builds and Clang does not
yet. The `bo` commands therefore exist only in builds made with GCC 16 (the `gcc-*` presets, the
release build, and the Docker image); `cexchain version` says whether a build has them. The
browser verifier never needs the compiler: verifying a contract replays its code.

Compiled contracts are WebAssembly modules in the contract profile, written by the compiler's own
emitter, with a small runtime it adds as needed: reading the call's input (checked inside the
contract to be deterministic CBOR, exactly as core decodes it), writing the output, checked 64-bit
arithmetic (an overflow refuses the call), multiply-divide on 128 bits with the rounding modes
half up, half even, and down, civil dates at a fixed UTC offset with month ends clamped, and text
comparison. Every routine runs to the same outcome, output, and fuel on the ledger's interpreter
and on the independent Python interpreter (`ctest -R bo_reference`, with Python 3);
`tests/bo/golden/runtime/fuel.txt` lists what each costs of a call's 10 million fuel.

The compiler now lowers a first subset of Bo to such modules: creation, the contract's own
actions with their inputs, fields, states, `requires` (with a guard such as `over 1_000_000`),
`if` and `otherwise`, `reject`, consents, and `in person`, over numbers, money, quantities,
rates, dates, durations, texts, yes or no, and parties. Each action is a function named by its
concept or as written (the same name in every language), and creation is `create` (`issue` for
an asset). Arguments are a map: `{"fields": {...}, "parties": {role: ledger}}` to create, the
action's inputs by name otherwise (money in cents, rates in millionths, dates in milliseconds).
A compiled contract asks for the consents an action needs (of its starter, of a role it binds,
of a party a changed field held, and of every `requires consent of`) with `[2, needs]`, the
home's own consent being the call itself; it keeps `{"state": NAME, "fields": {...}}`, reports
the state as the status, the parties and every field holding one, each state change as an
event, and the instance as final once no action can leave its state; and it refuses with the
text of a `reject` or with `bo:CODE` (`bo:requires sign 2`), which tools show in the reader's
language. The same contract in English, Traditional Chinese, Simplified Chinese, or mixed
compiles to the same bytes; `tests/bo/golden/build/` holds a two-party agreement in each, and the
fuel of each of its calls. The vocabulary's asset, service-state, and resource actions compile
with the standard library's terms, `when` rules compile to functions a keeper calls, and lists
and charges compute bills (all below). What later steps bring (executors, and the built-in
actions whose terms come later) is refused with a message for now. `testvectors/bo-v1.json`
(`tools/testvectors/bo_vectors.py`) pins sources, code, and outcomes, checked on both
interpreters.

```sh
cexchain bo build agreement.bo                  # code, hash, compiler, and the source bundle
cexchain bo build agreement.bo --out agreement.boc --hash sm3   # to deploy on an SM3 ledger
cexchain contract deploy --bo agreement.bo --as root.key        # build and deploy in one step
cexchain contract show <contract>               # its source bundle, and whether it rebuilds
cexchain contract verify evidence.cbor --ledger-id <home>       # ... and every instance's
```

A Bo deploy records the code, its interface, the language `bo`, the compiler (`cexchain-bo
RELEASE; codegen N; edition E`), the contract's name, and its source as a *bo-source bundle*
(spec section 15): the source as written, comments included (`bo build` warns that they are
published), its edition, and each language pack it was read with, by id, version, and digest
under the home's hash, the packs that are not official embedded in full. `contract show` and
`contract verify` rebuild the code from it and compare the bytes: "rebuilds"; "DOES NOT
REBUILD" when the compiler the deploy names builds something else (the source is not the
code's, and verification fails); "MALFORMED" when there is no usable bundle; or "not rebuilt"
when another compiler, release, or codegen version built it (named, never called a forgery) or
the build has no compiler. `contract verify --require-rebuild` accepts only "rebuilds".

### The contract text

What the parties read and confirm before they sign is the *contract text*, which Bo writes from
the contract in English, Traditional Chinese (Hong Kong usage), or Simplified Chinese: the
parties and when each is bound to a ledger, what each instance records, the states (the first,
the final ones, and the events), each action (who starts it, the consents it needs, its
requirements, numbered as a refusal such as `bo:requires sign 2` names them, its state changes,
and what AI agents may do), the time rules, and the rules Bo applied. Whatever Bo inferred
instead of reading it is spelled out in its clause and marked with its rule (`[R3]`, `〔R3〕`), and
the last section explains each rule used. Texts are always shown in quotation marks, including a
name Bo read as a text (R18: `客户所在地 = 中国内地` reads as `the customer location is
"中国内地"`). One contract gives the same text, byte for byte, whatever language its source was
written in; `tests/bo/golden/explain/` holds the text of each example in each language.

```sh
cexchain bo explain agreement.bo                         # before a deploy
cexchain bo explain agreement.bo --language zh-Hant-HK   # or set CEXCHAIN_LANGUAGE
cexchain contract explain <contract or instance>         # from the deploy, only if it rebuilds
```

```
4.2 sign
  4.2.1 Started by the customer, whose agreement it needs.
  4.2.2 Requirement 1: if the amount is over HKD 1,000,000, the customer must prove presence in
        person, with a passkey or a hardware key. [R6, R13]
  4.2.3 Requirement 2: the time of the call is before starts.
  4.2.4 If the instance is proposed, it becomes signed; otherwise the call is refused.
  4.2.5 An AI agent may start it within its delegation. [R14]
```

`contract explain` reads the source the deploy carries exactly as `contract verify` rebuilds it
(with the language packs it names, at their versions) and writes the text only if that source
rebuilds to the deployed code, so the text is the text of the code that runs; otherwise it says
why. For an instance, it shows its state and fields in the same words first (`amount: HKD
250,000.00`, `starts: 1 January 2030`). Messages follow `--language` or `CEXCHAIN_LANGUAGE`
everywhere the compiler reports, refusals of compiled contracts included.

### One contract, any language

`bo fmt` lays a source out canonically (two spaces per block, one space between words, comments
where they were) and, with `--language`, writes every keyword and word in one language. Names the
contract gives, texts in quotes, and comments stay as written. A contract written in Chinese can
so go to an English-speaking counterparty as English source: it parses to the same tree, checks
to the same model, builds to the same code, and explains to the same text.

```sh
cexchain bo fmt agreement.bo --check                     # is it formatted? (exit 3 if not)
cexchain bo fmt agreement.bo --language en               # the English source, on stdout
cexchain bo fmt agreement.bo --language zh-Hant-HK --write
```

```
requires consent of supplier          須經 供應商 同意          须经 供应商 同意
when 7 days before due notify bank    當到期前 7日 通知 銀行    当到期前 7天 通知 银行
```

Chinese is written as Chinese is: a keyword joined to the word after it (`可質押`, `須經`), a
number to its Chinese unit (`30日`, `500萬港元`); Latin words stand apart (`每 GB`). A word whose
argument sits on the other side in another language (`7 days before due`, `到期前 7日`) moves
around it, with parentheses where it would otherwise take a different argument. The text is not
reversible, though the contract is: a multiplier English lacks is written out (`500萬` is
`5_000_000`), and words become each language's first spelling (`pays`, then `支付`, then `pay`).
Before printing anything, `bo fmt` reads its result again; if words would read together in the
new language as another word, it says where and changes nothing.

### Tests

A contract carries its own tests: `test` blocks of steps, each a party, an action, and
optionally what it gives, when, and how it is signed, then what should happen.

```
test "nobody signs alone"
  we create with goods = "Bearings", pieces = 20_000, price = CNY 1_250_000, deliver_by = 2026-12-01
  we sign -> consent of bank             # the call waits for the bank's consent
  supplier sign -> consent of we         # we start sign: the supplier cannot alone
  we close -> refused "bo:state close"   # not signed yet
```

`bo test` builds the contract and runs each test on an instance of its own, exactly as a ledger
runs calls: every party a test names is a ledger of its own (a name the contract does not
declare, such as `bank1`, is a ledger only the test names, to which `to bank1` binds a role);
the first step creates the instance, and its party is the home. A call runs first without
consents; every party the contract asks then consents, except those the step expects it to wait
for and, when the step's party does not start the action, the party that does. `in person` signs
as a person who proves presence, `by AI agent` as an agent; `at DATE` moves time on (a test
starts on 2026-01-01). Expectations are a state (`-> signed`), a refusal (`-> refused`, or with
the contract's reason in quotes), or a wait (`-> consent of bank`); a step without one expects
an accept. The report shows each step as written and what happened, worded in `--language`, and
for a refusal the clause of the contract text it comes from; the results are the same whatever
language the contract and its tests are written in. Exit status 3 if a test fails.

```sh
cexchain bo test agreement.bo
cexchain bo test agreement.bo --language zh-Hans-CN --json
```

### The standard library

The built-in business actions are written in Bo itself, in a standard library compiled into the
compiler (`bo/stdlib/edition1.bo`): transfer, pledge, release, enforce, redeem, pay, confirm
payment, dispute, freeze, unfreeze, and cancel, with the semantics of CexChain's native assets
(spec section 13); split, which makes parts of an asset (below); suspend, resume, and terminate,
on the home's own word; and allocate and reclaim for resources. A contract that writes `can pledge to bank` gets the library's pledge: the
holder starts it, the holder and the bank consent, only an active asset can be pledged (so no
second pledge), and the bank becomes the pledgee. The lines a contract writes under a built-in
action add to its terms and are checked first (`over 5_000_000 requires in person`); without
`to`, each call names the counterparty, who consents. The contract text states every standard
term, marked R19. To change a built-in action, copy it under a name of your own: it is then the
contract's own action.

```sh
cexchain bo stdlib list                                  # who starts each, and its states
cexchain bo stdlib show pledge                           # its source, to copy, and its text
cexchain bo stdlib show 質押 --language zh-Hant-HK
```

```
can pledge to counterparty by holder
  requires not counterparty = holder
  active -> pledged
  pledgee = counterparty
```

Each instance then keeps the pledgee and the payee (none until an action sets them), and an
unfrozen asset returns to the state it was frozen in (`frozen -> previous state`). Run on the
same calls, a Bo receivable and a Bo warehouse receipt built from the library give the native
rules' states, holders, pledgees, payees, quantities, consents, and refusals
(`tests/bo/assets_test.cpp`).

#### Splitting, for multi-tier supply-chain finance

`can split` gives a receivable the library's split: its holder divides it among recipients, each
part an instance of its own (spec v0.7) held by its recipient, one tier down, and the receivable
ends (`divided`). The holder and every recipient consent (so at most 15 recipients besides the
holder), each part is at least the currency's smallest unit, the parts add up to the amount,
and only an active asset splits, so not while pledged. A part at depth 8 splits no further
(`bo:depth split`). The template ends with the statement that makes the parts, which a copy of
it can change:

```
can split by holder with parts, recipients
  requires count of recipients = count of parts
  requires count of recipients <= 15 or holder in recipients
  each part in parts
    requires part > 0
  requires sum of parts = amount
  requires consent of recipients
  active -> divided
  issue parts to recipients with tier = tier + 1
```

`issue PARTS to RECIPIENTS` (R30) makes each part an instance with the instance's fields, its
amount the part and its holder the recipient in the same place, `with` setting others; fields
Bo adds start empty, and the part starts in the first state. A part's evidence carries the
history of the instances it came from, the other parts of each split included, which the
contract text states. In tests, a step acts on the part its party holds (or names the holder:
`issuer pay forge`), and the report names parts by path (part 1.2).

```sh
cexchain contract propose <receivable> split --peer core \
    --args "{\"parts\": [60000000, 40000000], \"recipients\": [h'<tier-2 A>', h'<tier-2 B>']}"
cexchain contract pending --peer core            # a recipient sees the call it is asked to consent to
cexchain contract consent --peer core --call <call> --as root.key --log-key log.key --send
```

An action can let AI agents only propose it (`AI agent can propose`): an agent's call is then
kept with the instance as a proposal, and a person who proves presence approves it with the
function `approve`, which runs it with every requirement checked. In a test, `bank1 release by
AI agent -> pending approval`, then `bank1 approve in person -> active`.

### Time rules and keepers

A ledger acts only on calls, so a `when` rule compiles to a function of its own, `when.ACTION`
(`when.suspend`), that anyone the home delegates may call: a *keeper*, usually a device of the
home that calls it on a schedule. The rule applies only once the ledger's registration time
reaches the rule's time, and once for each such time; an earlier call is refused, and nothing
is recorded. The rule is the contract's own word: the actions it does need only the consents the
contract states, not their starters'. Its event records the time it applied at and how late the
call came. A rule fires at:

| Event | Fires | Example |
|---|---|---|
| a date | on that day | `when due + 1 month` (month ends clamp: 31 January plus a month is the end of February) |
| N before due | from N before the due date | `when 7 days before due` |
| overdue, overdue N | the day after the due date; N after it | `when overdue 3 days suspend` |
| a state held N | N after the instance entered the state | `when suspended 30 days terminate` |

Any of these may be joined to other conditions with `and` (`when 7 days before due and active`).
`when due issuer pays` names a party's duty: it says when an instance is due and overdue, and
nothing is called. In actions, `within 14 days` means less than 14 days since the instance last
changed state; `overdue`, `overdue N`, and `N before due` hold from those times on. Dates and days
are counted at a fixed offset from UTC, all year: `UTC offset "-05:00"` in the kind's block, or
+08:00 (R25). A resource allocated with the standard library goes to one holder at a time: each
allocation names it, with its consent (R23), and after a reclaim it cools for its cooling period
before it is allocated again.

```sh
# The keeper: a device whose delegation covers this contract's calls only.
cexchain actor add --as root.key --kind device --name Keeper --key keeper.pub
cexchain delegation grant --as root.key --to <keeper> --allow contract-call --contracts <contract>
# Has the rule's time come? Ask at any time; a dry run records nothing.
cexchain contract call <instance> when.suspend --as keeper.key --dry-run --at 2027-07-03
# On its schedule (cron, say), the keeper calls each rule; one whose time has not come is refused.
cexchain contract call <instance> when.suspend --as keeper.key
```

A keeper that is sometimes off (a personal computer) fires late, never early, and the event
shows how late. In tests, the keeper is a step: `keeper suspend at 2027-07-02 -> refused
"bo:when when.suspend"`, then `keeper suspend at 2027-07-03 -> suspended`; it calls, as a device
of the home, the rule that does that action (for a rule that does none, the state its first state
change leads to, such as `keeper closed`).
Nothing yet stops one IP address from being in two instances of a contract: unique keys across
instances come later.

### Lists and charges

A field or an input may be a list, of at most 16 items unless `at most N` says otherwise (1,000
at most): `codes list text at most 3`. A list given as an argument is checked when it is read
(longer ones are refused), `each n in rows` runs its block once for each item (requirements,
choices, refusals, and fields set; no state change), and `sum of rows`, `count of rows`, and
`"x" in codes` read it. One value where a list is needed is a list of that one item (R29).

Taxes, fees, commissions, and surcharges are *charges*, which the contract defines: there are no
built-in tax templates. A field named by a document, such as `invoice list HKD`, holds the lines of
a bill; each time it is set (when an instance is created, or by an action), the charges are
computed on its lines at the time of that call, and the instance keeps the bill as it was made
(R26): a later rate never changes a bill already made. The spec's VAT, in Simplified Chinese:

```
记录 销售单
  发票 列表 人民币 最多 20

费用 增值税
  税率 6%
  适用 客户所在地 = 中国内地
  另计
  按发票 四舍五入
  从 2027-01-01 起 税率 9%
```

A charge is a rate (in millionths) or a fixed amount; it applies always or when a condition
holds; it is `included` in the price (taken out of it) or `added` to it; it is rounded on each
line (`per line`, the default) or once per bill (`per document`, `according to invoice`), half up
(the default), half even, or down; and with `according to price, other` it is computed on the
price and on charges written before it (R27). Its rate is the one in force at the bill's time
(R28). Bills of 100.00 and 10.05 yuan: 6% of 11005 fen is 660.3, so 660, and the total is 116.65
yuan until 2026 ends; 9% from 2027-01-01 gives 990.45, so 990, and 119.95 yuan. The state keeps
`"bill": {"time", ? "lines", "price", "total", "charges": {NAME: {? "rate", "amount"}}}`, the
call records it as the event `[invoice, bill]`, and a charge's name in an action is its amount on
the bill (`requires payment = sum of invoice + 增值税`). `tests/bo/golden/test/tax/` and
`test/charges/` show the arithmetic of their tests; `tests/bo/golden/build/vat-amounts.txt` holds
the VAT written every way it can be (added or included, each rounding, per line or per bill) on
both sides of its rate change, which the Python reference computes again with its own integers.

## AI agents (MCP)

`cexchain mcp --ledger DIR --as AGENT_KEY` runs a Model Context Protocol server over stdio
(revision 2026-07-28, with fallback to earlier revisions). The agent can look up its identity and
delegations, query and issue records, endorse, move records through their lifecycle, read assets
and contract instances, and verify evidence from others. Every action is signed with the agent's own key, refused by the ledger if
its delegation does not cover it, and recorded with provenance: its model, a hash of the inputs it
acted on, and the digest of the tool it used. Verification reports show all of this. MCP clients
start the server without a terminal, so give it the agent key's passphrase with
`--passphrase-file` or `CEXCHAIN_PASSPHRASE`.

Agents take part in contracts too. On their own organization's ledger they create and call
instances (`cexchain_call_contract`): the contract runs first, and the result says what it decided,
whether it accepted the call, whose consents it still needs, or why it refuses. With another
organization's registrar they review the calls it holds and the instance itself
(`cexchain_list_pending_calls`, `cexchain_fetch_instance`), propose calls
(`cexchain_propose_contract_call`), and consent on their own ledger
(`cexchain_consent_contract_call`). A consent travels as evidence, so start the server with the
ledger's `--log-key` to let the agent consent. Arguments are CBOR diagnostic notation, as on the
command line. `cexchain mcp --help` lists every tool.

## Building

Requirements:

- GCC 16 (primary) or a recent Clang (tested with Clang 23)
- CMake 3.28+ and Ninja
- OpenSSL 3.5+
- Optional: the p11-kit headers, for keys on tokens (PKCS #11), and SoftHSM to test them
- Optional: Python 3, to check the Bo runtime on the reference interpreter

```sh
cmake --preset gcc-debug
cmake --build --preset gcc-debug
ctest --preset gcc-debug
```

Other presets: `gcc-release`, `gcc-asan` (the Bo compiler's tests with AddressSanitizer + UndefinedBehaviorSanitizer), `clang-debug`, `clang-asan` (AddressSanitizer + UndefinedBehaviorSanitizer), and `clang-fuzz` (libFuzzer targets).

The Bo compiler (`bo/`) needs GCC 16 for C++26 static reflection and contracts. `CEXCHAIN_BO`
chooses: `AUTO` (the default) builds it when the compiler can, `ON` (the GCC presets) requires
it, `OFF` leaves it out. Clang builds everything else, the compiler's front end included, so
that libFuzzer can fuzz what reads untrusted source.

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

Fuzz targets cover every parser of untrusted input, Bo language packs included. `make_seeds` writes valid objects (evidence bundles, access records, signed backups, passkey registrations, requests, the official packs) to start each corpus from, so mutations reach the checks behind the signatures:

```sh
cmake --preset clang-fuzz && cmake --build --preset clang-fuzz
./build/clang-fuzz/fuzz/make_seeds corpus
./build/clang-fuzz/fuzz/protocol_parse_fuzz corpus/protocol_parse_fuzz -max_total_time=300
```

The Bo compiler's lowering is GCC-only and libFuzzer is Clang-only, so its fuzzer, `bo_build_fuzz`, is a GCC program that drives itself: it generates contracts from random bytes, compiles them written in English and in mixed languages (which must give the same bytes), and runs the code on generated calls (`build/gcc-asan/tests/bo_build_fuzz -max_total_time=120`).

Test vectors in `testvectors/` come from implementations independent of CexChain. `tools/testvectors/generate.py` regenerates them; `tools/testvectors/bo_vectors.py` writes the Bo compiler's from a GCC build.

`tools/ci-local.sh` runs the Linux jobs of the CI workflow in CI's container image under Podman (or Docker), with logs in `build/ci-local/`.

On macOS, Homebrew's LLVM is keg-only. To use it with the Clang presets, add a `CMakeUserPresets.json` that inherits a Clang preset and sets `CMAKE_CXX_COMPILER` to `/opt/homebrew/opt/llvm/bin/clang++`. Homebrew's `openssl@3` is detected automatically.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Copyright 2026 Cirraya.
