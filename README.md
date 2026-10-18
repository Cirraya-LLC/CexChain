# CexChain

**Register, move, and prove anything, under rules you define.**

CexChain keeps a verifiable history of anything you choose to keep: a document, a photo, a
camera lent to a friend, an approval, a membership, a debt. You decide what a thing is, the
rules it follows, and whose agreement each step needs. Every step is signed by the person,
AI agent, or device that took it, and anyone can verify the whole history offline, without
trusting your database or any platform. It runs for one person on one computer, and for
organizations on servers and clusters, with ledgers that work with each other's.

Like a spreadsheet, CexChain knows nothing of what you keep in it: there are no built-in
purchase orders, invoices, or certificates. Those are things you define, and the
[examples](examples/) show how such things are built.

> **Status:** early development (specification v0.9 draft: [the protocol in prose](spec/README.md), [`spec/cexchain.cddl`](spec/cexchain.cddl); the contract language: [`spec/bo.md`](spec/bo.md)). Interfaces and formats may still change. Planned, not built yet: connectors for billing and accounting systems (Zoho first), a local web console, installers, and a public witness service; see [Known limits](#known-limits).

## Why

- Documents, photos, approvals, and promises move between people and organizations as files,
  scans, stamps, and messages. Checking them is slow, and disputes are hard to settle.
- AI makes forgery nearly free, and AI agents increasingly act for people and companies.
  Looking genuine no longer proves anything; cryptographic provenance does. And when an agent
  acts, someone must be able to show who authorized it and who answers for it.

## How it works

- **Things you define.** A *record* is a document of a type you name, such as
  `example.org.photo/1`: its fields stay private until you disclose them (the ledger keeps
  salted commitments), its files are committed by hash, and it can be endorsed in any role
  and revoked. Anything that follows rules is an *instance* of a *contract* you write in
  [Bo](#the-bo-language), whose keywords read as English, Traditional Chinese, or Simplified
  Chinese: its fields and states, the actions on it, who may take each, whose consent each
  needs, what must hold (a passkey in person above an amount, say), and what happens as time
  passes.
- **Consent where each party keeps its own ledger.** A step that concerns another party waits
  for that party's consent, given on its own ledger and naming that one step. There is no
  shared database and no platform in the middle.
- **Evidence anyone can check.** One file proves a record's or an instance's complete history:
  who did what, under whose authority, which fields were disclosed, and, for an instance,
  every contract call run again. It verifies offline, on the command line or in a
  self-contained browser page that uploads nothing.
- **Witnesses.** Independent parties (a friend, a partner, an auditor) cosign a ledger's
  checkpoints only if its history extends what they saw before, so nobody can rewrite or fork
  their own history unseen.
- **Accountable people, AI agents, and devices.** Every action names who took it and under
  whose delegation. A person's action carries proof of presence (a passkey, or a USB key and
  its PIN); anything without it is attributed to a machine. AI agents act through MCP with
  their own keys and delegations, their model recorded, and a person accountable for them.
- **Requests and executors.** Contracts decide; they never act on the outside world. A call may
  ask for work outside the ledger (send a notice, call another system): a *request*, which an
  executor (a device or an AI agent with a narrow delegation) or a person answers with a signed
  call: done, failed, or expired. Every request and answer is in the instance's evidence. A
  *keeper* inside the server fires contracts' time rules when they are due and expires
  overdue requests. `executor run` carries requests out through connectors (a webhook, a
  command, or any program that speaks the connector protocol) and answers them, acting only on
  requests it has verified in the signed log.

## Who it is for

- **One person, on one computer.** A ledger is a directory; keys are encrypted files, with a
  passkey or a USB key for proof of presence; evidence is a file you hand over. Today you use
  it from the command line; a local web console and installers are planned.
- **An organization.** Staff, AI agents, and devices act with rights the organization's root
  key delegates, which can only narrow. `cexchain serve` runs a ledger over HTTP with API
  tokens; replicas, backups, and Raft clusters keep it available; a Docker image runs it.
- **Several parties.** Each keeps its own ledger. They pin each other's ledgers, ask for and
  grant access to records, consent to each other's contract calls, and witness each other's
  checkpoints. A shared registry and governance for larger federations is planned.

## Design principles

- **Verifiable, not just "on chain."**
  - Tamper-evident history: a Merkle log with inclusion and consistency proofs.
  - Non-repudiation: every action is signed.
  - Independent verification: any third party can check a record without trusting its issuer's database.
- **Sovereign first.**
  - A single person or organization gets value on day one.
  - External witnesses co-sign checkpoints, so history can be neither rewritten nor forked.
  - Ledgers work together without a platform between them.
- **Documents stay off-chain.** The ledger holds salted commitments, signatures, state transitions, grants, and access records. Content is encrypted and stored separately.
- **Generic by design.** The protocol knows records, contracts, consents, access, witnesses, and evidence, nothing of any industry. What a thing is, its users define.
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
| `cli` | `cexchain` command-line tool: full control of keys, ledgers, actors, delegations, records, contracts, proofs, and evidence |
| `cexchain mcp` | MCP server through which an AI agent acts under its own key and delegation |
| `examples` | Complete stories built on the generic core, each a Bo contract with its tests and a narrated script ([below](#examples)) |

## Quick start

A ledger of your own, and a photo registered on it as a record of a type you name:

```sh
# Private keys are encrypted (PKCS #8, scrypt + AES-256). Passphrases come from
# a prompt, --passphrase-file, or $CEXCHAIN_PASSPHRASE.
cexchain key generate --out root.key
cexchain key generate --out log.key
export CEXCHAIN_LEDGER=./ledger
cexchain init --name "Alice" --root-key root.key --log-key log.key

# The root key registers who acts: you with an everyday key (keep the root key
# offline), and in an organization its staff, AI agents, and devices.
cexchain key generate --out alice.key && cexchain key public alice.key --out alice.pub
cexchain actor add --as root.key --kind person --name "Alice" --key alice.pub
cexchain delegation grant --as root.key --to <alice-id> \
    --allow record-register,record-endorse --record-types example.org.photo/1 --days 30

# Register the photo; field values stay private until disclosed.
cexchain record issue --as alice.key --type example.org.photo/1 \
    --field place="Victoria Harbour" --field taken=2026-10-16 --attach photo.jpg
cexchain record history <record-id>

# Checkpoint, export evidence with one field disclosed, and verify it anywhere.
cexchain checkpoint create --log-key log.key
cexchain export <record-id> --log-key log.key --disclose taken --with-attachments --out evidence.cbor
cexchain verify evidence.cbor --ledger-id <ledger-id> --attachment photo.jpg=photo.jpg
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

### A first contract

A record has one lifecycle: registered, endorsed, revoked. A thing with rules of its own is an
instance of a contract. Lending a camera, in Bo:

```
contract Lending
parties owner

thing Item
  name text
  holder owner

can lend to counterparty by owner
  active -> lent
  holder = counterparty
can bring_back by holder
  lent -> active
  holder = owner
```

The owner lends to whoever each call names, who must consent on their own ledger; only the
holder brings it back; and while it is lent, the contract refuses another loan. The same source,
with its tests, is [`examples/lending/lending.bo`](examples/lending/lending.bo). Deploy it and
register a camera (this needs a build with the Bo compiler, below):

```sh
cexchain bo test lending.bo           # the tests the contract carries
cexchain bo explain lending.bo        # the contract text the parties read, in English or Chinese
cexchain contract deploy --bo lending.bo --as root.key
cexchain contract create <contract> create --as root.key \
    --args "{\"fields\": {\"name\": \"Camera X100\"}, \"parties\": {\"owner\": h'<ledger-id>'}}"
cexchain contract call <camera> lend --args "{\"counterparty\": h'<friend-ledger-id>'}" \
    --dry-run --as root.key           # the contract needs the friend's consent
```

[`examples/lending`](examples/lending/) runs the whole story with two people on one computer:
the friend checks the camera's evidence offline, consents on his own ledger, and brings it
back, and anyone verifies the history.

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
| Contracts | `contract deploy`, `contract show`, `contract list`, `contract retire`, `contract create`, `contract call`, `contract instance`, `contract instances`, `contract evidence`, `contract propose`, `contract pending`, `contract consent`, `contract withdraw`, `contract send`, `contract fetch`, `contract verify`, `contract explain` |
| Requests | `request list`, `request show`, `request answer`, `request cancel`, `request wait` |
| Executors | `executor add`, `executor list`, `executor show`, `executor revoke`, `executor run`, `executor check`, `executor connector add\|list\|show\|remove`, `executor secret set\|list\|remove`, `executor journal list\|show`; `connector webhook`, `connector command` |
| Keepers | `keeper add`, `keeper list`, `keeper show`, `keeper revoke`, `keeper due`, `keeper run`; `serve --keeper-key` |
| Bo language | `bo check`, `bo build`, `bo explain`, `bo fmt`, `bo test`, `bo stdlib list`, `bo stdlib show`, `bo vocab list`, `bo vocab show`, `bo vocab check`, `bo packs list`, `bo packs show`, `bo packs check` (in builds with the Bo compiler); `contract deploy --bo` |

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
# The ledger's owner: register it. (A stolen signing key cannot enroll a thief's passkey.)
cexchain actor set-presence <alice-id> --as root.key --credential alice.passkey
# Require presence for what matters...
cexchain delegation grant --as root.key --to <alice-id> --allow record-endorse --require-presence
# ...and confirm with the passkey when acting.
cexchain record endorse <record-id> --as alice.key --role approver --presence
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
cexchain record endorse <record-id> --as alice.key --role approver \
    --presence-key "pkcs11:token=UKey;object=alice-presence?module-path=/path/to/vendor.so"
```

Every verification report shows, for each step a person took, whether they proved presence and
how (a passkey or a hardware key). The browser verifier shows it too.

## Keys on tokens and HSMs

Wherever a command takes a key file, it also takes an RFC 7512 PKCS #11 URI, so a ledger's root
key can stay in an HSM or on a USB key, and a person's signing key on a USB key. Keys generated with
`key generate --pkcs11` are marked sensitive and never leave the token. ESP256 and Ed25519 work
with any PKCS #11 module; SM2 needs the vendor's mechanism number in the URI
(`?x-sm2-mechanism=<hex>`), since SM2 is not part of the PKCS #11 standard. Every signature a
token returns is checked before it is used.

## Rotating a ledger's keys

A ledger's owner can replace its root key and the ledger's log key, for instance when a key is
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
friend, a partner, an auditor, or a regulator. It remembers the last checkpoint it cosigned for each
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
page: the same verification code as `cexchain verify` and `contract verify`, compiled to
WebAssembly together with OpenSSL and the contract interpreter. It takes a record's evidence bundle
or a contract instance's evidence, which it checks by running the contract again on every call. It
runs entirely in the browser and uploads nothing. It works offline, even opened from disk, and it
can be hosted on any static web server.

```sh
tools/wasm/build.sh            # needs Emscripten; writes build/wasm/cexchain-verify.html
```

Publish a record's evidence bundle, then print a QR code on the document, or beside the photo:

```sh
cexchain qr <record-id> --bundle-url https://example.com/evidence/photo-1016.cbor \
    --verifier-url https://example.com/verify.html --out photo-1016-qr.svg
```

Scanning the code opens the verifier with the ledger id, the record id, and the bundle's location.
The page refuses evidence about another record or from another ledger, and shows who did what,
person or AI agent, under whose authority.

## Running a ledger as a service

`cexchain serve` exposes a ledger over HTTP (API v1, described by `cexchain serve --help`). Signed
statements are the authorization: the server only checks API tokens, which gate access because
statements reveal metadata. The server holds the ledger's lock only while it writes, so
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
cexchain record issue --as alice.key --type example.org.photo/1 --field taken=2026-10-16
cexchain checkpoint create                    # the server signs (admin token); the client checks
cexchain export RECORD --disclose taken --vault-key vault.key --out evidence.cbor
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
three-member cluster on one Docker host, with an executor service beside it.


## Working with other parties

Two parties, each with its own ledger, can share records without a platform between them. Say a
reviewer asks another organization for one of its records:

```sh
# Each side pins the other's ledger by its id, learned through a channel they trust.
cexchain peer add holder --ledger-id <holder-ledger-id> --url https://ledger.holder.example --token-file holder.token
cexchain peer add reviewer --ledger-id <reviewer-ledger-id> --url https://ledger.reviewer.example ...

# The reviewer asks (a request record on its own ledger, with a key made for this request).
cexchain access request --peer holder --record <id> --purpose "annual review" \
    --fields result --attachments report.pdf --as reviewer.key --log-key log.key --send

# The holder sees who asked and under whose authority, and grants (a grant record on its ledger).
cexchain access inbox
cexchain access grant <request> --as approver.key --log-key log.key --attach report.pdf=report.pdf

# The reviewer fetches and checks everything against the holder's ledger, then acknowledges
# (a receipt record on its ledger, sent back).
cexchain access fetch --peer holder --request <request> --out delivery.cbor
cexchain access accept delivery.cbor --as reviewer.key --log-key log.key --save-dir received --send
```

Each step is a record on the acting party's own ledger, so delegations decide who may request,
grant, or acknowledge, and proof of presence shows when a person approved. Each side checks the
other's step with the offline evidence verifier, pinned to the peer's ledger id. The delivery
holds the grant's evidence and the record's, with only the granted fields and attachments, sealed
with HPKE to the request's key. The recipient checks every field and file against the record's
commitments. Revoking a grant (`record revoke`) stops future deliveries, and receipts make access
accountable. The same exchange works with files instead of the API (`--out`, then
`access grant FILE`, `access accept FILE`, `access receipt FILE`).

Two parties can also witness each other's ledgers. `cexchain serve --witness-dir DIR
--witness-key KEY` cosigns a peer's checkpoints online, and the peer runs
`cexchain checkpoint cosign-request --peer NAME --send`. No third party is needed for neither side
to be able to rewrite its history unseen.

## Contracts

A contract is a WebAssembly module deployed on a ledger, its *home*, that governs *instances*:
the things its rules are about, whatever they are. The home records a call on an instance only
if the contract, run on the call, accepts it. Parties on other ledgers consent on their own
ledgers, and anyone holding an instance's evidence runs the contract again on every call.
Contracts run in a deterministic, integer-only profile with metered fuel, so every verifier, the
browser included, reaches the same result. A home and parties on other ledgers:

```sh
# The home deploys a contract written in Bo and creates an instance, naming the parties.
cexchain contract deploy --bo rules.bo --as root.key
cexchain contract create <contract> create --args '{"fields": {...}, "parties": {...}}' --as clerk.key

# Its registrar records calls that need other parties' consents: a device with a delegation
# for calls on this contract only.
cexchain delegation grant --as root.key --to <registrar> --allow contract-call --contracts <contract>
cexchain serve --log-key log.key --registrar-key registrar.key ...

# Another party proposes a call; the contract names whose consents it needs. Each party sees
# the call's terms and consents on its own ledger; the last consent gets the call recorded.
cexchain contract propose <instance> sign --peer home
cexchain contract pending --peer home
cexchain contract consent --peer home --call <call> --as approver.key --log-key log.key --send

# Anyone: verify the instance offline, every call run again, every consent checked, and the
# contract's code rebuilt from the Bo source its deploy carries.
cexchain contract fetch --peer home --instance <instance> --out instance.cbor
cexchain contract verify instance.cbor --ledger-id <home-ledger-id>
```

Arguments are written in CBOR diagnostic notation: JSON without floating point, plus byte strings
(`h'00ff'`), keys of any type, and tags (`--args-cbor FILE` takes them encoded). `contract call
--dry-run` shows what the contract would do. A consent names exact terms, among them the instance's
*head* and a digest of the arguments, so it applies to one call, once. Without a registrar, the
home's people record calls with consents as files (`contract call <instance> sign --consent
a.cbor --consent b.cbor`). `contract verify` shows each call, its outcome, and who consented: a
person who proved presence, a key alone, or an AI agent and its model. The browser verifier shows
the same report. Delegations can be limited to contracts (`delegation grant --contracts`), and
`contract retire` stops new instances while existing ones carry on. `contract deploy WASM
--function NAME=KIND --compiler TEXT` deploys a module built some other way. The
[examples](#examples) walk through contracts end to end, narrated, from two people lending a
camera to organizations whose AI agents consent through MCP.

A call may also create instances of its contract, its *parts* (spec v0.7), such as one thing
divided among several holders: up to 16 per call, at most 8 generations deep. A part is an
instance like any other, held by its own parties: they propose calls on it, consent to them, and
fetch its evidence, which carries its ancestors' calls up to each division, consents and all. So
whoever takes a part three generations down verifies its whole chain offline:

```sh
cexchain contract propose <instance> split --peer home \
    --args "{\"parts\": [600, 400], \"recipients\": [h'<ledger A>', h'<ledger B>']}"
cexchain contract instances --parent <instance>      # the parts its calls created
cexchain contract instance <part>                    # its parent, depth, position, and ancestors
cexchain contract fetch --peer home --instance <part> --out part.cbor
cexchain contract verify part.cbor --ledger-id <home-ledger-id>   # its ancestors first, then its own calls
```

The ledger refuses a call that creates parts on a retired contract or at depth 8; `--dry-run` and
the registrar give the ledger's reason before anything is signed.

A call may also make *requests* (spec v0.8): work for an executor outside the ledger, each with a
kind (such as `notify`), params, a deadline, and the function an answer calls. A request stays
open until one answer closes it: done, failed, or expired (once its deadline has come); a late
answer is recorded as late, and the contract reacts to each answer, perhaps asking again. An
executor is a device or an AI agent whose delegation covers calls on some contracts, of their
reply functions, answering requests of some kinds only (scope keys 7 to 9), so its key can do
nothing else:

```sh
cexchain executor add Notifier --contract <contract> --kinds notify --key-out notifier.key --as root.key
cexchain request list --open                      # what contracts asked for, and what is overdue
cexchain request answer <request> --done --args '{"ref": "N-1"}' --as notifier.key
cexchain request answer <request> --failed --reason unavailable --as clerk.key   # by hand
cexchain request cancel <request> --as clerk.key  # answered failed, reason cancelled
cexchain contract verify instance.cbor --ledger-id <home-ledger-id> --require-answered
```

`contract verify` shows each call's requests and the answer it gives (who gave it, under which
delegation, how late), and the open requests, overdue once the checkpoint's time has passed their
deadline; `--require-answered` fails evidence with overdue requests. A server lists requests for
executors at `GET /v1/requests`, as a long poll (`request wait` asks it), under an `executor`
token that submits answers and nothing else; what it lists is a hint, and an executor checks a
request in the instance's verified evidence before acting on it.

**Executors at work.** `executor run` is that loop: it polls the server for the kinds its
connectors serve, verifies each request open in the instance's evidence, journals it (synced
before every outside action), hands it to the connector its config routes the contract and kind
to, and signs and sends the answer. A connector is a child process that speaks JSON lines over
stdin and stdout, in any language, and never sees the signing key
([`spec/connectors.md`](spec/connectors.md)); two ship with CexChain. `webhook` POSTs each request
to a URL, signed with HMAC-SHA-256, and `command` runs a program per request, without a shell,
with the request on its stdin:

```sh
cexchain executor add Notifier --contract <contract> --kinds notify,http.post \
    --key-out notifier.key --config-out notifier.json --as root.key
printf '%s' "$HOOK_KEY" | cexchain executor secret set hook-key --state notifier-state
cexchain executor connector add notices --config notifier.json --type webhook --kinds notify \
    --url https://hooks.example.com/ledger --secret hook-key
cexchain executor connector add poster --config notifier.json --type command --kinds http.post \
    --program /usr/local/bin/post-request --timeout 60
cexchain executor check --config notifier.json --state notifier-state
cexchain executor run --config notifier.json --state notifier-state \
    --server https://ledger.example.com --token-file executor.token --as notifier.key
cexchain executor journal list --state notifier-state   # what it did, and why
```

An answer carries the connector's result (external ids, statuses, codes: never personal data), a
failure's reason, and the salted digest of the outside system's response, which stays in the
journal for later disclosure. Transient failures are retried, with backoff, until the deadline; a
request answered elsewhere meanwhile (a keeper's expiry, a person by hand) is closed, not
answered twice; after a crash the journal resumes the work without acting twice. Secrets are
sealed with HPKE and reach a connector only over its pipe. Copies of one executor take turns
through the server's lease, so a standby takes over when the active copy stops. Run as a
service, it rides out its server's restarts and a cluster's elections: it waits while it cannot
reach the server and tries the ledger again within 30 seconds at most (an outside system's
retries back off to 5 minutes), each request still acted on and answered once.
`deploy/cluster/compose.yaml` runs one beside the three-member cluster, with a sample contract,
a `command` connector, and its secret from a Docker secret, never in the image.

**Relying on an instance's state.** When a party acts on an instance's state, say that a thing is
not already promised to someone else, it waits until the call that put it there is in a
checkpoint cosigned by witnesses it trusts, and parties that rely on one instance share a witness:
a home can then show neither of them a different history (spec section 13). The protocol does not
know what a state means; read the contract, or its contract text, and rebuild its code from the
source.

## The Bo language

Bo is the language contracts are written in: a few keywords in English, Traditional Chinese (Hong
Kong usage), and Simplified Chinese, freely mixed, and a built-in vocabulary of words with fixed
meanings. Its core, which every contract reads, holds 84 generic words: kinds of things (`thing`),
common actions (transfer, suspend, cancel), conditions, time words, units (a temperature among
them, `°C`), currencies, types, and common fields, states, and roles. Words of particular fields live in three official *vocabulary
packs*, each with the standard terms of its built-in actions: `finance` (24 words: pledges,
payments, freezes, splits), `commerce` (22: prices, charges such as taxes, bills), and `services`
(12: services and resources allocated to one holder at a time). A contract declares the packs it
uses, one line each at its top (`use finance`; `使用 finance` in Chinese), and a deploy records each
one's version and digest; a pack's word in a contract that does not use its pack is an error, never
a name of the contract's own. Its reference is [`spec/bo.md`](spec/bo.md), with the conformance suite `testvectors/bo-v1.json`. The
compiler reads every source through *language packs*, then lexes, parses, checks, and compiles it
to contract code, which `contract deploy --bo` deploys with its source. Each pack maps Bo's
concepts (`kw.can`, `act.transfer`, `unit.GB`) to one language's spellings, with its reading rules
(words that attach without a space, as in `可轉讓` or `30日內`; full-width punctuation; `萬` and `億`;
date forms), its messages, and the sentences of the contract text. A pack never changes what runs:
the same contract compiles to the same code through any of them.

```sh
cexchain bo vocab list                          # the core and the vocabulary packs, with digests
cexchain bo vocab show finance                  # a pack's words, field types, and built-in actions
cexchain bo vocab check events.vocab            # a vocabulary pack of your own
cexchain bo check tickets.bo --vocab events.vocab   # a source that uses it
cexchain bo packs list                          # the official language packs and their digests
cexchain bo packs show zh-Hant-HK               # its reading rules, keywords, and words
cexchain bo packs check company.pack            # a pack of your own, alone and with the official ones
cexchain bo packs check company.pack --language zh-Hant-HK   # messages in Traditional Chinese
cexchain bo check contract.bo                   # problems, as FILE:LINE:COLUMN: error: message (code)
cexchain bo check contract.bo --stage lex       # its tokens: 可轉讓 is kw.can + act.transfer
cexchain bo check contract.bo --stage parse     # its tree, the same in every language
cexchain bo check contract.bo --stage model     # its checked model, with what each rule inferred
```

The lexer reads a word only by the packs' fixed rules and never guesses: a run of characters
with two readings is an error asking for a space. So `可轉讓`, `can transfer`, and `可transfer`
give the same concepts; `可用率` stays one name; `500萬` is 5,000,000, `HKD 0.10` exact money, and
`5,000` an error (write `5_000`). Invisible characters are refused, and so are names that only
look alike (`оwner`, its first letter Cyrillic), so the text the parties read is the text that
runs.

The parser turns the tokens into a tree of concepts and names, so a contract gives the same tree
whatever language it is written in. Words whose argument sits on different sides in different
languages meet there: `7 days before due` and `到期前 7日`, `consent of counterparty` and
`經 相對方 同意`.

```
can transfer to counterparty           可轉讓 予 相對方
  over 50_000 requires in person         超過 50_000 須親身確認

can act.transfer to=role.counterparty  (the tree of both)
  requires cond.in_person guard=(cond.over 50000)
```

Clauses are `use`, `contract`, `parties`, a kind and its fields (`thing Item`), `can` with `by`,
`to`, and `with`, `when`, and `test`; an action's block holds `requires`, `if`/`otherwise`,
`each`, `reject`, `FIELD = VALUE`, and state changes (`active -> suspended`). `=` sets a field at
the start of an action's line and compares inside a condition. Ambiguity is an error, never a
guess: `a < b < c`, or `monthly HKD 120 * 12` (which words does `*` take?), ask for a rewrite, and
`可借出` is read as `可` + `借出` only when the contract declares `借出` and not `可借出`.

The checker reads the tree into a model: the parties, the one kind of instance and its fields,
the states, the actions, and the time rules, with every name resolved and every expression typed.
Money never mixes currencies, quantities never mix dimensions (TB and GB convert; TB and items do
not), months never mix with days, and every value is exact in its smallest unit (cents, bytes,
millionths of a rate): `HKD 0.001` is an error, never a rounding. Lists are bounded, actions never
recurse, and every state must be reachable. Whatever Bo infers rather than reads carries the id of
the fixed rule that inferred it, which the contract text spells out:

```
thing Item                             field field.holder instance party = owner{R2}
  amount HKD                           state state.active first{R4}
  holder owner                         can act.transfer standard by=field.holder{R19} to=role.counterparty{R21} agents=delegation{R14}
can transfer to counterparty             consent role.counterparty{R21}
  over 50_000 requires in person         requires cond.in_person{R13} guard=(cond.over (money cur.HKD 50000){R6})
```

The transfer takes the standard library's terms (R19), so the holder starts it; each call names
the counterparty, who consents (R21); the holder starts as the owner and may change (R2);
`over 50_000` takes the unit of the action's one amount (R6); in person asks the starter's
presence (R13); an AI agent may act within its delegation unless the action says it only
proposes (R14). Clauses that ask the outside world to act (notify, say) are accepted with a
warning: executors come in a later step.

Packs are files in CBOR diagnostic notation; `bo/packs/` holds the official language packs and
`bo/vocab/` the official vocabulary packs (their words, spelled in each language, and the
standard terms of their actions). A pack's digest is the hash of its canonical CBOR, and a deploy
records the packs its source was read with, so anyone can rebuild the contract from the source
and compare. Anyone can write a vocabulary pack of their own, in the same format, for words they
use in many contracts: `--vocab FILE` reads it on every `bo` command and on `contract deploy --bo`,
and the deploy embeds it whole, so whoever verifies the contract needs no copy
([`examples/events`](examples/events)). Bo never guesses: one spelling with
two meanings, in one pack or across the packs a source is read with, is an error, and so is a
word that an attaching rule could split into two others.

The compiler uses C++26 static reflection and contracts, which GCC 16 builds and Clang does not
yet. The `bo` commands therefore exist only in builds made with GCC 16 (the `gcc-*` presets, the
release build, and the Docker image); `cexchain version` says whether a build has them. The
browser verifier never needs the compiler: verifying a contract replays its code.

Compiled contracts are WebAssembly modules in the contract profile, written by the compiler's own
emitter, with a small runtime it adds as needed: reading the call's input (checked inside the
contract to be deterministic CBOR within the limits, as core decodes it; from codegen 2 on,
texts are not checked again for UTF-8, which the ledger's input always is), writing the output, checked 64-bit
arithmetic (an overflow refuses the call), multiply-divide on 128 bits with the rounding modes
half up, half even, and down, civil dates at a fixed UTC offset with month ends clamped, and text
comparison. Every routine runs to the same outcome, output, and fuel on the ledger's interpreter
and on the independent Python interpreter (`ctest -R bo_reference`, with Python 3);
`tests/bo/golden/runtime/fuel.txt` lists what each costs of a call's 10 million fuel.

The compiler lowers Bo to such modules: creation, the contract's own
actions with their inputs, fields, states, `requires` (with a guard such as `over 1_000_000`),
`if` and `otherwise`, `reject`, consents, and `in person`, over numbers, money, quantities,
rates, dates, durations, texts, yes or no, and parties. Each action is a function named by its
concept or as written (the same name in every language), and creation is `create` (`issue` for
the vocabulary's assets). Arguments are a map: `{"fields": {...}, "parties": {role: ledger}}` to create, the
action's inputs by name otherwise (money in cents, rates in millionths, dates in milliseconds).
A compiled contract asks for the consents an action needs (of its starter, of a role it binds,
of a counterparty it makes the holder (or another party field a built-in action sets) at every
call, however that role was bound, of a party a changed field held, and of every `requires consent of`) with
`[2, needs]`, the
home's own consent being the call itself; it keeps `{"state": NAME, "fields": {...}}`, reports
the state as the status, the parties and every field holding one, each state change as an
event, and the instance as final once no action can leave its state; and it refuses with the
text of a `reject` or with `bo:CODE` (`bo:requires sign 2`), which tools show in the reader's
language. The same contract in English, Traditional Chinese, Simplified Chinese, or mixed
compiles to the same bytes; `tests/bo/golden/build/` holds a two-party contract in each, and the
fuel of each of its calls. The vocabulary's built-in actions compile
with the standard library's terms, `when` rules compile to functions a keeper calls, and lists
and charges compute bills (all below). What later steps bring (executors, and the built-in
actions whose terms come later) is refused with a message for now. `testvectors/bo-v1.json`
(`tools/testvectors/bo_vectors.py`) pins sources, bo-source bundles, interfaces, code, fuel
bounds, and outcomes, checked on both interpreters, and the errors of sources that must not
build.

```sh
cexchain bo build contract.bo                   # code, hash, compiler, and the source bundle
cexchain bo build contract.bo --out contract.boc --hash sm3     # to deploy on an SM3 ledger
cexchain contract deploy --bo contract.bo --as root.key         # build and deploy in one step
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
The compiler keeps writing earlier codegen versions (codegens 1 to 3 beside today's 4), so a
deploy made with one still rebuilds. Codegen 4 (before the first release) reads a time rule
whose action is on the next line of its block as the same rule with the action on its line, so
the states it ends in are final; codegen 3 read such a contract as having no final state.

### Fuel

A call has 10 million fuel. For each function, `bo build` computes the most fuel a call can use
from the code's structure: each loop as often as the contract's bounds allow (lists, a bill's
lines and charges, a split's parts and consents), each comparison and copy as large as the
input allows, and reading the input as many items as the function's arguments, the state the
contract writes, and the ledger's other fields can hold. The bound holds for every call whose
arguments are of the function's shape. A contract a call could run out of fuel in does not build
(`build.fuel`: two lists of 1,000 items compared item by item, say); one whose output could
exceed what the code has for it (192 KiB: a large state split into many parts) builds with a
warning (`build.output`). `bo build` shows the highest bound, `--fuel` each function's:

```
$ cexchain bo build contract.bo --fuel
  ...
  fuel       at most 226,042 a call (amend), of 10,000,000; output at most 65,771 bytes (amend), of 196,608
  function               fuel       reading     output
  amend               226,042        63,080     65,771
  ...
```

Every test of the compiler checks each call's fuel against its bound; calls at the language's
limits use 40 to 70 percent of it (`tests/bo/golden/build/fuel-bounds.txt`).

### The contract text

What the parties read and confirm before they sign is the *contract text*, which Bo writes from
the contract in English, Traditional Chinese (Hong Kong usage), or Simplified Chinese: the
parties and when each is bound to a ledger, what each instance records, the states (the first,
the final ones, and the events), each action (who starts it, the consents it needs, its
requirements, numbered as a refusal such as `bo:requires sign 2` names them, its state changes,
and what AI agents may do), the time rules, and the rules Bo applied. Whatever Bo inferred
instead of reading it is spelled out in its clause and marked with its rule (`[R3]`, `〔R3〕`), and
the last section explains each rule used. Texts are always shown in quotation marks, including a
name Bo read as a text (R18: `颜色 = 红色` reads as `颜色 is "红色"`). One contract gives the same text, byte for byte, whatever language its source was
written in; `tests/bo/golden/explain/` holds the text of each example in each language.

```sh
cexchain bo explain contract.bo                          # before a deploy
cexchain bo explain contract.bo --language zh-Hant-HK    # or set CEXCHAIN_LANGUAGE
cexchain contract explain <contract or instance>         # from the deploy, only if it rebuilds
```

```
4.1 lend
  4.1.1 Started by owner, whose agreement it needs.
  4.1.2 The call gives counterparty (a party). [R21]
  4.1.3 It needs the consent of the counterparty, whose ledger each call names (the argument
        counterparty). [R21]
  4.1.4 It needs the consent of whichever party is the holder before the call, since the action
        changes the holder. [R8]
  4.1.5 If the instance is active, it becomes lent; otherwise the call is refused.
  4.1.6 It sets the holder to the counterparty.
  4.1.7 An AI agent may start it within its delegation. [R14]
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
cexchain bo fmt contract.bo --check                      # is it formatted? (exit 3 if not)
cexchain bo fmt contract.bo --language en                # the English source, on stdout
cexchain bo fmt contract.bo --language zh-Hant-HK --write
```

```
requires consent of counterparty        須經 相對方 同意           须经 相对方 同意
when 7 days before due notify holder    當到期前 7日 通知 持有人    当到期前 7天 通知 持有人
```

Chinese is written as Chinese is: a keyword joined to the word after it (`可轉讓`, `須經`), a
number to its Chinese unit (`30日`, `500萬港元`); Latin words stand apart (`每 GB`). A word whose
argument sits on the other side in another language (`7 days before due`, `到期前 7日`) moves
around it, with parentheses where it would otherwise take a different argument. The text is not
reversible, though the contract is: a multiplier English lacks is written out (`500萬` is
`5_000_000`), and words become each language's first spelling (`transfers`, then `轉讓`, then `transfer`).
Before printing anything, `bo fmt` reads its result again; if words would read together in the
new language as another word, it says where and changes nothing.

### Tests

A contract carries its own tests: `test` blocks of steps, each a party, an action, and
optionally what it gives, when, and how it is signed, then what should happen.

```
test "nothing is lent twice, and only the holder brings it back"
  owner create with name = "Camera X100"
  owner lend to friend1 -> lent                      # friend1 consents, then it is lent
  owner lend to friend2 -> refused "bo:state lend"   # not while it is lent
  friend2 bring_back -> consent of friend1           # the holder starts it: friend2 cannot
  friend1 bring_back at 2027-01-05 -> active
```

`bo test` builds the contract and runs each test on an instance of its own, exactly as a ledger
runs calls: every party a test names is a ledger of its own (a name the contract does not
declare, such as `friend1`, is a ledger only the test names, which `to friend1` names or binds
a role to);
the first step creates the instance, and its party is the home. A call runs first without
consents; every party the contract asks then consents, except those the step expects it to wait
for and, when the step's party does not start the action, the party that does. `in person` signs
as a person who proves presence, `by AI agent` as an agent; `at DATE` moves time on (a test
starts on 2026-01-01). Expectations are a state (`-> signed`), a refusal (`-> refused`, or with
the contract's reason in quotes), or a wait (`-> consent of friend1`); a step without one expects
an accept. The report shows each step as written and what happened, worded in `--language`, and
for a refusal the clause of the contract text it comes from; the results are the same whatever
language the contract and its tests are written in. Exit status 3 if a test fails.

```sh
cexchain bo test lending.bo
cexchain bo test lending.bo --language zh-Hans-CN --json
```

### Requests

A contract asks the outside world for something with `request`: a kind (a name, or an action's
or a document's word such as `notify` or `invoice`), the party it concerns, values, and a
deadline. `notify PARTY` is short for `request notify to PARTY within 1 day`. The answers come back
through one function, `result`, and the contract says what each does; `result` and `reason` are
the answer's texts there:

```
can deliver by carrier
  in_transit -> delivered
  request notify to consignee with message = "delivered" within 1 day

when notify done
  notified = yes
  notice = result
when notify fails
  request notify to shipper with message = "notice failed" within 1 day
```

The same in Traditional Chinese (`bo fmt --language zh-Hant-HK`):

```
可 deliver 由 carrier
  in_transit -> delivered
  請求 通知 予 consignee 連同 message = "delivered" 1日內

當通知 完成
  notified = 是
  notice = 結果
當通知 失敗
  請求 通知 予 shipper 連同 message = "notice failed" 1日內
```

A failed request and one no answer reaches by its deadline (expired) take the rule for failures,
unless one is written for expiry (`when notify expires`). An answer is never refused, so these
rules ask no consent and refuse nothing; an instance that has ended takes its answers but asks
nothing more. The contract text states every request, its deadline, and what happens if it fails.
Tests answer requests as an executor, a keeper, or a person would:

```
executor notify done with result = "RCPT-1" -> notified = yes
executor notify fails with reason = "unreachable" -> notice = "unreachable"
keeper notify expires at 2027-03-11
```

An executor (`executor add NAME --kinds notify`, then `executor run`) carries requests out through
connectors and answers on the ledger; `examples/shipment` runs one.

### A service's periods

With the `services` and `commerce` vocabulary packs, a `service` with a recurring price is paid
until a date and billed until a date, which Bo adds; it is due on the date it is paid until.
Subscribing and renewing bill one period: an executor is asked to `invoice` it, and once it is
invoiced, to `collect` it; a collection done pays the period, and resumes a suspended service no
longer overdue. On a service, `subscribe`, `upgrade`, `downgrade`, `suspend`, `resume`, and
`terminate` also ask an executor to act. The rest is the contract's:

```
use commerce
use services
contract Hosting
parties we, customer

service Plan
  price monthly HKD 120

can subscribe by customer
when 14 days before due renew
when overdue 3 days suspend
when overdue 30 days terminate
when collect fails notify we
```

The contract text states each request and what its answers do (rules R34 and R35); tests answer
them (`executor invoice done with result = "INV-1"`, `executor collect done`, `keeper suspend at
2027-01-13`). `spec/bo.md` section 6.12 has the details and the spec's VPS example.

### The standard library

The built-in actions are written in Bo itself, in a standard library compiled into the compiler:
the core's transfer and cancel, and suspend, resume, and terminate, on the home's own word
(`bo/stdlib/core.bo`); then the vocabulary packs' actions, in their pack files (`bo/vocab/`), which
a contract gets after its `use` line: finance's pledge, release, enforce, redeem, pay, confirm
payment, dispute, freeze, unfreeze, and split, which keep the semantics of the native assets that
spec v0.5 to v0.8 had (`tests/bo/finance_terms_test.cpp` holds those verdicts as goldens and
checks the pack's terms against them, call by call), and services' allocate and reclaim, and
subscribe, renew, upgrade, and downgrade. A
vocabulary pack of your own brings the terms of its own actions the same way. A contract that
writes `can transfer to counterparty` gets the library's transfer: the holder starts it, the
holder and the counterparty consent, only an active instance is transferred, and the
counterparty becomes the holder. The lines a contract writes under a built-in action add to its
terms and are checked first (`over 50_000 requires in person`); without `to`, each call names the
counterparty, who consents. A counterparty that a built-in action makes the holder (or puts in
another party field) consents to every such call, even when its role was bound when the instance
was created (R31). The contract text states every standard term, marked R19. To change a
built-in action, copy it under a name of your own: it is then the contract's own action.

```sh
cexchain bo stdlib list                                  # who starts each, its pack, its states
cexchain bo stdlib list finance                          # one pack's (or core)
cexchain bo stdlib show transfer                         # its source, to copy, and its text
cexchain bo stdlib show 轉讓 --language zh-Hant-HK
```

```
can transfer to counterparty by holder
  requires not counterparty = holder
  active -> active
  holder = counterparty
```

#### Splitting a thing into parts

`issue PARTS to RECIPIENTS` (R30) makes each part an instance of the contract with the
instance's fields, its amount the part and its holder the recipient in the same place, `with`
setting others; fields Bo adds start empty, and the part starts in the first state. A part's
evidence carries the history of the instances it came from, the other parts of each split
included, which the contract text states. The library's `split` uses it: the holder divides the
instance among recipients, each part held by its recipient, and the instance ends (`divided`).
The holder and every recipient consent (so at most 15 recipients besides the holder), each part
is at least the currency's smallest unit, the parts add up to the amount, and only an active
instance splits. A part at depth 8 splits no further (`bo:depth split`). The template ends with
the statement that makes the parts, which a copy of it can change:

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

In tests, a step acts on the part its party holds (or names the holder: `we cancel maker1`), and
the report names parts by path (part 1.2).
[`examples/multi-tier-split`](examples/multi-tier-split/) splits a receivable down a supply
chain across six organizations, an example from supply-chain finance.

```sh
cexchain contract propose <instance> split --peer home \
    --args "{\"parts\": [60000000, 40000000], \"recipients\": [h'<ledger A>', h'<ledger B>']}"
cexchain contract pending --peer home            # a recipient sees the call it is asked to consent to
cexchain contract consent --peer home --call <call> --as root.key --log-key log.key --send
```

An action can let AI agents only propose it (`AI agent can propose`): an agent's call is then
kept with the instance as a proposal, and a person who proves presence approves it with the
function `approve`, which runs it with every requirement checked. In a test, `owner lend to
friend1 by AI agent -> pending approval`, then `owner approve in person -> lent`.

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
`when due borrower bring_back` names a party's duty: it says when an instance is due and
overdue, and nothing is called. In actions, `within 14 days` means less than 14 days since the instance last
changed state; `overdue`, `overdue N`, and `N before due` hold from those times on. Dates and days
are counted at a fixed offset from UTC, all year: `UTC offset "-05:00"` in the kind's block, or
+08:00 (R25).

```sh
# The keeper: a device whose delegation covers these contracts' time rules (and result) only.
cexchain keeper add Keeper --contracts <contract> --key-out keeper.key --as root.key
# What is due now, or at a later time? Dry runs; nothing is recorded.
cexchain keeper due
cexchain keeper due --at 2027-07-03
# The server's keeper fires what is due every minute (on the leader, in a cluster) ...
cexchain serve --log-key log.key --keeper-key keeper.key
# ... or, for a ledger without a server, fire it now, or every minute.
cexchain keeper run --as keeper.key
cexchain keeper run --as keeper.key --every 60
```

A keeper finds what is due by dry runs: a rule is due if its contract accepts the call and the
call would change something. It also expires requests left open 15 minutes past their deadline
(`--expiry-grace`). Its delegation covers contract calls of the time rules and the replies
only, never the actions that are the home's own word; `keeper list`, `keeper show`, and
`keeper revoke` manage keepers, and `GET /v1/contracts/due` answers what is due.
A keeper that is sometimes off (a personal computer) fires late, never early, and the event
shows how late. In tests, the keeper is a step: `keeper suspend at 2027-07-02 -> refused
"bo:when when.suspend"`, then `keeper suspend at 2027-07-03 -> suspended`; it calls, as a device
of the home, the rule that does that action (for a rule that does none, the state its first state
change leads to, such as `keeper closed`).
Nothing yet keeps a field's value unique across a contract's instances: unique keys come later.

To try time rules on a real ledger without waiting, set `CEXCHAIN_CLOCK_OFFSET` (such as `30d`,
`12h`, or `90m`; at most 3660 days): every command, the server and its keeper included, runs its
clock that far ahead. It is for demonstrations and tests only. A ledger keeps the times it
records, so `serve` refuses to start with an offset unless it is given `--allow-clock-offset`,
then prints it and shows it in `/v1/status` (`clock_offset_ms`); a client ahead of its ledger
is refused (a statement may not claim to be issued in the future). `examples/idc-hosting`
moves a month this way.

### Lists and charges

A field or an input may be a list, of at most 16 items unless `at most N` says otherwise (1,000
at most): `codes list text at most 3`. A list given as an argument is checked when it is read
(longer ones are refused), `each n in rows` runs its block once for each item (requirements,
choices, refusals, and fields set; no state change), and `sum of rows`, `count of rows`, and
`"x" in codes` read it. One value where a list is needed is a list of that one item (R29).

Fees, commissions, surcharges, and taxes are *charges*, which a contract defines: nothing about
them is built in, rates included. A field named by a document word holds the lines of a bill;
each time it is set, the charges are computed on its lines at the time of that call, and the
instance keeps the bill as it was made (R26): a later rate never changes a bill already made. A
charge is a rate (in millionths) or a fixed amount; it applies always or when a condition holds;
it is `included` in the price or `added` to it; it is rounded per line or per bill, half up, half
even, or down; it may be computed on charges written before it (R27); and its rate is the one in
force at the bill's time (R28). The words for bills and charges belong to the `commerce`
vocabulary pack: a contract that uses them starts with `use commerce`. The spec ([`spec/bo.md`](spec/bo.md)) works through a
value-added tax on both sides of a rate change; `tests/bo/golden/test/charges/` and
`tests/bo/golden/build/vat-amounts.txt` hold the arithmetic, which the Python reference computes
again with its own integers.

## AI agents (MCP)

`cexchain mcp --ledger DIR --as AGENT_KEY` runs a Model Context Protocol server over stdio
(revision 2026-07-28, with fallback to earlier revisions). The agent can look up its identity and
delegations, query and issue records, endorse, move records through their lifecycle, read
contract instances, and verify evidence from others. Every action is signed with the agent's own key, refused by the ledger if
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
command line. An agent can also be an executor: it lists the requests contracts made
(`cexchain_list_requests`, `cexchain_get_request`) and answers those its delegation covers
(`cexchain_answer_request`), each answer recorded with its provenance. `cexchain mcp --help`
lists every tool.

With `--server URL` (and `--token-file`, `--ledger-id`, as for every command in client mode), the
agent works on a ledger a server or a cluster serves, through a verified local mirror: it reads,
calls, and answers there, its statements signed on its own computer. The tools that reach
other organizations need a ledger directory's peers, so they are refused in client mode.

## Examples

[`examples/`](examples/) holds complete stories built on the generic core. Each is a Bo contract
with its tests, a script that runs the story on one computer, narrated step by step, each party
with a ledger of its own, and a short README. They are examples, not features: CexChain knows none
of these things, and every one of them can be changed or written anew.

| Example | What it shows |
|---|---|
| [lending](examples/lending/) | Two people: a camera lent and brought back, the borrower's consent on his own ledger, private details in a record, the history verified offline. No server |
| [supply-agreement](examples/supply-agreement/) | Trade: an agreement signed once a supplier's manager and a bank's AI agent (through MCP) consent; a registrar; SM2 and SM3 |
| [receivable-financing](examples/receivable-financing/) | Supply-chain finance: a receivable pledged to a bank, a second pledge refused, released, sold, and paid; a regulator as witness |
| [multi-tier-split](examples/multi-tier-split/) | Supply-chain finance: a receivable split down a supply chain across six organizations, a part pledged after its chain is verified offline |
| [shipment](examples/shipment/) | A chain of custody: goods kept cold handed from a shipper to a carrier, a transit warehouse, and a consignee; a driver signs each handover in person, a data logger (a device) posts readings, a keeper marks the shipment late, a charge per day late, a QR code at delivery, a delivery notice an executor sends and answers, an insurer's claim; SM2 and SM3 |
| [idc-hosting](examples/idc-hosting/) | Services: a server rented and billed each month, on the `services` and `commerce` packs; the provider's ledger on a three-member cluster with its keeper; an executor with two webhooks (a control panel, a billing system); a notice answered by an AI agent through MCP and a payment answered by hand; suspended when overdue, resumed when paid, terminated and its address reclaimed |

The scripts run in the test suite (`ctest -R demo_`), so they keep working.

## Known limits

What requests, executors, and services do not do yet, as of this version:

- **Parts and requests.** A Bo contract that splits an instance into parts makes no requests:
  the compiler refuses a `request` in such a contract (`build.unsupported`), since an instance
  that issued parts has ended and an answer could not tell.
- **Request kinds in Bo** are lowercase letters, digits, and `_` (`notify`, `http_post`): the
  ledger also takes dotted kinds (`http.post`), which Bo cannot write, so a connector for a
  dotted kind needs a Bo-writable kind beside it.
- **A service's bills** bill one period of the price on subscribing and on each renewal. Charges
  and usage on a service's bills, proration (upgrading or downgrading mid-period), refunds (a
  service terminated with a period paid ahead gets nothing back), and paying ahead (one bill is
  open at a time) are not built.
- **A payment answered by hand** (`request answer` on a `collect`) pays the period on the
  ledger, but nothing posts it to the billing system: post it there too, by hand or by a
  connector of your own.
- **The first "N days before due" reminder** applies at the subscription: the first due date is
  the subscription day, so a rule such as `when 7 days before due` fires at once.
- **An executor's journal** closes a request that someone else answered (a person by hand, a
  keeper's expiry) only when its next retry comes up, after its backoff.
- **An executor asks one server** (`--server`): while that member is down it waits and tries
  again; it does not fail over to another member by itself. Point it at a load balancer, or
  restart it with another member's address.
- **MCP through a server** (`mcp --server`) works on the home ledger only: its tools that reach
  other organizations' ledgers need their peers, which belong to a ledger directory.
- **Connectors:** `webhook` and `command` ship with CexChain; first-party connectors for
  billing and accounting systems (Zoho first) come later, on the same protocol.
- **`CEXCHAIN_CLOCK_OFFSET`** is for demonstrations and tests only (`serve` refuses it without
  `--allow-clock-offset`); a ledger keeps the later times it recorded.

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
report to match `cexchain verify --json` (and `contract verify --json`) exactly, and a Chromium
test drives the page:

```sh
tools/wasm/build.sh
(cd tests/browser && npm ci && npx playwright install chromium)
tests/browser/run.sh build/gcc-debug/cli/cexchain build/wasm
```

`tests/cli/serve.sh` runs a server, a replica, and backups end to end; `tests/node/` covers the
HTTP parser and the API over real sockets, including a primary that serves a forged history.

Fuzz targets cover every parser of untrusted input, Bo language and vocabulary packs included. `make_seeds` writes valid objects (evidence bundles, access records, signed backups, passkey registrations, requests, the official packs and the example's vocabulary pack) to start each corpus from, so mutations reach the checks behind the signatures:

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
