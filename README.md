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

> **Alpha: pre-release software.** The protocol specification (v0.12) is a draft and may change,
> and so may interfaces and file formats; ledgers and evidence made with this version may need
> to be made again with a later one. The code has not been audited yet; see
> [Security](#security) for how to report a vulnerability and the known open items.
>
> The specification: [the protocol in prose](spec/README.md), [`spec/cexchain.cddl`](spec/cexchain.cddl); the contract language: [`spec/bo.md`](spec/bo.md). What is not built yet: [Known limits](#known-limits).

## What is here

Four parts, each a program, and each its own directory:

| Part | Program | What it is |
|---|---|---|
| [The chain](chain/README.md) | `cexchain` | The protocol and everything that keeps, serves, and verifies a ledger: records, actors and delegations, contracts, witnesses, evidence, servers, replicas, clusters, and other organizations' ledgers |
| [The Bo language](bo/README.md) | `bo` | The language contracts are written in, and its compiler: it builds contracts, writes their contract text in three languages, runs their tests, and rebuilds deployed ones from their source |
| [The web console](apps/console/README.md) | `cexchain-console` | A ledger in a browser, for a person or a company: setup, documents, rules, things, parties, people, each statement approved with a passkey |
| [The search index](apps/index/README.md) | `cexchain-index` | Searches and reports over a ledger, from an index kept beside it |

The chain needs none of the others: it runs a contract's code and keeps its source, whatever
the language. Bo uses only the chain's verification layer, and the applications are built on
both. The build checks this direction. Shared by all four: the specification (`spec/`), the test
vectors (`testvectors/`), the [examples](examples/), the tests, and the tools. Beside them,
[a second verifier](verifiers/python/README.md), written in Python from the specification alone.

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
  it from the command line, or from a local web console (in progress); installers are planned.
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

## Installing

Packages are built by the Release workflow on a version tag, with their SHA-256 sums, and by
hand with `tools/package/linux.sh` (in the `gcc:16-trixie` image) and `tools/package/macos.sh`.
On Linux there are two, each a tarball, a `.deb`, and an `.rpm`:

- **`cexchain`**, what a server needs: the `cexchain` and `cexchain-index` programs, and a ledger
  server unit for companies (`cexchain.service`, not enabled; its options in
  `/etc/cexchain/serve.env`).
- **`cexchain-console`**, which needs `cexchain` of the same version: the `cexchain-console` and
  `bo` programs, a menu entry for the console, and a unit for a company's console
  (`cexchain-console.service`, not enabled, instead of `cexchain.service`; its options in
  `/etc/cexchain/console.env`).

On macOS, a `.pkg` installs all four programs in `/usr/local/bin`. Every program comes with its
shell completion. Removing a package keeps every ledger, console, and backup. Updates come the
same way: a newer package, through the platform's package manager or the releases page. To build
from source instead, see [Building](#building).

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

The ledger holds only an attachment's salted commitment, so the photo itself stays with you. Add
`--keep-files` to keep it with the record too, sealed to the ledger's vault key (16 MiB a file at
most): `record file get <record-id> photo.jpg --out photo.jpg` opens it, checked against the
record, and backups include it.

**New versions.** When a document changes (a form, a policy, a price list), issue the new one with
`--supersedes <old-record-id>`. The old record stays as it was, but shows as superseded in
`record show` and `record list` (`--current` leaves it out), `record versions` lists the chain
oldest first, and the old record's evidence tells whoever verifies it that a newer version replaced
it, when, and by whom, so nobody keeps working from an outdated copy. A record is superseded once,
and a delegation must cover the old record's type as well as the new one's.

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
register a camera (with the `bo` program, [below](#the-bo-language)):

```sh
bo test lending.bo           # the tests the contract carries
bo explain lending.bo        # the contract text the parties read, in English or Chinese
bo build lending.bo --out lending.boc
cexchain contract deploy lending.boc --as root.key
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
| Ledger | `init`, `status`, `audit`, `log list`, `log show`, `log export`, `ledger keys`, `ledger genesis`, `ledger rotate-log-key`, `ledger rotate-root-key`, `ledger snapshot create\|show\|remove` |
| Actors | `actor add`, `actor list`, `actor show`, `actor revoke`, `actor rotate-key`, `actor set-presence`, `presence enroll` |
| Delegations | `delegation grant`, `delegation list`, `delegation show`, `delegation revoke` |
| Records | `record issue`, `record list`, `record show`, `record history`, `record versions`, `record fields`, `record file list\|get\|add\|remove`, `record endorse`, `record transition`, `record revoke`, `record types` |
| Proofs | `checkpoint create`, `checkpoint list`, `checkpoint show`, `checkpoint cosign-request`, `checkpoint add-cosignature`, `checkpoint timestamp`, `checkpoint add-timestamp`, `checkpoint timestamps`, `proof inclusion`, `proof consistency`, `proof state`, `receipt` |
| Witnesses | `witness add-log`, `witness cosign`, `witness status`, `witness remove-log`; `witness register`, `witness registered`, `witness unregister` (public witnesses) |
| Evidence | `export`, `verify`, `inspect`, `qr` |
| Vault | `vault status`, `vault keygen`, `vault rekey` |
| AI agents | `mcp` |
| Server | `serve`, `token create`, `token list`, `token show`, `token revoke` |
| Clusters | `cluster init`, `cluster join`, `cluster add`, `cluster status`, `cluster remove`, `cluster step-down` |
| Replicas | `replica init`, `replica sync`, `replica status`, `replica promote` |
| Backups | `backup create`, `backup verify`, `backup restore` |
| Relays | `relay key init`, `relay use`, `relay show`, `relay stop`; `serve --relay-dir`, `serve --relay-key` |
| Other organizations | `peer invite`, `peer accept`, `peer add`, `peer list`, `peer show`, `peer remove`, `access request`, `access send`, `access inbox`, `access dismiss`, `access grant`, `access fetch`, `access accept`, `access receipt`, `access list` |
| Contracts | `contract deploy`, `contract show`, `contract list`, `contract retire`, `contract create`, `contract call`, `contract instance`, `contract instances`, `contract evidence`, `contract proposal`, `contract file show`, `contract propose`, `contract pending`, `contract consent`, `contract withdraw`, `contract send`, `contract fetch`, `contract verify`, `contract export` |
| Requests | `request list`, `request show`, `request answer`, `request cancel`, `request wait` |
| Executors | `executor add`, `executor list`, `executor show`, `executor revoke`, `executor run`, `executor check`, `executor connector add\|list\|show\|remove`, `executor secret set\|list\|remove`, `executor journal list\|show`; `connector webhook`, `connector command` |
| Keepers | `keeper add`, `keeper list`, `keeper show`, `keeper revoke`, `keeper due`, `keeper run`; `serve --keeper-key` |

The other programs have their own: `bo` the [Bo language's](bo/README.md), `cexchain-console`
the [web console's](apps/console/README.md), and `cexchain-index` the
[search index's](apps/index/README.md). In all four:

- Every command takes `--help`, and `--json` for scripting.
- `cexchain help --json` describes every command and option in machine-readable form.
- `source <(cexchain completion bash)` (or `zsh`) enables tab completion.
- IDs can be shortened to any unique prefix of 8 or more hex digits.
- Exit codes: 0 for success, 1 for a usage error, 2 for a failure, and 3 when evidence or a ledger fails verification.

### The vault

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

**Public witnesses.** A witness can also serve anyone who asks, with no token
(`serve --witness-public`, with quotas on ledgers, registrations per address and day, and
cosignatures per ledger). A ledger registers once, which proves it holds its log key; from then
on `serve` and the web console ask it to cosign every new checkpoint, and exports carry its
cosignatures. The witness learns the ledger id, its first keys, and each checkpoint's size, root,
and time; never statements, records, fields, parties, or files.

```sh
# The witness's operator: serve it, with TLS of its own (quotas see callers' addresses).
cexchain serve --listen 0.0.0.0:443 --tls-cert cert.pem --tls-key key.pem \
    --witness-dir witness --witness-key witness.key --witness-public --witness-name example
# A ledger: register with it, pinning the key its operator publishes.
cexchain witness register https://witness.example.org --witness-key witness.pub
cexchain witness registered            # what each witness cosigned
cexchain witness unregister example    # stop asking; what it cosigned stays valid
```

In the web console, Parties lists the public witnesses a ledger asks and adds one by its address
and key. A build can offer known witnesses (`-DCEXCHAIN_PUBLIC_WITNESSES=name|url|keyhex,...`);
none is used unless someone chooses it.

**Relays.** A ledger that no party reaches directly, such as a console on a laptop, is reached
through a relay: the server of a public witness that also keeps mailboxes (`serve --relay-dir`).
Its parties' requests wait there sealed to its relay key; its node fetches each, answers it with
its own API as if it had come directly (the peer token decides, as always), and sends the sealed
answer back. The relay learns who writes to whom, when, and how much; never what.

```sh
cexchain relay key init --out relay.key
cexchain relay use https://witness.example.org --relay-key relay.key --witness-key witness.pub
cexchain serve --log-key log.key --relay-key relay.key   # answers what waits at the relay
cexchain peer invite bank                                # the code carries the relay
cexchain access fetch --peer factory --request ID --out d.cbor --log-key log.key
```

Commands that reach a party take `--log-key` to reach it through its relay (what goes there is
signed). In the console, Parties offers "Be reached through" each public witness whose server runs
a relay; new invitation codes then carry it instead of a local address.

## Time-stamp authorities

A checkpoint's time is the ledger's own word, and witnesses prove only that the ledger did not fork
or rewrite what they cosigned. A time-stamp authority (RFC 3161, such as a national time service or
a commercial one) gives an outsider a bound on *when*: it signs, at its own time, a digest of a
checkpoint, so whoever trusts it knows that everything the checkpoint covers existed by then.

```sh
cexchain checkpoint timestamp --tsa https://tsa.example.com/tsr   # the latest checkpoint, stamped
cexchain checkpoint timestamps --tsa-root tsa-root.pem            # what is kept, and whom you trust
cexchain serve --log-key log.key --tsa https://tsa.example.com/tsr   # stamps by itself, every hour

# A verifier that trusts the authority's root: when the record existed by, from outside the ledger.
cexchain verify evidence.cbor --ledger-id <ledger-id> --tsa-root tsa-root.pem --min-timestamps 1
```

Tokens are kept beside the checkpoints, never in the log, and replicas, clusters, and backups keep
them too. An export carries, as anchors, the earliest stamped checkpoint covering the record and
the latest, each with a consistency proof to the bundle's own checkpoint. A verifier that trusts the
authority reports the time by which each event existed, and refuses evidence whose ledger dates such
an event more than a minute after the authority saw it; one that does not counts the tokens and
relies on nothing. A token got another way (from a court's or a notary's service) is kept with
`checkpoint add-timestamp`: `checkpoint show --json` gives the digest to send (`timestamp_imprint`).
The browser verifier takes the authority's root certificate as it takes witness keys.

## Browser verifier

Anyone can check evidence without installing anything. `cexchain-verify.html` is one self-contained
page: the same verification code as `cexchain verify` and `contract verify`, compiled to
WebAssembly together with OpenSSL and the contract interpreter. It takes a record's evidence bundle
or a contract instance's evidence, which it checks by running the contract again on every call. It
runs entirely in the browser and uploads nothing. It works offline, even opened from disk, and it
can be hosted on any static web server. The page checks one signature after another; the CLI checks
a bundle's signatures on every core first, then runs the same verification, which takes each
outcome only for the very same key, message, and signature bytes. Long-running processes (the
server, executors, the MCP server) also remember the signatures they have verified, so a ledger's
genesis, checkpoints, and receipts are verified once, not for every bundle that carries them.

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

## An independent verifier

[`verifiers/python`](verifiers/python/README.md) verifies evidence again, in Python: a record's,
and an instance's contract evidence, running every call's contract again. It was written from the
specification and the test vectors alone, without reading the C++ code. Every test run hands both
verifiers the same evidence: valid, damaged, and forged at the specification's edges. They must
agree.

```sh
PYTHONPATH=verifiers/python python3 -m cexchain_verify evidence.cbor --ledger-id <ledger-id>
PYTHONPATH=verifiers/python python3 -m cexchain_verify contract deal.cbor --ledger-id <home-id>
```

## Running a ledger as a service

`cexchain serve` exposes a ledger over HTTP (API v1, described by `cexchain serve --help`). Signed
statements are the authorization: the server only checks API tokens, which gate access because
statements reveal metadata. The server holds the ledger's lock only while it writes (groups
back to back keep it until the writer runs out of work), so every other command keeps working on
the same ledger.

The server is built for many clients at once. Connections are spread over a pool of I/O threads
(`--threads`, one per core by default), and reads run on all of them in parallel. Writes queue for a
single writer, which commits everything that queued during the previous sync as one group: one
lock, one sync, and signatures checked and contract calls run on every core (a call's run counts
only if its input is still the same when the call's turn comes). The next group is validated while
one syncs, and readers wait only while a statement is applied, never for a group's contract runs or
its sync. Readers only ever see durable entries, and nothing is answered before it is durable.
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

**Snapshots.** Opening a ledger replays and re-validates its whole log, which takes minutes for
millions of entries. After a checkpoint, once the log has grown 100,000 entries since the last
(`serve --snapshot-interval`), the ledger writes a snapshot of its state beside the log, and later
opens start from the newest one that checks against the log (its leaves, roots, and state
commitment), replaying only what follows. The integrity check is not dropped, only moved: a server
opened from a snapshot replays the whole log on a thread of its own and stops serving if the state
differs, and `cexchain audit` does the same. A snapshot never leaves its machine; replicas,
restores, and cluster members validate every entry they take, and make their own (`ledger snapshot
create|show|remove`).

A replica copies only what the log key signed: each checkpoint is checked first, and the entries
it covers must lead to its root before any is taken, so a replica trails its primary by the
checkpoint interval. It stops (exit 3) at the first entry that does not validate, and refuses
histories that were rolled back, so a compromised primary cannot rewrite a replica's copy. If the primary is lost,
stop it for good and run `cexchain replica promote`; witnesses would detect two primaries signing.
Operations: `GET /healthz`, Prometheus metrics at `GET /metrics`, an access log in JSON lines on
stderr, automatic checkpoints (`--checkpoint-interval`), and graceful shutdown on SIGTERM. The
`Dockerfile` builds a small image that runs as a non-root user with the ledger in `/data`.

**A web console.** `cexchain-console run` serves the ledger with a web console beside its API,
for one person on their computer or a company on its server: setting a ledger up, signing people
in with passkeys, documents and their proof, rules written and deployed, things under them,
parties, machines and AI agents, and backups, each statement approved with a passkey. It is an
application on the chain, in [`apps/console/`](apps/console/README.md).

**A search index.** `cexchain-index serve` serves a ledger read-only, beside its primary or on a
replica, with searches and reports over its records and things (`GET /v1/records`,
`/v1/instances`, `/v1/reports/...`), from an index it keeps beside the ledger; `cexchain-index
search` and `report` read the same index on the command line. It is an application too, in
[`apps/index/`](apps/index/README.md).

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
# Each side pins the other's ledger by its id. An invitation code carries it, with the
# inviter's name, the URL of its API, and a token issued for the invited party: one code each
# way, sent to that party only, and the fingerprint (the id's first 20 hex digits) compared by
# voice. Accepting adds the peer, its token kept owner-only.
cexchain peer invite reviewer --url https://ledger.holder.example      # on the holder: a cxp_ code
cexchain peer accept cxp_... --name holder                              # on the reviewer
cexchain peer invite holder --url https://ledger.reviewer.example      # and back
cexchain peer accept cxp_... --name reviewer                            # on the holder
# Or by hand: cexchain peer add holder --ledger-id <id> --url <url> --token-file holder.token

# The reviewer asks (a request record on its own ledger, with a key made for this request).
cexchain access request --peer holder --record <id> --purpose "annual review" \
    --fields result --attachments report.pdf --as reviewer.key --log-key log.key --send

# The holder sees who asked and under whose authority, and grants (a grant record on its ledger);
# a file kept with the record serves without --attach. Or dismisses it: nothing is recorded.
cexchain access inbox
cexchain access grant <request> --as approver.key --log-key log.key --attach report.pdf=report.pdf
cexchain access dismiss <request>

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
`cexchain checkpoint cosign-request --peer NAME --send`. `peer invite --witness-key PUB` puts the
witness's key in the code, and the witness follows the peer's ledger from its genesis entry
(`witness add-log --genesis FILE`; a peer reads it at `GET /v1/genesis`), so it follows the peer's
key rotations too. No third party is needed for neither side to be able to rewrite its history
unseen. The web console does all of this by itself for its parties.

## Contracts

A contract is a WebAssembly module deployed on a ledger, its *home*, that governs *instances*:
the things its rules are about, whatever they are. The home records a call on an instance only
if the contract, run on the call, accepts it. Parties on other ledgers consent on their own
ledgers, and anyone holding an instance's evidence runs the contract again on every call.
Contracts run in a deterministic, integer-only profile with metered fuel, so every verifier, the
browser included, reaches the same result. A home and parties on other ledgers:

```sh
# The home deploys a contract written in Bo and creates an instance, naming the parties.
bo build rules.bo --out rules.boc
cexchain contract deploy rules.boc --as root.key
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

# Anyone: verify the instance offline, every call run again and every consent checked; and
# rebuild the contract's code from the Bo source its deploy carries.
cexchain contract fetch --peer home --instance <instance> --out instance.cbor
cexchain contract verify instance.cbor --ledger-id <home-ledger-id> --deploy-out rules.boc
bo rebuild rules.boc
```

Arguments are written in CBOR diagnostic notation: JSON without floating point, plus byte strings
(`h'00ff'`), keys of any type, and tags (`--args-cbor FILE` takes them encoded). `contract call
--dry-run` shows what the contract would do. A consent names exact terms, among them the instance's
*head* and a digest of the arguments, so it applies to one call, once. Without a registrar, or
between ledgers that do not reach each other's APIs, consents travel as files (`.cexchain`, by any
channel): the home writes a *proposal* with the call's terms and the instance's evidence
(`contract proposal <instance> sign --args ... --out sign.cexchain`); each party checks it offline
(`contract file show sign.cexchain`) and consents on its own ledger, which writes the *consent*
file to send back (`contract consent --proposal sign.cexchain --out ok.cexchain`); and the home
records the call with the consent files, its arguments taken from them (`contract call
<instance> sign --consent ok.cexchain`). `contract verify` shows each call, its outcome, and who consented: a
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

It works several requests at once (`--concurrency`, by default one per core), never two of one
instance, each verified once: the answer is built on the evidence its request was verified in.
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

Contracts are written in Bo, whose keywords read as English, Traditional Chinese, or Simplified
Chinese, freely mixed, with a built-in vocabulary of words with fixed meanings; `bo` builds a
contract to code, writes the contract text the parties read, runs its tests, and rebuilds a
deployed contract from the source its deploy carries. The chain knows no contract language: it
runs the code and keeps the source. The language and its compiler are in
[`bo/`](bo/README.md); its reference is [`spec/bo.md`](spec/bo.md).

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

What the chain does not do yet, as of this version (the Bo language's own are in
[its README](bo/README.md#known-limits)):

- **An executor's journal** closes a request that someone else answered (a person by hand, a
  keeper's expiry) only when its next retry comes up, after its backoff.
- **An executor asks one server** (`--server`): while that member is down it waits and tries
  again; it does not fail over to another member by itself. Point it at a load balancer, or
  restart it with another member's address.
- **MCP through a server** (`mcp --server`) works on the home ledger only: its tools that reach
  other organizations' ledgers need their peers, which belong to a ledger directory.
- **Connectors:** `webhook` and `command` ship with CexChain; a connector for another system is
  a program of its own, on the same protocol ([`spec/connectors.md`](spec/connectors.md)).
- **Opening from a snapshot** still reads the log's file, decodes the state, and rebuilds the two
  Merkle trees, on every core: about eleven times faster than a full replay (3.9 s against 43 s
  for a million entries on an 8-core server), not instant. A snapshot takes about 240 bytes of
  disk an entry, twice (two files).
- **Time-stamp authorities** are trusted through their certificate chains at the token's time;
  revocation (CRL, OCSP) is not checked. Tokens signed with SM2 verify where OpenSSL verifies
  them. The web console has no screen for them yet: `cexchain-console run --tsa URL` stamps, and the
  command line lists them.
- **The independent verifier** checks the code a contract runs, not the Bo source it was built
  from (`--deploy-out` writes the deploy for `bo rebuild`); it is slow on heavy contracts.
- **Kept files** (`record issue --keep-files`, `record file add`) are kept by a single server or
  ledger directory: a cluster refuses them for now (it would not replicate them), and a backup
  of a cluster's member does not hold them.
- **`CEXCHAIN_CLOCK_OFFSET`** is for demonstrations and tests only (`serve` refuses it without
  `--allow-clock-offset`); a ledger keeps the later times it recorded.

## Security

Please report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes, not in public
issues. What evidence proves, and what it does not, is in
[the specification's security considerations](spec/README.md#17-security-considerations).

### Known security items

Open items from the security review of this version:

- **Checkpoints hold up writes.** Making a checkpoint holds the ledger's state lock across two
  disk syncs, so writes wait while a checkpoint is made (a performance trade-off).
- **A log file shortened from outside the ledger** can crash the process that maps it (a bus
  error) instead of failing with an error. It takes write access to the ledger's files.
- **The HTTP server parses a request's headers again on each read**, so a client that sends its
  headers slowly costs more CPU than it should (the header timeout and connection limits bound
  it).
- **PINs typed at a prompt** (for keys on tokens) are not wiped from memory after use.
- **The vault key is not anchored in the log.** The key that seals records' private values is
  not recorded in the ledger's signed log: a replica takes it from its primary as served.
  Anchoring it is a protocol change.
- **A restore holds the backup's files in memory**, so restoring a large backup needs as much
  memory.
- **Delivered records are not required to be witnessed.** `access accept` checks a delivery
  against the granter's ledger, but cannot yet require witness cosignatures on the delivered
  record's evidence.

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
tests/browser/run.sh build/gcc-debug/bin/cexchain build/wasm
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

## Contributing

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md) for the principles, the
definition of done, and the Developer Certificate of Origin sign-off every commit needs. Discuss
large changes in an issue first.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Third-party components and their
licenses: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Copyright 2026 Cirraya.
