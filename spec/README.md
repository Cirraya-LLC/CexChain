# The CexChain protocol

Revision v0.7 (draft). Wire protocol version 1.

This document explains the protocol in prose. The normative definitions are:

- [`cexchain.cddl`](cexchain.cddl), the structures, in RFC 8610 CDDL;
- [`../testvectors/`](../testvectors), objects built by independent implementations, which any implementation must read and reproduce byte for byte.

Where this text and the CDDL disagree, the CDDL wins. The C++ code in this repository is one implementation; it does not define the protocol.

The key words MUST, MUST NOT, SHOULD, and MAY are used as in RFC 2119.

Bo, the language contracts are written in, has its own reference: [`bo.md`](bo.md).

## Contents

1. [Overview](#1-overview)
2. [Encoding](#2-encoding)
3. [Keys, algorithms, and identifiers](#3-keys-algorithms-and-identifiers)
4. [Statements](#4-statements)
5. [Ledger rules](#5-ledger-rules)
6. [Records and private data](#6-records-and-private-data)
7. [Proof of presence](#7-proof-of-presence)
8. [The log](#8-the-log)
9. [State commitments](#9-state-commitments)
10. [Witnesses](#10-witnesses)
11. [Evidence bundles and verification](#11-evidence-bundles-and-verification)
12. [Access across organizations](#12-access-across-organizations)
13. [Ownership assets](#13-ownership-assets)
14. [Contract execution](#14-contract-execution)
15. [Contracts](#15-contracts)
16. [The HTTP API](#16-the-http-api)
17. [Security considerations](#17-security-considerations)
18. [Test vectors](#18-test-vectors)

## 1. Overview

A **ledger** belongs to one organization. It records **statements**, which are signed claims by **actors**: people, AI agents, devices, and the organization itself. Statements register actors, delegate authority, and register, endorse, move, and revoke **records**. Records are business documents such as certificates, delivery notes, and agreements.

The ledger appends each accepted statement to an append-only **log**, a Merkle tree (RFC 9162). It periodically signs a **checkpoint**, which commits to the tree's size and root. Anyone can then check, offline and without trusting the ledger's operator:

- that a statement is in the log, with an inclusion **receipt** against a checkpoint;
- that the log only grew between two checkpoints, with a consistency proof;
- that the history they were shown of a record and of everyone involved is complete, with a proof against a **state commitment** in the log;
- that independent **witnesses** saw the same history, through their cosignatures on checkpoints.

An **evidence bundle** packs all of this for one record, so a third party can verify it with nothing else.

Documents stay off the ledger. The ledger holds salted commitments to field values and attachments, and the owner discloses fields selectively.

Two organizations exchange records through the same mechanism (section 12): each step is a statement on the acting organization's own ledger, checked by the other side with an evidence bundle.

**Ownership assets** (section 13), such as receivables and warehouse receipts, live on their issuer's ledger. Each change of hands needs the consent of every party involved, given on that party's own ledger. The issuer's ledger refuses a second pledge, and witnesses stop it from showing different banks different histories.

**Contracts** (sections 14 and 15) are deterministic WebAssembly modules on a ledger. They govern business objects, called instances, whose every call the contract must accept. The parties consent on their own ledgers, as with assets, and any verifier replays the calls with the same result. A call may also create instances, such as the parts a receivable is split into.

**Machine by default.** A signature shows only that a key was used. A statement counts as a person's action only if it carries proof of presence (section 7).

## 2. Encoding

All structures are **deterministic CBOR** (RFC 8949 section 4.2.1), restricted further:

- integers and lengths in their shortest form; definite lengths only;
- map keys sorted by the bytewise order of their encodings, with no duplicates;
- no floating-point numbers, no simple values other than `false`, `true`, and `null`, no bignums (tags 2 and 3);
- text strings MUST be valid UTF-8;
- at most 32 levels of nesting, where each array, map, and tag is one level (v0.6). A statement payload and a contract output hold at most 131,072 data items, every key and value counted. Decoders MUST refuse more, so that every implementation accepts exactly the same objects.

A decoder MUST accept exactly the bytes an encoder would produce for the decoded value, so `encode(decode(x)) == x` for every accepted input. Maps with unknown keys MUST be rejected, except where the CDDL allows any key (record metadata).

Signed objects are **COSE_Sign1** messages (RFC 9052), tagged (tag 18), with:

- a protected header holding exactly `alg` (1), `content type` (3), and `kid` (4), except for receipts (section 8);
- an empty unprotected header;
- signatures in the algorithm's fixed wire format (section 3).

Content types tell signed objects apart, so a signature on one kind can never be taken for another:

| Content type | Object | Signed by |
|---|---|---|
| `application/cexchain-statement+cbor` | statement | the actor's key |
| `application/cexchain-checkpoint+cbor` | checkpoint | the log key |
| `application/cexchain-cosignature+cbor` | cosignature of a checkpoint | a witness key |
| `application/cexchain-state+cbor` | state commitment | the log key |

## 3. Keys, algorithms, and identifiers

**Signature algorithms**, identified by COSE algorithm identifiers:

| Algorithm | COSE id | Public key | Signature |
|---|---|---|---|
| Ed25519 | -19 | 32 bytes | 64 bytes |
| ECDSA P-256 with SHA-256 (ESP256) | -9 | 65 bytes, uncompressed SEC 1 | 64 bytes, r ‖ s, low S |
| SM2 with SM3 (GB/T 32918, GM/T 0009) | -65537 (private use) | 65 bytes, uncompressed | 64 bytes, r ‖ s |
| ML-DSA-44 / 65 / 87 (FIPS 204) | -48 / -49 / -50 | FIPS 204 | FIPS 204 |

SM2 signatures use the default distinguishing identifier `1234567812345678`. ESP256 signatures MUST be in low-S form. A public key is encoded as `[alg, key bytes]`.

**Hash algorithms.** Each ledger uses one hash, fixed at genesis: SHA-256 (COSE -16) or SM3 (private use, -65538). Every identifier, Merkle tree, and commitment on that ledger uses it. Below, `HASH` means the ledger's hash.

**Identifiers** are 32-byte hashes:

- `statement_id = HASH(Sig_structure)`: the hash of exactly the bytes that were signed (RFC 9052 section 4.4, empty external_aad). It never depends on the signature bytes, so the same signed content has one id, however many times it is signed.
- `ledger_id` is the statement id of the genesis statement. It commits to the organization's name, first root key, first log key, and hash. A party that knows a ledger id therefore knows the keys the ledger started with; later ones are set by rotations in the log, each signed by the root key in effect (section 8).
- The organization's actor id is the ledger id. Every other actor, delegation, and record is identified by the statement id that created it.
- `kid = HASH(deterministic-CBOR([alg, key]))`. It is the COSE `kid` of everything the key signs.

## 4. Statements

A statement payload (`statement-payload` in the CDDL) holds:

| Key | Field | Notes |
|---|---|---|
| 0 | protocol version | 1 |
| 1 | statement type | see below |
| 2 | ledger id | absent only in genesis |
| 3 | actor id of the signer | absent only in genesis |
| 4 | delegation id | the delegation the signer acts under, if any |
| 5 | issued at | milliseconds since the Unix epoch, as claimed by the signer |
| 6 | nonce | 16 random bytes |
| 7 | body | depends on the type |
| 8 | proof of presence | section 7 |
| 9 | provenance | for AI agents: model, version, input commitment, tools pinned by digest |

Statement types:

| Type | Name | Body |
|---|---|---|
| 1 | genesis | hash, organization name, root key, log key |
| 2 | actor-register | kind (person 1, agent 2, device 3), name, key, responsible person, agent profile |
| 3 | actor-rotate-key | actor, new key |
| 4 | actor-revoke | actor, reason |
| 5 | delegation-grant | grantee, scope |
| 6 | delegation-revoke | delegation, reason |
| 7 | actor-set-presence | person, presence credentials (at most 16) |
| 8 | ledger-rotate-log-key | the new log key (v0.4) |
| 16 | record-register | record type, field root, field count, attachments, public metadata |
| 17 | record-endorse | record, role |
| 18 | record-transition | record, from state, to state |
| 19 | record-revoke | record, reason |
| 20 | asset-action | asset, action, head, counterparty, quantity, consents, reference (v0.5; section 13) |
| 21 | contract-deploy | code, interface, language, compiler, source, name (v0.6; section 15) |
| 22 | contract-call | contract or instance, function, arguments, head, consents, reference (v0.6) |
| 23 | contract-retire | contract, reason (v0.6) |

## 5. Ledger rules

A ledger accepts a statement only if every rule below holds at its registration time, `now`, by the ledger's clock. Replaying the log applies the same rules at each entry's recorded registration time. So any party holding the log can re-derive the ledger's state, and a log that breaks a rule is detected.

**Identity and integrity**

- The statement is for this ledger. It is not registered already, and its (actor, nonce) pair was never accepted before, so a payload cannot be replayed even when re-signed with a rotated key.
- `issued at` is no later than `now` plus 5 minutes.
- The signer is a registered, unrevoked actor, and the statement is signed with that actor's current key. The COSE `kid` MUST match it.
- An agent's statements MUST name a model in their provenance.

**Authority**

- The organization acts without a delegation.
- Any other actor needs a delegation granted to it whose scope covers the statement type, and the record type for record statements. There are two exceptions:
  - an actor may rotate its own key, and a person with presence credentials must then prove presence;
  - a person may replace their own presence credentials while proving presence with one already registered.

  In both, the proof MUST be user-verified (section 7).
- A scope never covers genesis or ledger-rotate-log-key.
- Every delegation in the chain from the organization to the signer MUST be unrevoked and valid at `now` (scope keys 3 and 4). Every grantor in the chain MUST be unrevoked. If any delegation in the chain requires presence (scope key 6), the statement MUST carry valid proof of presence.
- A delegation may only narrow its grantor's scope:
  - statement types and record types are subsets of the grantor's;
  - the validity window lies inside the grantor's;
  - "may delegate further" (scope key 5) must be set on the grantor's delegation;
  - presence, once required, stays required.
- Chains have at most 16 delegations.
- A scope may list contracts (scope key 7, v0.6). Calls and retires under it must then act on one of them, and a delegated scope's contracts are a subset of its grantor's (section 15).

**Bodies**

- **Actors.**
  - New keys must not be weak, must not belong to another actor, must not be one of the actor's presence keys, and must not be a log key of the ledger, current or past.
  - An agent names a responsible actor, which must be a person.
  - The organization actor cannot be revoked. Only the organization itself rotates its root key (actor-rotate-key on the ledger id).
  - Only people have presence credentials, and only people prove presence. A presence credential's key must not be the person's signing key, any actor's key, or a log key: it is a second key.
- **The log key.** Only the organization rotates it (ledger-rotate-log-key), without a delegation. The new key must not be weak, must not be an actor's key, and must never have been a log key of this ledger.
- **Delegations.** Only the grantor or the organization may revoke a delegation. Revoking an actor or a delegation ends everything that depends on it, because authority is checked through the whole chain at every statement.
- **Records.** Records follow their type's lifecycle (section 6). Transitions must start from the record's current state and be allowed by its type. Endorsement roles must be defined by the type, and an actor endorses a record at most once per role. A revoked record accepts no further statements.
- **Assets.** An asset's registration must carry its type's metadata, and asset actions follow the rules of section 13. Assets refuse record-transition and record-revoke: they change only through asset actions. For authority, an asset action acts on the asset's record type.
- **Contracts.** Deploys, calls, and retires follow the rules of section 15. A call is registered only if its contract, run on the call, accepts it.

## 6. Records and private data

**Field commitments.** A record's fields are `[name, salt, value]` triples with a fresh 16-byte salt each. The leaves are their deterministic-CBOR encodings, sorted by name, one per name. A verifier refuses a bundle that discloses one leaf twice, or discloses leaves whose names do not ascend with their indices. The record commits to the RFC 9162 Merkle root over the leaves, and to their count. To disclose a field, the owner gives the leaf and its inclusion path. Undisclosed fields stay hidden, and their salts stop dictionary attacks on small value spaces. Deleting a field's value and salt makes its commitment meaningless (crypto-shredding).

**Attachments.** The record carries each attachment's name, media type, size, and commitment `HASH(salt || content)`, never the content.

**Public metadata.** A record may carry a map with text keys, which is disclosed in the clear (key 5 of `record-register-body`).

**Built-in record types** define lifecycles:

| Type | Initial state | Transitions | Roles |
|---|---|---|---|
| `cexchain.certificate/1` | issued | issued ⇄ suspended | inspector, approver |
| `cexchain.delivery/1` | dispatched | dispatched → delivered, dispatched → rejected, delivered ⇄ disputed | carrier, receiver |
| `cexchain.agreement/1` | proposed | proposed → effective, proposed → withdrawn, effective → terminated | party, witness |
| `cexchain.access-request/1` | requested | requested → withdrawn | none |
| `cexchain.access-grant/1` | granted | none (revoke the record) | none |
| `cexchain.access-receipt/1` | received | none | none |
| `cexchain.asset-consent/1` | given | given → withdrawn | none |
| `cexchain.receivable/1` | active | asset actions only (section 13) | none |
| `cexchain.warehouse-receipt/1` | active | asset actions only (section 13) | inspector, insurer |
| `cexchain.contract-consent/1` | given | given → withdrawn | none |

Other record types use a generic lifecycle: initial state `registered`, no transitions, any role.

**The vault** is informative and local to an implementation. The reference implementation keeps each record's values and salts sealed with HPKE (RFC 9180, base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM) to the ledger's vault key. Each sealed file is bound to its ledger and record.

## 7. Proof of presence

A person proves presence for exactly one statement with a registered credential. The challenge is

```
challenge = HASH("CexChain presence v1" || kid || P)
```

where `kid` is the statement's COSE kid and `P` is the payload encoded without key 8. Binding the kid stops a proof from being reused with a rotated key.

**Passkeys (WebAuthn).** The proof is a WebAuthn assertion over the challenge. A verifier checks, for the signer's credential with the proof's credential id:

1. `authenticatorData` begins with `SHA-256(rp id)` and has the user-present flag set. The user-verified flag is reported. It is required when a person rotates their own key or replaces their own credentials (section 5): a touch, perhaps tricked, must not hand an identity over.
2. `clientDataJSON` passes the limited verification algorithm of WebAuthn Level 3: type `webauthn.get`, this challenge, an origin that belongs to the relying party, and no cross-origin use. The exact byte layout is in the CDDL.
3. The signature verifies over `authenticatorData || SHA-256(clientDataJSON)`.

**Hardware keys** (USB keys or UKey, smart cards, HSMs). The credential has no relying party and may use any signature algorithm, SM2 included. The proof is the key's signature over the challenge itself. The key never leaves the device and signs only after the person enters its PIN.

This is weaker evidence than a passkey's touch, and depends on how the token is set up:
- **Implementations.** They MUST use a second key, not the signing key. They MUST refuse a key the token marks as extractable or not sensitive. They MUST NOT take the PIN from configuration (such as a PIN written into the key's URI).
- **Tokens.** Tokens that need a touch or a PIN-pad entry for each signature give the strongest assurance.

A hardware key's proof counts as user-verified: the token signs only once its PIN is entered.

**What presence defends against.** Presence defeats a stolen key file: the thief also needs the person's authenticator, in their hands. It does not defeat malware on the person's own machine, which can show a misleading page and ask for a touch. The reference implementation's passkeys use the relying party id `localhost`, from a one-time local page; sites on the internet cannot use them at all. A relying party id on the organization's own domain would need a hosted page that signs any challenge a link hands it, so it adds a phishing surface without stopping local malware.

Verifiers report how presence was proven. A statement without proof of presence is attributed to a machine, whoever signed it.

## 8. The log

Each accepted statement becomes a **log entry**: `{1: id, 2: registered at, 3: the signed statement}`. Alternatively, key 4 replaces key 3 and holds a state commitment (section 9). The tree commits to the encoded log entries, in order, under the ledger's hash.

A **checkpoint** is signed by the log key over `{1: ledger id, 2: hash, 3: tree size, 4: root, 5: timestamp}`. The tree size is at least 1, since genesis is always in the log.

**The log key in effect.** The organization may rotate the log key (statement type 8) and its root key (actor-rotate-key on itself), each signed by its root key in effect. The log key in effect for a tree of N entries is the one set by the last rotation at an index below N, or the genesis key. It signs checkpoints of size N and receipts against them. A rotation therefore takes over from the first state commitment or checkpoint after it, and older checkpoints stay valid under the key that signed them. Log keys never repeat.

A **receipt** is an RFC 9942 COSE inclusion receipt for an encoded log entry:
- protected header `{1: alg, 4: kid, 395: vds}`;
- unprotected header `{396: {-1: [inclusion proof]}}`;
- detached payload, which is the Merkle root at the proof's tree size.

`vds` is 1 (RFC9162_SHA256) for SHA-256 ledgers. For SM3 ledgers it is -65537 (private use: the RFC 9162 tree with SM3).

## 9. State commitments

Inclusion proves that a statement is in the log, not that nothing was left out. A bundle could omit a later revocation. State commitments close that gap.

The **state** is a compact sparse Merkle tree over every actor, delegation, record, contract, and instance. It is keyed by object id, read as 256 bits, most significant first:

```
empty subtree            HASH("")
subtree of one object    HASH(0x00 || state-leaf)
any other subtree        HASH(0x01 || left || right)
state-leaf = [kind (actor 1, delegation 2, record 3, contract 4, instance 5), id, history]
```

A leaf's history lists every log index that created or changed the object:
- actors: registration, key rotations, presence changes, revocation;
- delegations: grant and revocation;
- records: every statement about them;
- contracts: deploy and retire;
- instances: creation and every call. An instance created by another's call (section 15) starts with that call, which its parent's history lists too.

Each key has exactly one position, and leaf and node hashes are domain-separated. So one root cannot give two histories for one id.

When it checkpoints, the ledger first appends a **state commitment** as a log entry, unless the last entry already is one. The commitment is signed by the log key in effect at its index over `{1: ledger id, 2: hash, 3: tree size = its own index, 4: state root, 5: timestamp}`. Then the ledger signs a checkpoint that covers it.

The organization's leaf lists every rotation of its root key and of the log key. The organization is involved in every bundle, so a complete bundle shows every rotation.

Being in the log, a commitment is witnessed like any entry and can never be withdrawn. Replaying the log MUST check every commitment against the replayed state. A false root is therefore a permanent, detectable fork, not a quiet lie.

## 10. Witnesses

A witness is an independent party: another organization, an auditor, or a regulator. It cosigns a ledger's checkpoints only if each one extends the history it cosigned before. For each ledger, the witness keeps the ledger id, the root key and log key in effect, the index of the last key rotation it followed, and the size and root it last cosigned. It learns the first keys from the genesis entry, checked against the ledger id it learned out of band. (A witness given only the log key cannot follow a rotation.)

A **cosign request** is `{1: signed checkpoint, 2: old size, 3: consistency proof, ? 4: key rotations}`. Key 4 lists every key rotation below the checkpoint's size as `[index, log entry, inclusion path]`. The witness first follows the rotations after the last one it followed: each must be in the checkpoint's log and signed by the root key in effect. Then it cosigns only if all of these hold:

1. the checkpoint is for that ledger and signed by the log key the rotations lead to;
2. the tree hash is the ledger's;
3. the old size equals the size it last cosigned (otherwise it refuses, and the operator asks again from that size);
4. the new size is not smaller;
5. the RFC 9162 consistency proof shows the new tree extends the old one.

A **cosignature** is a COSE_Sign1 by the witness key over the same checkpoint payload bytes, with the cosignature content type. Asking again for the checkpoint cosigned last MAY be answered with a fresh cosignature of it, so a lost answer can be retried.

Two organizations can witness each other's ledgers. Neither can then rewrite or fork its history without the other seeing it.

Once a witness has followed a log key rotation, it accepts only the new key. A leaked old log key can therefore not get a fork cosigned by it.

## 11. Evidence bundles and verification

An evidence bundle (`evidence-bundle`) holds:

- the record id, or an instance's id (section 15);
- log entries with their receipts, in ascending order, starting with genesis: the record's statements and every statement they depend on (signers' registrations and key rotations, delegation chains, referenced actors), and every rotation of the organization's keys below the checkpoint's size. For an instance created by a call, also its ancestors' calls up to the one that created each next generation (section 15);
- the signed checkpoint all receipts lead to, and witness cosignatures of it;
- optional field disclosures and attachment openings (salts; the contents travel alongside);
- state proofs for every involved object.

A verifier MUST:

1. Take the ledger's identity, hash, and first keys from the genesis entry. If it expects a particular ledger, check the ledger id.
2. Check every receipt's inclusion proof against the checkpoint (same size and root), with indices strictly ascending from 0.
3. Replay the included statements under the ledger rules (section 5), at their registration times. This follows the organization's key rotations.
4. Verify the checkpoint and every receipt's signature with the log key in effect at the checkpoint's size, and each state commitment with the one in effect at its index. A bundle that leaves out a log key rotation fails here, since keys never repeat.
5. Check disclosed fields against the record's field root and count, and any attachment contents provided against their commitments.
6. Count cosignatures only by witnesses it trusts, each witness once.
7. If the last entry the checkpoint covers is a state commitment (included with its receipt):
   - check it as replay would;
   - verify every state proof against its root;
   - for the record and each involved object, require a proof whose leaf equals that object's leaf in the replayed state. The involved objects are each event's signer, an agent signer's responsible person, and every delegation in the chain with its grantor; for an instance, also its contract. For an instance created by a call, its ancestors' included calls count as events too, and the ancestors themselves need no proof (section 15).

   Only then is the report **complete**: nothing, such as a later revocation, was left out.

A report states:
- who did what, when, and under whose authority;
- for each event, whether a person proved presence and how, and any AI provenance;
- the disclosed fields and attachment checks;
- the witnesses;
- whether it is complete.

## 12. Access across organizations

Two organizations, each with its own ledger, share a record in four steps. In the example, a bank (the requester) asks a factory (the granter):

| Step | Record type | On whose ledger | Metadata (key 5) |
|---|---|---|---|
| Request | `cexchain.access-request/1` | the bank's | `ledger` (asked), `record`, `purpose`, `until`, `recipient` (X25519 key), optional `fields`, `attachments` |
| Grant | `cexchain.access-grant/1` | the factory's | `ledger` (requester), `request`, `record`, `fields`, `attachments`, `until`, `recipient` |
| Delivery | not a record: a `delivery` object | sent to the bank | grant evidence, and contents sealed with HPKE |
| Receipt | `cexchain.access-receipt/1` | the bank's | `ledger` (granter), `grant`, `delivery` (SHA-256 of the delivery) |

Each side learns the other's **ledger id** out of band and pins every bundle it receives to it. Because the steps are records, delegations decide who may request, grant, or acknowledge, and proof of presence shows when a person approved.

- **Request.** The bank makes a fresh X25519 key for the request and records the request. It sends the request's evidence bundle. The factory checks the following:
  - the bundle verifies for the bank's ledger and is complete;
  - it is a live access request that names the factory's ledger;
  - it has not expired.

  The report shows who asked, under whose authority, and whether they were present.
- **Grant.** The factory records a grant for at most what was asked and until no later than the request's end.
- **Delivery.** The factory builds `{1: 1, 2: grant bundle, 3: {1: enc, 2: ciphertext}}`. The ciphertext seals `delivery-contents` with HPKE to the request's key, with info `"CexChain delivery v1"` and the grant id as additional authenticated data. `delivery-contents` holds the record's bundle with only the granted disclosures and openings, and the granted attachments' contents.
- **Acceptance.** The bank MUST check all of the following, and only then acknowledge:
  1. the grant verifies for the factory's ledger, which is the ledger the request asked, and is complete;
  2. the grant is live, and names the bank's ledger, its request, and its key;
  3. the grant answers the request: the same record, fields and attachments the request asked for (or fewer), and an end no later than the request's;
  4. the grant has not expired;
  5. the contents open with the request's key;
  6. the record bundle verifies for the factory's ledger at the grant bundle's checkpoint, is complete, and is the granted record, which is not revoked;
  7. the record bundle discloses exactly the granted fields, each once;
  8. the delivery holds exactly the granted attachments, each opened and matching its commitment.
- **Receipt.** The bank records the receipt and sends its evidence. The factory checks that the receipt comes from the ledger the grant was made to, names the factory's grant, and gives the hash of the delivery made under that grant. A stored receipt is never replaced by a different one.
- **Serving deliveries** (informative). A server hands out a delivery only to the peer it was granted to, and only while the grant is live and unexpired.

Revoking a grant stops future deliveries. It cannot make a recipient forget, but the receipt makes access accountable.

## 13. Ownership assets

An **asset** is a record of an asset type whose holder can change: a receivable, a warehouse receipt. The threat is no longer only tampering but double spending: pledging or selling one asset twice. CexChain prevents it without a shared chain:

- **One home.** Each asset lives on exactly one ledger, its **home**: its issuer's (the debtor's for a receivable, the warehouse's for a receipt). Only the home changes it, and its rules refuse every change the asset's state does not allow. A second pledge breaks a rule, so a log that holds one fails replay.
- **Parties are ledgers.** The holder, the pledgee, and the payee are other organizations, identified by ledger id. No party is the home ledger itself.
- **Consent on the party's own ledger.** A party consents to an action by registering a `cexchain.asset-consent/1` record on its own ledger, under its own delegations, with proof of presence if a person approved. The home records the action only once every party it needs has consented to the same terms, and the action cites each consent.
- **Witnesses** stop the home from showing different histories to different parties (section 10).

**Types.** Their metadata (key 5 of the registration) is public to whoever holds the asset's evidence, and checked by the rules:

| Type | Metadata | States |
|---|---|---|
| `cexchain.receivable/1` | `holder` (the first creditor's ledger), `amount` (≥ 1, in the currency's minor unit), `currency` (ISO 4217, three capital letters), `due` (ms) | active, pledged, frozen, paid, disputed; settled, cancelled (final) |
| `cexchain.warehouse-receipt/1` | `holder` (the depositor's ledger), `quantity` (≥ 1), `unit` (1 to 16 bytes) | active, pledged, frozen; redeemed, cancelled (final) |

Other metadata keys are allowed. Confidential terms (contracts, invoices, the goods) belong in fields and attachments, disclosed selectively. A new asset is active, held by `holder`.

**Splitting.** These assets do not split. A receivable that is split into parts for transfer along a supply chain is a contract instance whose parts are its children (section 15, v0.7). Nothing converts between the two.

**The head.** An asset's head is the log index of its registration or of its latest asset action (endorsements do not count). Every action and every consent names the head it follows. A consent therefore applies only to the asset as its party saw it, and only once.

**Actions** (statement type 20, `asset-action`):

| Action | Types | From | To | Consents from | Effect |
|---|---|---|---|---|---|
| transfer | both | active | active | the holder and `to` | the holder becomes `to` |
| pledge | both | active | pledged | the holder and `to` | `to` becomes the pledgee |
| release | both | pledged | active | the pledgee | no pledgee |
| enforce | both | pledged | active | the pledgee | the pledgee becomes the holder; no pledgee |
| redeem | receipt | active, pledged | unchanged, or redeemed when nothing remains | the holder, and the pledgee if pledged | the quantity falls by `quantity` |
| pay | receivable | active, pledged, disputed | paid | none | the payee becomes the pledgee if there is one, otherwise the holder (kept when paid again after a dispute) |
| confirm | receivable | paid, disputed | settled | the payee | |
| dispute | receivable | paid | disputed | the payee | |
| freeze | both | active, pledged, paid, disputed | frozen | none | remembers the state |
| unfreeze | both | frozen | the remembered state | none | |
| cancel | both | active | cancelled | the holder | |

An asset action MUST be refused unless:

- the asset exists, is of an asset type, and is not in a final state;
- `head` is the asset's head;
- the action is defined for the asset's type and allowed from its state;
- `to` is present exactly for transfer and pledge, and is neither the home ledger nor the holder;
- `quantity` is present exactly for redeem, at most the quantity remaining;
- `consents` cites exactly one consent from each party the table names, ascending by ledger, and is absent for pay, freeze, and unfreeze.

Pay, freeze, and unfreeze are the home's own word: a debtor's claim that it paid (which the payee confirms or disputes), or a freeze under a court order. Their `reference` says which.

**Consents.** The consent's metadata (`asset-consent`) names the terms (home ledger, asset, action, head, and `to` and `quantity` where the action has them), an expiry `until`, and optionally a `reference`, such as a financing contract or a registry filing. A consent reference in an action is `[ledger, record, bundle]`: the party's ledger, the consent record, and the hash, under the home's hash, of the consent's evidence bundle the home verified. Before recording an action, the home MUST check each consent bundle as a verifier does (step 3 below), and MUST keep the bundles it pins.

**Asset evidence** (`asset-evidence`) is the asset's evidence bundle with every consent bundle its actions pin. A verifier MUST:

1. verify the asset bundle for the expected home ledger (section 11) and require it to be complete, since only a complete history shows the asset's current state (not pledged, say);
2. replay the asset's actions to its current holder, pledgee, payee, state, and quantity;
3. for each consent reference, find the bundle with that hash and check that it verifies for the referenced ledger, completely; is about the referenced record, a live `cexchain.asset-consent/1` record (state given, not revoked); carries the action's terms; and lapses no earlier than the action's registration time;
4. refuse bundles that no reference pins, and references without a bundle.

The report shows the chain of title: each action, who consented to it, under whose authority, whether a person proved presence, and any AI provenance.

**Lending against an asset.** A lender MUST NOT fund until its pledge is in a checkpoint cosigned by witnesses it trusts. From then on, a second pledge is refused or detected:
- a consent with an old head no longer matches;
- a pledged asset cannot be pledged again;
- a home that forks its log to show another lender an unpledged asset needs that lender's witnesses to cosign the fork, and a witness cosigns only one history. So lenders SHOULD require a common witness, such as a regulator or a third-party witness service. Two checkpoints of one size with different roots, both signed by the home's log key, also prove the home's misconduct.

**Limits.**
- A home can refuse to record an action (censorship). It cannot move an asset without its parties' consents, nor fork unseen.
- The ledger cannot know whether goods exist: a warehouse could issue two receipts for the same goods. Every receipt it issued is in its log, for auditors and witnesses.
- Legal registries of pledges and transfers are not replaced; a consent's `reference` can carry the filing number.

## 14. Contract execution

*Draft for revision v0.6. This section defines how contract code runs. Section 15 defines the statements that deploy and call contracts.*

Contracts are WebAssembly modules (WebAssembly 2.0, binary format) restricted to a **deterministic profile**. The home ledger runs a contract when it registers a call. Every verifier runs it again when it replays the call. For a given module and input, every implementation MUST produce the same outcome: the same output or the same trap, and the same **fuel** used.

### 14.1 The profile

A module is refused unless all of the following hold.

**Size and structure**
- At most 524,288 bytes.
- No start section.
- Custom sections are ignored, but count towards the size.

**Types**
- Value types are only `i32` and `i64`, in function types, locals, globals, and block types.
- At most 1,024 types, each with at most 32 parameters and 16 results.

**Imports**
- Functions only, from the module `cexchain`, among the host functions of section 14.4, each with its exact type and at most once.

**Memory and table**
- At most one memory, defined in the module, of at most 16 pages (64 KiB each). The maximum, when absent, is 16.
- At most one table, `funcref`, of at most 1,024 elements.

**Globals**
- At most 1,024, of type `i32` or `i64`.
- Each initialized by a single `i32.const` or `i64.const`.

**Exports**
- The memory, named `memory`.
- A function `cexchain_call` of type `[] -> []`, defined in the module.
- Other exports are allowed and ignored.

**Segments**
- Element segments: only the active form for table 0 (flag 0), with an `i32.const` offset and function indices, within the table's initial size.
- Data segments: active (flag 0, with an `i32.const` offset, within the memory's initial size) or passive (flag 1); at most 1 MiB in all.

**Functions**
- At most 10,000 functions, counting imports.
- At most 4,096 locals each, counting parameters.
- Bodies of at most 131,072 bytes.

**Instructions:** only these.

| Kind | Instructions |
|---|---|
| Control | `unreachable`, `nop`, `block`, `loop`, `if`, `else`, `end`, `br`, `br_if`, `br_table`, `return`, `call`, `call_indirect` (table 0) |
| Parametric | `drop`, `select`, `select t` (with one value type) |
| Variable | `local.get`, `local.set`, `local.tee`, `global.get`, `global.set` |
| Memory | integer loads and stores (all widths), `memory.size`, `memory.grow`, `memory.init`, `data.drop`, `memory.copy`, `memory.fill` |
| Numeric | `i32.const`, `i64.const`; all `i32` and `i64` comparisons and arithmetic; `i32.wrap_i64`, `i64.extend_i32_s`, `i64.extend_i32_u`; `i32.extend8_s`, `i32.extend16_s`, `i64.extend8_s`, `i64.extend16_s`, `i64.extend32_s` |

Every floating-point instruction is refused, and so are SIMD, atomics, exceptions, tail calls, and reference instructions.

**Validation** follows the WebAssembly specification, with two additions:
- at most 1,024 control frames are open at once, the function's own included (so at most 1,023 nested blocks, loops, and ifs);
- each function's **maximum operand stack height** is at most 65,535. That height is the largest number of values on the operand stack after any instruction, as counted by the validation algorithm of the WebAssembly specification's appendix, unreachable code included.

### 14.2 Instantiation

- The memory starts zeroed at its initial size.
- Active data segments are copied in order, then dropped.
- Active element segments fill the table, whose other elements are null.
- Globals take their initial values.

Instantiation uses no fuel.

### 14.3 Execution and fuel

An invocation calls `cexchain_call` once. It has **10,000,000 fuel**, and each instruction executed consumes fuel *before* it takes effect.

| Cost | Instructions |
|---|---|
| 0 | `else` and `end` (reaching them) |
| 1 | every other instruction, except those below; including `block`, `loop`, `if`, every branch, `unreachable` (then trapping), loads, stores, `memory.size`, and `data.drop` |
| 2 | `call` and `call_indirect`, plus the cost of a host function they call |
| 1 + 1024 × *n* | `memory.grow` by *n* pages; 1 if the memory would exceed its maximum (it then returns −1) |
| 1 + ⌈*n* / 64⌉ | `memory.copy`, `memory.fill`, `memory.init` of *n* bytes, charged once their operands are taken and before their bounds are checked |

**Branches.** A branch to a loop resumes the loop's body at its first instruction, so re-entering the loop costs nothing beyond the branch.

**Limits.** An instruction that costs more than the fuel left traps with *out of fuel*. All the fuel is then used.

**Calls.** After a call's cost is charged:
- Calling a function defined in the module first checks the call depth: with the entry counted as 1, it must stay at most 256.
- It then checks the stack budget. Each active frame reserves one slot per local, parameters included, plus its function's maximum operand stack height. All active frames together reserve at most 131,072 slots.

**Traps.** These end the invocation:

| Trap | When |
|---|---|
| `unreachable` | an `unreachable` instruction |
| `divide by zero` | an integer division or remainder by zero |
| `integer overflow` | the most negative value divided by −1 (`div_s`) |
| `out of bounds` | a memory access, or a host function's memory range, beyond the memory; a `memory.init` beyond its segment |
| `indirect call out of range` | an index beyond the table |
| `indirect call to null` | an element that is null |
| `indirect call type mismatch` | an element whose function has another type |
| `out of fuel` | the fuel is exhausted |
| `call depth exceeded` | the call depth would exceed 256 |
| `stack budget exceeded` | the stack budget would be exceeded |
| `output written twice` | `output_write` called a second time |
| `output too large` | an output of more than 1 MiB |
| `aborted` | the contract called `abort` |

**The result.** An invocation that returns without a trap succeeds, and its output is what `output_write` wrote, or empty. *Fuel used* is 10,000,000 minus the fuel left, in either case.

### 14.4 Host functions

Imported from the module `cexchain`. Pointers and lengths are unsigned. A range `[ptr, ptr + len)` must lie within the memory, or the call traps with *out of bounds*. Each function charges its cost first, then checks its ranges, in the order listed.

| Function | Type | Cost | Effect |
|---|---|---|---|
| `input_size` | `[] -> [i32]` | 1 | the input's length |
| `input_read` | `[i32] -> []` | 1 + ⌈length / 64⌉ | copies the whole input to `ptr` |
| `output_write` | `[i32 i32] -> []` | 1 + ⌈len / 64⌉ | sets the output to `[ptr, ptr + len)`. Traps if an output was already written, then if `len` exceeds 1 MiB, then on the range |
| `hash` | `[i32 i32 i32] -> []` | 64 + ⌈len / 64⌉ | writes the ledger's hash (SHA-256 or SM3) of `[ptr, ptr + len)` to `[out, out + 32)`, checking the input range first |
| `abort` | `[i32 i32] -> []` | 1 | traps with *aborted*; the reason is the first min(`len`, 1,024) bytes at `ptr` |

The input and output are bytes to the execution layer. Their contents, deterministic CBOR, are defined in section 15.

## 15. Contracts

*Draft for revision v0.6; v0.7 adds instances created by a call.*

A **contract** is a module, in the profile of section 14, deployed on a ledger: its **home**. An **instance** is one business object the contract governs, such as an agreement, a bill, or an order. Like an asset (section 13), an instance lives on its home ledger only:
- only the home records its calls, and only if the contract accepts them;
- its **parties** are organizations, named by ledger id under roles such as `supplier` or `bank`;
- a party other than the home consents on its own ledger;
- every verifier replays the calls with the same contract and reaches the same result.

A call may also create instances of its contract, called **children**, such as the parts a receivable is split into (v0.7).

**Statements.**

| Type | Name | Body |
|---|---|---|
| 21 | contract-deploy | code, interface, language, compiler; optionally the source and a name |
| 22 | contract-call | the contract (to create an instance) or the instance and its head; the function, the arguments, consents, a reference |
| 23 | contract-retire | contract, reason |

**Deploy.** A contract is identified by its deploy statement's id, and its code never changes: a new version is a new deploy.
- **Code:** a module that loads under the profile (section 14.1), at most 524,288 bytes.
- **Interface:** each function's name (UTF-8, 1 to 64 bytes; at most 256 functions) and kind: 1 creates an instance, 2 acts on one. At least one function creates.
- **Language** (1 to 32 bytes: `bo`, `wasm`) and **compiler** (1 to 128 bytes, with its version).
- **Source** (at most 262,144 bytes), so that anyone can rebuild the module and compare.
- **Name** (1 to 256 bytes), for people.

**Contracts written in Bo.** Bo, the language CexChain's contracts are written in, is specified in [`bo.md`](bo.md). A deploy whose language is `bo` SHOULD carry, as its source, a **`bo-source` bundle** (`bo-source` in the CDDL): `{1: 1, 2: edition, 3: source, 4: [+ [id, version, digest]], ? 5: [+ pack]}`.
- **Source:** the source as written (UTF-8, comments included) and the Bo edition it is written in. Whoever holds the deploy reads it, comments too.
- **Packs:** every language pack the source was read with, by ascending id: its id, its version, and the hash under the home's hash of the pack's canonical CBOR. Packs that are not official are embedded in full (key 5, as their canonical CBOR, by ascending id); a reference without one names an official pack, which a Bo compiler carries in every released version. A pack maps spellings to concepts and never changes what runs, but it decides how the source reads, so the digests pin it.
- **Compiler:** the compiler string names the compiler, its release, its codegen version, and the edition it reads: `cexchain-bo 0.0.1; codegen 2; edition 1`. The same codegen version builds the same bytes from the same source, in any language and on any machine, and a compiler keeps writing the codegen versions before its own, so that older deploys rebuild ([`bo.md`](bo.md), section 16).

A verifier SHOULD rebuild the code: decode the bundle, find each pack (the official ones from its compiler, the others from the bundle) and check its digest, build the source, and compare the module, the interface, and the name with the deploy's. It reports one of:
- **rebuilds:** the source builds to the deployed code;
- **differs:** the compiler the deploy names builds something else, so the source is not the code's. The verifier SHOULD fail the evidence;
- **malformed:** no source, not a bundle, or a pack that does not match its digest or does not read. The verifier SHOULD fail the evidence;
- **another compiler:** another compiler, or another release or codegen version, built it, and this one builds something else. The verifier says which and MAY require a rebuild with that compiler; it never reports this as a forgery.

The ledger rules do not rebuild: a home that deploys a source that is not its code is caught by every verifier that rebuilds. For another Bo compiler, the language's behaviour is normative and these code bytes are not.

**Retire.** A retired contract creates no more instances. Its instances carry on.

**Call.** A call names either:
- a contract and a function of kind 1, to **create** an instance, whose id is then the call's statement id; or
- an instance, its **head**, and a function of kind 2. The head is the log index of the instance's latest call (at first, its creation).

The **arguments** are any CBOR value, at most 65,536 bytes encoded. Whoever holds the instance's evidence sees them, so values a contract must check are disclosed to every verifier.

**Ledger rules.** A contract-call MUST be refused unless:
- exactly one of contract and instance is present, and the head is present exactly with an instance;
- for a creation: the contract exists and is not retired, the function is in its interface with kind 1, and the call cites no consents;
- otherwise: the instance exists and is not final, the head is its head, and the function is in its contract's interface with kind 2;
- the consents, if any, are 1 to 16, strictly ascending by ledger, and none is from the home;
- the contract, run on the call's input (below), succeeds with an `accept` output;
- if the accept creates children (key 6, v0.7): the contract is not retired, and the instance the call acts on, or creates, has a depth below 8.

A contract-deploy MUST be refused unless its code loads and its interface is well formed. A contract-retire MUST name a contract that exists and is not retired.

**Authority.** Delegations cover types 21 to 23 like any other type. Scope key 7, when present, lists the contracts the grantee may act on: a call or a retire must act on one of them, where a call on an instance acts on the instance's contract. A delegated scope's contracts are a subset of the grantor's. Key 7 does not restrict deploys.

**The input** is a deterministic CBOR map, which the contract reads with `input_read`:

| Key | Field |
|---|---|
| 1 | the function |
| 2 | the arguments |
| 3 | the home ledger's id |
| 4 | the contract's id |
| 5 | the instance, absent for a creation: `{1: id, 2: head, 3: state, ? 4: status, ? 5: parties, ? 6: [parent, depth]}`; key 6 only for a child (v0.7) |
| 6 | the caller: `[actor, signer]` |
| 7 | the call's registration time |
| 8 | the consents, if any, in the call's order: `[ledger, signer]` each |

A **signer** describes who signed a statement: `{1: kind, ? 2: presence, ? 3: model}`.
- **Kind:** 0 for the organization; otherwise the actor's kind (person 1, agent 2, device 3).
- **Presence:** present only if the statement carries proof of presence, as its method (passkey 1, hardware key 2).
- **Model:** the model the statement's provenance names, if any (an agent's always names one).

So a contract can require that a person approved in person, or that an agent's step is confirmed by a person.

**The output** is a deterministic CBOR array, written with `output_write`:
- `[1, accept]` accepts the call. `accept` is `{1: state, ? 2: status, ? 3: parties, ? 4: events, ? 5: true, ? 6: children}`:
  - **state:** any CBOR value, at most 65,536 bytes encoded, kept by the home and given to the next call;
  - **status:** 1 to 64 bytes, shown in reports and lists, such as `proposed` or `effective`;
  - **parties:** a map from roles (1 to 64 bytes) to ledger ids, at most 64. It replaces the instance's parties; when absent, they stay as they were (none after a creation);
  - **events:** at most 64 `[name, data]` pairs, with names of 1 to 64 bytes, shown in reports;
  - **key 5:** the instance is **final** and takes no more calls;
  - **children** (v0.7): 1 to 16 new instances, each `{1: state, ? 2: status, ? 3: parties}` with the limits above; see "Instances created by a call" below.
- `[2, needs]` asks for consents. `needs` lists the ledgers whose consents the call lacks: 1 to 16, strictly ascending, none the home.

An output is well formed only if it is deterministic CBOR within the limits of section 2 and matches `contract-output`. The call is refused on a trap (`abort` is how a contract rejects a call, with its reason), on a `needs` output, and on an output that is not well formed. The contract is deterministic, so the home runs it first without consents to learn whom to ask. A role may name the home itself: the home agrees through the call it signs, so it never consents to its own calls.

**Instances created by a call** (v0.7). An accepted call may create up to 16 children (output key 6), such as the parts a receivable is split into. The instance the call acts on, or the one it creates, is their **parent**.
- **Id.** A child's id is `HASH(deterministic-CBOR([call, position]))` under the home's hash. `call` is the creating call's statement id, and `position` the child's index in key 6, from 0. A statement id hashes a COSE `Sig_structure` instead, so a child id never equals a statement id.
- **Start.** A child has its parent's contract. Its state, status, and parties are its keys 1 to 3; without status or parties it has none, like a new instance. Its head is the creating call's log index, as is its parent's after the call. It is not final.
- **Depth.** An instance created by a creation has depth 0, and a child its parent's depth plus 1, at most 8. So an instance has at most 8 ancestors, and its evidence stays bounded.
- **Order.** The home applies the accept to the parent as to any call (state, status, parties, finality), then creates the children in order. A parent may keep its state and take more calls, or end (key 5). A split normally ends it, so that only the parts carry its value.
- **Retired contracts** create no more instances, neither by a creation nor as children. Calls that create none carry on.
- **Calls on a child** are calls on an instance: its id, its head, a function of kind 2, and consents that name the child. Under scope key 7, a call on a child acts on its contract.
- **Final instances** take no more calls. They stay in the state, and their evidence can still be fetched and verified. A parent's end does not end its children, nor a child's its parent.
- **What the contract sees.** For a call on a child, the instance view (input key 5) carries key 6, `[parent, depth]`, so a contract can refuse to split at the depth limit with its own reason. For other instances the view has no key 6, and the input is as in v0.6.
- **Consents** are unchanged: at most 16 per call, none from the home. A split that needs the consents of the holder and of every recipient therefore has at most 15 recipients besides the holder.

**Consents.** A party consents with a `cexchain.contract-consent/1` record on its own ledger (state given, which may become withdrawn), under its own delegations and with proof of presence if a person approved. Its metadata names the terms:
- `ledger` (the home), `instance`, `function`, and `head`;
- `arguments`: the hash, under the home's hash, of the encoded arguments;
- `until`, when it lapses;
- optionally a `reference`.

A creation takes no consents: an instance starts as the home's proposal, and binds a party only once the party consents to a later call, which the head makes single-use.

A call cites each consent as `[ledger, record, bundle, signer]`: the party's ledger, the consent record, the hash under the home's hash of the consent's evidence bundle, and the signer of the consent's registration. The bundles are not in the log, so the ledger rules see only the citations, and the contract decides on the signers they claim. Before recording a call, the home MUST check each consent bundle as a verifier does (step 3 below), and MUST keep the bundles it cites.

**Contract evidence** (`contract-evidence`) is the instance's evidence bundle with every consent bundle its calls cite. The instance's bundle includes the deploy (and so the code), any retire, and every call on the instance. For a child, it also includes its **ancestors' histories** (v0.7): for each ancestor, its creation and every call on it up to and including the call that created the next generation. "Its calls" then include these, consents and all. A verifier MUST:
1. verify the instance's bundle for the expected home ledger (section 11) and require it to be complete;
2. replay it, running the contract for each call, the ancestors' included, to reach the instance's state, status, parties, and whether it is final. For a child, the replay also shows that each generation is the child its creating call's output made at its position, with that output's state, status, and parties, within the depth limit: otherwise the instance would not exist in the replayed state;
3. for each consent citation, find the bundle with that hash and check that:
   - it verifies, completely, for the cited ledger;
   - it is about the cited record, a live `cexchain.contract-consent/1` record (given, not revoked);
   - it carries the call's terms;
   - it lapses no earlier than the call's registration time;
   - the record's registration was signed as the citation claims (kind, presence method, and model);
4. refuse bundles that no citation pins, and citations without a bundle.

The report shows each call: the function and arguments, the outcome (status and events), who called and who consented, under whose authority, whether a person proved presence, and any AI provenance. For a child, it shows the ancestors first, each with its depth and its calls up to the one that created the next generation.

**Evidence for a child** leaves out its ancestors' later calls, and the siblings' calls. So it need not prove the ancestors' leaves, which list those later calls, and the home's bundles carry no proof for them. Their histories up to each creating call are still complete. Every call names the head it follows, so a call left out breaks the chain, and the creating calls are those the instance's id derives from. The involved objects (section 11, step 7) include those of the ancestors' calls, so their signers and delegations are proven complete like the instance's own.

**Not yet.** Evidence from other ledgers as input, requests to executors (see the Bo specification), and migration to a new version are planned for later revisions.

## 16. The HTTP API

This section is informative. The reference implementation serves a ledger over HTTP/1.1 (`cexchain serve`):

- Binary objects (log entries, checkpoints, proofs, receipts, bundles, deliveries) are CBOR or COSE as defined above. Everything else is JSON. Errors are `{"error": {"code", "message"}}`.
- Access is gated by bearer tokens with scopes. The statement signature remains the authorization for what is written.

| Scope | Routes |
|---|---|
| none | `GET /healthz`, `GET /v1/checkpoint[?size=N]`, `GET /v1/consistency?old=&new=` |
| read | `GET /metrics`, `/v1/status`, `/v1/entries?start=&count=`, `/v1/checkpoints`, `/v1/cosignatures`, `/v1/inclusion?index=&size=`, `/v1/statements/{id}`, `/v1/receipts/{index}`, `/v1/state/{id}`, `/v1/evidence/{record}`, `/v1/vault/public-key`, `/v1/vault/records/{record}`, `/v1/assets/{asset}`, `/v1/contracts?start=&count=`, `/v1/contracts/{contract}`, `/v1/contracts/instances/{instance}`, `/v1/contracts/calls`, `/v1/contracts/calls/{call}` |
| submit | `POST /v1/statements`, `POST /v1/contracts/calls` |
| admin | `POST /v1/checkpoint`, `POST /v1/cosignatures` |
| peer | `POST /v1/access/requests`, `GET /v1/access/deliveries/{request}`, `POST /v1/access/receipts`, `POST /v1/witness/cosign`, `POST /v1/assets/consents`, `GET /v1/assets/{asset}` (the asset's current parties), `POST /v1/contracts/calls` and `GET /v1/contracts/instances/{instance}` (the instance's current parties), `GET /v1/contracts/calls`, `/v1/contracts/calls/{call}` (the calls that concern the peer), `POST /v1/contracts/consents` |
| read, admin | clusters: `GET /v1/cluster`; `POST /v1/cluster/members`, `/v1/cluster/members/remove`, `/v1/cluster/step-down` |

**Clusters.** Several members can keep one ledger with Raft. Each group of statements is replicated as `{time, statements, sealed private data}` and applied by every member at that time, so their logs are identical. Checkpoints are signed by the leader and replicated as signed. The consent bundles a statement cites, and the calls a registrar holds, are replicated too, so a new leader carries on with them. A follower answers writes with 307 and the leader's API. Members authenticate their Raft messages with a shared secret. None of this changes the protocol: a cluster's log is one ledger's log.

`POST /v1/statements` also takes `application/cexchain-submission+cbor`: `{1: signed statement, 2: sealed private data}`, a record's registration with its vault file. The server stores the file with the record, once: the same file again is accepted (a retry), a different one refused, so nobody can store other data for a record first. For an asset action or a contract call, the submission is `{1: signed statement, 3: [consent bundles]}`, one bundle per consent in the statement's order: the server checks every consent the statement cites against its bundle (sections 13 and 15; for a call, the signer each citation claims too) before registering it, and keeps the bundles. A statement that cites consents is refused without them.

**Assets.** A server with a registrar key (an actor of the home with a delegation for asset actions) takes consents from its peers: `POST /v1/assets/consents` with a consent's evidence bundle, which must come from the peer's ledger. It checks the consent, holds it until every party the action needs has consented to the same terms, then signs and registers the action. It answers with the action once recorded, or with the parties still missing. A consent whose head is no longer the asset's, or that has lapsed, is dropped. `GET /v1/assets/{asset}` returns the asset evidence, without private data, to the asset's current holder, pledgee, and payee, and to read tokens. The evidence is as of a checkpoint that covers the asset's latest change; the server makes one if it must. Field values and attachments reach the parties through access (section 12) or out of band; a disclosure holds for the record whatever the checkpoint, so a holder can add the disclosures it has to later evidence.

**Contracts.** A server with a registrar key records the calls that need consents (an actor of the home with a delegation for type 22 whose scope covers the contract):

1. **Proposal.** `POST /v1/contracts/calls` proposes a call on an instance, from the home's submit tokens or from a peer whose ledger is one of the instance's current parties. For a part (v0.7), these are the part's own parties, not its parent's; a final instance, such as a parent a split ended, takes no proposals. The body is CBOR: `{1: instance, 2: head, 3: function, 4: arguments, ? 5: reference, ? 6: until}`. The server runs the contract on the call without consents, signed as the registrar:
   - it refuses the call if the contract rejects it (with the contract's reason), or if the ledger would (a call that creates parts on a retired contract or at depth 8, with the ledger's reason), or if the contract takes it as it is: the home's people sign such calls themselves, so the registrar never records a call on its own word;
   - otherwise it holds the call until `until` (at most 30 days ahead; 7 by default), and answers 202 with the call's id, the arguments (hex CBOR) and their digest, and `missing`, the ledgers the contract asked for.
2. **Consents.** Each party consents on its own ledger (section 15) and sends the consent's evidence bundle, from its own ledger, to `POST /v1/contracts/consents`. The server takes it only for a held call with exactly the consent's terms, from a ledger the contract asked for (or one that consented before, which replaces its consent). It checks the consent as a verifier does, and cites it with the signer the bundle shows. Then it runs the contract with the consents held, dropping any that has lapsed:
   - accepted: if the call creates parts, the ledger's rules for them apply first (section 15), and a call they refuse is refused as below, with the ledger's reason. Otherwise it signs the call as the registrar, keeps the bundles, records it, and answers 201 with the call's statement id and log index, the instance's status, and `children`, the ids of the parts the call created, in order;
   - more needed: it answers 202 with `missing`;
   - rejected: the consent is not kept (409).
3. **Lapse.** A held call is dropped once its instance moves on (its head is no longer the instance's) or once it lapses. A consent to an earlier head is refused.

A call's id is SHA-256 of `[instance, head, function, arguments digest]`, so a consent's terms name exactly one held call. `GET /v1/contracts/calls` and `/v1/contracts/calls/{call}` show the held calls: all of them to read tokens, and to a peer those that concern its ledger (as a party, as asked, or as consented).

`GET /v1/contracts` and `/v1/contracts/{contract}` list and show the contracts to read tokens: interface, language, compiler, name, whether retired, the number of instances, and, for one contract, its code's size and hash (the code is in the deploy statement). `GET /v1/contracts/instances/{instance}` returns the contract evidence, without private data, to the instance's current parties and to read tokens, as of a checkpoint that covers the instance's latest call; the server makes one if it must. For a part (v0.7), the evidence carries its ancestors' calls up to each one that created the next generation, with the consent bundles those calls cite, and goes to the part's current parties (a parent's parties see only the parent). Listing a parent's parts takes no route: its evidence shows each call's children, and the part's id is derived from the call (section 15).

A server holds the log key to sign checkpoints, receipts, and evidence. Across a rotation it may hold the old and new key, and signs with the one in effect.

**Replicas.** A replica copies a ledger through the read routes. It takes the entries a checkpoint covers only once they lead to its root and the checkpoint is signed by the log key in effect at its size, following any key rotation among them (checkpoints never go back in size or time). It re-validates every entry under the rules, rebuilds the tree, and never copies entries that no checkpoint covers. It MUST stop at the first entry that fails, and MUST refuse a primary whose log is shorter than its own (a rollback).

## 17. Security considerations

- **What a bundle proves.** Within one ledger, a bundle proves:
  - authorship: the actor's key signed the statement;
  - authority: the delegation chain at that time;
  - inclusion: the entry is in the log the log key signed;
  - completeness: proven against the state commitment.

  Presence shows that a person approved. Without it, an action is a machine's.
- **What it does not prove alone.** A ledger's operator could show different histories to different parties. Witnesses detect this: verifiers SHOULD require cosignatures from witnesses they trust. The log key is the operator's single point of trust and SHOULD be kept in an HSM.
- **Time.** Registration times come from the ledger's clock and are ordered. Issued-at times are claims by the signer, bounded only in the future direction. External time anchoring is future work.
- **Keys.**
  - Actor keys can be rotated, and revocation cascades through delegation chains.
  - The log key and the organization root key can be rotated (v0.4), for instance to ML-DSA. A leaked old log key can still sign a different history that never rotated. Only witnesses that followed the rotation reject it, so verifiers SHOULD require cosignatures from trusted witnesses.
  - A leaked root key can rotate both keys. Recovering from that needs action outside the ledger, such as a new ledger. Keep the root key in an HSM; threshold root keys are future work.
  - Algorithms are pluggable, and post-quantum signatures (ML-DSA) are supported now.
- **Privacy.**
  - Public metadata, record types, actor names, and timestamps are visible to whoever holds a bundle.
  - Field values and attachments are hidden behind salted commitments until disclosed.
  - Access to a server's read routes should be restricted accordingly.
- **Cross-organization access.**
  - A delivery is sealed to a key made for one request. It is bound to its grant and checked against the granter's ledger.
  - Revocation cannot recall data already delivered.
- **Assets.**
  - Double-pledge safety across lenders rests on the witnesses they share (section 13). If two lenders share no witness, the home can show each of them a different history, in which each pledge is the only one.
  - Every holder and pledgee sees an asset's chain of title and public metadata.
  - Consents are machine actions unless they carry proof of presence. Verifiers report this and MAY require it.
- **Contracts.**
  - A contract's code, arguments, states, and events are visible to whoever holds an instance's evidence. Private values belong in records, disclosed selectively.
  - Every call is bounded by fuel, call depth, and memory (section 14), so a contract cannot stall the home or a verifier.
  - Code is immutable, but it can be wrong. Verifiers show which contract, and which source, an instance runs, and rebuild a Bo contract's code from its source. Parties should read the code (or its Bo source) before consenting.
  - Consent signers are claimed in the call and checked only by verifiers that hold the consent bundles, so parties SHOULD verify contract evidence, not just the home's log.
- **Children** (v0.7).
  - A child's evidence shows its ancestors' calls up to each creating call: the parent's states and parties, the arguments of the split, and the first state and parties of every sibling. So a part's holder, and anyone it shows the part to, sees the other parts' holders and amounts. This is accepted for v1; commitments or zero-knowledge proofs may hide siblings later. The evidence does not show the siblings' later calls, nor the ancestors' calls after each split.
  - The protocol does not know amounts: a contract that splits must conserve them. A verifier that relies on a part SHOULD check, in the replayed split, that the parts add up to the parent's amount, or rely on a contract whose source it has read and rebuilt.
  - Depth is capped at 8, so a part's evidence carries at most 8 ancestors' histories.

## 18. Test vectors

| File | Covers |
|---|---|
| `hashes.json` | SHA-256, SM3 |
| `signatures.json` | Ed25519, ESP256, SM2, ML-DSA from independent implementations |
| `merkle-sha256.json`, `merkle-sm3.json` | RFC 9162 tree hashes, inclusion and consistency proofs |
| `cose-sign1.json` | COSE_Sign1 in the CexChain profile |
| `pkcs8.json` | encrypted private keys |
| `protocol-v0.1.json` | statements, log entries, checkpoints, receipts |
| `protocol-v0.2.json` | presence (passkey and hardware key), state trees and commitments, cosign requests |
| `protocol-v0.3.json` | access metadata, and a delivery sealed by an independent HPKE implementation |
| `protocol-v0.4.json` | log and root key rotation, the checkpoint and state commitment under the new key, a cosign request with key rotations |
| `protocol-v0.5.json` | assets: a receivable and a warehouse receipt through every action, consent metadata, actions the rules refuse, and asset evidence |
| `protocol-v0.6.json` | contracts (section 15): a test contract deployed, instances created and called, with each call's input and output, consent metadata, calls the rules refuse, and contract evidence |
| `protocol-v0.7.json` | instances created by a call (section 15): a splitting contract and the v0.6 test contract; children and their ids, calls on a child and a grandchild, splits down to the depth limit, children the rules refuse (too many, too deep, malformed, on a retired contract, on a final parent), the state tree, and signed evidence bundles: an instance, a tier-3 part with its ancestors and real consent bundles from other ledgers, and a child whose parent carried on |
| `vm-v1.json` | contract execution (section 14): modules in and out of the profile, invocations with their outputs, traps, and fuel, and random integer programs, all from an independent reference interpreter (`tools/testvectors/wasm_ref.py`) |
| `bo-v1.json` | the Bo language ([`bo.md`](bo.md), section 18): contracts' sources in each language, their interfaces and bo-source bundles, the code `cexchain-bo` builds and its bounds (informative), calls with their outcomes (normative), and sources that must not build with their errors' codes |

`tools/testvectors/generate.py` regenerates them with Python's `cryptography` and `cbor2`, and OpenSSL, independently of the C++ code; `tools/testvectors/bo_vectors.py` writes `bo-v1.json` from the Bo compiler's runs and checks each on the reference interpreter. `test-contracts.json` is not part of the protocol: it holds contracts for tests of the reference server (a contract that decides by how many consents a call cites, and the splitting contract of `protocol-v0.7.json`), from `tools/testvectors/test_contracts.py`.
