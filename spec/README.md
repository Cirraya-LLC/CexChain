# The CexChain protocol

Revision v0.4. Wire protocol version 1.

This document explains the protocol in prose. The normative definitions are:

- [`cexchain.cddl`](cexchain.cddl), the structures, in RFC 8610 CDDL;
- [`../testvectors/`](../testvectors), objects built by independent implementations, which any implementation must read and reproduce byte for byte.

Where this text and the CDDL disagree, the CDDL wins. The C++ code in this repository is one implementation; it does not define the protocol.

The key words MUST, MUST NOT, SHOULD, and MAY are used as in RFC 2119.

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
13. [The HTTP API](#13-the-http-api)
14. [Security considerations](#14-security-considerations)
15. [Test vectors](#15-test-vectors)

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

**Machine by default.** A signature shows only that a key was used. A statement counts as a person's action only if it carries proof of presence (section 7).

## 2. Encoding

All structures are **deterministic CBOR** (RFC 8949 section 4.2.1), restricted further:

- integers and lengths in their shortest form; definite lengths only;
- map keys sorted by the bytewise order of their encodings, with no duplicates;
- no floating-point numbers, no simple values other than `false`, `true`, and `null`, no bignums (tags 2 and 3);
- text strings MUST be valid UTF-8.

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

**Bodies**

- **Actors.**
  - New keys must not be weak, must not belong to another actor, must not be one of the actor's presence keys, and must not be a log key of the ledger, current or past.
  - An agent names a responsible actor, which must be a person.
  - The organization actor cannot be revoked. Only the organization itself rotates its root key (actor-rotate-key on the ledger id).
  - Only people have presence credentials, and only people prove presence. A presence credential's key must not be the person's signing key, any actor's key, or a log key: it is a second key.
- **The log key.** Only the organization rotates it (ledger-rotate-log-key), without a delegation. The new key must not be weak, must not be an actor's key, and must never have been a log key of this ledger.
- **Delegations.** Only the grantor or the organization may revoke a delegation. Revoking an actor or a delegation ends everything that depends on it, because authority is checked through the whole chain at every statement.
- **Records.** Records follow their type's lifecycle (section 6). Transitions must start from the record's current state and be allowed by its type. Endorsement roles must be defined by the type, and an actor endorses a record at most once per role. A revoked record accepts no further statements.

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

The **state** is a compact sparse Merkle tree over every actor, delegation, and record. It is keyed by object id, read as 256 bits, most significant first:

```
empty subtree            HASH("")
subtree of one object    HASH(0x00 || state-leaf)
any other subtree        HASH(0x01 || left || right)
state-leaf = [kind (actor 1, delegation 2, record 3), id, history]
```

A leaf's history lists every log index that created or changed the object:
- actors: registration, key rotations, presence changes, revocation;
- delegations: grant and revocation;
- records: every statement about them.

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

- the record id;
- log entries with their receipts, in ascending order, starting with genesis: the record's statements and every statement they depend on (signers' registrations and key rotations, delegation chains, referenced actors), and every rotation of the organization's keys below the checkpoint's size;
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
   - for the record and each involved object, require a proof whose leaf equals that object's leaf in the replayed state. The involved objects are each event's signer, an agent signer's responsible person, and every delegation in the chain with its grantor.

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

## 13. The HTTP API

This section is informative. The reference implementation serves a ledger over HTTP/1.1 (`cexchain serve`):

- Binary objects (log entries, checkpoints, proofs, receipts, bundles, deliveries) are CBOR or COSE as defined above. Everything else is JSON. Errors are `{"error": {"code", "message"}}`.
- Access is gated by bearer tokens with scopes. The statement signature remains the authorization for what is written.

| Scope | Routes |
|---|---|
| none | `GET /healthz`, `GET /v1/checkpoint[?size=N]`, `GET /v1/consistency?old=&new=` |
| read | `GET /metrics`, `/v1/status`, `/v1/entries?start=&count=`, `/v1/checkpoints`, `/v1/cosignatures`, `/v1/inclusion?index=&size=`, `/v1/statements/{id}`, `/v1/receipts/{index}`, `/v1/state/{id}`, `/v1/evidence/{record}`, `/v1/vault/public-key`, `/v1/vault/records/{record}` |
| submit | `POST /v1/statements` |
| admin | `POST /v1/checkpoint`, `POST /v1/cosignatures` |
| peer | `POST /v1/access/requests`, `GET /v1/access/deliveries/{request}`, `POST /v1/access/receipts`, `POST /v1/witness/cosign` |

A server holds the log key to sign checkpoints, receipts, and evidence. Across a rotation it may hold the old and new key, and signs with the one in effect.

**Replicas.** A replica copies a ledger through the read routes. It takes the entries a checkpoint covers only once they lead to its root and the checkpoint is signed by the log key in effect at its size, following any key rotation among them (checkpoints never go back in size or time). It re-validates every entry under the rules, rebuilds the tree, and never copies entries that no checkpoint covers. It MUST stop at the first entry that fails, and MUST refuse a primary whose log is shorter than its own (a rollback).

## 14. Security considerations

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

## 15. Test vectors

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

`tools/testvectors/generate.py` regenerates them with Python's `cryptography` and `cbor2`, and OpenSSL, independently of the C++ code.
