# The Kanhe protocol

Revision v0.17 (draft). Wire protocol version 1.

This document explains the protocol in prose. The normative definitions are:

- [`kanhe.cddl`](kanhe.cddl), the structures, in RFC 8610 CDDL;
- [`../testvectors/`](../testvectors), objects built by independent implementations, which any implementation must read and reproduce byte for byte.

Where this text and the CDDL disagree, the CDDL wins. The C++ code in this repository is one implementation; it does not define the protocol.

The key words MUST, MUST NOT, SHOULD, and MAY are used as in RFC 2119.

Bo, the language contracts are written in, has its own reference: [`bo.md`](bo.md).

**Changes in v0.17.** The protocol is Kanhe, formerly CexChain. Every protocol string changes with the name: the reserved record-type prefix is `kanhe.` (six bytes), so the mechanism types are `kanhe.access-request/1` to `kanhe.membership/1`, and the content types and every other string the protocol signs or hashes say `kanhe` where they said `cexchain`. Objects under the old name are not Kanhe objects and verify as nothing here; the wire protocol stays version 1, since the content types already tell the two apart. `state_rules_version` 4. The earlier revisions below are written under the new name.

**Changes in v0.16.** Trust nodes: a record of the new mechanism type `kanhe.membership/1` is a ledger's word that another ledger belongs to the organization or person it names, as it checked them (section 6). An evidence bundle may carry such memberships of its own ledger (key 9), each the complete evidence of the membership on the trust node's ledger. A verifier states, for each, the trust node, named from the verifier's own list and never from the evidence, whom it names, and where the membership stood when the record was registered and at the membership's checkpoint (section 11). A server may serve a ledger's membership (section 16). The ledger rules change for the new type only; the wire protocol stays version 1, and a bundle without key 9, and a log without memberships, verify as before.

**Changes in v0.15.** Asking about a condition: an access request may ask whether a condition holds in a record instead of asking for its data, and the granter answers with a claim that names the request (sections 6, 12, and 16). The requester checks that the claim answers its request, about that record and with that condition, and acknowledges it with a receipt as it acknowledges a delivery. The names in access metadata are written down as readers already checked them: non-empty, unique within their list, at most 256 to a list (section 12, `access-names`). The ledger rules do not change; the wire protocol stays version 1, and a log replays as before.

**Changes in v0.14.** Claims: a record of the new mechanism type `kanhe.claim/1` says that, in another record of the same ledger (its source), a condition on fields holds or does not, without disclosing them (section 6). A claim's evidence carries its source as an involved object, so that a verifier sees whether the source was revoked or replaced since, and the report states the condition in words (section 11). Nothing else changes; the wire protocol stays version 1, and a log without claims replays as before.

**Changes in v0.13.** Open witness networks: the witnesses of transparency networks that follow C2SP's specifications can cosign a SHA-256 ledger's checkpoints, as text notes under a name derived from the ledger id, and a verifier that trusts them counts their cosignatures as it counts its own witnesses' (sections 10.2, 11, 16, and 17). Bundles carry such cosignatures in anchors (key 4 of `anchor`, whose key 2 becomes optional). Nothing else changes; the wire protocol stays version 1, and a bundle without them verifies as before.

**Changes in v0.12.** Clarifications, and no new rule. A second verifier written from this text alone ([`verifiers/python`](../verifiers/python)), and a conformance suite made apart from both verifiers ([`evidence-v1.json`](../testvectors/evidence-v1.json), section 18), found places where the text left an outcome open. v0.12 states what both verifiers do: how nesting and data items are counted (section 2); the signatures' integers, ML-DSA's form, and weak keys (section 3); the exceptions, validity windows, and revoked objects of the ledger rules (section 5); the order of fields and disclosures, and attachment names (section 6); registration times and receipts (section 8); cosignatures (sections 10 and 11) and time-stamp tokens (section 10.1); attachment contents and state proofs in verification (section 11); and sizes and orders in the CDDL. Nothing that verified stops verifying, and nothing that failed verifies; the wire protocol stays version 1.

**Changes in v0.11.** Time-stamp authorities: an RFC 3161 token over a checkpoint's payload bounds, for whoever trusts the authority, when everything the checkpoint covers existed, and a verifier refuses evidence whose ledger dates such an entry later than the authority's time allows (sections 10, 11, 16, and 17). Bundles carry such tokens as anchors (key 8 of `evidence-bundle`); tokens are kept beside checkpoints, like cosignatures, never in the log. Nothing else changes; the wire protocol stays version 1, and a bundle without key 8 verifies as before.

**Changes in v0.10.** A record can supersede another: a registration may name the record it replaces (key 6 of `record-register-body`), so that its versions form a chain and a verifier holding an old version learns that a newer one replaced it, when, and by whom (sections 5, 6, 9, and 11). Nothing else changes; the wire protocol stays version 1, and a log without the key replays as before.

**Changes in v0.9.** The protocol knows only generic primitives: actors and delegations, records, contracts and their instances, consents, access, witnesses, and evidence. Revision v0.9 removes:
- statement type 20 (asset-action, v0.5), which is reserved and never reused: a decoder refuses it like any unknown type;
- the record types of particular industries: certificates, deliveries, and agreements (v0.1), and receivables, warehouse receipts, and asset consents (v0.5), with their lifecycles, the asset rules, and asset evidence. The `kanhe.` record type prefix is reserved for the protocol's own mechanism types (section 6).

A record's type is now its registrant's choice, with one generic lifecycle, and anything with rules of its own is a contract instance (sections 13 and 15). The wire protocol stays version 1, which was never released. A log that holds a type-20 statement or a removed record type therefore fails replay, so its ledger no longer opens; asset evidence no longer verifies; backups that carry asset consents are refused. That is accepted because nothing was released before v0.9: such logs exist only in tests, and keeping the types would bind every later version to them.

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
10. [Witnesses](#10-witnesses), [time-stamp authorities](#101-time-stamp-authorities-v011), [open witness networks](#102-open-witness-networks-v013)
11. [Evidence bundles and verification](#11-evidence-bundles-and-verification)
12. [Access across organizations](#12-access-across-organizations)
13. [Relying on an instance's state](#13-relying-on-an-instances-state)
14. [Contract execution](#14-contract-execution)
15. [Contracts](#15-contracts)
16. [The HTTP API](#16-the-http-api)
17. [Security considerations](#17-security-considerations)
18. [Test vectors](#18-test-vectors)

## 1. Overview

A **ledger** belongs to one organization: a company, any other body, or a single person. This text calls a ledger's owner its organization throughout. A ledger records **statements**, which are signed claims by **actors**: people, AI agents, devices, and the organization itself. Statements register actors, delegate authority, and register, endorse, and revoke **records**. A record is a document of any type its owner names, such as an inspection report, a lease, or the receipt for a lent camera: the ledger commits to its fields and attachments and knows nothing of what they mean.

The ledger appends each accepted statement to an append-only **log**, a Merkle tree (RFC 9162). It periodically signs a **checkpoint**, which commits to the tree's size and root. Anyone can then check, offline and without trusting the ledger's operator:

- that a statement is in the log, with an inclusion **receipt** against a checkpoint;
- that the log only grew between two checkpoints, with a consistency proof;
- that the history they were shown of a record and of everyone involved is complete, with a proof against a **state commitment** in the log;
- that independent **witnesses** saw the same history, through their cosignatures on checkpoints.

An **evidence bundle** packs all of this for one record, so a third party can verify it with nothing else.

Documents stay off the ledger. The ledger holds salted commitments to field values and attachments, and the owner discloses fields selectively.

Two organizations exchange records through the same mechanism (section 12): each step is a statement on the acting organization's own ledger, checked by the other side with an evidence bundle.

**Contracts** (sections 14 and 15) are deterministic WebAssembly modules on a ledger. Anything with rules of its own, such as a loan, a membership, or a booking, is an **instance** of a contract, which must accept its every call. Parties on other ledgers consent on their own ledgers, and any verifier replays the calls with the same result. A call may also create instances, such as the parts a thing is divided into, and ask **executors** to act outside the ledger: they answer with calls of their own, which the contract sees. Section 13 says when a party may rely on an instance's state.

**Machine by default.** A signature shows only that a key was used. A statement counts as a person's action only if it carries proof of presence (section 7).

## 2. Encoding

All structures are **deterministic CBOR** (RFC 8949 section 4.2.1), restricted further:

- integers and lengths in their shortest form; definite lengths only;
- map keys sorted by the bytewise order of their encodings, with no duplicates;
- no floating-point numbers, no simple values other than `false`, `true`, and `null`, no bignums (tags 2 and 3);
- text strings MUST be valid UTF-8;
- at most 32 levels of nesting in any object (v0.6): the outermost array, map, or tag is at level 1, and an array, map, or tag inside one is a level deeper. A statement payload and a contract output also hold at most 131,072 data items, each counted once: the outermost item, every array element, map key, and map value, and every tag and the item it wraps (v0.12). Decoders MUST refuse more, so that every implementation accepts exactly the same objects.

A decoder MUST accept exactly the bytes an encoder would produce for the decoded value, so `encode(decode(x)) == x` for every accepted input. Maps with unknown keys MUST be rejected, except where the CDDL allows any key (record metadata).

Signed objects are **COSE_Sign1** messages (RFC 9052), tagged (tag 18), with:

- a protected header holding exactly `alg` (1), `content type` (3), and `kid` (4), except for receipts (section 8);
- an empty unprotected header;
- signatures in the algorithm's fixed wire format (section 3).

Content types tell signed objects apart, so a signature on one kind can never be taken for another:

| Content type | Object | Signed by |
|---|---|---|
| `application/kanhe-statement+cbor` | statement | the actor's key |
| `application/kanhe-checkpoint+cbor` | checkpoint | the log key |
| `application/kanhe-cosignature+cbor` | cosignature of a checkpoint | a witness key |
| `application/kanhe-state+cbor` | state commitment | the log key |

## 3. Keys, algorithms, and identifiers

**Signature algorithms**, identified by COSE algorithm identifiers:

| Algorithm | COSE id | Public key | Signature |
|---|---|---|---|
| Ed25519 | -19 | 32 bytes | 64 bytes |
| ECDSA P-256 with SHA-256 (ESP256) | -9 | 65 bytes, uncompressed SEC 1 | 64 bytes, r ‖ s, low S |
| SM2 with SM3 (GB/T 32918, GM/T 0009) | -65537 (private use) | 65 bytes, uncompressed | 64 bytes, r ‖ s |
| ML-DSA-44 / 65 / 87 (FIPS 204) | -48 / -49 / -50 | FIPS 204 | FIPS 204 |

SM2 signatures use the default distinguishing identifier `1234567812345678`. ESP256 signatures MUST be in low-S form. In ESP256 and SM2 signatures, r and s are each 32 bytes, big-endian, padded with leading zeros; SM2 has no low-S rule. ML-DSA is the pure form of FIPS 204, with an empty context string. A public key is encoded as `[alg, key bytes]`.

A key is **weak** if it is an Ed25519 key whose encoding is not canonical (its y coordinate is not reduced modulo 2^255 − 19) or whose point has small order. Weak keys are refused wherever a key is registered (section 5), and nothing verifies under one (v0.12).

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
| 16 | record-register | record type, field root, field count, attachments, public metadata, the record it supersedes (v0.10) |
| 17 | record-endorse | record, role |
| 18 | record-transition | record, from state, to state |
| 19 | record-revoke | record, reason |
| 20 | reserved | asset-action in v0.5 to v0.8; removed in v0.9, never reused |
| 21 | contract-deploy | code, interface, language, compiler, source, name (v0.6; section 15) |
| 22 | contract-call | contract or instance, function, arguments, head, consents, reference (v0.6); an answer to a request (v0.8) |
| 23 | contract-retire | contract, reason (v0.6) |

Every other type, 20 included, is unknown: a decoder refuses a statement of an unknown type, and a scope that names one.

## 5. Ledger rules

A ledger accepts a statement only if every rule below holds at its registration time, `now`, by the ledger's clock. Replaying the log applies the same rules at each entry's recorded registration time. So any party holding the log can re-derive the ledger's state, and a log that breaks a rule is detected.

**Identity and integrity**

- The statement is for this ledger. It is not registered already, and its (actor, nonce) pair was never accepted before, so a payload cannot be replayed even when re-signed with a rotated key.
- `issued at` is no later than `now` plus 5 minutes.
- The signer is a registered, unrevoked actor, and the statement is signed with that actor's current key. The COSE `kid` MUST match it.
- An agent's statements MUST name a model in their provenance.

**Authority**

- The organization acts without a delegation.
- Any other actor needs a delegation granted to it whose scope covers the statement type, and the record type for record statements. There are two exceptions, for statements that name no delegation:
  - an actor may rotate its own key, and a person with presence credentials must then prove presence;
  - a person may replace their own presence credentials while proving presence with one already registered.

  In both, the proof MUST be user-verified (section 7).
- A scope never covers genesis or ledger-rotate-log-key.
- Every delegation in the chain from the organization to the signer MUST be unrevoked and valid at `now`: from scope key 3 to scope key 4, both included, an absent key leaving that side open. Every grantor in the chain MUST be unrevoked. If any delegation in the chain requires presence (scope key 6), the statement MUST carry valid proof of presence.
- A delegation may only narrow its grantor's scope:
  - statement types and record types are subsets of the grantor's;
  - the validity window lies inside the grantor's: each bound the grantor's has, the delegated one has too, and no wider;
  - "may delegate further" (scope key 5) must be set on the grantor's delegation;
  - presence, once required, stays required.
- Chains have at most 16 delegations.
- A scope may list contracts (scope key 7, v0.6). Calls and retires under it must then act on one of them, and a delegated scope's contracts are a subset of its grantor's (section 15).
- A scope may list functions (scope key 8, v0.8): calls under it must name one of them. It may list request kinds (scope key 9, v0.8): calls under it must then be answers to requests of those kinds. A delegated scope's lists are subsets of its grantor's (section 15).

**Bodies**

- **Actors.**
  - New keys must not be weak (section 3), must not be another actor's current key, must not be one of the actor's presence keys, and must not be a log key of the ledger, current or past.
  - An agent names a responsible actor, which must be a person. A device may name one too.
  - The organization actor cannot be revoked. Only the organization itself rotates its root key (actor-rotate-key on the ledger id).
  - Only people have presence credentials, and only people prove presence. A presence credential's key must not be the person's signing key, any actor's key, or a log key: it is a second key.
- **The log key.** Only the organization rotates it (ledger-rotate-log-key), without a delegation. The new key must not be weak, must not be an actor's key, and must never have been a log key of this ledger.
- **Delegations.** Only the grantor or the organization may revoke a delegation. Revoking an actor or a delegation ends everything that depends on it, because authority is checked through the whole chain at every statement.
- **Revoked objects** (v0.12). A revoked actor or delegation takes no statement about it: revoking it again, rotating a revoked actor's key or setting its presence credentials, granting a delegation to it, and registering an agent with it as the responsible person are refused.
- **Records.** A registration's type must not begin with `kanhe.` unless it is one of the protocol's mechanism types (v0.9; section 6). Records follow their type's lifecycle (section 6). Transitions must start from the record's current state and be allowed by its type, so a record of the generic lifecycle takes none. Endorsement roles must be allowed by the type: any role under the generic lifecycle, none for a mechanism type. An actor endorses a record at most once per role. A revoked record accepts no further statements, except a registration that supersedes it.
- **Versions** (v0.10). A registration that supersedes a record (section 6) is refused unless that record is a record of this ledger, neither of the two types is a mechanism type, the record was not superseded before, and the signer's scope covers that record's type as well as its own (the organization needs no scope). The record may be revoked.
- **Contracts.** Deploys, calls, and retires follow the rules of section 15. A call is registered only if its contract, run on the call, accepts it. An answer (v0.8) answers an open request of its instance, at most once.

## 6. Records and private data

**Field commitments.** A record's fields are `[name, salt, value]` triples with a fresh 16-byte salt each. The leaves are their deterministic-CBOR encodings, sorted by the bytewise order of the names' UTF-8 encodings, one per name. A verifier refuses a bundle that discloses one leaf twice, or discloses leaves whose names do not ascend with their indices; the disclosures themselves may be listed in any order. The record commits to the RFC 9162 Merkle root over the leaves, and to their count. To disclose a field, the owner gives the leaf and its inclusion path. Undisclosed fields stay hidden, and their salts stop dictionary attacks on small value spaces. Deleting a field's value and salt makes its commitment meaningless (crypto-shredding).

**Attachments.** The record carries each attachment's name, media type, size, and commitment `HASH(salt || content)`, never the content. Attachment names are unique within a record. A bundle opens an attachment by giving its salt (section 11).

**Public metadata.** A record may carry a map with text keys, which is disclosed in the clear (key 5 of `record-register-body`).

**Record types.** A record's type is any text its registrant chooses (key 1 of `record-register-body`). By convention it is `<owner's domain>.<name>/<version>`, such as `example.org.inspection/1`. The protocol gives every such type one **generic lifecycle**:
- the initial state is `registered`, and there are no transitions;
- any actor whose delegation covers the type may endorse the record in any role, once per role;
- the record may be revoked.

What a type's fields mean, which roles matter, and when a document stops counting are its owner's business.

**Versions** (v0.10). A registration may name the record it supersedes (key 6): a new version of a form, a policy, or a price list. A record is superseded at most once, and a registration supersedes at most one record, so a record's versions form one chain, oldest first; the types may differ (`example.org.form/1`, then `example.org.form/2`). A superseded record keeps its state, and may still be endorsed and revoked: it is what was in force until then. A revoked record may still be superseded, so that a version withdrawn by mistake can be replaced. Mechanism types neither supersede nor are superseded. The registration is a statement about both records (section 9), so a complete bundle of an old version shows whether a newer one replaced it (section 11). Anything with rules of its own, such as states that change or parties who must agree, is a contract instance (section 15), which may name records in its state.

**Mechanism types.** Six types belong to the protocol's own mechanisms, each with its lifecycle. None takes endorsements:

| Type | Initial state | Transitions | Used in |
|---|---|---|---|
| `kanhe.access-request/1` | requested | requested → withdrawn | access (section 12) |
| `kanhe.access-grant/1` | granted | none (revoke the record) | access |
| `kanhe.access-receipt/1` | received | none | access |
| `kanhe.contract-consent/1` | given | given → withdrawn | consents to contract calls (section 15) |
| `kanhe.claim/1` (v0.14) | confirmed | none (revoke the record) | claims, below |
| `kanhe.membership/1` (v0.16) | active | active → suspended, suspended → active, active → ended, suspended → ended | trust nodes, below |

**The `kanhe.` prefix is reserved** (v0.9). A registration whose type begins with the six bytes `kanhe.` and is not one of the six is refused, so that nobody can pass off a type as the protocol's. This covers the types that earlier revisions built in and v0.9 removed: `kanhe.certificate/1`, `kanhe.delivery/1`, and `kanhe.agreement/1` (v0.1), and `kanhe.receivable/1`, `kanhe.warehouse-receipt/1`, and `kanhe.asset-consent/1` (v0.5). The rule applies to registrations only: a scope may list any type, and a type nobody can register covers nothing.

Record-transition (type 18) stays for the mechanism types: it is how a party withdraws an access request or a consent, and how a trust node suspends, resumes, or ends a membership. On a record of the generic lifecycle it is always refused.

**Claims** (v0.14). A claim is the issuer's word that, in its record the claim names (the **source**), a condition on the source's fields holds, or does not, as of a time: "Chan Tai Man's monthly salary is above HKD 30,000.00" without the salary. It is a `kanhe.claim/1` record whose public metadata (key 5) is `claim` in the CDDL:
- `source`: the source's id. The ledger refuses a claim unless the source is a record of this ledger, of a generic type (no mechanism record is a source), neither revoked nor superseded when the claim is registered. The claim's registration is a statement about the claim only: the source's history is unchanged, and the signer's scope need cover only the claim's type.
- `condition`: 1 to 16 terms, all of which must hold. A term is `[field, op, type, value]`: the source's field name (1 to 64 bytes), an operator, the type of the value, and the value. The types are `number` (an integer, or a decimal text `-?[0-9]+(\.[0-9]+)?` of at most 40 characters), `money` (`[amount, currency, scale]`: the integer amount in units of 10^-scale, an ISO 4217 code of three upper-case letters, and a scale of 0 to 4), `date` (`YYYY-MM-DD`, a valid date), and `text` (1 to 256 bytes). The operators are `>`, `>=`, `<`, `<=` (numbers, money, and dates), `=`, `!=` (every type), `between` (numbers, money, and dates: a value `[low, high]` of the type, both included, low not above high, money in one currency), `in` (every type: an array of 1 to 64 distinct values of the type, distinct as values: `1` and `"1.0"` are one number, `[100, "HKD", 0]` and `[10000, "HKD", 2]` one amount), and `exists` (the type is `text`, and the value null: the source has the field). Integers are any CBOR integer (−2^64 to 2^64 − 1); a date is of the proleptic Gregorian calendar.
- `holds`: whether the condition holds. Implementations SHOULD register a claim that does not hold only when its issuer chose to: by default, a condition that does not hold gets no claim, so that asking reveals nothing more than silence.
- `as_of` (ms): when the issuer evaluated it, no later than the claim's registration; `until` (ms, optional, after `as_of`, possibly before the registration): after it the claim has lapsed.
- `subject` (optional, 1 to 256 bytes): whom or what the source is about, as the issuer names it.
- `for` (optional): `[ledger, record]`, the access request on that ledger that the claim answers (v0.15, section 12). The ledger checks its shape only: the request is on another ledger, and the requester checks the rest.

The ledger checks the metadata's shape and refuses other keys. It cannot check the answer: the values are sealed. A claim's own fields (at least one, as every record's) are the issuer's: the reference implementation commits the values it checked, sealed like any record's, so that the issuer can show later what it relied on. A claim is the issuer's statement, attributed to its signer as any registration is; what a verifier learns is the condition, the answer, the subject, and the source's type and status, nothing of the source's fields.

**Memberships** (v0.16). A membership is a ledger's word that another ledger (the **member**) belongs to the organization or person it names, as it checked them: "ledger 1a2b... is Kowloon Example School, company 12345678, Hong Kong, checked". A ledger that registers memberships is a **trust node**. Any ledger may be one; whether a verifier believes it is the verifier's choice (section 11). A membership is a `kanhe.membership/1` record whose public metadata (key 5) is `membership` in the CDDL:
- `member`: the member's ledger id. The ledger refuses its own id.
- `kind`: `organization` or `person`.
- `name`: 1 to 256 bytes: the name the trust node checked, or a person's display name.
- `verified`: whether the trust node checked who the member is. `false` is the member's own word, which a report calls self-declared.
- `registration` (optional, 1 to 64 bytes): a company or registry number.
- `jurisdiction` (optional): an ISO 3166-1 alpha-2 code of two upper-case letters, optionally followed by `-` and 1 to 3 upper-case letters or digits of a subdivision (ISO 3166-2): `HK`, `CN-44`.
- `until` (optional, ms, above 0): after it the membership has lapsed.

The ledger checks the metadata's shape and refuses other keys. A membership is active when registered; the trust node suspends it, resumes it, and ends it (the member left, or did not renew) by transitions, and revokes it for cause. It has no versions: a renewal is a new membership, which may overlap the old one, and each is judged by its own history. A membership's registration and transitions are statements about the membership only: the member's ledger is another ledger, unchanged.

**The vault** is informative and local to an implementation. The reference implementation keeps each record's values and salts sealed with HPKE (RFC 9180, base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM) to the ledger's vault key. Each sealed file is bound to its ledger and record.

## 7. Proof of presence

A person proves presence for exactly one statement with a registered credential. The challenge is

```
challenge = HASH("Kanhe presence v1" || kid || P)
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

**What presence defends against.** Presence defeats a stolen key file: the thief also needs the person's authenticator, in their hands. It does not defeat malware on the person's own machine, which can show a misleading page and ask for a touch. The reference implementation's passkeys use the relying party id of the page that made them: `localhost`, for the command line's one-time local page and a web console on one computer, or a company console's own host name, over HTTPS. Such a console is not a signing oracle: it computes each challenge from a statement that its signed-in user asked it to prepare, holds it for two minutes, and takes one approval of it; it never signs a challenge that a link or another site hands it. A compromised console serves its own page, so, as with local malware, presence does not defend against the server itself.

Verifiers report how presence was proven. A statement without proof of presence is attributed to a machine, whoever signed it.

## 8. The log

Each accepted statement becomes a **log entry**: `{1: id, 2: registered at, 3: the signed statement}`. Alternatively, key 4 replaces key 3 and holds a state commitment (section 9). The tree commits to the encoded log entries, in order, under the ledger's hash. Registration times never go back: each entry's is no earlier than the one before it, and a verifier refuses entries whose times do (v0.12).

A **checkpoint** is signed by the log key over `{1: ledger id, 2: hash, 3: tree size, 4: root, 5: timestamp}`. The tree size is at least 1, since genesis is always in the log.

**The log key in effect.** The organization may rotate the log key (statement type 8) and its root key (actor-rotate-key on itself), each signed by its root key in effect. The log key in effect for a tree of N entries is the one set by the last rotation at an index below N, or the genesis key. It signs checkpoints of size N and receipts against them. A rotation therefore takes over from the first state commitment or checkpoint after it, and older checkpoints stay valid under the key that signed them. Log keys never repeat.

A **receipt** is an RFC 9942 COSE inclusion receipt for an encoded log entry:
- protected header `{1: alg, 4: kid, 395: vds}`;
- unprotected header `{396: {-1: [inclusion proof]}}`;
- detached payload, which is the Merkle root at the proof's tree size.

A receipt is tagged (tag 18), and key -1 holds exactly one inclusion proof, `[tree size, leaf index, path]`, whose path has at most 64 hashes (v0.12).

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
- records: every statement about them, including the registration of the record that supersedes them (v0.10);
- contracts: deploy and retire;
- instances: creation and every call. An instance created by another's call (section 15) starts with that call, which its parent's history lists too. Requests and answers (v0.8) have no leaves of their own: the calls that make and answer them are in their instance's history.

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
5. the RFC 9162 consistency proof (at most 65 hashes) shows the new tree extends the old one.

A **cosignature** is a COSE_Sign1 by the witness key over the same checkpoint payload bytes, with the cosignature content type. Its kid is the witness key's, under the hash of the ledger it cosigns. Asking again for the checkpoint cosigned last MAY be answered with a fresh cosignature of it, so a lost answer can be retried.

Two organizations can witness each other's ledgers. Neither can then rewrite or fork its history without the other seeing it.

Once a witness has followed a log key rotation, it accepts only the new key. A leaked old log key can therefore not get a fork cosigned by it.

A **public witness** (informative) follows any ledger that asks. A ledger registers by sending its genesis entry with a cosign request; the witness learns the ledger id, hash, root key, and first log key from the genesis entry (the ledger id must be the checkpoint's), and follows the ledger only if it cosigns that request under the rules above. A registration therefore proves that the caller holds the log key in effect. The witness keeps only the state described above, and never the ledger's statements. Section 16 gives the routes and section 17 what a public witness learns.

### 10.1 Time-stamp authorities (v0.11)

A checkpoint's timestamp is the ledger's own word, and a witness proves only that a ledger did not fork or rewrite what it cosigned. A **time-stamp authority** (TSA) gives an outsider a bound on *when*: its **time-stamp token** is an RFC 3161 `TimeStampToken` (DER, CMS SignedData) whose `messageImprint` is the ledger's hash (SHA-256, or SM3 for SM3 ledgers) of a checkpoint's payload, the bytes witnesses cosign. The authority signs it at its own time (`genTime`, with its stated accuracy), so everything the checkpoint covers existed by then. A token is not a statement: the ledger keeps tokens beside its checkpoints, as it keeps cosignatures, and never in the log. Anyone may ask an authority for one (RFC 3161 over HTTP, `application/timestamp-query`), with the authority's certificate requested (`certReq`) so that verifiers can check it.

A ledger SHOULD keep a token only if it verifies with its signing certificate, stamps one of its checkpoints, and agrees with the ledger's clock (below): a token that does not could only make the ledger's evidence fail.

Which authorities to trust is each verifier's choice: it trusts the tokens whose signing certificate chains to one of the root certificates it holds, valid at the token's time and for time stamping (the critical `id-kp-timeStamping` usage, RFC 3161 section 2.3), with a signing-certificate attribute (RFC 5816) that names that certificate. Tokens of other authorities are counted, and relied on for nothing. A token without its signing certificate fails the evidence whoever its authority is, since nothing about it can be checked (v0.12). An authority is identified by the SHA-256 of its signing certificate's SubjectPublicKeyInfo, and counted once however many tokens it gave. An absent accuracy counts as zero, and accuracy in microseconds rounds up to the next millisecond.

**The clock rule.** A verifier that trusts a token over a checkpoint of size N, with time T and accuracy A, MUST refuse the evidence if the checkpoint, or an included entry with an index below N, is dated later than T + A + 60 seconds: the ledger dated what the authority had already seen. (The 60 seconds allow for two honest clocks that disagree.)

### 10.2 Open witness networks (v0.13)

A ledger can also be witnessed by the witnesses of open transparency networks that follow C2SP's specifications: [tlog-checkpoint](https://c2sp.org/tlog-checkpoint), [tlog-cosignature](https://c2sp.org/tlog-cosignature), [tlog-witness](https://c2sp.org/tlog-witness), and [signed-note](https://c2sp.org/signed-note). Such a witness knows nothing of this protocol. It cosigns a log's checkpoints as text notes, under the rule of section 10: each new tree extends the last one it cosigned, as an RFC 6962 consistency proof shows (RFC 9162 trees are RFC 6962 trees). Only SHA-256 ledgers can be witnessed so; an SM3 ledger's tree is not an RFC 6962 tree.

- **The origin.** A ledger's name in such a network, its *origin*, is `cirraya.com/kanhe/` followed by the ledger id in 64 lowercase hexadecimal digits. It is derived, never chosen: every verifier knows it from the ledger id, and a ledger cannot show one witness two forks under two names. The domain is a name, not an address: nothing is ever fetched from it.
- **The checkpoint note.** For a checkpoint the log key signed, the note text is three lines, each ending in a newline (U+000A): the origin, the tree size in decimal, and the root in base64 (RFC 4648 section 4, with padding). It has no extension lines.
- **The note key.** A witness checks a note's signature with the log's verifier key, which it was configured with, and a network never updates a log's key. So the ledger signs notes with a **note key**, its operator's Ed25519 key (signature type 0x01, key name the origin), apart from the log key, which can rotate. The note key is no part of evidence: verifiers never need it. Whoever steals it can push a tree to a witness, which would block the real one, but cannot make evidence verify: a network cosignature counts only for the size and root of a checkpoint the log key signed (section 11). (Informative: a network lists a log by its verifier key, its origin, and how many checkpoints a day it sends; Kanhe's tools print that entry.)
- **Cosignatures.** A network witness answers `add-checkpoint` with note signature lines, `— <name> <base64 bytes>`. The bytes are a 4-byte key ID, then an 8-byte big-endian POSIX time T, then the signature. Two kinds are recognized:
  - Ed25519 (signature type 0x04): over the text `cosignature/v1`, a newline, `time T` (T in decimal), a newline, then the note text;
  - ML-DSA-44 (signature type 0x06; FIPS 204's pure form, empty context): over tlog-cosignature's `CosignedSubtree`: the 12 bytes `subtree/v1\n\0`, the witness's name with a one-byte length, T, the origin with a one-byte length, start 0 and end the tree size (8-byte big-endian each), and the 32-byte root.

  A witness's key ID is the first four bytes of `SHA-256(name || 0x0A || type || public key)`. A verifier trusts network witnesses by their **verifier keys**, `<name>+<key ID in 8 lowercase hex digits>+<base64(type || public key)>`, the base64 with padding and in its canonical form (which may hold `+`: the first two `+` split the key), and checks the key ID. Names follow signed-note: 1 to 255 bytes of UTF-8 with no white space, no `+`, and no control character. T is an unsigned 64-bit count of seconds.
- **In evidence.** An anchor (section 11) may carry such cosignatures of its checkpoint's note: key 4, each `[name, bytes]`.

## 11. Evidence bundles and verification

An evidence bundle (`evidence-bundle`) holds:

- the record id, or an instance's id (section 15);
- log entries with their receipts, in ascending order, starting with genesis: the record's statements (with the registration that supersedes it, if any; not the record it supersedes) and every statement they depend on (signers' registrations and key rotations, delegation chains, referenced actors), and every rotation of the organization's keys below the checkpoint's size. For a claim (v0.14), also its source's statements (with the registration that superseded the source, if any) and theirs. For an instance created by a call, also its ancestors' calls up to the one that created each next generation (section 15);
- the signed checkpoint all receipts lead to, and witness cosignatures of it;
- optional field disclosures and attachment openings (salts; the contents travel alongside);
- state proofs for every involved object;
- optional anchors (v0.11): signed checkpoints at or before the bundle's checkpoint, each with time-stamp tokens over its payload (section 10.1), open-network witnesses' cosignatures of its note (v0.13, section 10.2), or both, and, for an earlier one, the RFC 9162 consistency proof from its size to the bundle's checkpoint;
- optional membership proofs (v0.16): 1 to 16 evidence bundles, each the complete evidence of a `kanhe.membership/1` record on a trust node's ledger that names this bundle's ledger as its `member` (section 6). A proof carries no membership proofs of its own.

A verifier MUST:

1. Take the ledger's identity, hash, and first keys from the genesis entry. If it expects a particular ledger, check the ledger id.
2. Check every receipt's inclusion proof against the checkpoint (same size and root), with indices strictly ascending from 0.
3. Replay the included statements under the ledger rules (section 5), at their registration times. This follows the organization's key rotations. A registration that supersedes a record the bundle does not hold (v0.10) is checked under every rule except those about that record: that record's own bundle shows the link. A claim's source (v0.14) has no such exception: a claim's bundle without its source fails.
4. Verify the checkpoint and every receipt's signature with the log key in effect at the checkpoint's size, and each state commitment with the one in effect at its index. A bundle that leaves out a log key rotation fails here, since keys never repeat.
5. Check disclosed fields against the record's field root and count, and the contents provided for opened attachments against their sizes and commitments: a content that does not match fails the evidence. A content given for an attachment the bundle does not open is reported as not provided (v0.12).
6. Count cosignatures only by witnesses it trusts, each witness once, network witnesses' among them (step 8). A cosignature over another checkpoint, and one by a trusted witness that does not verify, fail the evidence; one by a witness it does not trust is counted and relied on for nothing (v0.12).
7. If the last entry the checkpoint covers is a state commitment (included with its receipt):
   - check it as replay would;
   - verify every state proof against its root;
   - for the record and each involved object, require a proof whose leaf equals that object's leaf in the replayed state. The involved objects are each event's signer, an agent signer's responsible person, and every delegation in the chain with its grantor; for an instance, also its contract; for a claim (v0.14), also its source, whose statements count as events too. For an instance created by a call, its ancestors' included calls count as events too, and the ancestors themselves need no proof (section 15).

   A missing or differing proof fails the evidence, and so do state proofs in a bundle that does not include that commitment (v0.12). Only then is the report **complete**: nothing, such as a later revocation, was left out.
8. For each anchor (v0.11):
   - check that its checkpoint is of the ledger, no larger than the bundle's checkpoint, and signed by the log key in effect at its size; that it equals the bundle's checkpoint's size and root (with no proof) or its consistency proof leads from it to the bundle's checkpoint;
   - check each token: it verifies with its signing certificate, and its imprint is the ledger's hash of the anchor's checkpoint's payload, under the ledger's hash algorithm;
   - for the tokens it trusts (section 10.1), apply the clock rule to the anchor's checkpoint and to every included entry below its size. Each such entry then **existed by** the earliest trusted time plus its accuracy;
   - for each network cosignature (v0.13; section 10.2): an SM3 ledger's anchors carry none, and the bytes hold at least a key ID and a time. One whose name and key ID are a trusted network witness's MUST verify against the note of the anchor's checkpoint, or the evidence fails; it then counts in step 6 as that witness's, and shows that the witness saw that size by its time T. Others are counted and relied on for nothing. T is reported, and not put to the clock rule: a witness promises consistency, not time.
9. For each membership proof (v0.16):
   - verify it as an evidence bundle under steps 1 to 8, for the ledger its own genesis names (none is expected), with no attachment contents and with the verifier's own trusted witnesses, network witnesses, and time-stamp authorities (so a trusted cosignature that does not verify fails the proof, as in step 6). Its witnesses and tokens are not reported, and a verifier's minimums of witnesses or authorities apply to the outer bundle only. A proof that carries membership proofs is refused before anything in it is checked. It MUST verify and be complete (step 7), be about a `kanhe.membership/1` record whose metadata is a membership (section 6) naming this bundle's ledger as `member`, and carry no membership proofs. Two proofs of one membership (the same ledger and record) fail the evidence;
   - take the membership's state at a time T from its history in the proof, its transitions and revocation at their registration times (not their issue times) and in log order: **not yet a member** if T is before its registration; else **revoked** if it was revoked at or before T; else **lapsed** if T is after its `until`; else the state its last transition at or before T left (**active**, **suspended**, or **ended**), or active if none. A proof shows the history up to its checkpoint only: for a T after the checkpoint, the state is as of the checkpoint, with `until` applied;
   - state it at two times: when this bundle's record was registered (for an instance, when the call that created it was registered), and at the proof's checkpoint's time.

   A proof that fails any of this fails the evidence. Its trust node is **trusted** if its ledger is on the verifier's list (below); a proof from any other ledger is reported and relied on for nothing.

**Trust nodes** (v0.16). A verifier has a list of the trust nodes it believes, each a ledger id and the name the verifier gives it, each ledger once. A report names a trust node by that name, never by anything the evidence says, the node's organization name included, so a look-alike node gains nothing. A verifier with an empty list trusts no trust node, and still reports every proof.

A report states:
- who did what, when, and under whose authority;
- for each event, whether a person proved presence and how, and any AI provenance;
- for a record, the record it supersedes, and the registration that superseded it, if any (by whom and when);
- for a claim (v0.14): its condition in words (below), whether it holds, the subject, `as_of`, `until` and whether the checkpoint's time is past it, and its source's id, type, and status: revoked if it was revoked, else replaced if it was superseded, else live. The report's events are the claim's own;
- the disclosed fields and attachment checks;
- the witnesses, and each network cosignature, in the bundle's order: its witness, the size it cosigned, its time, and whether the witness is trusted (v0.13). A ledger witness is one by its key, a network witness by its verifier key, so each is counted once;
- the time-stamp tokens, and for each event the time by which a trusted authority saw it (v0.11);
- for each membership proof (v0.16), in the bundle's order: the trust node's ledger id, whether it is trusted, and the name the verifier's list gives it; the membership's id, `kind`, `name`, verified or self-declared, `registration`, `jurisdiction`, and `until`; and its state when the record was registered and at the proof's checkpoint, with that checkpoint's time;
- whether it is complete.

**A claim in words** (v0.14). A report states a claim's condition as one line of text, which every verifier gives the same. Each term is its field name, the operator's words, and the value, and the terms are joined by ` and `:

| `op` | English | 繁體中文 (informative) | 简体中文 (informative) |
|---|---|---|---|
| `>` | `is above V` | `高於 V` | `高于 V` |
| `>=` | `is at least V` | `不低於 V` | `不低于 V` |
| `<` | `is below V` | `低於 V` | `低于 V` |
| `<=` | `is at most V` | `不高於 V` | `不高于 V` |
| `=` | `is V` | `為 V` | `为 V` |
| `!=` | `is not V` | `不是 V` | `不是 V` |
| `between` | `is between L and H` | `介乎 L 至 H` | `介于 L 至 H` |
| `in` | `is one of V1, V2` (`, ` between them) | `屬於 V1、V2 其中之一` | `属于 V1、V2 其中之一` |
| `exists` | `is given` | `已填寫` | `已填写` |

A number is written as it is encoded (an integer in decimal digits, a decimal text as is). Money is its currency, a space, and the amount: a `-` if negative, the integer part's digits in groups of three from the right separated by `,`, and, for a scale above 0, a `.` and that many digits (`[3000000, "HKD", 2]` is `HKD 30,000.00`). A date is written as it is encoded, and text between double quotes, as it is. So `[["monthly_salary", ">", "money", [3000000, "HKD", 2]], ["status", "in", "text", ["staff", "contractor"]]]` is `monthly_salary is above HKD 30,000.00 and status is one of "staff", "contractor"`. In Chinese the terms are joined by `，且 ` (a space before the next field's name).

## 12. Access across organizations

Two organizations, each with its own ledger, share a record in four steps: the **requester** asks the **granter** for a record on the granter's ledger.

| Step | Record type | On whose ledger | Metadata (key 5) |
|---|---|---|---|
| Request | `kanhe.access-request/1` | the requester's | `ledger` (asked), `record`, `purpose`, `until`, `recipient` (X25519 key), optional `fields`, `attachments`; or, for a condition (v0.15), `condition` instead of the last three |
| Grant | `kanhe.access-grant/1` | the granter's | `ledger` (requester), `request`, `record`, `fields`, `attachments`, `until`, `recipient` |
| Delivery | not a record: a `delivery` object | sent to the requester | grant evidence, and contents sealed with HPKE |
| Receipt | `kanhe.access-receipt/1` | the requester's | `ledger` (granter), `grant`, `delivery` (SHA-256 of the delivery) |

Each side learns the other's **ledger id** out of band and pins every bundle it receives to it. Field and attachment names in requests and grants are non-empty, unique within their list (compared as their UTF-8 bytes, with no normalization), and at most 256 to a list. A key present with a value not of its type, null included, makes the metadata refused, whatever the key: an absent `fields` means all fields, a null one is refused. Because the steps are records, delegations decide who may request, grant, or acknowledge, and proof of presence shows when a person approved.

- **Request.** The requester makes a fresh X25519 key for the request and records the request. It sends the request's evidence bundle. The granter checks the following:
  - the bundle verifies for the requester's ledger and is complete;
  - it is a live access request that names the granter's ledger;
  - it has not expired.

  The report shows who asked, under whose authority, and whether they were present.
- **Grant.** The granter records a grant for at most what was asked and until no later than the request's end.
- **Delivery.** The granter builds `{1: 1, 2: grant bundle, 3: {1: enc, 2: ciphertext}}`. The ciphertext seals `delivery-contents` with HPKE to the request's key, with info `"Kanhe delivery v1"` and the grant id as additional authenticated data. `delivery-contents` holds the record's bundle with only the granted disclosures and openings, and the granted attachments' contents.
- **Acceptance.** The requester MUST check all of the following, and only then acknowledge:
  1. the grant verifies for the granter's ledger, which is the ledger the request asked, and is complete;
  2. the grant is live, and names the requester's ledger, its request, and its key;
  3. the grant answers the request: the same record, fields and attachments the request asked for (or fewer), and an end no later than the request's;
  4. the grant has not expired;
  5. the contents open with the request's key;
  6. the record bundle verifies for the granter's ledger at the grant bundle's checkpoint, is complete, and is the granted record, which is not revoked;
  7. the record bundle discloses exactly the granted fields, each once;
  8. the delivery holds exactly the granted attachments, each opened and matching its commitment.
- **Receipt.** The requester records the receipt and sends its evidence. The granter checks that the receipt comes from the ledger the grant was made to, names the granter's grant, and gives the hash of the delivery made under that grant. A stored receipt is never replaced by a different one.
- **Serving deliveries** (informative). A server hands out a delivery only to the peer it was granted to, and only while the grant is live and unexpired. The same route serves the answer to a condition (below).

Revoking a grant stops future deliveries. It cannot make a recipient forget, but the receipt makes access accountable.

**Asking about a condition** (v0.15). A request may ask whether a condition holds in the record instead of asking for its data: "is Chan Tai Man's monthly salary above HKD 30,000.00?" without the salary. Its metadata then has `condition`, 1 to 16 terms of a claim's condition (section 6), checked as a claim's are, and no `recipient`, `fields`, or `attachments`: nothing is sealed to the requester. A reader refuses a request that has `condition` and any of those three, or has neither `condition` nor `recipient`. `record` is the record asked about, and the request is open until `until`. The steps are those above, with a claim for the grant and the delivery:
- **Answer.** The granter registers a claim (section 6) whose `source` is the request's `record`, whose `condition` is the request's, term for term (the same deterministic encoding), and whose `for` is `[requester's ledger, request id]`. It says whether the condition holds; implementations SHOULD answer that it does not only when the granter chose to, and a granter that does not answer records nothing, so that a refusal looks like silence.
- **Serving it** (informative). The granter's server hands out the claim's complete evidence bundle, as made when it answered, at the route that serves deliveries, to the peer whose ledger the claim's `for` names, while the claim is live and has not lapsed. A bundle has key 0 and a delivery has not, so neither is taken for the other; the requester knows which to expect from its own request.
- **Acceptance.** The requester MUST check all of the following, and only then acknowledge:
  1. the claim's bundle verifies for the ledger the request asked, and is complete;
  2. it is a claim, live (confirmed, not revoked), and its `until`, if any, has not passed;
  3. its `for` names the requester's ledger and the request;
  4. its `source` is the request's `record`, and its `condition` the request's, term for term and in the same deterministic encoding: values that are equal as numbers or amounts but encoded otherwise (`2` and `"2.0"`, `[100, "HKD", 0]` and `[10000, "HKD", 2]`), or the same values of `in` in another order, are another condition;
  5. its source is live in the bundle: neither revoked nor replaced (section 11).

  The claim may say that the condition holds or that it does not; the report says which. Its `until` is the granter's choice and may end before or after the request's; its `as_of` is the granter's word, and a claim can name the request only once the request exists, since `for` holds the request's id.
- **Receipt.** The requester records an access receipt whose `grant` is the claim's id and whose `delivery` is the SHA-256 of the claim's bundle as served. The granter checks it as it checks a receipt for a grant: it comes from the ledger the claim's `for` names, names the granter's claim, and gives the hash of the bundle the granter served.

Revoking the claim withdraws the answer: the server stops serving it, and every later verifier of its evidence sees it withdrawn.

## 13. Relying on an instance's state

*Informative. Revisions v0.5 to v0.8 defined native ownership assets here, with statement type 20; v0.9 removed them (section 4). A receivable, a warehouse receipt, a ticket, or a booking is now a contract instance (section 15).*

A party often acts on what an instance's state says: a lender funds against a pledge the state records, a buyer pays once a transfer makes it the holder, a venue admits whoever holds a ticket. The protocol guarantees what an instance's history shows: one home, which records only calls its contract accepts; consents given on each party's own ledger and bound to the instance's head, so each is used once; and the same result for every verifier that replays the calls. It does not know what a state means: "pledged" is the contract's word, not the protocol's. A party that relies on an exclusive state therefore:

- **reads the rules:** it reads the contract the instance runs, or rebuilds its code from the source (section 15), and checks that the contract refuses what the party fears, such as a second pledge or a transfer without its consent;
- **waits for witnesses:** it acts only once the call it relies on is in a checkpoint cosigned by witnesses it trusts, and only on the instance's contract evidence, verified and complete, at that checkpoint. From then on a conflicting call is refused or detected: a consent to an older head no longer matches, the contract refuses what its state does not allow, and a home that forks its log to show another party a different state needs that party's witnesses to cosign the fork, while a witness cosigns only one history;
- **shares a witness:** parties that rely on one instance SHOULD require a common witness, such as a regulator or a witness service. Two checkpoints of one size with different roots, both signed by the home's log key, prove the home's misconduct.

**Limits.**
- A home can refuse to record a call (censorship). It cannot record a call that its contract or the parties' consents do not allow, nor fork its log unseen.
- The ledger cannot know whether goods, money, or seats exist: a home could make two instances for one thing. Every instance it made is in its log, for auditors and witnesses.
- Legal registries are not replaced; a call's reference can carry a filing number.

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
- Functions only, from the module `kanhe`, among the host functions of section 14.4, each with its exact type and at most once.

**Memory and table**
- At most one memory, defined in the module, of at most 16 pages (64 KiB each). The maximum, when absent, is 16.
- At most one table, `funcref`, of at most 1,024 elements.

**Globals**
- At most 1,024, of type `i32` or `i64`.
- Each initialized by a single `i32.const` or `i64.const`.

**Exports**
- The memory, named `memory`.
- A function `kanhe_call` of type `[] -> []`, defined in the module.
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

An invocation calls `kanhe_call` once. It has **10,000,000 fuel**, and each instruction executed consumes fuel *before* it takes effect.

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

Imported from the module `kanhe`. Pointers and lengths are unsigned. A range `[ptr, ptr + len)` must lie within the memory, or the call traps with *out of bounds*. Each function charges its cost first, then checks its ranges, in the order listed.

| Function | Type | Cost | Effect |
|---|---|---|---|
| `input_size` | `[] -> [i32]` | 1 | the input's length |
| `input_read` | `[i32] -> []` | 1 + ⌈length / 64⌉ | copies the whole input to `ptr` |
| `output_write` | `[i32 i32] -> []` | 1 + ⌈len / 64⌉ | sets the output to `[ptr, ptr + len)`. Traps if an output was already written, then if `len` exceeds 1 MiB, then on the range |
| `hash` | `[i32 i32 i32] -> []` | 64 + ⌈len / 64⌉ | writes the ledger's hash (SHA-256 or SM3) of `[ptr, ptr + len)` to `[out, out + 32)`, checking the input range first |
| `abort` | `[i32 i32] -> []` | 1 | traps with *aborted*; the reason is the first min(`len`, 1,024) bytes at `ptr` |

The input and output are bytes to the execution layer. Their contents, deterministic CBOR, are defined in section 15.

## 15. Contracts

*Draft for revision v0.6; v0.7 adds instances created by a call, and v0.8 requests and answers.*

A **contract** is a module, in the profile of section 14, deployed on a ledger: its **home**. An **instance** is one thing the contract governs, such as a loan, a lease, or a booking. An instance lives on its home ledger only:
- only the home records its calls, and only if the contract accepts them;
- its **parties** are organizations (any of which may be one person, section 1), named by ledger id under roles the contract chooses, such as `owner` or `guest`;
- a party other than the home consents on its own ledger;
- every verifier replays the calls with the same contract and reaches the same result.

A call may also create instances of its contract, called **children**, such as the parts a thing is divided into (v0.7). And it may ask **executors** to act outside the ledger, with **requests** that they **answer** by calls of their own (v0.8).

**Statements.**

| Type | Name | Body |
|---|---|---|
| 21 | contract-deploy | code, interface, language, compiler; optionally the source and a name |
| 22 | contract-call | the contract (to create an instance) or the instance and its head; the function, the arguments, consents, a reference; an answer to a request (v0.8) |
| 23 | contract-retire | contract, reason |

**Deploy.** A contract is identified by its deploy statement's id, and its code never changes: a new version is a new deploy.
- **Code:** a module that loads under the profile (section 14.1), at most 524,288 bytes.
- **Interface:** each function's name (UTF-8, 1 to 64 bytes; at most 256 functions) and kind: 1 creates an instance, 2 acts on one. At least one function creates.
- **Language** (1 to 32 bytes: `bo`, `wasm`) and **compiler** (1 to 128 bytes, with its version).
- **Source** (at most 262,144 bytes), so that anyone can rebuild the module and compare.
- **Name** (1 to 256 bytes), for people.

**Contracts written in Bo.** Bo, the language Kanhe's contracts are written in, is specified in [`bo.md`](bo.md). A deploy whose language is `bo` SHOULD carry, as its source, a **`bo-source` bundle** (`bo-source` in the CDDL): `{1: 1, 2: edition, 3: source, 4: [+ [id, version, digest]], ? 5: [+ pack], ? 6: [+ [id, version, digest]], ? 7: [+ vocabulary-pack]}`.
- **Source:** the source as written (UTF-8, comments included) and the Bo edition it is written in. Whoever holds the deploy reads it, comments too.
- **Packs:** every language pack the source was read with, by ascending id: its id, its version, and the hash under the home's hash of the pack's canonical CBOR. Packs that are not official are embedded in full (key 5, as their canonical CBOR, by ascending id); a reference without one names an official pack, which a Bo compiler carries in every released version. A pack maps spellings to concepts and never changes what runs, but it decides how the source reads, so the digests pin it.
- **Vocabulary packs:** every vocabulary pack the source uses (its `use` lines; key 6, by ascending id): its id, its version, and the hash of its canonical CBOR. A vocabulary pack (the official finance, commerce, and services, or one of a user's own) brings words beyond Bo's core and the standard terms of its built-in actions, so it changes what runs, and the digests pin it too. Vocabulary packs that are not official are embedded in full (key 7, as their canonical CBOR, by ascending id), so a verifier needs nothing but the deploy ([`bo.md`](bo.md), section 3.9).
- **Compiler:** the compiler string names the compiler, its release, its codegen version, and the edition it reads: `kanhe-bo 0.0.1; codegen 5; edition 1`. The same codegen version builds the same bytes from the same source, in any language and on any machine, and a compiler keeps writing the released codegen versions before its own, so that older deploys rebuild ([`bo.md`](bo.md), section 16).

A verifier SHOULD rebuild the code: decode the bundle, find each pack (the official ones from its compiler, the others from the bundle) and each vocabulary pack (the official ones from its compiler, the others from the bundle) and check its digest, build the source, and compare the module, the interface, and the name with the deploy's. It reports one of:
- **rebuilds:** the source builds to the deployed code;
- **differs:** the compiler the deploy names builds something else, so the source is not the code's. The verifier SHOULD fail the evidence;
- **malformed:** no source, not a bundle, or a pack that does not match its digest or does not read. The verifier SHOULD fail the evidence;
- **another compiler:** another compiler, or another release or codegen version, built it, and this one builds something else. The verifier says which and MAY require a rebuild with that compiler; it never reports this as a forgery.

The ledger rules do not rebuild: a home that deploys a source that is not its code is caught by every verifier that rebuilds. For another Bo compiler, the language's behaviour is normative and these code bytes are not.

**Retire.** A retired contract creates no more instances. Its instances carry on.

**Call.** A call names either:
- a contract and a function of kind 1, to **create** an instance, whose id is then the call's statement id; or
- an instance, its **head**, and a function of kind 2. The head is the log index of the instance's latest call (at first, its creation).

A call on an instance may also be an **answer** to one of its requests (body key 8, v0.8; see "Requests and answers" below).

The **arguments** are any CBOR value, at most 65,536 bytes encoded. Whoever holds the instance's evidence sees them, so values a contract must check are disclosed to every verifier.

**Ledger rules.** A contract-call MUST be refused unless:
- exactly one of contract and instance is present, and the head is present exactly with an instance; an answer (key 8, v0.8) names an instance;
- for a creation: the contract exists and is not retired, the function is in its interface with kind 1, and the call cites no consents;
- otherwise: the instance exists, the head is its head, and the function is in its contract's interface with kind 2; the instance is not final, unless the call is an answer (v0.8);
- the consents, if any, are 1 to 16, strictly ascending by ledger, and none is from the home;
- for an answer (v0.8): the request is an open request of the instance, the function is the request's reply, the status is expired only if the registration time has reached the request's deadline, and the call cites no consents;
- the contract, run on the call's input (below), succeeds with an `accept` output;
- if the accept creates children (key 6, v0.7): the contract is not retired, and the instance the call acts on, or creates, has a depth below 8;
- if the accept makes requests (key 7, v0.8): each deadline is after the call's registration time and at most 366 days (31,622,400,000 ms) after it, each reply is a function of kind 2 in the contract's interface, and the instance is left with at most 64 open requests;
- if the instance was final before the call (an answer, v0.8): the accept makes no requests and creates no children.

A contract-deploy MUST be refused unless its code loads and its interface is well formed. A contract-retire MUST name a contract that exists and is not retired.

**Authority.** Delegations cover types 21 to 23 like any other type. Scope key 7, when present, lists the contracts the grantee may act on: a call or a retire must act on one of them, where a call on an instance acts on the instance's contract. A delegated scope's contracts are a subset of the grantor's. Key 7 does not restrict deploys.

Two more scope keys (v0.8) restrict contract calls only:
- **key 8, functions:** a call under it must name one of these functions, a creation's included;
- **key 9, request kinds:** a call under it must be an answer to a request of one of these kinds.

Each is a strictly ascending list of text: function names of 1 to 64 bytes, and request kinds (below). Like key 7, each narrows: when the grantor's scope has the key, a delegated scope must have it too, and list a subset of the grantor's. When it is absent, any function, or any call, is allowed.

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
| 9 | for an answer only (v0.8): the request, `{1: id, 2: kind, 3: params, 4: deadline, 5: asked at, 6: status}`, with the answer's status |

A **signer** describes who signed a statement: `{1: kind, ? 2: presence, ? 3: model}`.
- **Kind:** 0 for the organization; otherwise the actor's kind (person 1, agent 2, device 3).
- **Presence:** present only if the statement carries proof of presence, as its method (passkey 1, hardware key 2).
- **Model:** the model the statement's provenance names, if any (an agent's always names one).

So a contract can require that a person approved in person, or that an agent's step is confirmed by a person.

**The output** is a deterministic CBOR array, written with `output_write`:
- `[1, accept]` accepts the call. `accept` is `{1: state, ? 2: status, ? 3: parties, ? 4: events, ? 5: true, ? 6: children, ? 7: requests}`:
  - **state:** any CBOR value, at most 65,536 bytes encoded, kept by the home and given to the next call;
  - **status:** 1 to 64 bytes, shown in reports and lists, such as `proposed` or `effective`;
  - **parties:** a map from roles (1 to 64 bytes) to ledger ids, at most 64. It replaces the instance's parties; when absent, they stay as they were (none after a creation);
  - **events:** at most 64 `[name, data]` pairs, with names of 1 to 64 bytes, shown in reports;
  - **key 5:** the instance is **final** and takes no more calls, except answers to its open requests (v0.8);
  - **children** (v0.7): 1 to 16 new instances, each `{1: state, ? 2: status, ? 3: parties}` with the limits above; see "Instances created by a call" below;
  - **requests** (v0.8): 1 to 16 requests to executors, each `{1: kind, 2: params, 3: deadline, 4: reply}`; see "Requests and answers" below.
- `[2, needs]` asks for consents. `needs` lists the ledgers whose consents the call lacks: 1 to 16, strictly ascending, none the home.

An output is well formed only if it is deterministic CBOR within the limits of section 2 and matches `contract-output`. The call is refused on a trap (`abort` is how a contract rejects a call, with its reason), on a `needs` output, and on an output that is not well formed. The contract is deterministic, so the home runs it first without consents to learn whom to ask. A role may name the home itself: the home agrees through the call it signs, so it never consents to its own calls. Section 13 says when a party may rely on an instance's state.

**Instances created by a call** (v0.7). An accepted call may create up to 16 children (output key 6), such as the parts a thing is divided into. The instance the call acts on, or the one it creates, is their **parent**.
- **Id.** A child's id is `HASH(deterministic-CBOR([call, position]))` under the home's hash. `call` is the creating call's statement id, and `position` the child's index in key 6, from 0. A statement id hashes a COSE `Sig_structure` instead, so a child id never equals a statement id.
- **Start.** A child has its parent's contract. Its state, status, and parties are its keys 1 to 3; without status or parties it has none, like a new instance. Its head is the creating call's log index, as is its parent's after the call. It is not final.
- **Depth.** An instance created by a creation has depth 0, and a child its parent's depth plus 1, at most 8. So an instance has at most 8 ancestors, and its evidence stays bounded.
- **Order.** The home applies the accept to the parent as to any call (state, status, parties, finality), then creates the children in order. A parent may keep its state and take more calls, or end (key 5). A split normally ends it, so that only the parts carry its value.
- **Retired contracts** create no more instances, neither by a creation nor as children. Calls that create none carry on.
- **Calls on a child** are calls on an instance: its id, its head, a function of kind 2, and consents that name the child. Under scope key 7, a call on a child acts on its contract.
- **Final instances** take no more calls, except answers to their open requests (v0.8). They stay in the state, and their evidence can still be fetched and verified. A parent's end does not end its children, nor a child's its parent.
- **What the contract sees.** For a call on a child, the instance view (input key 5) carries key 6, `[parent, depth]`, so a contract can refuse to split at the depth limit with its own reason. For other instances the view has no key 6, and the input is as in v0.6.
- **Consents** are unchanged: at most 16 per call, none from the home. A split that needs the consents of the holder and of every recipient therefore has at most 15 recipients besides the holder.

**Requests and answers** (v0.8). A contract decides, but never acts on the world outside the ledger: replay could not repeat that. Instead, an accepted call may make **requests**, and an **executor** carries them out: an actor of the home, such as a device next to a control panel, an AI agent, or a person, which acts (sends a notice, opens a door, records an entry in another system) and reports what happened with a call of its own, an **answer**. The contract then sees the answer and reacts. Requests are part of the contract's output, which every verifier recomputes by replay, so the log entry format does not change.
- **A request** is `{1: kind, 2: params, 3: deadline, 4: reply}` in accept key 7, at most 16 per call:
  - **kind:** what to do, 1 to 64 bytes of lowercase ASCII letters, digits, `.`, `_`, and `-`, starting with a letter: `notify`, `provision`, `suspend`;
  - **params:** what the executor needs, any CBOR value of at most 4,096 bytes encoded, within the privacy rules below;
  - **deadline:** when the work is due, after the call's registration time and at most 366 days after it;
  - **reply:** the function an answer calls, of kind 2 in the contract's interface.

  A request belongs to the instance the call acts on, or, for a creation, to the instance it creates. Children (key 6) start with none. A request is **asked at** its call's registration time.
- **Id.** A request's id is `HASH(deterministic-CBOR(["request", call, position]))` under the home's hash: `call` is the requesting call's statement id, and `position` the request's index in key 7, from 0. Its leading text keeps it apart from child ids (`[call, position]`), and statement ids hash a COSE `Sig_structure`. The id is the request's **idempotency key**: an executor MUST NOT carry out one id twice, and SHOULD give it to the outside system (as the reference of what it creates there, for instance) so that a retry after a crash is recognized there.
- **Open requests.** A request is **open** until an answer to it is recorded; then it is **closed**, with the answer's status. An instance has at most 64 open requests: a call whose accept would leave it more is refused. An answer closes its request first, so an instance at the limit still takes an answer that makes one new request.
- **An answer** is a contract-call on the instance with body key 8, `[request, status]`, the status being 1 **done**, 2 **failed**, or 3 **expired**. It calls the request's reply, and its arguments carry the result, as the contract defines it (at most 65,536 bytes, as for any call). Besides the rules of every call (the head, authority), an answer is refused unless:
  - the request is one of the instance's, and open: a request is answered **at most once**;
  - the function is the request's reply;
  - for status 3, the registration time has reached the deadline. Done and failed are valid at any time: one registered after the deadline is **late**, and is recorded all the same;
  - it cites no consents, and the contract accepts it. An answer the contract rejects, or for which it asks for consents, is refused, and the request stays open. A contract therefore never asks for consents for an answer: none could be given.
- **What the contract sees.** For an answer, input key 9 shows the request: `{1: id, 2: kind, 3: params, 4: deadline, 5: asked at, 6: status}`, with the answer's status. So a contract need not keep its requests in its state, and it sees whether an answer is late and who gave it (input key 6). For any other call, the input has no key 9.
- **Order.** The home closes the request, then applies the accept as for any call (state, status, parties, events, finality, children), then opens the requests the accept makes. An answer may make requests of its own: a retry after a failure, or the next step.
- **Expiry.** Expiring is an answer like the others, given by whoever the delegations allow, typically a keeper (the actor that fires a contract's time rules). It SHOULD wait for a grace period after the deadline, so that a slow but real result is recorded rather than lost. An executor SHOULD NOT start work after a request's deadline.
- **Final instances** take no calls except answers to their open requests. Such an answer may change the state, status, parties, and events, but it makes no requests and creates no children, and the instance stays final whatever its accept says. So a contract can end an instance and still learn whether the world followed: a service that ends asks a panel to reclaim its address, and the panel's answer arrives after the end.
- **Who may answer:** any actor whose delegation covers the call, a person answering by hand included. Scope keys 8 and 9 keep executors and keepers to their work: an executor gets key 8 `["result"]` (its contract's reply) and key 9 with the kinds it serves, so that it can answer those requests and nothing else; a keeper gets key 8 with the contract's time rules and the reply, so that it can fire rules and expire requests, but not call the actions that are the home's own word.
- **Executors verify before acting.** However an executor learns of requests (an API, a feed), it SHOULD act only on a request that it finds open by replaying contract evidence it has verified itself (below), against the home's ledger id and, for valuable work, the witnesses it trusts. Then a compromised API cannot make it act on a request that is not in the signed log.
- **Privacy.** Requests and answers are visible to everyone who holds the instance's evidence, like arguments and states. Contracts MUST keep requests, and executors their answers, to what may be shown:

  | Requests and answers may carry | They MUST NOT carry |
  |---|---|
  | kinds, ledger ids, values the contract already holds, amounts, dates, and record and request ids | names, e-mail addresses, phone numbers, postal addresses, or any document's content |
  | results: outside ids (such as another system's reference), statuses, amounts, reason codes, and salted digests of outside responses | secrets of any kind, or raw error texts from outside systems (they may name people) |

  An executor keeps contact details in its own directory, keyed by ledger id. It keeps an outside system's response too, and puts in the answer only `HASH(salt || response)` under the home's hash, with a fresh 16-byte salt, as attachments do (section 6), so that it can disclose the response later, with proof. The ledger cannot check any of this; verifiers show what requests and answers carry.

**Consents.** A party consents with a `kanhe.contract-consent/1` record on its own ledger (state given, which may become withdrawn), under its own delegations and with proof of presence if a person approved. Its metadata names the terms:
- `ledger` (the home), `instance`, `function`, and `head`;
- `arguments`: the hash, under the home's hash, of the encoded arguments;
- `until`, when it lapses;
- optionally a `reference`.

A creation takes no consents: an instance starts as the home's proposal, and binds a party only once the party consents to a later call, which the head makes single-use.

A call cites each consent as `[ledger, record, bundle, signer]`: the party's ledger, the consent record, the hash under the home's hash of the consent's evidence bundle, and the signer of the consent's registration. The bundles are not in the log, so the ledger rules see only the citations, and the contract decides on the signers they claim. Before recording a call, the home MUST check each consent bundle as a verifier does (step 3 below), and MUST keep the bundles it cites.

**Contract evidence** (`contract-evidence`) is the instance's evidence bundle with every consent bundle its calls cite. The instance's bundle includes the deploy (and so the code), any retire, and every call on the instance. For a child, it also includes its **ancestors' histories** (v0.7): for each ancestor, its creation and every call on it up to and including the call that created the next generation. "Its calls" then include these, consents and all. A verifier MUST:
1. verify the instance's bundle for the expected home ledger (section 11) and require it to be complete;
2. replay it, running the contract for each call, the ancestors' included, to reach the instance's state, status, parties, whether it is final, and its requests (v0.8). For a child, the replay also shows that each generation is the child its creating call's output made at its position, with that output's state, status, and parties, within the depth limit: otherwise the instance would not exist in the replayed state;
3. for each consent citation, find the bundle with that hash and check that:
   - it verifies, completely, for the cited ledger, trusting the witnesses, network witnesses, and time-stamp authorities the verifier trusts for the home (v0.13);
   - it is about the cited record, a live `kanhe.contract-consent/1` record (given, not revoked);
   - it carries the call's terms;
   - it lapses no earlier than the call's registration time;
   - the record's registration was signed as the citation claims (kind, presence method, and model);
4. refuse bundles that no citation pins, and citations without a bundle.

The report shows each call: the function and arguments, the outcome (status and events), who called and who consented, under whose authority, whether a person proved presence, and any AI provenance. For a child, it shows the ancestors first, each with its depth and its calls up to the one that created the next generation.

**Requests in evidence** (v0.8). They need no state leaf of their own: they are derived by replay from the calls in the instance's history, and a complete bundle holds every one of those calls. So complete evidence proves every request the instance made and every answer it took, and that none is missing. The report shows, besides each call:
- for each call, the requests it made: id, kind, params, deadline, and reply;
- for each answer, the request it answers, its status, and how late it is (its registration time minus the deadline, when positive); who answered, with kind, delegation, presence, and model, is shown as for every call;
- at the end, the instance's open requests, each flagged **overdue** if the checkpoint's time has reached its deadline.

A verifier MAY, when asked to, fail evidence that has overdue open requests. For a child, the requests its ancestors' included calls made belong to the ancestors: the report shows them with those calls, but cannot show whether they were answered later, since those calls are left out.

**Evidence for a child** leaves out its ancestors' later calls, and the siblings' calls. So it need not prove the ancestors' leaves, which list those later calls, and the home's bundles carry no proof for them. Their histories up to each creating call are still complete. Every call names the head it follows, so a call left out breaks the chain, and the creating calls are those the instance's id derives from. The involved objects (section 11, step 7) include those of the ancestors' calls, so their signers and delegations are proven complete like the instance's own.

**Proposal and consent files** (`exchange-file`, extension `.kanhe`) carry consents between ledgers that do not reach each other's APIs: people send them by any channel. They add nothing the ledgers rely on, since every claim in them is checked against the evidence they carry, and the home records the call as it would with any consent:
- a **proposal** is the home's request for consents to one call: the home ledger, the instance, its head, the function, the arguments, the home's hash, the instance's contract evidence (as of a checkpoint covering the head), and the ledgers whose consents the call waits for. A party verifies the evidence for the home ledger, requires the instance and head in the file to be the evidence's, and reads the call against the contract's text before it consents;
- a **consent** answers a proposal: the same terms, and the consent's evidence bundle from the party's ledger. The home checks the bundle as it checks any consent (above) before it cites it.

A file is at most 16 MiB, its note (if any) at most 1,000 bytes of text for people, and its list of ledgers at most 16. A reader refuses a file of another format version, of another kind, or with any other key.

**Not yet.** Evidence from other ledgers as input, and migration to a new version, are planned for later revisions.

## 16. The HTTP API

This section is informative. The reference implementation serves a ledger over HTTP/1.1 (`kanhe serve`):

- Binary objects (log entries, checkpoints, proofs, receipts, bundles, deliveries) are CBOR or COSE as defined above. Everything else is JSON. Errors are `{"error": {"code", "message"}}`.
- Access is gated by bearer tokens with scopes. The statement signature remains the authorization for what is written.

| Scope | Routes |
|---|---|
| none | `GET /healthz`, `GET /v1/checkpoint[?size=N]`, `GET /v1/consistency?old=&new=`, `GET /c/{token}` (a published record, below), `GET /m/{ledger}` (a membership, v0.16, below) |
| read | `GET /metrics`, `/v1/status`, `/v1/entries?start=&count=`, `/v1/genesis`, `/v1/checkpoints`, `/v1/cosignatures`, `/v1/timestamps` (v0.11), `/v1/network-cosignatures` (v0.13), `/v1/inclusion?index=&size=`, `/v1/statements/{id}`, `/v1/receipts/{index}`, `/v1/state/{id}`, `/v1/evidence/{record}`, `/v1/vault/public-key`, `/v1/vault/records/{record}`, `/v1/vault/files/{record}`, `/v1/vault/files/{record}/{index}`, `/v1/contracts?start=&count=`, `/v1/contracts/{contract}`, `/v1/contracts/instances/{instance}`, `/v1/contracts/calls`, `/v1/contracts/calls/{call}`, `/v1/requests` (v0.8), `/v1/contracts/due`; on a server with the search index, `/v1/records`, `/v1/records/{id}`, `/v1/records/{id}/versions`, `/v1/instances`, `/v1/reports/records`, `/v1/reports/instances` |
| submit | `POST /v1/statements`, `POST /v1/contracts/calls`, `PUT /v1/vault/files/{record}/{index}` |
| admin | `POST /v1/checkpoint`, `POST /v1/cosignatures`, `POST /v1/timestamps` (v0.11), `POST /v1/network-cosignatures` (v0.13), `DELETE /v1/vault/files/{record}/{index}`, `GET`, `POST /v1/published`, `DELETE /v1/published/{token}` |
| peer | `POST /v1/access/requests`, `GET /v1/access/deliveries/{request}` (a delivery, or, v0.15, the bundle of the claim that answers a request for a condition), `POST /v1/access/receipts`, `POST /v1/witness/cosign`, `POST /v1/contracts/calls` and `GET /v1/contracts/instances/{instance}` (the instance's current parties), `GET /v1/contracts/calls`, `/v1/contracts/calls/{call}` (the calls that concern the peer), `POST /v1/contracts/consents`, `GET /v1/genesis` (the genesis entry, which the ledger id authenticates: a peer that witnesses the ledger follows its root and log keys from it) |
| executor | `GET /v1/requests`, `GET /v1/contracts/instances/{instance}`, and `POST /v1/statements` for answers only (v0.8) |
| none, on a public witness | `GET /v1/witness`, `POST /v1/witness/register`, `POST /v1/witness/cosign` (below) |
| none, on a relay (signed) | `POST`, `GET /v1/relay/messages`, `DELETE /v1/relay/messages/{id}` (below) |
| read, admin | clusters: `GET /v1/cluster`; `POST /v1/cluster/members`, `/v1/cluster/members/remove`, `/v1/cluster/step-down` |

**Clusters.** Several members can keep one ledger with Raft. Each group of statements is replicated as `{time, statements, sealed private data}` and applied by every member at that time, so their logs are identical. Checkpoints are signed by the leader and replicated as signed. The consent bundles a statement cites, and the calls a registrar holds, are replicated too, so a new leader carries on with them. A follower answers writes with 307 and the leader's API. Members authenticate their Raft messages with a shared secret. None of this changes the protocol: a cluster's log is one ledger's log.

`POST /v1/statements` also takes `application/kanhe-submission+cbor`: `{1: signed statement, 2: sealed private data}`, a record's registration with its vault file. The server stores the file with the record, once: the same file again is accepted (a retry), a different one refused, so nobody can store other data for a record first. With `4: [[index, sealed file], ...]` (indexes ascending and distinct), the record's attached files come too, each sealed to the vault key like the vault file (HPKE `info` "Kanhe record file v1", the associated data the ledger id, the record id, and the attachment's name) and holding exactly the size the registration gives that attachment, at most 16 MiB: the server keeps each once, beside the vault file, and `GET /v1/vault/files/{record}` lists the indexes it keeps, `GET .../{index}` returns one, `PUT` keeps one later (once), `DELETE` removes one. The ledger still holds only the attachments' commitments: a reader opens a kept file with the vault key and checks it against the commitment with the salt in the vault file. For a contract call, the submission is `{1: signed statement, 3: [consent bundles]}`, one bundle per consent in the statement's order: the server checks every consent the call cites against its bundle, and the signer each citation claims (section 15), before registering it, and keeps the bundles. A statement that cites consents is refused without them.

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

`GET /v1/contracts` and `/v1/contracts/{contract}` list and show the contracts to read tokens: interface, language, compiler, name, whether retired, the number of instances, and, for one contract, its code's size and hash (the code is in the deploy statement). `GET /v1/contracts/instances/{instance}` returns the contract evidence, without private data, to the instance's current parties, to the ledgers a call the registrar holds on it asks to consent (so that they verify what they are asked to agree to), and to read tokens, as of a checkpoint that covers the instance's latest call; the server makes one if it must. For a part (v0.7), the evidence carries its ancestors' calls up to each one that created the next generation, with the consent bundles those calls cite, and goes to the part's current parties (a parent's parties see only the parent). Listing a parent's parts takes no route: its evidence shows each call's children, and the part's id is derived from the call (section 15).

**Requests** (v0.8). An answer is submitted like any other statement, with `POST /v1/statements`. It cites no consents, so a registrar never holds one, and the proposal route takes none: its body names no request, and a final instance takes no proposals. An executor reads the requests it serves in contract evidence (`GET /v1/contracts/instances/{instance}`), and checks them there before acting (section 15).

To find them, `GET /v1/requests` lists requests as JSON, oldest change first: each with its id, instance, contract, the instance's head, kind, params (hex CBOR), deadline, reply, the call that made it (log index and position), when it was asked, its status (`open`, `done`, `failed`, or `expired`), the answer's log index and time, how late the answer was, and whether it is open past its deadline by the server's clock. The query selects `state` (`open`, the default; `answered`; or `all`), `kind` (one or more, comma-separated), `contract`, `instance`, `after` (only requests made or answered after the log's first N entries), and `limit` (1 to 1,000; default 100). The answer carries a `cursor` for the next `after`, and `more` when a limit cut it short; a page never ends inside one log entry. With `wait=S` (at most 25 seconds) it is a long poll: if nothing matches, the server answers once something does, or when the wait is over, with what matches then. The list is a hint, never evidence: it comes from the server, not from a signed log, and an executor acts only on a request it finds open in evidence it has verified.

**Search.** A server keeps a search index beside its ledger (in the reference implementation, an SQLite file rebuilt from the log whenever it is missing), and answers searches and reports from it, to read tokens. It holds only what the ledger holds in the clear: records' types, states, registrants, registration times, versions (v0.10), endorsement counts, and public metadata; instances' contracts and their names, status, finality, parties, creation and last-call times, the creating call's reference, and the fields of their state (Bo's `fields`, section 15). Private field values are never indexed. Like the requests route, its answers are hints: each says `as_of`, the log size it reflects, and a party relies only on evidence it verified.
- `GET /v1/records` lists records, newest first, selected by `type`, `state`, `registrant` (an actor's id), `since` and `until` (registration time, milliseconds or `YYYY-MM-DD[THH:MM:SSZ]`), `current=1` (leave out superseded versions), `revoked` (`no`, the default; `yes`; `any`), `meta.KEY` (a metadata value exactly), `meta.KEY.min` and `meta.KEY.max` (a whole number in range, also when written as text), and `q` (text in the metadata's values: three or more characters use a trigram index, so a part of a word, Chinese included, matches). `GET /v1/instances` lists instances by `contract`, `contract_name`, `status`, `final`, `party` (a ledger id), `since`, `until` (creation), `changed_since`, `reference`, and `field.NAME`, `field.NAME.min`, `field.NAME.max`. Both page with `limit` (1 to 1,000; 100), `order` (`new` or `old`), and `cursor`, the answer's `next`. An unknown parameter is refused (400).
- `GET /v1/records/{id}` answers the record's row with `latest`, the newest of its versions, and `versions`, how many there are; `GET /v1/records/{id}/versions` answers every version's row, oldest first.
- `GET /v1/reports/records` and `/v1/reports/instances` count what the same filters select, grouped by `by` (comma-separated, at most four: `type`, `state`, `registrant`, `day`, `week`, `month` for records; `contract`, `state`, `day`, `week`, `month` for instances), with times bucketed in `utc_offset` (`+08:00`); for instances, `sum=FIELD` adds the total, least, and greatest of a whole-number field. At most 10,000 groups (`truncated` says if there were more).

**Published records.** A record can be published at a private address, so that whoever holds it (a printed certificate's QR code) gets the record's evidence without a token, as it is when asked: revoked or replaced since, the evidence says so. The address is `/c/{token}`, the token 16 random bytes in base64url (22 characters), not derived from the record, so published records can be neither listed nor guessed. Each publication chooses the fields it discloses, the ones its holder may see anyway (those on the paper); the others stay sealed.
- `POST /v1/published` takes CBOR `{1: record, 2: [* [leaf, index, path]]}`, the disclosures as an evidence bundle carries them (section 11), at most 64. The server checks each against the record's commitment, chooses the token, keeps it beside the ledger, and answers 201 with JSON: `token`, `address` (the path), `record`, `fields` (the disclosed fields as `{name, value}`, in the order given), `published_at` (ms). A read-only server or a replica refuses (403); so does a cluster, for now (501).
- `GET /v1/published` lists them, oldest first, in the same JSON; `DELETE /v1/published/{token}` takes the address down (the record stays on the ledger; 404 if nothing is published there).
- `GET /c/{token}` answers the evidence bundle (CBOR), as of a checkpoint that covers the record's latest change (the server makes one if it must), with `Access-Control-Allow-Origin: *` (any page may verify it) and `Cache-Control: no-store`; 404 for a token with nothing published.

**Memberships** (v0.16). A trust node's server answers `GET /m/{ledger}`, for a member's ledger id in 64 lower-case hexadecimal digits, with the complete evidence bundle (CBOR) of the newest membership on its ledger that names that ledger, whatever its state, as of a checkpoint that covers the membership's latest change (the server makes one if it must), with `Access-Control-Allow-Origin: *` and `Cache-Control: no-store`; 404 if none names it. A member's server fetches its proofs from the trust nodes it chooses, keeps the newest from each, and adds them (key 9) to the bundles it serves and exports.

**Executors and connectors.** How Kanhe's executor runtime talks to connectors, the programs that act in outside systems, what its answers carry, and how secrets reach them, is described in [`connectors.md`](connectors.md) (informative).

**Executors' leases.** Several copies of one executor (the same actor, for a standby) take turns through a lease the server keeps in memory: a poll that names `executor` (the actor's id) and `lease` (the copy's holder id: 8 to 64 letters, digits, `-`, or `_`, random per copy) takes the lease if it is free, lapsed, or the copy's own, and holds it through its wait and for `ttl` seconds after the answer (5 to 300; default 60). The answer then carries `lease` `{granted: true, holder, ttl_ms}`. A copy that does not hold it gets no requests and the cursor it sent, with `lease` `{granted: false, holder, retry_ms}`; it polls again later. A copy renews its lease by polling, and acts only while it holds it. In a cluster, a follower sends such polls to the leader (307), so every copy asks the same server; after a restart or a failover the first copy to poll takes the lease. A lease is coordination, not authority: anyone with an executor token may poll as any executor, and what keeps a lapse from doing harm is the ledger's at-most-once answer and the idempotency key every executor passes on (the request's id, `spec/connectors.md`).

The `executor` token scope is for executors: those routes, and `POST /v1/statements` for answers only (a contract call answering a request, without consents or private data); any other statement is refused (403) before the ledger sees it. What an answer may do is still decided by its signature and delegation (scope keys 7 to 9). In a cluster, requests and answers are derived from the replicated log, so a new leader lists the same requests, and a follower sends an answer to the leader like any other write.

**Keepers.** A ledger acts only on calls, so a contract's time rules (by convention its functions of kind 2 named `when.*`, which Bo compiles each `when` rule to; Bo names every request's reply `result`, [`bo.md`](bo.md) 6.11) apply when an actor calls them, and a request left open past its deadline closes when one expires it. A **keeper** is such an actor: a device of the home whose delegation covers contract calls only, on some contracts (scope key 7), of the time rules and the requests' replies (key 8), with no key 9. The reference server can be one (`serve --keeper-key`): every interval (60 seconds by default), on the leader only in a cluster, it finds what is due and calls it, signing as the keeper, its writes queued like any other. What is due is found by dry runs at the server's time:
- a **time rule** is due if its contract accepts the call (no arguments, on the instance at its head) and the accept would change something (the state, status, parties, or finality, or events, requests, or children); a rule refused before its time records nothing, so calling early is harmless;
- an **expiry** is due once an open request's deadline plus a grace (15 minutes by default) has passed and its contract takes the answer (status 3, null arguments), so that a slow but real result is recorded rather than lost.

Only the calls the keeper's delegations cover are its to make. Each call moves its instance's head, so the keeper makes one call per instance at a time and looks again. A scan runs a bounded number of contracts at a time (each a dry run; Bo's time rules cost about 10,000 to 13,000 fuel) and carries on where it stopped. A failover loses nothing: a rule applies once for each time and a request takes one answer, so a new leader's keeper redoes nothing its predecessor recorded.

`GET /v1/contracts/due` (read tokens; never public, since it runs contracts) answers what a keeper would do, as JSON: `at`, `grace_ms`, `keeper`, `rules` (instance, contract, head, status, function, and the rule's `time` and `late_ms` when the contract reports them in an event `["when", {"time", "late", ...}]`, as Bo's do), `expiries` (request, instance, contract, head, kind, reply, deadline, `overdue_ms`), `refused` (due work the contract or the ledger would not take, with the reason), `instances`, `runs`, `fuel`, and `next`. Without `keeper`, each item lists the `keepers` whose active delegations cover it. The query selects `at` (milliseconds since the epoch; default now), `grace` (seconds; default the server's), `keeper`, `contract`, `instance` (full ids), `start` (the `next` of an earlier answer), and `limit` (contract runs, 1 to 100,000; default 10,000). Like the requests route, it is a hint: the ledger decides each call when it registers it.

**Public witnesses.** A server can be a public witness (`serve --witness-public`) beside serving its own ledger. Three routes then take no token:
- `GET /v1/witness` describes it as JSON: `name`, `key` (the hex of its COSE public key), `algorithm`, `ledgers` (how many it follows), and `limits`. This is a hint: a ledger pins the key its operator publishes, never the one a witness says it has.
- `GET /v1/timestamps?start=&count=` (v0.11) pages through the time-stamp tokens the ledger keeps, oldest first, as CBOR `[checkpoint, token]` pairs (the signed checkpoint each stamps); `POST /v1/timestamps` takes CBOR `[token, checkpoint size]` and keeps the token as section 10.1 says.
- `GET /v1/network-cosignatures?start=&count=` (v0.13) pages through the open-network witnesses' cosignatures the ledger keeps, oldest first, as CBOR `[checkpoint, verifier key, bytes]` (the signed checkpoint whose note each cosigns, and the witness's verifier key); `POST /v1/network-cosignatures` takes CBOR `[checkpoint size, verifier key, bytes]`, and keeps a cosignature only if it verifies against that checkpoint's note.
- `POST /v1/witness/register` takes CBOR `{1: genesis entry, 2: cosign request}` and answers the cosignature (201 for a new ledger, 200 for one it follows already, which is then a cosign request like any other). A refused registration leaves nothing behind.
- `POST /v1/witness/cosign` takes a cosign request for a ledger it follows (404 for another: register first).

Its quotas bound what anyone can make it store and do: a number of ledgers in all (100,000 by default; then 503), new ledgers per caller address per UTC day (10; every attempt counts; then 429), and one cosignature per ledger per interval (60 seconds; then 429). A 429 carries `Retry-After`. Quotas see the connection's address, so a public witness serves TLS itself rather than behind a proxy.

A ledger keeps the public witnesses it registered with (in the reference implementation, `witnesses.json` beside the ledger, written by `witness register`), and its server asks each one to cosign every new checkpoint and keeps the cosignatures, which evidence then carries. Stopping keeps what was cosigned valid.

**Relays.** A ledger that no party reaches directly (a laptop) is reached through a relay, the server of a public witness (`serve --relay-dir`). The relay carries the peer API, sealed: a request to a party's `/v1` API (method, path, content type, body, the peer token) is sealed with HPKE (base mode, info "Kanhe relay request v1", associated data the recipient's ledger id, the sender's, and the message id) to the party's relay key (X25519), with a fresh answer key; the party's node opens it, answers it with its own API exactly as if it had come directly, and seals the answer (status, content type, body) to the answer key (info "Kanhe relay answer v1", the same associated data). A message on the relay is a COSE_Sign1 by the sender's log key in effect (external data "Kanhe relay message v1") over `{1: to, 2: from, 3: id (16 bytes), 4: [encapsulated key, ciphertext], ? 5: the id of the request it answers, 6: until (ms)}`. Past `until` a message is of no use: the relay refuses or drops it, and a node never answers a request found after it (a request waits at most ten minutes; its answer carries the same `until`), so a party offline for a day does not answer a day of requests when it returns. Routes, with no token:
- `POST /v1/relay/messages`: the relay checks the signature with the log key its witness follows for the sender, and that the recipient is witnessed there too (403 or 404 otherwise; a sender not yet witnessed registers, section 10, and sends again). A message sent again (the same id) is kept once.
- `GET /v1/relay/messages?to=LEDGER[&wait=S][&requests=1|&answers=ID]`: the mailbox, oldest first, as a CBOR array of messages: all, requests only, or the answers to one request; a long poll of up to 25 seconds. `DELETE /v1/relay/messages/ID?to=LEDGER` takes one. Both carry `Authorization: Kanhe-Relay <base64url COSE_Sign1>` by the mailbox ledger's log key (external data "Kanhe relay fetch v1") over `{1: ledger id, 2: time (ms)}`, at most five minutes from the relay's clock.

Quotas: a message at most 17 MiB; 1,000 messages and 64 MiB per mailbox; 2,000 messages and 256 MiB a day per sender; messages kept 14 days at most. Invitation codes carry a relay as key 7, `{1: relay URL, 2: relay key, 3: the relay's witness key}`.

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
- **Time.** Registration times come from the ledger's clock and are ordered. Issued-at times are claims by the signer, bounded only in the future direction. A trusted time-stamp authority's token (v0.11) bounds them from outside: what a stamped checkpoint covers existed by the authority's time, and a ledger that dates such an entry later fails verification. Without one, nothing outside the ledger bounds its times.
- **Open witness networks** (v0.13).
  - A network witness learns the ledger id (its origin names it), and each checkpoint's size, root, and time it is sent; never statements, records, or parties. Its list of logs is public.
  - It is trusted for consistency only: that the ledger showed it one history. Its time is the witness's own clock, reported and relied on for nothing.
  - The note key is a second key of the operator's, not the log key. Its theft can block a ledger's witnessing (a thief who pushes a tree first makes the witness refuse the real one), not forge evidence. Operators SHOULD keep it as they keep the log key, and back it up: networks do not update a log's key.
  - A network may refuse or rate-limit a log that sends more checkpoints a day than its listing says.
- **Time-stamp authorities** (v0.11).
  - An authority is trusted for time only, never for content: it sees a digest, not the checkpoint, and signs whatever digest it is sent. Its token proves that the checkpoint existed by its time, not that the ledger is honest; witnesses do that.
  - A token proves nothing about entries after its checkpoint: a ledger can still date them as it likes until a later checkpoint is stamped. Verifiers that rely on time SHOULD require a token on a checkpoint after the event (Kanhe's tools take `--min-timestamps`).
  - A verifier relies on an authority's certificate chain at the token's time. It does not check revocation (CRL or OCSP): a verifier that must, checks the authority's status by other means. An authority whose key leaked can backdate tokens; trusting two authorities, each once, bounds what one can do.
  - The 60 seconds of the clock rule let an honest ledger whose clock runs a little ahead pass; a ledger whose clock runs further ahead gets tokens it should not keep (section 10.1).
  - Kanhe's tools run their clock ahead when `KANHE_CLOCK_OFFSET` is set (informative; for demonstrations and tests, to try time rules without waiting). A home run ahead records later registration times, fires time rules and expires requests early, and keeps those times: registration times are ordered, so once the offset is gone its new entries carry the latest time it recorded until its real clock passes it. `serve` therefore refuses to start with an offset unless it is given `--allow-clock-offset`, and its status (`/v1/status`, `clock_offset_ms`) shows the offset to anyone who can read it. A client run ahead of its home is refused (a statement issued in the future); a command that writes a ledger directory itself (without `--server`) is that ledger's clock for its writes. The variable is trusted input, like the command line: whoever sets it controls the process. Verifiers cannot tell a clock run ahead from a correct one; witnesses' and parties' own clocks are the check (see above).
- **Keys.**
  - Actor keys can be rotated, and revocation cascades through delegation chains.
  - The log key and the organization root key can be rotated (v0.4), for instance to ML-DSA. A leaked old log key can still sign a different history that never rotated. Only witnesses that followed the rotation reject it, so verifiers SHOULD require cosignatures from trusted witnesses.
  - A leaked root key can rotate both keys. Recovering from that needs action outside the ledger, such as a new ledger. Keep the root key in an HSM; threshold root keys are future work.
  - Algorithms are pluggable, and post-quantum signatures (ML-DSA) are supported now.
- **Relays.** A relay learns which ledgers write to which, when, and how much; never what (requests and answers are sealed), and nothing it says is trusted: the answer key that only the sender holds lets only the node that opened a request answer it, and the peer token inside the request still decides what the recipient's API does. A relay can drop or delay messages, which shows as a party not reached. Its signatures are checked against the log keys its witness follows, so only witnessed ledgers use it.
- **Public witnesses.** A public witness learns the ledger id, the genesis entry (its organization's name and first keys), each checkpoint's size, root, and time, and the caller's address: how many entries a ledger has and when it grows, never its statements, records, fields, parties, or files. Checkpoints on a fixed schedule hide timing, not counts. Its state is bounded by its quotas (about 200 bytes per ledger). A witness that refuses a ledger, or disappears, cannot change what it cosigned; verifiers SHOULD trust more than one, run by different operators.
- **Privacy.**
  - Public metadata, record types, actor names, and timestamps are visible to whoever holds a bundle.
  - Field values and attachments are hidden behind salted commitments until disclosed.
  - Access to a server's read routes should be restricted accordingly.
- **Cross-organization access.**
  - A delivery is sealed to a key made for one request. It is bound to its grant and checked against the granter's ledger.
  - Revocation cannot recall data already delivered.
- **Contracts.**
  - A contract's code, arguments, states, and events are visible to whoever holds an instance's evidence. Private values belong in records, disclosed selectively.
  - Every call is bounded by fuel, call depth, and memory (section 14), so a contract cannot stall the home or a verifier.
  - Code is immutable, but it can be wrong. Verifiers show which contract, and which source, an instance runs, and rebuild a Bo contract's code from its source. Parties should read the code (or its Bo source) before consenting.
  - Consent signers are claimed in the call and checked only by verifiers that hold the consent bundles, so parties SHOULD verify contract evidence, not just the home's log.
  - Consents are machine actions unless they carry proof of presence. Verifiers report this and MAY require it.
  - Parties that rely on an exclusive state, such as a pledge, are safe from a home that shows them different histories only through the witnesses they share (section 13). If two lenders share no witness, the home can show each of them a history in which its pledge is the only one.
- **Children** (v0.7).
  - A child's evidence shows its ancestors' calls up to each creating call: the parent's states and parties, the arguments of the split, and the first state and parties of every sibling. So a part's holder, and anyone it shows the part to, sees the other parts' holders and amounts. This is accepted for v1; commitments or zero-knowledge proofs may hide siblings later. The evidence does not show the siblings' later calls, nor the ancestors' calls after each split.
  - The protocol does not know amounts: a contract that splits must conserve them. A verifier that relies on a part SHOULD check, in the replayed split, that the parts add up to the parent's amount, or rely on a contract whose source it has read and rebuilt.
  - Depth is capped at 8, so a part's evidence carries at most 8 ancestors' histories.
- **Requests and answers** (v0.8).
  - An answer is its signer's claim that the world followed, not proof of it. A false answer (a payment reported that was never made) is permanent and attributable to its signer, under its delegation: verifiers show who answered, with what authority and model, and whether a person did. Contracts MAY require a person's answer, or a second answer, for valuable kinds, and homes SHOULD reconcile answers against the outside systems.
  - A compromised executor key can answer the open requests its delegation reaches, falsely. Scope keys 7 to 9 bound that to some contracts, functions, and request kinds; it cannot answer twice, make requests, call other functions, or prove presence. Revoking its delegation stops it at once.
  - The ledger guarantees at most one answer per request, not that the work is done at most once: an executor that loses track of a request could act again. Executors use the request id as their idempotency key, outside too, and keep a journal.
  - Deadlines, lateness, and expiry follow the home's clock, which is ordered but not anchored (see "Time"). The home decides when an answer is registered: it could hold a valid answer back until a keeper expires the request. An executor that keeps its signed answer can show that it was offered in time.
  - A contract that refuses every answer to a request keeps it open, and a final instance with such a request takes answers forever. The limits (16 requests per call, 4,096 bytes of params, 64 open requests per instance) keep this, and replay, bounded.
  - Requests and answers are visible to whoever holds the instance's evidence; section 15 says what they may carry. Outside responses are committed by salted digest, never carried.
- **Connectors** ([`connectors.md`](connectors.md), informative).
  - A connector is trusted with its own requests' outcomes, and with nothing else: it holds no signing key, sees only the requests routed to it and the secrets its configuration names, and runs without the executor's environment. A connector that lies about an outcome produces a false answer, signed by the executor and attributable to it; a reconciliation against the outside system is the remedy, not the ledger.
  - The list of requests a server gives is a hint. An executor that acted on it without verifying the instance's evidence could be made to act on requests that do not exist; Kanhe's runtime never does. A server can still hide requests or delay answers.
  - An executor's lease is held in the server's memory and granted to anyone with an executor token: it coordinates honest copies, and protects nothing. A response kept in an executor's journal may carry personal data: the journal is the executor's, owner-only, and only its salted digest is published.
- **Keepers** (section 16).
  - A keeper's key can call only what its delegation covers: the time rules (which the contract refuses before their time, and applies once for each time) and the replies (expiry only once a deadline has passed). A compromised keeper key can fire rules on time and expire requests early within the grace, never the home's own-word actions; revoking its delegation stops it at once.
  - A keeper inside the server (`serve --keeper-key`) shares the server's trust: that server already holds the log key. A home that wants them apart runs the keeper as its own process, on its own key.
  - A keeper that stops leaves rules unfired and requests open; nothing else is lost, and any keeper (or any actor the delegations allow) can fire them later. Bo's events record how late each rule came.
- **Trust nodes** (v0.16).
  - A membership is its trust node's word and nothing more. A verifier relies on it only if it chose the trust node, and then on that node's checks, which `verified` says it made or not; a self-declared name is the member's own.
  - A proof shows a membership as of its checkpoint. A suspension, end, or revocation after it is unknown to a verifier that has only the proof, and a member may attach an older proof than the newest: the report gives the checkpoint's time. A verifier that needs the present state fetches a fresh proof from the trust node (section 16), or requires a recent checkpoint.
  - A trust node's name comes from the verifier's list, never from the evidence, so a node named like a known one gains nothing. The list is the verifier's to keep: a page ships one, and its readers trust whoever chose it.
  - A trust node that registers a false membership is accountable for it as any signer is for its registrations.

## 18. Test vectors

| File | Covers |
|---|---|
| `hashes.json` | SHA-256, SM3 |
| `signatures.json` | Ed25519, ESP256, SM2, ML-DSA from independent implementations |
| `merkle-sha256.json`, `merkle-sm3.json` | RFC 9162 tree hashes, inclusion and consistency proofs |
| `cose-sign1.json` | COSE_Sign1 in the Kanhe profile |
| `pkcs8.json` | encrypted private keys |
| `protocol-v0.1.json` | statements, log entries, checkpoints, receipts (encodings only: the statements are not a history the rules accept) |
| `protocol-v0.2.json` | presence (passkey and hardware key), state trees and commitments, cosign requests |
| `protocol-v0.3.json` | access metadata, and a delivery sealed by an independent HPKE implementation |
| `protocol-v0.4.json` | log and root key rotation, the checkpoint and state commitment under the new key, a cosign request with key rotations |
| `protocol-v0.6.json` | contracts (section 15): a test contract deployed, instances created and called, with each call's input and output, consent metadata, calls the rules refuse, and contract evidence |
| `protocol-v0.7.json` | instances created by a call (section 15): a splitting contract and the v0.6 test contract; children and their ids, calls on a child and a grandchild, splits down to the depth limit, children the rules refuse (too many, too deep, malformed, on a retired contract, on a final parent), the state tree, and signed evidence bundles: an instance, a tier-3 part with its ancestors and real consent bundles from other ledgers, and a child whose parent carried on |
| `protocol-v0.8.json` | requests and answers (section 15): a requesting contract; requests and their ids; answers done, failed, and expired, by a device, an AI agent, a keeper, and a person by hand, on time and late, some making new requests; answers the rules refuse (a second answer, expired too early, an unknown request or another instance's, a function that is not the reply, consents cited, outside scope keys 8 and 9, rejected by the contract, malformed); the limits (17 requests in a call, a 65th open request, 4,096 bytes of params, deadlines, replies) and malformed requests; scope keys 8 and 9 and their narrowing; a final instance that takes answers and refuses the rest; requests on a creation that also creates a child; the state, the log, and signed evidence showing answered, open, and overdue requests, with an outside response committed by salted digest |
| `protocol-v0.9.json` | the generic core (v0.9): a record of a user's type endorsed in several roles, refused a transition and a repeated endorsement, and revoked; the four mechanism types through their lifecycles, refusing endorsements and transitions they do not define; statements of type 20 and a scope naming it, which do not parse; registrations of the six removed types, of an invented `kanhe.` type, and of a version the protocol does not define, refused; the state and the log under a checkpoint |
| `protocol-v0.10.json` | versions (v0.10): a chain of three versions across two record types, a revoked version superseded, a version endorsed and revoked after it was superseded, and a version registered by the organization over a delegated one; refused: a record superseded twice, an unknown record, a mechanism type on either side, a scope that does not cover the old type; the state, whose leaves list the superseding registration in both histories, and the log under a checkpoint |
| `protocol-v0.11.json` | time-stamp tokens (v0.11): RFC 3161 tokens by OpenSSL's responder over the checkpoints of `protocol-v0.10.json`, one per hash, each with its imprint, time, accuracy, and authority, under a root and authority certificate made by Python's `cryptography` |
| `protocol-v0.13.json` | open witness networks (v0.13, section 10.2): the SHA-256 checkpoint of `protocol-v0.10.json` as a checkpoint note under its origin, signed with a note key, an add-checkpoint body, network witnesses' cosignatures of the Ed25519 and ML-DSA-44 kinds (valid, and over another size or time), an anchor carrying them, and signed-note's own example, all from c2sp.org's texts with Python's `cryptography` |
| `protocol-v0.14.json` | claims (v0.14, sections 6 and 11): claim metadata, valid with its encoding and its condition in words (the specification's example among them), and refused, each for the one rule it breaks; an employer's ledger whose clerk and organization claim conditions on employment records: claims accepted on live records of a generic type, and refused on a record that does not exist, on another claim, on a revoked record, on a superseded one, with `as_of` after the registration, and with an unknown key; claims that take no endorsement or transition and are withdrawn by revoking them; sources revoked and replaced after the claims, with what a report states of each claim; the state, in which a claim's registration is in the claim's history only, and the log under a checkpoint |
| `protocol-v0.15.json` | asking about a condition (v0.15, section 12): access request metadata of both forms, with their encodings, and refused metadata, each for the one rule it breaks; claims checked as answers to requests, accepted, or refused for the one rule of acceptance (items 3 and 4) they break, values equal as numbers or amounts but encoded otherwise among the refused |
| `protocol-v0.16.json` | trust nodes (v0.16, sections 6 and 11): membership metadata with its encodings, and refused metadata, each for the one rule it breaks; where a membership stood at given times, from its registration, transitions, revocation, and `until`; replay of a trust node's log, with the ledger's refusals; evidence bundles carrying membership proofs, verified with their reports, or refused for the one rule of step 9 they break |
| `vm-v1.json` | contract execution (section 14): modules in and out of the profile, invocations with their outputs, traps, and fuel, and random integer programs, all from an independent reference interpreter (`tools/testvectors/wasm_ref.py`) |
| `evidence-v1.json` | conformance (sections 11 and 15): record evidence and contract evidence forged from this specification independently of both verifiers, each with the options to verify it with, the verdict this specification decides (a failure names the section and step that decide it), and facts its report must show. A verifier passes it: `tests/verifiers/conformance.py` runs `kanhe verify` and `contract verify` on every case, and the Python verifier (`verifiers/python`) its own command line |
| `bo-v1.json` | the Bo language ([`bo.md`](bo.md), section 18): contracts' sources in each language, their interfaces and bo-source bundles, the code `kanhe-bo` builds and its bounds (informative), calls with their outcomes (normative; answers to requests among them, with input key 9, and accepts with key 7), and sources that must not build with their errors' codes |

Revision v0.9 retired `protocol-v0.5.json` (native assets), and regenerated `protocol-v0.1.json`, `protocol-v0.2.json`, and `protocol-v0.4.json` with the user type `example.document/1` in place of the removed built-in types; nothing else in them changed.

`tools/testvectors/generate.py` regenerates them with Python's `cryptography` and `cbor2`, and OpenSSL, independently of the C++ code; `tools/testvectors/bo_vectors.py` writes `bo-v1.json` from the Bo compiler's runs and checks each on the reference interpreter. `test-contracts.json` is not part of the protocol: it holds contracts for tests of the reference server (a contract that decides by how many consents a call cites, and the splitting contract of `protocol-v0.7.json`), from `tools/testvectors/test_contracts.py`, which also assembles the requesting contract of `protocol-v0.8.json`.
