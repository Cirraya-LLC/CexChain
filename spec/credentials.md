# Kanhe credentials

Profile 1 (draft), for protocol revision v0.17 and later. It changes nothing in the protocol: no
statement, ledger rule, or evidence format is new.

A record can be handed over as a **W3C Verifiable Credential**, so that a digital wallet can hold
it and any verifier that knows the standards can check it. A verifier that also knows Kanhe checks
the record behind it: that it is on the issuer's witnessed ledger, live or revoked, with the same
fields, and that the key that signed the credential was the issuer's when it issued it.

This profile uses, without changing them:

- [Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/) (VCDM);
- [Securing Verifiable Credentials using JOSE and COSE](https://www.w3.org/TR/vc-jose-cose/):
  a credential is the payload of a compact JWS (RFC 7515), media type `application/vc+jwt`;
- [Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/) for revocation;
- [did:web](https://w3c-ccg.github.io/did-method-web/) to name the issuer, with a verification
  method of type `JsonWebKey` ([Controlled Identifiers v1.0](https://www.w3.org/TR/cid-1.0/));
- JSON Canonicalization (RFC 8785, JCS), JWK thumbprints (RFC 7638), GZIP (RFC 1952).

The key words MUST, MUST NOT, SHOULD, and MAY are used as in RFC 2119. Section numbers without a
document name are the protocol's ([README.md](README.md)).

## 1. The issuer and its base URL

An issuer serves its ledger at a **base URL**: `https`, a host name (not an IP address), an
optional port, and an optional path without a trailing `/`, such as `https://ledger.example.com`
or `https://example.com:8443/kanhe`. Everything this profile publishes lives under it.

The issuer's **DID** is the did:web of the base URL: `did:web:` followed by the host, with
`%3A` and the port if there is one, and each path segment preceded by `:`.
`https://ledger.example.com` is `did:web:ledger.example.com`; `https://example.com:8443/kanhe` is
`did:web:example.com%3A8443:kanhe`. Its DID document is then at
`https://ledger.example.com/.well-known/did.json`, or, with a path, `BASE/did.json` (did:web's
rule).

For testing, a base URL MAY be `http://localhost` or `http://127.0.0.1` with a port; its DID
names the host the same way. Verifiers MUST NOT fetch an `http` URL unless told to.

## 2. The credential key

A credential is signed with ECDSA P-256 and SHA-256 (`ES256`), which wallets accept, by a
**credential key**: a device actor of the issuer's ledger (section 3 of the protocol, `esp256`)
whose delegations cover `record-endorse` (type 17) and nothing else. A ledger may have several,
and a credential key may rotate its key like any actor.

The first time it issues a credential for a record, the credential key **endorses that record in
the role `credential/N/I`**, where N and I are the credential's status list and index (section 5),
in decimal without leading zeros. That statement is the ledger's witnessed account of the issue:
the record's evidence then holds it, and with it the credential key's registration, its key
rotations, and its delegation chain (section 11), so a verifier learns which key the issuer used,
since when, under whose authority, and which status entry is the record's, from the ledger and not
from the issuer's word. A credential key endorses a record so at most once: issued again, the
credential keeps that entry. A revoked record takes no endorsement,
so no credential is issued for it. A mechanism type takes none either (section 6): claims,
memberships, and the other `kanhe.` types are not issued as credentials.

**The key as a JWK** is `{"kty":"EC","crv":"P-256","x":X,"y":Y}`, X and Y the point's
coordinates (32 bytes each, from the SEC 1 key of section 3) in unpadded base64url. Its
**thumbprint** is the unpadded base64url of the SHA-256 of
`{"crv":"P-256","kty":"EC","x":X,"y":Y}` (RFC 7638: those members, in that order, no spaces).

## 3. The DID document

`GET BASE/.well-known/did.json` (and `GET BASE/did.json`) answers the issuer's DID document, JSON,
`Content-Type: application/did+json`, `Access-Control-Allow-Origin: *`:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://www.w3.org/ns/cid/v1"],
  "id": "did:web:ledger.example.com",
  "verificationMethod": [{
    "id": "did:web:ledger.example.com#THUMBPRINT",
    "type": "JsonWebKey",
    "controller": "did:web:ledger.example.com",
    "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": "...", "y": "...", "alg": "ES256"}
  }],
  "assertionMethod": ["did:web:ledger.example.com#THUMBPRINT"],
  "service": [{
    "id": "did:web:ledger.example.com#kanhe",
    "type": "KanheLedger",
    "serviceEndpoint": "https://ledger.example.com",
    "ledger": "LEDGER ID IN HEX"
  }]
}
```

The verification methods are every key, current or earlier, of every unrevoked credential key the
issuer serves with, each once, ordered by thumbprint; `assertionMethod` lists them in the same
order. Earlier keys stay so that credentials signed before a rotation keep verifying; revoking the
credential key (the actor) removes all of its keys. The service names the ledger: a Kanhe
verifier checks that it is the ledger the credential's evidence names (section 7). The document is
serialized with JCS (section 4); a verifier MUST NOT rely on that.

## 4. The credential

A credential is about one record of the issuer's ledger that is **published** (section 16 of the
protocol: `/c/TOKEN`), and holds, as claims about its subject, the fields that address discloses
and, if the issuer chooses, entries of the record's public metadata: on a certificate, the fields
printed on it. Nothing else of the record goes into it.

Its JSON, before signing:

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential"],
  "name": "Diploma in Nursing",
  "issuer": {"id": "did:web:ledger.example.com", "name": "Example College"},
  "validFrom": "2026-07-01T08:00:00.000Z",
  "credentialSubject": {"name": "Chan Siu Ming", "programme": "Nursing", "year": 2026},
  "credentialStatus": {
    "id": "https://ledger.example.com/status/1#94567",
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "94567",
    "statusListCredential": "https://ledger.example.com/status/1"
  },
  "evidence": [{
    "id": "https://ledger.example.com/c/TOKEN",
    "type": ["KanheEvidence"],
    "ledger": "LEDGER ID IN HEX",
    "record": "RECORD ID IN HEX"
  }]
}
```

- `name` is optional: 1 to 256 bytes of the issuer's choosing (a certificate's kind).
- `issuer.name` is the organization's name from the ledger's genesis (section 4 of the protocol).
- `validFrom` is the record's registration time, by its log entry (section 8), as RFC 3339 in UTC
  with milliseconds: `YYYY-MM-DDTHH:MM:SS.sssZ`.
- `credentialSubject` holds 1 to 64 members, one per field: the field's name, and its value as
  JSON: a text value as a string, an integer of at most 2^53 - 1 in magnitude as a number, `true`
  and `false` as themselves. A field of any other value cannot go into a credential, nor a field
  named `id` or `type`, or whose name begins with `@`. A metadata entry is the same, by its key.
  Two members never share a name, so a field and a metadata entry of the same name cannot both go
  in.
- `credentialStatus`: list `N` (1 or more, in decimal) and index `I` (section 5), with `id`
  `BASE/status/N#I`.
- `evidence` names the record: `id` its published address, `ledger` and `record` their ids in
  lowercase hex.
- Ids, the published token, and URLs are as the issuer's server gives them; `BASE` is the base URL.

**Bytes.** The payload is the JSON's JCS serialization (RFC 8785): members sorted by their names'
UTF-16 code units, no insignificant whitespace, strings with the shortest escapes (`\"`, `\\`,
`\b`, `\f`, `\n`, `\r`, `\t`, other characters below U+0020 as `\u00xx` in lowercase hex, every
other character as itself in UTF-8), integers in decimal. A Kanhe verifier refuses a credential
whose payload is not the JCS of the JSON it parses (so a payload with a repeated member name never
verifies).

**The JWS.** The protected header is the JCS of
`{"alg":"ES256","cty":"vc","kid":KID,"typ":"vc+jwt"}`, with `KID` the issuer's DID, `#`, and the
credential key's thumbprint. The credential is the compact serialization: the unpadded base64url
of the header, `.`, of the payload, `.`, and of the 64-byte signature `r || s` (section 3 of the
protocol; JWS's own form for ES256) over the ASCII of the first two parts and the `.` between
them.

A record has one credential per credential key: issued again, it keeps its status list entry (its
endorsement), and is signed with the credential key's current key.

## 5. The status list

Each credential has an entry in a status list: list `N` (1 or more), index `I` in [0, 131072),
named by its endorsement (section 2). An issuer SHOULD choose `I` at random among the indices of its
current list that no endorsement names (so that indices say nothing of the order of issue), and
start list `N + 1` when one is full.

**A list is a function of the ledger.** Its bit `I` is 1 if a record endorsed in the role
`credential/N/I` is **revoked or replaced** (section 6 of the protocol: revoked, or superseded by
a newer version), and 0 otherwise; indices no endorsement names are 0. (Should two records name one
entry, which an issuer avoids, the bit is 1 if either is revoked or replaced.) So anyone holding
the ledger can recompute every list, and a Kanhe verifier checks one credential's bit against its
record's evidence. Bit `I` is bit
`7 - I mod 8` of byte `I div 8` (index 0 is the most significant bit of the first byte), and the
bitstring is 16,384 bytes. Its `encodedList` is `u` followed by the unpadded base64url of the
bitstring's GZIP (RFC 1952). Any GZIP encoding is valid; a verifier MUST decompress any, and
refuse one that does not decompress to exactly 16,384 bytes.

`GET BASE/status/N` answers the status list credential: a JWS as in section 4, with
`Content-Type: application/vc+jwt`, `Access-Control-Allow-Origin: *`, `Cache-Control: no-store`,
whose payload is the JCS of

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential", "BitstringStatusListCredential"],
  "id": "https://ledger.example.com/status/1",
  "issuer": {"id": "did:web:ledger.example.com", "name": "Example College"},
  "validFrom": "2026-11-13T08:00:00.000Z",
  "credentialSubject": {
    "id": "https://ledger.example.com/status/1#list",
    "type": "BitstringStatusList",
    "statusPurpose": "revocation",
    "encodedList": "uH4sI..."
  }
}
```

`validFrom` is when the list was made, from the ledger's state then. An issuer serves the list as
its ledger is when asked, so a revocation shows at once. 404 for a list no endorsement names.

## 6. Issuing

Whoever holds a credential key and can submit statements to the ledger issues credentials; the
server needs none of this, only the key to sign its status lists (section 8). To issue a
credential for a published record, an issuer:

1. takes the record's evidence from its published address, as anyone holding the address would,
   and verifies it: the record is of its ledger, of a type that is not a mechanism type, and
   neither revoked nor replaced;
2. picks the fields: every field the address discloses, and the public metadata entries asked for;
   checks them against section 4;
3. if the credential key endorsed the record in a role `credential/N/I` already, keeps N and I;
   otherwise chooses them (section 5) and registers that endorsement, signed by the credential key
   under its delegation;
4. builds the payload and signs it with the credential key's current key.

So the credential says exactly what the evidence says, and the issuer keeps nothing beside the
ledger.

## 7. Verifying a credential

A **standard verifier** checks a credential as the VCDM, VC-JOSE-COSE, and Bitstring Status List
specifications say: the JWS with the key the DID document names under `kid`, the data model, and
the status list entry.

A **Kanhe verifier** checks, in addition, the record behind it. Given the credential, the
record's evidence bundle (from `evidence[0].id`, or provided), and, when it has them, the issuer's
DID document and status list credential, it:

1. parses the JWS: three base64url parts, a header whose JCS is itself with `alg` `ES256`, `typ`
   `vc+jwt` and `cty` `vc` if present, and `kid` the issuer's DID, `#`, and a thumbprint; a
   payload that is the JCS of a JSON object with the members of section 4 (others are refused),
   `@context` and `type` as there, and one `evidence` entry of type `KanheEvidence`;
2. verifies the evidence bundle (section 11) for the ledger the `evidence` entry names: the
   bundle is about its `record`;
3. requires an endorsement of the record in the role `credential/N/I` by a device actor A, with
   N and I those of `credentialStatus` (whose URLs are `BASE/status/N` and `BASE/status/N#I` for
   the issuer's base URL), and the JWS to verify with A's key in effect at that endorsement, or
   with a key A rotated to after it (both in the bundle), whose thumbprint is the one `kid` names.
   If several actors endorsed it so, one of them suffices. A revoked since is reported (when);
4. requires `issuer.name` to be the ledger's organization name, `validFrom` the record's
   registration time, and each `credentialSubject` member to be a disclosed field of the bundle,
   or an entry of the record's public metadata, with the same name and value (section 4's JSON);
5. states the record's status from the bundle: **live**, **revoked** (when), or **replaced** (by
   which record, when), and whether the bundle is complete (section 11, step 7). A credential of a
   revoked or replaced record is reported as such, not as failing;
6. with a DID document: requires its `id` to be the issuer's DID, a verification method under
   `kid` whose JWK is A's key (the one the JWS verified with), and the Kanhe service's `ledger`
   to be the bundle's ledger;
7. with the status list credential: requires it to verify with a key of A (as in 3), its `id` to
   be the entry's `statusListCredential`, and its bit at the entry's index to be 1 exactly when
   the bundle shows the record revoked or replaced. A list that disagrees with the ledger is
   reported as such: the issuer's list says otherwise than its ledger.

It reports: the outcome of each check; the record, its type, its status; who endorsed it as a
credential (A's name and id) and when; the issuer as the genesis names it; the fields; and the
evidence's own report (section 11). A credential **verifies** when steps 1 to 4 hold, and 6 and 7
for what was given.

## 8. The HTTP routes

A server given a credential key and its base URL answers, openly (no token), each with
`Access-Control-Allow-Origin: *` and `Cache-Control: no-store`:

- `GET /.well-known/did.json`, `GET /did.json`: the DID document (section 3), whose keys are those
  of the server's credential key and of every credential key that endorsed a record in a role
  `credential/N/I`;
- `GET /status/{N}`: the status list credential (section 5), signed with the server's credential
  key, which must be unrevoked.

A server without one answers 404 to these, as to any unknown path. Nothing else is served:
issuing is an endorsement, submitted as any statement is (section 16 of the protocol).

## 9. Security and privacy

- **A bearer credential.** The subject is named by the printed fields only; there is no holder
  binding. Whoever holds the credential holds what the paper shows, and the published address in
  its evidence, which gives the record's evidence to anyone: keep it as private as the paper.
- **What leaves the issuer** is what the published address discloses already, and the metadata
  entries asked for. Sealed fields stay sealed.
- **Status indices** are random, so a list says nothing of when credentials were issued; whoever
  fetches a list learns only which indices are set. Fetching it tells the issuer that someone
  checks some credential of that list.
- **A compromised credential key** signs credentials a standard verifier accepts until the actor
  is revoked (and its keys leave the DID document). A Kanhe verifier is not fooled by its
  contents: every claim must match the evidence, and the endorsement records when the issuer
  issued a record's credential.
- **The status list can lie** to a standard verifier: an issuer could clear a revoked record's
  bit. A Kanhe verifier compares it with the ledger, where a revocation cannot be hidden from a
  complete bundle.
- **did:web trusts the domain.** Whoever controls the domain controls the DID document. The Kanhe
  service entry names the ledger, which a Kanhe verifier pins, so that a changed DID document
  cannot point at another ledger unseen.

## 10. Test vectors

[`../testvectors/credentials-v1.json`](../testvectors/credentials-v1.json), made with Python from
this text, apart from both verifiers (`tools/testvectors/credential_vectors.py`): JCS
serializations, and JSON that is not canonical; JWK thumbprints; base URLs and their did:web, and
URLs refused; endorsement roles naming status entries, and roles that do not; credentials built
from their content, payload and header byte for byte, each with a JWS that verifies (ECDSA
signatures are randomized, so an implementation reproduces the payload and header and checks the
signature); DID documents byte for byte; status lists compressed by another encoder, with the bits
they set, and encodedLists refused.

The verification of section 7 needs evidence, which ledgers make: the reference implementation's
tests make ledgers that issue, revoke, and forge credentials, and the independent Python verifier
([`../verifiers/python`](../verifiers/python), `python3 -m kanhe_verify credential`) must reach the
same verdict on each and state the same facts.
