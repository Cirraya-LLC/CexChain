# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Verifying an evidence bundle (spec section 11): a record's, or an
instance's (section 15), whose calls the replay runs again.

verify_bundle follows the verifier's steps of section 11 in order:

1. the ledger's identity, hash, and first keys from the genesis entry;
2. every receipt's inclusion proof against the checkpoint;
3. a replay of the included statements under the ledger rules;
4. the checkpoint's and the receipts' signatures with the log key in effect;
5. disclosed fields and attachment contents;
6. witness cosignatures, counted with the open-network witnesses' of step 8;
7. completeness against the state commitment the checkpoint ends with;
8. anchors: time-stamp tokens over checkpoints, and the clock rule; and
   open-network witnesses' cosignatures of checkpoint notes (section 10.2).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import contracts, cose, crypto, merkle, network, protocol, rules, statetree, timestamps
from .errors import VerifyError
from .protocol import AGENT


@dataclass
class TokenReport:
    checkpoint_size: int
    info: timestamps.TokenInfo


@dataclass
class NetworkCosignature:
    """An open-network witness's cosignature of an anchor's checkpoint note
    (section 10.2): who, the size it cosigned, and its time T, which is
    reported and relied on for nothing."""
    witness: str
    size: int
    time: int  # POSIX seconds, the witness's own clock
    trusted: bool


@dataclass
class Report:
    ledger: rules.Ledger
    id_checked: bool
    checkpoint: protocol.TreeHead
    log_key: crypto.PublicKey
    record: rules.Record | None  # the subject: a record, or
    instance: contracts.Instance | None  # an instance
    events: list  # [rules.Applied], in log order
    disclosed: list  # [(name, value)]
    attachments: list  # [(name, media type, size, status)]
    witnesses_trusted: int
    witnesses_untrusted: int
    tokens: list  # [TokenReport]
    trusted_authorities: int
    existed_by: dict  # log index -> ms
    complete: bool
    commitment: protocol.TreeHead | None
    commitment_index: int | None
    entries: int = 0
    notes: list = field(default_factory=list)
    network: list = field(default_factory=list)  # [NetworkCosignature], in the bundle's order


def fail(message: str):
    raise VerifyError(message)


def verify_bundle(data: bytes, *, ledger_id: bytes | None = None, witnesses: list | None = None,
                  tsa_roots_pem: bytes = b"", attachments: dict | None = None,
                  network_witnesses: list | None = None) -> Report:
    """Verifies an evidence bundle. Raises VerifyError if it does not
    verify; returns the report otherwise.

    witnesses: trusted witness public keys (crypto.PublicKey);
    tsa_roots_pem: trusted time-stamp authority roots, PEM;
    attachments: attachment contents by name;
    network_witnesses: trusted open-network witnesses' verifier keys
    (network.VerifierKey).
    """
    bundle = protocol.parse_bundle(data)
    checkpoint = protocol.parse_tree_head(bundle.checkpoint, cose.CHECKPOINT_TYPE, "the checkpoint")
    size = checkpoint.tree_size

    # Entries and receipts, strictly ascending from index 0 (step 2).
    entries = []
    previous = -1
    for encoded, encoded_receipt in bundle.entries:
        entry = protocol.parse_log_entry(encoded)
        receipt = cose.parse_receipt(encoded_receipt)
        if receipt.tree_size != size:
            fail("a receipt is not against the bundle's checkpoint (its tree size differs)")
        if receipt.leaf_index <= previous or (previous < 0 and receipt.leaf_index != 0):
            fail("the bundle's entries are not strictly ascending from index 0")
        previous = receipt.leaf_index
        entries.append((receipt.leaf_index, entry, receipt))

    # Step 1: the ledger from its genesis entry.
    ledger = rules.Ledger(entries[0][1], entries[0][0])
    h = ledger.h
    if ledger_id is not None and ledger_id != ledger.id:
        fail("the bundle comes from a different ledger")
    if checkpoint.ledger_id != ledger.id:
        fail("the checkpoint is for another ledger")
    if checkpoint.hash != ledger.hash_alg:
        fail("the checkpoint's tree hash is not the ledger's")

    # Step 2: inclusion of every entry in the checkpointed tree.
    for index, entry, receipt in entries:
        if receipt.vds != protocol.VDS[ledger.hash_alg]:
            fail("a receipt's verifiable data structure is not the ledger's tree")
        leaf = merkle.leaf_hash(h, entry.encoded)
        if not merkle.verify_inclusion(h, index, size, leaf, receipt.path, checkpoint.root):
            fail("an entry is not proven to be in the checkpointed log")

    # Step 3: replay, at the registration times, which follows the
    # organization's key rotations.
    last_time = None
    for index, entry, _ in entries:
        if last_time is not None and entry.registered_at < last_time:
            fail("registration times go back in the log")
        last_time = entry.registered_at
        if index == 0:
            continue
        if entry.commitment is not None:
            ledger.apply_commitment(entry, index)
        else:
            ledger.apply(entry, index)

    # Step 4: the checkpoint and every receipt, under the log key in effect
    # at the checkpoint's size. (State commitments were checked under the key
    # in effect at their index during replay.)
    log_key = ledger.log_key_for_size(size)
    ledger.check_signed_head(checkpoint, log_key, "the checkpoint")
    for index, entry, receipt in entries:
        if receipt.alg != log_key.alg or receipt.kid != log_key.kid(h):
            fail("a receipt is not signed by the log key in effect")
        if not crypto.verify_signature(log_key, receipt.to_be_signed(checkpoint.root), receipt.signature):
            fail("a receipt's signature does not verify")

    record = ledger.records.get(bundle.subject)
    instance = ledger.instances.get(bundle.subject) if record is None else None
    if record is None and instance is None:
        fail("the bundle does not hold the registration of its record, or the creation of its instance")

    # Step 5: disclosed fields and attachment contents.
    if instance is not None and (bundle.disclosures or bundle.openings):
        fail("an instance's bundle discloses no fields and opens no attachments")
    disclosed = _check_disclosures(h, record, bundle.disclosures) if record is not None else []
    attachment_report = (_check_attachments(h, record, bundle.openings, attachments or {})
                         if record is not None else [])

    # Step 6: cosignatures, by witnesses it trusts, each witness once (the
    # open-network witnesses' are counted with them after step 8).
    trusted, untrusted = _count_cosignatures(h, checkpoint, bundle.cosignatures, witnesses or [])

    # Step 7: completeness.
    included = {index: entry for index, entry, _ in entries}
    subject = record if record is not None else instance
    complete, commitment = _check_completeness(ledger, subject, size, included, bundle.proofs)

    # Step 8: anchors.
    tokens, authorities, existed_by, cosigned = _check_anchors(ledger, checkpoint, included, bundle.anchors,
                                                               tsa_roots_pem, network_witnesses or [])
    trusted |= {("network",) + w for w, n in cosigned if n.trusted}
    untrusted |= {("network",) + w for w, n in cosigned if not n.trusted}

    events = [ledger.applied[i] for i in event_indices(ledger, subject)]
    return Report(
        ledger=ledger, id_checked=ledger_id is not None, checkpoint=checkpoint, log_key=log_key,
        record=record, instance=instance, events=events, disclosed=disclosed, attachments=attachment_report,
        witnesses_trusted=len(trusted), witnesses_untrusted=len(untrusted), tokens=tokens,
        trusted_authorities=authorities, existed_by=existed_by, complete=complete,
        commitment=commitment, commitment_index=size - 1 if commitment is not None else None,
        entries=len(entries), network=[n for _, n in cosigned])


def _check_disclosures(h, record: rules.Record, disclosures: list) -> list:
    """Section 6: each disclosed leaf against the field root and count; no
    leaf twice; names ascending with their indices."""
    seen = set()
    ordered = []
    for d in sorted(disclosures, key=lambda d: d.index):
        if d.index in seen:
            fail("the bundle discloses one field twice")
        seen.add(d.index)
        if d.index >= record.field_count:
            fail("a disclosed field's index is beyond the record's field count")
        name, _salt, value = protocol.parse_field_leaf(d.leaf)
        if not merkle.verify_inclusion(h, d.index, record.field_count, merkle.leaf_hash(h, d.leaf), d.path,
                                       record.field_root):
            fail(f"the disclosed field {name!r} does not match the record's commitment")
        ordered.append((name, value))
    names = [name.encode("utf-8") for name, _ in ordered]
    if any(a >= b for a, b in zip(names, names[1:])):
        fail("disclosed fields' names do not ascend with their indices")
    return ordered


def _check_attachments(h, record: rules.Record, openings: list, contents: dict) -> list:
    """Attachment contents provided beside the bundle, against the record's
    commitments HASH(salt || content)."""
    names = {a[0] for a in record.attachments}
    salts = {}
    for name, salt in openings:
        if name not in names:
            fail(f"the bundle opens an attachment the record does not have ({name!r})")
        if name in salts:
            fail(f"the bundle opens the attachment {name!r} twice")
        salts[name] = salt
    out = []
    for name, media_type, size, commitment in record.attachments:
        if name in salts and name in contents:
            content = contents[name]
            ok = len(content) == size and h(salts[name] + content) == commitment
            status = "verified" if ok else "mismatch"
        else:
            status = "not-provided"
        out.append((name, media_type, size, status))
    return out


def _count_cosignatures(h, checkpoint: protocol.TreeHead, cosignatures: list, witnesses: list):
    """The witnesses (by kid) whose cosignatures the bundle carries: those
    it trusts, each of whose cosignatures verifies, and the others."""
    by_kid = {key.kid(h): key for key in witnesses}
    trusted, untrusted = set(), set()
    for encoded in cosignatures:
        sign1 = cose.parse_sign1(encoded, cose.COSIGNATURE_TYPE, "a cosignature")
        if sign1.payload != checkpoint.sign1.payload:
            fail("a cosignature is not over the bundle's checkpoint")
        key = by_kid.get(sign1.kid)
        if key is None:
            untrusted.add(sign1.kid)
            continue
        if sign1.alg != key.alg or not crypto.verify_signature(key, sign1.to_be_signed(), sign1.signature):
            fail("a cosignature by a trusted witness does not verify")
        trusted.add(sign1.kid)
    return trusted, untrusted


def event_indices(ledger: rules.Ledger, subject) -> list:
    """The log indices of a record's events, or of an instance's calls with,
    for a child, its ancestors' calls up to each one that created the next
    generation (section 15), in log order."""
    if isinstance(subject, rules.Record):
        return list(subject.history)
    events = set(subject.history)
    node = subject
    while node.parent is not None:
        parent = ledger.instances[node.parent]
        events |= {i for i in parent.history if i <= node.created_by}
        node = parent
    return sorted(events)


def involved_objects(ledger: rules.Ledger, subject) -> dict:
    """Section 11, step 7: the record, or the instance and its contract, and
    for each of its events the signer, an agent signer's responsible person,
    and every delegation in the chain with its grantor. A child's ancestors
    need no proof, but their included calls count as events. Returns {id:
    state kind}."""
    if isinstance(subject, rules.Record):
        involved = {subject.id: statetree.RECORD}
    else:
        involved = {subject.id: statetree.INSTANCE, subject.contract: statetree.CONTRACT}
    for index in event_indices(ledger, subject):
        applied = ledger.applied[index]
        signer = ledger.actors[applied.signer]
        involved[signer.id] = statetree.ACTOR
        if signer.kind == AGENT and signer.responsible is not None:
            involved[signer.responsible] = statetree.ACTOR
        for delegation_id in applied.chain:
            involved[delegation_id] = statetree.DELEGATION
            involved[ledger.delegations[delegation_id].grantor] = statetree.ACTOR
    return involved


def _check_completeness(ledger: rules.Ledger, subject, size: int, included: dict, proofs: list):
    last = included.get(size - 1)
    commitment = ledger.commitments.get(size - 1) if last is not None and last.commitment is not None else None
    if commitment is None:
        # Without the commitment the checkpoint ends with, a bundle cannot
        # rule out omissions: it verifies, and is not complete. State proofs
        # could not be verified against any root, so they are refused.
        if proofs:
            fail("state proofs need the state commitment the checkpoint ends with")
        return False, None
    h = ledger.h
    by_id = {}
    for proof in proofs:
        if proof.id in by_id:
            fail("the bundle holds two state proofs for one object")
        if statetree.root_from_proof(h, proof.leaf, proof.siblings) != commitment.root:
            fail("a state proof does not lead to the state commitment")
        by_id[proof.id] = proof
    for object_id, kind in involved_objects(ledger, subject).items():
        proof = by_id.get(object_id)
        expected = ledger.leaf(object_id)
        if proof is None:
            fail(f"the bundle holds no state proof for an involved {statetree.KIND_NAMES[kind]} "
                 f"({object_id.hex()[:12]})")
        if proof.leaf != expected:
            fail(f"the history of an involved {statetree.KIND_NAMES[kind]} ({object_id.hex()[:12]}) "
                 "differs from the state commitment: the bundle leaves part of it out")
    return True, commitment


def _check_anchors(ledger: rules.Ledger, checkpoint: protocol.TreeHead, included: dict, anchors: list,
                   roots_pem: bytes, network_witnesses: list):
    h = ledger.h
    size = checkpoint.tree_size
    reports, authorities, existed_by, cosigned = [], set(), {}, []
    for anchor in anchors:
        head = protocol.parse_tree_head(anchor.checkpoint, cose.CHECKPOINT_TYPE, "an anchor's checkpoint")
        if head.ledger_id != ledger.id or head.hash != ledger.hash_alg:
            fail("an anchor's checkpoint is of another ledger")
        if head.tree_size > size:
            fail("an anchor's checkpoint is larger than the bundle's")
        ledger.check_signed_head(head, ledger.log_key_for_size(head.tree_size), "an anchor's checkpoint")
        if head.tree_size == size:
            if anchor.consistency is not None or head.root != checkpoint.root:
                fail("an anchor's checkpoint of the bundle's size is not the bundle's checkpoint")
        elif anchor.consistency is None or not merkle.verify_consistency(
                h, head.tree_size, size, head.root, checkpoint.root, anchor.consistency):
            fail("an anchor's checkpoint is not proven consistent with the bundle's")
        cosigned += _check_network(ledger, head, anchor.cosignatures, network_witnesses)
        imprint = h(head.sign1.payload)
        for token in anchor.tokens:
            info = timestamps.check_token(token, imprint, ledger.hash_alg, roots_pem)
            reports.append(TokenReport(checkpoint_size=head.tree_size, info=info))
            if not info.trusted:
                continue
            # The clock rule (section 10.1).
            bound = info.time_ms + info.accuracy_ms + timestamps.CLOCK_ALLOWANCE_MS
            if head.timestamp > bound:
                fail("the ledger dated a checkpoint later than a trusted time-stamp authority saw it")
            for index, entry in included.items():
                if index < head.tree_size and entry.registered_at > bound:
                    fail("the ledger dated an entry later than a trusted time-stamp authority saw it")
            authorities.add(info.authority_id)
            seen = info.time_ms + info.accuracy_ms
            for index in included:
                if index < head.tree_size and (index not in existed_by or seen < existed_by[index]):
                    existed_by[index] = seen
    return reports, len(authorities), existed_by, cosigned


def _check_network(ledger: rules.Ledger, head: protocol.TreeHead, cosignatures: list, trusted: list) -> list:
    """Section 11, step 8, for an anchor's open-network cosignatures
    (section 10.2): none in an SM3 ledger's bundle; one whose name and key ID
    are a trusted witness's must verify against the note of the anchor's
    checkpoint, and counts as that witness's; the others are counted, by
    name and key ID, and relied on for nothing. The time T of each is
    reported, and not put to the clock rule.

    Returns [(witness identity, NetworkCosignature)], in the anchor's order:
    a trusted witness is identified by its verifier key, another by its name
    and key ID."""
    if cosignatures and ledger.hash_alg != crypto.SHA256:
        fail("an SM3 ledger's anchor carries network cosignatures: only SHA-256 ledgers are witnessed so "
             "(section 10.2)")
    note_origin = network.origin(ledger.id)
    out = []
    for name, data in cosignatures:
        key_id = network.cosignature_key_id(data)
        keys = [k for k in trusted if k.name == name and k.key_id == key_id]
        report = NetworkCosignature(witness=name, size=head.tree_size, time=network.cosignature_time(data),
                                    trusted=bool(keys))
        if not keys:
            out.append(((name, key_id), report))
            continue
        # Two trusted keys could share a name and a 4-byte key ID: the
        # cosignature is that of the first one it verifies with.
        key = next((k for k in keys if network.verify_cosignature(k, note_origin, head.tree_size, head.root, data)),
                   None)
        if key is None:
            fail(f"a trusted network witness's cosignature does not verify against the note of the checkpoint of "
                 f"size {head.tree_size} ({name})")
        out.append(((key.name, key.key_id, key.kind, key.public.key), report))
    return out


__all__ = ["NetworkCosignature", "Report", "VerifyError", "event_indices", "involved_objects", "verify_bundle"]
