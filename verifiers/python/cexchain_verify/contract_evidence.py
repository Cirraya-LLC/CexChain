# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Verifying an instance's contract evidence (spec section 15, "Contract
evidence"): the instance's evidence bundle, whose replay runs the contract
again on every call, and every consent bundle its calls cite.

verify_contract_evidence follows the verifier's steps of section 15:

1. the instance's bundle verifies for the expected home ledger (section 11)
   and is complete;
2. its replay, running the contract on each call, the ancestors' included,
   reaches the instance's state, status, parties, finality, and requests
   (rules.py and contracts.py);
3. each consent citation's bundle verifies, completely, for the cited ledger,
   is about the cited record, a live cexchain.contract-consent/1 record, and
   carries the call's terms, lapses no earlier than the call, and was signed
   as the citation claims;
4. no bundle goes unpinned, and no citation lacks its bundle.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import cbor, contracts, evidence, protocol, rules
from .errors import VerifyError

CONSENT_TYPE = "cexchain.contract-consent/1"
CONSENT_TERMS = {"ledger", "instance", "function", "arguments", "head", "until"}


def fail(message: str):
    raise VerifyError(message)


@dataclass
class Consent:
    """A consent a call cites, verified: its citation, its bundle's report,
    and its terms."""
    call: int  # the citing call's log index
    ref: protocol.ConsentRef
    report: evidence.Report
    terms: dict

    @property
    def registration(self) -> rules.Applied:
        return self.report.ledger.applied[self.report.record.history[0]]


@dataclass
class ContractReport:
    bundle: evidence.Report  # the instance's bundle
    instance: contracts.Instance
    contract: contracts.Contract
    calls: list  # [rules.Applied]: its calls, and a child's ancestors' included calls, in log order
    consents: dict  # call index -> [Consent], in the call's order
    names: dict  # ledger id -> organization name, as each ledger's genesis names it

    @property
    def ledger(self) -> rules.Ledger:
        return self.bundle.ledger

    def own_requests(self) -> list:
        return [self.ledger.requests[r] for r in self.instance.requests]

    def open_requests(self) -> list:
        return [r for r in self.own_requests() if r.status is None]

    def overdue(self, request: contracts.Request) -> bool:
        return request.status is None and self.bundle.checkpoint.timestamp >= request.deadline

    def deploy_file(self) -> bytes:
        """The deploy as a deploy file (spec/bo.md, section 16.5): the
        contract-deploy-body's keys, and 7, the home's hash."""
        c = self.contract
        out = {1: c.code, 2: c.interface, 3: c.language, 4: c.compiler, 7: self.ledger.hash_alg}
        if c.source is not None:
            out[5] = c.source
        if c.name is not None:
            out[6] = c.name
        return cbor.encode(out)


def verify_contract_evidence(data: bytes, *, ledger_id: bytes | None = None, witnesses: list | None = None,
                             tsa_roots_pem: bytes = b"", network_witnesses: list | None = None) -> ContractReport:
    """Verifies contract evidence. Raises VerifyError if it does not verify;
    returns the report otherwise. The witnesses, open-network witnesses, and
    time-stamp authorities it trusts are trusted on every ledger: the home's
    and each consenting party's."""
    instance_bundle, consent_bundles = protocol.parse_contract_evidence(data)

    # Steps 1 and 2: the instance's bundle, replayed.
    bundle = evidence.verify_bundle(instance_bundle, ledger_id=ledger_id, witnesses=witnesses,
                                    tsa_roots_pem=tsa_roots_pem, network_witnesses=network_witnesses)
    if bundle.instance is None:
        fail("the evidence's bundle is about a record, not an instance")
    if not bundle.complete:
        fail("an instance's evidence must be complete: its checkpoint does not end with a state commitment")
    ledger = bundle.ledger
    instance = bundle.instance

    # Steps 3 and 4: the consents.
    by_hash = {}
    for encoded in consent_bundles:
        digest = ledger.h(encoded)
        if digest in by_hash:
            fail("the evidence holds one consent bundle twice")
        by_hash[digest] = encoded
    pinned, consents = set(), {}
    names = {ledger.id: ledger.name}
    for applied in bundle.events:
        f = applied.statement.fields
        checked = []
        for ref in f["consents"]:
            encoded = by_hash.get(ref.bundle)
            if encoded is None:
                fail(f"the call at {applied.index} cites a consent whose bundle the evidence does not hold")
            pinned.add(ref.bundle)
            consent = _check_consent(ledger, applied, ref, encoded, witnesses, tsa_roots_pem, network_witnesses)
            names[ref.ledger] = consent.report.ledger.name
            checked.append(consent)
        consents[applied.index] = checked
    if set(by_hash) - pinned:
        fail("the evidence holds a consent bundle that no call cites")
    return ContractReport(bundle=bundle, instance=instance, contract=ledger.contracts[instance.contract],
                          calls=bundle.events, consents=consents, names=names)


def _check_consent(home: rules.Ledger, applied: rules.Applied, ref: protocol.ConsentRef, encoded: bytes,
                   witnesses, tsa_roots_pem: bytes, network_witnesses) -> Consent:
    """Section 15, step 3, for one citation."""
    what = f"the consent of {ref.ledger.hex()[:12]} to the call at {applied.index}"
    try:
        report = evidence.verify_bundle(encoded, ledger_id=ref.ledger, witnesses=witnesses,
                                        tsa_roots_pem=tsa_roots_pem, network_witnesses=network_witnesses)
    except VerifyError as e:
        fail(f"{what} does not verify: {e}")
    if not report.complete:
        fail(f"{what} is not complete")
    record = report.record
    if record is None or record.id != ref.record:
        fail(f"{what} is not about the record the call cites")
    if record.type != CONSENT_TYPE:
        fail(f"{what} is not a {CONSENT_TYPE} record")
    if record.revoked or record.state != "given":
        fail(f"{what} is {'revoked' if record.revoked else record.state}, not given")
    terms = record.metadata or {}
    if not (CONSENT_TERMS <= set(terms) <= CONSENT_TERMS | {"reference"}):
        fail(f"{what} does not name exactly the terms of a consent")
    f = applied.statement.fields
    expected = {"ledger": home.id, "instance": f["instance"], "function": f["function"],
                "arguments": home.h(cbor.encode(f["arguments"])), "head": f["head"]}
    if any(terms[k] != v or type(terms[k]) is not type(v) for k, v in expected.items()):
        fail(f"{what} carries other terms than the call's")
    until = terms["until"]
    if not (isinstance(until, int) and not isinstance(until, bool) and until > 0):
        fail(f"{what} names no time it lapses")
    if until < applied.registered_at:
        fail(f"{what} lapsed before the call was registered")
    if "reference" in terms and not (isinstance(terms["reference"], str)
                                     and 1 <= len(terms["reference"].encode("utf-8")) <= 1024):
        fail(f"{what} has a reference that is not 1 to 1,024 bytes of text")
    consent = Consent(call=applied.index, ref=ref, report=report, terms=terms)
    if contracts.applied_signer(report.ledger, consent.registration) != ref.signer:
        fail(f"{what} was not signed as the call claims")
    return consent


__all__ = ["Consent", "ContractReport", "verify_contract_evidence"]
