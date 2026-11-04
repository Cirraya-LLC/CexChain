# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Probes of the contract rules' edges (spec sections 14 and 15): home and
party ledgers forged here, each with one unusual call, consent, or piece of
evidence, verified by both verifiers (`contract verify`, or `verify` for a
bundle alone).

The home runs the oracle contract of protocol-v0.6.json, whose byte-string
arguments are its output, so a probe writes the contract's output itself.
Consents come from a party ledger forged the same way, whose clock runs a
day behind the home's.

A probe either has an expected verdict, which the specification decides
(both verifiers must reach it and, when both verify, report the same), or
is open: the specification does not say, and the probe records what each
verifier does.

Usage: python3 contract_probes.py CEXCHAIN
Exit status 1 if a decided probe fails in either verifier.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from cexchain_verify import cbor, crypto, merkle  # noqa: E402
from compare_reports import compare  # noqa: E402
from probes import DAY, MINUTE, T0, Forge, _key, passkey, webauthn  # noqa: E402

ORACLE = bytes.fromhex(json.loads((HERE.parents[2] / "testvectors" / "protocol-v0.6.json").read_text())["contract"])
CONSENT = "cexchain.contract-consent/1"
LIMIT = 31_622_400_000  # a request is due at most 366 days after its call


def accept(state=0, **keys) -> list:
    """[1, accept]: state 1, and status 2, parties 3, events 4, final 5,
    children 6, requests 7 by name."""
    names = {"status": 2, "parties": 3, "events": 4, "final": 5, "children": 6, "requests": 7}
    return [1, {1: state, **{names[k]: v for k, v in keys.items()}}]


def ask(due: int, n: int = 1, reply: str = "act", params=None) -> list:
    """`n` requests due at `due`."""
    return [{1: "notify", 2: params, 3: due, 4: reply}] * n


class Home(Forge):
    """A home ledger with the oracle contract deployed (`contract`). Calls
    record their children, and each instance's head."""

    def __init__(self, interface=None, code: bytes = ORACLE, extra=None):
        super().__init__(name="Probe Home")
        self.heads, self.children = {}, {}
        body = {1: code, 2: interface or {"open": 1, "act": 2}, 3: "wasm", 4: "probe 1", **(extra or {})}
        self.contract = self.add(21, "root", self.ledger_id, body, creates=4)

    def _call(self, body, target, signer, actor, delegation, children, **options) -> bytes:
        sid = self.add(22, signer, actor or self.ledger_id, body, delegation, creates=None if target else 5,
                       touches=[target] if target else (), **options)
        index = len(self.entries) - 1
        self.heads[target or sid] = index
        self.children[sid] = []
        for position in range(children):
            child = self.h(cbor.encode([sid, position]))
            self.leaves[child] = [5, child, [index]]
            self.heads[child] = index
            self.children[sid].append(child)
        return sid

    def create(self, output=None, children: int = 0, contract=None, consents=None, signer="root", actor=None,
               delegation=None) -> bytes:
        body = {1: contract or self.contract, 3: "open", 4: cbor.encode(output or accept())}
        if consents:
            body[6] = consents
        return self._call(body, None, signer, actor, delegation, children)

    def call(self, instance, output=None, children: int = 0, consents=None, answer=None, args=None, head=None,
             signer="root", actor=None, delegation=None, function="act") -> bytes:
        body = {2: instance, 3: function, 4: cbor.encode(output or accept()) if args is None else args,
                5: self.heads[instance] if head is None else head}
        if consents:
            body[6] = sorted(consents, key=lambda c: c[0])
        if answer is not None:
            body[8] = answer
        return self._call(body, instance, signer, actor, delegation, children)

    def request(self, call: bytes, position: int = 0) -> bytes:
        return self.h(cbor.encode(["request", call, position]))

    def evidence(self, instance: bytes, consents=(), mutate=None) -> bytes:
        out = {0: 1, 1: self.bundle(instance)}
        if consents:
            out[2] = list(consents)
        if mutate is not None:
            mutate(out)
        return cbor.encode(out)


class Party(Forge):
    """Another organization's ledger, whose clock runs a day behind the
    home's, so its consents come before the home's calls."""

    def __init__(self, hash_alg: int = crypto.SHA256):
        super().__init__(hash_alg, name="Probe Party", t0=T0 - DAY)

    def consent(self, home: Home, instance: bytes, output=None, head=None, until=None, kind=CONSENT, terms=None,
                arguments_hash=None, signer="root", actor=None, delegation=None, presence=None,
                provenance=None) -> bytes:
        """Registers a consent to the home's next call on `instance` with
        `output` as its arguments; `terms` replaces terms (None drops one)."""
        metadata = {"ledger": home.ledger_id, "instance": instance, "function": "act",
                    "arguments": (arguments_hash or home.h)(cbor.encode(cbor.encode(output or accept()))),
                    "head": home.heads.get(instance, 0) if head is None else head,
                    "until": T0 + 30 * DAY if until is None else until}
        metadata.update(terms or {})
        metadata = {k: v for k, v in metadata.items() if v is not None}
        leaf = cbor.encode(["note", bytes([0x5A]) * 16, "consent"])
        body = {1: kind, 2: merkle.tree_hash(self.h, [leaf]), 3: 1, 5: metadata}
        return self.add(16, signer, actor or self.ledger_id, body, delegation, creates=3, presence=presence,
                        provenance=provenance)

    def cite(self, home: Home, record: bytes, signer=None, bundle=None) -> tuple[list, bytes]:
        """The citation [ledger, record, HASH(bundle), signer], and the bundle."""
        bundle = self.bundle(record) if bundle is None else bundle
        return [self.ledger_id, record, home.h(bundle), signer or {1: 0}], bundle


def hardware_proof(forge, signer, payload) -> dict:
    challenge = forge.h(b"CexChain presence v1" + forge.kid(signer) + cbor.encode(payload))
    return {1: b"ukey", 4: _key("ukey").sign(challenge)}


# ---------------------------------------------------------------------------
# The probes: (name, expected verdict or None if the spec is open, build,
# verify options, "contract" or "bundle")
# ---------------------------------------------------------------------------

def consented(kind: int = 0, presence=None, claimed=None, until=None, terms=None, record_type=CONSENT,
              party_hash=crypto.SHA256, arguments_hash=None, edit=None, party_ahead=None):
    """An instance whose one call cites a consent, given by the party's
    organization (kind 0) or by an actor of `kind`, with proof of presence
    by passkey (`presence` its flags) or hardware key ("hardware");
    `until` is relative to the call's registration time."""
    def build():
        home, party = Home(), Party(party_hash)
        instance = home.create(accept(status="proposed"))
        signer, actor, delegation, provenance = "root", None, None, None
        if kind:
            extra = {4: party.actor(1, "Owner", "owner"), 5: {1: "m"}} if kind == 2 else None
            actor = party.actor(kind, "Approver", "approver", extra=extra)
            delegation = party.grant(actor, {1: [16]})
            signer, provenance = "approver", {1: "m"} if kind == 2 else None
        proof = None
        if presence is not None:
            hardware = presence == "hardware"
            credential = {2: b"ukey", 3: party.pub("ukey"), 5: 2} if hardware else passkey(party, "pk")
            party.add(7, "root", party.ledger_id, {1: actor, 2: [credential]}, touches=[actor])
            proof = hardware_proof if hardware else webauthn("pk", flags=presence)
        if party_ahead is not None:
            party.time = home.time + party_ahead
        output = accept(status="agreed")
        record = party.consent(home, instance, output, until=None if until is None else home.time + until,
                               kind=record_type, terms=terms, arguments_hash=arguments_hash, signer=signer,
                               actor=actor, delegation=delegation, presence=proof, provenance=provenance)
        if edit is not None:
            party.add(edit[0], "root", party.ledger_id, {1: record, **edit[1]}, touches=[record])
        claim = {1: kind}
        if presence is not None:
            claim[2] = 2 if presence == "hardware" else 1
        if provenance is not None:
            claim[3] = provenance[1]
        citation, bundle = party.cite(home, record, claimed or claim)
        home.call(instance, output, consents=[citation])
        return home.evidence(instance, [bundle])
    return build


def requests(deadline: int = 10 * MINUTE, reply: str = "act", count: int = 1, more: int = 0, answer_at=None,
             status: int = 3, final: bool = False, answer_output=None):
    """An instance whose creation makes `count` requests due `deadline`
    after it, then takes `more` calls of 16 requests each, due a day later;
    then (with `answer_at`) an answer to the first request, `answer_at`
    after its deadline."""
    def build():
        home = Home(interface={"open": 1, "act": 2, "make": 1})
        created = home.time
        flags = {"final": True} if final else {}
        instance = home.create(accept(requests=ask(created + deadline, count, reply), **flags))
        for _ in range(more):
            home.call(instance, accept(requests=ask(home.time + DAY, 16)))
        if answer_at is not None:
            home.time = created + deadline + answer_at
            home.call(instance, answer_output, answer=[home.request(instance), status])
        return home.evidence(instance)
    return build


def sixty_five_open():
    home = Home()
    instance = home.create(accept(requests=ask(home.time + DAY, 16)))
    for n in (16, 16, 16, 1):
        home.call(instance, accept(requests=ask(home.time + DAY, n)))
    return home.evidence(instance)


def answer_at_the_limit():
    home = Home()
    instance = home.create(accept(requests=ask(home.time + DAY, 16)))
    for _ in range(3):
        home.call(instance, accept(requests=ask(home.time + DAY, 16)))
    home.call(instance, accept(requests=ask(home.time + DAY)), answer=[home.request(instance), 1])
    return home.evidence(instance)


def chain(depth: int, last_children: int = 0, retire: bool = False):
    """A child at `depth`, each generation made by a call that ends its
    parent; then (with `last_children`) a call on it that makes children,
    after the contract is retired (with `retire`)."""
    def build():
        home = Home()
        current = home.children[home.create(accept(children=[{1: 0}]), children=1)][0]
        for _ in range(depth - 1):
            current = home.children[home.call(current, accept(children=[{1: 0}], final=True), children=1)][0]
        if retire:
            home.add(23, "root", home.ledger_id, {1: home.contract}, touches=[home.contract])
        if last_children or retire:
            home.call(current, accept(children=[{1: 0}] * last_children) if last_children else accept(status="on"),
                      children=last_children)
        return home.evidence(current)
    return build


def one_call(output=None, args=None, **home_options):
    def build():
        home = Home(**home_options)
        instance = home.create()
        home.call(instance, output, args=args)
        return home.evidence(instance)
    return build


def scoped(scope: dict, answer: bool = False):
    """A device calls act, under a delegation with `scope`, on an instance
    with one open request; as an answer to it, with `answer`."""
    def build():
        home = Home()
        device = home.actor(3, "Executor", "executor")
        delegation = home.grant(device, scope)
        instance = home.create(accept(requests=ask(home.time + DAY)))
        home.call(instance, signer="executor", actor=device, delegation=delegation,
                  answer=[home.request(instance), 1] if answer else None)
        return home.evidence(instance)
    return build


def cases():
    out = []

    def case(name, expect, build, options=(), kind="contract"):
        out.append((name, expect, build, list(options), kind))

    # Consents (section 15, contract evidence, step 3).
    case("a consent by the party's organization", True, consented())
    case("a consent that lapses exactly when the call is registered", True, consented(until=0))
    case("a consent that lapsed 1 ms before the call was registered", False, consented(until=-1))
    for term, value in (("head", 99), ("function", "open"), ("arguments", bytes(32)), ("ledger", bytes(32)),
                        ("instance", bytes(32)), ("head", "2")):
        case(f"a consent whose {term} is {value!r}, not the call's", False, consented(terms={term: value}))
    case("a consent whose metadata lacks until", False, consented(terms={"until": None}))
    case("a consent whose metadata has an unknown key", None, consented(terms={"note": "extra"}))
    case("a consent whose reference is 1,025 bytes", None, consented(terms={"reference": "r" * 1025}))
    case("a consent whose reference is empty", None, consented(terms={"reference": ""}))
    case("a consent of a user's record type, with a consent's metadata", False,
         consented(record_type="example.org.consent/1"))
    case("a consent withdrawn before the call", False, consented(edit=(18, {2: "given", 3: "withdrawn"})))
    case("a consent revoked before the call", False, consented(edit=(19, {})))
    case("a consent whose citation claims a person signed it", False, consented(claimed={1: 1}))
    case("a consent whose citation claims a passkey", False, consented(claimed={1: 0, 2: 1}))
    case("a consent by a person, without presence", True, consented(kind=1))
    case("a consent by a device", True, consented(kind=3))
    case("a consent by an AI agent, its model claimed", True, consented(kind=2))
    case("a consent by an AI agent, its model not claimed", False, consented(kind=2, claimed={1: 2}))
    case("a consent by a person with a passkey, user verified", True, consented(kind=1, presence=0x05))
    case("a consent by a person with a passkey, not user verified", True, consented(kind=1, presence=0x01))
    case("a consent by a person with a hardware key", True, consented(kind=1, presence="hardware"))
    case("presence required: a consent proven with a passkey", True, consented(kind=1, presence=0x05),
         ["--require-presence"])
    case("presence required: a person's consent without presence", False, consented(kind=1), ["--require-presence"])
    case("a consent registered after the home's call, by the two clocks", None, consented(party_ahead=DAY))
    case("a consent from an SM3 party, arguments hashed under the home's hash", True,
         consented(party_hash=crypto.SM3))
    case("a consent from an SM3 party, arguments hashed under the party's hash", False,
         consented(party_hash=crypto.SM3, arguments_hash=crypto.hash_function(crypto.SM3)))

    def consent_bundles(variant: str):
        def build():
            home, party = Home(), Party()
            instance = home.create()
            record = party.consent(home, instance)
            other = party.consent(home, instance, terms={"reference": "another"})
            bundle = {"other record": party.bundle(other),
                      "incomplete": party.bundle(record, mutate=lambda b: b.pop(7))}.get(variant)
            citation, bundle = party.cite(home, record, bundle=bundle)
            home.call(instance, consents=[citation])
            return home.evidence(instance, [bundle] + ([party.bundle(other)] if variant == "extra" else []))
        return build
    case("a consent bundle about another record than the one cited", False, consent_bundles("other record"))
    case("a consent bundle without state proofs (not complete)", False, consent_bundles("incomplete"))
    case("a consent bundle that no call cites, beside the cited one", False, consent_bundles("extra"))

    def reused_consent():
        home, party = Home(), Party()
        instance = home.create()
        citation, bundle = party.cite(home, party.consent(home, instance))
        home.call(instance, consents=[citation])
        home.call(instance, consents=[citation])
        return home.evidence(instance, [bundle])
    case("one consent cited by two calls", False, reused_consent)

    def home_consent():
        home = Home()
        instance = home.create()
        home.call(instance, consents=[[home.ledger_id, bytes(32), bytes(32), {1: 0}]])
        return home.evidence(instance)
    case("a call citing a consent from its home", False, home_consent)

    def stranger():
        home, party = Home(), Party()
        instance = home.create(accept(parties={"buyer": bytes([0x11]) * 32}))
        citation, bundle = party.cite(home, party.consent(home, instance))
        home.call(instance, consents=[citation])
        return home.evidence(instance, [bundle])
    case("a consent from a ledger the instance does not name", True, stranger)

    def creation_consent():
        home, party = Home(), Party()
        citation, bundle = party.cite(home, party.consent(home, home.ledger_id, head=0))
        return home.evidence(home.create(consents=[citation]), [bundle])
    case("a creation citing a consent", False, creation_consent)

    # Requests and answers (v0.8).
    case("a request due 1 ms after its call", True, requests(deadline=1))
    case("a request due when its call is registered", False, requests(deadline=0))
    case("a request due exactly 366 days after its call", True, requests(deadline=LIMIT))
    case("a request due 366 days and 1 ms after its call", False, requests(deadline=LIMIT + 1))
    case("a request whose reply creates instances", False, requests(reply="make"))
    case("a request whose reply is not in the interface", False, requests(reply="other"))
    case("a request expired exactly at its deadline", True, requests(answer_at=0))
    case("a request expired 1 ms before its deadline", False, requests(answer_at=-1))
    case("a request answered done 1 ms late", True, requests(answer_at=1, status=1))
    case("a request failed before its deadline", True, requests(answer_at=-1, status=2))
    case("64 open requests", True, requests(count=16, more=3))
    case("65 open requests", False, sixty_five_open)
    case("an answer at the limit of 64 that makes one new request", True, answer_at_the_limit)
    case("a final instance takes an answer", True, requests(final=True, answer_at=0, status=1))
    case("a final instance's answer that makes a request", False,
         requests(final=True, answer_at=0, status=1, answer_output=accept(requests=ask(T0 + 300 * DAY))))
    case("a final instance's answer that creates a child", False,
         requests(final=True, answer_at=0, status=1, answer_output=accept(children=[{1: 0}])))
    case("an answer whose accept says final again", True,
         requests(final=True, answer_at=0, status=1, answer_output=accept(final=True)))

    def parent_request():
        home = Home()
        parent = home.create(accept(children=[{1: 0}], requests=ask(home.time + DAY)), children=1)
        child = home.children[parent][0]
        home.call(child, answer=[home.request(parent), 1])
        return home.evidence(child)
    case("a child answering its parent's request", False, parent_request)

    # Children (v0.7).
    case("a child at depth 8", True, chain(8))
    case("a child at depth 8 that creates a child", False, chain(8, last_children=1))
    case("a child at depth 7 that creates 16 children", True, chain(7, last_children=16))
    case("a child that creates a child once the contract is retired", False, chain(1, last_children=1, retire=True))
    case("a child that carries on once the contract is retired", True, chain(1, retire=True))

    def carried_on():
        home = Home()
        parent = home.create(accept(children=[{1: 0}, {1: 1}]), children=2)
        first, second = home.children[parent]
        home.call(parent, accept(status="carried on"))
        home.call(second, accept(status="the sibling moved"))
        home.call(first, accept(status="the part moved"))
        return home.evidence(first)
    case("a child's evidence that also holds its parent's later call and a sibling's", None, carried_on)

    # Outputs, sizes, deploys.
    case("an output with an unknown key 8", False, one_call([1, {1: 0, 8: True}]))
    case("arguments of exactly 65,536 bytes encoded", True, one_call(args=cbor.encode(accept(b"x" * 65_526))))
    case("arguments of 65,537 bytes encoded", False, one_call(args=cbor.encode(accept(b"x" * 65_527))))
    case("params of exactly 4,096 bytes encoded", True,
         one_call(accept(requests=ask(T0 + DAY, params=b"p" * 4093))))
    case("params of 4,097 bytes encoded", False, one_call(accept(requests=ask(T0 + DAY, params=b"p" * 4094))))
    case("a contract name of 256 bytes", True, one_call(extra={6: "n" * 256}))
    case("a contract name of 257 bytes", False, one_call(extra={6: "n" * 257}))
    case("an interface of 257 functions", False,
         one_call(interface={"open": 1, **{f"f{i:03d}": 2 for i in range(256)}}))
    case("code that is not WebAssembly", False, one_call(code=b"\0asm\x01\0\0\0junk"))

    # Scope keys 7 to 9 (sections 5 and 15).
    case("a call under scope key 8 that lists its function", True, scoped({1: [22], 8: ["act"]}))
    case("a call under scope key 8 that does not list its function", False, scoped({1: [22], 8: ["other"]}))
    case("an answer under scope key 9 that lists its kind", True, scoped({1: [22], 9: ["notify"]}, answer=True))
    case("an answer under scope key 9 that does not list its kind", False,
         scoped({1: [22], 9: ["invoice"]}, answer=True))
    case("a call that answers nothing under scope key 9", False, scoped({1: [22], 9: ["notify"]}))
    case("a call under scope key 7 that does not list its contract", False, scoped({1: [22], 7: [bytes(32)]}))

    def deploy_under_keys():
        home = Home()
        device = home.actor(3, "Deployer", "deployer")
        delegation = home.grant(device, {1: [21], 7: [home.contract], 8: ["none"], 9: ["none"]})
        contract = home.add(21, "deployer", device, {1: ORACLE, 2: {"open": 1, "act": 2}, 3: "wasm", 4: "probe 2"},
                            delegation, creates=4)
        return home.evidence(home.create(contract=contract))
    case("a deploy under scope keys 7 to 9, which restrict calls only", True, deploy_under_keys)

    # Evidence.
    def evidence_with(mutate):
        def build():
            home = Home()
            instance = home.create()
            home.call(instance)
            return home.evidence(instance, mutate=mutate)
        return build
    case("contract evidence of format version 2", False, evidence_with(lambda e: e.update({0: 2})))
    case("contract evidence with an empty list of consent bundles", False, evidence_with(lambda e: e.update({2: []})))

    def bundle_of(mutate=None, contract=False):
        def build():
            home = Home()
            instance = home.create()
            return home.bundle(home.contract if contract else instance, mutate=mutate)
        return build
    case("an instance's bundle alone, as verify reports it", True, bundle_of(), kind="bundle")
    case("an instance's bundle that discloses a field", None,
         bundle_of(lambda b: b.update({5: [[cbor.encode(["f", bytes(16), 1]), 0, []]]})), kind="bundle")
    case("a bundle whose subject is a contract's deploy (key 1 names a record or an instance)", False,
         bundle_of(contract=True), kind="bundle")
    return out


def _verify(args: list, env=None) -> tuple[int, dict]:
    done = subprocess.run(args, capture_output=True, text=True, env=env)
    try:
        report = json.loads(done.stdout)
    except ValueError:
        report = {"error": (done.stderr or done.stdout).strip()[-200:]}
    return done.returncode, report


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    cexchain = argv[1]
    failures, open_differ = 0, 0
    env = dict(os.environ, PYTHONPATH=str(HERE.parent))
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "probe.cbor")
        for name, expect, build, options, kind in cases():
            with open(path, "wb") as f:
                f.write(build())
            contract = ["contract"] if kind == "contract" else []
            py_code, py = _verify([sys.executable, "-m", "cexchain_verify", *contract, path, "--json", *options], env)
            bb_code, bb = _verify([cexchain, *contract, "verify", path, "--json", *options])
            py_ok, bb_ok = py_code == 0, bb_code == 0
            problems, soft = compare(py, py_code, bb, bb_code)
            if expect is None:
                tag = "open, both agree" if not problems else "OPEN, THEY DIFFER"
                open_differ += bool(problems)
            elif py_ok == expect and bb_ok == expect and not problems:
                tag = "as the spec says"
            else:
                tag = "WRONG"
                failures += 1

            def verdict(ok, report):
                return "verified" if ok else f"refused ({report.get('error', '?')})"
            print(f"  {tag}: {name}\n      python: {verdict(py_ok, py)}\n      cexchain: {verdict(bb_ok, bb)}")
            for line in problems if py_ok and bb_ok else []:
                print(f"      differs: {line}")
            for line in soft:
                print(f"      note: wording differs at {line}")
    print(f"contract probes: {failures} decided probe(s) failed; {open_differ} open probe(s) on which the verifiers "
          "differ")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
