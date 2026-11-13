// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// The WebAssembly verifier must reach exactly the conclusions of the native
// one. Usage: node verifier_node.js MODULE_JS API_JS EVIDENCE_DIR
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const [moduleJs, apiJs, dir] = process.argv.slice(2);
const factory = require(path.resolve(moduleJs));
const { createKanheVerifier } = require(path.resolve(apiJs));
const read = (name) => new Uint8Array(fs.readFileSync(path.join(dir, name)));
const text = (name) => fs.readFileSync(path.join(dir, name), "utf8").trim();

(async () => {
  const verifier = await createKanheVerifier(factory);
  const bundle = read("bundle.cbor");
  const ledgerId = text("ledger-id");

  // Same report as `kanhe verify --json`, field for field.
  const report = verifier.verify(bundle, { ledgerId, attachments: { "report.pdf": read("report.pdf") } });
  assert.equal(report.verified, true, report.error);
  assert.equal(typeof report.text, "string");
  assert.match(report.text, /AI agent: claude-opus-5-5; responsible: Alice Inspector/);
  delete report.text;
  assert.equal(report.kind, "record");
  delete report.kind;
  assert.deepEqual(report, JSON.parse(text("native-report.json")));
  assert.equal(report.record.id, text("record-id"));
  assert.equal(report.disclosed_fields.result, "pass");
  assert.equal(report.disclosed_fields.note, "中文 ✓ <script>alert(1)</script>");
  assert.equal(report.attachments[0].status, "verified");
  assert.equal(report.events[0].actor.kind, "agent");
  assert.equal(report.events[0].actor.responsible, "Alice Inspector");

  // Without an expected ledger id the report says it was not checked.
  const unchecked = verifier.verify(bundle);
  assert.equal(unchecked.verified, true);
  assert.equal(unchecked.ledger.id_checked, false);
  assert.equal(unchecked.attachments[0].status, "not-provided");

  // A forged attachment, another ledger, a bad id, and damaged bytes all fail.
  const forged = verifier.verify(bundle, { attachments: { "report.pdf": new TextEncoder().encode("forged") } });
  assert.equal(forged.verified, false);
  assert.equal(forged.attachments[0].status, "mismatch");
  const otherLedger = verifier.verify(bundle, { ledgerId: "00".repeat(32) });
  assert.equal(otherLedger.verified, false);
  assert.match(otherLedger.error, /ledger/);
  assert.equal(verifier.verify(bundle, { ledgerId: "xyz" }).verified, false);
  // Every byte matters. (The bundle ends with the attachment's salt, which can
  // only be checked against the attachment's content, so supply it.)
  const attachments = { "report.pdf": read("report.pdf") };
  for (let offset = 0; offset < bundle.length; offset += 7) {
    const damaged = bundle.slice();
    damaged[offset] ^= 1;
    assert.equal(verifier.verify(damaged, { ledgerId, attachments }).verified, false, "flipped byte at " + offset);
  }
  const lastByte = bundle.slice();
  lastByte[lastByte.length - 1] ^= 1;
  assert.equal(verifier.verify(lastByte, { ledgerId, attachments }).verified, false);
  assert.equal(verifier.verify(new Uint8Array(0)).verified, false);

  // A time-stamp authority's token (v0.11): the same report as `kanhe
  // verify --tsa-root`, and without the root, nothing relied on.
  const stamped = read("stamped.cbor");
  const stampedReport = verifier.verify(stamped, {
    ledgerId, attachments: { "report.pdf": read("report.pdf") }, timestampRoots: [read("tsa-root.pem")] });
  assert.equal(stampedReport.verified, true, stampedReport.error);
  assert.match(stampedReport.text, /Time-stamps  1 trusted authority/);
  delete stampedReport.text;
  delete stampedReport.kind;
  assert.deepEqual(stampedReport, JSON.parse(text("native-stamped-report.json")));
  assert.equal(stampedReport.timestamps.trusted_authorities, 1);
  assert.match(stampedReport.timestamps.existed_by, /^20\d\d-/);
  const unrooted = verifier.verify(stamped, { ledgerId });
  assert.equal(unrooted.verified, true);
  assert.equal(unrooted.timestamps.trusted_authorities, 0);
  assert.equal(unrooted.timestamps.existed_by, null);
  assert.equal(verifier.verify(stamped, { timestampRoots: [read("witness.pub")] }).verified, false);

  // Witness keys: a public key file is accepted, anything else refused.
  assert.equal(verifier.verify(bundle, { witnesses: [read("witness.pub")] }).verified, true);
  assert.equal(verifier.verify(bundle, { witnesses: [read("witness.key")] }).verified, false);

  // Options do not leak from one call into the next.
  assert.equal(verifier.verify(bundle).attachments[0].status, "not-provided");

  // A contract instance's evidence: the contract is run again on every call,
  // here by the interpreter compiled to WebAssembly, and the report is the
  // same as `kanhe contract verify`, in JSON and in text.
  const contract = read("contract.cbor");
  const contractLedger = text("contract-ledger-id");
  const contractReport = verifier.verify(contract, { ledgerId: contractLedger });
  assert.equal(contractReport.kind, "contract");
  assert.equal(contractReport.verified, true, contractReport.error);
  assert.equal(contractReport.text, fs.readFileSync(path.join(dir, "native-contract-report.txt"), "utf8"));
  delete contractReport.text;
  delete contractReport.kind;
  assert.deepEqual(contractReport, JSON.parse(text("native-contract-report.json")));
  assert.equal(contractReport.instance.id, text("instance-id"));
  assert.equal(contractReport.instance.status, "effective");
  assert.equal(contractReport.instance.contract.name, "Supply agreement");
  assert.equal(contractReport.complete, true);
  assert.deepEqual(contractReport.calls.map((c) => c.function), ["propose", "sign"]);
  const signed = contractReport.calls[1];
  assert.equal(signed.called_by.name, "Procurement Manager");
  assert.equal(signed.outcome.status, "effective");
  assert.deepEqual(signed.outcome.events.map((e) => e.name), ["signed"]);
  assert.deepEqual(signed.consents.map((c) => c.organization).sort(), ["Cirraya Bank", "Cirraya Supplier"]);
  const bankConsent = signed.consents.find((c) => c.organization === "Cirraya Bank");
  assert.equal(bankConsent.signer.kind, "agent");
  assert.equal(bankConsent.provenance.model, "credit-model-7");
  assert.equal(bankConsent.signer.responsible, "Credit Officer");
  assert.equal(bankConsent.reference, "Credit approval CA-9");
  // Unpinned, it verifies but says the home was not compared; pinned to
  // another ledger it fails; and so does any damage.
  const contractUnchecked = verifier.verify(contract);
  assert.equal(contractUnchecked.verified, true, contractUnchecked.error);
  assert.equal(contractUnchecked.home.id_checked, false);
  assert.equal(verifier.verify(contract, { ledgerId }).verified, false);
  for (let offset = 0; offset < contract.length; offset += 97) {
    const damaged = contract.slice();
    damaged[offset] ^= 1;
    assert.equal(verifier.verify(damaged, { ledgerId: contractLedger }).verified, false,
                 "contract: flipped byte at " + offset);
  }

  // A tier-3 part of a receivable (v0.7): its subject is no statement id but
  // derived from the call that created it, and its ancestors' calls are run
  // again too. The same report as `kanhe contract verify`.
  const part = read("part.cbor");
  const partReport = verifier.verify(part, { ledgerId: contractLedger });
  assert.equal(partReport.kind, "contract");
  assert.equal(partReport.verified, true, partReport.error);
  assert.equal(partReport.text, fs.readFileSync(path.join(dir, "native-part-report.txt"), "utf8"));
  assert.match(partReport.text, /Ancestors {4}oldest first/);
  delete partReport.text;
  delete partReport.kind;
  assert.deepEqual(partReport, JSON.parse(text("native-part-report.json")));
  assert.equal(partReport.instance.id, text("part-id"));
  assert.equal(partReport.instance.parent, text("part-parent-id"));
  assert.equal(partReport.instance.depth, 2);
  assert.deepEqual(partReport.instance.ancestors.map((a) => a.id), [text("part-root-id"), text("part-parent-id")]);
  assert.deepEqual(partReport.calls.map((c) => c.function), ["issue", "split", "split", "transfer"]);
  assert.equal(partReport.calls[1].outcome.children.length, 2);
  assert.deepEqual(partReport.calls.map((c) => c.consents.map((k) => k.organization)),
                   [[], ["Cirraya Supplier"], ["Cirraya Supplier"], ["Cirraya Bank"]]);
  assert.equal(verifier.verify(part, { ledgerId }).verified, false);
  for (let offset = 0; offset < part.length; offset += 97) {
    const damaged = part.slice();
    damaged[offset] ^= 1;
    assert.equal(verifier.verify(damaged, { ledgerId: contractLedger }).verified, false,
                 "part: flipped byte at " + offset);
  }

  // Requests and answers (v0.8): every request the calls made, each answer
  // with its status and lateness, and the open ones, one overdue at the
  // checkpoint. The same report as `kanhe contract verify`.
  const asking = read("requests.cbor");
  const askingLedger = text("requests-ledger-id");
  const askingReport = verifier.verify(asking, { ledgerId: askingLedger });
  assert.equal(askingReport.verified, true, askingReport.error);
  assert.equal(askingReport.text, fs.readFileSync(path.join(dir, "native-requests-report.txt"), "utf8"));
  assert.match(askingReport.text, /OVERDUE/);
  delete askingReport.text;
  delete askingReport.kind;
  assert.deepEqual(askingReport, JSON.parse(text("native-requests-report.json")));
  const asked = askingReport.instance;
  assert.equal(asked.id, text("requests-id"));
  assert.deepEqual(asked.requests.map((r) => r.kind), ["notify", "http.post", "notify", "notify"]);
  assert.deepEqual(asked.requests.map((r) => r.status), ["done", "done", "open", "open"]);
  assert.equal(asked.open_requests.length, 2);
  assert.deepEqual(asked.overdue_requests, [asked.requests[2].id]);
  const answers = askingReport.calls.filter((c) => c.answer);
  assert.deepEqual(answers.map((c) => [c.answer.kind, c.answer.status, c.answer.late, c.called_by.kind]),
                   [["notify", "done", false, "device"], ["http.post", "done", true, "person"]]);
  assert.equal(answers[1].outcome.requests.length, 1);
  assert.equal(askingReport.calls[0].outcome.requests.length, 3);
  for (let offset = 0; offset < asking.length; offset += 97) {
    const damaged = asking.slice();
    damaged[offset] ^= 1;
    assert.equal(verifier.verify(damaged, { ledgerId: askingLedger }).verified, false,
                 "requests: flipped byte at " + offset);
  }

  // Trust nodes (spec v0.16): the independent vectors' members' evidence,
  // with the trust nodes the page is told to believe, and without.
  const v16 = JSON.parse(fs.readFileSync(path.join(__dirname, "../../testvectors/protocol-v0.16.json"), "utf8"));
  const hexBytes = (h) => new Uint8Array(Buffer.from(h, "hex"));
  for (const c of v16.bundles.valid) {
    const got = verifier.verify(hexBytes(c.bundle), { ledgerId: c.ledger, trustNodes: c.trust_nodes });
    assert.equal(got.verified, true, c.name + ": " + got.error);
    assert.equal(got.memberships.length, c.memberships.length, c.name);
    got.memberships.forEach((m, i) => {
      const want = c.memberships[i];
      for (const key of ["trust_node", "trusted", "trust_node_name", "membership", "kind", "name", "verified", "at_record", "at_checkpoint"]) {
        assert.equal(m[key], want[key], c.name + ": " + key);
      }
    });
  }
  for (const c of v16.bundles.refused) {
    assert.equal(verifier.verify(hexBytes(c.bundle), { ledgerId: c.ledger }).verified, false, c.name);
  }
  assert.equal(verifier.verify(new Uint8Array(1), { trustNodes: [{ ledger: "xyz", name: "A" }] }).verified, false);

  // A W3C credential (spec/credentials.md): the same report as `kanhe
  // credential verify --offline`, and a changed claim fails.
  const credential = text("credential.jwt");
  const where = verifier.credentialAddresses(credential);
  assert.equal(where.evidence, "https://college.example/c/" + text("credential-token"));
  assert.equal(where.did_document, "https://college.example/.well-known/did.json");
  assert.equal(where.status_list, "https://college.example/status/1");
  assert.equal(where.ledger, ledgerId);
  const credentialOptions = { didDocument: text("credential-did.json"), statusList: text("credential-list.jwt") };
  const checked = verifier.verifyCredential(credential, read("credential-evidence.cbor"), credentialOptions);
  assert.equal(checked.verified, true, JSON.stringify(checked.problems || checked.error));
  assert.equal(typeof checked.text, "string");
  delete checked.text;
  assert.deepEqual(checked, JSON.parse(text("native-credential-report.json")));
  assert.equal(checked.credential.subject.note, "中文 ✓ <script>alert(1)</script>");
  const [h, p, sig] = credential.split(".");
  const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  payload.credentialSubject.result = "fail";
  const canonical = (v) => Array.isArray(v) ? "[" + v.map(canonical).join(",") + "]"
    : v && typeof v === "object" ? "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}"
    : JSON.stringify(v);
  const forgedCredential = [h, Buffer.from(canonical(payload)).toString("base64url"), sig].join(".");
  const lie = verifier.verifyCredential(forgedCredential, read("credential-evidence.cbor"), credentialOptions);
  assert.equal(lie.verified, false);
  assert.ok(lie.problems.some((x) => /result = fail/.test(x)), JSON.stringify(lie.problems));
  assert.match(verifier.credentialAddresses("not a credential").error, /JWS/);
  console.log("wasm verifier (node): ok, version " + verifier.version);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
