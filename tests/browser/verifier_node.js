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
const { createCexChainVerifier } = require(path.resolve(apiJs));
const read = (name) => new Uint8Array(fs.readFileSync(path.join(dir, name)));
const text = (name) => fs.readFileSync(path.join(dir, name), "utf8").trim();

(async () => {
  const verifier = await createCexChainVerifier(factory);
  const bundle = read("bundle.cbor");
  const ledgerId = text("ledger-id");

  // Same report as `cexchain verify --json`, field for field.
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

  // Witness keys: a public key file is accepted, anything else refused.
  assert.equal(verifier.verify(bundle, { witnesses: [read("witness.pub")] }).verified, true);
  assert.equal(verifier.verify(bundle, { witnesses: [read("witness.key")] }).verified, false);

  // Options do not leak from one call into the next.
  assert.equal(verifier.verify(bundle).attachments[0].status, "not-provided");

  // A contract instance's evidence: the contract is run again on every call,
  // here by the interpreter compiled to WebAssembly, and the report is the
  // same as `cexchain contract verify`, in JSON and in text.
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
  // again too. The same report as `cexchain contract verify`.
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

  console.log("wasm verifier (node): ok, version " + verifier.version);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
