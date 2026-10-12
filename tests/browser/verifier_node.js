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

  // An asset's evidence: the same report as `cexchain asset verify --json`.
  const asset = read("asset.cbor");
  const assetLedger = text("asset-ledger-id");
  const assetReport = verifier.verify(asset, { ledgerId: assetLedger });
  assert.equal(assetReport.kind, "asset");
  assert.equal(assetReport.verified, true, assetReport.error);
  assert.match(assetReport.text, /Chain of title/);
  delete assetReport.text;
  delete assetReport.kind;
  assert.deepEqual(assetReport, JSON.parse(text("native-asset-report.json")));
  assert.equal(assetReport.asset.id, text("asset-id"));
  assert.equal(assetReport.asset.state, "pledged");
  assert.equal(assetReport.asset.display, "125000.00 CNY");
  assert.equal(assetReport.chain.length, 2);
  assert.deepEqual(assetReport.chain[1].consents.map((c) => c.organization).sort(),
                   ["Cirraya Bank", "Cirraya Supplier"]);
  assert.equal(assetReport.report.disclosed_fields.invoice, "INV-77");
  // Pinned to another ledger, it fails; and so does any damage.
  assert.equal(verifier.verify(asset, { ledgerId }).verified, false);
  for (let offset = 0; offset < asset.length; offset += 97) {
    const damaged = asset.slice();
    damaged[offset] ^= 1;
    assert.equal(verifier.verify(damaged, { ledgerId: assetLedger }).verified, false, "asset: flipped byte at " + offset);
  }

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

  console.log("wasm verifier (node): ok, version " + verifier.version);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
