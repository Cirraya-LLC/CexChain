// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// Drives cexchain-verify.html in a real browser, as a verifier would use it:
// opened from a QR link that names the ledger, the record, and the bundle's
// URL; opened from disk with files chosen by hand; fed a forged attachment;
// and given a contract instance's evidence, and a part's.
// Usage: node page_test.js PAGE EVIDENCE_DIR CEXCHAIN
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { chromium } = require("playwright");

const [pagePath, dir, cexchain] = process.argv.slice(2).map((p) => path.resolve(p));
const text = (name) => fs.readFileSync(path.join(dir, name), "utf8").trim();
const ledgerId = text("ledger-id");
const recordId = text("record-id");

function serve() {
  const files = { "/cexchain-verify.html": pagePath, "/bundle.cbor": path.join(dir, "bundle.cbor"),
                  "/contract.cbor": path.join(dir, "contract.cbor"), "/part.cbor": path.join(dir, "part.cbor") };
  const server = http.createServer((req, res) => {
    const file = files[req.url];
    if (!file) { res.writeHead(404).end(); return; }
    res.writeHead(200, { "Content-Type": file.endsWith(".html") ? "text/html" : "application/cbor" });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

async function verdict(page) {
  await page.waitForFunction(() => !document.getElementById("result").hidden);
  return {
    kind: (await page.getAttribute("#verdict", "class")).replace("verdict ", ""),
    title: await page.textContent("#verdict-title"),
    detail: await page.textContent("#verdict-detail"),
  };
}

(async () => {
  // Pure ASCII, so the page survives email, re-encoding, and servers that
  // send no charset.
  assert.ok(/^[\x00-\x7f]*$/.test(fs.readFileSync(pagePath, "latin1")), "the page must be pure ASCII");
  const server = await serve();
  const base = "http://127.0.0.1:" + server.address().port;
  const browser = await chromium.launch();
  const problems = [];
  const open = async (url) => {
    const page = await browser.newPage();
    page.on("dialog", (d) => { problems.push("a dialog opened: " + d.message()); d.dismiss(); });
    page.on("console", (m) => { if (m.type() === "error") problems.push("console error: " + m.text()); });
    page.on("pageerror", (e) => problems.push("page error: " + e.message));
    await page.goto(url);
    try {
      await page.waitForFunction(() => window.verifierReady === true);
    } catch (e) {
      const verdict = await page.evaluate(() => document.getElementById("verdict-title").textContent + ": " +
                                                document.getElementById("verdict-detail").textContent);
      throw new Error(`the page did not get ready (${verdict}); problems: ${problems.join(" | ")}`);
    }
    return page;
  };
  try {
    // 1. The link in a QR code from `cexchain qr`: everything is checked, and
    // the result is green.
    const qr = JSON.parse(execFileSync(cexchain, [
      "qr", recordId, "--ledger", path.join(dir, "ledger"), "--json",
      "--bundle-url", base + "/bundle.cbor", "--verifier-url", base + "/cexchain-verify.html"]));
    const link = qr.url;
    let page = await open(link);
    let v = await verdict(page);
    assert.equal(v.kind, "ok", v.title + ": " + v.detail);
    assert.equal(v.title, "Verified");
    const body = await page.textContent("#result");
    assert.match(body, /Cirraya Test Factory/);
    assert.match(body, /AI agent/);
    assert.match(body, /model claude-opus-5-5 2026-09/);
    assert.match(body, /accountable person: Alice Inspector/);
    assert.match(body, /authorized by Alice Inspector ← Cirraya Test Factory/);
    assert.match(body, /Endorsed as inspector/);
    // Untrusted text is shown as text, never run.
    assert.match(body, /中文 ✓ <script>alert\(1\)<\/script>/);
    assert.equal(await page.locator("#fields script").count(), 0);
    await page.close();

    // 2. A link naming another record is refused.
    page = await open(link.replace(`r=${recordId}`, "r=" + "ab".repeat(32)));
    v = await verdict(page);
    assert.equal(v.kind, "bad");
    assert.match(v.detail, /different record/);
    await page.close();

    // 3. Opened from disk; files chosen by hand.
    page = await open("file://" + pagePath);
    await page.setInputFiles("#bundle-file", path.join(dir, "bundle.cbor"));
    v = await verdict(page);
    assert.equal(v.kind, "warn", "without a ledger id the issuer is unconfirmed");
    await page.fill("#ledger", ledgerId);
    await page.dispatchEvent("#ledger", "change");
    await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "Verified");
    await page.setInputFiles("#attachment-files", path.join(dir, "report.pdf"));
    await page.waitForFunction(() => /matches/.test(document.getElementById("attachments").textContent));
    assert.equal((await verdict(page)).kind, "ok");

    // 4. A forged attachment turns the result red.
    const forged = path.join(dir, "forged", "report.pdf");
    fs.mkdirSync(path.dirname(forged), { recursive: true });
    fs.writeFileSync(forged, "forged");
    await page.setInputFiles("#attachment-files", forged);
    await page.waitForFunction(() => /DOES NOT MATCH/.test(document.getElementById("attachments").textContent));
    v = await verdict(page);
    assert.equal(v.kind, "bad");
    assert.match(v.detail, /attachment/);

    // 5. Damaged evidence is refused outright.
    const damaged = fs.readFileSync(path.join(dir, "bundle.cbor"));
    damaged[200] ^= 1;
    await page.setInputFiles("#bundle-file", { name: "damaged.cbor", mimeType: "application/cbor", buffer: damaged });
    await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "Not verified");
    await page.close();

    // 6. A contract instance's evidence: every call, what the contract made
    // of it, and each consent with who gave it. The page's report is the one
    // `cexchain contract verify --json` gives for the same evidence.
    const contractLedger = text("contract-ledger-id");
    const instanceId = text("instance-id");
    page = await open("file://" + pagePath);
    await page.setInputFiles("#bundle-file", path.join(dir, "contract.cbor"));
    v = await verdict(page);
    assert.equal(v.kind, "warn", "without a ledger id the home is unconfirmed: " + v.detail);
    await page.fill("#ledger", contractLedger);
    await page.dispatchEvent("#ledger", "change");
    await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "Verified");
    v = await verdict(page);
    assert.equal(v.kind, "ok", v.title + ": " + v.detail);
    assert.match(v.detail, /Supply agreement.* at "Cirraya Core Enterprise": status effective after 2 calls/);
    const shown = await page.evaluate(() => window.lastReport);
    assert.equal(shown.kind, "contract");
    delete shown.kind;
    delete shown.text;
    assert.deepEqual(shown, JSON.parse(text("native-contract-report.json")));
    const calls = await page.textContent("#result");
    assert.match(calls, /Instance ID/);
    assert.match(calls, new RegExp(instanceId));
    assert.match(calls, /bank: Cirraya Bank \(ledger [0-9a-f]{12}/);
    assert.match(calls, /Created with propose/);
    assert.match(calls, /reference: PO-2026-1012/);
    assert.match(calls, /Called sign/);
    assert.match(calls, /Procurement Manager/);
    assert.match(calls, /signed with their key; presence not proven/);
    assert.match(calls, /authorized by Cirraya Core Enterprise/);
    assert.match(calls, /outcome: status effective; event signed \{"amount": 125000\}/);
    assert.match(calls, /consent of Cirraya Bank \(SHA-256\): given by "Credit Agent" \(a machine: AI agent\), ref\. Credit approval CA-9/);
    assert.match(calls, /model credit-model-7 \u00b7 accountable person: Credit Officer/);
    assert.match(calls, /consent of Cirraya Supplier \(SHA-256\): given by "Cirraya Supplier" \(the organization's own key\)/);
    assert.match(calls, /complete \(proven against the state commitment\)/);
    assert.match(calls, /contract was run again on every call/);
    await page.close();

    // 7. A link to a contract instance's evidence, naming the home and the
    // instance, is green; one naming another instance is refused.
    const contractLink = base + "/cexchain-verify.html#l=" + contractLedger + "&r=" + instanceId +
      "&b=" + encodeURIComponent(base + "/contract.cbor");
    page = await open(contractLink);
    v = await verdict(page);
    assert.equal(v.kind, "ok", v.title + ": " + v.detail);
    await page.close();
    page = await open(contractLink.replace("r=" + instanceId, "r=" + "ab".repeat(32)));
    v = await verdict(page);
    assert.equal(v.kind, "bad");
    assert.match(v.detail, /different instance/);
    await page.close();

    // 8. A tier-3 part's evidence (v0.7): the chain of its ancestors, each
    // with its calls and consents, then its own; the report is the one
    // `cexchain contract verify --json` gives. A link naming the part is green.
    const partId = text("part-id");
    page = await open("file://" + pagePath);
    await page.fill("#ledger", contractLedger);
    await page.dispatchEvent("#ledger", "change");
    await page.setInputFiles("#bundle-file", path.join(dir, "part.cbor"));
    await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "Verified");
    v = await verdict(page);
    assert.equal(v.kind, "ok", v.title + ": " + v.detail);
    assert.match(v.detail, /Receivable.* at "Cirraya Core Enterprise": a part at depth 2, status active after 4 calls \(its ancestors' included\)/);
    const shownPart = await page.evaluate(() => window.lastReport);
    delete shownPart.kind;
    delete shownPart.text;
    assert.deepEqual(shownPart, JSON.parse(text("native-part-report.json")));
    const partText = await page.textContent("#result");
    assert.match(partText, new RegExp("Part ofpart 0 of call #\\d+ on " + text("part-parent-id")));
    assert.match(partText, /Depth2 \(2 ancestors: /);
    assert.match(partText, new RegExp("Ancestor " + text("part-root-id") + ", depth 0"));
    assert.match(partText, new RegExp("Ancestor " + text("part-parent-id") + ", depth 1, part 0 of #\\d+ \\(above\\)"));
    assert.match(partText, /This instance's own calls, after the call that created it/);
    assert.match(partText, new RegExp("part 0 " + partId.slice(0, 12) + ": active \\(holder: Cirraya Bank"));
    assert.match(partText, /consent of Cirraya Bank \(SHA-256\)/);
    assert.match(partText, /run again too, consents and all/);
    // The ancestors' creating calls are shown once: four calls, four items.
    assert.equal(await page.locator("#events li:not(.group):not(.meta)").count(), 4);
    await page.close();
    page = await open(base + "/cexchain-verify.html#l=" + contractLedger + "&r=" + partId + "&b=" +
      encodeURIComponent(base + "/part.cbor"));
    v = await verdict(page);
    assert.equal(v.kind, "ok", v.title + ": " + v.detail);
    await page.close();

    assert.deepEqual(problems, []);
    console.log("wasm verifier (browser): ok");
  } finally {
    await browser.close();
    server.close();
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
