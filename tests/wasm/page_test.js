// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// Drives cexchain-verify.html in a real browser, as a verifier would use it:
// opened from a QR link that names the ledger, the record, and the bundle's
// URL; opened from disk with files chosen by hand; fed a forged attachment.
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
  const files = { "/cexchain-verify.html": pagePath, "/bundle.cbor": path.join(dir, "bundle.cbor") };
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
    await page.waitForFunction(() => window.verifierReady === true);
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
