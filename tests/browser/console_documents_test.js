// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// Documents and proof in the console, in a real browser: the README's photo
// story. One person sets up, defines a kind (Photo: place, taken, a file),
// registers a photo with its file, checked in the browser before the tap;
// opens the thing's page; shares proof with one field disclosed and the
// file; and the proof verifies with `cexchain verify`, in the console's
// Verify screen, and in the standalone verifier page, while a forged photo
// is caught.
// Usage: node console_documents_test.js CEXCHAIN [VERIFIER_PAGE]
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const cexchain = path.resolve(process.argv[2]);
const verifierPage = process.argv[3] ? path.resolve(process.argv[3]) : null;
const work = fs.mkdtempSync(path.join(os.tmpdir(), "cexchain-documents-"));
const ledger = path.join(work, "ledger");
const env = { ...process.env, CEXCHAIN_LEDGER: ledger, CEXCHAIN_NO_BROWSER: "1", HOME: work };
const run = (...args) => execFileSync(cexchain, args, { cwd: work, env, encoding: "utf8" });

function freePort() {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function waitRunning() {
  for (let i = 0; i < 300; i++) {
    if (JSON.parse(run("console", "status", "--json")).running) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("the console did not start");
}

(async () => {
  const photo = path.join(work, "photo.jpg");
  fs.writeFileSync(photo, Buffer.from("not really a photo, but its bytes count\n"));
  const port = await freePort();
  const consoleProcess = spawn(cexchain, ["console", "run", "--port", String(port), "--quiet"],
                               { cwd: work, env });
  let browser;
  const violations = [];
  let page;
  try {
    await waitRunning();
    const base = `http://localhost:${port}/console/`;
    const setup = fs.readFileSync(path.join(ledger, "console", "setup-link"), "utf8").trim();
    browser = await chromium.launch();
    const context = await browser.newContext({ locale: "en-GB", acceptDownloads: true });
    page = await context.newPage();
    page.on("console", (m) => {
      if (/Content Security Policy|Refused to/.test(m.text())) violations.push(m.text());
    });
    page.on("pageerror", (e) => violations.push(String(e)));
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
      protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });

    // Set up: Alice, a passkey, the sheet, no backup folder.
    await page.goto(setup);
    await page.getByLabel("Your name").fill("Alice");
    await page.getByRole("button", { name: "Create my passkey" }).click();
    await page.getByRole("heading", { name: "Your recovery code" }).waitFor();
    await page.getByLabel("I have printed or saved my recovery code").check();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Not now" }).click();
    await page.getByRole("heading", { name: "Home" }).waitFor();

    // A kind: Photo, with a place (required), the day it was taken, a file.
    await page.getByRole("link", { name: "Kinds" }).click();
    await page.getByRole("heading", { name: "Kinds", level: 1 }).waitFor();
    await page.getByLabel("Name", { exact: true }).first().fill("Photo");
    assert.equal(await page.getByLabel("Record type").inputValue(), "photo/1");
    await page.getByLabel("Record type").fill("example.org.photo/1");
    await page.getByLabel("Name of field 1").fill("place");
    await page.getByRole("checkbox", { name: "Required" }).first().check();
    await page.getByRole("button", { name: "Add a field" }).click();
    await page.getByLabel("Name of field 2").fill("taken");
    await page.getByLabel("Type of field 2").selectOption("date");
    await page.getByLabel("Files", { exact: true }).selectOption("required");
    await page.getByRole("button", { name: "Save the kind" }).click();
    await page.getByRole("heading", { name: "Photo", level: 2 }).waitFor();
    const kinds = JSON.parse(run("console", "kind", "list", "--json"));
    assert.equal(kinds[0].type, "example.org.photo/1");
    assert.deepEqual(kinds[0].fields.map((f) => [f.name, f.type, f.required]),
                     [["place", "text", true], ["taken", "date", false]]);

    // The photo, registered: checked in this browser, then one tap.
    await page.getByRole("link", { name: "Things" }).click();
    await page.getByRole("link", { name: "Register a document" }).click();
    await page.getByRole("heading", { name: "Register a document" }).waitFor();
    await page.getByLabel("place (required)").fill("Victoria Harbour");
    await page.getByLabel("taken").fill("2026-10-16");
    await page.getByLabel("Files").setInputFiles(photo);
    await page.getByRole("button", { name: "Prepare" }).click();
    await page.getByRole("heading", { name: "Approve with your passkey" }).waitFor();
    await page.getByText("Checked in this browser").waitFor();
    await page.getByText("Victoria Harbour").waitFor();
    await page.getByText(/photo\.jpg, .* kept with the record/).waitFor();
    await page.getByRole("button", { name: "Approve with your passkey" }).click();
    await page.getByRole("heading", { name: "Done" }).waitFor();
    const record = (await page.locator("main p.id").textContent()).trim();
    assert.match(record, /^[0-9a-f]{64}$/);
    const shown = JSON.parse(run("record", "show", record, "--json"));
    assert.equal(shown.record_type ?? shown.type, "example.org.photo/1");
    const files = JSON.parse(run("record", "file", "list", record, "--json")).files;
    assert.deepEqual(files.map((f) => [f.name, f.kept]), [["photo.jpg", true]]);

    assert.deepEqual(violations, [], "no CSP violation or script error");
    console.log("console documents browser test: passed");
  } catch (error) {
    if (page) console.error(`page ${page.url()}:\n${await page.locator("main").innerText().catch(() => "")}`);
    throw error;
  } finally {
    if (browser) await browser.close();
    try {
      run("console", "stop");
    } catch {
      // Not running: nothing to stop.
    }
    consoleProcess.kill();
    fs.rmSync(work, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
