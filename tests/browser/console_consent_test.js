// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// Consents between two consoles on one computer, by file, in real browsers:
// Alice and Bob each set up a console of their own (a ledger, a passkey).
// Alice creates a camera under the lending rules and lends it to Bob: the
// call waits for his consent, so she writes a proposal file. Bob opens it,
// reads the call (verified against the camera's history), consents with a
// tap, and gets a consent file; Alice opens that, and records the loan with
// a tap. The camera is then lent, its history showing the consent.
// Usage: node console_consent_test.js CEXCHAIN [SOURCE_DIR]
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const cexchain = path.resolve(process.argv[2]);
const source = path.resolve(process.argv[3] ?? path.join(__dirname, "..", ".."));
const lending = path.join(source, "examples", "lending", "lending.bo");
const work = fs.mkdtempSync(path.join(os.tmpdir(), "cexchain-consent-"));

function freePort() {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

/// One person's console: its ledger directory, process, and browser page.
async function person(browser, name) {
  const ledger = path.join(work, name.toLowerCase(), "ledger");
  fs.mkdirSync(path.dirname(ledger), { recursive: true });
  const env = { ...process.env, CEXCHAIN_LEDGER: ledger, CEXCHAIN_NO_BROWSER: "1",
                HOME: path.dirname(ledger) };
  const run = (...args) => execFileSync(cexchain, args, { cwd: work, env, encoding: "utf8" });
  const port = await freePort();
  const process_ = spawn(cexchain, ["console", "run", "--port", String(port), "--quiet"],
                         { cwd: work, env });
  for (let i = 0; i < 300; i++) {
    try {
      if (JSON.parse(run("console", "status", "--json")).running) break;
    } catch {
      // Not yet.
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  const context = await browser.newContext({ locale: "en-GB", acceptDownloads: true });
  const page = await context.newPage();
  const violations = [];
  page.on("console", (m) => {
    if (/Content Security Policy|Refused to/.test(m.text())) violations.push(m.text());
  });
  page.on("pageerror", (e) => violations.push(String(e)));
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  const setup = fs.readFileSync(path.join(ledger, "console", "setup-link"), "utf8").trim();
  await page.goto(setup);
  await page.getByLabel("Your name").fill(name);
  await page.getByRole("button", { name: "Create my passkey" }).click();
  await page.getByRole("heading", { name: "Your recovery code" }).waitFor();
  await page.getByLabel("I have printed or saved my recovery code").check();
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Not now" }).click();
  await page.getByRole("heading", { name: "Home" }).waitFor();
  const id = JSON.parse(run("status", "--json")).ledger_id;
  return { name, page, run, process: process_, violations, id };
}

/// Approves what the page shows, checked in the browser, with the passkey.
async function tap(page, what) {
  await page.getByRole("heading", { name: "Approve with your passkey" }).waitFor();
  await page.getByText("Checked in this browser").waitFor();
  if (what) await page.getByText(what, { exact: true }).first().waitFor();
  await page.getByRole("button", { name: "Approve with your passkey" }).click();
  await page.getByRole("heading", { name: "Done" }).waitFor();
}

(async () => {
  const browser = await chromium.launch();
  const people = [];
  let current;
  try {
    const alice = await person(browser, "Alice");
    people.push(alice);
    const bob = await person(browser, "Bob");
    people.push(bob);

    // Alice: the rules, and her camera.
    current = alice;
    const a = alice.page;
    await a.getByRole("link", { name: "Rules" }).click();
    await a.getByRole("link", { name: "Write rules" }).click();
    await a.getByLabel("Open a file").setInputFiles(lending);
    await a.getByLabel("Name of the rules").waitFor();
    await a.getByRole("button", { name: "Deploy" }).click();
    await tap(a, "Deploy rules");
    await a.getByRole("button", { name: "Back to the rules" }).click();
    await a.getByRole("link", { name: "Create a thing under Lending" }).click();
    await a.getByLabel("name", { exact: true }).fill("Camera X100");
    await a.getByRole("button", { name: "Prepare" }).click();
    await tap(a);
    await a.getByRole("button", { name: "Open the thing" }).click();
    await a.getByRole("heading", { name: "Lending", level: 1 }).waitFor();
    const camera = a.url().match(/instance\/([0-9a-f]{64})/)[1];

    // The loan waits for Bob's consent: a proposal file for him.
    const lend = a.getByRole("region", { name: "lend" });
    await lend.getByLabel("counterparty", { exact: true }).selectOption("other");
    await lend.getByLabel("Ledger id for counterparty").fill(bob.id);
    await lend.getByRole("button", { name: "Prepare" }).click();
    await lend.getByText(/This needs the consent of another ledger/).waitFor();
    await lend.getByLabel("Note for them (optional)").fill("For your trip");
    const proposing = a.waitForEvent("download");
    proposing.catch(() => {}); // awaited below; a step failing first is the error shown
    await lend.getByRole("button", { name: "Ask for consent by file" }).click();
    const proposal = path.join(work, "lend.cexchain");
    await (await proposing).saveAs(proposal);
    await lend.getByText(/^Saved proposal-[0-9a-f]{12}-lend\.cexchain\./).waitFor();

    // Bob reads it, verified, and consents with a tap; the consent file is saved.
    current = bob;
    const b = bob.page;
    await b.getByRole("link", { name: "Open a proposal or consent file" }).click();
    await b.getByRole("heading", { name: "Proposals and consents" }).waitFor();
    await b.getByLabel("Proposal or consent file").setInputFiles(proposal);
    await b.getByRole("heading", { name: "A proposal from Alice" }).waitFor();
    await b.getByText(/^Verified: the thing's history checks/).waitFor();
    await b.getByText("For your trip").waitFor();
    await b.getByText("Camera X100").first().waitFor();
    await b.getByRole("button", { name: "Consent with your passkey" }).click();
    const consenting = b.waitForEvent("download", { timeout: 60000 });
    consenting.catch(() => {});
    await tap(b, "Consent to a call");
    const consent = path.join(work, "lend-consent.cexchain");
    await (await consenting).saveAs(consent);
    await b.getByText(/^Saved consent-[0-9a-f]{12}-lend\.cexchain\./).waitFor();
    const consents = JSON.parse(bob.run("record", "list", "--json"));
    const list = Array.isArray(consents) ? consents : consents.records;
    assert.ok(list.some((r) => (r.record_type ?? r.type) === "cexchain.contract-consent/1"),
              "Bob's consent is a record on his ledger");

    // Alice opens the consent, and records the loan with it.
    current = alice;
    await a.getByRole("link", { name: "Home" }).click();
    await a.getByRole("link", { name: "Open a proposal or consent file" }).click();
    await a.getByLabel("Proposal or consent file").setInputFiles(consent);
    await a.getByRole("heading", { name: "A consent from Bob" }).waitFor();
    await a.getByText(/^Verified on the consenting ledger/).waitFor();
    await a.getByRole("button", { name: "Record the call with your passkey" }).click();
    await tap(a, "Act under rules");
    await a.getByRole("button", { name: "Open the thing" }).click();
    await a.getByRole("heading", { name: "History" }).waitFor();
    assert.equal(await a.locator("ol.events li").count(), 2);
    const instances = JSON.parse(alice.run("contract", "instances", "--json"));
    const camera_ = (Array.isArray(instances) ? instances : instances.instances)
      .find((i) => (i.id?.id ?? i.id) === camera || String(i.id).startsWith(camera));
    assert.equal((camera_ ?? instances[0]).status, "lent");
    // The same consent file again: the camera has moved on.
    await a.getByRole("link", { name: "Home" }).click();
    await a.getByRole("link", { name: "Open a proposal or consent file" }).click();
    await a.getByLabel("Proposal or consent file").setInputFiles(consent);
    await a.getByText("The thing has moved on since this consent: ask again.").waitFor();

    for (const p of people) {
      assert.deepEqual(p.violations, [], `${p.name}: no CSP violation or script error`);
    }
    console.log("console consent browser test: passed");
  } catch (error) {
    if (current) {
      console.error(`${current.name}'s page ${current.page.url()}:\n` +
                    `${await current.page.locator("main").innerText().catch(() => "")}`);
    }
    throw error;
  } finally {
    await browser.close();
    for (const p of people) {
      try {
        p.run("console", "stop");
      } catch {
        // Not running: nothing to stop.
      }
      p.process.kill();
    }
    fs.rmSync(work, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
