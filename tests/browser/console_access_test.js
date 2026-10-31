// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// Documents between two consoles, in real browsers: Alice and Bob become
// parties with one code each way. Alice registers a photo (a place, the
// day, the file, kept). Bob asks her for it from his Parties screen with a
// tap, the request sent online. Alice's Home shows it asked of her; she
// shares the place and the photo, not the day, with a tap, and the delivery
// waits for Bob. Bob's console fetches it; he opens it, verified, saves the
// photo, and accepts it with a tap, the receipt sent back; Alice sees it
// acknowledged.
// Usage: node console_access_test.js CEXCHAIN
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const cexchain = path.resolve(process.argv[2]);
const work = fs.mkdtempSync(path.join(os.tmpdir(), "cexchain-access-"));

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

/// Reloads until `locator` shows (a poll or a peer's answer may come later).
async function until(page, locator, tries = 20) {
  for (let i = 0; i < tries; i++) {
    if (await locator.count() > 0) return;
    await new Promise((r) => setTimeout(r, 1000));
    await page.reload();
  }
  await locator.first().waitFor();
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
    const a = alice.page;
    const b = bob.page;

    // One code each way.
    current = alice;
    await a.getByRole("link", { name: "Parties" }).click();
    await a.getByRole("heading", { name: "Parties", level: 1 }).waitFor();
    await a.getByLabel("Their name here").first().fill("bob");
    await a.getByRole("button", { name: "Make an invitation code" }).click();
    const invitation = await a.getByLabel("The invitation for bob:").inputValue();
    current = bob;
    await b.getByRole("link", { name: "Parties" }).click();
    await b.getByLabel("Their code").fill(invitation);
    await b.getByLabel("Their name here").nth(1).fill("alice");
    await b.getByRole("button", { name: "Accept" }).click();
    await b.getByText(/^Connected with alice: Alice, fingerprint/).waitFor();
    const reply = await b.getByLabel("Send this code back to alice, so that they connect with you too:").inputValue();
    current = alice;
    await a.getByLabel("Their code").fill(reply);
    await a.getByLabel("Their name here").nth(1).fill("bob");
    await a.getByRole("button", { name: "Accept" }).click();
    await a.getByText(/^Connected with bob: Bob, fingerprint/).waitFor();

    // Alice's photo: a kind of hers (place, the day, a file kept), registered with a tap.
    const sheet = path.join(work, "photo-kind.json");
    fs.writeFileSync(sheet, JSON.stringify({
      sheet: 1, kind: "document", type: "example.org.photo/1", name: "Photo",
      fields: [{ name: "place", required: true }, { name: "taken", type: "date" }],
      files: "required" }));
    alice.run("console", "kind", "add", sheet);
    const photo = path.join(work, "photo.jpg");
    fs.writeFileSync(photo, "the photo itself, as bytes");
    await a.getByRole("link", { name: "Things" }).click();
    await a.getByRole("link", { name: "Register a document" }).click();
    await a.getByLabel("place (required)").fill("Victoria Harbour");
    await a.getByLabel("taken").fill("2026-10-16");
    await a.getByLabel("Files").setInputFiles(photo);
    await a.getByRole("button", { name: "Prepare" }).click();
    await tap(a);
    const record = (await a.locator("main p.id").textContent()).trim();
    assert.match(record, /^[0-9a-f]{64}$/);

    // Bob asks for it, with a tap: the request goes to Alice online.
    current = bob;
    await b.reload(); // still on Parties, from connecting: the same address does not reload
    await b.getByRole("heading", { name: "Ask for a document" }).waitFor();
    await b.getByLabel("Party", { exact: true }).selectOption("alice");
    await b.getByLabel("Document", { exact: true }).fill(record);
    await b.getByLabel("Why", { exact: true }).fill("insurance claim");
    await b.getByLabel("Fields", { exact: true }).fill("place");
    await b.getByRole("button", { name: "Ask with your passkey" }).click();
    await tap(b, "Ask for a document");
    await b.getByText("Sent to alice. It shows on Home once they share it.").waitFor();
    const requests = JSON.parse(bob.run("access", "list", "--json"));
    assert.deepEqual(requests.map((r) => r.kind), ["request"]);

    // Alice's Home: asked of her. She shares the place and the photo.
    current = alice;
    await a.getByRole("link", { name: "Home" }).click();
    await until(a, a.getByRole("heading", { name: "Asked of you" }));
    await a.getByRole("link", { name: "Look at what bob asks" }).click();
    await a.getByRole("heading", { name: "bob asks for a document" }).waitFor();
    await a.getByText("insurance claim").waitFor();
    assert.ok(await a.getByRole("checkbox", { name: "place" }).isChecked());
    assert.ok(await a.getByRole("checkbox", { name: /^taken/ }).isDisabled(), "the day was not asked");
    assert.ok(await a.getByRole("checkbox", { name: /^photo\.jpg/ }).isChecked());
    await a.getByRole("button", { name: "Grant with your passkey" }).click();
    await tap(a, "Share a document");
    await a.getByText("Delivered: bob fetches it from here.").waitFor();

    // Bob's console fetches it; he opens it, verified, saves the photo, accepts it.
    current = bob;
    await b.getByRole("link", { name: "Home" }).click();
    await until(b, b.getByRole("heading", { name: "Delivered to you" }));
    await b.getByRole("link", { name: "Open what alice shared" }).click();
    await b.getByRole("heading", { name: "What alice shared" }).waitFor();
    await b.getByText(/^Verified: Alice of Alice \(present: passkey\) granted it/).waitFor();
    await b.getByText("Victoria Harbour").waitFor();
    assert.equal(await b.getByText("2026-10-16").count(), 0, "the day stays with Alice");
    const saving = b.waitForEvent("download");
    saving.catch(() => {});
    await b.getByRole("button", { name: "Save photo.jpg" }).click();
    const saved = path.join(work, "saved.jpg");
    await (await saving).saveAs(saved);
    assert.equal(fs.readFileSync(saved, "utf8"), "the photo itself, as bytes");
    await b.getByRole("button", { name: "Accept with your passkey" }).click();
    await tap(b, "Acknowledge a delivery");
    await b.getByText("Accepted: the receipt went to alice.").waitFor();
    const kinds = JSON.parse(bob.run("access", "list", "--json")).map((r) => r.kind).sort();
    assert.deepEqual(kinds, ["receipt", "request"]);

    // Alice sees it acknowledged.
    current = alice;
    await a.getByRole("link", { name: "Parties" }).click();
    await until(a, a.getByRole("cell", { name: "Acknowledged" }));
    const grants = JSON.parse(alice.run("access", "list", "--json")).filter((r) => r.kind === "grant");
    assert.equal(grants.length, 1);
    assert.equal(grants[0].acknowledged, true);
    assert.deepEqual(grants[0].fields, ["place"]);

    for (const p of people) {
      assert.deepEqual(p.violations, [], `${p.name}: no CSP violation or script error`);
    }
    console.log("console access browser test: passed");
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
