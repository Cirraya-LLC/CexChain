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
// acknowledged. Then Bob asks only whether the photo was taken before 2027:
// Alice's console checks it in the record, she answers with a tap, and Bob
// reads the answer verified, the day never shown, and acknowledges it. And
// each console witnesses the other's ledger: it follows it from its genesis
// and cosigns its checkpoints.
// Usage: node console_access_test.js KANHE
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const kanhe = path.resolve(process.argv[2]);
// The programs beside kanhe: a command line's first word may name one.
const programOf = (args) =>
  ["bo", "kanhe-console", "kanhe-index"].includes(args[0])
    ? [path.join(path.dirname(kanhe), args[0]), args.slice(1)]
    : [kanhe, args];
const work = fs.mkdtempSync(path.join(os.tmpdir(), "kanhe-access-"));

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
  const env = { ...process.env, KANHE_LEDGER: ledger, KANHE_NO_BROWSER: "1",
                HOME: path.dirname(ledger) };
  const run = (...args) => execFileSync(...programOf(args), { cwd: work, env, encoding: "utf8" });
  const port = await freePort();
  const process_ = spawn(...programOf(["kanhe-console", "run", "--port", String(port), "--quiet"]),
                         { cwd: work, env });
  for (let i = 0; i < 300; i++) {
    try {
      if (JSON.parse(run("kanhe-console", "status", "--json")).running) break;
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
  return { name, page, run, process: process_, violations, id, ledger };
}

/// Approves what the page shows, checked in the browser, with the passkey.
async function tap(page, what) {
  await page.getByRole("heading", { name: "Approve with your passkey" }).waitFor();
  await page.getByText("Checked in this browser").waitFor();
  if (what) await page.getByText(what, { exact: true }).first().waitFor();
  await page.getByRole("button", { name: "Approve with your passkey" }).click();
  await page.getByRole("heading", { name: "Done" }).waitFor();
}

/// Has the console ask its parties now, as Home does when it opens.
async function poll(page) {
  const answered = page.waitForResponse((r) => r.url().includes("api/inbox?refresh=1"),
                                        { timeout: 60000 });
  await page.evaluate(() => { location.hash = location.hash === "#/" ? "#/home" : "#/"; });
  await answered;
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
    alice.run("kanhe-console", "kind", "add", sheet);
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
    // The screen asks for documents and asks questions: two forms alike.
    await b.locator("#access-party").selectOption("alice");
    await b.locator("#access-record").fill(record);
    await b.locator("#access-purpose").fill("insurance claim");
    await b.getByLabel("Fields", { exact: true }).fill("place");
    await b.getByRole("button", { name: "Ask with your passkey" }).first().click();
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

    // Bob asks only whether the photo was taken before 2027.
    current = bob;
    await b.getByRole("link", { name: "Parties" }).click();
    await b.getByRole("heading", { name: "Ask whether a condition holds" }).waitFor();
    await b.locator("#question-party").selectOption("alice");
    await b.locator("#question-record").fill(record);
    await b.locator("#question-purpose").fill("insurance check");
    await b.getByLabel("Field of condition 1").fill("taken");
    await b.getByLabel("Comparison of condition 1").selectOption("<");
    await b.getByLabel("Value of condition 1").fill("2027-01-01");
    await b.getByRole("button", { name: "Ask with your passkey" }).nth(1).click();
    await tap(b, "Ask whether a condition holds");
    await b.getByText("Sent to alice. Their answer shows on Home once they give it.").waitFor();

    // Alice's console checks it in the photo's record; she answers with a tap.
    current = alice;
    await a.getByRole("link", { name: "Home" }).click();
    await until(a, a.getByText("bob asks whether taken is below 2027-01-01: insurance check"));
    await a.getByRole("link", { name: "Look at what bob asks" }).click();
    await a.getByRole("heading", { name: "bob asks whether a condition holds" }).waitFor();
    await a.getByText("As the document stands, this holds.").waitFor();
    await a.getByLabel("About whom or what").fill("the harbour photo");
    await a.getByRole("button", { name: "Answer with your passkey" }).click();
    await tap(a, "Answer a question");
    await a.getByText("Answered: bob fetches the answer from here.").waitFor();

    // Bob reads the answer, verified, without the day, and acknowledges it.
    current = bob;
    await b.getByRole("link", { name: "Home" }).click();
    await until(b, b.getByText("alice answered your question: insurance check"));
    await b.getByText("alice answered your question: insurance check")
      .getByRole("link").click();
    await b.getByRole("heading", { name: "alice's answer" }).waitFor();
    await b.getByText("Verified: Alice confirms that taken is below 2027-01-01.").waitFor();
    await b.getByText("the harbour photo").waitFor();
    assert.equal(await b.getByText("2026-10-16").count(), 0, "the day stays with Alice");
    await b.getByRole("button", { name: "Accept with your passkey" }).click();
    await tap(b, "Acknowledge a delivery");
    await b.getByText("Accepted: the receipt went to alice.").waitFor();
    current = alice;
    await a.getByRole("link", { name: "Parties" }).click();
    const answeredTable = a.getByRole("table", { name: "Answered for them" });
    await until(a, answeredTable.getByRole("cell", { name: "Acknowledged" }));
    const answers = JSON.parse(alice.run("access", "list", "--json")).filter((r) => r.kind === "answer");
    assert.equal(answers.length, 1);
    assert.equal(answers[0].holds, true);
    assert.equal(answers[0].acknowledged, true);

    // Each witnesses the other: Alice follows Bob's ledger and asks him to
    // cosign hers, Bob does the same, and each cosigns the other's checkpoint.
    await poll(a);
    await poll(b);
    await poll(a);
    for (const p of [alice, bob]) {
      current = p;
      await p.page.goto(p.page.url().replace(/#.*$/, "#/parties"));
      await p.page.reload();
      await p.page.getByRole("heading", { name: "Parties", level: 1 }).waitFor();
      assert.equal(await p.page.getByRole("cell", { name: /entries cosigned$/ }).count(), 2,
                   `${p.name}: witnessed and witnessing`);
      const followed = JSON.parse(p.run("witness", "status", "--dir",
                                        path.join(p.ledger, "console", "witness"), "--json"));
      assert.equal(followed.length, 1);
      assert.ok(followed[0].size > 0, `${p.name} cosigned the other's checkpoint`);
      assert.equal(followed[0].follows_rotations, true);
    }

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
        p.run("kanhe-console", "stop");
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
