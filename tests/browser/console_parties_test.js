// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// Two consoles become parties, then agree online, in real browsers: Alice
// invites Bob with a code, Bob accepts it and answers with his own, Alice
// accepts that. Alice lends her camera to Bob and proposes the loan online:
// her registrar holds it. Bob's Home shows it waiting for his consent; he
// reads it (verified against the camera's evidence, fetched from Alice's
// node), consents with a tap, and the consent goes to Alice's registrar,
// which records the loan. Then Alice asks a public witness to witness her
// ledger, by its address and key, and stops. With --relay, both consoles
// are reached only through a relay (a public witness's server): each adds
// the witness and chooses to be reached through it, their codes carry the
// relay and no address, and everything between them goes through it.
// Usage: node console_parties_test.js CEXCHAIN [SOURCE_DIR] [--relay]
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const cexchain = path.resolve(process.argv[2]);
const viaRelay = process.argv.includes("--relay");
const source = path.resolve(process.argv[3] && process.argv[3] !== "--relay" ? process.argv[3]
                                                                             : path.join(__dirname, "..", ".."));
const lending = path.join(source, "examples", "lending", "lending.bo");
const work = fs.mkdtempSync(path.join(os.tmpdir(), "cexchain-parties-"));

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

/// A public witness's server (with a relay), on its own ledger.
async function startWitness() {
  const witnessDir = path.join(work, "witness");
  fs.mkdirSync(witnessDir, { recursive: true });
  const witnessEnv = { ...process.env, CEXCHAIN_PASSPHRASE: "witness test" };
  const w = (...args) => execFileSync(cexchain, args, { cwd: witnessDir, env: witnessEnv,
                                                        encoding: "utf8" });
  for (const k of ["root", "log", "witness"]) w("key", "generate", "--out", `${k}.key`);
  w("init", "--ledger", "ledger", "--org", "Witness", "--root-key", "root.key",
    "--log-key", "log.key");
  const port = await freePort();
  const process_ = spawn(cexchain, ["serve", "--ledger", "ledger", "--listen", `127.0.0.1:${port}`,
                                    "--witness-dir", "state", "--witness-key", "witness.key",
                                    "--witness-public", "--witness-name", "test-witness",
                                    "--relay-dir", "mailboxes", "--quiet"],
                         { cwd: witnessDir, env: witnessEnv });
  const url = `http://127.0.0.1:${port}`;
  let info;
  for (let i = 0; i < 300 && !info; i++) {
    info = await fetch(`${url}/v1/witness`).then((r) => r.json()).catch(() => null);
    if (!info) await new Promise((r) => setTimeout(r, 100));
  }
  return { process: process_, url, key: info.key };
}

/// Adds the public witness on a console's Parties screen.
async function addWitness(page, witness) {
  await page.getByRole("link", { name: "Parties" }).click();
  await page.getByRole("heading", { name: "Public witnesses" }).waitFor();
  await page.getByLabel("Its address").fill(witness.url);
  await page.getByLabel("Its key").fill(witness.key);
  await page.getByRole("button", { name: "Ask it to witness this ledger" }).click();
  await page.getByText(/^test-witness cosigned this ledger at \d+ entries/).waitFor();
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
  let witness;
  try {
    const alice = await person(browser, "Alice");
    people.push(alice);
    const bob = await person(browser, "Bob");
    people.push(bob);
    const a = alice.page;
    const b = bob.page;

    if (viaRelay) {
      // Both reached only through the relay: the witness's server.
      witness = await startWitness();
      for (const p of [alice, bob]) {
        current = p;
        await addWitness(p.page, witness);
        await p.page.getByRole("heading", { name: "Reached through a relay" }).waitFor();
        await p.page.getByText("Parties reach this console directly, at its own address.").waitFor();
        await p.page.getByRole("button", { name: "Be reached through test-witness" }).click();
        await p.page.getByText("Parties now reach this console through test-witness. Give them a new invitation code.").waitFor();
        await p.page.getByText(`Parties reach this console through ${witness.url}.`).waitFor();
      }
    }

    // One code each way.
    current = alice;
    await a.getByRole("link", { name: "Parties" }).click();
    await a.getByRole("heading", { name: "Parties", level: 1 }).waitFor();
    await a.getByLabel("Their name here").first().fill("bob");
    await a.getByRole("button", { name: "Make an invitation code" }).click();
    const invitation = await a.getByLabel("The invitation for bob:").inputValue();
    assert.match(invitation, /^cxp_/);
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
    await a.reload();
    await a.getByRole("cell", { name: "bob", exact: true }).waitFor();
    if (viaRelay) {
      // The codes carried the relay, and no address on this computer.
      for (const [p, other] of [[alice, "bob"], [bob, "alice"]]) {
        const shown = JSON.parse(p.run("peer", "show", other, "--json"));
        assert.equal(shown.url, null, `${p.name} has no address for ${other}`);
        assert.equal(shown.relay.url, witness.url, `${p.name} reaches ${other} through the relay`);
      }
    }

    // Alice's camera, lent to Bob, proposed online.
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
    const camera = a.url().match(/instance\/([0-9a-f]{64})/)[1];
    const lend = a.getByRole("region", { name: "lend" });
    await lend.getByLabel("counterparty", { exact: true }).selectOption("other");
    await lend.getByLabel("Ledger id for counterparty").fill(bob.id);
    await lend.getByRole("button", { name: "Prepare" }).click();
    await lend.getByRole("button", { name: "Propose online" }).click();
    await lend.getByText(/^This ledger's registrar holds the call until/).waitFor();

    // Bob's Home: the loan waits for his consent; he reads it and consents.
    current = bob;
    await b.getByRole("link", { name: "Home" }).click();
    await b.getByRole("heading", { name: "Waiting for your consent" }).waitFor();
    await b.getByRole("button", { name: "Read lend from alice" }).click();
    await b.getByRole("heading", { name: "A proposal from Alice" }).waitFor();
    await b.getByText("Camera X100").first().waitFor();
    await b.getByRole("button", { name: "Consent with your passkey" }).click();
    await tap(b, "Consent to a call");
    await b.getByText("Sent to Alice: the call is recorded on their ledger.").waitFor();

    // Alice's camera is lent.
    current = alice;
    await a.reload();
    await a.getByRole("heading", { name: "History" }).waitFor();
    assert.ok(a.url().endsWith(`#/instance/${camera}`));
    assert.equal(await a.locator("ol.events li").count(), 2);
    const instances = JSON.parse(alice.run("contract", "instances", "--json"));
    assert.equal((Array.isArray(instances) ? instances : instances.instances)[0].status, "lent");

    if (!viaRelay) {
      // A public witness: Alice asks one, by its address and key, then stops.
      witness = await startWitness();
      current = alice;
      await addWitness(a, witness);
      assert.equal(JSON.parse(alice.run("witness", "registered", "--json")).witnesses.length, 1);
      await a.getByRole("button", { name: "Stop asking test-witness" }).click();
      await a.getByText("test-witness is no longer asked. What it cosigned stays valid.").waitFor();
      assert.equal(JSON.parse(alice.run("witness", "registered", "--json")).witnesses.length, 0);
    }

    for (const p of people) {
      assert.deepEqual(p.violations, [], `${p.name}: no CSP violation or script error`);
    }
    console.log(`console parties browser test${viaRelay ? " through a relay" : ""}: passed`);
  } catch (error) {
    if (current) {
      console.error(`${current.name}'s page ${current.page.url()}:\n` +
                    `${await current.page.locator("main").innerText().catch(() => "")}`);
    }
    throw error;
  } finally {
    await browser.close();
    witness?.process.kill();
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
