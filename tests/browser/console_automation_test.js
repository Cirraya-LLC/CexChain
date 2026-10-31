// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// Automation, action links, and a phone, in real browsers. Alice sets up a
// console, deploys rules for checking a room in person, and creates a room.
// She adds an executor (its device, then, signed by the organization, what
// it may do: answer notify requests under those rules) and takes its key
// once, encrypted with a passphrase, with its token and config; then an AI
// agent answering to her, with its MCP setup. She makes a link (and a QR
// code) to the room's "check" action and invites Bob, who registers a
// passkey on his phone; she approves him. On the phone, Bob opens the link
// and checks the room with a tap; the page fits the phone's screen.
// Usage: node console_automation_test.js CEXCHAIN
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const cexchain = path.resolve(process.argv[2]);
const work = fs.mkdtempSync(path.join(os.tmpdir(), "cexchain-automation-"));

const visits = `contract Visits
parties owner

thing Room
  name text
  holder owner

can check by owner
  requires in person
  active -> checked
can reopen by owner
  checked -> active
`;

function freePort() {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function personIn(browser, name, options = {}) {
  const context = await browser.newContext({ locale: "en-GB", acceptDownloads: true, ...options });
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
  return { name, page, violations };
}

async function tap(page, what) {
  await page.getByRole("heading", { name: "Approve with your passkey" }).waitFor();
  await page.getByText("Checked in this browser").waitFor();
  if (what) await page.getByText(what, { exact: true }).first().waitFor();
  await page.getByRole("button", { name: "Approve with your passkey" }).click();
}

(async () => {
  const port = await freePort();
  const ledger = path.join(work, "ledger");
  const env = { ...process.env, CEXCHAIN_LEDGER: ledger, CEXCHAIN_NO_BROWSER: "1", HOME: work };
  const run = (...args) => execFileSync(cexchain, args, { cwd: work, env, encoding: "utf8" });
  const console_ = spawn(cexchain, ["console", "run", "--port", String(port), "--quiet"], { cwd: work, env });
  for (let i = 0; i < 300 && !fs.existsSync(path.join(ledger, "console", "setup-link")); i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
  const browser = await chromium.launch();
  const people = [];
  let current;
  try {
    const alice = await personIn(browser, "Alice");
    people.push(alice);
    current = alice;
    const a = alice.page;
    await a.goto(fs.readFileSync(path.join(ledger, "console", "setup-link"), "utf8").trim());
    await a.getByLabel("Your name").fill("Alice");
    await a.getByRole("button", { name: "Create my passkey" }).click();
    await a.getByRole("heading", { name: "Your recovery code" }).waitFor();
    await a.getByLabel("I have printed or saved my recovery code").check();
    await a.getByRole("button", { name: "Continue" }).click();
    await a.getByRole("button", { name: "Not now" }).click();
    await a.getByRole("heading", { name: "Home" }).waitFor();

    // The rules, and a room under them.
    const source = path.join(work, "visits.bo");
    fs.writeFileSync(source, visits);
    await a.getByRole("link", { name: "Rules" }).click();
    await a.getByRole("link", { name: "Write rules" }).click();
    await a.getByLabel("Open a file").setInputFiles(source);
    await a.getByLabel("Name of the rules").waitFor();
    await a.getByRole("button", { name: "Deploy" }).click();
    await tap(a, "Deploy rules");
    await a.getByRole("button", { name: "Back to the rules" }).click();
    await a.getByRole("link", { name: "Create a thing under Visits" }).click();
    await a.getByLabel("name", { exact: true }).fill("Room 101");
    await a.getByRole("button", { name: "Prepare" }).click();
    await tap(a);
    await a.getByRole("button", { name: "Open the thing" }).click();
    await a.getByRole("heading", { name: "Visits", level: 1 }).waitFor();
    const room = a.url().match(/instance\/([0-9a-f]{64})/)[1];

    // A link to its check, with a QR code.
    await a.getByRole("button", { name: "Link to check" }).click();
    const link = await a.getByLabel("The link to check").inputValue();
    assert.ok(link.endsWith(`#/act/${room}/check`), link);
    const qr = a.getByRole("img", { name: "QR code for check" });
    await qr.waitFor();
    assert.ok(await qr.evaluate((img) => img.complete && img.naturalWidth > 0), "the QR code is drawn");

    // An executor: its device, then (signed by the organization) its work.
    await a.getByRole("link", { name: "Automation" }).click();
    await a.getByRole("heading", { name: "Automation", level: 1 }).waitFor();
    await a.getByLabel("Name", { exact: true }).first().fill("notifier");
    await a.getByLabel("Request kinds it answers").fill("notify");
    await a.getByRole("button", { name: "Add an executor" }).click();
    await a.getByText("Step 1 of 2").waitFor();
    await tap(a, "Register a machine");
    await a.getByText("Step 2 of 2").waitFor();
    await a.getByText(/^the organization, with its root key/).waitFor();
    await tap(a, "Grant what they may do");
    await a.getByRole("heading", { name: "Set up notifier" }).waitFor();
    await a.getByLabel("Passphrase for its key").fill("notifier passphrase");
    await a.getByRole("button", { name: "Get its key and token" }).click();
    const saving = a.waitForEvent("download");
    saving.catch(() => {});
    await a.getByRole("button", { name: "Save notifier.key" }).click();
    const keyFile = path.join(work, "notifier.key");
    await (await saving).saveAs(keyFile);
    assert.match(await a.getByLabel("Its API token (notifier):").inputValue(), /^cxt_/);
    const config = JSON.parse(await a.getByLabel("Its config for executor run:").inputValue());
    fs.writeFileSync(path.join(work, "pass.txt"), "notifier passphrase\n");
    const shown = JSON.parse(run("key", "show", keyFile, "--passphrase-file", path.join(work, "pass.txt"), "--json"));
    const actor = JSON.parse(run("actor", "show", config.actor, "--json"));
    assert.equal(shown.public_key.key, actor.key.key, "the key handed out is the executor's");
    assert.equal(actor.kind, "device");
    const executors = JSON.parse(run("executor", "list", "--json"));
    assert.ok(JSON.stringify(executors).includes(config.actor), "listed as an executor");

    // An AI agent answering to Alice, with its MCP setup.
    await a.getByRole("button", { name: "Automation" }).click();
    await a.getByRole("heading", { name: "Automation", level: 1 }).waitFor();
    await a.locator("#agent-name").fill("helper");
    await a.getByLabel("Model", { exact: true }).fill("test-model");
    await a.getByRole("button", { name: "Add an AI agent" }).click();
    await tap(a, "Register a machine");
    await tap(a, "Grant what they may do");
    await a.getByLabel("Passphrase for its key").fill("helper passphrase");
    await a.getByRole("button", { name: "Get its key and token" }).click();
    const mcp = JSON.parse(await a.getByLabel("For an MCP client:").inputValue());
    assert.equal(mcp.mcpServers.cexchain.args[0], "mcp");
    await a.getByRole("button", { name: "Automation" }).click();
    await a.getByRole("cell", { name: "AI agent" }).waitFor();
    await a.getByRole("cell", { name: "Alice" }).first().waitFor();

    // Bob, on his phone: a passkey from the invitation; Alice approves him.
    await a.getByRole("link", { name: "People" }).click();
    await a.getByRole("heading", { name: "People", level: 1 }).waitFor();
    await a.getByLabel("Name", { exact: true }).fill("Bob");
    await a.getByRole("button", { name: "Make an invitation link" }).click();
    const invitation = await a.getByLabel("The invitation for Bob:").inputValue();
    const bob = await personIn(browser, "Bob", { viewport: { width: 390, height: 844 }, isMobile: true,
                                                 hasTouch: true, deviceScaleFactor: 3 });
    people.push(bob);
    current = bob;
    const b = bob.page;
    await b.goto(invitation);
    await b.getByLabel("Your name").fill("Bob");
    await b.getByRole("button", { name: "Register a passkey" }).click();
    await b.getByRole("heading", { name: "Home" }).waitFor();
    current = alice;
    await a.reload();
    await a.getByRole("button", { name: "Approve Bob" }).click();
    await a.getByRole("button", { name: "Approve (3 taps)" }).click();
    for (const i of [1, 2, 3]) {
      await a.getByText(`Step ${i} of 3`).waitFor();
      await tap(a);
    }
    await a.getByRole("heading", { name: "Done" }).waitFor();

    // The link, opened on the phone: the room's check, with Bob's tap.
    current = bob;
    await b.goto(link);
    const check = b.getByRole("region", { name: "check" });
    await check.waitFor();
    assert.ok(await check.evaluate((s) => s.classList.contains("focused")), "the action the link names");
    await check.getByRole("button", { name: "Prepare" }).click();
    await b.getByRole("heading", { name: "Approve with your passkey" }).waitFor();
    const approve = b.getByRole("button", { name: "Approve with your passkey" });
    const box = await approve.boundingBox();
    assert.ok(box.height >= 44, `a target of ${box.height} px`);
    assert.ok(await b.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1),
              "nothing wider than the phone");
    await tap(b);
    await b.getByRole("heading", { name: "Done" }).waitFor();
    const instances = JSON.parse(run("contract", "instances", "--json"));
    const list = Array.isArray(instances) ? instances : instances.instances;
    assert.equal(list.find((i) => JSON.stringify(i).includes(room))?.status ?? list[0].status, "checked");

    for (const p of people) {
      assert.deepEqual(p.violations, [], `${p.name}: no CSP violation or script error`);
    }
    console.log("console automation browser test: passed");
  } catch (error) {
    if (current) {
      console.error(`${current.name}'s page ${current.page.url()}:\n` +
                    `${await current.page.locator("main").innerText().catch(() => "")}`);
      console.error(current.violations.join("\n"));
      if (process.env.SHOT) {
        await current.page.screenshot({ path: process.env.SHOT, fullPage: true }).catch(() => {});
      }
    }
    throw error;
  } finally {
    await browser.close();
    try {
      run("console", "stop");
    } catch {
      // Not running: nothing to stop.
    }
    console_.kill();
    fs.rmSync(work, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
