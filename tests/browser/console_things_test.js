// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// Things with rules in a real browser, on one console. One person deploys
// rules that make a request, creates a thing under them from a form drawn
// from the contract, acts on it, and answers its request by hand: each call
// run on the ledger's state first, checked in this browser, and approved with
// a passkey; the thing's page shows its state, its fields in words, and its
// history in person. Its proof verifies with `cexchain contract verify` and
// in the Verify screen. A value that does not fit is shown on its field; a
// loan needs the friend's consent, and the page says so before any tap; and
// the rules editor's draft survives a reload.
// Usage: node console_things_test.js CEXCHAIN [SOURCE_DIR]
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
const sync = path.join(source, "tests", "bo", "golden", "form", "requests", "source.bo");
const lending = path.join(source, "examples", "lending", "lending.bo");
const work = fs.mkdtempSync(path.join(os.tmpdir(), "cexchain-things-"));
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
  const port = await freePort();
  const consoleProcess = spawn(cexchain, ["console", "run", "--port", String(port), "--quiet"],
                               { cwd: work, env });
  let browser;
  const violations = [];
  let page;
  try {
    await waitRunning();
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

    await page.goto(setup);
    await page.getByLabel("Your name").fill("Alice");
    await page.getByRole("button", { name: "Create my passkey" }).click();
    await page.getByRole("heading", { name: "Your recovery code" }).waitFor();
    await page.getByLabel("I have printed or saved my recovery code").check();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Not now" }).click();
    await page.getByRole("heading", { name: "Home" }).waitFor();
    const ledgerId = JSON.parse(run("status", "--json")).ledger_id;

    const tap = async (what) => {
      await page.getByRole("heading", { name: "Approve with your passkey" }).waitFor();
      await page.getByText("Checked in this browser").waitFor();
      if (what) await page.getByText(what, { exact: true }).first().waitFor();
      await page.getByRole("button", { name: "Approve with your passkey" }).click();
      await page.getByRole("heading", { name: "Done" }).waitFor();
    };
    const deploy = async (file) => {
      await page.getByRole("link", { name: "Rules" }).click();
      await page.getByRole("link", { name: "Write rules" }).click();
      await page.getByLabel("Open a file").setInputFiles(file);
      await page.getByLabel("Name of the rules").waitFor();
      await page.getByRole("button", { name: "Deploy" }).click();
      await tap("Deploy rules");
      await page.getByRole("button", { name: "Back to the rules" }).click();
      await page.getByRole("heading", { name: "Rules", level: 1 }).waitFor();
    };

    // The rules editor's draft survives a reload.
    await page.getByRole("link", { name: "Rules" }).click();
    await page.getByRole("link", { name: "Write rules" }).click();
    await page.getByLabel("Name of the rules").fill("Draft");
    await page.reload();
    await page.getByLabel("Name of the rules").waitFor();
    assert.equal(await page.getByLabel("Name of the rules").inputValue(), "Draft");

    // Rules that make a request, deployed; a thing created under them.
    await deploy(sync);
    await page.getByRole("link", { name: "Create a thing under Sync" }).click();
    await page.getByRole("heading", { name: "A new thing under Sync" }).waitFor();
    await page.getByLabel("note", { exact: true }).fill("first");
    assert.match(await page.locator('[data-name="we"] select option:checked').textContent(), /^this ledger/);
    // A value that does not fit is shown on its field.
    await page.getByLabel("partner", { exact: true }).selectOption("other");
    await page.getByLabel("Ledger id for partner").fill("xyz");
    await page.getByRole("button", { name: "Prepare" }).click();
    await page.getByText("Some values do not fit: see the fields marked.").waitFor();
    await page.locator('[data-name="partner"] .problem')
      .getByText("Error: A ledger id is 64 hexadecimal digits.").waitFor();
    await page.getByLabel("Ledger id for partner").fill("2".repeat(64));
    await page.getByRole("button", { name: "Prepare" }).click();
    await tap("Act under rules");
    await page.getByRole("button", { name: "Open the thing" }).click();
    await page.getByRole("heading", { name: "Sync", level: 1 }).waitFor();
    await page.getByRole("heading", { name: "What it holds" }).waitFor();
    await page.getByText(/first/).first().waitFor();

    // An action that asks for work outside the ledger, then its answer by hand.
    await page.getByRole("region", { name: "share" }).getByRole("button", { name: "Prepare" }).click();
    await tap("share");
    await page.getByRole("button", { name: "Open the thing" }).click();
    await page.getByRole("heading", { name: "Waiting for an answer" }).waitFor();
    await page.getByRole("heading", { name: "Request: sync" }).waitFor();
    await page.getByRole("button", { name: "Answer sync: done" }).click();
    await tap("Done");
    await page.getByRole("button", { name: "Open the thing" }).click();
    await page.getByRole("heading", { name: "History" }).waitFor();
    const history = page.locator("ol.events li");
    assert.equal(await history.count(), 3);
    for (let i = 0; i < 3; i++) {
      assert.match(await history.nth(i).textContent(), /by Alice in person/);
    }
    const instances = JSON.parse(run("contract", "instances", "--json"));
    const list = Array.isArray(instances) ? instances : instances.instances;
    assert.equal(list.length, 1);
    assert.equal(list[0].status, "synced");

    // Its proof: every call, verified offline and in this browser.
    const proving = page.waitForEvent("download");
    await page.getByRole("button", { name: "Share proof" }).click();
    const proof = path.join(work, "proof.cbor");
    await (await proving).saveAs(proof);
    const verified = run("contract", "verify", proof, "--ledger-id", ledgerId);
    assert.match(verified, /rebuilds/);
    await page.getByRole("link", { name: "Verify" }).click();
    await page.locator("#verify-proof").setInputFiles(proof);
    await page.getByLabel("Expected ledger id (optional)").fill(ledgerId);
    await page.getByLabel("Expected ledger id (optional)").dispatchEvent("change");
    await page.getByText("Verified", { exact: true }).waitFor();

    // A loan needs the friend's consent: said before any tap.
    await deploy(lending);
    await page.getByRole("link", { name: "Create a thing under Lending" }).click();
    await page.getByLabel("name", { exact: true }).fill("Camera X100");
    await page.getByRole("button", { name: "Prepare" }).click();
    await tap();
    await page.getByRole("button", { name: "Open the thing" }).click();
    await page.getByRole("heading", { name: "Lending", level: 1 }).waitFor();
    const lend = page.getByRole("region", { name: "lend" });
    await lend.getByLabel("counterparty", { exact: true }).selectOption("other");
    await lend.getByLabel("Ledger id for counterparty").fill("7".repeat(64));
    await lend.getByRole("button", { name: "Prepare" }).click();
    await lend.getByText(/This needs the consent of another ledger \(777777777777\.\.\.\)/).waitFor();

    // In Chinese.
    await page.locator("#language").selectOption("zh-Hant-HK");
    await page.getByRole("heading", { name: "可做的事" }).waitFor();
    await page.locator("#language").selectOption("en");

    assert.deepEqual(violations, [], "no CSP violation or script error");
    console.log("console things browser test: passed");
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
