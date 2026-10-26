// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// One person's first run, in a real browser: on an empty directory, the
// setup link leads through a name and a passkey, the recovery sheet, and the
// backup folder to Home, in under ten clicks. Then Settings; then the
// laptop's passkey is lost, and the recovery code registers a new one on
// another device (another virtual authenticator), after which the lost one
// signs in no more.
// Usage: node console_first_run_test.js CEXCHAIN
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const cexchain = path.resolve(process.argv[2]);
const work = fs.mkdtempSync(path.join(os.tmpdir(), "cexchain-first-run-"));
const ledger = path.join(work, "ledger");
// The console suggests a backup folder in the home folder: this test's.
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

/// A device: a browser context with its own virtual authenticator.
async function device(browser, violations) {
  const context = await browser.newContext({ locale: "en-GB", acceptDownloads: true });
  const page = await context.newPage();
  page.on("console", (m) => {
    if (/Content Security Policy|Refused to/.test(m.text())) violations.push(m.text());
  });
  page.on("pageerror", (e) => violations.push(String(e)));
  if (process.env.CONSOLE_TEST_LOG) {
    page.on("response", (r) => {
      if (r.url().includes("/console/api/")) console.log(`${r.status()} ${r.request().method()} ${r.url()}`);
    });
  }
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  pages.push(page);
  return { context, page };
}

/// Every device's page, to show what each one says when a step fails.
const pages = [];

const slotKinds = () =>
  JSON.parse(run("console", "key", "list", "--json")).slots.map((s) => s.kind).sort();

(async () => {
  const port = await freePort();
  const start = () =>
    spawn(cexchain, ["console", "run", "--port", String(port), "--quiet"], { cwd: work, env });
  let consoleProcess = start();
  let browser;
  try {
    await waitRunning();
    const base = `http://localhost:${port}/console/`;
    const setup = fs.readFileSync(path.join(ledger, "console", "setup-link"), "utf8").trim();
    assert.ok(setup.startsWith(base + "#/enroll/cxi_"));

    browser = await chromium.launch();
    const violations = [];
    const laptop = await device(browser, violations);
    const page = laptop.page;
    let clicks = 0;
    const click = async (locator) => {
      clicks += 1;
      await locator.click();
    };

    // Step 1: a name and a passkey.
    await page.goto(setup);
    await page.getByRole("heading", { name: "Set up your console" }).waitFor();
    await page.getByText("Step 1 of 3").waitFor();
    await page.getByLabel("Your name").fill("Alice");
    await click(page.getByRole("button", { name: "Create my passkey" }));

    // Step 2: the recovery sheet, shown once; going on needs it kept.
    await page.getByRole("heading", { name: "Your recovery code" }).waitFor();
    const code = (await page.locator("#recovery-code").textContent()).trim();
    assert.match(code, /^[A-Z2-7]{4}(-[A-Z2-7]{4}){5}-[A-Z2-7]{2}$/);
    await click(page.getByRole("button", { name: "Continue" }));
    await page.getByText("Print or save the code first").waitFor();
    const downloading = page.waitForEvent("download");
    await click(page.getByRole("button", { name: "Save as a file" }));
    const sheet = path.join(work, "sheet.txt");
    await (await downloading).saveAs(sheet);
    const sheetText = fs.readFileSync(sheet, "utf8");
    assert.ok(sheetText.includes(code), "the saved sheet holds the code");
    assert.ok(sheetText.includes("Alice"), "and the organization");
    await click(page.getByLabel("I have printed or saved my recovery code"));
    await click(page.getByRole("button", { name: "Continue" }));

    // Step 3: the backup folder, suggested in the home folder.
    await page.getByRole("heading", { name: "Where should backups go?" }).waitFor();
    const suggested = path.join(work, "CexChain backups");
    assert.equal(await page.getByLabel("Backup folder").inputValue(), suggested);
    await click(page.getByRole("button", { name: "Use this folder" }));

    // Home: the ledger is made, served, and unlocked.
    await page.getByRole("heading", { name: "Home" }).waitFor();
    await page.getByText("Signed in as Alice (owner)").waitFor();
    await page.getByRole("definition").filter({ hasText: /^Alice$/ }).waitFor();
    assert.equal(await page.getByText("This console is locked").count(), 0);
    // A passkey that gave no PRF output when it was made needs one sign-in
    // to unlock the console after a restart; the page offers it.
    if (await page.getByText("does not unlock this console yet").count()) {
      await click(page.getByRole("button", { name: "Sign in with my passkey" }));
      await page.getByText("does not unlock this console yet").waitFor({ state: "detached" });
    }
    assert.ok(clicks < 10, `the first run took ${clicks} clicks`);
    console.log(`first run to Home: ${clicks} clicks`);
    assert.deepEqual(slotKinds(), ["passkey", "recovery"]);
    const keys = JSON.parse(run("console", "key", "list", "--json")).keys.map((k) => k.name).sort();
    assert.deepEqual(keys, ["log", "owner", "root"]);
    const settings = JSON.parse(run("console", "settings", "show", "--json"));
    assert.equal(settings.backup_folder, suggested);
    assert.ok(fs.statSync(suggested).isDirectory());
    const people = JSON.parse(run("console", "user", "list", "--json"));
    assert.equal(people.users.length, 1);
    assert.equal(people.users[0].role, "owner");

    // After a restart, signing in with the passkey unlocks the console.
    run("console", "stop");
    consoleProcess = start();
    await waitRunning();
    await page.goto(base);
    await page.getByRole("button", { name: "Sign in with a passkey" }).click();
    await page.getByRole("heading", { name: "Home" }).waitFor();
    await page.getByRole("definition").filter({ hasText: /^Alice$/ }).waitFor();
    assert.equal(await page.getByText("This console is locked").count(), 0);

    // Settings: the ledger, and the language new browsers start in.
    await page.getByRole("link", { name: "Settings" }).click();
    await page.getByRole("heading", { name: "Settings" }).waitFor();
    await page.getByText(/^[0-9a-f]{64}$/).waitFor();
    assert.equal(await page.getByLabel("Backup folder").inputValue(), suggested);
    await page.getByLabel("Language for new browsers").selectOption("zh-Hans-CN");
    await page.getByRole("button", { name: "Save" }).click();
    await page.getByText("Saved.").waitFor();
    assert.equal(JSON.parse(run("console", "settings", "show", "--json")).language, "zh-Hans-CN");
    const fresh = await browser.newContext({ locale: "en-GB" });
    const freshPage = await fresh.newPage();
    await freshPage.goto(base);
    await freshPage.getByRole("heading", { name: "登录" }).waitFor();
    await fresh.close();
    await page.getByLabel("Language for new browsers").selectOption("");
    await page.getByRole("button", { name: "Save" }).click();
    await page.getByText("Saved.").waitFor();
    assert.equal(JSON.parse(run("console", "settings", "show", "--json")).language, null);
    // Locked from Settings, then unlocked with the recovery code.
    await page.getByRole("button", { name: "Lock now" }).click();
    await page.getByText("This console is locked").waitFor();
    await page.getByLabel("Passphrase or recovery code").fill(code);
    await page.getByRole("button", { name: "Unlock" }).click();
    await page.getByText("Unlocked.", { exact: true }).waitFor();

    // The laptop's passkey is lost: on a phone, the recovery code and a new
    // passkey.
    const phone = await device(browser, violations);
    await phone.page.goto(base);
    await phone.page.getByRole("heading", { name: "Sign in" }).waitFor();
    await phone.page.getByRole("link", { name: "Lost your passkey?" }).click();
    await phone.page.getByRole("heading", { name: "Recover with your recovery code" }).waitFor();
    await phone.page.getByLabel("Recovery code").fill("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA");
    await phone.page.getByRole("button", { name: "Create a new passkey" }).click();
    await phone.page.getByText("That is not this console's recovery code.").waitFor();
    // Typed as people type: lower case, spaces for dashes.
    await phone.page.getByLabel("Recovery code").fill(code.toLowerCase().replace(/-/g, " "));
    await phone.page.getByLabel("This device's name (optional)").fill("phone");
    await phone.page.getByRole("button", { name: "Create a new passkey" }).click();
    await phone.page.getByRole("heading", { name: "Home" }).waitFor();
    await phone.page.getByText("Your new passkey is now the only one").waitFor();
    if (await phone.page.getByText("does not unlock this console yet").count()) {
      await phone.page.getByRole("button", { name: "Sign in with my passkey" }).click();
      await phone.page.getByText("does not unlock this console yet").waitFor({ state: "detached" });
    }
    // The console and the ledger know only the phone's passkey.
    const after = JSON.parse(run("console", "user", "list", "--json")).users[0];
    assert.equal(after.passkeys.length, 1);
    assert.equal(after.passkeys[0].label, "phone");
    assert.deepEqual(slotKinds(), ["passkey", "recovery"]);
    // The laptop's session ended, and its passkey signs in no more.
    await page.reload();
    await page.getByRole("heading", { name: "Sign in" }).waitFor();
    await page.getByRole("button", { name: "Sign in with a passkey" }).click();
    await page.getByText("the passkey did not sign in").waitFor();

    // After a restart, the phone's passkey unlocks the console.
    run("console", "stop");
    consoleProcess = start();
    await waitRunning();
    await phone.page.goto(base);
    await phone.page.getByRole("button", { name: "Sign in with a passkey" }).click();
    await phone.page.getByRole("heading", { name: "Home" }).waitFor();
    await phone.page.getByRole("definition").filter({ hasText: /^Alice$/ }).waitFor();
    assert.equal(await phone.page.getByText("This console is locked").count(), 0);

    assert.deepEqual(violations, [], "no CSP violation or script error");
    console.log("console first-run browser test: passed");
  } catch (error) {
    for (const p of pages) {
      const text = await p.locator("main").innerText().catch(() => "(closed)");
      console.error(`page ${p.url()}:\n${text}\n`);
    }
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
