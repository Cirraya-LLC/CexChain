// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// The web console in a real browser: Chromium's virtual WebAuthn
// authenticator plays the person's passkey. The owner sets the console up
// from the setup link, signs out and in again, reads Home and Things in each
// language, by keyboard, with no Content-Security-Policy violation.
// Usage: node console_test.js CEXCHAIN
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const cexchain = path.resolve(process.argv[2]);
const work = fs.mkdtempSync(path.join(os.tmpdir(), "cexchain-console-"));
const env = { ...process.env, CEXCHAIN_PASSPHRASE: "console test", CEXCHAIN_LEDGER: path.join(work, "ledger") };
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
  for (const k of ["root", "log"]) run("key", "generate", "--out", k + ".key");
  const idFrom = (text) => text.match(/[0-9a-f]{64}/)[0];
  const ledgerId = idFrom(run("init", "--org", "Console Test Org", "--root-key", "root.key", "--log-key",
                              "log.key"));
  const record = idFrom(run("record", "issue", "--as", "root.key", "--type", "example.document/1",
                            "--field", "result=pass"));
  // Sealed keys: the console starts locked.
  fs.writeFileSync(path.join(work, "unlock.txt"), "the unlock passphrase of this test\n");
  run("console", "key", "init", "--unlock-file", "unlock.txt");

  const port = await freePort();
  const start = () => spawn(cexchain, ["console", "run", "--port", String(port), "--quiet"], { cwd: work, env });
  let consoleProcess = start();
  let browser;
  try {
    await waitRunning();
    const base = `http://localhost:${port}/console/`;
    const setup = JSON.parse(run("console", "setup-link", "--json")).link;
    assert.ok(setup.startsWith(base + "#/enroll/cxi_"));

    browser = await chromium.launch();
    const context = await browser.newContext({ locale: "en-GB" });
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

    // The setup link: the code leaves the address bar at once.
    await page.goto(setup);
    await page.getByRole("heading", { name: "Register your passkey" }).waitFor();
    assert.ok(!page.url().includes("cxi_"), "the code is taken out of the address");
    await page.getByLabel("Your name").fill("Alice");
    await page.getByLabel("This device's name (optional)").fill("test laptop");
    await page.getByRole("button", { name: "Register a passkey" }).click();
    await page.getByRole("heading", { name: "Home" }).waitFor();
    await page.getByText("Console Test Org").waitFor();
    await page.getByText("Signed in as Alice (owner)").waitFor();
    // Locked: the owner unlocks it with the passphrase.
    await page.getByText("This console is locked").waitFor();
    await page.getByLabel("Passphrase or recovery code").fill("not it");
    await page.getByRole("button", { name: "Unlock" }).click();
    await page.getByText("That does not unlock the console.").waitFor();
    await page.getByLabel("Passphrase or recovery code").fill("the unlock passphrase of this test");
    await page.getByRole("button", { name: "Unlock" }).click();
    await page.getByText("This console is locked").waitFor({ state: "detached" });
    await page.getByRole("heading", { name: "Home" }).waitFor();
    const people = JSON.parse(run("console", "user", "list", "--json"));
    assert.equal(people.users[0].name, "Alice");
    assert.equal(people.users[0].role, "owner");
    assert.equal(people.users[0].passkeys[0].label, "test laptop");

    // Things, reached by keyboard.
    await page.getByRole("link", { name: "Things" }).focus();
    await page.keyboard.press("Enter");
    await page.getByRole("heading", { name: "Things" }).waitFor();
    await page.getByRole("cell", { name: "example.document/1", exact: true }).waitFor();
    const snapshot = await page.locator("main").ariaSnapshot();
    assert.match(snapshot, /heading "Things" \[level=1\]/);
    assert.match(snapshot, /table "Records"/);
    assert.equal(await page.getByRole("link", { name: "Things" }).getAttribute("aria-current"), "page");

    // Signing out forgets the session; signing in takes the passkey again.
    await page.getByRole("button", { name: "Sign out" }).click();
    await page.getByRole("heading", { name: "Sign in" }).waitFor();
    assert.equal(JSON.parse(run("console", "status", "--json")).sessions, 0);
    await page.getByRole("button", { name: "Sign in with a passkey" }).click();
    await page.getByRole("heading", { name: "Home" }).waitFor();
    // Signed in while unlocked, the owner's passkey got a slot of its own...
    const slots = JSON.parse(run("console", "key", "list", "--json")).slots.map((x) => x.kind).sort();
    assert.deepEqual(slots, ["passkey", "passphrase", "recovery"]);
    // ...so after a restart, signing in with it unlocks the console.
    run("console", "stop");
    consoleProcess = start();
    await waitRunning();
    await page.goto(base);
    await page.getByRole("button", { name: "Sign in with a passkey" }).click();
    await page.getByRole("heading", { name: "Home" }).waitFor();
    assert.equal(await page.getByText("This console is locked").count(), 0);

    // Alice acts as a person of the ledger: her key sealed in the console,
    // her console passkey registered for her on the ledger, and a delegation
    // that requires her presence.
    run("key", "generate", "--out", "alice.key");
    const alice = idFrom(run("actor", "add", "--as", "root.key", "--kind", "person", "--name", "Alice",
                             "--key", "alice.key"));
    run("console", "key", "import", "alice", "alice.key");
    run("console", "user", "link", "Alice", "--actor", alice, "--key", "alice");
    run("console", "user", "passkeys", "Alice", "--out", "passkeys");
    run("actor", "set-presence", alice, "--as", "root.key", "--add", "--credential", "passkeys/Alice-1.passkey");
    run("delegation", "grant", "--as", "root.key", "--to", alice, "--allow", "record-endorse,record-revoke",
        "--days", "30", "--require-presence");

    // Prepared, then cancelled: nothing is signed.
    await page.getByRole("link", { name: "Things" }).click();
    await page.getByRole("button", { name: "Act on this example.document/1 record" }).click();
    await page.getByLabel("Role of the endorsement").fill("cancelled");
    await page.getByRole("button", { name: "Prepare" }).click();
    await page.getByRole("heading", { name: "Approve with your passkey" }).waitFor();
    await page.getByRole("button", { name: "Cancel" }).click();
    await page.getByRole("heading", { name: "Things" }).waitFor();

    // Prepared and approved with one tap.
    await page.getByRole("button", { name: "Act on this example.document/1 record" }).click();
    await page.getByLabel("Role of the endorsement").fill("reviewed");
    await page.getByRole("button", { name: "Prepare" }).click();
    await page.getByText("Endorse a record").waitFor();
    await page.getByText("reviewed").waitFor();
    await page.getByRole("button", { name: "Approve with your passkey" }).click();
    await page.getByRole("heading", { name: "Done" }).waitFor();
    const shown = JSON.parse(run("record", "show", record, "--json"));
    assert.deepEqual(shown.endorsements.map((e) => e.role), ["reviewed"]);

    // Anyone verifying the evidence sees Alice was present, verified, on this console.
    run("checkpoint", "create", "--log-key", "log.key");
    run("export", record, "--log-key", "log.key", "--out", "bundle.cbor");
    const report = JSON.parse(run("verify", "bundle.cbor", "--ledger-id", ledgerId, "--json"));
    assert.equal(report.verified, true);
    const present = report.events.filter((e) => e.presence);
    assert.equal(present.length, 1);
    assert.equal(present[0].presence.user_verified, true);
    assert.match(run("verify", "bundle.cbor", "--ledger-id", ledgerId), /present: passkey, user verified/);

    // The page in the other two languages, from its own catalogs.
    await page.getByRole("link", { name: "Home" }).click();
    await page.getByRole("heading", { name: "Home" }).waitFor();
    await page.getByLabel("Language").selectOption("zh-Hant-HK");
    await page.getByRole("heading", { name: "首頁" }).waitFor();
    assert.equal(await page.evaluate(() => document.documentElement.lang), "zh-Hant-HK");
    await page.getByLabel("語言").selectOption("zh-Hans-CN");
    await page.getByRole("heading", { name: "首页" }).waitFor();
    await page.getByRole("link", { name: "物件" }).click();
    await page.getByRole("heading", { name: "物件" }).waitFor();

    // A used setup link registers nothing more.
    await page.goto(setup);
    await page.getByRole("button", { name: "注册通行密钥" }).click();
    await page.getByRole("alert").waitFor();

    // On a phone's width, the page is one column and still reads.
    await page.setViewportSize({ width: 375, height: 800 });
    await page.goto(base);
    await page.getByRole("heading", { name: "首页" }).waitFor();

    assert.deepEqual(violations, [], "no CSP violation or script error");
    console.log("console browser test: passed");
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
