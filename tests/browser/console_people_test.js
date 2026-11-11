// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// A company's console on its own host name, in real browsers. The owner
// sets it up at https://ledger.example.test:PORT (the console serving TLS
// itself, with a certificate made here that the browser trusts by its key,
// and the name mapped to this computer), with passkeys for that host name,
// and invites Bob as a member. Bob, in another browser, registers
// a passkey for that host name from the link. The owner approves him with
// three taps, choosing in plain words that he may register photos. Bob
// registers one with his own tap, and manages no one. The owner withdraws
// what he may do, and his next registration is refused. Then an API token,
// shown once, and the console's activity log.
// Usage: node console_people_test.js KANHE
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const crypto = require("node:crypto");
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
const work = fs.mkdtempSync(path.join(os.tmpdir(), "kanhe-people-"));
const host = "ledger.example.test";

function freePort() {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

/// A browser context with a passkey of its own, and what goes wrong in it.
async function personIn(browser, name) {
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
  return { name, page, violations };
}

/// Approves what the page shows, checked in the browser, with the passkey.
async function tap(page, what) {
  await page.getByRole("heading", { name: "Approve with your passkey" }).waitFor();
  await page.getByText("Checked in this browser").waitFor();
  if (what) await page.getByText(what, { exact: true }).first().waitFor();
  await page.getByRole("button", { name: "Approve with your passkey" }).click();
}

(async () => {
  const port = await freePort();
  const origin = `https://${host}:${port}`;
  // A certificate for the host name; the browser trusts it by its key's hash.
  const cert = path.join(work, "cert.pem");
  const key = path.join(work, "key.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                           "-nodes", "-keyout", key, "-out", cert, "-days", "2", "-subj", `/CN=${host}`,
                           "-addext", `subjectAltName=DNS:${host}`], { stdio: "ignore" });
  const spki = crypto.createHash("sha256")
    .update(new crypto.X509Certificate(fs.readFileSync(cert)).publicKey.export({ type: "spki", format: "der" }))
    .digest("base64");
  const ledger = path.join(work, "ledger");
  const env = { ...process.env, KANHE_LEDGER: ledger, KANHE_NO_BROWSER: "1", HOME: work };
  const run = (...args) => execFileSync(...programOf(args), { cwd: work, env, encoding: "utf8" });
  const console_ = spawn(...programOf(["kanhe-console", "run", "--port", String(port), "--public-url", origin,
                                    "--tls-cert", cert, "--tls-key", key, "--quiet"]), { cwd: work, env });
  for (let i = 0; i < 300 && !fs.existsSync(path.join(ledger, "console", "setup-link")); i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
  const browser = await chromium.launch({ args: [`--host-resolver-rules=MAP ${host} 127.0.0.1`,
                                                  `--ignore-certificate-errors-spki-list=${spki}`] });
  const people = [];
  let current;
  try {
    // The owner's first run, on the company's host name.
    const alice = await personIn(browser, "Alice");
    people.push(alice);
    current = alice;
    const a = alice.page;
    const setup = fs.readFileSync(path.join(ledger, "console", "setup-link"), "utf8").trim();
    assert.ok(setup.startsWith(`${origin}/console/#/enroll/`), "the setup link is on the host name");
    await a.goto(setup);
    await a.getByLabel("Your name").fill("Alice");
    await a.getByRole("button", { name: "Create my passkey" }).click();
    await a.getByRole("heading", { name: "Your recovery code" }).waitFor();
    await a.getByLabel("I have printed or saved my recovery code").check();
    await a.getByRole("button", { name: "Continue" }).click();
    await a.getByRole("button", { name: "Not now" }).click();
    await a.getByRole("heading", { name: "Home" }).waitFor();
    const owner = JSON.parse(run("kanhe-console", "user", "show", "Alice", "--json"));
    assert.ok(JSON.stringify(owner.passkeys).includes(host), "the owner's passkey is for the host name");
    const sheet = path.join(work, "photo-kind.json");
    fs.writeFileSync(sheet, JSON.stringify({
      sheet: 1, kind: "document", type: "example.org.photo/1", name: "Photo",
      fields: [{ name: "place", required: true }], files: "optional" }));
    run("kanhe-console", "kind", "add", sheet);

    // Bob is invited, and registers his passkey for the host name in his own browser.
    await a.getByRole("link", { name: "People" }).click();
    await a.getByRole("heading", { name: "People", level: 1 }).waitFor();
    await a.getByLabel("Name", { exact: true }).fill("Bob");
    await a.getByRole("button", { name: "Make an invitation link" }).click();
    const link = await a.getByLabel("The invitation for Bob:").inputValue();
    assert.ok(link.startsWith(`${origin}/console/#/enroll/khi_`));
    const bob = await personIn(browser, "Bob");
    people.push(bob);
    current = bob;
    const b = bob.page;
    await b.goto(link);
    await b.getByLabel("Your name").fill("Bob");
    await b.getByRole("button", { name: "Register a passkey" }).click();
    await b.getByRole("heading", { name: "Home" }).waitFor();
    // He manages no one.
    await b.getByRole("link", { name: "People" }).click();
    await b.getByRole("heading", { name: "People", level: 1 }).waitFor();
    assert.equal(await b.getByRole("heading", { name: "Invite someone" }).count(), 0);

    // The owner approves him: he may register photos, in person. Three taps.
    current = alice;
    await a.reload();
    await a.getByRole("cell", { name: "Waiting for approval" }).waitFor();
    await a.getByRole("button", { name: "Approve Bob" }).click();
    await a.getByRole("heading", { name: "Approve Bob" }).waitFor();
    for (const what of ["endorse documents", "revoke documents",
                        "create and act on things under rules"]) {
      await a.getByLabel(what, { exact: true }).uncheck();
    }
    await a.getByRole("button", { name: "Approve (3 taps)" }).click();
    for (const [i, what] of [[1, "Register a person"], [2, "Register their passkeys"],
                             [3, "Grant what they may do"]]) {
      await a.getByText(`Step ${i} of 3`).waitFor();
      await tap(a, what);
    }
    await a.getByRole("heading", { name: "Done" }).waitFor();
    await a.getByText("Bob may now act on the ledger, each time with their passkey.").waitFor();
    await a.getByRole("button", { name: "People" }).click();
    await a.getByRole("cell", { name: /^register documents; in person \(passkey\)$/ }).waitFor();

    // Bob registers a photo with his own tap.
    current = bob;
    const register = async () => {
      await b.getByRole("link", { name: "Things" }).click();
      await b.getByRole("link", { name: "Register a document" }).click();
      await b.getByLabel("place (required)").fill("Central");
      await b.getByRole("button", { name: "Prepare" }).click();
    };
    await register();
    await tap(b, "Register a document");
    await b.getByRole("heading", { name: "Done" }).waitFor();
    const records = JSON.parse(run("record", "list", "--json"));
    const list = Array.isArray(records) ? records : records.records;
    assert.equal(list.filter((r) => (r.record_type ?? r.type) === "example.org.photo/1").length, 1);

    // The owner withdraws it; his next registration is refused.
    current = alice;
    await a.getByRole("link", { name: "People" }).click();
    await a.reload();
    await a.getByRole("button", { name: "Withdraw what Bob may do" }).click();
    await tap(a, "Withdraw what they may do");
    await a.getByRole("heading", { name: "Done" }).waitFor();
    current = bob;
    await register();
    await b.getByText(/no valid delegation lets Bob do this/).waitFor();

    // A token for a program, shown once; and the activity log.
    current = alice;
    await a.getByRole("link", { name: "Settings" }).click();
    await a.getByRole("heading", { name: "API tokens" }).waitFor();
    await a.getByLabel("Name", { exact: true }).fill("robot");
    await a.getByRole("button", { name: "Make a token" }).click();
    assert.match(await a.getByLabel("The token robot:").inputValue(), /^kht_/);
    for (const what of ["invited someone", "registered a person", "registered passkeys",
                        "granted what someone may do", "withdrew what someone may do"]) {
      await a.getByRole("cell", { name: what, exact: true }).first().waitFor();
    }
    const tokens = JSON.parse(run("token", "list", "--json"));
    assert.ok(tokens.some((t) => t.name === "robot"));

    for (const p of people) {
      assert.deepEqual(p.violations, [], `${p.name}: no CSP violation or script error`);
    }
    console.log("console people browser test: passed");
  } catch (error) {
    if (current) {
      console.error(`${current.name}'s page ${current.page.url()}:\n` +
                    `${await current.page.locator("main").innerText().catch(() => "")}`);
    }
    throw error;
  } finally {
    await browser.close();
    try {
      run("kanhe-console", "stop");
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
