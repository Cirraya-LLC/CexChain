// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// Proof of presence end to end with a real browser: Chromium's virtual
// WebAuthn authenticator plays the person's passkey (Touch ID, a phone, or a
// security key), and the command-line tool runs every ceremony through its
// localhost page, exactly as for a person at a desk.
// Usage: node presence_test.js CEXCHAIN VERIFY_PAGE
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const [cexchain, verifyPage] = process.argv.slice(2).map((p) => path.resolve(p));
const work = fs.mkdtempSync(path.join(os.tmpdir(), "cexchain-presence-"));
const env = { ...process.env, CEXCHAIN_PASSPHRASE: "presence test", CEXCHAIN_LEDGER: path.join(work, "ledger"),
              CEXCHAIN_NO_BROWSER: "1" };
const run = (...args) => execFileSync(cexchain, args, { cwd: work, env, encoding: "utf8" });
const fails = (...args) => {
  try {
    execFileSync(cexchain, args, { cwd: work, env, stdio: "pipe" });
  } catch (e) {
    return e.stderr.toString() + e.stdout.toString();
  }
  throw new Error("expected failure: " + args.join(" "));
};
const idFrom = (text) => text.match(/[0-9a-f]{64}/)[0];

/// Runs a command that needs the passkey, completing its ceremony in `page`.
function withPasskey(page, ...args) {
  return new Promise((resolve, reject) => {
    const child = spawn(cexchain, [...args, "--no-browser"], { cwd: work, env });
    let stdout = "";
    let stderr = "";
    let opened = false;
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => {
      stderr += d;
      const url = stderr.match(/http:\/\/localhost:\d+\/[0-9a-f]+/);
      if (url && !opened) {
        opened = true;
        page.goto(url[0]).catch(reject);
      }
    });
    child.on("exit", (code) => (code === 0 ? resolve(stdout) : reject(new Error(`${args.join(" ")}: ${stderr}`))));
  });
}

(async () => {
  for (const k of ["root", "log", "alice"]) run("key", "generate", "--out", k + ".key");
  const ledgerId = idFrom(run("init", "--org", "Cirraya Test Factory", "--root-key", "root.key", "--log-key", "log.key"));
  const alice = idFrom(run("actor", "add", "--as", "root.key", "--kind", "person", "--name", "Alice Inspector",
                           "--key", "alice.key"));
  run("delegation", "grant", "--as", "root.key", "--to", alice, "--allow", "record-register,record-endorse",
      "--days", "30", "--require-presence");

  // The ceremony page is served once, and only that page can deliver the
  // result: another local process that learns the address gets nothing.
  {
    const child = spawn(cexchain, ["presence", "enroll", "--out", "nope.passkey", "--name", "X", "--no-browser"],
                        { cwd: work, env });
    const url = await new Promise((resolve) => {
      let text = "";
      child.stderr.on("data", (d) => {
        text += d;
        const m = text.match(/http:\/\/localhost:\d+\/[0-9a-f]+/);
        if (m) resolve(m[0]);
      });
    });
    const first = await fetch(url);
    assert.equal(first.status, 200);
    assert.equal((await fetch(url)).status, 410);
    const forged = await fetch(url + "/result", { method: "POST", headers: { Origin: new URL(url).origin },
                                                   body: JSON.stringify({ id: "AAAA" }) });
    assert.equal(forged.status, 403);
    child.kill();
    assert.ok(!fs.existsSync(path.join(work, "nope.passkey")));
  }

  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true } });
  try {
    // Alice creates a passkey; the organization registers it.
    const enrolled = JSON.parse(await withPasskey(page, "presence", "enroll", "--out", "alice.passkey",
                                                  "--name", "Alice Inspector", "--label", "test laptop", "--json"));
    assert.equal(enrolled.rp_id, "localhost");
    assert.equal(enrolled.key.algorithm, "ESP256");
    assert.equal(JSON.parse(run("inspect", "alice.passkey", "--json")).kind, "passkey-credential");
    run("actor", "set-presence", alice, "--as", "root.key", "--credential", "alice.passkey");
    assert.match(run("actor", "show", alice), /passkey: +ESP256 .* for localhost \(test laptop\)/);

    // Her delegation requires presence: her key alone does nothing.
    assert.match(fails("record", "issue", "--as", "alice.key", "--type", "cexchain.certificate/1",
                       "--field", "result=pass"), /requires proof of presence/);
    const issued = JSON.parse(await withPasskey(page, "record", "issue", "--as", "alice.key", "--type",
                                                "cexchain.certificate/1", "--field", "result=pass", "--presence",
                                                "--json"));
    const record = issued.record.id;
    await withPasskey(page, "record", "endorse", record, "--as", "alice.key", "--role", "inspector", "--presence");
    assert.match(run("record", "history", record), /presence proven with a passkey/);
    assert.match(run("log", "show", record.slice(0, 12)), /presence: +proven with passkey .*\(user verified\)/);

    // Alice adds a second passkey herself, proving presence with the first.
    await withPasskey(page, "presence", "enroll", "--out", "second.passkey", "--name", "Alice Inspector");
    assert.match(fails("actor", "set-presence", alice, "--as", "alice.key", "--credential", "second.passkey",
                       "--add"), /no valid delegation/);
    await withPasskey(page, "actor", "set-presence", alice, "--as", "alice.key", "--credential", "second.passkey",
                      "--add", "--presence");
    assert.equal(JSON.parse(run("actor", "show", alice, "--json")).presence_credentials.length, 2);

    // Anyone verifying the evidence sees that a person was present.
    run("checkpoint", "create", "--log-key", "log.key");
    run("export", record, "--log-key", "log.key", "--out", "bundle.cbor");
    const report = JSON.parse(run("verify", "bundle.cbor", "--ledger-id", ledgerId, "--json"));
    assert.equal(report.verified, true);
    assert.deepEqual(report.events.map((e) => e.presence && e.presence.user_verified), [true, true]);
    assert.match(run("verify", "bundle.cbor", "--ledger-id", ledgerId), /present: passkey, user verified/);

    const viewer = await context.newPage();
    await viewer.goto("file://" + verifyPage);
    await viewer.waitForFunction(() => window.verifierReady === true);
    await viewer.setInputFiles("#bundle-file", path.join(work, "bundle.cbor"));
    await viewer.waitForFunction(() => !document.getElementById("result").hidden);
    assert.equal(await viewer.locator(".chip.present").count(), 2);
    console.log("passkey presence (browser): ok");
  } finally {
    await browser.close();
    fs.rmSync(work, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
