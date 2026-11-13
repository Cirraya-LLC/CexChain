// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// Certificates on the console, in a real browser. Alice sets up a console
// with a kind that prints fields, lets the console issue it (a tap: the
// organization's grant to its machine), and issues a table of three with
// one more tap; the console's machine signs each. She shows one's QR code
// and link, saves its page to print, and withdraws another. Scanning (GET
// /c/TOKEN) gets the record with the printed fields disclosed, issued by
// the organization's device; the same table again issues nothing twice; and
// a certificate she registers herself, in person, is published at once.
// Usage: node console_certificates_test.js KANHE
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const kanhe = path.resolve(process.argv[2]);
const programOf = (args) =>
  ["bo", "kanhe-console", "kanhe-index"].includes(args[0])
    ? [path.join(path.dirname(kanhe), args[0]), args.slice(1)]
    : [kanhe, args];
const work = fs.mkdtempSync(path.join(os.tmpdir(), "kanhe-certificates-"));

function freePort() {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
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
  const env = { ...process.env, KANHE_LEDGER: ledger, KANHE_NO_BROWSER: "1", HOME: work };
  const run = (...args) => execFileSync(...programOf(args), { cwd: work, env, encoding: "utf8" });
  const console_ = spawn(...programOf(["kanhe-console", "run", "--port", String(port), "--quiet"]),
                         { cwd: work, env });
  for (let i = 0; i < 300 && !fs.existsSync(path.join(ledger, "console", "setup-link")); i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
  const browser = await chromium.launch();
  const context = await browser.newContext({ locale: "en-GB", acceptDownloads: true });
  const a = await context.newPage();
  const violations = [];
  a.on("console", (m) => {
    if (/Content Security Policy|Refused to/.test(m.text())) violations.push(m.text());
  });
  a.on("pageerror", (e) => violations.push(String(e)));
  const cdp = await context.newCDPSession(a);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  try {
    await a.goto(fs.readFileSync(path.join(ledger, "console", "setup-link"), "utf8").trim());
    await a.getByLabel("Your name").fill("Alice");
    await a.getByRole("button", { name: "Create my passkey" }).click();
    await a.getByRole("heading", { name: "Your recovery code" }).waitFor();
    await a.getByLabel("I have printed or saved my recovery code").check();
    await a.getByRole("button", { name: "Continue" }).click();
    await a.getByRole("button", { name: "Not now" }).click();
    await a.getByRole("heading", { name: "Home" }).waitFor();

    // A kind that prints the name and the degree; the grades stay sealed.
    const sheet = path.join(work, "diploma.json");
    fs.writeFileSync(sheet, JSON.stringify({
      sheet: 1, kind: "document", type: "example.org.diploma/1", name: "Diploma", files: "none",
      fields: [{ name: "name", label: "Name", required: true }, { name: "degree", label: "Degree", required: true },
               { name: "grades", label: "Grades" }],
      printed: ["name", "degree"] }));
    run("kanhe-console", "kind", "add", sheet);
    await a.getByRole("link", { name: "Kinds" }).click();
    await a.getByText("Its certificates show: name, degree").waitFor();

    // The console may issue them once Alice lets it: the organization's grant.
    await a.getByRole("link", { name: "Certificates" }).click();
    await a.getByRole("heading", { name: "Certificates", level: 1 }).waitFor();
    await a.getByText(/only this computer opens/).waitFor();
    await a.getByRole("button", { name: "Let the console issue Diploma certificates" }).click();
    await tap(a);
    await a.getByText("The console may now issue Diploma certificates.").waitFor();
    await a.getByRole("cell", { name: "allowed", exact: true }).waitFor();

    // A table of three, checked, then issued with one tap.
    const table = path.join(work, "class.csv");
    fs.writeFileSync(table, 'Name,Degree,Grades\n"Chan, Tai Man",BSc,"A, A, B"\nWong Siu Ming,MSc,\nLee Ka Yan,BA,B\n');
    await a.getByLabel("Table (CSV)").setInputFiles(table);
    await a.getByRole("button", { name: "Check the table" }).click();
    await a.getByText("3 certificates: 0 issued already, 3 to issue.").waitFor();
    await a.getByRole("button", { name: "Issue 3 certificates" }).click();
    await a.getByText("Issued 3 certificates.").waitFor();
    await a.getByRole("cell", { name: "Chan, Tai Man · BSc" }).waitFor();
    assert.equal(await a.getByRole("cell", { name: "valid", exact: true }).count(), 3);

    // One's QR code and the link it holds; its page to print.
    await a.getByRole("button", { name: "QR code of Chan, Tai Man BSc" }).click();
    await a.getByRole("img", { name: "QR code that opens the certificate of Chan, Tai Man BSc" }).waitFor();
    const link = await a.getByLabel("The link the QR code of Chan, Tai Man BSc holds").inputValue();
    const named = link.match(/^https:\/\/kanhe\.cirraya\.com\/verify\/#l=([0-9a-f]{64})&r=([0-9a-f]{64})&b=(.+)$/);
    assert.ok(named, link);
    const address = decodeURIComponent(named[3]);
    assert.match(address, new RegExp(`^http://localhost:${port}/c/[A-Za-z0-9_-]{22}$`));
    const saving = a.waitForEvent("download");
    saving.catch(() => {});
    await a.getByRole("button", { name: "Page to print for Chan, Tai Man BSc" }).click();
    const pageFile = path.join(work, "page.html");
    await (await saving).saveAs(pageFile);
    const printed = fs.readFileSync(pageFile, "utf8");
    assert.match(printed, /Chan, Tai Man/);
    assert.match(printed, /<svg/);
    assert.doesNotMatch(printed, /A, A, B/);

    // Scanning: the record, its printed fields disclosed, issued by a device.
    const response = await fetch(address.replace("localhost", "127.0.0.1"));
    assert.equal(response.status, 200);
    const bundle = path.join(work, "scanned.cbor");
    fs.writeFileSync(bundle, Buffer.from(await response.arrayBuffer()));
    const report = JSON.parse(run("verify", bundle, "--ledger-id", named[1], "--json"));
    assert.equal(report.verified, true);
    assert.equal(report.record.id, named[2]);
    assert.equal(report.disclosed_fields.name, "Chan, Tai Man");
    assert.equal(report.disclosed_fields.grades, undefined, "the grades stay sealed");
    assert.equal(report.events[0].actor.kind, "device");

    // Certificates as W3C credentials: Alice turns them on (two taps: the
    // console's credential key registered, then allowed); a certificate
    // downloads as one, which a standard check and the record behind it pass:
    // the console's server gives its DID document and status list.
    await a.getByRole("button", { name: "Turn credentials on" }).click();
    await tap(a);
    await tap(a);
    await a.getByText("Credentials are on: each valid certificate now downloads as a credential.").waitFor();
    await a.getByText(/issued by did:web:localhost%3A/).waitFor();
    const fetching = a.waitForEvent("download");
    fetching.catch(() => {});
    await a.getByRole("button", { name: "Download the certificate of Chan, Tai Man BSc as a W3C credential" }).click();
    const credentialFile = path.join(work, "diploma.jwt");
    await (await fetching).saveAs(credentialFile);
    const checked = JSON.parse(run("credential", "verify", credentialFile, "--allow-http", "--ledger-id", named[1], "--json"));
    assert.equal(checked.verified, true, JSON.stringify(checked.problems));
    assert.equal(checked.credential.subject.name, "Chan, Tai Man");
    assert.equal(checked.credential.subject.grades, undefined, "the grades stay sealed");
    assert.equal(checked.credential.name, "Diploma");
    assert.deepEqual(checked.did_document.problems, []);
    assert.equal(checked.status_list.revoked, false);
    assert.equal(checked.credential_key.name, "Credentials");

    // Withdrawn: the address finds nothing; the same table issues nothing.
    await a.getByRole("button", { name: "Withdraw the certificate of Wong Siu Ming MSc" }).click();
    await a.getByText(/The certificate of Wong Siu Ming MSc is taken down/).waitFor();
    assert.equal(await a.getByRole("cell", { name: "valid", exact: true }).count(), 2);
    await a.getByLabel("Table (CSV)").setInputFiles(table);
    await a.getByRole("button", { name: "Check the table" }).click();
    await a.getByText("3 certificates: 3 issued already, 0 to issue.").waitFor();

    // One registered in person is published at once.
    await a.evaluate(() => { location.hash = "#/new"; });
    await a.getByLabel("Name (required)").fill("Ho Ka Ming");
    await a.getByLabel("Degree (required)").fill("PhD");
    await a.getByRole("button", { name: "Prepare" }).click();
    await tap(a);
    await a.getByRole("heading", { name: "Done" }).waitFor();
    await a.getByRole("link", { name: "Certificates" }).click();
    await a.getByRole("cell", { name: "Ho Ka Ming · PhD" }).waitFor();
    const listed = JSON.parse(run("kanhe-console", "certificate", "list", "--json"));
    assert.equal(listed.length, 3);

    assert.deepEqual(violations, [], "no CSP violation or script error");
    console.log("console certificates browser test: passed");
  } catch (error) {
    console.error(`the page ${a.url()}:\n${await a.locator("main").innerText().catch(() => "")}`);
    console.error(violations.join("\n"));
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
