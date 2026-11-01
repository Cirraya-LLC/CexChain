// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// An applicant in a real browser: a school publishes the day-student rules as
// a self-service form; a student opens its link, signs in with the school's
// account (a small OpenID Connect provider, tests/cli/idp.py), fills in the
// form, follows it under My items, and withdraws it. The intake actor signs;
// the student appears to the ledger only by a pseudonym.
// Usage: node console_apply_test.js CEXCHAIN
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const cexchain = path.resolve(process.argv[2]);
const source = path.resolve(__dirname, "..", "..");
const work = fs.mkdtempSync(path.join(os.tmpdir(), "cexchain-apply-"));
const ledger = path.join(work, "ledger");
const env = { ...process.env, CEXCHAIN_LEDGER: ledger, CEXCHAIN_NO_BROWSER: "1", HOME: work,
              CEXCHAIN_PASSPHRASE: "apply test" };
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

async function until(check, what) {
  for (let i = 0; i < 300; i++) {
    if (check()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`${what} did not happen`);
}

(async () => {
  const children = [];
  let browser;
  let page;
  const violations = [];
  try {
    if (JSON.parse(run("version", "--json")).bo === null) {
      console.log("console apply browser test: skipped (no Bo compiler in this build)");
      return;
    }
    // The school: a ledger, its console's keys, the provider, the form.
    execFileSync("openssl", ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                             "-out", path.join(work, "idp.pem")], { stdio: "ignore" });
    const idp = spawn("python3", [path.join(source, "tests", "cli", "idp.py"), path.join(work, "idp.port"),
                                  path.join(work, "idp.pem")], { cwd: work });
    children.push(idp);
    await until(() => fs.existsSync(path.join(work, "idp.port")), "the provider");
    const issuer = `http://127.0.0.1:${fs.readFileSync(path.join(work, "idp.port"), "utf8").trim()}`;
    for (const k of ["root", "log"]) run("key", "generate", "--out", path.join(work, `${k}.key`));
    run("init", "--name", "Example School", "--root-key", "root.key", "--log-key", "log.key");
    fs.writeFileSync(path.join(work, "unlock.txt"), "the unlock passphrase of these tests\n");
    run("console", "key", "init", "--unlock-file", "unlock.txt");
    run("console", "key", "import", "root", "root.key");
    fs.writeFileSync(path.join(work, "secret.txt"), "the-client-secret\n");
    run("console", "sso", "add", "school", "--oidc", issuer, "--client-id", "console",
        "--client-secret-file", "secret.txt", "--label", "School account");
    const contract = JSON.parse(run("contract", "deploy", "--bo",
                                    path.join(source, "examples", "day-student", "day-student.bo"),
                                    "--as", "root.key", "--json")).contract.id;
    fs.writeFileSync(path.join(work, "kind.json"), JSON.stringify({
      sheet: 1, kind: "document", type: "example.school.day-student-form/1", name: "Day student form",
      fields: [{ name: "student", label: "Student", type: "text", private: false, required: true },
               { name: "address", label: "Address", type: "text", private: true, required: true }],
      files: "none", keep_files: false }));
    run("console", "kind", "add", "kind.json");
    fs.writeFileSync(path.join(work, "form.json"), JSON.stringify({
      form: 1, name: "day-student", title: "Day student application", contract, create: "create",
      steps: ["withdraw"], kind: "example.school.day-student-form/1", record_field: "details" }));
    run("console", "form", "add", "form.json");
    run("console", "intake", "grant", "--unlock-file", "unlock.txt");

    const port = await freePort();
    children.push(spawn(cexchain, ["console", "run", "--port", String(port), "--unlock-file",
                                   "unlock.txt", "--quiet"], { cwd: work, env }));
    await until(() => {
      try { return JSON.parse(run("console", "status", "--json")).running; } catch { return false; }
    }, "the console");

    browser = await chromium.launch();
    const context = await browser.newContext({ locale: "en-GB" });
    page = await context.newPage();
    page.on("console", (m) => {
      if (/Content Security Policy|Refused to/.test(m.text())) violations.push(m.text());
    });
    page.on("pageerror", (e) => violations.push(String(e)));

    // The link, then the school's sign-in, and back.
    await page.goto(`http://localhost:${port}/console/#/apply/day-student`);
    await page.getByRole("heading", { name: "Day student application" }).waitFor();
    await page.getByRole("button", { name: "Sign in with School account" }).click();
    await page.getByText("Signed in as Li Ming.").waitFor();
    // The form: the document's fields, then the rules' own.
    await page.getByLabel("Student (required)").fill("Li Ming");
    await page.getByLabel("Address (required)").fill("12 Hill Road, Sha Tin");
    await page.getByLabel("guardian_agrees").selectOption("yes");
    await page.getByRole("button", { name: "Submit" }).click();
    await page.getByRole("heading", { name: "My items" }).waitFor();
    await page.getByText("Where it stands: submitted").waitFor();
    // A step of theirs.
    await page.getByRole("button", { name: "withdraw" }).click();
    await page.getByText("Where it stands: withdrawn").waitFor();

    // On the ledger: one thing, by the pseudonym, made by the intake actor.
    const found = JSON.parse(run("search", "instances", "--status", "withdrawn", "--json")).instances;
    assert.equal(found.length, 1);
    assert.match(found[0].reference, /^a-[0-9a-f]{24}$/);
    assert.ok(!fs.readdirSync(ledger).some((f) => f.startsWith("statements") &&
              fs.readFileSync(path.join(ledger, f)).includes("Hill Road")), "the address is sealed");

    // Signing out ends the applicant's session.
    await page.getByRole("button", { name: "Sign out" }).click();
    await page.getByText("You are signed out.").waitFor();
    await page.evaluate(() => { location.hash = "#/apply/day-student"; });
    await page.getByText("Sign in with your organization's account to go on.").waitFor();
    await page.getByRole("button", { name: "Sign in with School account" }).waitFor();

    assert.deepEqual(violations, [], "no CSP violation or script error");
    console.log("console apply browser test: passed");
  } catch (error) {
    if (page) console.error(`page ${page.url()}:\n${await page.locator("main").innerText().catch(() => "")}`);
    throw error;
  } finally {
    if (browser) await browser.close();
    try { run("console", "stop"); } catch { /* not running */ }
    for (const c of children) c.kill();
    fs.rmSync(work, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
