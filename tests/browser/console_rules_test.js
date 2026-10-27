// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// The rules editor in a real browser. One person sets up, then writes
// examples/lending in the form: a mistake shown on the field it belongs to,
// fixed; the same rules as Bo text and back; the contract in three
// languages side by side; a test run. Deployed with a passkey (the code
// checked in this browser, the same code as lending.bo's), listed, and
// retired with a passkey. Then lending.bo opened from a file opens in the
// form and passes its three tests, a source the form cannot hold stays as
// text, and the editor speaks Chinese.
// Usage: node console_rules_test.js CEXCHAIN [EXAMPLES_DIR]
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const cexchain = path.resolve(process.argv[2]);
const examples = path.resolve(process.argv[3] ?? path.join(__dirname, "..", "..", "examples"));
const lending = path.join(examples, "lending", "lending.bo");
const work = fs.mkdtempSync(path.join(os.tmpdir(), "cexchain-rules-"));
const ledger = path.join(work, "ledger");
const env = { ...process.env, CEXCHAIN_LEDGER: ledger, CEXCHAIN_NO_BROWSER: "1", HOME: work };
const run = (...args) => execFileSync(cexchain, args, { cwd: work, env, encoding: "utf8" });
const contracts = () => {
  const listed = JSON.parse(run("contract", "list", "--json"));
  return Array.isArray(listed) ? listed : listed.contracts;
};

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

    // The Rules screen: nothing deployed yet.
    await page.getByRole("link", { name: "Rules" }).click();
    await page.getByRole("heading", { name: "Rules", level: 1 }).waitFor();
    await page.getByText("Nothing yet.").waitFor();
    await page.getByRole("link", { name: "Write rules" }).click();
    await page.getByRole("heading", { name: "Write rules" }).waitFor();
    // The packs, as boxes to tick, none ticked.
    const packs = page.getByRole("group", { name: "Vocabulary packs" });
    assert.ok(await packs.getByRole("checkbox").count() >= 3, "the official packs");
    assert.equal(await packs.getByRole("checkbox", { checked: true }).count(), 0);

    // examples/lending, filled in the form.
    await page.getByLabel("Name of the rules").fill("Lending");
    await page.getByLabel("Party 1", { exact: true }).fill("owner");
    const thing = page.getByRole("group", { name: "The thing" });
    assert.equal(await thing.getByLabel("Word", { exact: true }).inputValue(), "thing");
    await thing.getByLabel("Name of the kind").fill("Item");
    await thing.getByRole("button", { name: "Add a field" }).click();
    const field1 = thing.getByRole("group", { name: "Field 1" });
    await field1.getByLabel("Name", { exact: true }).fill("name");
    await field1.getByLabel("Type", { exact: true }).fill("words"); // a mistake, fixed below
    await thing.getByRole("button", { name: "Add a field" }).click();
    const field2 = thing.getByRole("group", { name: "Field 2" });
    await field2.getByLabel("Name", { exact: true }).fill("holder");
    await field2.getByLabel("Type", { exact: true }).fill("owner");

    const fillAction = async (n, name, by, to, from, toState, value) => {
      await page.getByRole("button", { name: "Add an action" }).first().click();
      const action = page.getByRole("group", { name: `Action ${n}`, exact: true });
      await action.getByLabel("Action", { exact: true }).fill(name);
      await action.getByLabel("Started by (optional)").fill(by);
      if (to) await action.getByLabel("With (optional)").fill(to);
      await action.getByRole("button", { name: "Add a state" }).click();
      await action.getByLabel("State 1", { exact: true }).fill(from);
      await action.getByLabel("To the state (optional)").fill(toState);
      await action.getByRole("button", { name: "Set a field" }).click();
      const set = action.getByRole("group", { name: "Field set 1" });
      await set.getByLabel("Name", { exact: true }).fill("holder");
      await set.getByLabel("Value", { exact: true }).fill(value);
    };
    await fillAction(1, "lend", "owner", "counterparty", "active", "lent", "counterparty");
    await fillAction(2, "bring_back", "holder", null, "lent", "active", "owner");

    await page.getByRole("button", { name: "Add a test" }).click();
    const test = page.getByRole("group", { name: "Test 1" });
    await test.getByLabel("Name (optional)").fill('"lent and brought back"');
    const step = async (n, party, action, values) => {
      await test.getByRole("button", { name: "Add a step" }).click();
      const s = test.getByRole("group", { name: `Step ${n}` });
      await s.getByLabel("Party", { exact: true }).fill(party);
      await s.getByLabel("Action", { exact: true }).fill(action);
      if (values.to) await s.getByLabel("With (optional)").fill(values.to);
      if (values.expect) await s.getByLabel("Expected (optional)").fill(values.expect);
      if (values.name) {
        await s.getByRole("button", { name: "Add a value" }).click();
        await s.getByRole("group", { name: "Value 1" }).getByLabel("Name", { exact: true }).fill("name");
        await s.getByRole("group", { name: "Value 1" }).getByLabel("Value", { exact: true }).fill(values.name);
      }
    };
    await step(1, "owner", "create", { name: '"Camera X100"' });
    await step(2, "owner", "lend", { to: "friend1", expect: "lent" });
    await step(3, "friend1", "bring_back", { expect: "active" });

    // Checked: the mistake is shown on its field, and in the list above.
    await page.getByRole("button", { name: "Check" }).click();
    await field1.locator(".problem").first().waitFor();
    assert.match(await field1.locator(".problem").first().textContent(), /^Error: /);
    await page.getByRole("alert").getByRole("button", { name: /^The thing › Field 1: / })
      .first().waitFor();
    await field1.getByLabel("Type", { exact: true }).fill("text");
    await page.getByRole("button", { name: "Check" }).click();
    await page.getByText("No problems found.").waitFor();
    assert.equal(await page.locator(".rules-form .problem").count(), 0);

    // The same rules as Bo text, and back.
    await page.getByRole("button", { name: "Bo text" }).click();
    const text = page.getByLabel("Bo text", { exact: true });
    await text.waitFor();
    const written = await text.inputValue();
    assert.match(written, /^contract Lending\nparties owner\n/);
    assert.match(written, /can lend by owner to counterparty\n  active -> lent\n  holder = counterparty\n/);
    // Its keywords in Traditional Chinese, then in English again.
    await page.getByLabel("Write its keywords in").selectOption("zh-Hant-HK");
    await page.waitForFunction(() => document.getElementById("rules-source").value.startsWith("合約 Lending"));
    await page.getByLabel("Write its keywords in").selectOption("en");
    await page.waitForFunction(() => document.getElementById("rules-source").value.startsWith("contract Lending"));
    await page.getByRole("button", { name: "Form" }).click();
    await page.getByLabel("Name of the rules").waitFor();
    assert.equal(await page.getByLabel("Name of the rules").inputValue(), "Lending");
    assert.equal(await page.getByRole("group", { name: "Action 2", exact: true })
      .getByLabel("Action", { exact: true }).inputValue(), "bring_back");

    // The contract in three languages, side by side.
    await page.getByRole("button", { name: "Read as a contract" }).click();
    await page.getByRole("heading", { name: "The contract, in three languages" }).waitFor();
    const columns = page.locator("article.explained");
    assert.equal(await columns.count(), 3);
    assert.match(await columns.nth(0).textContent(), /Contract Lending/);
    assert.match(await columns.nth(1).textContent(), /合約 Lending/);
    assert.match(await columns.nth(2).textContent(), /合约 Lending/);
    assert.equal(await columns.nth(1).getAttribute("lang"), "zh-Hant-HK");

    // Its test.
    await page.getByRole("button", { name: "Run the tests" }).click();
    await page.getByText("1 of 1 tests passed.").waitFor();
    await page.getByText("Passed: lent and brought back").waitFor();

    // Deployed with a passkey: the code checked here is lending.bo's.
    const built = JSON.parse(run("bo", "build", lending, "--out", path.join(work, "lending.boc"),
                                 "--json"));
    await page.getByRole("button", { name: "Deploy" }).click();
    await page.getByRole("heading", { name: "Approve with your passkey" }).waitFor();
    await page.getByText("Checked in this browser").waitFor();
    await page.getByText("Deploy rules").waitFor();
    await page.getByText(built.code_hash).waitFor();
    await page.getByRole("button", { name: "Approve with your passkey" }).click();
    await page.getByRole("heading", { name: "Done" }).waitFor();
    let listed = contracts();
    assert.equal(listed.length, 1);
    assert.equal(listed[0].name, "Lending");
    assert.equal(listed[0].code_hash, built.code_hash);
    assert.deepEqual(Object.keys(listed[0].functions).sort(), ["bring_back", "create", "lend"]);
    assert.equal(listed[0].retired, false);

    // Listed, then retired with a passkey.
    await page.getByRole("button", { name: "Back to the rules" }).click();
    await page.getByRole("heading", { name: "Rules", level: 1 }).waitFor();
    await page.getByRole("cell", { name: "in force" }).waitFor();
    await page.getByRole("button", { name: "Retire the rules Lending" }).click();
    await page.getByLabel("Reason (optional)").fill("replaced by a new version");
    await page.getByRole("button", { name: "Prepare" }).click();
    await page.getByRole("heading", { name: "Approve with your passkey" }).waitFor();
    await page.getByText("Checked in this browser").waitFor();
    await page.getByText("Retire rules").waitFor();
    await page.getByText("replaced by a new version").waitFor();
    await page.getByRole("button", { name: "Approve with your passkey" }).click();
    await page.getByRole("heading", { name: "Done" }).waitFor();
    await page.getByRole("button", { name: "Back to the rules" }).click();
    await page.getByRole("cell", { name: "retired", exact: true }).waitFor();
    listed = contracts();
    assert.equal(listed[0].retired, true);
    assert.equal(listed[0].retire_reason, "replaced by a new version");

    // lending.bo from a file opens in the form, with its three tests.
    await page.getByRole("link", { name: "Write rules" }).click();
    await page.getByLabel("Open a file").setInputFiles(lending);
    await page.getByRole("group", { name: "Test 3" }).waitFor();
    assert.equal(await page.getByLabel("Name of the rules").inputValue(), "Lending");
    await page.getByRole("button", { name: "Run the tests" }).click();
    await page.getByText("3 of 3 tests passed.").waitFor();

    // A source the form cannot hold stays as text, and says where.
    const choice = path.join(work, "choice.bo");
    fs.writeFileSync(choice, "contract Choice\nparties we\n\nthing T\n  n number\n\n" +
                             "can act by we\n  if n > 1\n    -> big\n");
    await page.getByLabel("Open a file").setInputFiles(choice);
    await page.getByLabel("Bo text", { exact: true }).waitFor();
    await page.getByRole("alert").getByText(/^Line 8: These rules do not fit the form/).waitFor();
    assert.match(await page.getByLabel("Bo text", { exact: true }).inputValue(), /^contract Choice/);
    await page.getByRole("button", { name: "Check" }).click();
    await page.getByText("No problems found.").waitFor();

    // In Chinese.
    await page.getByLabel("Language").selectOption("zh-Hant-HK");
    await page.getByRole("heading", { name: "撰寫規則" }).waitFor();
    await page.getByRole("button", { name: "表格" }).waitFor();
    await page.locator("#language").selectOption("en");
    await page.getByRole("heading", { name: "Write rules" }).waitFor();

    assert.deepEqual(violations, [], "no CSP violation or script error");
    console.log("console rules browser test: passed");
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
