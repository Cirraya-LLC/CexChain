// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// The console on a phone: a 390 by 844 touch screen, in English and in
// Chinese. The first run, a document registered and approved with the
// passkey, then every screen: none may be wider than the screen (no sideways
// scrolling), the bar above them stays short, folded into a menu button,
// and the menu reaches each one. With CONSOLE_TEST_SHOTS=DIR,
// each screen is also saved there as a picture.
// Usage: node console_phone_test.js CEXCHAIN
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const cexchain = path.resolve(process.argv[2]);
const programOf = (args) =>
  ["bo", "cexchain-console", "cexchain-index"].includes(args[0])
    ? [path.join(path.dirname(cexchain), args[0]), args.slice(1)]
    : [cexchain, args];
const work = fs.mkdtempSync(path.join(os.tmpdir(), "cexchain-phone-"));
const ledger = path.join(work, "ledger");
const env = { ...process.env, CEXCHAIN_LEDGER: ledger, CEXCHAIN_NO_BROWSER: "1", HOME: work };
const run = (...args) => execFileSync(...programOf(args), { cwd: work, env, encoding: "utf8" });
const shots = process.env.CONSOLE_TEST_SHOTS;

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
    if (JSON.parse(run("cexchain-console", "status", "--json")).running) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("the console did not start");
}

/// A phone: a small touch screen, with a platform passkey.
async function phone(browser, locale, violations) {
  const context = await browser.newContext({
    locale, acceptDownloads: true, viewport: { width: 390, height: 844 },
    deviceScaleFactor: 2, isMobile: true, hasTouch: true });
  const page = await context.newPage();
  page.on("console", (m) => {
    if (/Content Security Policy|Refused to/.test(m.text())) violations.push(m.text());
  });
  page.on("pageerror", (e) => violations.push(String(e)));
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  return { context, page };
}

/// Fails if the page is wider than the screen; names what sticks out.
async function fits(page, name) {
  if (shots) {
    await page.screenshot({ path: path.join(shots, `${name}.png`), fullPage: true });
    await page.screenshot({ path: path.join(shots, `${name}-screen.png`) });
  }
  const wider = await page.evaluate(() => {
    const width = document.documentElement.clientWidth;
    if (document.documentElement.scrollWidth <= width + 1) return [];
    return [...document.querySelectorAll("body *")]
      .filter((e) => e.getBoundingClientRect().right > width + 1)
      .slice(0, 5)
      .map((e) => `${e.tagName.toLowerCase()}${e.id ? "#" + e.id : ""}${e.className ? "." + e.className : ""}`);
  });
  assert.deepEqual(wider, [], `${name}: wider than the screen`);
}

const screens = ["#/", "#/things", "#/new", "#/reports", "#/kinds", "#/rules", "#/parties",
                 "#/people", "#/automation", "#/exchange", "#/verify", "#/settings"];

/// Opens a screen from the menu if it has an entry there, else by its
/// address; the menu closes again, and the bar stays short.
async function open(page, hash) {
  const entry = page.locator(`#nav a[href="${hash}"]`);
  if (await entry.count()) {
    assert.equal(await entry.isVisible(), false, "the menu starts closed");
    await page.locator("#menu").tap();
    await entry.tap();
  } else {
    await page.evaluate((h) => { location.hash = h; }, hash);
  }
  await page.waitForLoadState("networkidle");
  await page.locator("main h1").first().waitFor();
  assert.equal(await page.locator("#menu").getAttribute("aria-expanded"), "false");
  const bar = await page.locator("header.bar").boundingBox();
  assert.ok(bar.height < 80, `${hash}: the bar is ${bar.height}px high`);
  assert.ok(await page.locator("#menu").isVisible() && bar.y === 0,
            `${hash}: the screen starts at the top, the menu button in view`);
}

(async () => {
  if (shots) fs.mkdirSync(shots, { recursive: true });
  const port = await freePort();
  const consoleProcess = spawn(...programOf(["cexchain-console", "run", "--port", String(port), "--quiet"]),
                               { cwd: work, env });
  let browser;
  try {
    await waitRunning();
    const setup = fs.readFileSync(path.join(ledger, "console", "setup-link"), "utf8").trim();
    browser = await chromium.launch();
    const violations = [];
    const { page } = await phone(browser, "en-GB", violations);

    // The first run, each step on the small screen.
    await page.goto(setup);
    await page.getByRole("heading", { name: "Set up your console" }).waitFor();
    await fits(page, "en-setup-name");
    await page.getByLabel("Your name").fill("Alice");
    await page.getByRole("button", { name: "Create my passkey" }).tap();
    await page.getByRole("heading", { name: "Your recovery code" }).waitFor();
    await fits(page, "en-setup-recovery");
    await page.getByLabel("I have printed or saved my recovery code").tap();
    await page.getByRole("button", { name: "Continue" }).tap();
    await page.getByRole("heading", { name: "Where should backups go?" }).waitFor();
    await fits(page, "en-setup-backups");
    await page.getByRole("button", { name: "Not now" }).tap();
    await page.getByRole("heading", { name: "Home" }).waitFor();

    // A kind of document, then one registered and approved on the phone.
    const sheet = path.join(work, "letter-kind.json");
    fs.writeFileSync(sheet, JSON.stringify({
      sheet: 1, kind: "document", type: "example.org.letter/1", name: "Letter",
      fields: [{ name: "subject", required: true }, { name: "sent", type: "date" }] }));
    run("cexchain-console", "kind", "add", sheet);
    await page.evaluate(() => { location.hash = "#/new"; });
    await page.getByLabel("subject (required)").fill("A long subject to see how the form wraps on a phone");
    await page.getByLabel("sent").fill("2026-11-10");
    await page.getByRole("button", { name: "Prepare" }).tap();
    await page.getByRole("heading", { name: "Approve with your passkey" }).waitFor();
    await page.getByText("Checked in this browser").waitFor();
    await fits(page, "en-approve");
    await page.getByRole("button", { name: "Approve with your passkey" }).tap();
    await page.getByRole("heading", { name: "Done" }).waitFor();
    await fits(page, "en-done");

    // Every screen, in English, then in Chinese.
    for (const [language, prefix] of [["en", "en"], ["zh-Hans-CN", "zh"]]) {
      if (language !== "en") {
        await page.locator("#menu").tap();
        await page.locator("#language").selectOption(language);
        // The menu folds once the language's words have come.
        await page.locator('#menu[aria-expanded="false"]').waitFor();
      }
      for (const hash of screens) {
        await open(page, hash);
        await fits(page, `${prefix}-${hash.replace("#/", "") || "home"}`);
      }
    }
    assert.deepEqual(violations, []);
    console.log("console on a phone: passed");
  } finally {
    if (browser) await browser.close();
    try { run("cexchain-console", "stop"); } catch { consoleProcess.kill(); }
    fs.rmSync(work, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
