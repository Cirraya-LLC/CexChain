// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The console's page. Everything the ledger or a person wrote is shown with
// textContent, never as markup. The session is a bearer token in
// sessionStorage (no cookies); the page talks only to its own console.

const LANGUAGES = ["en", "zh-Hant-HK", "zh-Hans-CN"];
const SESSION = "cexchain.session";
const LANGUAGE = "cexchain.language";

const state = { language: "en", text: {}, english: {}, who: null, firstRun: false,
                defaultLanguage: null, flash: null };

// --- Text ----------------------------------------------------------------

function t(key, values = {}) {
    const template = state.text[key] ?? state.english[key] ?? key;
    return template.replace(/\{(\w+)\}/g, (_, name) => String(values[name] ?? ""));
}

function stored(storage, key) {
    try {
        return storage.getItem(key);
    } catch {
        return null;
    }
}

function store(storage, key, value) {
    try {
        if (value === null) {
            storage.removeItem(key);
        } else {
            storage.setItem(key, value);
        }
    } catch {
        // Private browsing: the page still works, it only forgets.
    }
}

function preferredLanguage() {
    const saved = stored(localStorage, LANGUAGE);
    if (LANGUAGES.includes(saved)) {
        return saved;
    }
    // The console's own choice (Settings), then the browser's.
    if (LANGUAGES.includes(state.defaultLanguage)) {
        return state.defaultLanguage;
    }
    for (const tag of navigator.languages ?? []) {
        const lower = tag.toLowerCase();
        if (/^zh-(hant|hk|tw|mo)/.test(lower)) {
            return "zh-Hant-HK";
        }
        if (lower.startsWith("zh")) {
            return "zh-Hans-CN";
        }
        if (lower.startsWith("en")) {
            return "en";
        }
    }
    return "en";
}

async function catalog(language) {
    const response = await fetch(`i18n/${language}.json`, { credentials: "omit" });
    if (!response.ok) {
        throw new Error(`no catalog for ${language}`);
    }
    return response.json();
}

async function setLanguage(language, remember = true) {
    state.text = language === "en" ? state.english : await catalog(language);
    state.language = language;
    document.documentElement.lang = language;
    if (remember) {
        store(localStorage, LANGUAGE, language);
    }
    document.getElementById("language").value = language;
    for (const element of document.querySelectorAll("[data-text]")) {
        element.textContent = t(element.dataset.text);
    }
    for (const element of document.querySelectorAll("[data-label]")) {
        element.setAttribute("aria-label", t(element.dataset.label));
    }
    document.title = t("app.name");
}

// --- Elements --------------------------------------------------------------

/// An element with attributes and children (strings become text nodes).
function el(tag, attributes = {}, ...children) {
    const element = document.createElement(tag);
    for (const [name, value] of Object.entries(attributes)) {
        if (name === "text") {
            element.textContent = value;
        } else if (value !== undefined && value !== null && value !== false) {
            element.setAttribute(name, value === true ? "" : String(value));
        }
    }
    for (const child of children.flat()) {
        if (child !== null && child !== undefined) {
            element.append(typeof child === "string" ? document.createTextNode(child) : child);
        }
    }
    return element;
}

function show(...children) {
    const main = document.getElementById("main");
    main.replaceChildren(...children.filter((c) => c !== null));
    main.focus();
}

function status(text) {
    document.getElementById("status").textContent = text;
}

function problem(message) {
    return el("div", { class: "error", role: "alert" },
              el("strong", { text: t("error.title") }), el("p", { text: message }));
}

// --- The console's API ---------------------------------------------------------

class ApiError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

async function api(method, path, body) {
    const headers = {};
    const token = stored(sessionStorage, SESSION);
    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }
    if (body !== undefined) {
        headers["Content-Type"] = "application/json";
    }
    const response = await fetch(`api/${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: "omit",
        cache: "no-store",
    });
    const answer = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new ApiError(response.status, answer?.error?.message ?? String(response.status));
    }
    return answer;
}

// --- Passkeys ------------------------------------------------------------------

function fromBase64url(text) {
    const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0)).buffer;
}

function toBase64url(buffer) {
    let binary = "";
    for (const byte of new Uint8Array(buffer)) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function passkeysAvailable() {
    return typeof window.PublicKeyCredential === "function" && !!navigator.credentials;
}

/// What went wrong with a passkey, in the reader's words.
function passkeyProblem(error) {
    if (error instanceof ApiError) {
        return error.status === 400 && /address/.test(error.message)
            ? t("error.address")
            : t("error.server", { message: error.message });
    }
    if (error?.name === "NotAllowedError" || error?.name === "AbortError") {
        return t("error.cancelled");
    }
    return t("error.server", { message: String(error?.message ?? error) });
}

/// Makes a passkey with the console's registration options; what the
/// console needs back from it.
async function createPasskey(options, device) {
    // The PRF salt, where the console sends one, so that the new passkey
    // unlocks the console's keys from its first use.
    const extensions = { ...options.extensions };
    const salt = extensions.prf?.eval?.first;
    if (salt) {
        extensions.prf = { eval: { first: fromBase64url(salt) } };
    }
    const credential = await navigator.credentials.create({
        publicKey: {
            challenge: fromBase64url(options.challenge),
            rp: options.rp,
            user: {
                id: fromBase64url(options.user.id),
                name: options.user.name,
                displayName: options.user.displayName,
            },
            pubKeyCredParams: options.pubKeyCredParams,
            authenticatorSelection: options.authenticatorSelection,
            attestation: options.attestation,
            extensions,
            excludeCredentials: options.excludeCredentials.map((c) => ({
                type: c.type,
                id: fromBase64url(c.id),
            })),
            timeout: options.timeout,
        },
    });
    const prf = credential.getClientExtensionResults?.().prf?.results?.first;
    return {
        attestation_object: toBase64url(credential.response.attestationObject),
        client_data_json: toBase64url(credential.response.clientDataJSON),
        label: device,
        prf: prf ? toBase64url(prf) : undefined,
    };
}

async function register(code, name, device) {
    const begun = await api("POST", "enroll/begin", { code, name });
    const made = await createPasskey(begun.public_key, device);
    return api("POST", "enroll/finish", { ceremony: begun.ceremony, ...made });
}

/// A lost passkey: the recovery code opens the console, a new passkey is
/// made here, and the console makes it the owner's only one.
async function recover(code, name, device) {
    const begun = await api("POST", "recover/begin", { recovery_code: code, name });
    const made = await createPasskey(begun.public_key, device);
    return api("POST", "recover/finish", { ceremony: begun.ceremony, ...made });
}

async function signIn() {
    const begun = await api("POST", "sign-in/begin", {});
    const options = begun.public_key;
    const publicKey = {
        challenge: fromBase64url(options.challenge),
        rpId: options.rpId,
        userVerification: options.userVerification,
        timeout: options.timeout,
    };
    // With sealed keys, the passkey's PRF output unlocks them (where the
    // passkey has one); the console sends the salt.
    const salt = options.extensions?.prf?.eval?.first;
    if (salt) {
        publicKey.extensions = { prf: { eval: { first: fromBase64url(salt) } } };
    }
    const credential = await navigator.credentials.get({ publicKey });
    const prf = credential.getClientExtensionResults?.().prf?.results?.first;
    return api("POST", "sign-in/finish", {
        ceremony: begun.ceremony,
        credential_id: toBase64url(credential.rawId),
        authenticator_data: toBase64url(credential.response.authenticatorData),
        client_data_json: toBase64url(credential.response.clientDataJSON),
        signature: toBase64url(credential.response.signature),
        prf: prf ? toBase64url(prf) : undefined,
    });
}

// --- Screens -------------------------------------------------------------------

function signedIn(answer, next = home) {
    store(sessionStorage, SESSION, answer.session);
    state.who = { user: answer.user, role: answer.role, keys: answer.keys ?? "none",
                  // A new passkey that could not unlock the console yet.
                  needsSlot: answer.key_slot === false && answer.keys === "unlocked" &&
                             (answer.role === "owner" || answer.role === "admin") };
    next();
}

/// A new passkey that gave no PRF output when it was made unlocks the
/// console only after one sign-in with it: offered on Home.
function slotNotice() {
    if (!state.who?.needsSlot || state.who.keys !== "unlocked") {
        return null;
    }
    const button = el("button", { type: "button", text: t("slot.button") });
    const answer = el("div");
    button.addEventListener("click", async () => {
        button.disabled = true;
        try {
            signedIn(await signIn(), route);
        } catch (error) {
            answer.replaceChildren(problem(passkeyProblem(error)));
            button.disabled = false;
        }
    });
    return el("section", { class: "notice" }, el("p", { text: t("slot.intro") }), answer, button);
}

/// While the console's keys are locked, it signs nothing: say so, and let
/// an owner or an admin unlock it with a passphrase or the recovery code.
function keysNotice() {
    if (state.who?.keys !== "locked") {
        return null;
    }
    const box = el("section", { class: "notice", "aria-labelledby": "keys-locked" },
                   el("p", { id: "keys-locked", text: t("keys.locked") }));
    if (state.who.role === "owner" || state.who.role === "admin") {
        const [secretField, secret] = field("unlock-secret", t("keys.secret"), t("keys.secret_hint"),
                                            { type: "password", autocomplete: "current-password" });
        const button = el("button", { type: "submit", text: t("keys.unlock") });
        const answer = el("div");
        const form = el("form", { novalidate: true }, secretField, answer, button);
        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            button.disabled = true;
            try {
                const result = await api("POST", "unlock", { secret: secret.value });
                state.who.keys = result.keys;
                route();
            } catch (error) {
                answer.replaceChildren(problem(error.status === 403 ? t("keys.wrong")
                                                                    : passkeyProblem(error)));
            } finally {
                button.disabled = false;
            }
        });
        box.append(form);
    }
    return box;
}

/// To Home: through the hash when it changes, else at once.
function home() {
    if (location.hash !== "#/") {
        location.hash = "#/";
    } else {
        route();
    }
}

function signInScreen(message) {
    const button = el("button", { type: "button", class: "primary", text: t("sign_in.button") });
    const notice = el("div");
    if (message) {
        notice.append(problem(message));
    }
    button.addEventListener("click", async () => {
        if (!passkeysAvailable()) {
            notice.replaceChildren(problem(t("error.no_passkeys")));
            return;
        }
        button.disabled = true;
        status(t("status.working"));
        try {
            signedIn(await signIn());
        } catch (error) {
            notice.replaceChildren(problem(passkeyProblem(error)));
        } finally {
            button.disabled = false;
            status("");
        }
    });
    show(el("h1", { text: t("sign_in.title") }), el("p", { text: t("sign_in.intro") }), notice,
         button, el("p", {}, el("a", { href: "#/recover", text: t("recover.link") })),
         el("p", {}, el("a", { href: "#/verify", text: t("verify.link") })));
}

function field(id, label, hint, attributes = {}) {
    const input = el("input", { id, "aria-describedby": `${id}-hint`, ...attributes });
    return [el("div", { class: "field" }, el("label", { for: id, text: label }), input,
               el("span", { id: `${id}-hint`, class: "hint", text: hint })), input];
}

function enrollScreen(code) {
    const [nameField, name] = field("enroll-name", t("enroll.name"), t("enroll.name_hint"),
                                    { autocomplete: "name", maxlength: 64 });
    const [deviceField, device] = field("enroll-device", t("enroll.device"),
                                        t("enroll.device_hint"), { maxlength: 64 });
    const firstRun = state.firstRun;
    const button = el("button", { type: "submit", class: "primary",
                                  text: t(firstRun ? "setup.button" : "enroll.button") });
    const notice = el("div");
    const form = el("form", { novalidate: true }, nameField, deviceField, notice, button);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!passkeysAvailable()) {
            notice.replaceChildren(problem(t("error.no_passkeys")));
            return;
        }
        button.disabled = true;
        status(t("status.working"));
        try {
            const answer = await register(code, name.value.trim(), device.value.trim());
            state.pendingCode = null;
            if (answer.first_run) {
                // The ledger is made: the recovery sheet next, shown once.
                state.firstRun = false;
                signedIn(answer, () => sheetScreen(answer));
            } else {
                signedIn(answer);
            }
        } catch (error) {
            notice.replaceChildren(problem(passkeyProblem(error)));
        } finally {
            button.disabled = false;
            status("");
        }
    });
    if (firstRun) {
        show(el("p", { class: "step", text: t("setup.step", { step: 1 }) }),
             el("h1", { text: t("setup.title") }), el("p", { text: t("setup.intro") }), form);
    } else {
        show(el("h1", { text: t("enroll.title") }), el("p", { text: t("enroll.intro") }), form);
    }
}

/// The recovery sheet: the code, shown this once, to print or save before
/// going on.
function sheetScreen(answer) {
    const made = new Date().toISOString().slice(0, 10);
    const consoleAddress = `${location.origin}${location.pathname}`;
    const facts = el("dl", { class: "facts" },
                     el("dt", { text: t("sheet.organization") }), el("dd", { text: answer.user }),
                     el("dt", { text: t("sheet.ledger") }),
                     el("dd", { class: "id", text: answer.ledger }),
                     el("dt", { text: t("sheet.console") }), el("dd", { text: consoleAddress }),
                     el("dt", { text: t("sheet.date") }), el("dd", { text: made }));
    const code = el("p", { class: "code", id: "recovery-code", text: answer.recovery_code });
    const print = el("button", { type: "button", text: t("sheet.print") });
    print.addEventListener("click", () => window.print());
    const save = el("button", { type: "button", text: t("sheet.save") });
    save.addEventListener("click", () => {
        const lines = [t("sheet.title"), "", `${t("sheet.organization")}: ${answer.user}`,
                       `${t("sheet.ledger")}: ${answer.ledger}`,
                       `${t("sheet.console")}: ${consoleAddress}`, `${t("sheet.date")}: ${made}`,
                       "", `${t("sheet.code")}: ${answer.recovery_code}`, "", t("sheet.intro"), ""];
        const url = URL.createObjectURL(new Blob([lines.join("\n")],
                                                 { type: "text/plain;charset=utf-8" }));
        const link = el("a", { href: url, download: "cexchain-recovery-code.txt" });
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
    const kept = el("input", { type: "checkbox", id: "sheet-kept" });
    const notice = el("div");
    const next = el("button", { type: "submit", class: "primary", text: t("sheet.continue") });
    const form = el("form", { novalidate: true, class: "no-print" },
                    el("label", { class: "check" }, kept, " ", t("sheet.saved")), notice, next);
    // The code is never shown again: leaving the page asks first.
    const leaving = (event) => {
        event.preventDefault();
        event.returnValue = "";
    };
    window.addEventListener("beforeunload", leaving);
    form.addEventListener("submit", (event) => {
        event.preventDefault();
        if (!kept.checked) {
            notice.replaceChildren(problem(t("sheet.needed")));
            return;
        }
        window.removeEventListener("beforeunload", leaving);
        backupScreen();
    });
    show(el("p", { class: "step no-print", text: t("setup.step", { step: 2 }) }),
         el("section", { class: "sheet", "aria-labelledby": "sheet-title" },
            el("h1", { id: "sheet-title", text: t("sheet.title") }),
            el("p", { text: t("sheet.intro") }), facts,
            el("p", { class: "label", text: t("sheet.code") }), code,
            el("p", { class: "hint", text: t("sheet.once") })),
         el("p", { class: "no-print" }, print, " ", save), form);
}

/// Where backups go: a folder the person chooses, or later in Settings.
async function backupScreen() {
    const settings = await api("GET", "settings");
    const [folderField, folder] = field("backup-folder", t("backup.folder"),
                                        t("backup.folder_hint"),
                                        { value: settings.backup_folder ??
                                                 settings.suggested_backup_folder });
    const notice = el("div");
    const use = el("button", { type: "submit", class: "primary", text: t("backup.use") });
    const later = el("button", { type: "button", text: t("backup.later") });
    later.addEventListener("click", () => home());
    const form = el("form", { novalidate: true }, folderField, notice, use, " ", later);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        use.disabled = true;
        try {
            await api("POST", "settings", { backup_folder: folder.value.trim() });
            home();
        } catch (error) {
            notice.replaceChildren(problem(t("error.server", { message: error.message })));
        } finally {
            use.disabled = false;
        }
    });
    show(el("p", { class: "step", text: t("setup.step", { step: 3 }) }),
         el("h1", { text: t("backup.title") }), el("p", { text: t("backup.intro") }), form);
}

/// The recovery code and a new passkey, for an owner who lost theirs.
function recoverScreen() {
    const [codeField, code] = field("recover-code", t("recover.code"), t("recover.code_hint"),
                                    { autocomplete: "off", spellcheck: "false",
                                      autocapitalize: "characters" });
    const [nameField, name] = field("recover-name", t("recover.name"), t("recover.name_hint"),
                                    { autocomplete: "name", maxlength: 64 });
    const [deviceField, device] = field("recover-device", t("enroll.device"),
                                        t("enroll.device_hint"), { maxlength: 64 });
    const button = el("button", { type: "submit", class: "primary", text: t("recover.button") });
    const notice = el("div");
    const form = el("form", { novalidate: true }, codeField, nameField, deviceField, notice,
                    button);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!passkeysAvailable()) {
            notice.replaceChildren(problem(t("error.no_passkeys")));
            return;
        }
        button.disabled = true;
        status(t("status.working"));
        try {
            const answer = await recover(code.value.trim(), name.value.trim(),
                                         device.value.trim());
            code.value = "";
            state.flash = t("recover.done");
            signedIn(answer);
        } catch (error) {
            notice.replaceChildren(problem(error instanceof ApiError && error.status === 403
                ? t("recover.wrong") : passkeyProblem(error)));
        } finally {
            button.disabled = false;
            status("");
        }
    });
    show(el("h1", { text: t("recover.title") }), el("p", { text: t("recover.intro") }), form);
}

/// A message for the next screen only.
function flash() {
    const message = state.flash;
    state.flash = null;
    return message ? el("p", { class: "notice", role: "status", text: message }) : null;
}

async function homeScreen() {
    let home;
    try {
        home = await api("GET", "home");
    } catch (error) {
        // Locked: Home waits for the unlock, and says how.
        if (error instanceof ApiError && error.status === 423) {
            state.who.keys = "locked";
            show(flash(), keysNotice(), el("h1", { text: t("home.title") }),
                 el("p", { class: "hint", text: t("home.locked") }));
            return;
        }
        throw error;
    }
    const counts = el("dl", { class: "facts" });
    for (const key of ["actors", "records", "contracts", "instances", "open_requests"]) {
        counts.append(el("dt", { text: t(`count.${key}`) }),
                      el("dd", { text: String(home.counts[key]) }));
    }
    show(flash(), keysNotice(), slotNotice(), el("h1", { text: t("home.title") }),
         el("dl", { class: "facts" },
            el("dt", { text: t("home.organization") }), el("dd", { text: home.ledger.organization }),
            el("dt", { text: t("home.ledger") }), el("dd", { class: "id", text: home.ledger.id })),
         el("h2", { text: t("home.counts") }), counts);
}

function table(caption, columns, rows) {
    if (rows.length === 0) {
        return [el("h2", { text: caption }), el("p", { text: t("things.none") })];
    }
    const head = el("tr", {}, columns.map(([key]) => el("th", { scope: "col", text: t(key) })));
    const body = rows.map((row) =>
        el("tr", {}, columns.map(([key, cell]) => {
            const value = cell(row);
            if (value instanceof Node) {
                return el("td", { "data-label": t(key) }, value);
            }
            return el("td", { "data-label": t(key), class: value.id ? "id" : null,
                              text: value.text ?? value });
        })));
    return [el("table", {}, el("caption", { text: caption }), el("thead", {}, head),
               el("tbody", {}, body))];
}

const short = (id) => ({ id: true, text: `${id.slice(0, 12)}...` });

/// A file's size in the reader's units.
function sizeText(bytes) {
    const format = (n, unit) => t(unit, { n: new Intl.NumberFormat(state.language,
                                                                     { maximumFractionDigits: 1 })
                                                 .format(n) });
    if (bytes < 1024) {
        return format(bytes, "size.bytes");
    }
    if (bytes < 1024 * 1024) {
        return format(bytes / 1024, "size.kib");
    }
    return format(bytes / (1024 * 1024), "size.mib");
}

/// Uploads a file for a registration; its upload id.
async function uploadFile(file) {
    const headers = { "Content-Type": "application/octet-stream" };
    const token = stored(sessionStorage, SESSION);
    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }
    const response = await fetch(`api/uploads?name=${encodeURIComponent(file.name)}`, {
        method: "POST", headers, body: file, credentials: "omit", cache: "no-store",
    });
    const answer = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new ApiError(response.status, answer?.error?.message ?? String(response.status));
    }
    return answer.upload;
}
const yesNo = (value) => t(value ? "value.yes" : "value.no");

async function thingsScreen() {
    const things = await api("GET", "things");
    const records = table(t("things.records"), [
        ["column.type", (r) => el("a", { href: `#/thing/${r.id}`, text: r.type })],
        ["column.state", (r) => (r.revoked ? t("value.revoked") : r.state)],
        ["column.registrant", (r) => r.registrant.name ?? short(r.registrant.id).text],
        ["column.endorsements", (r) => String(r.endorsements)],
        ["column.id", (r) => short(r.id)],
        ...(state.who.role === "viewer" ? [] : [["column.actions", (r) => {
            const button = el("button", { type: "button", text: t("act.button"),
                                          "aria-label": t("act.label", { type: r.type }) });
            button.addEventListener("click", () => actScreen(r));
            return button;
        }]]),
    ], things.records);
    const instances = table(t("things.instances"), [
        ["column.contract", (i) => i.contract_name ?? short(i.contract).text],
        ["column.status", (i) => i.status ?? t("value.none")],
        ["column.final", (i) => yesNo(i.final)],
        ["column.open_requests", (i) => String(i.open_requests)],
        ["column.id", (i) => short(i.id)],
    ], things.instances);
    const register = state.who.role === "viewer" ? null
        : el("p", {}, el("a", { href: "#/new", class: "button", text: t("register.button") }));
    show(el("h1", { text: t("things.title") }), el("p", { class: "hint", text: t("things.hint") }),
         register, ...records, ...instances,
         things.more ? el("p", { class: "hint", text: t("things.more") }) : null);
}

// --- A thing's page, and its proof --------------------------------------------------

/// Fetches a file from the console and saves it (the session's token goes
/// in a header, so no plain link can fetch it).
async function saveDownload(path, options, fallback) {
    const headers = { ...(options.headers ?? {}) };
    const token = stored(sessionStorage, SESSION);
    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }
    const response = await fetch(`api/${path}`, { ...options, headers, credentials: "omit",
                                                 cache: "no-store" });
    if (!response.ok) {
        const answer = await response.json().catch(() => ({}));
        throw new ApiError(response.status, answer?.error?.message ?? String(response.status));
    }
    const disposition = response.headers.get("Content-Disposition") ?? "";
    const named = disposition.match(/filename\*=UTF-8''(.+)$/);
    const name = named ? decodeURIComponent(named[1]) : fallback;
    const url = URL.createObjectURL(await response.blob());
    const link = el("a", { href: url, download: name });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    return name;
}

async function thingScreen(id) {
    const thing = await api("GET", `records/${id}`);
    const facts = el("dl", { class: "facts" });
    const fact = (key, value, attributes = {}) => {
        facts.append(el("dt", { text: t(key) }), el("dd", { text: String(value), ...attributes }));
    };
    fact("column.type", thing.type);
    fact("column.state", thing.revoked ? t("value.revoked") : thing.state);
    fact("column.registrant", thing.registrant.name ?? short(thing.registrant.id).text);
    fact("thing.entry", thing.index);
    fact("column.id", thing.id, { class: "id" });
    for (const [name, value] of Object.entries(thing.metadata)) {
        fact("thing.public", `${name}: ${value}`);
    }
    const parts = [keysNotice(), el("h1", { text: thing.kind ?? thing.type }), facts,
                   el("h2", { text: t("thing.private_title") })];
    if (!thing.private.allowed) {
        parts.push(el("p", { class: "hint", text: t("thing.private_hidden") }));
    } else if (thing.private.locked) {
        parts.push(el("p", { class: "hint", text: t("thing.private_locked") }));
    } else if (thing.private.fields === null) {
        parts.push(el("p", { class: "hint", text: t("thing.private_elsewhere") }));
    } else {
        const fields = el("dl", { class: "facts" });
        for (const f of thing.private.fields) {
            fields.append(el("dt", { text: f.name }), el("dd", { text: f.value }));
        }
        parts.push(fields);
    }
    parts.push(el("h2", { text: t("thing.files_title") }));
    if (thing.files.length === 0) {
        parts.push(el("p", { text: t("thing.no_files") }));
    }
    const notice = el("div");
    for (const f of thing.files) {
        const line = el("p", { text: `${f.name}, ${sizeText(f.size)} ` });
        if (f.kept && thing.private.allowed && !thing.private.locked) {
            const save = el("button", { type: "button", text: t("thing.download"),
                                        "aria-label": t("thing.download_label", { name: f.name }) });
            save.addEventListener("click", async () => {
                try {
                    await saveDownload(`records/${thing.id}/files/${f.index}`, {}, f.name);
                } catch (error) {
                    notice.replaceChildren(problem(t("error.server", { message: error.message })));
                }
            });
            line.append(save);
        } else if (!f.kept) {
            line.append(t("thing.not_kept"));
        }
        parts.push(line);
    }
    parts.push(notice, el("h2", { text: t("thing.endorsements_title") }));
    if (thing.endorsements.length === 0) {
        parts.push(el("p", { text: t("things.none") }));
    } else {
        parts.push(el("ul", {}, thing.endorsements.map((e) => el("li", {
            text: t("thing.endorsed", { name: e.actor.name ?? short(e.actor.id).text, role: e.role }),
        }))));
    }
    const actions = el("p", { class: "actions" });
    const share = el("button", { type: "button", class: "primary", text: t("share.button") });
    share.addEventListener("click", () => shareScreen(thing));
    actions.append(share);
    if (state.who.role !== "viewer" && !thing.revoked) {
        const act = el("button", { type: "button", text: t("act.button"),
                                   "aria-label": t("act.label", { type: thing.type }) });
        act.addEventListener("click", () => actScreen({ id: thing.id, type: thing.type }));
        actions.append(" ", act);
    }
    parts.push(actions);
    show(...parts);
}

/// Sharing proof: the fields to disclose and whether to open the files;
/// the proof as a file, and the files to send along.
function shareScreen(thing) {
    const boxes = [];
    const fields = el("fieldset", {}, el("legend", { text: t("share.disclose") }));
    const readable = thing.private.allowed && Array.isArray(thing.private.fields);
    if (readable) {
        for (const f of thing.private.fields) {
            const box = el("input", { type: "checkbox", value: f.name });
            boxes.push(box);
            fields.append(el("label", { class: "check" }, box, " ", f.name));
        }
    } else {
        fields.append(el("p", { class: "hint", text: t("share.nothing_private") }));
    }
    const filesBox = el("input", { type: "checkbox", checked: thing.files.length > 0 && readable });
    const files = thing.files.length > 0 && readable
        ? el("label", { class: "check" }, filesBox, " ", t("share.files")) : null;
    const notice = el("div");
    const after = el("div");
    const make = el("button", { type: "submit", class: "primary", text: t("share.make") });
    const form = el("form", { novalidate: true }, fields, files, notice, make, " ",
                    (() => {
                        const back = el("button", { type: "button", text: t("approve.cancel") });
                        back.addEventListener("click", () => thingScreen(thing.id));
                        return back;
                    })());
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        make.disabled = true;
        status(t("status.working"));
        try {
            const disclose = boxes.filter((b) => b.checked).map((b) => b.value);
            const withFiles = !!files && filesBox.checked;
            const saved = await saveDownload("proof", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ record: thing.id, disclose, files: withFiles }),
            }, "proof.cbor");
            const sendAlong = withFiles ? thing.files.filter((f) => f.kept).map((f) => {
                const save = el("button", { type: "button",
                                            text: t("thing.download_label", { name: f.name }) });
                save.addEventListener("click", () =>
                    saveDownload(`records/${thing.id}/files/${f.index}`, {}, f.name));
                return el("p", {}, save);
            }) : [];
            after.replaceChildren(el("p", { role: "status", text: t("share.made", { name: saved }) }),
                                  el("p", { text: t(withFiles ? "share.send_files" : "share.send") }),
                                  ...sendAlong);
        } catch (error) {
            notice.replaceChildren(problem(error.status === 423 ? t("keys.locked")
                                                                : t("error.server", { message: error.message })));
        } finally {
            make.disabled = false;
            status("");
        }
    });
    show(el("h1", { text: t("share.title") }), el("p", { class: "id", text: `${thing.type} ${thing.id}` }),
         el("p", { text: t("share.intro") }), form, after);
}

// --- Verify ----------------------------------------------------------------------------

/// A localized verification report, from the verifier's JSON.
function reportView(report) {
    const parts = [];
    if (report.error) {
        parts.push(el("div", { class: "error", role: "alert" },
                      el("strong", { text: t("verify.failed") }),
                      el("p", { text: t("verify.reason", { reason: report.error }) })));
        return parts;
    }
    const mismatch = (report.attachments ?? []).some((a) => a.status === "mismatch");
    const unconfirmed = !report.ledger.id_checked;
    parts.push(el("div", { class: mismatch ? "error" : "notice", role: "status" },
                  el("strong", { text: t(mismatch ? "verify.mismatch_title"
                                                  : unconfirmed ? "verify.unconfirmed_title"
                                                                : "verify.verified_title") }),
                  el("p", { text: t(mismatch ? "verify.mismatch"
                                             : unconfirmed ? "verify.unconfirmed" : "verify.verified") })));
    const facts = el("dl", { class: "facts" });
    const fact = (key, value, attributes = {}) => {
        facts.append(el("dt", { text: t(key) }), el("dd", { text: String(value), ...attributes }));
    };
    fact("verify.organization", report.ledger.organization);
    fact("home.ledger", report.ledger.id, { class: "id" });
    fact("verify.checkpoint", t("verify.checkpoint_value", { size: report.checkpoint.tree_size ??
                                                                    report.checkpoint.size,
                                                             time: report.checkpoint.timestamp ?? "" }));
    if (report.kind === "record") {
        fact("column.type", report.record.type);
        fact("column.state", report.record.revoked ? t("value.revoked") : report.record.state);
        fact("column.id", report.record.id, { class: "id" });
    }
    parts.push(facts);
    if (report.events) {
        parts.push(el("h2", { text: t("verify.history") }));
        parts.push(el("ol", { class: "events" }, report.events.map((e) => {
            const who = e.actor.kind === "person"
                ? t(e.presence ? (e.presence.user_verified ? "verify.person_present"
                                                           : "verify.person_passkey")
                               : "verify.person_not_present", { name: e.actor.name })
                : t(`verify.actor.${e.actor.kind}`, { name: e.actor.name });
            const what = t(`verify.event.${e.type}`, { detail: e.detail ?? "" });
            return el("li", {}, el("span", { class: "id", text: `#${e.index} ` }),
                      `${what} ${t("verify.by", { who })} `,
                      el("span", { class: "hint", text: e.registered_at }));
        })));
    }
    const disclosed = Object.entries(report.disclosed_fields ?? {});
    if (disclosed.length > 0) {
        parts.push(el("h2", { text: t("verify.disclosed") }));
        const fields = el("dl", { class: "facts" });
        for (const [name, value] of disclosed) {
            fields.append(el("dt", { text: name }),
                          el("dd", { text: typeof value === "string" ? value : JSON.stringify(value) }));
        }
        parts.push(fields);
    }
    if ((report.attachments ?? []).length > 0) {
        parts.push(el("h2", { text: t("verify.files") }));
        parts.push(el("ul", {}, report.attachments.map((a) => el("li", {
            class: a.status === "mismatch" ? "bad" : null,
            text: t(`verify.file.${a.status}`, { name: a.name, size: sizeText(a.size) }),
        }))));
    }
    parts.push(el("p", { class: "hint", text: t(report.complete ? "verify.complete"
                                                                : "verify.incomplete") }));
    return parts;
}

/// Checking a proof, in this browser: the proof file, the files it may
/// check, and the ledger it should come from.
function verifyScreen() {
    const proofInput = el("input", { id: "verify-proof", type: "file", accept: ".cbor,application/cbor" });
    const filesInput = el("input", { id: "verify-files", type: "file", multiple: true });
    const [ledgerField, ledgerInput] = field("verify-ledger", t("verify.ledger"), t("verify.ledger_hint"),
                                             { spellcheck: "false", maxlength: 64 });
    const result = el("section", { "aria-live": "polite", "aria-labelledby": "verify-result" });
    let proof = null;
    const files = new Map();
    const check = async () => {
        if (!proof) {
            return;
        }
        const checker = await loadChecker();
        if (!checker) {
            result.replaceChildren(problem(t("verify.unavailable")));
            return;
        }
        const report = checker.verify(proof, files, ledgerInput.value.trim().toLowerCase());
        result.replaceChildren(el("h2", { id: "verify-result", text: t("verify.result") }),
                               ...reportView(report));
    };
    const take = async (list) => {
        for (const file of list) {
            const bytes = new Uint8Array(await file.arrayBuffer());
            if (file.name.endsWith(".cbor") && !proof) {
                proof = bytes;
            } else {
                files.set(file.name, bytes);
            }
        }
        await check();
    };
    proofInput.addEventListener("change", async () => {
        proof = null;
        await take(proofInput.files);
    });
    filesInput.addEventListener("change", async () => {
        for (const file of filesInput.files) {
            files.set(file.name, new Uint8Array(await file.arrayBuffer()));
        }
        await check();
    });
    ledgerInput.addEventListener("change", check);
    const drop = el("section", { class: "drop", "aria-label": t("verify.drop") },
                    el("p", { text: t("verify.drop") }));
    drop.addEventListener("dragover", (event) => {
        event.preventDefault();
        drop.classList.add("over");
    });
    drop.addEventListener("dragleave", () => drop.classList.remove("over"));
    drop.addEventListener("drop", async (event) => {
        event.preventDefault();
        drop.classList.remove("over");
        await take(event.dataTransfer.files);
    });
    show(el("h1", { text: t("verify.title") }), el("p", { text: t("verify.intro") }), drop,
         el("div", { class: "field" }, el("label", { for: "verify-proof", text: t("verify.proof") }),
            proofInput),
         el("div", { class: "field" }, el("label", { for: "verify-files", text: t("verify.with_files") }),
            filesInput),
         ledgerField, result);
}

// --- Kinds and new documents --------------------------------------------------------

/// A kind's record type, suggested from its name (the user may change it):
/// the name in lower case, spaces as dashes, version 1.
function kindType(name) {
    const slug = name.trim().toLowerCase().replace(/\s+/g, "-");
    return slug ? `${slug}/1` : "";
}

async function kindsScreen() {
    const listed = await api("GET", "kinds");
    const parts = [el("h1", { text: t("kinds.title") }), el("p", { class: "hint", text: t("kinds.hint") })];
    if (listed.kinds.length === 0) {
        parts.push(el("p", { text: t("kinds.none") }));
    }
    for (const kind of listed.kinds) {
        const fields = el("ul", {}, kind.fields.map((f) => el("li", {
            text: t(f.private ? "kinds.field_private" : "kinds.field_public",
                    { name: f.label || f.name, type: t(`field.${f.type}`) }) +
                  (f.required ? t("kinds.required") : ""),
        })));
        const section = el("section", { class: "kind", "aria-labelledby": `kind-${kind.type}` },
                           el("h2", { id: `kind-${kind.type}`, text: kind.name }),
                           el("p", { class: "id", text: kind.type }),
                           kind.description ? el("p", { text: kind.description }) : null,
                           fields, el("p", { text: t(`kinds.files.${kind.files}`) }));
        if (listed.may_change) {
            const remove = el("button", { type: "button", text: t("kinds.remove"),
                                          "aria-label": t("kinds.remove_label", { name: kind.name }) });
            remove.addEventListener("click", async () => {
                await api("POST", "kinds", { remove: kind.type });
                route();
            });
            section.append(remove);
        }
        parts.push(section);
    }
    if (listed.may_change) {
        parts.push(kindForm());
    }
    show(...parts);
}

/// The form that defines a kind: a name, its fields, and its files.
function kindForm() {
    const [nameField, name] = field("kind-name", t("kinds.name"), t("kinds.name_hint"),
                                    { maxlength: 64 });
    const [typeField, type] = field("kind-type", t("kinds.type"), t("kinds.type_hint"),
                                    { maxlength: 128, spellcheck: "false" });
    let typed = false;
    type.addEventListener("input", () => { typed = true; });
    name.addEventListener("input", () => {
        if (!typed) {
            type.value = kindType(name.value);
        }
    });
    const rows = el("div", { class: "kind-fields" });
    let count = 0;
    const addRow = () => {
        count += 1;
        const n = count;
        const label = el("input", { id: `kind-field-${n}`, maxlength: 64,
                                    "aria-label": t("kinds.field_name", { n }) });
        const kindOf = el("select", { "aria-label": t("kinds.field_type", { n }) },
                          ["text", "number", "date", "yes-no"].map((v) =>
                              el("option", { value: v, text: t(`field.${v}`) })));
        const secret = el("input", { type: "checkbox", checked: true });
        const required = el("input", { type: "checkbox" });
        const row = el("fieldset", { class: "kind-field" },
                       el("legend", { text: t("kinds.field", { n }) }),
                       el("label", { for: `kind-field-${n}`, text: t("kinds.field_label") }), label,
                       kindOf,
                       el("label", { class: "check" }, secret, " ", t("kinds.private")),
                       el("label", { class: "check" }, required, " ", t("kinds.required_box")));
        row.read = () => ({ name: label.value.trim(), type: kindOf.value, private: secret.checked,
                            required: required.checked });
        rows.append(row);
        label.focus();
    };
    const more = el("button", { type: "button", text: t("kinds.add_field") });
    more.addEventListener("click", addRow);
    const files = el("select", { id: "kind-files" },
                     ["optional", "required", "none"].map((v) =>
                         el("option", { value: v, text: t(`kinds.files.${v}`) })));
    const keep = el("input", { type: "checkbox", id: "kind-keep", checked: true });
    const notice = el("div");
    const save = el("button", { type: "submit", class: "primary", text: t("kinds.save") });
    const form = el("form", { novalidate: true, "aria-labelledby": "kind-new" },
                    el("h2", { id: "kind-new", text: t("kinds.new") }), nameField, typeField, rows,
                    more,
                    el("div", { class: "field" }, el("label", { for: "kind-files", text: t("kinds.files_label") }), files),
                    el("label", { class: "check" }, keep, " ", t("kinds.keep")), notice, save);
    addRow();
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const fields = [...rows.children].map((r) => r.read()).filter((f) => f.name);
        try {
            await api("POST", "kinds", {
                sheet: 1, kind: "document", type: type.value.trim(), name: name.value.trim(),
                fields: fields.map((f) => ({ name: f.name, label: f.name, type: f.type,
                                             private: f.private, required: f.required })),
                files: files.value, keep_files: keep.checked,
            });
            route();
        } catch (error) {
            notice.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    return form;
}

/// Registering a document: a kind, its fields, its files, then the tap.
async function newDocumentScreen() {
    const listed = await api("GET", "kinds");
    if (listed.kinds.length === 0) {
        show(el("h1", { text: t("register.title") }), el("p", { text: t("register.no_kinds") }),
             el("p", {}, el("a", { href: "#/kinds", text: t("register.define") })));
        return;
    }
    const chooser = el("select", { id: "register-kind" },
                       listed.kinds.map((k) => el("option", { value: k.type, text: k.name })));
    const area = el("div");
    const notice = el("div");
    const inputs = new Map();
    let fileInput;
    const render = () => {
        const kind = listed.kinds.find((k) => k.type === chooser.value);
        inputs.clear();
        const parts = kind.fields.map((f, i) => {
            const id = `register-field-${i}`;
            let input;
            if (f.type === "yes-no") {
                input = el("select", { id }, el("option", { value: "", text: "" }),
                           el("option", { value: "yes", text: t("value.yes") }),
                           el("option", { value: "no", text: t("value.no") }));
            } else {
                input = el("input", { id, type: f.type === "date" ? "date" : "text",
                                      inputmode: f.type === "number" ? "decimal" : null,
                                      required: f.required, maxlength: 4096 });
            }
            inputs.set(f.name, input);
            return el("div", { class: "field" },
                      el("label", { for: id, text: (f.label || f.name) +
                                                   (f.required ? t("register.required_mark") : "") }),
                      input,
                      el("span", { class: "hint", text: t(f.private ? "register.private_hint"
                                                                    : "register.public_hint") }));
        });
        if (kind.files !== "none") {
            fileInput = el("input", { id: "register-files", type: "file", multiple: true,
                                      required: kind.files === "required" });
            parts.push(el("div", { class: "field" },
                          el("label", { for: "register-files", text: t("register.files") }),
                          fileInput,
                          el("span", { class: "hint", text: t(kind.keep_files ? "register.files_kept"
                                                                              : "register.files_not_kept") })));
        } else {
            fileInput = null;
        }
        area.replaceChildren(...parts);
    };
    chooser.addEventListener("change", render);
    render();
    const prepare = el("button", { type: "submit", class: "primary", text: t("act.prepare") });
    const form = el("form", { novalidate: true },
                    el("div", { class: "field" },
                       el("label", { for: "register-kind", text: t("register.kind") }), chooser),
                    area, notice, prepare);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        prepare.disabled = true;
        status(t("status.working"));
        try {
            const fields = {};
            for (const [name, input] of inputs) {
                if (input.value.trim()) {
                    fields[name] = input.value.trim();
                }
            }
            // Each file uploaded, and kept here too: the page checks its
            // commitment before the tap.
            const files = new Map();
            const uploads = [];
            for (const file of fileInput?.files ?? []) {
                if (file.size > 16 * 1024 * 1024) {
                    throw new ApiError(413, t("register.too_large", { name: file.name }));
                }
                const id = await uploadFile(file);
                uploads.push(id);
                files.set(id, new Uint8Array(await file.arrayBuffer()));
            }
            const prepared = await api("POST", "prepare", {
                action: "record.register", kind: chooser.value, fields, files: uploads,
            });
            await approveScreen(prepared, files);
        } catch (error) {
            notice.replaceChildren(problem(error.status === 423 ? t("keys.locked")
                                                                : t("error.server", { message: error.message })));
        } finally {
            prepare.disabled = false;
            status("");
        }
    });
    show(el("h1", { text: t("register.title") }), form);
}

// --- Settings ----------------------------------------------------------------------

async function settingsScreen() {
    const settings = await api("GET", "settings");
    const parts = [el("h1", { text: t("settings.title") })];
    const ledger = settings.ledger;
    parts.push(el("h2", { text: t("settings.ledger") }));
    if (ledger) {
        parts.push(el("dl", { class: "facts" },
                      el("dt", { text: t("home.organization") }),
                      el("dd", { text: ledger.organization }),
                      el("dt", { text: t("home.ledger") }), el("dd", { class: "id", text: ledger.id }),
                      el("dt", { text: t("settings.entries") }),
                      el("dd", { text: String(ledger.entries) }),
                      el("dt", { text: t("settings.hash") }), el("dd", { text: ledger.hash }),
                      el("dt", { text: t("settings.directory") }),
                      el("dd", { class: "id", text: settings.directory })));
    } else {
        parts.push(el("p", { class: "hint", text: t("home.locked") }));
    }

    parts.push(el("h2", { text: t("settings.language") }),
               el("p", { class: "hint", text: t("settings.language_here") }));
    const notice = el("div", { role: "status" });
    const changeable = settings.may_change;
    const language = el("select", { id: "default-language", disabled: !changeable },
                        el("option", { value: "", text: t("settings.browser_language") }),
                        settings.languages.map((l) => el("option", {
                            value: l, lang: l,
                            text: document.querySelector(`#language option[value="${l}"]`)
                                ?.textContent ?? l,
                        })));
    language.value = settings.language ?? "";
    parts.push(el("div", { class: "field" },
                  el("label", { for: "default-language", text: t("settings.default_language") }),
                  language));

    parts.push(el("h2", { text: t("settings.backups") }));
    const [folderField, folder] = field("settings-backup", t("backup.folder"),
                                        t("backup.folder_hint"),
                                        { value: settings.backup_folder ?? "",
                                          placeholder: settings.suggested_backup_folder,
                                          disabled: !changeable });
    parts.push(folderField, el("p", { class: "hint", text: t("settings.backup_note") }));
    if (changeable) {
        const save = el("button", { type: "button", class: "primary", text: t("settings.save") });
        save.addEventListener("click", async () => {
            save.disabled = true;
            try {
                const typed = folder.value.trim();
                const saved = await api("POST", "settings", {
                    language: language.value === "" ? null : language.value,
                    backup_folder: typed === "" ? null : typed,
                });
                state.defaultLanguage = saved.language;
                notice.replaceChildren(el("p", { text: t("settings.saved") }));
            } catch (error) {
                notice.replaceChildren(problem(t("error.server", { message: error.message })));
            } finally {
                save.disabled = false;
            }
        });
        parts.push(notice, save);
    } else {
        parts.push(el("p", { class: "hint", text: t("settings.read_only") }));
    }

    parts.push(el("h2", { text: t("settings.keys") }),
               el("p", { id: "keys-state", text: t(`settings.keys_state.${settings.keys}`) }));
    if (changeable && settings.keys === "unlocked") {
        const lock = el("button", { type: "button", text: t("settings.lock") });
        lock.addEventListener("click", async () => {
            const result = await api("POST", "unlock", { lock: true });
            state.who.keys = result.keys;
            route();
        });
        parts.push(lock);
    }
    show(keysNotice(), ...parts);
}

// --- Rules --------------------------------------------------------------------------

/// The rules sheet's shape, which the form follows. Each key holds a piece
/// of Bo text as written (names, types, values, conditions, in any
/// language), a piece that may stay empty, a yes or no, a choice, a list, or
/// a group of its own; `rules.CONTEXT.KEY` is its label in the catalogs (a
/// list's items `.item`, its button `.add`, a hint `.hint`). The compiler
/// checks the source the sheet writes, so the page checks nothing but what
/// is missing.
const OUTCOMES = ["done", "fails", "expires"];
const piece = { kind: "piece" };
const maybe = { kind: "maybe" };
const yes = { kind: "yes" };
const choice = (values, optional = false) => ({ kind: "choice", values, optional });
const listOf = (of) => ({ kind: "list", of });
const group = (context, keys) => ({ kind: "group", context, keys });

const ASSIGN = group("assign", [["name", piece], ["value", piece]]);
const REQUEST = group("request", [["kind", piece], ["to", maybe], ["with", listOf(ASSIGN)],
                                  ["within", piece]]);
const EFFECTS = [["from", listOf(piece), "effects"], ["to_state", maybe, "effects"],
                 ["set", listOf(ASSIGN), "effects"], ["requests", listOf(REQUEST), "effects"]];
const SHEET = group("sheet", [
    ["contract", piece],
    ["parties", listOf(piece)],
    ["thing", group("thing", [
        ["word", piece], ["name", piece],
        ["fields", listOf(group("field", [["name", piece], ["type", piece], ["default", maybe]]))],
    ])],
    ["actions", listOf(group("action", [
        ["action", piece], ["by", maybe], ["to", maybe],
        ["inputs", listOf(group("input", [["name", piece], ["type", piece]]))],
        ["requires", listOf(piece)], ["consent_of", listOf(piece)], ["in_person", yes],
        ["in_person_over", maybe], ["agents_propose", yes], ...EFFECTS,
    ]))],
    ["rules", listOf(group("rule", [["when", piece], ["do", listOf(piece)], ...EFFECTS]))],
    ["answers", listOf(group("answer", [["kind", piece], ["outcome", choice(OUTCOMES)],
                                        ["do", listOf(piece)], ...EFFECTS]))],
    ["tests", listOf(group("test", [
        ["name", maybe],
        ["steps", listOf(group("step", [
            ["party", piece], ["action", piece], ["outcome", choice(OUTCOMES, true)],
            ["args", listOf(piece)], ["to", maybe], ["by", maybe], ["with", listOf(ASSIGN)],
            ["expect", maybe],
        ]))],
    ]))],
]);

const RULES_INPUT = 256 * 1024;
const mayWriteRules = () => state.who.role === "owner" || state.who.role === "admin";

function blank(desc) {
    switch (desc.kind) {
    case "piece":
        return "";
    case "maybe":
        return null;
    case "yes":
        return false;
    case "choice":
        return desc.optional ? null : desc.values[0];
    case "list":
        return [];
    default:
        return Object.fromEntries(desc.keys.map(([key, d]) => [key, blank(d)]));
    }
}

/// A sheet read from the compiler or a file, every key the form shows filled in.
function filled(desc, value) {
    switch (desc.kind) {
    case "list":
        return Array.isArray(value) ? value.map((v) => filled(desc.of, v)) : [];
    case "group": {
        const object = value !== null && typeof value === "object" ? value : {};
        return Object.fromEntries(desc.keys.map(([key, d]) => [key, filled(d, object[key])]));
    }
    case "yes":
        return value === true;
    case "piece":
        return typeof value === "string" ? value : "";
    default:
        return typeof value === "string" ? value : blank(desc);
    }
}

function openedSheet(value) {
    const sheet = { packs: Array.isArray(value.packs) ? [...value.packs] : [],
                    ...filled(SHEET, value) };
    if (sheet.thing.word === "") {
        sheet.thing.word = "thing";
    }
    return sheet;
}

function newSheet() {
    return openedSheet({ parties: [""] });
}

/// What the compiler gets: pieces without spaces at either end, empty
/// optional pieces left out, and no kind block when the kind has no name
/// and no fields.
function sendable(desc, value) {
    switch (desc.kind) {
    case "piece":
        return value.trim();
    case "maybe": {
        const text = (value ?? "").trim();
        return text === "" ? null : text;
    }
    case "list":
        return value.map((v) => sendable(desc.of, v));
    case "group":
        return Object.fromEntries(desc.keys.map(([key, d]) => [key, sendable(d, value[key])]));
    default:
        return value;
    }
}

function sheetToSend(sheet) {
    const out = { sheet: 1, kind: "rules", packs: sheet.packs, ...sendable(SHEET, sheet) };
    if (out.thing.name === "" && out.thing.fields.length === 0) {
        out.thing = null;
    }
    return out;
}

/// The pieces left empty that must be filled in.
function missingPieces(sheet) {
    const out = [];
    const walk = (desc, value, path) => {
        if (desc.kind === "piece" && value.trim() === "") {
            out.push({ path, message: t("rules.required") });
        } else if (desc.kind === "list") {
            value.forEach((v, i) => walk(desc.of, v, `${path}/${i}`));
        } else if (desc.kind === "group") {
            desc.keys.forEach(([key, d]) => walk(d, value[key], `${path}/${key}`));
        }
    };
    const kind = sheetToSend(sheet).thing !== null;
    for (const [key, d] of SHEET.keys) {
        if (key !== "thing" || kind) {
            walk(d, sheet[key], `/${key}`);
        }
    }
    return out;
}

/// A sheet path in the reader's words: "Action 1 › Condition 2".
function placeOf(path) {
    const names = [];
    let desc = SHEET;
    let labelKey = null;
    const parts = (path ?? "").split("/").slice(1);
    for (let i = 0; i < parts.length; i++) {
        if (desc.kind === "group") {
            const entry = desc.keys.find(([key]) => key === parts[i]);
            if (!entry) {
                if (parts[i] === "packs") {
                    names.push(t("rules.packs"));
                }
                break;
            }
            labelKey = `rules.${entry[2] ?? desc.context}.${parts[i]}`;
            desc = entry[1];
            if (desc.kind !== "list" || i === parts.length - 1) {
                names.push(t(labelKey));
            }
        } else if (desc.kind === "list") {
            names.push(t(`${labelKey}.item`, { n: Number(parts[i]) + 1 }));
            desc = desc.of;
        } else {
            break;
        }
    }
    return names.join(" › ");
}

function hintOf(labelKey, id) {
    const key = `${labelKey}.hint`;
    return state.english[key] === undefined ? null
                                             : el("span", { id, class: "hint", text: t(key) });
}

/// The form for one key of a group (or one item of a list): its inputs
/// write into the sheet as the person types; adding or removing an item
/// draws the form again, focused on `path`.
function formPart(desc, holder, key, path, labelKey, redraw) {
    const value = holder[key];
    const id = `rules${path.replace(/\//g, "-")}`;
    switch (desc.kind) {
    case "piece":
    case "maybe": {
        const hint = hintOf(labelKey, `${id}-hint`);
        const input = el("input", { id, value: value ?? "", spellcheck: "false",
                                    autocomplete: "off", maxlength: 4096,
                                    "aria-describedby": hint ? `${id}-hint` : null });
        input.addEventListener("input", () => {
            holder[key] = input.value;
        });
        return el("div", { class: "field", "data-path": path },
                  el("label", { for: id, text: t(labelKey) }), input, hint);
    }
    case "yes": {
        const box = el("input", { type: "checkbox", id, checked: value });
        box.addEventListener("change", () => {
            holder[key] = box.checked;
        });
        return el("label", { class: "check", "data-path": path }, box, " ", t(labelKey));
    }
    case "choice": {
        const select = el("select", { id },
                          desc.optional ? el("option", { value: "", text: t("rules.outcome.none") })
                                        : null,
                          desc.values.map((v) => el("option", { value: v, selected: value === v,
                                                                text: t(`rules.outcome.${v}`) })));
        select.addEventListener("change", () => {
            holder[key] = select.value === "" ? null : select.value;
        });
        return el("div", { class: "field", "data-path": path },
                  el("label", { for: id, text: t(labelKey) }), select);
    }
    case "list": {
        const items = value.map((item, i) => {
            const itemPath = `${path}/${i}`;
            const name = t(`${labelKey}.item`, { n: i + 1 });
            const remove = el("button", { type: "button", class: "remove", text: t("rules.remove"),
                                          "aria-label": t("rules.remove_label", { what: name }) });
            remove.addEventListener("click", () => {
                value.splice(i, 1);
                redraw(path);
            });
            if (desc.of.kind === "group") {
                return groupPart(desc.of, item, itemPath, name, redraw, remove);
            }
            const input = el("input", { id: `rules${itemPath.replace(/\//g, "-")}`, value: item,
                                        spellcheck: "false", autocomplete: "off", maxlength: 4096,
                                        "aria-label": name });
            input.addEventListener("input", () => {
                value[i] = input.value;
            });
            return el("div", { class: "item", "data-path": itemPath }, input, remove);
        });
        const add = el("button", { type: "button", class: "add", text: t(`${labelKey}.add`) });
        add.addEventListener("click", () => {
            value.push(blank(desc.of));
            redraw(`${path}/${value.length - 1}`);
        });
        return el("fieldset", { class: "list", "data-path": path },
                  el("legend", { text: t(labelKey) }), hintOf(labelKey), items, add);
    }
    default:
        return groupPart(desc, value, path, t(labelKey), redraw);
    }
}

function groupPart(desc, value, path, legend, redraw, extra = null) {
    return el("fieldset", { class: "group", "data-path": path }, el("legend", { text: legend }),
              desc.keys.map(([key, d, context]) =>
                  formPart(d, value, key, `${path}/${key}`, `rules.${context ?? desc.context}.${key}`,
                           redraw)),
              extra);
}

/// The packs, as boxes to tick: a pack's words mean something only where
/// its box is ticked.
function packsPart(draft) {
    const boxes = (draft.packs ?? []).map((pack) => {
        const box = el("input", { type: "checkbox", checked: draft.sheet.packs.includes(pack.id) });
        box.addEventListener("change", () => {
            const others = draft.sheet.packs.filter((id) => id !== pack.id);
            draft.sheet.packs = box.checked ? [...others, pack.id] : others;
        });
        return el("label", { class: "check" }, box, " ",
                  t("rules.pack", { name: pack.name ?? pack.id, words: pack.words }));
    });
    return el("fieldset", { class: "list", "data-path": "/packs" },
              el("legend", { text: t("rules.packs") }),
              el("p", { class: "hint", text: t("rules.packs_hint") }), boxes);
}

/// Each problem shown on the part of the form it belongs to (or on the
/// nearest part that holds it).
function markProblems(area, problems) {
    problems.forEach((problem, n) => {
        let path = problem.path ?? "";
        let target = null;
        while (path !== "") {
            target = area.querySelector(`[data-path="${CSS.escape(path)}"]`);
            if (target) {
                break;
            }
            path = path.slice(0, path.lastIndexOf("/"));
        }
        if (!target) {
            return;
        }
        const id = `rules-problem-${n}`;
        const note = el("p", { id, class: problem.severity === "warning" ? "problem warning" : "problem",
                               text: t(problem.severity === "warning" ? "rules.warning" : "rules.error",
                                       { message: problem.message }) });
        const legend = target.querySelector(":scope > legend");
        if (legend) {
            legend.after(note);
        } else {
            target.append(note);
        }
        const input = target.querySelector(":scope > input, :scope > select, :scope > label > input");
        if (input) {
            input.setAttribute("aria-invalid", "true");
            const described = input.getAttribute("aria-describedby");
            input.setAttribute("aria-describedby", described ? `${described} ${id}` : id);
        }
    });
}

/// The sheet's form, drawn again whenever an item comes or goes (its
/// problems then forgotten: their places have moved).
function sheetForm(draft, moved) {
    const area = el("div", { class: "rules-form" });
    const redraw = (focus) => {
        draft.problems = [];
        moved();
        draw(focus);
    };
    const draw = (focus) => {
        const sheet = draft.sheet;
        area.replaceChildren(packsPart(draft),
                             ...SHEET.keys.map(([key, d]) =>
                                 formPart(d, sheet, key, `/${key}`, `rules.sheet.${key}`, redraw)));
        markProblems(area, draft.problems);
        if (focus) {
            const target = area.querySelector(`[data-path="${CSS.escape(focus)}"]`);
            const control = target?.querySelector("input, select") ?? target;
            const list = focus.match(/\/\d+$/) ? null : target?.querySelector(":scope > button.add");
            (list ?? control)?.focus();
        }
    };
    draw();
    area.redraw = () => draw();
    return area;
}

/// A problem in the list above the results: where (a place in the form, or
/// a line of the text), and a button that goes there.
function problemsPanel(problems, go) {
    if (problems.length === 0) {
        return null;
    }
    const errors = problems.some((p) => p.severity !== "warning");
    return el("div", { class: errors ? "error" : "notice", role: "alert" },
              el("strong", { text: t("rules.problems", { n: problems.length }) }),
              el("ul", {}, problems.map((p) => {
                  const where = p.line ? t("rules.at_line", { line: p.line, message: p.message })
                      : p.path ? t("rules.at_place", { place: placeOf(p.path), message: p.message })
                      : p.message;
                  const button = el("button", { type: "button", class: "link", text: where });
                  button.addEventListener("click", () => go(p));
                  return el("li", { class: p.severity === "warning" ? null : "bad" }, button);
              })));
}

/// The compiler's problems in the page's terms.
const problemsOf = (diagnostics, withLines) => (diagnostics ?? []).map((d) => ({
    path: d.path ?? null, severity: d.severity, message: d.message,
    line: withLines && d.span?.line > 0 ? d.span.line : null,
}));

function languageName(language) {
    return document.querySelector(`#language option[value="${language}"]`)?.textContent ?? language;
}

function slug(text) {
    return text.trim().toLowerCase().replace(/[^\p{L}\p{N}]+/gu, "-").replace(/^-|-$/g, "") || "rules";
}

/// The rules on this ledger, and retiring them.
async function rulesScreen() {
    const listed = await api("GET", "rules");
    const writes = mayWriteRules();
    const rows = table(t("rules.deployed"), [
        ["column.name", (c) => c.name ?? short(c.id).text],
        ["column.functions", (c) => c.functions.join(", ")],
        ["column.instances", (c) => String(c.instances)],
        ["thing.entry", (c) => String(c.index)],
        ["column.state", (c) => t(c.retired ? "value.retired" : "value.active")],
        ["column.id", (c) => short(c.id)],
        ...(writes ? [["column.actions", (c) => {
            if (c.retired) {
                return t("value.none");
            }
            const name = c.name ?? short(c.id).text;
            const button = el("button", { type: "button", text: t("rules.retire"),
                                          "aria-label": t("rules.retire_label", { name }) });
            button.addEventListener("click", () => retireScreen(c));
            return button;
        }]] : []),
    ], listed.contracts);
    show(keysNotice(), el("h1", { text: t("rules.title") }),
         el("p", { class: "hint", text: t("rules.hint") }),
         writes ? el("p", {}, el("a", { href: "#/rules/new", class: "button", text: t("rules.write") }))
                : null,
         ...rows);
}

function retireScreen(contract) {
    const name = contract.name ?? short(contract.id).text;
    const [reasonField, reason] = field("retire-reason", t("rules.retire_reason"),
                                        t("rules.retire_reason_hint"), { maxlength: 200 });
    const notice = el("div");
    const form = el("form", { novalidate: true }, reasonField, notice,
                    el("button", { type: "submit", class: "primary", text: t("act.prepare") }),
                    " ", backButton(t("approve.cancel")));
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            await approveScreen(await api("POST", "prepare", {
                action: "contract.retire", contract: contract.id, reason: reason.value.trim(),
            }));
        } catch (error) {
            notice.replaceChildren(problem(error.status === 423 ? t("keys.locked")
                                                                : passkeyProblem(error)));
        }
    });
    show(el("h1", { text: t("rules.retire_title", { name }) }),
         el("p", { text: t("rules.retire_intro") }), el("p", { class: "id", text: contract.id }), form);
}

/// Saves text as a file in the browser.
function saveText(text, name, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const link = el("a", { href: url, download: name });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/// The rules editor: the form and the Bo text are two views of the same
/// rules; the compiler, in the console, checks, explains, and tests them,
/// and a deploy is approved with a passkey. The draft lives as long as the
/// page.
async function rulesEditor() {
    if (!mayWriteRules()) {
        show(el("h1", { text: t("rules.editor_title") }), el("p", { text: t("rules.read_only") }));
        return;
    }
    const draft = state.rules ??= { sheet: newSheet(), source: "", view: "form", problems: [],
                                    packs: undefined, language: state.language };
    if (draft.packs === undefined) {
        try {
            draft.packs = (await api("GET", "rules/packs")).packs.filter((p) => p.id !== "core");
        } catch (error) {
            if (error instanceof ApiError && error.status === 501) {
                show(el("h1", { text: t("rules.editor_title") }),
                     el("p", { text: t("rules.no_compiler") }));
                return;
            }
            throw error;
        }
    }
    const view = el("div");
    const problems = el("div");
    const results = el("div", { "aria-live": "polite" });
    let form = null;
    let text = null;

    const formButton = el("button", { type: "button", text: t("rules.view_form") });
    const textButton = el("button", { type: "button", text: t("rules.view_text") });
    const actions = ["check", "explain", "test", "deploy"].map((what) =>
        el("button", { type: "button", class: what === "deploy" ? "primary" : null,
                       text: t(`rules.${what}`) }));
    const [check, explain, test, deploy] = actions;
    const opener = el("input", { id: "rules-open", type: "file", accept: ".bo,.json,text/plain,application/json",
                                 "aria-describedby": "rules-open-hint" });
    const download = el("button", { type: "button", text: t("rules.download") });
    const buttons = [formButton, textButton, ...actions, download, opener];

    const goTo = (p) => {
        if (draft.view === "text" && p.line && text) {
            const lines = text.value.split("\n");
            const start = lines.slice(0, p.line - 1).reduce((n, l) => n + l.length + 1, 0);
            text.focus();
            text.setSelectionRange(start, start + (lines[p.line - 1]?.length ?? 0));
            return;
        }
        let path = p.path ?? "";
        while (path !== "" && form) {
            const target = form.querySelector(`[data-path="${CSS.escape(path)}"]`);
            if (target) {
                (target.querySelector("input, select, button") ?? target).focus();
                return;
            }
            path = path.slice(0, path.lastIndexOf("/"));
        }
    };
    const setProblems = (list) => {
        draft.problems = list;
        problems.replaceChildren(problemsPanel(list, goTo) ?? "");
        if (form) {
            form.redraw();
        }
    };

    const drawView = () => {
        formButton.setAttribute("aria-pressed", String(draft.view === "form"));
        textButton.setAttribute("aria-pressed", String(draft.view === "text"));
        if (draft.view === "form") {
            text = null;
            form = sheetForm(draft, () => problems.replaceChildren());
            view.replaceChildren(form);
            return;
        }
        form = null;
        text = el("textarea", { id: "rules-source", class: "source", rows: 24, spellcheck: "false",
                                autocomplete: "off", wrap: "off", "aria-describedby": "rules-source-hint" });
        text.value = draft.source;
        text.addEventListener("input", () => {
            draft.source = text.value;
        });
        const language = el("select", { id: "rules-language" },
                            LANGUAGES.map((l) => el("option", { value: l, lang: l, text: languageName(l),
                                                                selected: l === draft.language })));
        language.addEventListener("change", () => busy(async () => {
            const answer = await api("POST", "rules/fmt", { source: text.value, language: language.value });
            if (answer.ok) {
                draft.language = language.value;
                draft.source = answer.source;
                text.value = answer.source;
                setProblems([]);
            } else {
                language.value = draft.language;
                setProblems(problemsOf(answer.diagnostics, true));
            }
        }));
        view.replaceChildren(
            el("div", { class: "field wide" }, el("label", { for: "rules-source", text: t("rules.source") }),
               text, el("span", { id: "rules-source-hint", class: "hint", text: t("rules.source_hint") })),
            el("div", { class: "field" }, el("label", { for: "rules-language", text: t("rules.write_in") }),
               language));
    };

    let working = false;
    async function busy(work) {
        if (working) {
            return;
        }
        working = true;
        buttons.forEach((b) => { b.disabled = true; });
        status(t("status.working"));
        try {
            await work();
        } catch (error) {
            results.replaceChildren(problem(
                error.status === 423 ? t("keys.locked")
                    : error.status === 501 ? t("rules.no_compiler")
                    : t("error.server", { message: error.message })));
        } finally {
            working = false;
            buttons.forEach((b) => { b.disabled = false; });
            status("");
        }
    }

    /// The source the form writes, checked, with each problem on its field;
    /// null if it does not check.
    const fromForm = async () => {
        const missing = missingPieces(draft.sheet);
        if (missing.length > 0) {
            setProblems(missing);
            return null;
        }
        const answer = await api("POST", "rules/form", { sheet: sheetToSend(draft.sheet),
                                                        language: state.language });
        if (answer.source === undefined) {
            setProblems([{ path: answer.path, message: answer.error }]);
            return null;
        }
        draft.language = state.language;
        setProblems(problemsOf(answer.diagnostics, false));
        return answer;
    };
    /// The source in either view, checked; null if it does not check.
    const checkedSource = async () => {
        if (draft.view === "form") {
            const answer = await fromForm();
            return answer?.ok ? answer.source : null;
        }
        draft.source = text.value;
        const answer = await api("POST", "rules/check", { source: draft.source, language: state.language });
        setProblems(problemsOf(answer.diagnostics, true));
        return answer.ok ? draft.source : null;
    };

    formButton.addEventListener("click", () => busy(async () => {
        if (draft.view === "form") {
            return;
        }
        draft.source = text.value;
        const answer = await api("POST", "rules/from", { source: draft.source });
        if (!answer.fits) {
            setProblems([{ severity: "warning", line: answer.line ?? null,
                           message: t("rules.unfit", { reason: answer.reason }) },
                         ...problemsOf(answer.diagnostics, true)]);
            return;
        }
        draft.sheet = openedSheet(answer.sheet);
        draft.view = "form";
        setProblems([]);
        drawView();
    }));
    textButton.addEventListener("click", () => busy(async () => {
        if (draft.view === "text") {
            return;
        }
        const answer = await fromForm();
        if (answer === null) {
            return;
        }
        draft.source = answer.source;
        draft.view = "text";
        // The lines' problems, now that the lines show.
        setProblems(problemsOf(answer.diagnostics, true));
        drawView();
    }));
    check.addEventListener("click", () => busy(async () => {
        results.replaceChildren();
        if (await checkedSource() !== null && draft.problems.length === 0) {
            results.replaceChildren(el("p", { class: "notice", role: "status", text: t("rules.no_problems") }));
        }
    }));
    explain.addEventListener("click", () => busy(async () => {
        results.replaceChildren();
        const source = await checkedSource();
        if (source === null) {
            return;
        }
        // One at a time: the console runs one compiler per session.
        const columns = [];
        for (const language of LANGUAGES) {
            const answer = await api("POST", "rules/explain", { source, language });
            columns.push(el("article", { class: "explained", lang: language },
                            el("h3", { text: languageName(language) }),
                            el("pre", { text: answer.text ?? "" })));
        }
        results.replaceChildren(el("h2", { text: t("rules.explain_title") }),
                                el("p", { class: "hint", text: t("rules.explain_hint") }),
                                el("div", { class: "explained-all" }, columns));
    }));
    test.addEventListener("click", () => busy(async () => {
        results.replaceChildren();
        const source = await checkedSource();
        if (source === null) {
            return;
        }
        const answer = await api("POST", "rules/test", { source, language: state.language });
        if (!answer.built) {
            setProblems(problemsOf(answer.diagnostics, draft.view === "text"));
            return;
        }
        const tests = answer.tests ?? [];
        results.replaceChildren(
            el("h2", { text: t("rules.tests_title") }),
            el("p", { role: "status", class: answer.failed > 0 ? "error" : "notice",
                      text: tests.length === 0 ? t("rules.no_tests")
                                               : t("rules.tests_summary", { passed: answer.passed,
                                                                            total: answer.total }) }),
            tests.length === 0 ? null : el("ul", {}, tests.map((x, i) => el("li", {
                class: x.passed ? null : "bad",
                text: t(x.passed ? "rules.test_passed" : "rules.test_failed",
                        { name: x.name ?? t("rules.test_unnamed", { n: i + 1 }) }),
            }))),
            tests.length === 0 ? null : el("details", {}, el("summary", { text: t("rules.test_steps") }),
                                           el("pre", { text: answer.text ?? "" })));
    }));
    deploy.addEventListener("click", () => busy(async () => {
        results.replaceChildren();
        const source = await checkedSource();
        if (source === null) {
            return;
        }
        await approveScreen(await api("POST", "prepare", { action: "contract.deploy", source }));
    }));
    download.addEventListener("click", () => {
        const name = slug(draft.sheet.contract || draft.name || "");
        if (draft.view === "form") {
            saveText(`${JSON.stringify(sheetToSend(draft.sheet), null, 2)}\n`, `${name}.json`,
                     "application/json");
        } else {
            saveText(text.value, `${name}.bo`, "text/plain");
        }
    });
    opener.addEventListener("change", () => busy(async () => {
        const file = opener.files[0];
        opener.value = "";
        if (!file) {
            return;
        }
        if (file.size > RULES_INPUT) {
            throw new ApiError(413, t("rules.too_large", { name: file.name }));
        }
        const content = await file.text();
        draft.name = file.name.replace(/\.[^.]*$/, "");
        results.replaceChildren();
        if (file.name.endsWith(".json")) {
            let parsed = null;
            try {
                parsed = JSON.parse(content);
            } catch {
                // Not JSON: said below.
            }
            if (parsed?.kind !== "rules") {
                throw new ApiError(400, t("rules.not_a_sheet", { name: file.name }));
            }
            draft.sheet = openedSheet(parsed);
            draft.view = "form";
            setProblems([]);
            drawView();
            return;
        }
        // A source opens in the form if it fits, and as text if not.
        draft.source = content;
        const answer = await api("POST", "rules/from", { source: content });
        if (answer.fits) {
            draft.sheet = openedSheet(answer.sheet);
            draft.view = "form";
            setProblems([]);
        } else {
            draft.view = "text";
            draft.sheet = newSheet();
            setProblems([{ severity: "warning", line: answer.line ?? null,
                           message: t("rules.unfit", { reason: answer.reason }) },
                         ...problemsOf(answer.diagnostics, true)]);
        }
        drawView();
    }));

    drawView();
    problems.replaceChildren(problemsPanel(draft.problems, goTo) ?? "");
    show(keysNotice(), el("h1", { text: t("rules.editor_title") }),
         el("p", { class: "hint", text: t("rules.editor_intro") }),
         el("div", { class: "toolbar", role: "group", "aria-label": t("rules.view") },
            formButton, textButton),
         el("div", { class: "field" },
            el("label", { for: "rules-open", text: t("rules.open") }), opener,
            el("span", { id: "rules-open-hint", class: "hint", text: t("rules.open_hint") })),
         view, problems,
         el("div", { class: "toolbar" }, ...actions, download),
         results);
}

// --- The checks in this browser --------------------------------------------------

/// The core, compiled to WebAssembly and served by the console, decodes what a
/// passkey is about to approve and computes its challenge here; without it
/// (a console built without Emscripten), the page says so.
let checker;

async function loadChecker() {
    if (checker !== undefined) {
        return checker;
    }
    try {
        const { default: create } = await import("./wasm/cexchain-console.mjs");
        const module = await create();
        const call = (name, bytes, ...rest) => {
            const pointer = module._malloc(Math.max(bytes.length, 1));
            module.HEAPU8.set(bytes, pointer);
            const pointers = [pointer];
            const args = rest.map((r) => {
                if (r instanceof Uint8Array) {
                    const p = module._malloc(Math.max(r.length, 1));
                    module.HEAPU8.set(r, p);
                    pointers.push(p);
                    return [p, r.length];
                }
                return [r];
            }).flat();
            const out = module[name](pointer, bytes.length, ...args);
            const text = module.UTF8ToString(out);
            module._cexchain_free(out);
            pointers.forEach((p) => module._free(p));
            return JSON.parse(text);
        };
        checker = {
            describe: (payload) => call("_cexchain_describe_payload", payload),
            challenge: (payload, kid, hash) =>
                call("_cexchain_presence_challenge", payload, kid, hash),
            verify: (proof, files, ledger) => {
                module._cexchain_proof_reset();
                for (const [name, content] of files) {
                    const label = new TextEncoder().encode(name);
                    const n = module._malloc(Math.max(label.length, 1));
                    const d = module._malloc(Math.max(content.length, 1));
                    module.HEAPU8.set(label, n);
                    module.HEAPU8.set(content, d);
                    module._cexchain_proof_attachment(n, label.length, d, content.length);
                    module._free(n);
                    module._free(d);
                }
                return call("_cexchain_proof_verify", proof, new TextEncoder().encode(ledger));
            },
            fieldRoot: (request) => call("_cexchain_field_root",
                                         new TextEncoder().encode(JSON.stringify(request))),
            commitment: (content, salt, hash) =>
                call("_cexchain_attachment_commitment", content, salt, hash),
        };
    } catch {
        checker = null;
    }
    return checker;
}

/// What the page decoded itself agrees with what the console described.
function agrees(decoded, summary) {
    return decoded.ok && decoded.type === summary.type && decoded.record === summary.record &&
           (decoded.contract ?? null) === (summary.contract ?? null) &&
           (decoded.role ?? null) === (summary.role ?? null) &&
           (decoded.reason ?? null) === (summary.reason ?? null);
}

/// A deploy's bytes carry the code the console built: its size and digest
/// computed here from the bytes, its name, its language, and its functions.
function deployAgrees(decoded, summary) {
    return decoded.ok && decoded.type === "contract-deploy" &&
           (decoded.name ?? null) === (summary.name ?? null) &&
           decoded.language === summary.language && decoded.code_size === summary.code_size &&
           decoded.code_sha256 === summary.code_sha256 &&
           JSON.stringify(decoded.functions) === JSON.stringify(summary.functions);
}

/// A registration's bytes commit to what the page shows: the fields' root
/// from the values and salts shown, the public metadata, and each file's
/// commitment from the file this page uploaded.
function registrationAgrees(check, decoded, prepared, files) {
    const summary = prepared.summary;
    if (!decoded.ok || decoded.type !== "record-register" ||
        decoded.record_type !== summary.record_type ||
        decoded.field_count !== summary.fields.length ||
        JSON.stringify(decoded.metadata ?? {}) !==
            JSON.stringify(Object.fromEntries(Object.entries(summary.metadata).sort()))) {
        return false;
    }
    const root = check.fieldRoot({ hash: prepared.hash, fields: summary.fields });
    if (!root.ok || root.root !== decoded.field_root) {
        return false;
    }
    if (decoded.attachments.length !== summary.files.length) {
        return false;
    }
    return summary.files.every((f, i) => {
        const a = decoded.attachments[i];
        const content = files.get(f.upload);
        if (!content || a.name !== f.name || a.size !== f.size || a.media_type !== f.media_type) {
            return false;
        }
        const own = check.commitment(content, new Uint8Array(fromBase64url(f.salt)), prepared.hash);
        return own.ok && own.commitment === a.commitment;
    });
}

// --- Acting, approved with a passkey ---------------------------------------------

/// Back to the list (the address is still #/things, so a link would not move).
function backButton(text) {
    const button = el("button", { type: "button", text });
    button.addEventListener("click", () => route());
    return button;
}

/// To a screen, even the one the address already names.
function goButton(text, hash) {
    const button = el("button", { type: "button", text });
    button.addEventListener("click", () => {
        if (location.hash === hash) {
            route();
        } else {
            location.hash = hash;
        }
    });
    return button;
}

/// What to do with a record: the person chooses, the console prepares it.
function actScreen(record) {
    const endorse = el("input", { type: "radio", name: "act", id: "act-endorse", value: "endorse",
                                  checked: true });
    const revoke = el("input", { type: "radio", name: "act", id: "act-revoke", value: "revoke" });
    const [roleField, role] = field("act-role", t("act.role"), t("act.role_hint"),
                                    { maxlength: 64 });
    const [reasonField, reason] = field("act-reason", t("act.reason"), t("act.reason_hint"),
                                        { maxlength: 200 });
    const notice = el("div");
    const form = el("form", { novalidate: true },
                    el("fieldset", {}, el("legend", { text: t("act.what") }),
                       el("label", {}, endorse, " ", t("act.endorse")),
                       el("label", {}, revoke, " ", t("act.revoke"))),
                    roleField, reasonField, notice,
                    el("button", { type: "submit", class: "primary", text: t("act.prepare") }),
                    " ", backButton(t("approve.cancel")));
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const intent = endorse.checked
            ? { action: "record.endorse", record: record.id, role: role.value.trim() }
            : { action: "record.revoke", record: record.id, reason: reason.value.trim() };
        try {
            await approveScreen(await api("POST", "prepare", intent));
        } catch (error) {
            notice.replaceChildren(problem(error.status === 423 ? t("keys.locked")
                                                                : passkeyProblem(error)));
        }
    });
    show(el("h1", { text: t("act.title") }),
         el("p", { class: "id", text: `${record.type} ${record.id}` }), form);
}

/// What the person approves, as the console prepared it and this page
/// decoded it, then the tap.
async function approveScreen(prepared, files = new Map()) {
    const summary = prepared.summary;
    const registering = summary.type === "record-register";
    const deploying = summary.type === "contract-deploy";
    const rules = deploying || summary.type === "contract-retire";
    const check = await loadChecker();
    let challenge = prepared.public_key.challenge;
    let checkedHere = false;
    if (check) {
        const payload = new Uint8Array(fromBase64url(prepared.payload));
        const decoded = check.describe(payload);
        const own = check.challenge(payload, new Uint8Array(fromBase64url(prepared.kid)),
                                    prepared.hash);
        const matches = registering ? registrationAgrees(check, decoded, prepared, files)
            : deploying ? deployAgrees(decoded, summary) : agrees(decoded, summary);
        if (!matches || !own.ok || own.challenge !== challenge) {
            show(el("h1", { text: t("approve.title") }), problem(t("approve.mismatch")),
                 backButton(t("nav.things")));
            return;
        }
        challenge = own.challenge;
        checkedHere = true;
    }
    const facts = el("dl", { class: "facts" });
    const fact = (key, value) => {
        if (value !== undefined && value !== null) {
            facts.append(el("dt", { text: t(key) }), el("dd", { text: String(value) }));
        }
    };
    fact("approve.action", t(`approve.type.${summary.type}`));
    fact("column.type", summary.record_type);
    fact("approve.name", summary.name);
    fact("column.id", summary.record ?? summary.contract);
    if (deploying) {
        fact("approve.language", summary.language);
        fact("approve.code_size", sizeText(summary.code_size));
        fact("approve.functions", summary.functions.join(", "));
        fact("approve.code_sha256", summary.code_sha256);
    }
    fact("act.role", summary.role);
    fact("act.reason", summary.reason);
    if (registering) {
        for (const f of summary.fields) {
            facts.append(el("dt", { text: t("register.private_field", { name: f.name }) }),
                         el("dd", { text: f.value }));
        }
        for (const [name, value] of Object.entries(summary.metadata)) {
            facts.append(el("dt", { text: t("register.public_field", { name }) }),
                         el("dd", { text: value }));
        }
        for (const f of summary.files) {
            facts.append(el("dt", { text: t("register.file") }),
                         el("dd", { text: t(summary.keep_files ? "register.file_kept"
                                                               : "register.file_not_kept",
                                            { name: f.name, size: sizeText(f.size) }) }));
        }
    }
    const button = el("button", { type: "button", class: "primary", text: t("approve.button") });
    const notice = el("div");
    button.addEventListener("click", async () => {
        button.disabled = true;
        status(t("status.working"));
        try {
            const options = prepared.public_key;
            const credential = await navigator.credentials.get({
                publicKey: {
                    challenge: fromBase64url(challenge),
                    rpId: options.rpId,
                    allowCredentials: options.allowCredentials.map((c) => ({
                        type: c.type, id: fromBase64url(c.id),
                    })),
                    userVerification: options.userVerification,
                    timeout: options.timeout,
                },
            });
            const done = await api("POST", "approve", {
                prepared: prepared.prepared,
                credential_id: toBase64url(credential.rawId),
                authenticator_data: toBase64url(credential.response.authenticatorData),
                client_data_json: toBase64url(credential.response.clientDataJSON),
                signature: toBase64url(credential.response.signature),
            });
            show(el("h1", { text: t("approve.done_title") }),
                 el("p", { role: "status", text: t("approve.done", { index: done.index }) }),
                 el("p", { class: "id", text: done.statement_id }),
                 registering ? el("p", {}, el("a", { href: `#/thing/${done.statement_id}`,
                                                     text: t("register.open") }))
                             : null,
                 rules ? goButton(t("rules.done"), "#/rules") : backButton(t("nav.things")));
        } catch (error) {
            notice.replaceChildren(problem(passkeyProblem(error)));
            button.disabled = false;
        } finally {
            status("");
        }
    });
    show(el("h1", { text: t("approve.title") }), el("p", { text: t("approve.intro") }), facts,
         el("p", { class: "hint", text: t(checkedHere ? "approve.checked_here"
                                                      : "approve.checked_by_console") }),
         notice, button, " ", backButton(t("approve.cancel")));
}

// --- Navigation ------------------------------------------------------------------

function chrome() {
    const signedIn = state.who !== null;
    document.getElementById("nav").hidden = !signedIn;
    document.getElementById("sign-out").hidden = !signedIn;
    const who = document.getElementById("who");
    who.hidden = !signedIn;
    who.textContent = signedIn
        ? t("session.signed_in_as", { user: state.who.user, role: t(`role.${state.who.role}`) })
        : "";
    const hash = location.hash;
    const current = hash.startsWith("#/things") || hash.startsWith("#/new") ||
                    hash.startsWith("#/thing/") ? "things"
        : hash.startsWith("#/kinds") ? "kinds"
        : hash.startsWith("#/rules") ? "rules"
        : hash.startsWith("#/verify") ? "verify"
        : hash.startsWith("#/settings") ? "settings" : "home";
    for (const link of document.querySelectorAll("nav a")) {
        if (link.dataset.route === current) {
            link.setAttribute("aria-current", "page");
        } else {
            link.removeAttribute("aria-current");
        }
    }
}

async function route() {
    const hash = location.hash;
    // An invitation's code is read once and taken out of the address bar and
    // the history at once.
    const enroll = hash.match(/^#\/enroll\/(cxi_[A-Za-z0-9_-]{43})$/);
    if (enroll) {
        history.replaceState(null, "", `${location.pathname}#/enroll`);
        state.pendingCode = enroll[1];
    }
    if (hash.startsWith("#/enroll") && state.pendingCode) {
        state.who = null;
        chrome();
        enrollScreen(state.pendingCode);
        return;
    }
    if (state.who === null && stored(sessionStorage, SESSION)) {
        try {
            const me = await api("GET", "session");
            state.who = { user: me.user, role: me.role, keys: me.keys ?? "none" };
        } catch {
            store(sessionStorage, SESSION, null);
        }
    }
    chrome();
    if (hash.startsWith("#/verify")) {
        verifyScreen();
        return;
    }
    if (state.who === null) {
        if (hash.startsWith("#/recover")) {
            recoverScreen();
        } else {
            signInScreen();
        }
        return;
    }
    try {
        const thing = hash.match(/^#\/thing\/([0-9a-f]{64})$/);
        await (thing ? thingScreen(thing[1])
            : hash.startsWith("#/things") ? thingsScreen()
            : hash.startsWith("#/new") ? newDocumentScreen()
            : hash.startsWith("#/kinds") ? kindsScreen()
            : hash.startsWith("#/rules/new") ? rulesEditor()
            : hash.startsWith("#/rules") ? rulesScreen()
            : hash.startsWith("#/settings") ? settingsScreen() : homeScreen());
    } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
            state.who = null;
            store(sessionStorage, SESSION, null);
            chrome();
            signInScreen();
            return;
        }
        show(problem(t("error.server", { message: error.message })));
    }
}

async function signOut() {
    try {
        await api("DELETE", "session");
    } catch {
        // Signed out anyway: the token is forgotten here.
    }
    store(sessionStorage, SESSION, null);
    state.who = null;
    state.rules = undefined;
    home();
}

async function start() {
    state.english = await catalog("en");
    try {
        const begun = await api("GET", "start");
        state.firstRun = begun.first_run;
        state.defaultLanguage = begun.language;
    } catch {
        // An older console, or one starting: the defaults do.
    }
    const saved = LANGUAGES.includes(stored(localStorage, LANGUAGE));
    await setLanguage(preferredLanguage(), saved);
    document.getElementById("language").addEventListener("change", async (event) => {
        await setLanguage(event.target.value);
        route();
    });
    document.getElementById("sign-out").addEventListener("click", signOut);
    window.addEventListener("hashchange", route);
    route();
}

start();
