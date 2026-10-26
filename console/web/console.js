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
         button, el("p", {}, el("a", { href: "#/recover", text: t("recover.link") })));
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
const yesNo = (value) => t(value ? "value.yes" : "value.no");

async function thingsScreen() {
    const things = await api("GET", "things");
    const records = table(t("things.records"), [
        ["column.type", (r) => r.type],
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
    show(el("h1", { text: t("things.title") }), el("p", { class: "hint", text: t("things.hint") }),
         ...records, ...instances,
         things.more ? el("p", { class: "hint", text: t("things.more") }) : null);
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
        };
    } catch {
        checker = null;
    }
    return checker;
}

/// What the page decoded itself agrees with what the console described.
function agrees(decoded, summary) {
    return decoded.ok && decoded.type === summary.type && decoded.record === summary.record &&
           (decoded.role ?? null) === (summary.role ?? null) &&
           (decoded.reason ?? null) === (summary.reason ?? null);
}

// --- Acting, approved with a passkey ---------------------------------------------

/// Back to the list (the address is still #/things, so a link would not move).
function backButton(text) {
    const button = el("button", { type: "button", text });
    button.addEventListener("click", () => route());
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
async function approveScreen(prepared) {
    const summary = prepared.summary;
    const check = await loadChecker();
    let challenge = prepared.public_key.challenge;
    let checkedHere = false;
    if (check) {
        const payload = new Uint8Array(fromBase64url(prepared.payload));
        const decoded = check.describe(payload);
        const own = check.challenge(payload, new Uint8Array(fromBase64url(prepared.kid)),
                                    prepared.hash);
        if (!agrees(decoded, summary) || !own.ok || own.challenge !== challenge) {
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
    fact("column.id", summary.record);
    fact("act.role", summary.role);
    fact("act.reason", summary.reason);
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
                 el("p", { class: "id", text: done.statement_id }), backButton(t("nav.things")));
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
    const current = location.hash.startsWith("#/things") ? "things"
        : location.hash.startsWith("#/settings") ? "settings" : "home";
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
    if (state.who === null) {
        if (hash.startsWith("#/recover")) {
            recoverScreen();
        } else {
            signInScreen();
        }
        return;
    }
    try {
        await (hash.startsWith("#/things") ? thingsScreen()
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
