// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The web console's server side: its page, its headers, and the Host and
// Origin checks every request passes first.

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/app/support.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/console/keystore.hpp>
#include <cexchain/console/sessions.hpp>
#include <cexchain/console/users.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/environment.hpp>

#include "support/authenticator.hpp"
#include "support/ledger_world.hpp"

namespace console = cexchain::console;
namespace http = cexchain::node::http;

namespace {

http::Request request(std::string method, std::string path, std::string host,
                      std::string origin = {}) {
    http::Request r;
    r.method = std::move(method);
    r.target = path;
    r.path = std::move(path);
    r.headers.emplace_back("host", std::move(host));
    if (!origin.empty()) {
        r.headers.emplace_back("origin", std::move(origin));
    }
    return r;
}

std::string header(const http::Response& r, std::string_view name) {
    for (const auto& [key, value] : r.headers) {
        if (key == name) {
            return value;
        }
    }
    return {};
}

std::string body(const http::Response& r) {
    return {r.body.begin(), r.body.end()};
}

const cexchain::crypto::Provider& provider() {
    static const cexchain::crypto::openssl::Provider instance;
    return instance;
}

/// A fresh directory, removed at the end of the test.
struct TempDirectory {
    std::filesystem::path path;
    TempDirectory() {
        static int counter = 0;
        path = std::filesystem::temp_directory_path() /
               ("cexchain-console-test-" + std::to_string(::getpid()) + "-" +
                std::to_string(++counter));
        std::filesystem::remove_all(path);
    }
    ~TempDirectory() { std::filesystem::remove_all(path); }
    TempDirectory(const TempDirectory&) = delete;
    TempDirectory& operator=(const TempDirectory&) = delete;
};

constexpr cexchain::protocol::Timestamp minute = 60'000;

} // namespace

TEST_CASE("the console serves its page with its security headers", "[console]") {
    console::Console c;
    c.set_origins(console::loopback_origins(7470));
    const auto page = c.handle(request("GET", "/console/", "localhost:7470"));
    CHECK(page.status == 200);
    CHECK(page.content_type == "text/html; charset=utf-8");
    CHECK(body(page).starts_with("<!doctype html>"));
    CHECK(header(page, "Content-Security-Policy") == console::content_security_policy);
    CHECK(header(page, "X-Content-Type-Options") == "nosniff");
    CHECK(header(page, "X-Frame-Options") == "DENY");
    CHECK(header(page, "Cache-Control") == "no-store");
    for (const std::string host : {"127.0.0.1:7470", "[::1]:7470", "LOCALHOST:7470"}) {
        INFO(host);
        CHECK(c.handle(request("GET", "/console/console.js", host)).status == 200);
    }
    const auto script = c.handle(request("GET", "/console/console.js", "localhost:7470"));
    CHECK(script.content_type == "text/javascript; charset=utf-8");
    const auto moved = c.handle(request("GET", "/console", "localhost:7470"));
    CHECK(moved.status == 308);
    CHECK(header(moved, "Location") == "/console/");
    const auto missing = c.handle(request("GET", "/console/nothing", "localhost:7470"));
    CHECK(missing.status == 404);
    CHECK(header(missing, "Content-Security-Policy") == console::content_security_policy);
    const auto api = c.handle(request("GET", "/console/api/nothing", "localhost:7470"));
    CHECK(api.status == 404);
    CHECK(api.content_type == "application/json");
}

TEST_CASE("the console answers only for its own names (DNS rebinding)", "[console]") {
    console::Console c;
    CHECK(c.handle(request("GET", "/console/", "localhost:7470")).status == 503);
    c.set_origins(console::loopback_origins(7470));
    for (const std::string host : {"attacker.example:7470", "localhost:7471", "localhost",
                                   "localhost:0", "localhost:x", "local host:7470", ""}) {
        INFO(host);
        CHECK(c.handle(request("GET", "/console/", host)).status != 200);
    }
    http::Request no_host;
    no_host.method = "GET";
    no_host.path = "/console/";
    CHECK(c.handle(no_host).status == 400);
}

TEST_CASE("the console refuses other sites' pages", "[console]") {
    console::Console c;
    c.set_origins(console::loopback_origins(7470));
    const std::string host = "localhost:7470";
    CHECK(c.handle(request("GET", "/console/", host, "http://localhost:7470")).status == 200);
    CHECK(c.handle(request("GET", "/console/", host, "https://attacker.example")).status == 403);
    CHECK(c.handle(request("GET", "/console/", host, "http://localhost:7471")).status == 403);
    CHECK(c.handle(request("GET", "/console/", host, "null")).status == 403);
    // A request that changes something must say it comes from the console.
    CHECK(c.handle(request("POST", "/console/api/session", host)).status == 403);
    CHECK(c.handle(request("POST", "/console/api/nothing", host, "http://localhost:7470")).status ==
          404);
    CHECK(c.handle(request("POST", "/console/", host, "http://localhost:7470")).status == 405);
}

TEST_CASE("a public URL is the console's only name", "[console]") {
    const auto origin = console::parse_origin("https://Ledger.Example.com/");
    REQUIRE(origin);
    CHECK(origin->text() == "https://ledger.example.com");
    CHECK(origin->authority() == "ledger.example.com");
    CHECK(console::parse_origin("https://ledger.example.com:8443")->text() ==
          "https://ledger.example.com:8443");
    CHECK(console::parse_origin("http://ledger.example.com:80")->port == 0);
    for (const std::string_view bad :
         {"ftp://ledger.example.com", "https://", "https://ledger.example.com/path",
          "https://user@ledger.example.com", "https://ledger.example.com:99999",
          "https://ledger.example.com?x", "ledger.example.com"}) {
        INFO(bad);
        CHECK_FALSE(console::parse_origin(bad));
    }
    console::Console c;
    c.set_origins({*origin});
    CHECK(c.handle(request("GET", "/console/", "ledger.example.com")).status == 200);
    CHECK(c.handle(request("GET", "/console/", "ledger.example.com:443")).status == 200);
    CHECK(c.handle(request("GET", "/console/", "localhost:7470")).status == 421);
}

TEST_CASE("a session's bearer token", "[console][sessions]") {
    const std::string token = "cxs_" + std::string(43, 'A');
    CHECK(console::bearer_token("Bearer " + token) == token);
    CHECK(console::bearer_token("bearer " + token) == token);
    for (const std::string& bad :
         {"Bearer " + token + "A", "Bearer " + token.substr(0, 46), "Basic " + token,
          "Bearer  " + token.substr(1), "Bearer cxt_" + std::string(43, 'A'),
          "Bearer cxs_" + std::string(42, 'A') + "=", "Bearer cxs_" + std::string(42, 'A') + " ",
          std::string("Bearer"), std::string()}) {
        INFO(bad);
        CHECK_FALSE(console::bearer_token(bad));
    }
}

TEST_CASE("sessions end when idle, at their lifetime, on sign-out, and when revoked",
          "[console][sessions]") {
    const TempDirectory dir;
    cexchain::ledger::ManualClock clock(1'800'000'000'000);
    cexchain::ledger::SeededEntropy entropy(7);
    console::Sessions sessions(dir.path, provider(), clock, entropy);

    const std::string token = sessions.create("alice");
    CHECK(console::bearer_token("Bearer " + token) == token);
    const auto session = sessions.use(token);
    REQUIRE(session);
    CHECK(session->user == "alice");
    CHECK(session->id.size() == 16);
    CHECK_FALSE(sessions.use("cxs_" + std::string(43, 'A')));

    // Idle: 30 minutes without a request.
    clock.advance(29 * minute);
    REQUIRE(sessions.use(token));
    clock.advance(30 * minute);
    CHECK_FALSE(sessions.use(token));

    // Used every 20 minutes, it still ends 12 hours after it began.
    const std::string busy = sessions.create("bob");
    for (int i = 0; i < 35; ++i) {
        clock.advance(20 * minute);
        REQUIRE(sessions.use(busy));
    }
    clock.advance(20 * minute);
    CHECK_FALSE(sessions.use(busy));

    // Signing out.
    const std::string out = sessions.create("carol");
    CHECK(sessions.end(out));
    CHECK_FALSE(sessions.end(out));
    CHECK_FALSE(sessions.use(out));

    // Revoked from the command line, by the id it lists.
    const std::string revoked = sessions.create("dave");
    const std::string kept = sessions.create("erin");
    const auto listed = console::published_sessions(dir.path);
    REQUIRE(listed.size() == 2);
    const std::string dave_id = sessions.use(revoked)->id;
    console::request_revocation(dir.path, dave_id);
    CHECK_FALSE(sessions.use(revoked));
    CHECK(sessions.use(kept));
    REQUIRE(sessions.list().size() == 1);
    CHECK(console::published_sessions(dir.path).size() == 1);
    CHECK_THROWS(console::request_revocation(dir.path, "not-an-id"));

    // What is published names sessions, never their tokens or hashes.
    const auto text = cexchain::app::read_file(dir.path / "sessions.json");
    const std::string published(text.begin(), text.end());
    CHECK(published.find(kept) == std::string::npos);
    CHECK(published.find("erin") != std::string::npos);
    CHECK(published.find("cxs_") == std::string::npos);
}

TEST_CASE("the console's session route", "[console][sessions]") {
    const TempDirectory dir;
    cexchain::ledger::ManualClock clock(1'800'000'000'000);
    cexchain::ledger::SeededEntropy entropy(8);
    console::Sessions sessions(dir.path, provider(), clock, entropy);
    console::Console c(console::Services{dir.path, &provider(), &clock, &entropy, &sessions});
    c.set_origins(console::loopback_origins(7470));
    const std::string host = "localhost:7470";
    const std::string origin = "http://localhost:7470";

    auto none = c.handle(request("GET", "/console/api/session", host));
    CHECK(none.status == 401);
    CHECK(header(none, "WWW-Authenticate") == "Bearer");
    CHECK(header(none, "Cache-Control") == "no-store");

    // Sessions belong to the console's users.
    console::People people;
    people.users.push_back({"alice", console::Role::viewer, clock.now(), {}});
    console::save_people(dir.path, people);
    const std::string token = sessions.create("alice");
    auto mine = request("GET", "/console/api/session", host);
    mine.headers.emplace_back("authorization", "Bearer " + token);
    const auto who = c.handle(mine);
    CHECK(who.status == 200);
    CHECK(body(who).find("\"user\":\"alice\"") != std::string::npos);
    CHECK(body(who).find(token) == std::string::npos);

    auto forged = request("GET", "/console/api/session", host);
    forged.headers.emplace_back("authorization", "Bearer cxs_" + std::string(43, 'B'));
    CHECK(c.handle(forged).status == 401);

    // Signing out is a change: from the console's page only.
    auto sign_out = request("DELETE", "/console/api/session", host);
    sign_out.headers.emplace_back("authorization", "Bearer " + token);
    CHECK(c.handle(sign_out).status == 403);
    sign_out.headers.emplace_back("origin", origin);
    CHECK(c.handle(sign_out).status == 200);
    CHECK(c.handle(mine).status == 401);

    console::Console without;
    without.set_origins(console::loopback_origins(7470));
    CHECK(without.handle(mine).status == 503);
}

namespace {

/// A console with its services, on localhost:7470.
struct ConsoleWorld {
    TempDirectory dir;
    cexchain::ledger::ManualClock clock{1'800'000'000'000};
    cexchain::ledger::SeededEntropy entropy{11};
    console::Sessions sessions{dir.path, provider(), clock, entropy};
    console::Console web{console::Services{dir.path, &provider(), &clock, &entropy, &sessions}};
    std::string origin = "http://localhost:7470";

    ConsoleWorld() { web.set_origins(console::loopback_origins(7470)); }

    http::Response post(const std::string& path, const nlohmann::json& body) {
        auto r = request("POST", path, "localhost:7470", origin);
        const std::string text = body.dump();
        r.body.assign(text.begin(), text.end());
        return web.handle(r);
    }

    std::string invite(std::string user, console::Role role) {
        auto people = console::load_people(dir.path);
        auto [code, invitation] =
            console::make_invitation(provider(), entropy, std::move(user), role, clock.now());
        people.invitations.push_back(invitation);
        console::save_people(dir.path, people);
        return code;
    }

    /// A session for a user of the console, made without a passkey.
    std::string session_for(const std::string& name, console::Role role) {
        auto people = console::load_people(dir.path);
        people.users.push_back({name, role, clock.now(), {}});
        console::save_people(dir.path, people);
        return sessions.create(name);
    }

    http::Response get(const std::string& path, const std::string& token) {
        auto r = request("GET", path, "localhost:7470");
        r.headers.emplace_back("authorization", "Bearer " + token);
        return web.handle(r);
    }

    /// Registers `passkey` with an invitation code; returns the answer.
    http::Response enroll(const cexchain::test::SoftPasskey& passkey, const std::string& code,
                          const std::string& name = {}) {
        const auto begun = post("/console/api/enroll/begin", {{"code", code}, {"name", name}});
        if (begun.status != 200) {
            return begun;
        }
        const auto options = nlohmann::json::parse(body(begun));
        const auto challenge =
            *cexchain::from_base64url(options["public_key"]["challenge"].get<std::string>());
        return post(
            "/console/api/enroll/finish",
            {{"ceremony", options["ceremony"]},
             {"attestation_object", cexchain::to_base64url(passkey.attestation(provider()))},
             {"client_data_json",
              cexchain::to_base64url(passkey.client_data("webauthn.create", challenge))},
             {"label", "laptop"}});
    }

    /// Signs in with `passkey`; returns the answer.
    http::Response sign_in(const cexchain::test::SoftPasskey& passkey) {
        const auto begun = post("/console/api/sign-in/begin", nlohmann::json::object());
        REQUIRE(begun.status == 200);
        const auto options = nlohmann::json::parse(body(begun));
        const auto challenge =
            *cexchain::from_base64url(options["public_key"]["challenge"].get<std::string>());
        const auto proof = passkey.sign(provider(), challenge);
        return post("/console/api/sign-in/finish",
                    {{"ceremony", options["ceremony"]},
                     {"credential_id", cexchain::to_base64url(proof.credential_id)},
                     {"authenticator_data", cexchain::to_base64url(proof.authenticator_data)},
                     {"client_data_json", cexchain::to_base64url(proof.client_data_json)},
                     {"signature", cexchain::to_base64url(proof.signature)}});
    }
};

cexchain::test::SoftPasskey passkey(std::uint8_t id) {
    auto key = cexchain::crypto::openssl::KeyPair::generate(cexchain::crypto::SigAlg::esp256);
    REQUIRE(key);
    auto shared = std::make_shared<const cexchain::crypto::openssl::KeyPair>(std::move(*key));
    cexchain::test::SoftPasskey p;
    p.public_key = shared->public_key();
    p.key = shared;
    p.credential_id = cexchain::Bytes(16, id);
    return p;
}

std::string session_of(const http::Response& r) {
    return nlohmann::json::parse(body(r))["session"].get<std::string>();
}

} // namespace

TEST_CASE("the first owner sets the console up with a passkey, then signs in",
          "[console][passkeys]") {
    ConsoleWorld w;
    const auto alice = passkey(1);
    const std::string setup = w.invite("", console::Role::owner);

    const auto made = w.enroll(alice, setup, "Alice");
    REQUIRE(made.status == 200);
    auto who = request("GET", "/console/api/session", "localhost:7470");
    who.headers.emplace_back("authorization", "Bearer " + session_of(made));
    const auto me = nlohmann::json::parse(body(w.web.handle(who)));
    CHECK(me["user"] == "Alice");
    CHECK(me["role"] == "owner");
    const auto people = console::load_people(w.dir.path);
    REQUIRE(people.users.size() == 1);
    CHECK(people.users[0].passkeys.size() == 1);
    CHECK(people.users[0].passkeys[0].label == "laptop");
    CHECK(people.invitations.empty());

    // The setup code is used up, and a second setup finds an owner.
    CHECK(w.enroll(passkey(2), setup, "Mallory").status == 404);
    CHECK(w.enroll(passkey(2), w.invite("", console::Role::owner), "Mallory").status == 409);

    const auto signed_in = w.sign_in(alice);
    REQUIRE(signed_in.status == 200);
    CHECK(nlohmann::json::parse(body(signed_in))["user"] == "Alice");
}

TEST_CASE("signing in refuses what a passkey did not sign for this console",
          "[console][passkeys]") {
    ConsoleWorld w;
    auto alice = passkey(1);
    REQUIRE(w.enroll(alice, w.invite("", console::Role::owner), "Alice").status == 200);

    // A passkey not registered here.
    CHECK(w.sign_in(passkey(9)).status == 401);
    // Present but not verified (no PIN or biometric).
    alice.flags = 0x01;
    CHECK(w.sign_in(alice).status == 401);
    alice.flags = 0x05;
    // Signed on another page.
    alice.origin = "http://localhost:7471";
    CHECK(w.sign_in(alice).status == 401);
    alice.origin = "http://localhost:7470";
    CHECK(w.sign_in(alice).status == 200);

    // A challenge is used once, and expires.
    const auto begun = w.post("/console/api/sign-in/begin", nlohmann::json::object());
    const auto options = nlohmann::json::parse(body(begun));
    const auto challenge =
        *cexchain::from_base64url(options["public_key"]["challenge"].get<std::string>());
    const auto proof = alice.sign(provider(), challenge);
    const nlohmann::json finish{
        {"ceremony", options["ceremony"]},
        {"credential_id", cexchain::to_base64url(proof.credential_id)},
        {"authenticator_data", cexchain::to_base64url(proof.authenticator_data)},
        {"client_data_json", cexchain::to_base64url(proof.client_data_json)},
        {"signature", cexchain::to_base64url(proof.signature)}};
    CHECK(w.post("/console/api/sign-in/finish", finish).status == 200);
    CHECK(w.post("/console/api/sign-in/finish", finish).status == 404);
    const auto late = w.post("/console/api/sign-in/begin", nlohmann::json::object());
    w.clock.advance(console::ceremony_lifetime);
    nlohmann::json expired = finish;
    expired["ceremony"] = nlohmann::json::parse(body(late))["ceremony"];
    CHECK(w.post("/console/api/sign-in/finish", expired).status == 404);

    // Passkeys need a name: not an address.
    w.origin = "http://127.0.0.1:7470";
    CHECK(w.post("/console/api/sign-in/begin", nlohmann::json::object()).status == 400);
    // Only POST, and only from the console's page.
    CHECK(w.web.handle(request("GET", "/console/api/sign-in/begin", "localhost:7470")).status ==
          405);
    CHECK(w.web.handle(request("POST", "/console/api/sign-in/begin", "localhost:7470")).status ==
          403);
}

TEST_CASE("invitations name their user and role; a removed user is signed out",
          "[console][passkeys]") {
    ConsoleWorld w;
    REQUIRE(w.enroll(passkey(1), w.invite("", console::Role::owner), "Alice").status == 200);
    const auto bob = passkey(2);
    const auto made = w.enroll(bob, w.invite("Bob", console::Role::member));
    REQUIRE(made.status == 200);
    CHECK(nlohmann::json::parse(body(made))["role"] == "member");
    // The same passkey twice, a bad code, a bad name.
    CHECK(w.enroll(bob, w.invite("Bob", console::Role::member)).status == 409);
    CHECK(w.enroll(passkey(3), "cxi_nothing").status == 400);
    CHECK(w.enroll(passkey(3), w.invite("", console::Role::owner), " ").status == 400);
    // A second passkey for Bob, from his own invitation.
    REQUIRE(w.enroll(passkey(4), w.invite("Bob", console::Role::member)).status == 200);
    CHECK(console::load_people(w.dir.path).find("Bob")->passkeys.size() == 2);

    const std::string token = session_of(w.sign_in(bob));
    auto who = request("GET", "/console/api/session", "localhost:7470");
    who.headers.emplace_back("authorization", "Bearer " + token);
    CHECK(w.web.handle(who).status == 200);
    auto people = console::load_people(w.dir.path);
    std::erase_if(people.users, [](const console::User& u) { return u.name == "Bob"; });
    console::save_people(w.dir.path, people);
    CHECK(w.web.handle(who).status == 401);
    CHECK(w.sign_in(bob).status == 401);
}

TEST_CASE("the console's home and things views read the node's ledger", "[console][views]") {
    cexchain::test::World ledger;
    const cexchain::Bytes root(32, 7);
    for (int i = 0; i < 3; ++i) {
        ledger.ok(ledger.org(),
                  ledger.statement(ledger.org_id(), std::nullopt,
                                   cexchain::protocol::RecordRegisterBody{
                                       "example.thing/1", root, 1, {}, std::nullopt}));
    }
    ConsoleWorld w;
    const std::string token = w.session_for("Vera", console::Role::viewer);
    CHECK(w.get("/console/api/home", token).status == 503);
    w.web.set_ledger(&ledger.ledger());

    const auto home = nlohmann::json::parse(body(w.get("/console/api/home", token)));
    CHECK(home["counts"]["records"] == 3);
    CHECK(home["ledger"]["organization"] == ledger.ledger().state().organization());
    CHECK(home["you"]["role"] == "viewer");

    const auto things = nlohmann::json::parse(body(w.get("/console/api/things", token)));
    REQUIRE(things["records"].size() == 3);
    CHECK(things["records"][0]["type"] == "example.thing/1");
    CHECK(things["records"][0]["index"] > things["records"][1]["index"]);
    CHECK(things["more"] == false);
    CHECK(things["instances"].empty());

    CHECK(w.get("/console/api/things", "cxs_" + std::string(43, 'Z')).status == 401);
    CHECK(w.web.handle(request("GET", "/console/api/home", "localhost:7470")).status == 401);
}

TEST_CASE("recovery codes", "[console][keys]") {
    cexchain::ledger::SeededEntropy entropy(21);
    const std::string code = console::make_recovery_code(entropy);
    CHECK(code.size() == 26 + 6);
    CHECK(code[4] == '-');
    const auto canonical = console::canonical_recovery_code(code);
    REQUIRE(canonical);
    CHECK(canonical->size() == 26);
    std::string typed = code;
    std::ranges::transform(typed, typed.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    CHECK(console::canonical_recovery_code(typed) == canonical);
    CHECK_FALSE(console::canonical_recovery_code(code.substr(1)));
    CHECK_FALSE(console::canonical_recovery_code(code + "A"));
    CHECK_FALSE(console::canonical_recovery_code("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-Y1"));
    CHECK(console::make_recovery_code(entropy) != code);
}

TEST_CASE("the console's keys are sealed to its node key", "[console][keys]") {
    const TempDirectory dir;
    cexchain::ledger::SeededEntropy entropy(22);
    console::KeyStore store(dir.path);
    CHECK_FALSE(store.initialized());
    const std::string code = store.initialize(entropy);
    CHECK(store.initialized());
    CHECK(store.unlocked());
    CHECK_THROWS(store.initialize(entropy));

    auto key = cexchain::crypto::openssl::KeyPair::generate(cexchain::crypto::SigAlg::esp256);
    REQUIRE(key);
    store.seal("alice", *key);
    REQUIRE(store.keys().size() == 1);
    CHECK(store.keys()[0].public_key == key->public_key());
    CHECK(store.open("alice").public_key() == key->public_key());
    CHECK_THROWS(store.seal("Alice", *key));

    // Locked, nothing opens; the recovery code unlocks it, a wrong one does not.
    store.lock();
    CHECK_FALSE(store.unlocked());
    CHECK_THROWS(store.open("alice"));
    const console::Slot recovery{console::SlotKind::recovery, {}};
    CHECK_FALSE(store.unlock(recovery, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA"));
    CHECK_FALSE(store.unlock(recovery, "not a code"));
    REQUIRE(store.unlock(recovery, code));
    CHECK(store.open("alice").public_key() == key->public_key());

    // A passphrase slot and a passkey's slot, added while unlocked.
    const console::Slot passphrase{console::SlotKind::passphrase, {}};
    const console::Slot passkey{console::SlotKind::prf, "AAECAwQFBgcICQoLDA0ODw"};
    CHECK_THROWS(store.add_slot(passphrase, "short"));
    store.add_slot(passphrase, "a long enough passphrase");
    store.add_slot(passkey, "prf output as base64url, 43 characters long");
    CHECK(store.slots().size() == 3);
    store.lock();
    CHECK_THROWS(store.add_slot(passphrase, "while locked, nothing"));
    CHECK_FALSE(store.unlock(passphrase, "the wrong passphrase"));
    REQUIRE(store.unlock(passphrase, "a long enough passphrase"));
    store.lock();
    REQUIRE(store.unlock(passkey, "prf output as base64url, 43 characters long"));
    CHECK(store.remove_slot(passphrase));
    CHECK_FALSE(store.unlock(passphrase, "a long enough passphrase"));
    CHECK_THROWS(store.remove_slot(recovery));
    CHECK_THROWS(store.add_slot({console::SlotKind::prf, "../escape"}, "a long enough secret"));

    // The name is part of what is sealed: a file renamed does not open.
    auto other = cexchain::crypto::openssl::KeyPair::generate(cexchain::crypto::SigAlg::ed25519);
    REQUIRE(other);
    store.seal("bob", *other);
    std::filesystem::copy_file(dir.path / "keys" / "bob.sealed",
                               dir.path / "keys" / "mallory.sealed");
    CHECK_THROWS(store.open("mallory"));
    CHECK(store.remove_key("mallory"));
    CHECK(store.open("bob").public_key() == other->public_key());
    CHECK(store.keys().size() == 2);

    // Another console's store, from the files alone, starts locked.
    console::KeyStore reopened(dir.path);
    CHECK(reopened.initialized());
    CHECK_FALSE(reopened.unlocked());
    REQUIRE(reopened.unlock(recovery, code));
    CHECK(reopened.open("alice").public_key() == key->public_key());
}
