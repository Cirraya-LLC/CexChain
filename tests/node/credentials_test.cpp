// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Records as W3C Verifiable Credentials (spec/credentials.md): JCS, GZIP,
// base URLs and their did:web, status entries and lists, and a credential
// issued on a ledger and verified against its record's evidence, with every
// way it can lie.

#include <fstream>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/record.hpp>
#include <kanhe/node/credentials.hpp>
#include <kanhe/verifier/credentials.hpp>
#include <kanhe/verifier/gzip.hpp>
#include <kanhe/verifier/jcs.hpp>

#include "support/ledger_world.hpp"

using namespace kanhe::test;
using kanhe::Bytes;
using kanhe::ByteView;
using verifier_json = kanhe::verifier::Json;
namespace verifier = kanhe::verifier;
namespace node = kanhe::node;

namespace {

using V = cbor::Value;

/// Python's gzip.compress of 3,179 bytes of words, at level 9: one dynamic
/// block (another encoder's output).
constexpr std::string_view python_gzip =
    "1f8b08000000000002ffedced109c3300c45d155b49ab15f1d11552e92edac1f434ad2150afabc0f818ea05418"
    "b1fb4021b96ac2f8c5ab0db959793a1b0ab47312ca4d0415bf53e18fb477a283bbc2fd6e4c5e2719a4c39cb53e"
    "43de122b794f7df8370cb3edebd59e74c35d12cc60063398c10c66308319cc6006f3af9827810c05166b0c0000";
constexpr std::string_view python_text_sha256 =
    "fb6279acbac87550e049ecc07760d0f08b8b814492f2b53a353ad86f376a52dc";

/// A college's ledger: a credential key (a device with an ES256 key whose
/// delegation allows endorsements only), and a diploma with three fields,
/// two of them published.
struct College {
    World w{crypto::HashAlg::sha256, "Example College"};
    KeyPair device = std::move(*KeyPair::generate(crypto::SigAlg::esp256));
    protocol::Id device_id;
    protocol::Id delegation;
    protocol::FieldCommitment fields;
    protocol::Id record;
    verifier::BaseUrl base = *verifier::parse_base_url("https://ledger.example.com");
    std::string token = "AAAAAAAAAAAAAAAAAAAAAA";

    College() {
        protocol::ActorRegisterBody body{protocol::ActorKind::device, "Credentials",
                                         device.public_key(), std::nullopt, std::nullopt};
        device_id = w.ok(w.org(), w.statement(w.org_id(), std::nullopt, body));
        delegation = w.grant(w.org(), w.org_id(), std::nullopt, device_id,
                             scope({StatementType::record_endorse}));
        fields = *protocol::commit_fields(provider(), w.hash(),
                                          {{"name", w.nonce(), V::text("Chan Siu Ming")},
                                           {"programme", w.nonce(), V::text("Nursing")},
                                           {"grades", w.nonce(), V::text("A, A, B")}});
        protocol::RecordRegisterBody r{
            "example.org.diploma/1",
            Bytes(fields.root.bytes().begin(), fields.root.bytes().end()),
            fields.leaves.size(),
            {},
            V::map({{V::text("note"), V::bytes(Bytes{1})}, {V::text("year"), V::integer(2026)}}),
            std::nullopt};
        record = w.ok(w.org(), w.statement(w.org_id(), std::nullopt, r));
    }

    void endorse(const verifier::StatusEntry& entry, const KeyPair& key) {
        w.ok(key,
             w.statement(device_id, delegation,
                         protocol::RecordEndorseBody{record, verifier::credential_role(entry)}));
    }

    /// The published address's evidence: the record's, as of a new
    /// checkpoint, with name and programme disclosed.
    Bytes evidence() {
        REQUIRE(w.ledger().checkpoint(w.log_key()));
        auto bundle = w.ledger().export_evidence(w.log_key(), record);
        REQUIRE(bundle);
        for (const char* name : {"name", "programme"}) {
            bundle->disclosures.push_back(
                *protocol::disclose_field(provider(), w.hash(), fields, name));
        }
        return *protocol::encode_bundle(*bundle);
    }

    protocol::EvidenceReport report(ByteView bundle) {
        auto r = protocol::verify_bundle(provider(), bundle);
        REQUIRE(r);
        return *r;
    }

    verifier_json payload(ByteView bundle, const verifier::StatusEntry& entry,
                          std::vector<std::string> metadata = {"year"}) {
        auto content = verifier::credential_content(report(bundle), base, token, entry, metadata,
                                                    std::string("Diploma in Nursing"));
        INFO((content ? std::string() : content.error()));
        REQUIRE(content);
        return verifier::credential_json(*content);
    }

    std::string sign(const verifier_json& payload, const KeyPair& key) {
        auto jws = verifier::sign_credential(key, provider(), base.did, payload);
        REQUIRE(jws);
        return *jws;
    }

    verifier::CredentialReport check(const std::string& credential, ByteView bundle,
                                     verifier::CredentialOptions options = {}) {
        auto r = verifier::verify_credential(provider(), credential, bundle, options);
        INFO((r ? std::string() : std::string(r.error().detail)));
        REQUIRE(r);
        return *r;
    }

    std::vector<node::CredentialEntry> entries() {
        return node::credential_entries(w.ledger().state());
    }

    std::string status_list(const KeyPair& key) {
        const auto e = entries();
        const Bytes bits = node::status_bits(w.ledger().state(), e, 1);
        return sign(verifier::status_list_json(base, "Example College", 1, bits, t0), key);
    }
};

/// A compact JWS with its payload replaced by `payload` (bytes as given).
std::string with_payload(const std::string& jws, std::string_view payload) {
    const auto first = jws.find('.');
    const auto second = jws.find('.', first + 1);
    return jws.substr(0, first) + "." + kanhe::to_base64url(kanhe::as_bytes(payload)) +
           jws.substr(second);
}

} // namespace

TEST_CASE("JCS: members by UTF-16 code units, shortest escapes, integers only", "[credentials]") {
    verifier_json j = verifier_json::object();
    j["b"] = 1;
    j["a"] = verifier_json::array({"x\n\x1f/\xc3\xa9", true, nullptr, -5});
    j["\xef\xbd\x9e"] = 0;     // U+FF5E: after U+1F600 in UTF-16, before it by code point
    j["\xf0\x9f\x98\x80"] = 0; // U+1F600
    const auto out = verifier::jcs(j);
    REQUIRE(out);
    CHECK(*out == "{\"a\":[\"x\\n\\u001f/\xc3\xa9\",true,null,-5],\"b\":1,\"\xf0\x9f\x98\x80\":0,"
                  "\"\xef\xbd\x9e\":0}");
    CHECK(verifier::jcs(verifier_json(verifier::max_json_integer)));
    CHECK_FALSE(verifier::jcs(verifier_json(verifier::max_json_integer + 1)));
    CHECK_FALSE(verifier::jcs(verifier_json(1.5)));
    CHECK(verifier::parse_jcs(*out));
    CHECK_FALSE(verifier::parse_jcs("{\"b\":1,\"a\":2}"));
    CHECK_FALSE(verifier::parse_jcs("{\"a\":1,\"a\":2}"));
    CHECK_FALSE(verifier::parse_jcs("{\"a\": 1}"));
    CHECK_FALSE(verifier::parse_jcs("{\"a\":\"\\u0041\"}"));
    CHECK_FALSE(verifier::parse_jcs("{\"a\":1e2}"));
}

TEST_CASE("GZIP: ours round-trips small, others' decompress, damage fails", "[credentials]") {
    Bytes bits(verifier::status_list_bytes, 0);
    verifier::set_status_bit(bits, 0);
    verifier::set_status_bit(bits, 94'567);
    verifier::set_status_bit(bits, verifier::status_list_size - 1);
    CHECK(bits[0] == 0x80);
    CHECK(bits.back() == 0x01);
    const Bytes z = verifier::gzip_compress(bits);
    CHECK(z.size() < 200);
    const auto back = verifier::gzip_decompress(z, 1 << 20);
    REQUIRE(back);
    CHECK(*back == bits);
    for (const std::uint64_t i :
         {std::uint64_t{0}, std::uint64_t{94'567}, std::uint64_t{131'071}}) {
        CHECK(verifier::status_bit(bits, i));
    }
    CHECK_FALSE(verifier::status_bit(bits, 1));
    // Every length of run, and none at all.
    for (const std::size_t n : {0UZ, 1UZ, 2UZ, 3UZ, 4UZ, 258UZ, 259UZ, 260UZ, 261UZ, 1000UZ}) {
        const Bytes data(n, 7);
        const auto again = verifier::gzip_decompress(verifier::gzip_compress(data), 1 << 20);
        REQUIRE(again);
        CHECK(*again == data);
    }
    const auto other = verifier::gzip_decompress(*kanhe::from_hex(python_gzip), 1 << 20);
    REQUIRE(other);
    CHECK(other->size() == 3179);
    CHECK(kanhe::to_hex(provider().digest(crypto::HashAlg::sha256, *other)->bytes()) ==
          python_text_sha256);

    Bytes damaged = z;
    damaged[damaged.size() - 5] ^= 1; // the CRC
    CHECK_FALSE(verifier::gzip_decompress(damaged, 1 << 20));
    Bytes longer = z;
    longer.push_back(0);
    CHECK_FALSE(verifier::gzip_decompress(longer, 1 << 20));
    CHECK_FALSE(verifier::gzip_decompress(ByteView(z).first(z.size() - 1), 1 << 20));
    CHECK_FALSE(verifier::gzip_decompress(z, 1000)); // past the limit
    Bytes flagged = z;
    flagged[3] = 0x20;
    CHECK_FALSE(verifier::gzip_decompress(flagged, 1 << 20));

    const std::string encoded = verifier::encode_status_list(bits);
    CHECK(encoded.starts_with("uH4sI"));
    const auto decoded = verifier::decode_status_list(encoded);
    REQUIRE(decoded);
    CHECK(*decoded == bits);
    CHECK_FALSE(verifier::decode_status_list(encoded.substr(1)));
    CHECK_FALSE(verifier::decode_status_list(
        "u" + kanhe::to_base64url(verifier::gzip_compress(Bytes(100, 0)))));
}

TEST_CASE("a base URL and its did:web", "[credentials]") {
    const auto plain = verifier::parse_base_url("https://ledger.example.com/");
    REQUIRE(plain);
    CHECK(plain->url == "https://ledger.example.com");
    CHECK(plain->did == "did:web:ledger.example.com");
    CHECK(plain->did_document_url == "https://ledger.example.com/.well-known/did.json");
    const auto pathed = verifier::parse_base_url("https://example.com:8443/kanhe/college");
    REQUIRE(pathed);
    CHECK(pathed->did == "did:web:example.com%3A8443:kanhe:college");
    CHECK(pathed->did_document_url == "https://example.com:8443/kanhe/college/did.json");
    CHECK(verifier::parse_base_url("http://127.0.0.1:8080"));
    CHECK(verifier::parse_base_url("http://localhost:8080"));
    for (const char* bad :
         {"http://example.com", "https://1.2.3.4", "https://Example.com", "https://a..b",
          "ftp://example.com", "https://example.com:0", "https://example.com:65536",
          "https://example.com/a/../b", "https://example.com/a b", "https://", "example.com"}) {
        INFO(bad);
        CHECK_FALSE(verifier::parse_base_url(bad));
    }
}

TEST_CASE("status entries in endorsement roles", "[credentials]") {
    CHECK(verifier::credential_role({.list = 1, .index = 94'567}) == "credential/1/94567");
    const auto e = verifier::parse_credential_role("credential/2/0");
    REQUIRE(e);
    CHECK(*e == verifier::StatusEntry{.list = 2, .index = 0});
    for (const char* bad :
         {"credential/0/1", "credential/01/1", "credential/1/01", "credential/1/131072",
          "credential/1/", "credential/1", "credential/1/2/3", "credentials/1/2", "reviewer"}) {
        INFO(bad);
        CHECK_FALSE(verifier::parse_credential_role(bad));
    }
}

TEST_CASE("a credential issued on the ledger verifies against its evidence", "[credentials]") {
    College c;
    const verifier::StatusEntry entry{.list = 1, .index = 94'567};
    c.endorse(entry, c.device);
    const Bytes bundle = c.evidence();
    const verifier_json payload = c.payload(bundle, entry);
    CHECK(payload["credentialSubject"] ==
          verifier_json{{"name", "Chan Siu Ming"}, {"programme", "Nursing"}, {"year", 2026}});
    CHECK(payload["issuer"]["id"] == "did:web:ledger.example.com");
    CHECK(payload["credentialStatus"]["id"] == "https://ledger.example.com/status/1#94567");
    const std::string credential = c.sign(payload, c.device);

    const auto jws = verifier::parse_jws(credential);
    REQUIRE(jws);
    CHECK(jws->header ==
          verifier_json{{"alg", "ES256"},
                        {"cty", "vc"},
                        {"kid", "did:web:ledger.example.com#" +
                                    *verifier::jwk_thumbprint(provider(), c.device.public_key())},
                        {"typ", "vc+jwt"}});
    CHECK(verifier::verify_jws(provider(), *jws, c.device.public_key()));

    const auto doc = verifier::did_document(
        provider(), c.base, std::vector<crypto::PublicKey>{c.device.public_key()}, c.w.org_id());
    REQUIRE(doc);
    verifier::CredentialOptions options;
    options.did_document = doc->dump();
    options.status_list = c.status_list(c.device);
    const auto r = c.check(credential, bundle, options);
    INFO(r.problems.size());
    CHECK(r.verified());
    CHECK(r.record_status == "live");
    CHECK(r.key_actor == c.device_id);
    CHECK(r.status_list_bit == false);
    CHECK(r.evidence.complete);
    CHECK(verifier::credential_report_json(r, false)["verified"] == true);
    CHECK(verifier::credential_report_text(r, false).starts_with("VERIFIED"));

    const auto addresses = verifier::credential_addresses(credential);
    REQUIRE(addresses);
    CHECK(addresses->evidence == "https://ledger.example.com/c/" + c.token);
    CHECK(addresses->did_document == "https://ledger.example.com/.well-known/did.json");
    CHECK(addresses->status_list == "https://ledger.example.com/status/1");

    // The ledger shows it: its entry, list 1's bit clear until revoked.
    const auto entries = c.entries();
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].entry == entry);
    CHECK(entries[0].actor == c.device_id);
    CHECK(node::is_credential_key(c.w.ledger().state(), *c.w.ledger().state().actor(c.device_id)));
    CHECK_FALSE(
        node::is_credential_key(c.w.ledger().state(), *c.w.ledger().state().actor(c.w.org_id())));
    ledger::SeededEntropy entropy(3);
    for (int i = 0; i < 50; ++i) {
        CHECK(node::choose_status_entry(entries, entropy) != entry);
    }

    // Revoked: the list says so, and a list made before disagrees.
    const std::string before = options.status_list.value();
    c.w.ok(c.w.org(), c.w.statement(c.w.org_id(), std::nullopt,
                                    protocol::RecordRevokeBody{c.record, "issued in error"}));
    const Bytes revoked = c.evidence();
    options.status_list = c.status_list(c.device);
    const auto rr = c.check(credential, revoked, options);
    CHECK(rr.verified());
    CHECK(rr.record_status == "revoked");
    CHECK(rr.status_list_bit == true);
    options.status_list = before;
    const auto hidden = c.check(credential, revoked, options);
    CHECK_FALSE(hidden.verified());
    REQUIRE(hidden.status_list_problems.size() == 1);
    CHECK(hidden.status_list_problems[0].find("ledger says the record is revoked") !=
          std::string::npos);
    // No credential for a revoked record.
    CHECK_FALSE(
        verifier::credential_content(c.report(revoked), c.base, c.token, entry, {}, std::nullopt));
}

TEST_CASE("a credential that lies is found out", "[credentials]") {
    College c;
    const verifier::StatusEntry entry{.list = 1, .index = 7};
    c.endorse(entry, c.device);
    const Bytes bundle = c.evidence();
    const verifier_json payload = c.payload(bundle, entry);
    auto problems = [&](const std::string& credential) {
        return c.check(credential, bundle).problems;
    };
    auto mentions = [](const std::vector<std::string>& list, std::string_view what) {
        return std::ranges::any_of(
            list, [&](const std::string& p) { return p.find(what) != std::string::npos; });
    };

    // Signed by a key that did not endorse the record.
    const KeyPair stranger = std::move(*KeyPair::generate(crypto::SigAlg::esp256));
    CHECK(mentions(problems(c.sign(payload, stranger)), "signature"));
    // Another status entry than its endorsement's.
    verifier_json other = payload;
    other["credentialStatus"]["id"] = "https://ledger.example.com/status/1#8";
    other["credentialStatus"]["statusListIndex"] = "8";
    CHECK(mentions(problems(c.sign(other, c.device)), "credential/1/8"));
    // A sealed field claimed.
    other = payload;
    other["credentialSubject"]["grades"] = "A, A, A";
    CHECK(mentions(problems(c.sign(other, c.device)), "grades = A, A, A"));
    // A disclosed field changed, a number as text.
    other = payload;
    other["credentialSubject"]["year"] = "2026";
    CHECK(mentions(problems(c.sign(other, c.device)), "year = 2026"));
    // Another issuer's name, another date.
    other = payload;
    other["issuer"]["name"] = "Example University";
    CHECK(mentions(problems(c.sign(other, c.device)), "Example University"));
    other = payload;
    other["validFrom"] = "2026-01-01T00:00:00.000Z";
    CHECK(mentions(problems(c.sign(other, c.device)), "registered at"));

    // Not this profile: refused before anything else.
    const std::string good = c.sign(payload, c.device);
    auto refused = [&](const std::string& credential) {
        return !verifier::verify_credential(provider(), credential, bundle, {});
    };
    CHECK(refused(with_payload(good, payload.dump(1)))); // not JCS
    other = payload;
    other["evidence"][0]["id"] = "https://ledger.example.org/c/" + c.token;
    CHECK(refused(c.sign(other, c.device))); // another base URL than the issuer's
    other = payload;
    other["credentialStatus"]["statusListCredential"] = "https://ledger.example.com/lists/1";
    other["credentialStatus"]["id"] = "https://ledger.example.com/lists/1#7";
    CHECK(refused(c.sign(other, c.device))); // a list elsewhere
    other = payload;
    other["extra"] = true;
    CHECK(refused(c.sign(other, c.device))); // a member not defined
    other = payload;
    other["credentialSubject"]["id"] = "did:example:1";
    CHECK(refused(c.sign(other, c.device)));         // a subject id
    CHECK(refused(good.substr(0, good.rfind('.')))); // two parts
    CHECK(refused("a.b.c"));
    verifier::CredentialOptions pinned;
    pinned.verify.expected_ledger = *protocol::to_id(Bytes(32, 1));
    CHECK_FALSE(verifier::verify_credential(provider(), good, bundle, pinned));

    // The DID document must name this key and this ledger.
    verifier::CredentialOptions options;
    options.did_document =
        verifier::did_document(provider(), c.base,
                               std::vector<crypto::PublicKey>{stranger.public_key()}, c.w.org_id())
            ->dump();
    CHECK_FALSE(c.check(good, bundle, options).verified());
    options.did_document =
        verifier::did_document(provider(), c.base,
                               std::vector<crypto::PublicKey>{c.device.public_key()},
                               *protocol::to_id(Bytes(32, 1)))
            ->dump();
    const auto wrong_ledger = c.check(good, bundle, options);
    CHECK(mentions(wrong_ledger.did_document_problems, "ledger"));
    // A status list signed by a stranger.
    options = {};
    options.status_list = c.status_list(stranger);
    CHECK(mentions(c.check(good, bundle, options).status_list_problems, "not signed"));
}

TEST_CASE("a credential key that rotates keeps its credentials verifying", "[credentials]") {
    College c;
    const verifier::StatusEntry entry{.list = 1, .index = 3};
    c.endorse(entry, c.device);
    const KeyPair rotated = std::move(*KeyPair::generate(crypto::SigAlg::esp256));
    c.w.ok(c.device,
           c.w.statement(c.device_id, std::nullopt,
                         protocol::ActorRotateKeyBody{c.device_id, rotated.public_key()}));
    const Bytes bundle = c.evidence();
    const verifier_json payload = c.payload(bundle, entry);
    CHECK(c.check(c.sign(payload, c.device), bundle).verified()); // signed before the rotation
    CHECK(c.check(c.sign(payload, rotated), bundle).verified());  // and again after it

    // The DID document lists both keys, ordered by thumbprint.
    const auto keys = node::credential_keys(
        c.w.ledger().state(), c.entries(), std::nullopt,
        [&](std::uint64_t index) -> kanhe::Result<protocol::SignedStatement> {
            const auto entry_bytes = c.w.ledger().entry(index);
            const auto log_entry = protocol::decode_log_entry(*entry_bytes);
            return protocol::parse_statement(provider(), log_entry->statement, c.w.hash());
        });
    REQUIRE(keys);
    REQUIRE(keys->size() == 2);
    const auto doc = verifier::did_document(provider(), c.base, *keys, c.w.org_id());
    REQUIRE(doc);
    const auto& methods = (*doc)["verificationMethod"];
    REQUIRE(methods.size() == 2);
    CHECK(methods[0]["id"].get<std::string>() < methods[1]["id"].get<std::string>());
}

TEST_CASE("what cannot be a claim is named", "[credentials]") {
    College c;
    const Bytes bundle = c.evidence();
    const auto report = c.report(bundle);
    const verifier::StatusEntry entry{.list = 1, .index = 1};
    auto refusal = [&](std::vector<std::string> metadata) {
        const auto content =
            verifier::credential_content(report, c.base, c.token, entry, metadata, std::nullopt);
        REQUIRE_FALSE(content);
        return content.error();
    };
    CHECK(refusal({"note"}).find("note holds neither text") != std::string::npos);
    CHECK(refusal({"colour"}).find("no entry colour") != std::string::npos);
    CHECK_FALSE(
        verifier::credential_content(report, c.base, c.token, entry, {}, std::string(257, 'a')));
    CHECK(verifier::claim_name_problem("id"));
    CHECK(verifier::claim_name_problem("type"));
    CHECK(verifier::claim_name_problem("@context"));
    CHECK_FALSE(verifier::claim_name_problem("name"));
    CHECK(verifier::claim_value(V::integer(verifier::max_json_integer)));
    CHECK_FALSE(verifier::claim_value(V::integer(verifier::max_json_integer + 1)));
    CHECK_FALSE(verifier::claim_value(V::bytes(Bytes{1})));
    CHECK(*verifier::claim_value(V::boolean(true)) == true);
}

TEST_CASE("a full status list moves on to the next", "[credentials]") {
    std::vector<node::CredentialEntry> entries;
    for (std::uint64_t i = 0; i < verifier::status_list_size; ++i) {
        entries.push_back(
            {.record = {}, .actor = {}, .entry = {.list = 1, .index = i}, .index = i});
    }
    ledger::SeededEntropy entropy(1);
    CHECK(node::choose_status_entry(entries, entropy).list == 2);
    entries.pop_back();
    CHECK(node::choose_status_entry(entries, entropy) ==
          verifier::StatusEntry{.list = 1, .index = verifier::status_list_size - 1});
}

TEST_CASE("the credential test vectors, made apart from this code", "[credentials][vectors]") {
    std::ifstream file(KANHE_TESTVECTORS_DIR "/credentials-v1.json");
    REQUIRE(file);
    const auto v = nlohmann::json::parse(file);
    auto key_of = [](const std::string& hex) {
        return crypto::PublicKey{crypto::SigAlg::esp256, *kanhe::from_hex(hex)};
    };
    for (const auto& c : v["jcs"]) {
        CHECK(*verifier::jcs(verifier_json(c["value"])) == c["jcs"].get<std::string>());
    }
    for (const auto& text : v["jcs_refused"]) {
        INFO(text.get<std::string>());
        CHECK_FALSE(verifier::parse_jcs(text.get<std::string>()));
    }
    for (const auto& t : v["thumbprints"]) {
        const auto key = key_of(t["key"]);
        CHECK(*verifier::jwk_thumbprint(provider(), key) == t["thumbprint"].get<std::string>());
        CHECK(*verifier::jcs(*verifier::public_jwk(key)) ==
              *verifier::jcs(verifier_json(t["jwk"])));
        CHECK(*verifier::jwk_key(verifier_json(t["jwk"])) == key);
    }
    for (const auto& b : v["base_urls"]) {
        const auto base = verifier::parse_base_url(b["url"].get<std::string>());
        REQUIRE(base);
        CHECK(base->url == b["base"].get<std::string>());
        CHECK(base->did == b["did"].get<std::string>());
        CHECK(base->did_document_url == b["did_document"].get<std::string>());
    }
    for (const auto& url : v["base_urls_refused"]) {
        INFO(url.get<std::string>());
        CHECK_FALSE(verifier::parse_base_url(url.get<std::string>()));
    }
    for (const auto& r : v["roles"]) {
        const auto entry = verifier::parse_credential_role(r["role"].get<std::string>());
        REQUIRE(entry);
        CHECK(entry->list == r["list"].get<std::uint64_t>());
        CHECK(entry->index == r["index"].get<std::uint64_t>());
        CHECK(verifier::credential_role(*entry) == r["role"].get<std::string>());
    }
    for (const auto& role : v["roles_refused"]) {
        INFO(role.get<std::string>());
        CHECK_FALSE(verifier::parse_credential_role(role.get<std::string>()));
    }
    for (const auto& c : v["credentials"]) {
        INFO(c["description"].get<std::string>());
        const auto& in = c["content"];
        verifier::CredentialContent content;
        content.base = *verifier::parse_base_url(in["base"].get<std::string>());
        content.organization = in["organization"].get<std::string>();
        if (!in["name"].is_null()) {
            content.name = in["name"].get<std::string>();
        }
        content.registered_at = in["registered_at"].get<protocol::Timestamp>();
        for (const auto& claim : in["subject"]) {
            content.subject.emplace_back(claim[0].get<std::string>(), verifier_json(claim[1]));
        }
        content.entry = {.list = in["list"].get<std::uint64_t>(),
                         .index = in["index"].get<std::uint64_t>()};
        content.token = in["token"].get<std::string>();
        content.ledger = *protocol::to_id(*kanhe::from_hex(in["ledger"].get<std::string>()));
        content.record = *protocol::to_id(*kanhe::from_hex(in["record"].get<std::string>()));
        CHECK(*verifier::jcs(verifier::credential_json(content)) ==
              c["payload"].get<std::string>());
        const auto jws = verifier::parse_jws(c["jws"].get<std::string>());
        REQUIRE(jws);
        CHECK(*verifier::jcs(jws->header) == c["header"].get<std::string>());
        CHECK(*verifier::jcs(jws->payload) == c["payload"].get<std::string>());
        CHECK(verifier::verify_jws(provider(), *jws, key_of(c["key"])));
        CHECK(jws->kid ==
              content.base.did + "#" + *verifier::jwk_thumbprint(provider(), key_of(c["key"])));
        CHECK(verifier::credential_addresses(c["jws"].get<std::string>()));
    }
    for (const auto& d : v["did_documents"]) {
        INFO(d["description"].get<std::string>());
        std::vector<crypto::PublicKey> keys;
        for (const auto& k : d["keys"]) {
            keys.push_back(key_of(k));
        }
        const auto doc = verifier::did_document(
            provider(), *verifier::parse_base_url(d["base"].get<std::string>()), keys,
            *protocol::to_id(*kanhe::from_hex(d["ledger"].get<std::string>())));
        REQUIRE(doc);
        CHECK(*verifier::jcs(*doc) == d["document"].get<std::string>());
    }
    for (const auto& s : v["status_lists"]) {
        INFO(s["description"].get<std::string>());
        const auto bits = verifier::decode_status_list(s["encoded"].get<std::string>());
        REQUIRE(bits);
        CHECK(kanhe::to_hex(provider().digest(crypto::HashAlg::sha256, *bits)->bytes()) ==
              s["sha256"].get<std::string>());
        for (const auto& i : s["set"]) {
            CHECK(verifier::status_bit(*bits, i.get<std::uint64_t>()));
        }
    }
    for (const auto& s : v["status_lists_refused"]) {
        INFO(s["why"].get<std::string>());
        CHECK_FALSE(verifier::decode_status_list(s["encoded"].get<std::string>()));
    }
}
