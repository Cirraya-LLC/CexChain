// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstdint>
#include <map>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/merkle.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "support/vectors.hpp"

namespace cbor = cexchain::cbor;
namespace crypto = cexchain::crypto;
namespace protocol = cexchain::protocol;
using cbor::Value;
using cexchain::Bytes;
using cexchain::Errc;
using cexchain::to_hex;
using cexchain::test::hex;
using cexchain::test::hex_field;
using cexchain::test::load_vectors;
using crypto::openssl::KeyPair;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

const nlohmann::json& vectors() {
    static const nlohmann::json document = load_vectors("protocol-v0.1.json");
    return document;
}

const KeyPair& key(const std::string& name) {
    static std::map<std::string, KeyPair> keys;
    auto it = keys.find(name);
    if (it == keys.end()) {
        auto loaded = KeyPair::from_ed25519_seed(hex(vectors()["seeds"][name].get<std::string>()));
        REQUIRE(loaded);
        it = keys.emplace(name, std::move(*loaded)).first;
    }
    return it->second;
}

crypto::HashAlg ledger_hash(const nlohmann::json& ledger) {
    const auto alg = crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
    REQUIRE(alg);
    return *alg;
}

Value json_to_cbor(const nlohmann::json& value) {
    if (value.is_string()) {
        return Value::text(value.get<std::string>());
    }
    REQUIRE(value.is_number_unsigned());
    return Value::unsigned_integer(value.get<std::uint64_t>());
}

Bytes encoded(const Value& value) {
    auto bytes = cbor::encode(value);
    REQUIRE(bytes);
    return *bytes;
}

/// A valid non-genesis payload map from the vectors, for mutation tests.
cbor::Map sample_payload_map() {
    const auto& statement = vectors()["ledgers"][0]["statements"][2]; // delegation grant
    auto value = cbor::decode(hex_field(statement["payload"]));
    REQUIRE(value);
    return *value->as_map();
}

Errc payload_error(const cbor::Map& map) {
    const auto statement = protocol::decode_payload(encoded(Value::map(map)));
    REQUIRE_FALSE(statement);
    return statement.error().code;
}

const cbor::Map& map_at(const cbor::Map& map, std::int64_t key) {
    for (const auto& item : map) {
        if (item.key.as_int64() == key) {
            REQUIRE(item.value.as_map() != nullptr);
            return *item.value.as_map();
        }
    }
    FAIL("missing key");
    return map;
}

void set_key(cbor::Map& map, std::int64_t key, Value value) {
    for (auto& item : map) {
        if (item.key.as_int64() == key) {
            item.value = std::move(value);
            return;
        }
    }
    map.push_back({Value::integer(key), std::move(value)});
}

void remove_key(cbor::Map& map, std::int64_t key) {
    std::erase_if(map, [key](const cbor::MapEntry& item) { return item.key.as_int64() == key; });
}

} // namespace

TEST_CASE("statements match the independent encoder byte for byte", "[protocol][vectors]") {
    for (const auto& ledger : vectors()["ledgers"]) {
        const crypto::HashAlg hash = ledger_hash(ledger);
        INFO(crypto::name(hash));
        for (const auto& vector : ledger["statements"]) {
            INFO(vector["name"].get<std::string>());
            const Bytes bytes = hex_field(vector["encoded"]);
            const std::string signer_name = vector["signer"].get<std::string>();
            const KeyPair& signer = key(signer_name);

            const auto parsed = protocol::parse_statement(provider(), bytes, hash);
            REQUIRE(parsed);
            CHECK(to_hex(parsed->id.bytes()) == vector["statement_id"].get<std::string>());
            CHECK(protocol::encode_payload(parsed->statement) == hex_field(vector["payload"]));
            CHECK(protocol::verify_statement(provider(), *parsed, signer.public_key()));

            const auto resigned =
                protocol::sign_statement(signer, provider(), hash, parsed->statement);
            REQUIRE(resigned);
            CHECK(resigned->encoded == bytes);
            CHECK(resigned->id == parsed->id);
        }
        const auto genesis =
            protocol::parse_statement(provider(), hex_field(ledger["statements"][0]["encoded"]));
        REQUIRE(genesis);
        CHECK(genesis->hash_alg == hash);
        CHECK(to_hex(genesis->id.bytes()) == ledger["ledger_id"].get<std::string>());
    }
}

TEST_CASE("statement signatures bind the signer's key", "[protocol]") {
    const auto& ledger = vectors()["ledgers"][0];
    const auto parsed = protocol::parse_statement(
        provider(), hex_field(ledger["statements"][1]["encoded"]), ledger_hash(ledger));
    REQUIRE(parsed);
    CHECK(protocol::verify_statement(provider(), *parsed, key("org_root").public_key()));
    CHECK(
        protocol::verify_statement(provider(), *parsed, key("person").public_key()).error().code ==
        Errc::verification_failed);

    // Non-genesis statements need the ledger hash to compute their identifier.
    CHECK(protocol::parse_statement(provider(), parsed->encoded).error().code ==
          Errc::invalid_argument);
    // Genesis with a mismatched expected hash is refused.
    CHECK(protocol::parse_statement(provider(), hex_field(ledger["statements"][0]["encoded"]),
                                    crypto::HashAlg::sm3)
              .error()
              .code == Errc::invalid_argument);
}

TEST_CASE("log entries, tree, checkpoint, and cosignature match the vectors",
          "[protocol][vectors]") {
    for (const auto& ledger : vectors()["ledgers"]) {
        const crypto::HashAlg hash = ledger_hash(ledger);
        INFO(crypto::name(hash));

        cexchain::merkle::Tree tree(provider(), hash);
        for (const auto& entry_hex : ledger["log_entries"]) {
            const Bytes entry = hex(entry_hex.get<std::string>());
            const auto decoded = protocol::decode_log_entry(entry);
            REQUIRE(decoded);
            CHECK(protocol::encode_log_entry(*decoded) == entry);
            REQUIRE(tree.append(entry));
        }
        CHECK(to_hex(tree.root()->bytes()) == ledger["root"].get<std::string>());

        const Bytes checkpoint_bytes = hex_field(ledger["checkpoint"]);
        const auto checkpoint = protocol::parse_checkpoint(checkpoint_bytes);
        REQUIRE(checkpoint);
        CHECK(checkpoint->checkpoint.tree_size == tree.size());
        CHECK(checkpoint->checkpoint.root == *tree.root());
        CHECK(checkpoint->checkpoint.tree_hash == hash);
        CHECK(protocol::verify_checkpoint(provider(), *checkpoint, key("log").public_key()));
        CHECK_FALSE(
            protocol::verify_checkpoint(provider(), *checkpoint, key("witness").public_key()));
        const auto resigned =
            protocol::sign_checkpoint(key("log"), provider(), checkpoint->checkpoint);
        REQUIRE(resigned);
        CHECK(resigned->encoded == checkpoint_bytes);

        const Bytes cosignature_bytes = hex_field(ledger["cosignature"]);
        const auto cosignature = protocol::parse_cosignature(cosignature_bytes);
        REQUIRE(cosignature);
        CHECK(cosignature->checkpoint == checkpoint->checkpoint);
        CHECK(protocol::verify_cosignature(provider(), *cosignature, key("witness").public_key()));
        const auto recosigned =
            protocol::cosign_checkpoint(key("witness"), provider(), checkpoint->checkpoint);
        REQUIRE(recosigned);
        CHECK(recosigned->encoded == cosignature_bytes);

        // The content types keep checkpoints and cosignatures apart.
        CHECK(protocol::parse_checkpoint(cosignature_bytes).error().code == Errc::malformed);
        CHECK(protocol::parse_cosignature(checkpoint_bytes).error().code == Errc::malformed);
        CHECK(protocol::parse_statement(provider(), checkpoint_bytes, hash).error().code ==
              Errc::malformed);
    }
}

TEST_CASE("receipts match the vectors and verify against log entries", "[protocol][vectors]") {
    for (const auto& ledger : vectors()["ledgers"]) {
        const crypto::HashAlg hash = ledger_hash(ledger);
        INFO(crypto::name(hash));
        const auto& entries = ledger["log_entries"];
        for (const auto& vector : ledger["receipts"]) {
            const auto index = vector["index"].get<std::size_t>();
            INFO("receipt for entry " << index);
            const Bytes bytes = hex_field(vector["encoded"]);
            const auto receipt = protocol::parse_receipt(bytes);
            REQUIRE(receipt);
            CHECK(receipt->tree_hash == hash);
            CHECK(receipt->proof.leaf_index == index);
            CHECK(receipt->proof.tree_size == entries.size());

            const Bytes entry = hex(entries[index].get<std::string>());
            const auto root =
                protocol::verify_receipt(provider(), *receipt, entry, key("log").public_key());
            REQUIRE(root);
            CHECK(to_hex(root->bytes()) == ledger["root"].get<std::string>());

            const auto reissued =
                protocol::issue_receipt(key("log"), provider(), hash, *root, receipt->proof);
            REQUIRE(reissued);
            CHECK(*reissued == bytes);

            const Bytes other_entry = hex(entries[(index + 1) % entries.size()].get<std::string>());
            CHECK_FALSE(protocol::verify_receipt(provider(), *receipt, other_entry,
                                                 key("log").public_key()));
            CHECK_FALSE(
                protocol::verify_receipt(provider(), *receipt, entry, key("witness").public_key()));
        }
    }
}

TEST_CASE("record field commitments and disclosure match the vectors", "[protocol][vectors]") {
    for (const auto& ledger : vectors()["ledgers"]) {
        const crypto::HashAlg hash = ledger_hash(ledger);
        INFO(crypto::name(hash));

        std::vector<protocol::RecordField> fields;
        for (const auto& item : ledger["record_fields"]) {
            protocol::RecordField field;
            field.name = item["name"].get<std::string>();
            const Bytes salt = hex_field(item["salt"]);
            std::ranges::copy(salt, field.salt.begin());
            field.value = json_to_cbor(item["value"]);
            fields.push_back(std::move(field));
        }
        const auto commitment = protocol::commit_fields(provider(), hash, fields);
        REQUIRE(commitment);
        CHECK(to_hex(commitment->root.bytes()) == ledger["field_root"].get<std::string>());

        const auto& expected = ledger["disclosure"];
        const auto disclosure = protocol::disclose_field(provider(), hash, *commitment,
                                                         expected["name"].get<std::string>());
        REQUIRE(disclosure);
        CHECK(disclosure->leaf == hex_field(expected["leaf"]));
        CHECK(disclosure->index == expected["index"].get<std::uint64_t>());
        REQUIRE(disclosure->path.size() == expected["path"].size());
        for (std::size_t i = 0; i < disclosure->path.size(); ++i) {
            CHECK(to_hex(disclosure->path[i].bytes()) == expected["path"][i].get<std::string>());
        }

        const auto field = protocol::verify_disclosure(provider(), hash, commitment->root.bytes(),
                                                       fields.size(), *disclosure);
        REQUIRE(field);
        CHECK(field->name == "result");
        CHECK(*field->value.as_text() == "pass");

        auto forged = *disclosure;
        forged.leaf = *protocol::encode_field({"result", field->salt, Value::text("fail")});
        CHECK_FALSE(protocol::verify_disclosure(provider(), hash, commitment->root.bytes(),
                                                fields.size(), forged));

        const auto& attachment = ledger["attachment"];
        protocol::Nonce salt{};
        std::ranges::copy(hex_field(attachment["salt"]), salt.begin());
        const auto commitment_value = protocol::attachment_commitment(
            provider(), hash, salt, hex_field(attachment["content"]));
        REQUIRE(commitment_value);
        CHECK(to_hex(commitment_value->bytes()) == attachment["commitment"].get<std::string>());
    }
}

TEST_CASE("statement payloads enforce the specification", "[protocol]") {
    SECTION("unknown keys and an incomplete presence proof") {
        auto map = sample_payload_map();
        set_key(map, 99, Value::null());
        CHECK(payload_error(map) == Errc::malformed);
        map = sample_payload_map();
        set_key(map, 8, Value::map({}));
        CHECK(payload_error(map) == Errc::malformed);
    }
    SECTION("version and type") {
        auto map = sample_payload_map();
        set_key(map, 0, Value::unsigned_integer(2));
        CHECK(payload_error(map) == Errc::unsupported);
        map = sample_payload_map();
        set_key(map, 1, Value::unsigned_integer(9));
        CHECK(payload_error(map) == Errc::unsupported);
    }
    SECTION("ledger and actor are required outside genesis") {
        auto map = sample_payload_map();
        remove_key(map, 3);
        CHECK(payload_error(map) == Errc::malformed);
    }
    SECTION("nonce and identifiers have fixed sizes") {
        auto map = sample_payload_map();
        set_key(map, 6, Value::bytes(Bytes(15, 0)));
        CHECK(payload_error(map) == Errc::malformed);
        map = sample_payload_map();
        set_key(map, 2, Value::bytes(Bytes(31, 0)));
        CHECK(payload_error(map) == Errc::malformed);
    }
    SECTION("scope lists must be canonical") {
        const cbor::Map map = sample_payload_map();
        const cbor::Map body = map_at(map, 7);
        const cbor::Map scope = map_at(body, 2);
        auto with_scope = [&](cbor::Map changed) {
            auto new_body = body;
            set_key(new_body, 2, Value::map(std::move(changed)));
            auto new_map = map;
            set_key(new_map, 7, Value::map(std::move(new_body)));
            return payload_error(new_map);
        };
        auto unsorted = scope;
        set_key(unsorted, 1,
                Value::array({Value::unsigned_integer(17), Value::unsigned_integer(16)}));
        CHECK(with_scope(unsorted) == Errc::non_canonical);
        auto with_genesis = scope;
        set_key(with_genesis, 1, Value::array({Value::unsigned_integer(1)}));
        CHECK(with_scope(with_genesis) == Errc::malformed);
        auto explicit_false = scope;
        set_key(explicit_false, 5, Value::boolean(false));
        CHECK(with_scope(explicit_false) == Errc::non_canonical);
        auto inverted = scope;
        set_key(inverted, 3, Value::unsigned_integer(UINT64_MAX));
        CHECK(with_scope(inverted) == Errc::malformed);
    }
}

TEST_CASE("encoding refuses statements that break structural rules", "[protocol]") {
    const auto& ledger = vectors()["ledgers"][0];
    const auto agent = protocol::parse_statement(
        provider(), hex_field(ledger["statements"][3]["encoded"]), ledger_hash(ledger));
    REQUIRE(agent);

    auto no_responsible = agent->statement;
    std::get<protocol::ActorRegisterBody>(no_responsible.body).responsible.reset();
    CHECK(protocol::encode_payload(no_responsible).error().code == Errc::invalid_argument);

    auto person_with_profile = agent->statement;
    std::get<protocol::ActorRegisterBody>(person_with_profile.body).kind =
        protocol::ActorKind::person;
    CHECK(protocol::encode_payload(person_with_profile).error().code == Errc::invalid_argument);

    auto genesis_with_ledger =
        protocol::parse_statement(provider(), hex_field(ledger["statements"][0]["encoded"]))
            ->statement;
    genesis_with_ledger.ledger_id = agent->id;
    CHECK(protocol::encode_payload(genesis_with_ledger).error().code == Errc::invalid_argument);
}

TEST_CASE("signed envelopes are strict about their headers", "[protocol]") {
    const auto& ledger = vectors()["ledgers"][0];
    const auto parsed = protocol::parse_statement(
        provider(), hex_field(ledger["statements"][1]["encoded"]), ledger_hash(ledger));
    REQUIRE(parsed);
    const Bytes payload = *parsed->envelope.payload;
    const Bytes signature = parsed->envelope.signature;

    auto rebuild = [&](cbor::Map protected_map, cbor::Map unprotected, Value body) {
        return encoded(Value::tagged(
            18, Value::array({Value::bytes(encoded(Value::map(std::move(protected_map)))),
                              Value::map(std::move(unprotected)), std::move(body),
                              Value::bytes(signature)})));
    };
    const cbor::Map good_protected = *parsed->envelope.protected_header.as_map();

    CHECK(protocol::parse_statement(provider(), rebuild(good_protected, {}, Value::bytes(payload)),
                                    crypto::HashAlg::sha256));

    auto extra = good_protected;
    extra.push_back({Value::integer(99), Value::null()});
    CHECK(protocol::parse_statement(provider(), rebuild(extra, {}, Value::bytes(payload)),
                                    crypto::HashAlg::sha256)
              .error()
              .code == Errc::malformed);

    CHECK(protocol::parse_statement(
              provider(),
              rebuild(good_protected, {{Value::integer(99), Value::null()}}, Value::bytes(payload)),
              crypto::HashAlg::sha256)
              .error()
              .code == Errc::malformed);

    CHECK(protocol::parse_statement(provider(), rebuild(good_protected, {}, Value::null()),
                                    crypto::HashAlg::sha256)
              .error()
              .code == Errc::malformed);
}

TEST_CASE("receipts are strict about their structure", "[protocol]") {
    const auto& ledger = vectors()["ledgers"][0];
    const auto receipt = protocol::parse_receipt(hex_field(ledger["receipts"][1]["encoded"]));
    REQUIRE(receipt);

    const cbor::Map protected_map = *receipt->envelope.protected_header.as_map();
    auto rebuild = [&](cbor::Map protected_header, Value unprotected, Value payload) {
        return encoded(Value::tagged(
            18, Value::array({Value::bytes(encoded(Value::map(std::move(protected_header)))),
                              std::move(unprotected), std::move(payload),
                              Value::bytes(receipt->envelope.signature)})));
    };
    CHECK(protocol::parse_receipt(
        rebuild(protected_map, receipt->envelope.unprotected_header, Value::null())));
    CHECK(protocol::parse_receipt(rebuild(protected_map, receipt->envelope.unprotected_header,
                                          Value::bytes(Bytes(32, 0))))
              .error()
              .code == Errc::malformed);

    auto unknown_vds = protected_map;
    set_key(unknown_vds, protocol::label_vds, Value::integer(7));
    CHECK(protocol::parse_receipt(
              rebuild(unknown_vds, receipt->envelope.unprotected_header, Value::null()))
              .error()
              .code == Errc::unsupported);

    // Tampering with any path element breaks verification.
    auto tampered = *receipt;
    Bytes node(tampered.proof.path[0].bytes().begin(), tampered.proof.path[0].bytes().end());
    node[0] ^= 1;
    tampered.proof.path[0] = *crypto::Digest::from_bytes(node);
    const Bytes entry = hex(ledger["log_entries"][1].get<std::string>());
    CHECK_FALSE(protocol::verify_receipt(provider(), tampered, entry, key("log").public_key()));
}
