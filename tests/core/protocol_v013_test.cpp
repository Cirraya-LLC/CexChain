// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.13 (open witness networks) against vectors written from c2sp.org's
// texts with Python's `cryptography` (tools/testvectors/generate.py), and
// against signed-note's own example: the checkpoint note and its origin, the
// note key's signed note, verifier keys, and cosignatures of both kinds.

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/network.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "support/vectors.hpp"

namespace protocol = cexchain::protocol;
namespace network = cexchain::protocol::network;
namespace crypto = cexchain::crypto;
using cexchain::as_bytes;
using cexchain::Bytes;
using cexchain::ByteView;
using cexchain::Errc;
using cexchain::to_hex;
using cexchain::test::hex;
using cexchain::test::load_vectors;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

} // namespace

TEST_CASE("v0.13 vectors: checkpoint notes, verifier keys, and cosignatures",
          "[protocol][v0.13][network]") {
    const auto v = load_vectors("protocol-v0.13.json");
    auto checkpoint = protocol::parse_checkpoint(hex(v["checkpoint"].get<std::string>()));
    REQUIRE(checkpoint);
    const auto& at = checkpoint->checkpoint;
    const std::string origin = network::origin(at.ledger_id);
    CHECK(to_hex(at.ledger_id.bytes()) == v["ledger_id"].get<std::string>());
    CHECK(origin == v["origin"].get<std::string>());
    const std::string note = v["note"].get<std::string>();
    CHECK(network::checkpoint_note(origin, at.tree_size, at.root) == note);

    // The note key's log signature: Ed25519, deterministic.
    const auto seed =
        provider().digest(crypto::HashAlg::sha256, as_bytes("CexChain test key: note"));
    auto note_key = crypto::openssl::KeyPair::from_ed25519_seed(seed->bytes());
    REQUIRE(note_key);
    auto note_vkey = network::make_verifier_key(provider(), origin, network::log_ed25519,
                                                note_key->public_key());
    REQUIRE(note_vkey);
    CHECK(network::verifier_key_text(*note_vkey) == v["note_vkey"].get<std::string>());
    auto signed_note = network::sign_note(provider(), *note_key, origin, note);
    REQUIRE(signed_note);
    CHECK(*signed_note == v["signed_note"].get<std::string>());
    CHECK(network::add_checkpoint_body(0, {}, *signed_note) ==
          v["add_checkpoint"].get<std::string>());

    for (const auto& c : v["cases"]) {
        INFO(c["name"].get<std::string>());
        auto key = network::parse_verifier_key(provider(), c["vkey"].get<std::string>());
        REQUIRE(key);
        CHECK(network::verifier_key_text(*key) == c["vkey"].get<std::string>());
        const network::NoteSignature signature{c["cosigner"].get<std::string>(),
                                               hex(c["bytes"].get<std::string>())};
        CHECK(*network::cosignature_time(signature.bytes) == c["time"].get<std::uint64_t>());
        auto verified =
            network::verify_cosignature(provider(), *key, origin, at.tree_size, at.root, signature);
        CHECK(verified.has_value() == c["valid"].get<bool>());
        if (verified) {
            CHECK(*verified == c["time"].get<std::uint64_t>());
        }
        auto lines = network::parse_signature_lines(network::signature_line(signature));
        REQUIRE(lines);
        CHECK(*lines == std::vector{signature});
    }

    // The anchor: the checkpoint and the two valid cosignatures.
    auto anchor = cexchain::cbor::decode(hex(v["anchor"].get<std::string>()));
    REQUIRE(anchor);
    const auto* map = anchor->as_map();
    REQUIRE(map);
    CHECK(map->size() == 2);

    // signed-note's own example: a log signature (type 0x01) by its key.
    const auto& example = v["c2sp_example"];
    auto example_key = network::parse_verifier_key(provider(), example["vkey"].get<std::string>());
    REQUIRE(example_key);
    CHECK(example_key->type == network::log_ed25519);
    auto bytes = cexchain::from_base64(example["signature"].get<std::string>());
    REQUIRE(bytes);
    CHECK(std::ranges::equal(ByteView(*bytes).first(4), example_key->id));
    CHECK(provider().verify(example_key->key, as_bytes(example["note"].get<std::string>()),
                            ByteView(*bytes).subspan(4)));
}

TEST_CASE("verifier keys, names, signature lines, and sizes are read strictly", "[network]") {
    const auto v = load_vectors("protocol-v0.13.json");
    const std::string good = v["cases"][0]["vkey"].get<std::string>();
    REQUIRE(network::parse_verifier_key(provider(), good));
    const auto plus = good.find('+');
    const std::string name = good.substr(0, plus);
    const std::string id = good.substr(plus + 1, 8);
    const std::string key = good.substr(plus + 10);
    auto refused = [](const std::string& text) {
        return !network::parse_verifier_key(provider(), text).has_value();
    };
    CHECK(refused(name + "+00000000+" + key));    // not its key's ID
    CHECK(refused(name + "x+" + id + "+" + key)); // another name, so another ID
    std::string upper = id;
    std::ranges::transform(upper, upper.begin(),
                           [](char c) { return static_cast<char>(std::toupper(c)); });
    if (upper != id) {
        CHECK(refused(name + "+" + upper + "+" + key)); // the ID in lowercase only
    }
    CHECK(refused(name + "+" + id));                                       // no key
    CHECK(refused(name + "+" + id + "+" + key + "+x"));                    // more after the base64
    CHECK(refused(name + "+" + id + "+" + key.substr(0, key.size() - 4))); // too short
    CHECK(refused("+" + id + "+" + key));                                  // no name
    CHECK(refused(name + "+" + id + "+AgAA"));                             // signature type 0x02

    CHECK(network::valid_name("example.com/witness"));
    CHECK_FALSE(network::valid_name(""));
    CHECK_FALSE(network::valid_name("a b"));
    CHECK_FALSE(network::valid_name("a+b"));
    CHECK_FALSE(network::valid_name("a\tb"));
    CHECK_FALSE(network::valid_name("a\xC2\xA0"
                                    "b")); // U+00A0, a space
    CHECK_FALSE(network::valid_name("a\xE3\x80\x80"
                                    "b")); // U+3000, a space
    CHECK_FALSE(network::valid_name(std::string(256, 'a')));
    CHECK(network::valid_name(std::string(255, 'a')));
    CHECK_FALSE(network::valid_name("\xFF"));

    const std::string line = network::signature_line({"w", Bytes(12, 1)});
    CHECK(network::parse_signature_lines(line));
    CHECK_FALSE(network::parse_signature_lines(""));
    CHECK_FALSE(network::parse_signature_lines(line.substr(0, line.size() - 1))); // no newline
    CHECK_FALSE(network::parse_signature_lines("- w AQEBAQEBAQEBAQEB\n"));        // no em dash
    CHECK_FALSE(network::parse_signature_lines("\xE2\x80\x94 w AQEB\n"));         // under 4 bytes
    std::string seventeen;
    for (int i = 0; i < 17; ++i) {
        seventeen += line;
    }
    CHECK(network::parse_signature_lines(seventeen).error().code == Errc::limit_exceeded);
    CHECK(network::cosignature_time(Bytes(11)).error().code == Errc::malformed);

    CHECK(*network::parse_tlog_size("12\n") == 12);
    CHECK(*network::parse_tlog_size("0\n") == 0);
    for (const char* bad : {"012\n", "12", "", "\n", "-1\n", "1 \n", "18446744073709551616\n"}) {
        INFO(bad);
        CHECK_FALSE(network::parse_tlog_size(bad));
    }

    CHECK(*cexchain::from_base64("AA==") == Bytes{0});
    CHECK(cexchain::to_base64(Bytes{0xFB, 0xFF}) == "+/8=");
    for (const char* bad : {"AA=", "AB==", "A-==", "A_==", "=AAA", "AA=A", "A==="}) {
        INFO(bad);
        CHECK_FALSE(cexchain::from_base64(bad));
    }
}

TEST_CASE("the implementation names the specification revision it follows", "[protocol]") {
    // `cexchain version` reports it; it once stayed at v0.5 for eight revisions.
    std::ifstream in(std::filesystem::path(CEXCHAIN_TESTVECTORS_DIR) / ".." / "spec" / "README.md");
    std::string line;
    std::string revision;
    while (std::getline(in, line)) {
        if (line.starts_with("Revision ")) {
            revision = line.substr(9, line.find(' ', 9) - 9);
            break;
        }
    }
    CHECK(revision == protocol::spec_revision);
}
