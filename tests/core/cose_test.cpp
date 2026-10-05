// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstdint>
#include <optional>
#include <string>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators_all.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/cose.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "support/vectors.hpp"

namespace cbor = cexchain::cbor;
namespace cose = cexchain::cose;
namespace crypto = cexchain::crypto;
using cbor::Value;
using cexchain::as_bytes;
using cexchain::Bytes;
using cexchain::ByteView;
using cexchain::Errc;
using cexchain::to_hex;
using cexchain::test::hex;
using cexchain::test::hex_field;
using cexchain::test::load_vectors;
using crypto::SigAlg;
using crypto::openssl::KeyPair;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

const KeyPair& ed25519_key() {
    static const KeyPair key = *KeyPair::from_ed25519_seed(
        hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
    return key;
}

Bytes encoded(const Value& value) {
    auto bytes = cbor::encode(value);
    REQUIRE(bytes);
    return *bytes;
}

/// Builds a tagged COSE_Sign1 from parts, bypassing cose::sign, so tests can
/// construct messages the profile must reject.
Bytes raw_sign1(const Value& protected_header, const Value& unprotected, const Value& payload,
                const Bytes& signature = Bytes(64, 0)) {
    return encoded(Value::tagged(cose::tag_sign1,
                                 Value::array({Value::bytes(encoded(protected_header)), unprotected,
                                               payload, Value::bytes(signature)})));
}

Value alg_header(std::int64_t alg) {
    return Value::map({{Value::integer(cose::label_alg), Value::integer(alg)}});
}

Errc parse_error(const Bytes& message) {
    const auto parsed = cose::parse(message);
    REQUIRE_FALSE(parsed);
    return parsed.error().code;
}

} // namespace

TEST_CASE("COSE_Sign1 vectors from independent implementations", "[core][cose][vectors]") {
    const auto document = load_vectors("cose-sign1.json");
    for (const auto& vector : document["vectors"]) {
        const auto alg = crypto::sig_alg_from_cose(vector["algorithm"].get<std::int64_t>());
        REQUIRE(alg);
        INFO(vector["name"].get<std::string>());
        const Bytes message = hex_field(vector["message"]);
        const Bytes payload = hex_field(vector["payload"]);
        const Bytes aad = hex_field(vector["external_aad"]);
        const bool detached = vector["detached"].get<bool>();
        const crypto::PublicKey key{*alg, hex_field(vector["public_key"])};

        const auto parsed = cose::parse(message);
        REQUIRE(parsed);
        CHECK(parsed->algorithm == *alg);
        REQUIRE(parsed->protected_header.find(cose::label_kid) != nullptr);
        CHECK(*parsed->protected_header.find(cose::label_kid)->as_bytes() ==
              hex_field(vector["kid"]));
        CHECK(parsed->payload.has_value() == !detached);

        const std::optional<ByteView> detached_payload =
            detached ? std::optional<ByteView>(payload) : std::nullopt;
        CHECK(cose::verify(provider(), *parsed, key, aad, detached_payload));

        const Bytes wrong_aad = aad.empty() ? Bytes{0x00} : Bytes{};
        CHECK(cose::verify(provider(), *parsed, key, wrong_aad, detached_payload).error().code ==
              Errc::verification_failed);

        // Deterministic signatures must be reproduced byte for byte.
        if (vector.contains("seed")) {
            const auto signer = KeyPair::from_ed25519_seed(hex_field(vector["seed"]));
            REQUIRE(signer);
            cose::SignOptions options;
            options.protected_header = {
                {Value::integer(cose::label_kid), Value::bytes(hex_field(vector["kid"]))}};
            options.external_aad = aad;
            options.detached = detached;
            const auto produced = cose::sign(*signer, payload, options);
            REQUIRE(produced);
            CHECK(to_hex(*produced) == vector["message"].get<std::string>());
        }
    }
}

TEST_CASE("sign then verify with every algorithm", "[core][cose]") {
    const SigAlg alg = GENERATE(from_range(crypto::all_sig_algs));
    INFO(crypto::name(alg));
    const auto key = KeyPair::generate(alg);
    REQUIRE(key);

    const auto message = cose::sign(*key, as_bytes("payload"));
    REQUIRE(message);
    const auto parsed = cose::parse(*message);
    REQUIRE(parsed);
    CHECK(parsed->algorithm == alg);
    REQUIRE(parsed->payload);
    CHECK(*parsed->payload == Bytes{'p', 'a', 'y', 'l', 'o', 'a', 'd'});
    CHECK(cose::verify(provider(), *parsed, key->public_key()));
}

TEST_CASE("verification binds payload, key, algorithm, and AAD", "[core][cose]") {
    const KeyPair& key = ed25519_key();
    cose::SignOptions options;
    options.external_aad = as_bytes("aad");
    const auto message = cose::sign(key, as_bytes("payload"), options);
    REQUIRE(message);
    const auto parsed = cose::parse(*message);
    REQUIRE(parsed);
    CHECK(cose::verify(provider(), *parsed, key.public_key(), as_bytes("aad")));

    CHECK(cose::verify(provider(), *parsed, key.public_key()).error().code ==
          Errc::verification_failed);

    auto altered = *parsed;
    altered.payload = Bytes{'P', 'a', 'y', 'l', 'o', 'a', 'd'};
    CHECK(cose::verify(provider(), altered, key.public_key(), as_bytes("aad")).error().code ==
          Errc::verification_failed);

    const auto other = KeyPair::generate(SigAlg::ed25519);
    REQUIRE(other);
    CHECK(cose::verify(provider(), *parsed, other->public_key(), as_bytes("aad")).error().code ==
          Errc::verification_failed);

    // A key of a different algorithm is refused before any cryptography runs.
    const auto p256 = KeyPair::generate(SigAlg::esp256);
    REQUIRE(p256);
    CHECK(cose::verify(provider(), *parsed, p256->public_key(), as_bytes("aad")).error().code ==
          Errc::verification_failed);
}

TEST_CASE("detached payloads must be supplied exactly when omitted", "[core][cose]") {
    const KeyPair& key = ed25519_key();
    cose::SignOptions options;
    options.detached = true;
    const auto message = cose::sign(key, as_bytes("document"), options);
    REQUIRE(message);
    const auto parsed = cose::parse(*message);
    REQUIRE(parsed);
    CHECK_FALSE(parsed->payload);
    CHECK(cose::verify(provider(), *parsed, key.public_key(), {}, as_bytes("document")));
    CHECK(cose::verify(provider(), *parsed, key.public_key(), {}, as_bytes("tampered"))
              .error()
              .code == Errc::verification_failed);
    CHECK(cose::verify(provider(), *parsed, key.public_key()).error().code ==
          Errc::invalid_argument);

    const auto attached = cose::parse(*cose::sign(key, as_bytes("document")));
    REQUIRE(attached);
    CHECK(cose::verify(provider(), *attached, key.public_key(), {}, as_bytes("document"))
              .error()
              .code == Errc::invalid_argument);
}

TEST_CASE("parse enforces the message structure", "[core][cose]") {
    const Value alg = alg_header(-19);
    const Value empty = Value::map({});
    const Value payload = Value::bytes(as_bytes("p"));

    CHECK(cose::parse(raw_sign1(alg, empty, payload)));
    CHECK(cose::parse(raw_sign1(alg, empty, Value::null())));

    // Untagged, wrong tag, wrong arity.
    CHECK(parse_error(encoded(Value::array({Value::bytes(encoded(alg)), empty, payload,
                                            Value::bytes(Bytes(64, 0))}))) == Errc::malformed);
    CHECK(parse_error(encoded(Value::tagged(98, Value::array({})))) == Errc::malformed);
    CHECK(parse_error(encoded(Value::tagged(
              cose::tag_sign1, Value::array({Value::bytes(encoded(alg)), empty, payload})))) ==
          Errc::malformed);

    // Wrong element types: the protected header must be a byte string.
    CHECK(parse_error(encoded(Value::tagged(
              cose::tag_sign1, Value::array({alg, empty, payload, Value::bytes(Bytes(64, 0))})))) ==
          Errc::malformed);
    CHECK(parse_error(raw_sign1(alg, Value::array({}), payload)) == Errc::malformed);
    CHECK(parse_error(raw_sign1(alg, empty, Value::text("p"))) == Errc::malformed);
    CHECK(parse_error(raw_sign1(Value::unsigned_integer(1), empty, payload)) == Errc::malformed);

    // Not CBOR at all, and trailing bytes.
    CHECK(parse_error(Bytes{0xff}) == Errc::malformed);
    Bytes trailing = raw_sign1(alg, empty, payload);
    trailing.push_back(0x00);
    CHECK(parse_error(trailing) == Errc::malformed);
}

TEST_CASE("parse enforces the header profile", "[core][cose]") {
    const Value empty = Value::map({});
    const Value payload = Value::bytes(as_bytes("p"));
    const Value kid = Value::bytes(as_bytes("k"));

    // Missing alg, unsupported alg, non-integer alg.
    CHECK(parse_error(raw_sign1(Value::map({}), empty, payload)) == Errc::malformed);
    CHECK(parse_error(raw_sign1(alg_header(-7), empty, payload)) == Errc::unsupported);
    CHECK(
        parse_error(raw_sign1(Value::map({{Value::integer(cose::label_alg), Value::text("EdDSA")}}),
                              empty, payload)) == Errc::unsupported);

    // alg only in the unprotected header.
    CHECK(parse_error(raw_sign1(
              Value::map({}), Value::map({{Value::integer(cose::label_alg), Value::integer(-19)}}),
              payload)) == Errc::malformed);

    // crit anywhere.
    CHECK(parse_error(raw_sign1(
              Value::map({{Value::integer(cose::label_alg), Value::integer(-19)},
                          {Value::integer(cose::label_crit), Value::array({Value::integer(99)})}}),
              empty, payload)) == Errc::unsupported);

    // A parameter in both headers.
    CHECK(parse_error(raw_sign1(Value::map({{Value::integer(cose::label_alg), Value::integer(-19)},
                                            {Value::integer(cose::label_kid), kid}}),
                                Value::map({{Value::integer(cose::label_kid), kid}}), payload)) ==
          Errc::malformed);

    // A protected header whose bytes are not deterministic CBOR: the map
    // {4: h'6b', 1: -19} lists its keys out of order.
    const Bytes message = encoded(
        Value::tagged(cose::tag_sign1, Value::array({Value::bytes(hex("a204416b0132")), empty,
                                                     payload, Value::bytes(Bytes(64, 0))})));
    CHECK(parse_error(message) == Errc::non_canonical);
}

TEST_CASE("sign rejects reserved header parameters", "[core][cose]") {
    const KeyPair& key = ed25519_key();
    cose::SignOptions with_alg;
    with_alg.protected_header = {{Value::integer(cose::label_alg), Value::integer(-19)}};
    CHECK(cose::sign(key, as_bytes("p"), with_alg).error().code == Errc::invalid_argument);

    cose::SignOptions with_crit;
    with_crit.unprotected_header = {{Value::integer(cose::label_crit), Value::array({})}};
    CHECK(cose::sign(key, as_bytes("p"), with_crit).error().code == Errc::unsupported);

    cose::SignOptions duplicated;
    duplicated.protected_header = {{Value::integer(cose::label_kid), Value::bytes(as_bytes("a"))}};
    duplicated.unprotected_header = {
        {Value::integer(cose::label_kid), Value::bytes(as_bytes("b"))}};
    CHECK(cose::sign(key, as_bytes("p"), duplicated).error().code == Errc::invalid_argument);

    cose::SignOptions with_kid;
    with_kid.unprotected_header = {{Value::integer(cose::label_kid), Value::bytes(as_bytes("k"))}};
    const auto message = cose::sign(key, as_bytes("p"), with_kid);
    REQUIRE(message);
    const auto parsed = cose::parse(*message);
    REQUIRE(parsed);
    CHECK(parsed->unprotected_header.find(cose::label_kid) != nullptr);
    CHECK(cose::verify(provider(), *parsed, key.public_key()));
}
