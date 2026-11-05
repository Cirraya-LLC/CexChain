// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstdint>
#include <span>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/crypto.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "support/timestamp_authority.hpp"

namespace crypto = cexchain::crypto;
using cexchain::as_bytes;
using cexchain::Bytes;
using cexchain::Errc;
using cexchain::test::TimestampAuthority;
using crypto::HashAlg;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

Bytes digest(HashAlg alg, std::string_view text) {
    const auto d = provider().digest(alg, as_bytes(text));
    return Bytes(d->bytes().begin(), d->bytes().end());
}

// 2026-10-06T12:34:56.789Z.
constexpr std::uint64_t at = 1'791'290'096'789;

} // namespace

TEST_CASE("a time-stamp token says when, over what, and by whom", "[timestamp]") {
    const TimestampAuthority authority;
    const Bytes imprint = digest(HashAlg::sha256, "a checkpoint");
    const Bytes token = authority.token(HashAlg::sha256, imprint, at, 2);

    auto read = provider().read_timestamp(token, {});
    REQUIRE(read);
    CHECK(read->time == at);
    CHECK(read->accuracy == 2000);
    CHECK(read->imprint_alg == HashAlg::sha256);
    CHECK(read->imprint == imprint);
    CHECK(read->authority == "CN=Test Time-Stamp Authority");
    CHECK(read->authority_key.size() == 32);
    CHECK_FALSE(read->trusted);

    // Trusted only by its own root.
    const Bytes root = authority.root_der();
    auto trusted = provider().read_timestamp(token, std::span(&root, 1));
    REQUIRE(trusted);
    CHECK(trusted->trusted);
    const TimestampAuthority other("Another Authority");
    const Bytes other_root = other.root_der();
    auto foreign = provider().read_timestamp(token, std::span(&other_root, 1));
    REQUIRE(foreign);
    CHECK_FALSE(foreign->trusted);

    // SM3 imprints, for SM3 ledgers.
    const Bytes sm3 = digest(HashAlg::sm3, "a checkpoint");
    auto read_sm3 = provider().read_timestamp(authority.token(HashAlg::sm3, sm3, at), {});
    REQUIRE(read_sm3);
    CHECK(read_sm3->imprint_alg == HashAlg::sm3);
    CHECK(read_sm3->imprint == sm3);
}

TEST_CASE("a token that does not verify is refused", "[timestamp]") {
    const TimestampAuthority authority;
    const Bytes imprint = digest(HashAlg::sha256, "a checkpoint");
    const Bytes token = authority.token(HashAlg::sha256, imprint, at);

    // Its signature changed (the last byte belongs to it).
    Bytes changed = token;
    changed.back() ^= 0x01;
    auto tampered = provider().read_timestamp(changed, {});
    REQUIRE_FALSE(tampered);
    CHECK(tampered.error().code == Errc::verification_failed);

    CHECK(provider().read_timestamp(Bytes{0x30, 0x03, 0x02, 0x01, 0x00}, {}).error().code ==
          Errc::malformed);
    CHECK(provider().read_timestamp(Bytes(crypto::max_timestamp_token_size + 1), {}).error().code ==
          Errc::limit_exceeded);

    // A time its certificate was not valid at: before 2020. (After 2038 a
    // time would not fit OpenSSL's time callback, a long, on Windows.)
    const std::uint64_t in_2019 = 1'559'347'200'000;
    const auto too_early =
        provider().read_timestamp(authority.token(HashAlg::sha256, imprint, in_2019), {});
    REQUIRE_FALSE(too_early);
    CHECK(too_early.error().code == Errc::verification_failed);
}

TEST_CASE("an authority's answer must answer the request", "[timestamp]") {
    const TimestampAuthority authority;
    const Bytes imprint = digest(HashAlg::sha256, "a checkpoint");
    const auto request = crypto::openssl::timestamp_request(HashAlg::sha256, imprint, 7);
    REQUIRE(request);
    const Bytes response = authority.respond(*request, at);
    CHECK(crypto::openssl::timestamp_from_response(response, HashAlg::sha256, imprint, 7));
    CHECK(crypto::openssl::timestamp_from_response(response, HashAlg::sha256, imprint, 8)
              .error()
              .code == Errc::verification_failed);
    CHECK(crypto::openssl::timestamp_from_response(response, HashAlg::sha256,
                                                   digest(HashAlg::sha256, "something else"), 7)
              .error()
              .code == Errc::verification_failed);
    CHECK(crypto::openssl::timestamp_from_response(Bytes{1, 2, 3}, HashAlg::sha256, imprint, 7)
              .error()
              .code == Errc::malformed);
}

TEST_CASE("certificates are read from PEM or DER", "[timestamp]") {
    const TimestampAuthority authority;
    const std::string pem = authority.root_pem();
    auto from_pem = crypto::openssl::read_certificates(as_bytes(pem));
    REQUIRE(from_pem);
    REQUIRE(from_pem->size() == 1);
    CHECK(from_pem->front() == authority.root_der());

    const std::string two = pem + TimestampAuthority("Second").root_pem();
    CHECK(crypto::openssl::read_certificates(as_bytes(two))->size() == 2);
    const Bytes der = authority.root_der();
    CHECK(crypto::openssl::read_certificates(der)->front() == der);
    CHECK(crypto::openssl::read_certificates(as_bytes(std::string("not a certificate")))
              .error()
              .code == Errc::invalid_argument);
}
