// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/crypto/pkcs11.hpp>

namespace pkcs11 = cexchain::crypto::pkcs11;
using cexchain::Bytes;

TEST_CASE("PKCS #11 URIs parse as RFC 7512 writes them", "[pkcs11]") {
    const auto uri =
        pkcs11::parse_uri("pkcs11:token=My%20Token;object=alice;id=%00%01;slot-id=3;type=private"
                          "?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-source=file:/run/pin"
                          "&x-sm2-mechanism=0x80000001");
    REQUIRE(uri);
    CHECK(uri->token == "My Token");
    CHECK(uri->object == "alice");
    CHECK(uri->id == Bytes{0, 1}); // an id is binary: a NUL is fine
    CHECK(uri->slot_id == 3);
    CHECK(uri->module_path == "/usr/lib/softhsm/libsofthsm2.so");
    CHECK(uri->pin_source == "/run/pin");
    CHECK(uri->sm2_mechanism == 0x80000001UL);

    // '?' is a plain character in the query: one module-path, read whole.
    const auto odd = pkcs11::parse_uri("pkcs11:object=a?module-path=/a?module-path=/b");
    REQUIRE(odd);
    CHECK(odd->module_path == "/a?module-path=/b");
}

TEST_CASE("PKCS #11 URIs that could read two ways are refused", "[pkcs11]") {
    for (const std::string_view text : {
             "pkcs11:object=a?module-path=/a&module-path=/b", // repeated
             "pkcs11:object=a;object=b?module-path=/a",       // repeated
             "pkcs11:object=a?module-path=lib.so",            // relative
             "pkcs11:object=a?module-path=/a%00.so",          // cut short by a NUL
             "pkcs11:object=a%00b?module-path=/a",            // label with a NUL
             "pkcs11:object=a b?module-path=/a",              // space unencoded
             "pkcs11:object=a?module-path=/a;type=private",   // ';' in the query
             "pkcs11:object=a/b?module-path=/a",              // '/' in the path
             "pkcs11:object=a\n?module-path=/a",              // control character
             "pkcs11:object=a;type=public?module-path=/a",    // not the private key
             "pkcs11:object=a?module-path=/a&pin-value=%2",   // broken escape
             "pkcs11:token=t?module-path=/a",                 // no key named
         }) {
        CAPTURE(text);
        CHECK_FALSE(pkcs11::parse_uri(text));
    }
}
