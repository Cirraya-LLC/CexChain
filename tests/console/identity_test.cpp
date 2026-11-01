// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Signing in with an organization's account: ID tokens signed with RS256,
// PS256, ES256, and EdDSA verify through OpenSSL and every claim is checked;
// JSON Web Key Sets and CAS answers read; providers kept; pseudonyms stable.

#include <filesystem>
#include <memory>
#include <string>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <cexchain/console/identity.hpp>
#include <cexchain/crypto/openssl.hpp>

namespace console = cexchain::console;
using cexchain::Bytes;
using cexchain::ByteView;

namespace {

struct PkeyFree {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyFree>;

Bytes bn(const EVP_PKEY* key, const char* param, int pad = 0) {
    BIGNUM* value = nullptr;
    REQUIRE(EVP_PKEY_get_bn_param(key, param, &value) == 1);
    Bytes out(static_cast<std::size_t>(pad > 0 ? pad : BN_num_bytes(value)));
    if (pad > 0) {
        BN_bn2binpad(value, out.data(), pad);
    } else {
        BN_bn2bin(value, out.data());
    }
    BN_free(value);
    return out;
}

/// Signs `input` with an OpenSSL key, as a JWS signature of `alg`.
Bytes sign(EVP_PKEY* key, std::string_view alg, std::string_view input) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = nullptr;
    REQUIRE(EVP_DigestSignInit(ctx, &pctx, alg == "EdDSA" ? nullptr : EVP_sha256(), nullptr, key) ==
            1);
    if (alg == "PS256") {
        REQUIRE(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1);
        REQUIRE(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32) == 1);
    }
    std::size_t size = 0;
    const auto* data = reinterpret_cast<const unsigned char*>(input.data());
    REQUIRE(EVP_DigestSign(ctx, nullptr, &size, data, input.size()) == 1);
    Bytes sig(size);
    REQUIRE(EVP_DigestSign(ctx, sig.data(), &size, data, input.size()) == 1);
    sig.resize(size);
    EVP_MD_CTX_free(ctx);
    if (alg == "ES256") {
        const unsigned char* at = sig.data();
        ECDSA_SIG* parsed = d2i_ECDSA_SIG(nullptr, &at, static_cast<long>(sig.size()));
        REQUIRE(parsed != nullptr);
        Bytes raw(64);
        BN_bn2binpad(ECDSA_SIG_get0_r(parsed), raw.data(), 32);
        BN_bn2binpad(ECDSA_SIG_get0_s(parsed), raw.data() + 32, 32);
        ECDSA_SIG_free(parsed);
        return raw;
    }
    return sig;
}

std::string b64(std::string_view text) {
    return cexchain::to_base64url(cexchain::as_bytes(text));
}

/// A provider's key: OpenSSL's, and as its JWKS publishes it.
struct Key {
    Pkey pkey;
    console::Jwk jwk;
};

Key rsa() {
    Key k{Pkey(EVP_RSA_gen(2048)), {}};
    REQUIRE(k.pkey);
    k.jwk.kid = "rsa";
    k.jwk.key = {cexchain::crypto::openssl::JoseKey::Type::rsa,
                 bn(k.pkey.get(), OSSL_PKEY_PARAM_RSA_N),
                 bn(k.pkey.get(), OSSL_PKEY_PARAM_RSA_E),
                 {},
                 {}};
    return k;
}

Key p256() {
    Key k{Pkey(EVP_EC_gen("P-256")), {}};
    REQUIRE(k.pkey);
    k.jwk.kid = "ec";
    k.jwk.key = {cexchain::crypto::openssl::JoseKey::Type::p256,
                 {},
                 {},
                 bn(k.pkey.get(), OSSL_PKEY_PARAM_EC_PUB_X, 32),
                 bn(k.pkey.get(), OSSL_PKEY_PARAM_EC_PUB_Y, 32)};
    return k;
}

Key ed25519() {
    Key k{Pkey(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519")), {}};
    REQUIRE(k.pkey);
    Bytes raw(32);
    std::size_t size = raw.size();
    REQUIRE(EVP_PKEY_get_raw_public_key(k.pkey.get(), raw.data(), &size) == 1);
    k.jwk.kid = "ed";
    k.jwk.key = {cexchain::crypto::openssl::JoseKey::Type::ed25519, {}, {}, raw, {}};
    return k;
}

constexpr cexchain::protocol::Timestamp now = 1'793'491'200'000; // 2026-11-01

nlohmann::json claims() {
    return {{"iss", "https://login.school.example"},
            {"sub", "student-42"},
            {"aud", "console"},
            {"iat", now / 1000},
            {"exp", now / 1000 + 300},
            {"nonce", "n-1"},
            {"name", "Li Ming"},
            {"email", "li@school.example"},
            {"email_verified", true}};
}

std::string token(EVP_PKEY* key, std::string_view alg, const nlohmann::json& c,
                  std::string_view kid) {
    const std::string input =
        b64(nlohmann::json{{"alg", alg}, {"kid", kid}}.dump()) + "." + b64(c.dump());
    return input + "." + cexchain::to_base64url(sign(key, alg, input));
}

const console::IdTokenCheck check{"https://login.school.example", "console", "n-1", now};

std::string problem(const std::variant<console::Identity, std::string>& r) {
    return std::holds_alternative<std::string>(r) ? std::get<std::string>(r) : std::string("ok");
}

} // namespace

TEST_CASE("ID tokens verify with RS256, PS256, ES256, and EdDSA", "[console][identity]") {
    Key r = rsa();
    Key e = p256();
    Key d = ed25519();
    const std::vector<console::Jwk> keys{r.jwk, e.jwk, d.jwk};
    for (const auto& [key, alg, kid] :
         {std::tuple{r.pkey.get(), "RS256", "rsa"}, std::tuple{r.pkey.get(), "PS256", "rsa"},
          std::tuple{e.pkey.get(), "ES256", "ec"}, std::tuple{d.pkey.get(), "EdDSA", "ed"}}) {
        INFO(alg);
        const auto who = console::check_id_token(token(key, alg, claims(), kid), keys, check);
        REQUIRE(std::holds_alternative<console::Identity>(who));
        const auto& id = std::get<console::Identity>(who);
        CHECK(id.subject == "student-42");
        CHECK(id.issuer == "https://login.school.example");
        CHECK(id.email == "li@school.example");
        CHECK(id.email_verified);
        CHECK(id.name == "Li Ming");
    }
    // Without a kid, any key that verifies; a key of another type never.
    const std::string input = b64(R"({"alg":"ES256"})") + "." + b64(claims().dump());
    const std::string no_kid =
        input + "." + cexchain::to_base64url(sign(e.pkey.get(), "ES256", input));
    CHECK(problem(console::check_id_token(no_kid, keys, check)) == "ok");
    CHECK(problem(console::check_id_token(no_kid, {r.jwk, d.jwk}, check)).find("signature") !=
          std::string::npos);
    // A signature by another key of the same kid.
    Key other = rsa();
    CHECK(problem(console::check_id_token(token(other.pkey.get(), "RS256", claims(), "rsa"), keys,
                                          check))
              .find("signature") != std::string::npos);
}

TEST_CASE("an ID token's claims are all checked", "[console][identity]") {
    Key r = rsa();
    const std::vector<console::Jwk> keys{r.jwk};
    auto with = [&](const std::string& key, nlohmann::json value) {
        auto c = claims();
        if (value.is_null()) {
            c.erase(key);
        } else {
            c[key] = std::move(value);
        }
        return problem(
            console::check_id_token(token(r.pkey.get(), "RS256", c, "rsa"), keys, check));
    };
    CHECK(with("name", "Li Ming") == "ok");
    CHECK(with("iss", "https://evil.example").find("issuer") != std::string::npos);
    CHECK(with("aud", "another").find("client") != std::string::npos);
    CHECK(with("aud", nlohmann::json::array({"console", "other"})).find("party") !=
          std::string::npos);
    CHECK(with("exp", now / 1000 - 120).find("expired") != std::string::npos);
    CHECK(with("exp", now / 1000 - 30) == "ok"); // a minute's leeway
    CHECK(with("iat", now / 1000 + 600).find("future") != std::string::npos);
    CHECK(with("nonce", "n-2").find("sign-in") != std::string::npos);
    CHECK(with("sub", nullptr).find("subject") != std::string::npos);
    CHECK(with("exp", "tomorrow").find("expired") != std::string::npos);

    // Algorithms that are not signatures, or none at all, are refused.
    const std::string body = b64(claims().dump());
    for (const char* alg : {"none", "HS256", "RS512"}) {
        INFO(alg);
        const std::string t = b64(nlohmann::json{{"alg", alg}}.dump()) + "." + body + ".";
        CHECK(problem(console::check_id_token(t, keys, check)).find("RS256, PS256") !=
              std::string::npos);
    }
    for (const char* bad : {"", "a.b", "a.b.c.d", "!!.e30.", "e30.e30"}) {
        CHECK(problem(console::check_id_token(bad, keys, check)) == "the ID token is malformed");
    }
    // A key the set limits to another algorithm.
    console::Jwk limited = r.jwk;
    limited.alg = "PS256";
    CHECK(problem(console::check_id_token(token(r.pkey.get(), "RS256", claims(), "rsa"), {limited},
                                          check))
              .find("signature") != std::string::npos);
}

TEST_CASE("key sets, CAS answers, and discovery documents read", "[console][identity]") {
    const auto keys = console::parse_jwks(nlohmann::json::parse(R"({"keys": [
        {"kty": "RSA", "kid": "a", "use": "sig", "n": "sXch", "e": "AQAB"},
        {"kty": "RSA", "kid": "enc", "use": "enc", "n": "sXch", "e": "AQAB"},
        {"kty": "EC", "crv": "P-256", "kid": "b",
         "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
         "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
        {"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"},
        {"kty": "OKP", "crv": "Ed25519", "kid": "c", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
        {"kty": "oct", "k": "c2VjcmV0"},
        {"kty": "RSA", "kid": "private", "n": "sXch", "e": "AQAB", "d": "AQAB"},
        "junk"]})"));
    REQUIRE(keys.size() == 3);
    CHECK(keys[0].kid == "a");
    CHECK(keys[1].key.type == cexchain::crypto::openssl::JoseKey::Type::p256);
    CHECK(keys[2].key.type == cexchain::crypto::openssl::JoseKey::Type::ed25519);
    CHECK(console::parse_jwks(nlohmann::json::parse("{}")).empty());

    const auto cas = console::parse_cas_validation(
        R"({"serviceResponse": {"authenticationSuccess": {"user": "chan",
            "attributes": {"displayName": ["Chan Wing"], "mail": ["chan@school.example"],
                           "memberOf": ["S4A", "students"]}}}})",
        "https://cas.school.example/cas");
    REQUIRE(std::holds_alternative<console::Identity>(cas));
    const auto& c = std::get<console::Identity>(cas);
    CHECK(c.subject == "chan");
    CHECK(c.issuer == "https://cas.school.example/cas");
    CHECK(c.name == "Chan Wing");
    CHECK(c.email == "chan@school.example");
    CHECK(c.groups == std::vector<std::string>{"S4A", "students"});
    CHECK(
        problem(console::parse_cas_validation(
                    R"({"serviceResponse": {"authenticationFailure": {"code": "INVALID_TICKET"}}})",
                    "x"))
            .find("did not validate") != std::string::npos);
    CHECK(problem(console::parse_cas_validation("<xml/>", "x")).find("malformed") !=
          std::string::npos);

    const auto doc = nlohmann::json::parse(R"({"issuer": "https://login.school.example",
        "authorization_endpoint": "https://login.school.example/auth",
        "token_endpoint": "https://login.school.example/token",
        "jwks_uri": "https://login.school.example/keys"})");
    const auto d = console::parse_discovery(doc, "https://login.school.example");
    REQUIRE(std::holds_alternative<console::Discovery>(d));
    CHECK(std::get<console::Discovery>(d).jwks_uri == "https://login.school.example/keys");
    CHECK(std::holds_alternative<std::string>(
        console::parse_discovery(doc, "https://other.example")));
    auto plain = doc;
    plain["token_endpoint"] = "http://login.school.example/token";
    CHECK(std::holds_alternative<std::string>(
        console::parse_discovery(plain, "https://login.school.example")));
    CHECK(console::secure_url("http://127.0.0.1:8080/x"));
    CHECK_FALSE(console::secure_url("http://login.school.example/"));
}

TEST_CASE("providers are kept, domains limit them, and pseudonyms stay", "[console][identity]") {
    const std::filesystem::path dir = std::filesystem::temp_directory_path() /
                                      ("cexchain-identity-test-" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    console::IdentityProvider school;
    school.name = "school";
    school.label = "School account";
    school.url = "https://login.school.example";
    school.client_id = "console";
    school.allow_domains = {"school.example"};
    console::IdentityProvider campus;
    campus.name = "campus";
    campus.kind = console::IdentityProvider::Kind::cas;
    campus.label = "Campus";
    campus.url = "https://cas.school.example/cas";
    CHECK_FALSE(console::check_provider(school));
    CHECK_FALSE(console::check_provider(campus));
    console::save_providers(dir, {school, campus});
    const auto loaded = console::load_providers(dir);
    REQUIRE(loaded.size() == 2);
    CHECK(loaded[0].allow_domains == school.allow_domains);
    CHECK(loaded[1].kind == console::IdentityProvider::Kind::cas);
    std::filesystem::remove_all(dir);

    auto bad = school;
    bad.name = "School";
    CHECK(console::check_provider(bad));
    bad = school;
    bad.url = "http://login.school.example";
    CHECK(console::check_provider(bad));
    bad = school;
    bad.scopes = {"profile"};
    CHECK(console::check_provider(bad));

    console::Identity li{
        "https://login.school.example", "student-42", "Li Ming", "li@SCHOOL.example", true, {}};
    CHECK(console::allowed(school, li));
    li.email_verified = false;
    CHECK_FALSE(console::allowed(school, li));
    li.email_verified = true;
    li.email = "li@elsewhere.example";
    CHECK_FALSE(console::allowed(school, li));
    CHECK(console::allowed(campus, li));

    const Bytes secret(32, 7);
    const std::string p = console::pseudonym(secret, li);
    CHECK(p.size() == 26);
    CHECK(p.starts_with("a-"));
    CHECK(console::pseudonym(secret, li) == p);
    li.subject = "student-43";
    CHECK(console::pseudonym(secret, li) != p);
    CHECK(console::pseudonym(Bytes(32, 8), li) != console::pseudonym(secret, li));
}
