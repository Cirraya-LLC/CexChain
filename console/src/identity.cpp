// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <cctype>
#include <format>
#include <stdexcept>

#include <cexchain/app/support.hpp>
#include <cexchain/console/identity.hpp>

namespace cexchain::console {

namespace {

constexpr std::string_view providers_file = "identity.json";
constexpr std::size_t max_token = 16 * 1024;
constexpr protocol::Timestamp leeway = 60'000;

std::string lower(std::string_view text) {
    std::string out(text);
    std::ranges::transform(out, out.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::optional<Bytes> b64(const nlohmann::json& value) {
    if (!value.is_string()) {
        return std::nullopt;
    }
    auto bytes = from_base64url(value.get<std::string>());
    return bytes ? std::optional(*bytes) : std::nullopt;
}

std::optional<std::string> text(const nlohmann::json& object, std::string_view key) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_string()) {
        return std::nullopt;
    }
    return it->get<std::string>();
}

/// A NumericDate (seconds) in milliseconds, if it is one.
std::optional<protocol::Timestamp> date(const nlohmann::json& claims, std::string_view key) {
    const auto it = claims.find(key);
    if (it == claims.end() || !it->is_number_integer() || it->get<std::int64_t>() < 0 ||
        it->get<std::int64_t>() > 32'503'680'000) { // year 3000
        return std::nullopt;
    }
    return static_cast<protocol::Timestamp>(it->get<std::int64_t>()) * 1000;
}

std::vector<std::string> strings(const nlohmann::json& value) {
    std::vector<std::string> out;
    if (value.is_string()) {
        out.push_back(value.get<std::string>());
    } else if (value.is_array()) {
        for (const auto& v : value) {
            if (v.is_string() && out.size() < 256) {
                out.push_back(v.get<std::string>());
            }
        }
    }
    return out;
}

} // namespace

std::string_view name(IdentityProvider::Kind kind) noexcept {
    return kind == IdentityProvider::Kind::oidc ? "oidc" : "cas";
}

bool secure_url(std::string_view url) {
    if (url.starts_with("https://")) {
        return url.size() > 8;
    }
    for (const char* loop : {"http://127.0.0.1:", "http://localhost:", "http://[::1]:",
                             "http://127.0.0.1/", "http://localhost/"}) {
        if (url.starts_with(loop)) {
            return true;
        }
    }
    return false;
}

std::optional<std::string> check_provider(const IdentityProvider& p) {
    if (p.name.empty() || p.name.size() > 32 || !std::ranges::all_of(p.name, [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        })) {
        return "a provider's name is 1 to 32 of a-z, 0-9, and -";
    }
    if (p.label.empty() || p.label.size() > 64) {
        return "a provider's label is 1 to 64 bytes";
    }
    if (!secure_url(p.url) || p.url.size() > 2048 ||
        p.url.find_first_of("?#") != std::string::npos) {
        return "a provider's URL is https (http only on this computer), without a query";
    }
    if (p.kind == IdentityProvider::Kind::oidc) {
        if (p.client_id.empty() || p.client_id.size() > 256) {
            return "an OpenID Connect provider needs its client id";
        }
        if (!std::ranges::contains(p.scopes, std::string("openid"))) {
            return "an OpenID Connect provider's scopes include openid";
        }
    }
    for (const std::string& d : p.allow_domains) {
        if (d.empty() || d.size() > 253 || d != lower(d) || d.find('@') != std::string::npos) {
            return "an allowed domain is a lower-case DNS name, such as school.example";
        }
    }
    return std::nullopt;
}

nlohmann::json provider_json(const IdentityProvider& p) {
    nlohmann::json out{{"name", p.name},
                       {"kind", name(p.kind)},
                       {"label", p.label},
                       {"url", p.url},
                       {"allow_domains", p.allow_domains}};
    if (p.kind == IdentityProvider::Kind::oidc) {
        out["client_id"] = p.client_id;
        out["scopes"] = p.scopes;
    }
    out["ca_file"] = p.ca_file ? nlohmann::json(*p.ca_file) : nlohmann::json();
    return out;
}

std::vector<IdentityProvider> load_providers(const std::filesystem::path& directory) {
    const std::filesystem::path file = directory / providers_file;
    if (!std::filesystem::exists(file)) {
        return {};
    }
    const Bytes bytes = app::read_file(file);
    const auto doc = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false);
    if (!doc.is_object() || !doc.contains("providers") || !doc["providers"].is_array()) {
        throw std::runtime_error("the console's identity providers file is damaged");
    }
    std::vector<IdentityProvider> out;
    for (const auto& j : doc["providers"]) {
        if (!j.is_object()) {
            throw std::runtime_error("the console's identity providers file is damaged");
        }
        IdentityProvider p;
        p.name = j.value("name", "");
        p.kind = j.value("kind", "") == "cas" ? IdentityProvider::Kind::cas
                                              : IdentityProvider::Kind::oidc;
        p.label = j.value("label", "");
        p.url = j.value("url", "");
        p.client_id = j.value("client_id", "");
        if (j.contains("scopes")) {
            p.scopes = strings(j["scopes"]);
        }
        p.allow_domains = strings(j.value("allow_domains", nlohmann::json::array()));
        p.ca_file = text(j, "ca_file");
        if (check_provider(p)) {
            throw std::runtime_error("the console's identity providers file is damaged");
        }
        out.push_back(std::move(p));
    }
    return out;
}

void save_providers(const std::filesystem::path& directory,
                    const std::vector<IdentityProvider>& providers) {
    nlohmann::json list = nlohmann::json::array();
    for (const IdentityProvider& p : providers) {
        list.push_back(provider_json(p));
    }
    const std::string text = nlohmann::json{{"providers", list}}.dump(2) + "\n";
    app::write_file(directory / providers_file, as_bytes(text), true);
}

std::string secret_name(std::string_view provider) {
    return "sso-" + std::string(provider);
}

bool allowed(const IdentityProvider& p, const Identity& who) {
    if (p.allow_domains.empty()) {
        return true;
    }
    if (!who.email || !who.email_verified) {
        return false;
    }
    const std::size_t at = who.email->rfind('@');
    if (at == std::string::npos) {
        return false;
    }
    const std::string domain = lower(who.email->substr(at + 1));
    return std::ranges::contains(p.allow_domains, domain);
}

std::string pseudonym(ByteView secret, const Identity& who) {
    const std::string input = who.issuer + "\n" + who.subject;
    const auto mac = crypto::openssl::hmac(crypto::HashAlg::sha256, secret, as_bytes(input));
    if (!mac) {
        throw std::runtime_error("computing a pseudonym failed");
    }
    return "a-" + to_hex(mac->bytes()).substr(0, 24);
}

std::optional<Jwt> decode_jwt(std::string_view token) {
    if (token.size() > max_token) {
        return std::nullopt;
    }
    const std::size_t first = token.find('.');
    const std::size_t second = first == std::string_view::npos ? first : token.find('.', first + 1);
    if (second == std::string_view::npos || token.find('.', second + 1) != std::string_view::npos) {
        return std::nullopt;
    }
    const auto header = from_base64url(token.substr(0, first));
    const auto claims = from_base64url(token.substr(first + 1, second - first - 1));
    const auto signature = from_base64url(token.substr(second + 1));
    if (!header || !claims || !signature) {
        return std::nullopt;
    }
    Jwt out;
    out.header = nlohmann::json::parse(header->begin(), header->end(), nullptr, false);
    out.claims = nlohmann::json::parse(claims->begin(), claims->end(), nullptr, false);
    if (!out.header.is_object() || !out.claims.is_object()) {
        return std::nullopt;
    }
    out.signing_input = std::string(token.substr(0, second));
    out.signature = *signature;
    return out;
}

std::vector<Jwk> parse_jwks(const nlohmann::json& jwks) {
    std::vector<Jwk> out;
    if (!jwks.is_object() || !jwks.contains("keys") || !jwks["keys"].is_array()) {
        return out;
    }
    for (const auto& k : jwks["keys"]) {
        if (out.size() >= 64) {
            break;
        }
        if (!k.is_object() || text(k, "use") == "enc" || k.contains("d")) {
            continue;
        }
        Jwk jwk;
        jwk.kid = text(k, "kid");
        jwk.alg = text(k, "alg");
        const auto kty = text(k, "kty");
        if (kty == "RSA") {
            const auto n = b64(k.value("n", nlohmann::json()));
            const auto e = b64(k.value("e", nlohmann::json()));
            if (!n || !e || n->size() > 1024 || e->size() > 8) {
                continue;
            }
            jwk.key = {crypto::openssl::JoseKey::Type::rsa, *n, *e, {}, {}};
        } else if (kty == "EC" && text(k, "crv") == "P-256") {
            const auto x = b64(k.value("x", nlohmann::json()));
            const auto y = b64(k.value("y", nlohmann::json()));
            if (!x || !y || x->size() != 32 || y->size() != 32) {
                continue;
            }
            jwk.key = {crypto::openssl::JoseKey::Type::p256, {}, {}, *x, *y};
        } else if (kty == "OKP" && text(k, "crv") == "Ed25519") {
            const auto x = b64(k.value("x", nlohmann::json()));
            if (!x || x->size() != 32) {
                continue;
            }
            jwk.key = {crypto::openssl::JoseKey::Type::ed25519, {}, {}, *x, {}};
        } else {
            continue;
        }
        out.push_back(std::move(jwk));
    }
    return out;
}

std::variant<Identity, std::string>
check_id_token(std::string_view token, const std::vector<Jwk>& keys, const IdTokenCheck& check) {
    const auto jwt = decode_jwt(token);
    if (!jwt) {
        return std::string("the ID token is malformed");
    }
    const auto alg = text(jwt->header, "alg");
    if (!alg || (*alg != "RS256" && *alg != "PS256" && *alg != "ES256" && *alg != "EdDSA")) {
        return std::string("the ID token is not signed with RS256, PS256, ES256, or EdDSA");
    }
    if (jwt->header.contains("crit")) {
        return std::string("the ID token names extensions the console does not know");
    }
    const auto kid = text(jwt->header, "kid");
    bool verified = false;
    for (const Jwk& k : keys) {
        if ((kid && k.kid != kid) || (k.alg && *k.alg != *alg)) {
            continue;
        }
        if (crypto::openssl::verify_jose(*alg, k.key, as_bytes(jwt->signing_input),
                                         jwt->signature)) {
            verified = true;
            break;
        }
    }
    if (!verified) {
        return std::string("the ID token's signature does not verify with the provider's keys");
    }
    const nlohmann::json& c = jwt->claims;
    if (text(c, "iss") != check.issuer) {
        return std::string("the ID token is from another issuer");
    }
    const auto aud = strings(c.value("aud", nlohmann::json()));
    if (!std::ranges::contains(aud, check.audience)) {
        return std::string("the ID token is for another client");
    }
    if (aud.size() > 1 && text(c, "azp") != check.audience) {
        return std::string("the ID token names several clients but not this one as its party");
    }
    const auto exp = date(c, "exp");
    const auto iat = date(c, "iat");
    if (!exp || *exp + leeway < check.now) {
        return std::string("the ID token has expired");
    }
    if (!iat || *iat > check.now + leeway) {
        return std::string("the ID token was issued in the future");
    }
    if (text(c, "nonce") != check.nonce) {
        return std::string("the ID token is not the answer to this sign-in");
    }
    const auto sub = text(c, "sub");
    if (!sub || sub->empty() || sub->size() > 255) {
        return std::string("the ID token names no subject");
    }
    Identity who;
    who.issuer = check.issuer;
    who.subject = *sub;
    who.name = text(c, "name");
    who.email = text(c, "email");
    const auto verified_email = c.find("email_verified");
    who.email_verified =
        verified_email != c.end() &&
        ((verified_email->is_boolean() && verified_email->get<bool>()) ||
         (verified_email->is_string() && verified_email->get<std::string>() == "true"));
    if (c.contains("groups")) {
        who.groups = strings(c["groups"]);
    }
    return who;
}

std::variant<Identity, std::string> parse_cas_validation(std::string_view body,
                                                         std::string_view server) {
    if (body.size() > 256 * 1024) {
        return std::string("the CAS answer is too large");
    }
    const auto doc = nlohmann::json::parse(body.begin(), body.end(), nullptr, false);
    if (!doc.is_object() || !doc.contains("serviceResponse") ||
        !doc["serviceResponse"].is_object()) {
        return std::string("the CAS answer is malformed");
    }
    const auto& response = doc["serviceResponse"];
    if (response.contains("authenticationFailure")) {
        return std::string("the CAS server did not validate the ticket");
    }
    const auto success = response.find("authenticationSuccess");
    if (success == response.end() || !success->is_object()) {
        return std::string("the CAS answer is malformed");
    }
    const auto user = text(*success, "user");
    if (!user || user->empty() || user->size() > 255) {
        return std::string("the CAS answer names no user");
    }
    Identity who;
    who.issuer = std::string(server);
    who.subject = *user;
    if (const auto attributes = success->find("attributes");
        attributes != success->end() && attributes->is_object()) {
        auto first =
            [&](std::initializer_list<std::string_view> keys) -> std::optional<std::string> {
            for (const std::string_view key : keys) {
                if (const auto it = attributes->find(key); it != attributes->end()) {
                    const auto values = strings(*it);
                    if (!values.empty()) {
                        return values.front();
                    }
                }
            }
            return std::nullopt;
        };
        who.name = first({"name", "displayName", "cn"});
        who.email = first({"mail", "email"});
        // The CAS server vouches for the attributes it releases.
        who.email_verified = who.email.has_value();
        for (const std::string_view key : {"groups", "memberOf"}) {
            if (const auto it = attributes->find(key); it != attributes->end()) {
                who.groups = strings(*it);
                break;
            }
        }
    }
    return who;
}

std::variant<Discovery, std::string> parse_discovery(const nlohmann::json& doc,
                                                     std::string_view issuer) {
    if (!doc.is_object()) {
        return std::string("the provider's discovery document is malformed");
    }
    if (text(doc, "issuer") != std::string(issuer)) {
        return std::string("the provider's discovery document names another issuer");
    }
    Discovery out;
    for (auto [key, field] :
         {std::pair{"authorization_endpoint", &out.authorization_endpoint},
          std::pair{"token_endpoint", &out.token_endpoint}, std::pair{"jwks_uri", &out.jwks_uri}}) {
        const auto value = text(doc, key);
        if (!value || !secure_url(*value) || value->size() > 2048) {
            return std::format("the provider's {} is missing or not https", key);
        }
        *field = *value;
    }
    return out;
}

} // namespace cexchain::console
