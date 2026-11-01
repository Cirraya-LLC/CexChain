// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/crypto/openssl.hpp>

/// Signing in with an organization's own accounts: its identity provider,
/// by OpenID Connect (authorization code with PKCE; ID tokens checked
/// against the provider's published keys) or by CAS 3.0 (a ticket validated
/// with the CAS server). Those who sign in so are applicants: never enrolled,
/// known to the ledger only by a pseudonym. Nothing here touches the network:
/// the console's routes fetch, these functions read and check.
namespace cexchain::console {

/// An identity provider the console trusts, as `identity.json` keeps it
/// (its client secret sealed apart, `sso-NAME` in the key store).
struct IdentityProvider {
    /// 1 to 32 of a-z, 0-9, and '-'.
    std::string name;
    enum class Kind : std::uint8_t { oidc, cas };
    Kind kind = Kind::oidc;
    /// What the sign-in button says ("School account").
    std::string label;
    /// OIDC: the issuer (its discovery document is at
    /// ISSUER/.well-known/openid-configuration). CAS: the server's base URL
    /// (ISSUER/login, ISSUER/p3/serviceValidate).
    std::string url;
    /// OIDC only.
    std::string client_id;
    std::vector<std::string> scopes{"openid", "profile", "email"};
    /// Email domains whose accounts may sign in (lower case); empty: any
    /// account the provider vouches for.
    std::vector<std::string> allow_domains;
    /// A PEM file of CA certificates to trust for this provider instead of
    /// the system's (a private CA).
    std::optional<std::string> ca_file;
};

[[nodiscard]] std::string_view name(IdentityProvider::Kind kind) noexcept;
/// Why `p` is not one the console takes, or nothing.
[[nodiscard]] std::optional<std::string> check_provider(const IdentityProvider& p);
/// As `identity.json` and `console sso show --json` write it: no secret.
[[nodiscard]] nlohmann::json provider_json(const IdentityProvider& p);
/// The providers kept in the console's folder; none if it keeps none.
/// Throws std::runtime_error if the file is damaged.
[[nodiscard]] std::vector<IdentityProvider> load_providers(const std::filesystem::path& directory);
void save_providers(const std::filesystem::path& directory,
                    const std::vector<IdentityProvider>& providers);
/// The key store's name for a provider's client secret.
[[nodiscard]] std::string secret_name(std::string_view provider);

/// Who an identity provider says signed in.
struct Identity {
    std::string issuer;
    std::string subject;
    std::optional<std::string> name;
    std::optional<std::string> email;
    bool email_verified = false;
    std::vector<std::string> groups;

    friend bool operator==(const Identity&, const Identity&) = default;
};

/// Someone signed in through a provider: what the console keeps of them, in
/// memory, for as long as their session lasts.
struct Applicant {
    std::string provider;
    Identity identity;
    std::string pseudonym;
    /// The self-service form they came for, if any.
    std::string form;
    protocol::Timestamp expires = 0;
};

/// An applicant's session lasts at most this long.
inline constexpr protocol::Timestamp applicant_lifetime = 12 * 60 * 60'000;

/// As the console's routes answer it: provider, pseudonym, name, email,
/// form, expires.
[[nodiscard]] nlohmann::json applicant_json(const Applicant& a);

/// Whether `p` lets `who` in: any account, or a verified email in one of its
/// domains.
[[nodiscard]] bool allowed(const IdentityProvider& p, const Identity& who);

/// `who` as the ledger may see them: "a-" and 24 hex digits of
/// HMAC-SHA256(secret, issuer "\n" subject). The same person, the same
/// pseudonym, as long as the console keeps its secret; nothing about them
/// can be read from it.
[[nodiscard]] std::string pseudonym(ByteView secret, const Identity& who);

/// A JSON Web Token's parts (RFC 7519): its header and claims, the bytes the
/// signature covers, and the signature. Nothing is checked but its shape.
struct Jwt {
    nlohmann::json header;
    nlohmann::json claims;
    std::string signing_input;
    Bytes signature;
};
/// At most 16 KiB; three base64url parts, the first two JSON objects.
[[nodiscard]] std::optional<Jwt> decode_jwt(std::string_view token);

/// A key from a JSON Web Key Set (RFC 7517) that may sign ID tokens.
struct Jwk {
    std::optional<std::string> kid;
    /// The algorithm the set names for it, if any.
    std::optional<std::string> alg;
    crypto::openssl::JoseKey key;
};
/// The usable keys of a set: RSA, P-256, and Ed25519 public keys meant for
/// signatures (any `use` but "enc"); others are left out. At most 64.
[[nodiscard]] std::vector<Jwk> parse_jwks(const nlohmann::json& jwks);

/// What an ID token must say.
struct IdTokenCheck {
    std::string issuer;
    /// The client id.
    std::string audience;
    std::string nonce;
    protocol::Timestamp now = 0;
};

/// The identity an ID token (OIDC Core 3.1.3.7) vouches for: signed by one
/// of `keys` (by its kid, or any if it names none) under RS256, PS256,
/// ES256, or EdDSA (never "none", never a shared-secret MAC), from the
/// issuer, for this audience (and `azp` it if it names several), not
/// expired, not issued in the future, with this nonce. Clocks may differ by
/// a minute. Or why not.
[[nodiscard]] std::variant<Identity, std::string>
check_id_token(std::string_view token, const std::vector<Jwk>& keys, const IdTokenCheck& check);

/// The identity a CAS 3.0 service validation answer (JSON) names, for the
/// server `server`: the user, and the attributes name (displayName, cn),
/// mail (email), and groups (memberOf). Or why not.
[[nodiscard]] std::variant<Identity, std::string> parse_cas_validation(std::string_view body,
                                                                       std::string_view server);

/// The OIDC discovery document's endpoints (OIDC Discovery 3), checked:
/// its issuer must be `issuer`, and every endpoint https (http only on a
/// loopback address, for tests).
struct Discovery {
    std::string authorization_endpoint;
    std::string token_endpoint;
    std::string jwks_uri;
};
[[nodiscard]] std::variant<Discovery, std::string> parse_discovery(const nlohmann::json& doc,
                                                                   std::string_view issuer);

/// Whether `url` is https, or http on a loopback address.
[[nodiscard]] bool secure_url(std::string_view url);

// The network, as the console's routes reach a provider (sso.cpp), for
// `console sso test` too.

/// The provider's discovery document, fetched and checked now.
[[nodiscard]] std::variant<Discovery, std::string> discover(const IdentityProvider& p);
/// Its signing keys, fetched now.
[[nodiscard]] std::variant<std::vector<Jwk>, std::string> fetch_keys(const IdentityProvider& p,
                                                                     const Discovery& d);
/// For CAS: why its login page does not answer, or nothing.
[[nodiscard]] std::optional<std::string> reach_cas(const IdentityProvider& p);

} // namespace cexchain::console
