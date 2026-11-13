// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/verifier/report.hpp>

/// Records as W3C Verifiable Credentials (spec/credentials.md): what a
/// credential, a DID document, and a status list hold, the JWS that secures
/// them, and the Kanhe verification of a credential against its record's
/// evidence. Portable C++23, like core: the command line and the browser
/// verifier share it.
namespace kanhe::verifier {

/// A problem with a name or a value in it, for a person to read.
template <class T>
using Explained = std::expected<T, std::string>;

inline constexpr std::size_t status_list_size = 131'072;
inline constexpr std::size_t status_list_bytes = status_list_size / 8;
inline constexpr std::size_t max_subject_members = 64;
inline constexpr std::size_t max_credential_name = 256;
inline constexpr std::string_view credential_role_prefix = "credential/";
inline constexpr std::string_view credentials_context = "https://www.w3.org/ns/credentials/v2";
inline constexpr std::string_view credential_media_type = "application/vc+jwt";

/// A base URL (section 1): https, a host name, an optional port and path;
/// http only for localhost and 127.0.0.1. Its did:web, and where its DID
/// document is.
struct BaseUrl {
    std::string url;
    std::string did;
    std::string did_document_url;

    friend bool operator==(const BaseUrl&, const BaseUrl&) = default;
};
[[nodiscard]] Explained<BaseUrl> parse_base_url(std::string_view url);

/// A credential's status list entry: list N (1 or more) and index I.
struct StatusEntry {
    std::uint64_t list = 0;
    std::uint64_t index = 0;

    friend bool operator==(const StatusEntry&, const StatusEntry&) = default;
};
/// "credential/N/I", the endorsement role that names it (section 2).
[[nodiscard]] std::string credential_role(const StatusEntry& entry);
/// The entry a role names, if it is such a role (decimal, no leading zeros,
/// N at least 1, I below 131072).
[[nodiscard]] std::optional<StatusEntry> parse_credential_role(std::string_view role);

/// An ES256 key as a JWK {"kty","crv","x","y"}; fails for other algorithms.
[[nodiscard]] Result<Json> public_jwk(const crypto::PublicKey& key);
/// The key a JWK holds: an EC P-256 point (other members ignored).
[[nodiscard]] Result<crypto::PublicKey> jwk_key(const Json& jwk);
/// The RFC 7638 thumbprint (SHA-256, unpadded base64url) of an ES256 key.
[[nodiscard]] Result<std::string> jwk_thumbprint(const crypto::Provider& provider,
                                                 const crypto::PublicKey& key);

/// A field's value as a credential claims it: text, an integer of at most
/// 2^53 - 1 in magnitude, or a boolean.
[[nodiscard]] std::optional<Json> claim_value(const cbor::Value& value);
/// Why a name cannot name a claim (`id`, `type`, `@...`, empty), if it cannot.
[[nodiscard]] std::optional<std::string> claim_name_problem(std::string_view name);

/// What a credential says (section 4).
struct CredentialContent {
    BaseUrl base;
    std::string organization;
    std::optional<std::string> name;
    protocol::Timestamp registered_at = 0;
    /// Claims, by name; at most one each.
    std::vector<std::pair<std::string, Json>> subject;
    StatusEntry entry;
    std::string token;
    protocol::Id ledger;
    protocol::Id record;
};

/// A published record's credential content, from its verified evidence:
/// every disclosed field, and the public metadata entries `metadata` names.
/// Refuses a record that is a mechanism type, revoked, or replaced, and a
/// field or entry that cannot be a claim (each named).
[[nodiscard]] Explained<CredentialContent>
credential_content(const protocol::EvidenceReport& report, const BaseUrl& base, std::string token,
                   const StatusEntry& entry, std::span<const std::string> metadata,
                   std::optional<std::string> name);

/// The credential's JSON (section 4).
[[nodiscard]] Json credential_json(const CredentialContent& content);

/// The status list credential's JSON (section 5): `bits` is the bitstring.
[[nodiscard]] Json status_list_json(const BaseUrl& base, std::string_view organization,
                                    std::uint64_t list, ByteView bits, protocol::Timestamp made_at);

/// The DID document (section 3): `keys` (ES256), each once, ordered by
/// thumbprint.
[[nodiscard]] Result<Json> did_document(const crypto::Provider& provider, const BaseUrl& base,
                                        std::span<const crypto::PublicKey> keys,
                                        const protocol::Id& ledger);

/// A compact JWS of `payload` (its JCS), signed with `key` (ES256), with
/// header {"alg":"ES256","cty":"vc","kid":DID#THUMBPRINT,"typ":"vc+jwt"}.
[[nodiscard]] Result<std::string> sign_credential(const crypto::Signer& key,
                                                  const crypto::Provider& provider,
                                                  std::string_view did, const Json& payload);

/// A compact JWS, parsed: header and payload each the JCS of a JSON object.
struct Jws {
    Json header;
    Json payload;
    std::string signing_input;
    Bytes signature;
    std::string kid;
};
[[nodiscard]] Result<Jws> parse_jws(std::string_view compact);
[[nodiscard]] Status verify_jws(const crypto::Provider& provider, const Jws& jws,
                                const crypto::PublicKey& key);

/// A bitstring's `encodedList`: "u" and the unpadded base64url of its GZIP.
[[nodiscard]] std::string encode_status_list(ByteView bits);
/// The bitstring an `encodedList` holds: exactly 16,384 bytes.
[[nodiscard]] Result<Bytes> decode_status_list(std::string_view encoded);
/// Bit `index`: bit 7 - index mod 8 of byte index div 8.
[[nodiscard]] bool status_bit(ByteView bits, std::uint64_t index) noexcept;
void set_status_bit(std::span<std::uint8_t> bits, std::uint64_t index) noexcept;

struct CredentialOptions {
    protocol::VerifyOptions verify;
    /// The issuer's DID document (JSON) and status list credential (JWS),
    /// when the caller has them.
    std::optional<std::string> did_document;
    std::optional<std::string> status_list;
};

/// A credential, checked against its record's evidence (section 7).
struct CredentialReport {
    // What the credential says.
    std::string issuer;
    std::string issuer_name;
    std::optional<std::string> name;
    std::string valid_from;
    Json subject = Json::object();
    StatusEntry entry;
    std::string status_list_url;
    std::string evidence_url;
    std::string kid;
    BaseUrl base;
    // What its evidence shows.
    protocol::EvidenceReport evidence;
    /// "live", "revoked", or "replaced".
    std::string record_status;
    /// The credential key that endorsed the record as this entry and whose
    /// key the JWS verified with: its id, name, revoked since, the
    /// endorsement's log index and registration time.
    std::optional<protocol::Id> key_actor;
    std::string key_actor_name;
    bool key_actor_revoked = false;
    std::uint64_t endorsement_index = 0;
    protocol::Timestamp endorsed_at = 0;
    /// Steps 3 and 4: each a sentence.
    std::vector<std::string> problems;
    /// Step 6, if a DID document was given.
    bool did_document_checked = false;
    std::vector<std::string> did_document_problems;
    /// Step 7, if a status list was given: the bit it holds.
    bool status_list_checked = false;
    std::optional<bool> status_list_bit;
    std::vector<std::string> status_list_problems;

    [[nodiscard]] bool verified() const noexcept {
        return problems.empty() && did_document_problems.empty() && status_list_problems.empty();
    }
};

/// Verifies `credential` (a compact JWS) against `bundle`, the evidence of
/// its record, and the DID document and status list if given. Fails if the
/// credential is not one of this profile, or the evidence does not verify;
/// a mismatch is a problem in the report.
[[nodiscard]] Result<CredentialReport> verify_credential(const crypto::Provider& provider,
                                                         std::string_view credential,
                                                         ByteView bundle,
                                                         const CredentialOptions& options);

/// The evidence address a credential names, and the issuer's DID document
/// and status list addresses, without verifying anything: to fetch them.
struct CredentialAddresses {
    std::string evidence;
    std::string did_document;
    std::string status_list;
    protocol::Id ledger;
};
[[nodiscard]] Result<CredentialAddresses> credential_addresses(std::string_view credential);

[[nodiscard]] Json credential_report_json(const CredentialReport& report, bool ledger_checked);
[[nodiscard]] std::string credential_report_text(const CredentialReport& report,
                                                 bool ledger_checked);

} // namespace kanhe::verifier
