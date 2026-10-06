// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <optional>
#include <span>
#include <string>
#include <string_view>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/statement.hpp>

/// Proof of human presence: with WebAuthn (passkeys and security keys), or
/// with a hardware key on a token (a USB key or smart card) that signs the
/// challenge after its PIN is entered.
///
/// A person's statement may carry a WebAuthn assertion whose challenge is
///   HASH(ledger)("CexChain presence v1" || kid || payload without its presence proof)
/// so the assertion approves exactly that statement, signed with exactly that
/// key: re-signing the payload with a rotated key does not reuse the proof. Verification follows
/// WebAuthn Level 3: the relying party id hash, the user-present flag, the
/// client data (checked with the limited verification algorithm of section
/// 5.8.1.2), and the signature over authenticatorData || SHA-256(clientDataJSON).
namespace cexchain::protocol {

inline constexpr std::string_view presence_context = "CexChain presence v1";

/// The WebAuthn challenge that a presence proof for `statement`, signed with
/// the key whose id is `kid`, must sign. Any presence proof already in
/// `statement` is ignored.
[[nodiscard]] Result<Bytes> presence_challenge(const crypto::Provider& provider,
                                               crypto::HashAlg ledger_hash,
                                               const Statement& statement, const Id& kid);

/// What a verified presence proof establishes.
struct PresenceCheck {
    /// The authenticator verified the user (PIN or biometric), not merely
    /// that someone was there.
    bool user_verified = false;
    /// The web origin the browser reported, e.g. "https://example.com".
    std::string origin;
    std::string rp_id;
    std::optional<std::string> label;
    PresenceMethod method = PresenceMethod::webauthn;

    friend bool operator==(const PresenceCheck&, const PresenceCheck&) = default;
};

/// Verifies `statement`'s presence proof, for the statement signed with the
/// key whose id is `kid`, against the signer's registered credentials. Fails
/// with Errc::verification_failed if it does not prove presence for this
/// statement and key.
[[nodiscard]] Result<PresenceCheck>
verify_presence(const crypto::Provider& provider, crypto::HashAlg ledger_hash,
                const Statement& statement, const Id& kid,
                std::span<const PresenceCredential> credentials);

/// Turns a WebAuthn registration (the attestation object and client data
/// returned by navigator.credentials.create) into a credential, after
/// checking the client data against `challenge` and `rp_id`. The attestation
/// statement itself is not verified: CexChain asks for "none" attestation,
/// and it is the organization's registration that vouches for the person.
[[nodiscard]] Result<PresenceCredential>
credential_from_registration(const crypto::Provider& provider, ByteView attestation_object,
                             ByteView client_data_json, ByteView challenge, std::string_view rp_id,
                             std::optional<std::string> label);

/// True if a browser at `origin` may use credentials of `rp_id`: the origin's
/// host is the id or a subdomain of it over HTTPS, or the id is "localhost".
[[nodiscard]] bool origin_matches_rp_id(std::string_view origin, std::string_view rp_id);

} // namespace cexchain::protocol
