// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/ledger/environment.hpp>
#include <kanhe/node/http.hpp>
#include <kanhe/verifier/credentials.hpp>

/// Credentials as the ledger shows them (spec/credentials.md): a record
/// endorsed by a credential key in a role `credential/N/I` has a credential
/// with status list entry N/I. Everything here is computed from the ledger's
/// state; the server keeps nothing beside it.
namespace kanhe::node {

/// A record endorsed as a credential.
struct CredentialEntry {
    protocol::Id record;
    protocol::Id actor;
    verifier::StatusEntry entry;
    /// The endorsement's log index.
    std::uint64_t index = 0;
};

/// Every credential entry, in the log order of their endorsements.
[[nodiscard]] std::vector<CredentialEntry> credential_entries(const protocol::LedgerState& state);

/// The entry `actor` gave `record`, if it endorsed it as a credential.
[[nodiscard]] std::optional<CredentialEntry>
credential_entry_of(std::span<const CredentialEntry> entries, const protocol::Id& record,
                    const protocol::Id& actor);

/// An entry no endorsement names: an index drawn at random among the free
/// ones of the newest list that has room (list 1 at first).
[[nodiscard]] verifier::StatusEntry choose_status_entry(std::span<const CredentialEntry> entries,
                                                        ledger::Entropy& entropy);

/// "live", "revoked", or "replaced".
[[nodiscard]] std::string_view record_status(const protocol::RecordState& record);

/// The lists that entries name, ascending.
[[nodiscard]] std::vector<std::uint64_t> status_lists(std::span<const CredentialEntry> entries);

/// List `list`'s bitstring (16,384 bytes): bit I set if a record endorsed
/// as `credential/list/I` is revoked or replaced.
[[nodiscard]] Bytes status_bits(const protocol::LedgerState& state,
                                std::span<const CredentialEntry> entries, std::uint64_t list);

/// Whether `actor` is a credential key: an unrevoked device with an ES256
/// key whose delegations (at least one, unrevoked) cover record endorsements
/// and nothing else.
[[nodiscard]] bool is_credential_key(const protocol::LedgerState& state,
                                     const protocol::ActorState& actor);

/// Every key, current and earlier, of every unrevoked actor that endorsed a
/// record as a credential, and of `also` if given: the DID document's keys.
/// `statement_at` reads the signed statement at a log index.
[[nodiscard]] Result<std::vector<crypto::PublicKey>> credential_keys(
    const protocol::LedgerState& state, std::span<const CredentialEntry> entries,
    std::optional<protocol::Id> also,
    const std::function<Result<protocol::SignedStatement>(std::uint64_t)>& statement_at);

/// A server's credential key and base URL (serve --credential-key,
/// --credential-url; the console's own once an owner turns credentials on).
/// Both are asked at each request: no key (nullptr) while there is none, or
/// while the console that keeps it is locked; no base URL while the server
/// does not know where it is reached.
struct CredentialService {
    std::function<std::shared_ptr<const crypto::Signer>()> key;
    std::function<std::optional<verifier::BaseUrl>()> base;
};

/// Whether `path` is one the service answers: /.well-known/did.json,
/// /did.json, /status/N.
[[nodiscard]] bool credential_path(std::string_view path) noexcept;

/// Answers GET of a credential path from the ledger's state: the DID
/// document, or a status list signed now with the service's key.
/// `statement_at` as for `credential_keys`.
[[nodiscard]] http::Response credential_response(
    const crypto::Provider& provider, const CredentialService& service,
    const protocol::LedgerState& state, std::string_view path, protocol::Timestamp now,
    const std::function<Result<protocol::SignedStatement>(std::uint64_t)>& statement_at);

} // namespace kanhe::node
