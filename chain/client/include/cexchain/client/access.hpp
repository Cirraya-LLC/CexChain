// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/client/records.hpp>
#include <cexchain/client/support.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/protocol/access.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/ledger.hpp>
#include <cexchain/node/peers.hpp>

/// Access to records across ledgers, as the command line and the console
/// share it: a request's key, kept sealed to the vault key; the requests a
/// peer sent, checked; a grant's delivery, sealed and checked as its
/// recipient will check it; and a delivery opened and checked against the
/// request it answers.
namespace cexchain::client {

/// The HPKE `info` for a request's key, sealed to the vault key for the
/// request's id.
inline constexpr std::string_view access_key_info = "CexChain access key v1";

/// Where a request's key is kept: <ledger>/vault/access/<request>.cbor.
[[nodiscard]] std::filesystem::path request_key_path(const std::filesystem::path& dir,
                                                     const protocol::Id& request);
/// A request's key file: its private key sealed to the vault public key,
/// `{1: encapsulated key, 2: ciphertext}`.
[[nodiscard]] Bytes seal_request_key(ByteView vault_public, const protocol::Id& request,
                                     const crypto::openssl::HpkeKey& key);
/// The request's key from its file, opened with the vault key; throws if it
/// does not open.
[[nodiscard]] crypto::openssl::HpkeKey open_request_key(ByteView file, const protocol::Id& request,
                                                        const crypto::openssl::HpkeKey& vault_key);

/// The peer of the ledger at `dir` whose ledger `bundle` claims to come
/// from; throws if it is malformed or no peer's. Nothing is verified here:
/// callers verify the bundle once, pinned to that peer's ledger.
[[nodiscard]] node::Peer peer_for_bundle(const std::filesystem::path& dir, ByteView bundle);

/// Who took a step, for people: "Ann of Factory (present: passkey)", or the
/// organization alone.
[[nodiscard]] std::string acted_by(const protocol::EvidenceReport& report);

/// A request a peer sent to this ledger, from the inbox.
struct ReceivedRequest {
    std::filesystem::path file;
    Bytes bundle;
    std::optional<node::Peer> peer;
    /// Checked for this ledger at the time asked; unset if it does not check
    /// out, with `problem` saying why.
    std::optional<protocol::Checked<protocol::AccessRequest>> checked;
    std::string problem;
    /// Whether a delivery for it is in the outbox.
    bool granted = false;
};

/// The requests in the inbox of the ledger at `dir` (whose id is `own`),
/// each checked at `now`, by file name.
[[nodiscard]] std::vector<ReceivedRequest> received_requests(const std::filesystem::path& dir,
                                                             const crypto::Provider& provider,
                                                             const protocol::Id& own,
                                                             protocol::Timestamp now);
/// The one with this id; throws if the inbox has none.
[[nodiscard]] ReceivedRequest received_request(const std::filesystem::path& dir,
                                               const crypto::Provider& provider,
                                               const protocol::Id& own, const protocol::Id& request,
                                               protocol::Timestamp now);

/// A grant's delivery from this ledger (`own`): the grant's evidence, and
/// `contents` sealed to the grant's recipient key. Checked first as the
/// recipient will check it (the record's evidence at the grant's
/// checkpoint, exactly the granted fields and files); throws if it does not
/// check out.
[[nodiscard]] Bytes seal_delivery(const crypto::Provider& provider, const protocol::Id& own,
                                  ByteView grant_bundle, const protocol::AccessGrant& grant,
                                  const protocol::DeliveryContents& contents);

/// A delivery a requester opened and checked.
struct OpenedDelivery {
    node::Peer peer;
    protocol::Id request;
    protocol::Checked<protocol::AccessGrant> grant;
    /// The record's evidence, with what was disclosed and the files checked.
    protocol::EvidenceReport record;
    protocol::DeliveryContents contents;
};

/// A delivery that fails a check (the command line's NOT ACCEPTED): what
/// failed, and whether it failed to verify (rather than, say, expired).
struct NotAccepted {
    std::string message;
    bool unverified = true;
};

/// Opens a delivery for one of the requests of `ledger` (at `dir`): its
/// grant from a peer, answering a live request made here, checked against
/// that request; sealed to the request's key (opened with the vault key,
/// asked only then); the record's evidence checked against the grant.
/// Throws ActionError for a delivery that is not for this ledger, and
/// NotAccepted for one that fails a check.
[[nodiscard]] OpenedDelivery open_delivery(const ledger::Ledger& ledger,
                                           const std::filesystem::path& dir,
                                           const crypto::Provider& provider, ByteView delivery,
                                           const VaultKeySource& vault_key,
                                           protocol::Timestamp now);

/// The receipt that acknowledges `delivery` (its SHA-256), for its grant.
[[nodiscard]] protocol::AccessReceipt receipt_for(const crypto::Provider& provider,
                                                  const OpenedDelivery& opened, ByteView delivery);

/// Whether what a peer served is a claim's evidence bundle, the answer to a
/// request for a condition (v0.15), rather than a delivery: a bundle has
/// key 0, a delivery not.
[[nodiscard]] bool is_claim_answer(ByteView answer);

/// A claim a requester checked: the answer to one of its requests for a
/// condition.
struct AnsweredClaim {
    node::Peer peer;
    protocol::Id request;
    protocol::Checked<protocol::Claim> claim;
};

/// Checks a claim's bundle from a peer as the answer to a live request for a
/// condition made on `ledger` (at `dir`), the one its `for` names (spec
/// section 12). Throws ActionError for a claim that answers no request of
/// this ledger's, and NotAccepted for one that fails a check.
[[nodiscard]] AnsweredClaim open_claim_answer(const ledger::Ledger& ledger,
                                              const std::filesystem::path& dir,
                                              const crypto::Provider& provider, ByteView bundle,
                                              protocol::Timestamp now);

/// The receipt that acknowledges the claim's bundle (its SHA-256).
[[nodiscard]] protocol::AccessReceipt receipt_for(const crypto::Provider& provider,
                                                  const AnsweredClaim& answered, ByteView bundle);

/// An attachment's name is a file name, safe to save under: no path.
[[nodiscard]] bool plain_file_name(std::string_view name);

} // namespace cexchain::client
