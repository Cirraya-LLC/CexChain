// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/id_map.hpp>
#include <kanhe/node/http.hpp>

/// A public witness (`serve --witness-public`): a witness any ledger may ask,
/// with no token. A ledger registers by sending its genesis entry with a
/// cosign request; the witness follows it only if it cosigns that request,
/// so a registration proves the caller holds the ledger's log key. After
/// that, the ledger asks as any party would (POST /v1/witness/cosign). The
/// witness keeps the usual witness state, about 200 bytes per ledger and no
/// name: never statements, records, or parties. Quotas bound what anyone
/// can make it store and do.
namespace kanhe::client {

/// A registration: {1: genesis entry, 2: cosign request}, CBOR.
struct WitnessRegistration {
    Bytes genesis;
    Bytes cosign_request;
};

[[nodiscard]] Result<Bytes> encode_witness_registration(const WitnessRegistration& registration);
/// At most 4 MiB; Errc::malformed if it is not one.
[[nodiscard]] Result<WitnessRegistration> decode_witness_registration(ByteView encoded);

inline constexpr std::size_t max_witness_registration = std::size_t{4} << 20;

struct PublicWitnessLimits {
    /// Ledgers followed in all.
    std::size_t max_ledgers = 100'000;
    /// New ledgers from one caller address in one (UTC) day.
    std::size_t registrations_per_day = 10;
    /// Between two cosignatures of one ledger.
    protocol::Timestamp cosign_interval = 60'000;
};

class PublicWitness {
public:
    /// `dir` is the witness's state directory (made if missing), shared
    /// with `witness add-log` and a witness of parties.
    PublicWitness(std::filesystem::path dir, std::shared_ptr<const crypto::Signer> key,
                  std::string name, PublicWitnessLimits limits);

    /// Answers GET /v1/witness, POST /v1/witness/register, and POST
    /// /v1/witness/cosign from the caller at `address`; nothing for another
    /// path. Never waits for another caller: a busy witness answers 503.
    [[nodiscard]] std::optional<node::http::Response>
    handle(const node::http::Request& request, std::string_view address, protocol::Timestamp now);

    [[nodiscard]] std::size_t ledgers() const;

private:
    [[nodiscard]] node::http::Response info() const;
    [[nodiscard]] node::http::Response register_ledger(ByteView body, std::string_view address,
                                                       protocol::Timestamp now);
    [[nodiscard]] node::http::Response cosign(ByteView body, protocol::Timestamp now);
    [[nodiscard]] node::http::Response cosign_followed(const protocol::Id& ledger, ByteView request,
                                                       protocol::Timestamp now);

    std::filesystem::path dir_;
    std::shared_ptr<const crypto::Signer> key_;
    std::string name_;
    PublicWitnessLimits limits_;
    mutable std::mutex mutex_;
    std::size_t ledgers_ = 0;
    /// Per caller address: the day (since the epoch) and its registrations.
    std::map<std::string, std::pair<std::uint64_t, std::size_t>, std::less<>> registrations_;
    std::map<protocol::IdKey, protocol::Timestamp> cosigned_;
};

} // namespace kanhe::client
