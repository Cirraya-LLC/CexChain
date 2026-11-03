// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <string>
#include <system_error>

#include <nlohmann/json.hpp>

#include <cexchain/client/errors.hpp>
#include <cexchain/client/public_witness.hpp>
#include <cexchain/client/support.hpp>
#include <cexchain/client/witness.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/keys.hpp>
#include <cexchain/core/protocol/witness.hpp>

namespace cexchain::client {

namespace {

using node::http::Response;

Response json_answer(int status, const nlohmann::json& body) {
    Response r;
    r.status = status;
    r.principal = "witness";
    const std::string text = body.dump() + "\n";
    r.body.assign(text.begin(), text.end());
    return r;
}

Response refusal(int status, std::string_view code, std::string_view message) {
    return json_answer(status, {{"error", {{"code", code}, {"message", message}}}});
}

Response too_many(std::string_view message, protocol::Timestamp retry_ms) {
    auto r = refusal(429, "limit_exceeded", message);
    r.headers.emplace_back(
        "Retry-After", std::to_string(std::max<protocol::Timestamp>(1, (retry_ms + 999) / 1000)));
    return r;
}

Response refusal(const Error& error) {
    switch (error.code) {
    case Errc::not_found:
        return refusal(404, "not_found", error.detail);
    case Errc::rejected:
        return refusal(409, "rejected", error.detail);
    case Errc::verification_failed:
        return refusal(422, "verification_failed", error.detail);
    case Errc::unavailable:
        return refusal(503, "unavailable", error.detail);
    default:
        return refusal(400, "malformed", error.detail);
    }
}

/// The ledger a cosign request is for, from its checkpoint.
Result<protocol::Id> ledger_of(ByteView request) {
    auto decoded = protocol::decode_cosign_request(request);
    if (!decoded) {
        return std::unexpected(decoded.error());
    }
    auto checkpoint = protocol::parse_checkpoint(decoded->checkpoint);
    if (!checkpoint) {
        return std::unexpected(checkpoint.error());
    }
    return checkpoint->checkpoint.ledger_id;
}

constexpr protocol::Timestamp day_ms = 24 * 60 * 60'000;

} // namespace

Result<Bytes> encode_witness_registration(const WitnessRegistration& registration) {
    return cbor::encode(cbor::Value::map(
        {{cbor::Value::integer(1), cbor::Value::bytes(registration.genesis)},
         {cbor::Value::integer(2), cbor::Value::bytes(registration.cosign_request)}}));
}

Result<WitnessRegistration> decode_witness_registration(ByteView encoded) {
    if (encoded.size() > max_witness_registration) {
        return fail(Errc::limit_exceeded, "a registration is at most 4 MiB");
    }
    auto value = cbor::decode(encoded);
    if (!value) {
        return std::unexpected(value.error());
    }
    const cbor::Map* map = value->as_map();
    const cbor::Value* genesis = value->find(1);
    const cbor::Value* request = value->find(2);
    if (map == nullptr || map->size() != 2 || genesis == nullptr ||
        genesis->as_bytes() == nullptr || request == nullptr || request->as_bytes() == nullptr) {
        return fail(Errc::malformed, "a registration is {1: genesis entry, 2: cosign request}");
    }
    return WitnessRegistration{Bytes(genesis->as_bytes()->begin(), genesis->as_bytes()->end()),
                               Bytes(request->as_bytes()->begin(), request->as_bytes()->end())};
}

PublicWitness::PublicWitness(std::filesystem::path dir, std::shared_ptr<const crypto::Signer> key,
                             std::string name, PublicWitnessLimits limits)
    : dir_(std::move(dir)), key_(std::move(key)), name_(std::move(name)), limits_(limits) {
    std::filesystem::create_directories(dir_);
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(dir_, ec)) {
        if (entry.path().extension() == ".cbor") {
            ++ledgers_;
        }
    }
}

std::size_t PublicWitness::ledgers() const {
    const std::lock_guard lock(mutex_);
    return ledgers_;
}

std::optional<Response> PublicWitness::handle(const node::http::Request& request,
                                              std::string_view address, protocol::Timestamp now) {
    const bool get = request.method == "GET";
    const bool post = request.method == "POST";
    auto only = [](std::string_view method) {
        auto r = refusal(405, "unsupported", "method not allowed");
        r.headers.emplace_back("Allow", std::string(method));
        return r;
    };
    if (request.path == "/v1/witness") {
        return get ? info() : only("GET");
    }
    if (request.path != "/v1/witness/register" && request.path != "/v1/witness/cosign") {
        return std::nullopt;
    }
    if (!post) {
        return only("POST");
    }
    const bool registering = request.path == "/v1/witness/register";
    // No I/O thread waits for another caller.
    const std::unique_lock lock(mutex_, std::try_to_lock);
    if (!lock) {
        auto busy = refusal(503, "unavailable", "the witness is busy; retry");
        busy.headers.emplace_back("Retry-After", "1");
        return busy;
    }
    return registering ? register_ledger(request.body, address, now) : cosign(request.body, now);
}

Response PublicWitness::info() const {
    const std::lock_guard lock(mutex_);
    const auto key = cbor::encode(protocol::encode_public_key(key_->public_key()));
    return json_answer(200, {{"witness", true},
                             {"name", name_},
                             {"key", key ? to_hex(*key) : std::string()},
                             {"algorithm", crypto::name(key_->public_key().algorithm)},
                             {"ledgers", ledgers_},
                             {"limits",
                              {{"max_ledgers", limits_.max_ledgers},
                               {"registrations_per_day", limits_.registrations_per_day},
                               {"cosign_interval_ms", limits_.cosign_interval}}}});
}

Response PublicWitness::register_ledger(ByteView body, std::string_view address,
                                        protocol::Timestamp now) {
    auto registration = decode_witness_registration(body);
    if (!registration) {
        return refusal(registration.error());
    }
    auto ledger = ledger_of(registration->cosign_request);
    if (!ledger) {
        return refusal(ledger.error());
    }
    const std::filesystem::path path = witness_state_path(dir_, *ledger);
    if (std::filesystem::exists(path)) {
        // Registered before: a cosign request like any other.
        return cosign_followed(*ledger, registration->cosign_request, now);
    }
    if (ledgers_ >= limits_.max_ledgers) {
        return refusal(503, "unavailable", "this witness follows as many ledgers as it takes");
    }
    const std::uint64_t today = now / day_ms;
    for (auto it = registrations_.begin(); it != registrations_.end();) {
        it = it->second.first == today ? std::next(it) : registrations_.erase(it);
    }
    auto& [day, count] = registrations_[std::string(address)];
    day = today;
    if (count >= limits_.registrations_per_day) {
        return too_many("too many registrations from this address today",
                        (today + 1) * day_ms - now);
    }
    // Every attempt counts: a refused one cost the witness its checks too.
    ++count;
    WitnessState state;
    try {
        state = state_from_genesis(registration->genesis, "", *ledger);
        add_witnessed(dir_, state);
    } catch (const ActionError& e) {
        return refusal(400, "malformed", e.message);
    }
    auto cosigned = witness_cosign(dir_, *key_, registration->cosign_request, now);
    if (!cosigned) {
        // Followed only once it has proved its log key.
        std::error_code ec;
        std::filesystem::remove(path, ec);
        return refusal(cosigned.error());
    }
    ++ledgers_;
    cosigned_[protocol::key_of(*ledger)] = now;
    Response r;
    r.principal = "witness";
    r.status = 201;
    r.content_type = "application/cose";
    r.body = std::move(*cosigned);
    return r;
}

Response PublicWitness::cosign(ByteView body, protocol::Timestamp now) {
    auto ledger = ledger_of(body);
    if (!ledger) {
        return refusal(ledger.error());
    }
    if (!std::filesystem::exists(witness_state_path(dir_, *ledger))) {
        return refusal(404, "not_found",
                       "this witness does not follow the ledger: register it first "
                       "(POST /v1/witness/register)");
    }
    return cosign_followed(*ledger, body, now);
}

Response PublicWitness::cosign_followed(const protocol::Id& ledger, ByteView request,
                                        protocol::Timestamp now) {
    const auto key = protocol::key_of(ledger);
    if (const auto it = cosigned_.find(key);
        it != cosigned_.end() && now < it->second + limits_.cosign_interval) {
        return too_many("this ledger was cosigned a moment ago",
                        it->second + limits_.cosign_interval - now);
    }
    auto cosigned = witness_cosign(dir_, *key_, request, now);
    if (!cosigned) {
        return refusal(cosigned.error());
    }
    cosigned_[key] = now;
    Response r;
    r.principal = "witness";
    r.content_type = "application/cose";
    r.body = std::move(*cosigned);
    return r;
}

} // namespace cexchain::client
