// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A relay takes messages and signed fetches from anyone, and a node opens
// what comes out of its mailbox: reading a message, a fetch's header, a
// sealed request, or a sealed answer must refuse anything that is not one,
// and never crash. A relay with no witnessed ledger stores nothing.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <unistd.h>

#include <kanhe/client/relay.hpp>
#include <kanhe/client/relay_server.hpp>
#include <kanhe/crypto/openssl.hpp>

namespace {

struct World {
    std::filesystem::path dir =
        std::filesystem::temp_directory_path() / ("kanhe-relay-fuzz-" + std::to_string(::getpid()));
    std::unique_ptr<kanhe::client::Relay> relay;
    kanhe::crypto::openssl::HpkeKey key = *kanhe::crypto::openssl::HpkeKey::generate();

    World() {
        std::filesystem::remove_all(dir);
        relay = std::make_unique<kanhe::client::Relay>(dir / "relay", dir / "witness",
                                                       kanhe::client::RelayLimits{});
    }
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static World world;
    const kanhe::ByteView bytes(data, size);
    if (const auto message = kanhe::client::parse_relay_message(bytes)) {
        static_cast<void>(kanhe::client::open_relay_request(world.key, message->envelope));
        static_cast<void>(kanhe::client::open_relay_answer(
            world.key, message->envelope.to, message->envelope.from, message->envelope.id,
            message->envelope.sealed));
    }
    const std::string text(reinterpret_cast<const char*>(data), size);
    static_cast<void>(kanhe::client::parse_relay_authorization(text));
    static_cast<void>(kanhe::client::parse_relay_authorization("Kanhe-Relay " + text));

    kanhe::node::http::Request request;
    request.method = "POST";
    request.target = request.path = "/v1/relay/messages";
    request.body.assign(bytes.begin(), bytes.end());
    bool answered = false;
    world.relay->handle(request, 1'800'000'000'000, [&](kanhe::node::http::Response r) {
        answered = true;
        if (r.status / 100 == 2) {
            __builtin_trap();
        }
    });
    if (!answered) {
        __builtin_trap();
    }
    return 0;
}
