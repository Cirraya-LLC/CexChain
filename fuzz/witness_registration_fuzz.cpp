// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A public witness takes registrations and cosign requests from anyone on
// the network: whatever comes, it must answer without crashing, and a
// refused registration must leave nothing behind (the witness follows a
// ledger only once it has cosigned for it). A registration that decodes
// encodes back to the same parts.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <unistd.h>

#include <kanhe/client/public_witness.hpp>
#include <kanhe/crypto/openssl.hpp>

namespace {

std::size_t followed(const std::filesystem::path& dir) {
    std::size_t n = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        n += entry.path().extension() == ".cbor" ? 1 : 0;
    }
    return n;
}

struct World {
    std::filesystem::path dir = std::filesystem::temp_directory_path() /
                                ("kanhe-witness-fuzz-" + std::to_string(::getpid()));
    std::unique_ptr<kanhe::client::PublicWitness> witness;
    kanhe::protocol::Timestamp now = 1'800'000'000'000;

    World() {
        std::filesystem::remove_all(dir);
        auto key = kanhe::crypto::openssl::KeyPair::generate(kanhe::crypto::SigAlg::ed25519);
        if (!key) {
            throw std::runtime_error("no key");
        }
        // No quota that would stop the fuzzer short of the checks.
        kanhe::client::PublicWitnessLimits limits;
        limits.registrations_per_day = SIZE_MAX;
        limits.cosign_interval = 0;
        witness = std::make_unique<kanhe::client::PublicWitness>(
            dir, std::make_shared<kanhe::crypto::openssl::KeyPair>(std::move(*key)), "fuzz",
            limits);
    }
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static World world;
    const kanhe::ByteView bytes(data, size);
    if (const auto decoded = kanhe::client::decode_witness_registration(bytes)) {
        const auto again = kanhe::client::encode_witness_registration(*decoded);
        const auto decoded_again =
            again ? kanhe::client::decode_witness_registration(*again) : decltype(decoded)();
        if (!decoded_again || decoded_again->genesis != decoded->genesis ||
            decoded_again->cosign_request != decoded->cosign_request) {
            __builtin_trap();
        }
    }
    for (const char* path : {"/v1/witness/register", "/v1/witness/cosign"}) {
        kanhe::node::http::Request request;
        request.method = "POST";
        request.target = request.path = path;
        request.body.assign(bytes.begin(), bytes.end());
        const std::size_t before = followed(world.dir);
        const auto answer = world.witness->handle(request, "fuzz", ++world.now);
        if (!answer || (answer->status / 100 != 2 && followed(world.dir) != before)) {
            __builtin_trap();
        }
    }
    return 0;
}
