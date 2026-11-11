// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// What open-network witnesses send and what verifiers are given (spec
// section 10.2): verifier keys, the signature lines of an add-checkpoint
// answer, a 409 answer's tree size, and base64. Parsing must never crash,
// and whatever parses must print back to the same text.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <string>
#include <string_view>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/protocol/network.hpp>
#include <kanhe/crypto/openssl.hpp>

namespace network = kanhe::protocol::network;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const kanhe::crypto::openssl::Provider provider;
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    if (const auto key = network::parse_verifier_key(provider, text)) {
        require(network::verifier_key_text(*key) == text);
        require(network::valid_name(key->name));
    }
    if (const auto lines = network::parse_signature_lines(text)) {
        std::string again;
        for (const network::NoteSignature& line : *lines) {
            require(network::valid_name(line.name) && line.bytes.size() >= 4);
            again += network::signature_line(line);
        }
        require(again == text);
    }
    if (const auto tree_size = network::parse_tlog_size(text)) {
        require(std::format("{}\n", *tree_size) == text);
    }
    if (const auto bytes = kanhe::from_base64(text)) {
        require(kanhe::to_base64(*bytes) == text);
    }
    return 0;
}
