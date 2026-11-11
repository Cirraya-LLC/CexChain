// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <array>
#include <cstdint>
#include <string>

#include <kanhe/crypto/openssl.hpp>
#include <kanhe/node/timestamps.hpp>

namespace kanhe::node {

Result<Bytes> request_timestamp(const crypto::Provider& provider, std::string_view url,
                                crypto::HashAlg hash, const protocol::SignedCheckpoint& checkpoint,
                                const ClientOptions& options) {
    auto authority = Url::parse(url);
    if (!authority) {
        return std::unexpected(authority.error());
    }
    if (!checkpoint.envelope.payload) {
        return fail(Errc::invalid_argument, "the checkpoint has no payload");
    }
    auto imprint = provider.digest(hash, *checkpoint.envelope.payload);
    if (!imprint) {
        return std::unexpected(imprint.error());
    }
    std::array<std::uint8_t, 8> random{};
    if (auto s = crypto::openssl::random_bytes(random); !s) {
        return std::unexpected(s.error());
    }
    std::uint64_t nonce = 0;
    for (const std::uint8_t byte : random) {
        nonce = (nonce << 8U) | byte;
    }
    auto request = crypto::openssl::timestamp_request(hash, imprint->bytes(), nonce);
    if (!request) {
        return std::unexpected(request.error());
    }
    // The authority's URL is the whole address to POST to, not a base for
    // other paths.
    const std::string path = authority->base_path.empty() ? "/" : authority->base_path;
    authority->base_path.clear();
    const Client client(*authority, options);
    auto answer = client.request("POST", path, *request, "application/timestamp-query");
    if (!answer) {
        return std::unexpected(answer.error());
    }
    if (answer->status != 200) {
        return fail(Errc::unavailable, "the time-stamp authority answered with an error");
    }
    return crypto::openssl::timestamp_from_response(answer->body, hash, imprint->bytes(), nonce);
}

} // namespace kanhe::node
