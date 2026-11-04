// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <string_view>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/node/client.hpp>

/// Asking a time-stamp authority for a token over a checkpoint (spec v0.11).
namespace cexchain::node {

/// Asks the time-stamp authority at `url` (RFC 3161 over HTTP: a POST of
/// application/timestamp-query) for a token over `checkpoint`'s payload under
/// the ledger's hash `hash`, with a random nonce. Returns the token once the
/// answer grants the request and answers it (the same imprint and nonce);
/// whether to trust the authority is for verifiers to decide.
[[nodiscard]] Result<Bytes> request_timestamp(const crypto::Provider& provider,
                                              std::string_view url, crypto::HashAlg hash,
                                              const protocol::SignedCheckpoint& checkpoint,
                                              const ClientOptions& options = {});

} // namespace cexchain::node
