// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <cexchain/app/requests.hpp>

#include "contracts.hpp"
#include "output.hpp"
#include "support.hpp"

/// Requests and answers for people, and the keys and validity of the
/// devices that answer them, from options.
namespace cexchain::cli {

/// A request for people, as request_json shows it to programs.
void print_request(const app::Session& session, const protocol::RequestState& request,
                   protocol::Timestamp now);
/// One line for a list.
[[nodiscard]] std::string request_line(const app::Session& session,
                                       const protocol::RequestState& request,
                                       protocol::Timestamp now);
/// A duration for people: "2 d 3 h", "45 min", "12 s".
[[nodiscard]] std::string duration_text(protocol::Timestamp ms);

/// The key of a device being registered (an executor, a keeper): --key (a
/// public key file, a private key file, or a pkcs11: URI), or --key-out FILE
/// (a new key, made with --alg and encrypted with the passphrase; never
/// overwriting a file). `whose` names it in messages ("the executor's").
struct NewActorKey {
    crypto::PublicKey key;
    std::optional<std::string> file;
};
[[nodiscard]] NewActorKey new_actor_key(const Args& args, std::string_view whose);

/// A delegation's end from --days N or --until DATE, if either is given.
[[nodiscard]] std::optional<protocol::Timestamp> validity_end(const Args& args);

} // namespace cexchain::cli
