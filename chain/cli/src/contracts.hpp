// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <string>

#include <kanhe/client/contracts.hpp>

#include "output.hpp"
#include "support.hpp"

/// Contract operations from options, with Bo's words in the reader's
/// language ($KANHE_LANGUAGE).
namespace kanhe::cli {

/// A command's arguments: --args in diagnostic notation, --args-cbor from a
/// file of CBOR, or null.
[[nodiscard]] cbor::Value contract_arguments_of(const Args& args);

/// client::give_consent, with the log key from --log-key (or the server's).
[[nodiscard]] GivenConsent give_consent(client::Session& session, const crypto::Signer& signer,
                                        protocol::ContractConsent& consent,
                                        const ConsentOptions& options, const Args& ledger_args);

} // namespace kanhe::cli
