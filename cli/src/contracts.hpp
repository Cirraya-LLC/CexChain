// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <string>

#include <cexchain/app/contracts.hpp>

#include "output.hpp"
#include "support.hpp"

/// Contract operations from options, with Bo's words in the reader's
/// language ($CEXCHAIN_LANGUAGE).
namespace cexchain::cli {

/// A command's arguments: --args in diagnostic notation, --args-cbor from a
/// file of CBOR, or null.
[[nodiscard]] cbor::Value contract_arguments_of(const Args& args);

/// app::refusal and app::run_json, in the reader's language.
[[nodiscard]] std::string refusal(const app::Session& session, const CallAttempt& attempt);
[[nodiscard]] Json run_json(const app::Session& session, const CallAttempt& attempt);

/// app::give_consent, with the log key from --log-key (or the server's).
[[nodiscard]] GivenConsent give_consent(app::Session& session, const crypto::Signer& signer,
                                        protocol::ContractConsent& consent,
                                        const ConsentOptions& options, const Args& ledger_args);

} // namespace cexchain::cli
