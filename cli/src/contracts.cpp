// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "contracts.hpp"

#include "bo_support.hpp"

namespace cexchain::cli {

cbor::Value contract_arguments_of(const Args& args) {
    const auto text = args.get("args");
    const auto file = args.get("args-cbor");
    if (text && file) {
        throw UsageError{"give --args or --args-cbor, not both"};
    }
    if (text) {
        return parse_contract_arguments(*text, "--args");
    }
    cbor::Value value;
    if (file) {
        value = unwrap(cbor::decode(read_file(*file)), "--args-cbor " + *file);
    }
    check_contract_arguments(value);
    return value;
}

std::string refusal(const app::Session& session, const CallAttempt& attempt) {
    return app::refusal(session, attempt, *environment_language());
}

Json run_json(const app::Session& session, const CallAttempt& attempt) {
    return app::run_json(session, attempt, *environment_language());
}

GivenConsent give_consent(app::Session& session, const crypto::Signer& signer,
                          protocol::ContractConsent& consent, const ConsentOptions& options,
                          const Args& ledger_args) {
    return app::give_consent(session, signer, consent, options, log_key(ledger_args));
}

} // namespace cexchain::cli
