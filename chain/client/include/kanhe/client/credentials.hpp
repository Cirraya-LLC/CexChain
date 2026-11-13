// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include <kanhe/client/session.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/verifier/credentials.hpp>

/// Issuing a published record's W3C Verifiable Credential
/// (spec/credentials.md, section 6), for the command line and the console.
namespace kanhe::client {

struct CredentialRequest {
    /// The published record's token (record publish, certificate issue).
    std::string token;
    /// The base URL the issuer's server is reached at.
    verifier::BaseUrl base;
    std::optional<std::string> name;
    /// Public metadata entries to claim too.
    std::vector<std::string> metadata;
    /// The credential key's delegation, if not the one chosen.
    std::optional<std::string> delegation;
};

struct IssuedCredential {
    /// The compact JWS.
    std::string credential;
    protocol::Id record;
    verifier::StatusEntry entry;
    /// The endorsement registered now; none if the key had endorsed the
    /// record before (issued again: the same entry).
    std::optional<protocol::Id> endorsement;
    std::size_t claims = 0;
};

/// Issues the credential of the record published under `request.token`,
/// signed by `key`, a credential key of the session's ledger: from the
/// published address's evidence (fetched from the server in client mode;
/// made with `log_key` on a ledger directory, checkpointing first if the
/// latest checkpoint does not cover the record), verified here. Endorses the
/// record as its status entry the first time. Throws ActionError for a key
/// that is not a credential key, an unknown token, a record that cannot be
/// issued, or a field that cannot be a claim (each said in words).
[[nodiscard]] IssuedCredential issue_credential(Session& session, const crypto::Signer& key,
                                                const CredentialRequest& request,
                                                const LogKey& log_key);

} // namespace kanhe::client
