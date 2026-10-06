// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/record.hpp>

#include "support.hpp"

/// Record operations shared by the command line and the MCP server.
namespace cexchain::cli {

struct IssueRequest {
    std::string record_type;
    std::vector<std::pair<std::string, std::string>> fields;
    std::vector<std::pair<std::string, std::string>> metadata;
    std::vector<std::filesystem::path> attachments;
    std::optional<std::string> delegation;
    std::optional<protocol::Provenance> provenance;
};

/// Commits to the fields and attachments, registers the record, and keeps
/// the private data (values and salts) in the ledger directory's vault.
protocol::Id issue_record(Session& session, const crypto::Signer& signer,
                          const IssueRequest& request);

struct VaultAttachment {
    std::string name;
    protocol::Nonce salt{};
};

/// The private data behind a record's commitments.
struct Vault {
    std::vector<protocol::RecordField> fields;
    std::vector<VaultAttachment> attachments;
};

void save_vault(const Session& session, const protocol::Id& record, const Vault& vault);
[[nodiscard]] Vault load_vault(const Session& session, const protocol::Id& record);

[[nodiscard]] std::string display_value(const cbor::Value& value);

/// The human-readable verification report.
[[nodiscard]] std::string format_report(const protocol::EvidenceReport& report,
                                        bool ledger_checked);

} // namespace cexchain::cli
