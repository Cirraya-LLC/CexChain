// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/statement.hpp>

/// Self-service forms: what an organization publishes for applicants (those
/// who sign in with its accounts) to fill in. A form names deployed rules
/// and their creating call, the later steps an applicant may take on their
/// own thing, and optionally a document kind filled in with it. What
/// applicants submit is signed by the console's intake actor, a device of
/// the organization whose delegation covers exactly the published forms:
/// the ledger shows a machine acted, never that a person was present.
namespace cexchain::console {

struct SelfServiceForm {
    /// 1 to 32 of a-z, 0-9, and '-': the link is /console/#/apply/NAME.
    std::string name;
    /// What applicants see, 1 to 128 bytes.
    std::string title;
    protocol::Id contract;
    /// The contract's creating call.
    std::string create;
    /// Calls an applicant may make later on their own thing.
    std::vector<std::string> steps;
    /// A document kind (its record type) filled in first, its private fields
    /// sealed as any record's; the creating call then gets the record's id
    /// in `record_field`.
    std::optional<std::string> kind;
    std::optional<std::string> record_field;
    /// The identity providers applicants may sign in with; empty: any the
    /// console trusts.
    std::vector<std::string> providers;
    /// Submissions an applicant may make in an hour, 1 to 1,000.
    std::uint32_t per_hour = 20;
};

/// The form a sheet describes: {"form": 1, "name", "title", "contract"
/// (hex), "create", "steps"?, "kind"?, "record_field"?, "providers"?,
/// "per_hour"?}. Throws std::invalid_argument saying what is wrong.
[[nodiscard]] SelfServiceForm parse_form(const nlohmann::json& sheet);
[[nodiscard]] nlohmann::json form_json(const SelfServiceForm& form);
/// The forms kept in the console's folder (forms.json); none if it keeps
/// none. Throws std::runtime_error if the file is damaged.
[[nodiscard]] std::vector<SelfServiceForm> load_forms(const std::filesystem::path& directory);
void save_forms(const std::filesystem::path& directory, const std::vector<SelfServiceForm>& forms);

/// The intake actor's key, sealed in the console.
inline constexpr std::string_view intake_key_name = "intake";
/// The intake actor's display name on the ledger.
inline constexpr std::string_view intake_name = "Intake";

/// What the intake actor's delegation covers for `forms`: contract calls on
/// their contracts, of their creating calls and steps, and registrations of
/// their kinds; no presence, no delegating further, until `until`.
[[nodiscard]] protocol::Scope intake_scope(const std::vector<SelfServiceForm>& forms,
                                           protocol::Timestamp until);

} // namespace cexchain::console
