// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/id_map.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/core/vm.hpp>

/// Contracts (D-053, spec v0.6, section 15): modules deployed on a ledger,
/// their home, that govern instances. A call is registered only if its
/// contract, run on the call's input, accepts it, so every replay runs it
/// again and reaches the same instance state. See `contract-input`,
/// `contract-output`, and `contract-consent` in spec/cexchain.cddl.
namespace cexchain::protocol {

/// A party's consent to a call, on its own ledger: "given", which may become
/// "withdrawn".
inline constexpr std::string_view contract_consent_type = "cexchain.contract-consent/1";

inline constexpr std::size_t max_contract_parties = 64;
inline constexpr std::size_t max_contract_events = 64;
inline constexpr std::size_t max_contract_status = 64;

struct ContractState {
    CompactId id;
    CompactId deployer;
    std::map<std::string, FunctionKind> interface;
    std::string language;
    std::string compiler;
    std::optional<std::string> name;
    /// The module, loaded when the contract was deployed.
    std::optional<vm::Module> module;
    bool retired = false;
    std::uint64_t deployed_at_index = 0;
    std::optional<std::uint64_t> retired_at_index;
};

/// Roles to party ledgers.
using Parties = std::map<std::string, Id>;

struct InstanceState {
    CompactId id;
    CompactId contract;
    /// The log index of its latest call (at first, its creation).
    std::uint64_t head = 0;
    cbor::Value state;
    std::optional<std::string> status;
    Parties parties;
    bool final = false;
    /// Its creation and every call, in order.
    IndexList history;
};

struct ContractEvent {
    std::string name;
    cbor::Value data;

    friend bool operator==(const ContractEvent&, const ContractEvent&) = default;
};

/// An accepted call's effect on its instance.
struct ContractAccept {
    cbor::Value state;
    std::optional<std::string> status;
    /// Replaces the parties when set.
    std::optional<Parties> parties;
    std::vector<ContractEvent> events;
    bool final = false;

    friend bool operator==(const ContractAccept&, const ContractAccept&) = default;
};

/// The ledgers whose consents a call lacks, strictly ascending.
struct ContractNeeds {
    std::vector<Id> ledgers;

    friend bool operator==(const ContractNeeds&, const ContractNeeds&) = default;
};

using ContractOutput = std::variant<ContractAccept, ContractNeeds>;

/// Decodes a contract's output and checks it against section 15: deterministic
/// CBOR within the limits of section 2, matching `contract-output`, and never
/// needing the home's consent. Errc::malformed otherwise.
[[nodiscard]] Result<ContractOutput> decode_contract_output(ByteView output, const Id& home);

/// Encodes an output, as a contract would write it.
[[nodiscard]] Result<Bytes> encode_contract_output(const ContractOutput& output);

/// An instance as the input shows it to its contract.
struct ContractInstanceView {
    Id id;
    std::uint64_t head = 0;
    cbor::Value state;
    std::optional<std::string> status;
    Parties parties;
};

/// What a call's contract reads (`contract-input`).
struct ContractInput {
    std::string function;
    cbor::Value arguments;
    Id home;
    Id contract;
    /// Absent for a creation.
    std::optional<ContractInstanceView> instance;
    Id caller;
    ContractSigner caller_signer;
    /// The call's registration time.
    Timestamp time = 0;
    /// Each cited consent's ledger and signer, in the call's order.
    std::vector<std::pair<Id, ContractSigner>> consents;
};

[[nodiscard]] Result<Bytes> encode_contract_input(const ContractInput& input);

/// One run of a call's contract.
struct ContractRun {
    Bytes input;
    vm::Outcome outcome;
    /// The output, if the run returned and the output is well formed.
    std::optional<ContractOutput> output;
    /// Why it is not, if the run returned but its output is not well formed.
    std::optional<Error> malformed;

    /// The accept, if the contract accepted the call.
    [[nodiscard]] const ContractAccept* accepted() const noexcept {
        return output ? std::get_if<ContractAccept>(&*output) : nullptr;
    }
};

/// The metadata of a `cexchain.contract-consent/1` record.
struct ContractConsent {
    /// The instance's home ledger.
    Id ledger;
    Id instance;
    std::string function;
    /// HASH (the home's) of the encoded arguments.
    Id arguments;
    std::uint64_t head = 0;
    /// The consent lapses then (> 0).
    Timestamp until = 0;
    std::optional<std::string> reference;

    friend bool operator==(const ContractConsent&, const ContractConsent&) = default;
};

[[nodiscard]] Result<cbor::Value> encode_contract_consent(const ContractConsent& consent);
[[nodiscard]] Result<ContractConsent> decode_contract_consent(const cbor::Value& metadata);

/// HASH (the home's) of a call's encoded arguments, as consents name them.
[[nodiscard]] Result<Id> contract_arguments_digest(const crypto::Provider& provider,
                                                   crypto::HashAlg hash,
                                                   const cbor::Value& arguments);

/// True if the consent carries the call's terms: the home, the instance, the
/// function, the arguments' digest, and the head.
[[nodiscard]] bool consent_matches(const ContractConsent& consent, const Id& home,
                                   const ContractCallBody& call, const Id& arguments_digest);

} // namespace cexchain::protocol
