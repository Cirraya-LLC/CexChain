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

/// Contracts (spec v0.6, section 15): modules deployed on a ledger,
/// their home, that govern instances. A call is registered only if its
/// contract, run on the call's input, accepts it, so every replay runs it
/// again and reaches the same instance state. Since v0.7 an accepted call may
/// also create instances, its children; since v0.8 it may make requests to
/// executors, which they answer with calls of their own. See
/// `contract-input`, `contract-output`, `contract-child`, `contract-request`,
/// and `contract-consent` in spec/cexchain.cddl.
namespace cexchain::protocol {

/// A party's consent to a call, on its own ledger: "given", which may become
/// "withdrawn".
inline constexpr std::string_view contract_consent_type = "cexchain.contract-consent/1";
inline constexpr std::string_view consent_given = "given";
inline constexpr std::string_view consent_withdrawn = "withdrawn";

inline constexpr std::size_t max_contract_parties = 64;
inline constexpr std::size_t max_contract_events = 64;
inline constexpr std::size_t max_contract_status = 64;
/// An accepted call creates at most this many children (v0.7).
inline constexpr std::size_t max_contract_children = 16;
/// An instance a creation makes has depth 0, a child its parent's plus 1, at
/// most this (v0.7): a call that creates children on an instance of this
/// depth is refused.
inline constexpr std::uint32_t max_instance_depth = 8;
/// An accepted call makes at most this many requests (v0.8).
inline constexpr std::size_t max_contract_requests = 16;
/// An instance has at most this many open requests (v0.8): a call whose
/// accept would leave it more is refused.
inline constexpr std::size_t max_open_requests = 64;
/// A request's params, encoded, are at most this many bytes (v0.8).
inline constexpr std::size_t max_request_params = 4096;
/// A request's deadline is after its call's registration time and at most
/// this far after it: 366 days, in milliseconds (v0.8).
inline constexpr Timestamp max_request_deadline = 31'622'400'000;

/// Modules loaded before (say, by earlier verifications of the same
/// ledger's evidence), asked before a contract's code is loaded. A module
/// found must be what `vm::load` gives for exactly that code: a load is a
/// function of the bytes alone, and a module never changes once loaded
/// (`vm::Module::bytes` is the code, to compare byte for byte). One shared
/// by verifications that run at once must be safe to call from their
/// threads.
class ModuleCache {
public:
    virtual ~ModuleCache() = default;
    /// The module `vm::load(code)` gave, if this knows it.
    [[nodiscard]] virtual std::optional<vm::Module> find(ByteView code) = 0;
    /// Told each module loaded (not found).
    virtual void loaded(const vm::Module& module) = 0;

protected:
    ModuleCache() = default;
    ModuleCache(const ModuleCache&) = default;
    ModuleCache(ModuleCache&&) = default;
    ModuleCache& operator=(const ModuleCache&) = default;
    ModuleCache& operator=(ModuleCache&&) = default;
};

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
    /// The log index of its latest call (at first, the call that created it).
    std::uint64_t head = 0;
    /// Kept encoded: inputs splice it, outputs are sliced into it, and a tree
    /// is built only for a reader (`state.value()`).
    cbor::Encoded state;
    std::optional<std::string> status;
    Parties parties;
    bool final = false;
    /// The call that created it and every call on it, in order.
    IndexList history;
    /// The log index of the call that created it: a creation, whose id is
    /// the instance's, or a call that made it a child (v0.7), whose id is
    /// not. Always `history.front()`.
    std::uint64_t created_by = 0;
    /// For a child (v0.7): the instance whose call created it, and its index
    /// among that call's children.
    std::optional<CompactId> parent;
    std::uint32_t position = 0;
    /// 0 without a parent, else the parent's depth plus 1.
    std::uint32_t depth = 0;
    /// Its open requests (v0.8), in the order they were made: at most 64.
    std::vector<CompactId> open_requests;
};

/// A request a call made (v0.8), open until an answer closes it. Requests
/// have no state leaf: replaying the instance's calls derives them.
struct RequestState {
    CompactId id;
    /// The instance it belongs to: the one its call acted on, or created.
    CompactId instance;
    /// The log index of the call that made it, and its index in that call's
    /// accept key 7.
    std::uint64_t call = 0;
    std::uint32_t position = 0;
    std::string kind;
    cbor::Value params;
    Timestamp deadline = 0;
    std::string reply;
    /// Its call's registration time.
    Timestamp asked_at = 0;
    /// Set once answered (closed): the answer's status, log index, and
    /// registration time.
    std::optional<AnswerStatus> status;
    std::optional<std::uint64_t> answered_by;
    Timestamp answered_at = 0;

    [[nodiscard]] bool open() const noexcept { return !status.has_value(); }
    /// How late its answer was: the answer's registration time minus the
    /// deadline, when positive; 0 for an answer on time or an open request.
    [[nodiscard]] Timestamp late_by() const noexcept {
        return status && answered_at > deadline ? answered_at - deadline : 0;
    }
};

struct ContractEvent {
    std::string name;
    cbor::Value data;

    friend bool operator==(const ContractEvent&, const ContractEvent&) = default;
};

/// An instance an accepted call creates (`contract-child`, v0.7).
struct ContractChild {
    cbor::Encoded state;
    /// None when absent.
    std::optional<std::string> status;
    /// None when empty (an encoded child never has an empty map).
    Parties parties;

    friend bool operator==(const ContractChild&, const ContractChild&) = default;
};

/// A request to an executor that an accepted call makes (`contract-request`,
/// v0.8): what to do, with what, by when, and the function its answer calls.
struct ContractRequest {
    /// 1 to 64 bytes: see `is_request_kind`.
    std::string kind;
    /// At most 4,096 bytes encoded.
    cbor::Value params;
    Timestamp deadline = 0;
    /// The reply: a function of kind 2 in the contract's interface (a ledger
    /// rule), 1 to 64 bytes.
    std::string reply;

    friend bool operator==(const ContractRequest&, const ContractRequest&) = default;
};

/// An accepted call's effect on its instance.
struct ContractAccept {
    cbor::Encoded state;
    std::optional<std::string> status;
    /// Replaces the parties when set.
    std::optional<Parties> parties;
    std::vector<ContractEvent> events;
    bool final = false;
    /// New instances of the contract, created after the instance changed
    /// (v0.7): at most 16.
    std::vector<ContractChild> children;
    /// Requests to executors (v0.8), opened after the children are created:
    /// at most 16. They belong to the instance the call acts on or creates.
    std::vector<ContractRequest> requests;

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
/// needing the home's consent. Errc::malformed otherwise. The states (the
/// accept's, its children's) are sliced from the output as they are encoded;
/// trees are built only for the parts kept as trees (events, params).
[[nodiscard]] Result<ContractOutput> decode_contract_output(ByteView output, const Id& home);

/// Encodes an output, as a contract would write it.
[[nodiscard]] Result<Bytes> encode_contract_output(const ContractOutput& output);

/// The id of the child at `position` (from 0) among those the call `call`
/// created: HASH(deterministic-CBOR([call, position])) under the home's
/// hash (`child-id-input`, v0.7). It never equals a statement id, whose
/// preimage is a COSE Sig_structure.
[[nodiscard]] Result<Id> child_instance_id(const crypto::Provider& provider, crypto::HashAlg hash,
                                           const Id& call, std::uint64_t position);

/// The id of the request at `position` (from 0) among those the call `call`
/// made: HASH(deterministic-CBOR(["request", call, position])) under the
/// home's hash (`request-id-input`, v0.8). Its leading text keeps it apart
/// from child ids, and statement ids hash a COSE Sig_structure. It is the
/// request's idempotency key.
[[nodiscard]] Result<Id> request_id(const crypto::Provider& provider, crypto::HashAlg hash,
                                    const Id& call, std::uint64_t position);

/// The request an answer answers, as the input shows it (`request-view`,
/// input key 9, v0.8).
struct ContractRequestView {
    Id id;
    std::string kind;
    cbor::Value params;
    Timestamp deadline = 0;
    /// Its call's registration time.
    Timestamp asked_at = 0;
    /// The answer's status.
    AnswerStatus status = AnswerStatus::done;
};

/// An instance as the input shows it to its contract.
struct ContractInstanceView {
    Id id;
    std::uint64_t head = 0;
    cbor::Encoded state;
    std::optional<std::string> status;
    Parties parties;
    /// For a child only (v0.7): its parent and depth, view key 6.
    std::optional<Id> parent;
    std::uint32_t depth = 0;
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
    /// For an answer only (v0.8): the request it answers, key 9.
    std::optional<ContractRequestView> request;
};

/// Writes the input in deterministic CBOR, the instance's state spliced in as
/// it is encoded.
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
