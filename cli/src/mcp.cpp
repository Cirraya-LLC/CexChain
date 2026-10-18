// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// An MCP server (stdio) through which an AI agent acts on a ledger under its
// own identity. Every write is signed with the agent's key, checked against
// its delegation by the ledger, and recorded with provenance: the agent's
// model, a commitment to the inputs it acted on, and the digest of the tool
// definition it used.
//
// Dual-era per the MCP 2026-07-28 revision: modern clients send per-request
// _meta and may call server/discover; legacy clients (2025-11-25 and
// earlier) open with initialize.

#include <array>
#include <cstdio>
#include <format>
#include <functional>
#include <iostream>
#include <limits>
#include <print>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/record_types.hpp>
#include <cexchain/node/contracts.hpp>
#include <cexchain/node/peers.hpp>

#include "commands.hpp"
#include "contracts.hpp"
#include "output.hpp"
#include "peers.hpp"
#include "records.hpp"
#include "requests.hpp"
#include "support.hpp"

namespace cexchain::cli {

namespace {

using json = nlohmann::json;

constexpr std::string_view modern_version = "2026-07-28";
constexpr std::array<std::string_view, 4> legacy_versions{"2025-11-25", "2025-06-18", "2025-03-26",
                                                          "2024-11-05"};
constexpr std::string_view meta_protocol_version = "io.modelcontextprotocol/protocolVersion";
constexpr std::string_view meta_server_info = "io.modelcontextprotocol/serverInfo";

constexpr int parse_error = -32700;
constexpr int invalid_request = -32600;
constexpr int method_not_found = -32601;
constexpr int invalid_params = -32602;
constexpr int unsupported_protocol_version = -32022;

json server_info() {
    return {{"name", "cexchain"}, {"version", CEXCHAIN_VERSION}};
}

json supported_versions() {
    json versions = json::array({std::string(modern_version)});
    for (const std::string_view v : legacy_versions) {
        versions.push_back(std::string(v));
    }
    return versions;
}

json error_response(const json& id, int code, const std::string& message, json data = nullptr) {
    json error = {{"code", code}, {"message", message}};
    if (!data.is_null()) {
        error["data"] = std::move(data);
    }
    return {{"jsonrpc", "2.0"}, {"id", id}, {"error", std::move(error)}};
}

/// A failure inside a tool, reported to the model as a tool result.
struct ToolError {
    std::string message;
};

std::string text_arg(const json& arguments, const char* name) {
    if (!arguments.contains(name) || !arguments[name].is_string() ||
        arguments[name].get<std::string>().empty()) {
        throw ToolError{std::string("missing string argument '") + name + "'"};
    }
    return arguments[name].get<std::string>();
}

std::optional<std::string> optional_text(const json& arguments, const char* name) {
    if (!arguments.contains(name) || arguments[name].is_null()) {
        return std::nullopt;
    }
    if (!arguments[name].is_string()) {
        throw ToolError{std::string("argument '") + name + "' must be a string"};
    }
    return arguments[name].get<std::string>();
}

/// An optional whole number from `low` to `high`.
std::optional<std::uint64_t> optional_number(const json& arguments, const char* name,
                                             std::uint64_t low, std::uint64_t high) {
    if (!arguments.contains(name) || arguments[name].is_null()) {
        return std::nullopt;
    }
    const json& value = arguments[name];
    if (!value.is_number_unsigned() || value.get<std::uint64_t>() < low ||
        value.get<std::uint64_t>() > high) {
        throw ToolError{
            std::format("argument '{}' must be a whole number from {} to {}", name, low, high)};
    }
    return value.get<std::uint64_t>();
}

bool optional_flag(const json& arguments, const char* name, bool fallback) {
    if (!arguments.contains(name) || arguments[name].is_null()) {
        return fallback;
    }
    if (!arguments[name].is_boolean()) {
        throw ToolError{std::string("argument '") + name + "' must be true or false"};
    }
    return arguments[name].get<bool>();
}

std::vector<std::string> string_list(const json& arguments, const char* name) {
    std::vector<std::string> out;
    if (!arguments.contains(name)) {
        return out;
    }
    if (!arguments[name].is_array()) {
        throw ToolError{std::string("argument '") + name + "' must be an array of strings"};
    }
    for (const json& item : arguments[name]) {
        if (!item.is_string()) {
            throw ToolError{std::string("argument '") + name + "' must be an array of strings"};
        }
        out.push_back(item.get<std::string>());
    }
    return out;
}

/// A contract call's arguments: a string in CBOR diagnostic notation, or any
/// other JSON value as it is (which is diagnostic notation too); null if
/// absent.
cbor::Value contract_arguments(const json& arguments) {
    if (!arguments.contains("arguments")) {
        return {};
    }
    const json& value = arguments["arguments"];
    return parse_contract_arguments(value.is_string() ? value.get<std::string>() : value.dump(),
                                    "arguments");
}

/// The JSON of the command line (ordered keys) as the MCP server's JSON.
json plain(const Json& value) {
    return json::parse(value.dump());
}

std::vector<std::pair<std::string, std::string>> string_map(const json& arguments,
                                                            const char* name) {
    std::vector<std::pair<std::string, std::string>> out;
    if (!arguments.contains(name)) {
        return out;
    }
    if (!arguments[name].is_object()) {
        throw ToolError{std::string("argument '") + name + "' must be an object of strings"};
    }
    for (const auto& [key, value] : arguments[name].items()) {
        if (!value.is_string()) {
            throw ToolError{std::string("values in '") + name + "' must be strings"};
        }
        out.emplace_back(key, value.get<std::string>());
    }
    return out;
}

json scope_json(const protocol::Scope& scope) {
    json types = json::array();
    for (const protocol::StatementType t : scope.statement_types) {
        types.push_back(std::string(protocol::name(t)));
    }
    json out = {{"statement_types", types}, {"may_delegate", scope.may_delegate}};
    if (scope.record_types) {
        out["record_types"] = *scope.record_types;
    }
    if (scope.contracts) {
        json contracts = json::array();
        for (const protocol::Id& id : *scope.contracts) {
            contracts.push_back(to_hex(id.bytes()));
        }
        out["contracts"] = std::move(contracts);
    }
    // Keys 8 and 9 (v0.8): the functions its calls may name, and the kinds
    // of request it may answer (then it only answers).
    if (scope.functions) {
        out["functions"] = *scope.functions;
    }
    if (scope.request_kinds) {
        out["request_kinds"] = *scope.request_kinds;
    }
    if (scope.not_after) {
        out["valid_until"] = format_time(*scope.not_after);
    }
    return out;
}

class Server {
public:
    /// `args` are the command's: the ledger, and the log key (--log-key) that
    /// checkpoints it for the evidence of the agent's contract consents.
    Server(const Args& args, std::unique_ptr<crypto::Signer> key)
        : args_(args), key_(std::move(key)) {
        define_tools();
        Session session(args_);
        if (!session.remote()) {
            ledger_ = session.directory();
        }
        const protocol::ActorState& me = session.actor_for(*key_);
        std::string responsible = "your organization";
        if (me.responsible) {
            responsible = session.state().actor(*me.responsible)->display_name;
        }
        instructions_ =
            "You act on the CexChain ledger of " + session.state().organization() + " as \"" +
            me.display_name + "\" (" + kind_label(me.kind) +
            "). Every action you take is signed with your own key, recorded as performed by "
            "you, and attributed to " +
            responsible +
            ", who is accountable for you. You can only do what your delegations allow "
            "(cexchain_whoami lists them); if the ledger refuses an action, do not try to work "
            "around it, report it. Before acting on a document from someone else, verify its "
            "evidence with cexchain_verify_evidence. When issuing or changing records, pass "
            "'inputs' describing what you based the action on: only its hash is recorded. "
            "Contracts with other organizations: cexchain_list_pending_calls shows the calls a "
            "home holds for your consent; check the instance with cexchain_fetch_instance before "
            "consenting with cexchain_consent_contract_call. Requests: contracts ask for work "
            "outside the ledger (cexchain_list_requests); answer one your delegations let you "
            "with cexchain_answer_request, once the work is done or has failed, and never claim "
            "work you did not do.";
    }

    int run() {
        std::string line;
        while (std::getline(std::cin, line)) {
            if (line.empty()) {
                continue;
            }
            json response = handle_line(line);
            if (!response.is_null()) {
                std::cout << response.dump() << '\n' << std::flush;
            }
        }
        return 0;
    }

private:
    struct Tool {
        std::string name;
        std::string description;
        json input_schema;
        json annotations;
        std::function<json(const json&)> run;
        std::string digest; // hex SHA-256 of the definition, pinned in provenance
    };

    json handle_line(const std::string& line) {
        json request;
        try {
            request = json::parse(line);
        } catch (const json::exception&) {
            return error_response(nullptr, parse_error, "parse error");
        }
        if (!request.is_object() || request.value("jsonrpc", "") != "2.0" ||
            !request.contains("method") || !request["method"].is_string()) {
            return error_response(request.is_object() ? request.value("id", json()) : json(),
                                  invalid_request, "invalid request");
        }
        const bool notification = !request.contains("id");
        const json id = notification ? json() : request["id"];
        const std::string method = request["method"];
        const json params = request.value("params", json::object());

        if (notification) {
            return nullptr; // e.g. notifications/initialized: nothing to do
        }

        // Modern requests declare their protocol version on every request.
        bool modern = false;
        if (params.is_object() && params.contains("_meta") && params["_meta"].is_object() &&
            params["_meta"].contains(meta_protocol_version)) {
            const json& version = params["_meta"][std::string(meta_protocol_version)];
            if (!version.is_string() || version.get<std::string>() != modern_version) {
                return error_response(
                    id, unsupported_protocol_version, "Unsupported protocol version",
                    {{"supported", supported_versions()}, {"requested", version}});
            }
            modern = true;
        }

        try {
            json result;
            if (method == "initialize") {
                std::string version(legacy_versions.front());
                const std::string requested = params.value("protocolVersion", "");
                if (std::ranges::contains(legacy_versions, requested)) {
                    version = requested;
                }
                return {{"jsonrpc", "2.0"},
                        {"id", id},
                        {"result",
                         {{"protocolVersion", version},
                          {"capabilities", {{"tools", json::object()}}},
                          {"serverInfo", server_info()},
                          {"instructions", instructions_}}}};
            }
            if (method == "ping") {
                result = json::object();
            } else if (method == "server/discover") {
                result = {{"supportedVersions", supported_versions()},
                          {"capabilities", {{"tools", json::object()}}},
                          {"instructions", instructions_},
                          {"ttlMs", 300000},
                          {"cacheScope", "private"}};
                modern = true;
            } else if (method == "tools/list") {
                json tools = json::array();
                for (const Tool& tool : tools_) {
                    tools.push_back({{"name", tool.name},
                                     {"description", tool.description},
                                     {"inputSchema", tool.input_schema},
                                     {"annotations", tool.annotations}});
                }
                result = {{"tools", tools}, {"ttlMs", 300000}, {"cacheScope", "private"}};
            } else if (method == "tools/call") {
                if (!params.contains("name") || !params["name"].is_string()) {
                    return error_response(id, invalid_params, "tools/call needs a tool name");
                }
                const std::string name = params["name"];
                const auto tool = std::ranges::find(tools_, name, &Tool::name);
                if (tool == tools_.end()) {
                    return error_response(id, invalid_params, "unknown tool " + name);
                }
                const json arguments = params.value("arguments", json::object());
                result = call(*tool, arguments.is_object() ? arguments : json::object());
            } else {
                return error_response(id, method_not_found, "method not found: " + method);
            }
            if (modern) {
                result["resultType"] = "complete";
                result["_meta"] = {{std::string(meta_server_info), server_info()}};
            }
            return {{"jsonrpc", "2.0"}, {"id", id}, {"result", result}};
        } catch (const std::exception& e) {
            return error_response(id, invalid_params, e.what());
        }
    }

    json call(const Tool& tool, const json& arguments) {
        try {
            json structured = tool.run(arguments);
            const std::string text = structured.contains("report")
                                         ? structured["report"].get<std::string>()
                                         : structured.dump(2);
            return {{"content", json::array({{{"type", "text"}, {"text", text}}})},
                    {"structuredContent", structured},
                    {"isError", false}};
        } catch (const ToolError& e) {
            return tool_error(e.message);
        } catch (const UsageError& e) {
            return tool_error(e.message);
        } catch (const CommandError& e) {
            return tool_error(e.message);
        }
    }

    static json tool_error(const std::string& message) {
        return {{"content", json::array({{{"type", "text"}, {"text", message}}})},
                {"isError", true}};
    }

    /// Provenance for a write made through `tool`.
    protocol::Provenance provenance(const Tool& tool, const json& arguments, Session& session) {
        protocol::Provenance p;
        if (const auto inputs = optional_text(arguments, "inputs")) {
            const auto digest =
                unwrap(session.provider().digest(session.state().hash(), as_bytes(*inputs)),
                       "hashing the inputs");
            p.input_commitment = Bytes(digest.bytes().begin(), digest.bytes().end());
        }
        p.tools.push_back({"mcp:" + tool.name, unwrap(from_hex(tool.digest), "tool digest")});
        return p;
    }

    /// Proposals carry no signature: they go out under the organization's
    /// peer token, so only an agent that may consent to contract calls makes
    /// them.
    void require_consent_delegation(const Session& session) const {
        const protocol::ActorState& me = session.actor_for(*key_);
        if (!node::choose_delegation(
                session.state(), me.id, protocol::StatementType::record_register,
                std::string(protocol::contract_consent_type), ledger::SystemClock{}.now())) {
            throw ToolError{"no valid delegation lets you consent to contract calls "
                            "(cexchain.contract-consent/1 records), so you may not propose them "
                            "for your organization either"};
        }
    }

    void add(std::string name, std::string description, json properties, json required,
             json annotations, std::function<json(const Tool&, const json&)> run) {
        Tool tool;
        tool.name = std::move(name);
        tool.description = std::move(description);
        tool.input_schema = {{"type", "object"},
                             {"properties", std::move(properties)},
                             {"required", std::move(required)},
                             {"additionalProperties", false}};
        tool.annotations = std::move(annotations);
        const json definition = {{"name", tool.name},
                                 {"description", tool.description},
                                 {"inputSchema", tool.input_schema}};
        const crypto::openssl::Provider provider;
        tool.digest =
            to_hex(unwrap(provider.digest(crypto::HashAlg::sha256, as_bytes(definition.dump())),
                          "tool digest")
                       .bytes());
        const std::size_t index = tools_.size();
        tool.run = [this, index, run = std::move(run)](const json& arguments) {
            return run(tools_[index], arguments);
        };
        tools_.push_back(std::move(tool));
    }

    void define_tools() {
        const json read_only = {{"readOnlyHint", true}, {"openWorldHint", false}};
        const json writes = {{"readOnlyHint", false},
                             {"destructiveHint", false},
                             {"idempotentHint", false},
                             {"openWorldHint", false}};
        const json inputs_property = {
            {"type", "string"},
            {"description", "What you based this action on (only its hash is recorded)."}};

        add("cexchain_whoami",
            "Your identity on the ledger: name, kind, accountable person, and the delegations "
            "that define what you may do.",
            json::object(), json::array(), read_only, [this](const Tool&, const json&) {
                Session session(args_);
                const protocol::ActorState& me = session.actor_for(*key_);
                json delegations = json::array();
                for (const auto& [k, d] : session.state().delegations()) {
                    if (d.grantee == me.id && !d.revoked) {
                        json item = scope_json(d.scope);
                        item["id"] = hex_id(d.id);
                        item["granted_by"] = session.state().actor(d.grantor)->display_name;
                        delegations.push_back(item);
                    }
                }
                json out = {{"actor_id", hex_id(me.id)},
                            {"name", me.display_name},
                            {"kind", kind_label(me.kind)},
                            {"organization", session.state().organization()},
                            {"delegations", delegations}};
                if (me.responsible) {
                    out["responsible"] = session.state().actor(*me.responsible)->display_name;
                }
                if (me.agent && me.agent->model) {
                    out["model"] = *me.agent->model;
                }
                return out;
            });

        add("cexchain_ledger_status",
            "The ledger's identity, size, and latest checkpoint, and its peers: other "
            "organizations' ledgers, by the names the contract tools take as 'home'.",
            json::object(), json::array(), read_only, [this](const Tool&, const json&) {
                Session session(args_);
                json out = {{"ledger_id", hex_id(session.state().ledger_id())},
                            {"organization", session.state().organization()},
                            {"hash", std::string(crypto::name(session.state().hash()))},
                            {"entries", session.ledger().size()},
                            {"records", session.state().records().size()}};
                if (const auto& c = session.ledger().latest_checkpoint()) {
                    out["checkpoint"] = {{"tree_size", c->checkpoint.tree_size},
                                         {"time", format_time(c->checkpoint.timestamp)}};
                }
                json peers = json::array();
                for (const node::Peer& p :
                     unwrap(node::load_peers(session.directory()), "reading the peers")) {
                    peers.push_back({{"name", p.name},
                                     {"ledger_id", hex_id(p.ledger_id)},
                                     {"online", p.url.has_value()}});
                }
                out["peers"] = std::move(peers);
                return out;
            });

        add("cexchain_record_types",
            "Record types. A record is a document of any kind, and its type is a name the "
            "registrant chooses (e.g. example.org.photo/1), with the generic lifecycle "
            "(registered, no transitions, endorsed in any role, revocable). Lists the "
            "protocol's own types (access requests, grants, and receipts; contract consents) "
            "with what each is for, its initial state, transitions, and endorsement roles; "
            "other names beginning with \"cexchain.\" are reserved.",
            json::object(), json::array(), read_only, [](const Tool&, const json&) {
                json types = json::array();
                for (const protocol::RecordType& t : protocol::builtin_record_types()) {
                    json transitions = json::array();
                    for (const protocol::Transition& tr : t.transitions) {
                        transitions.push_back({{"from", tr.from}, {"to", tr.to}});
                    }
                    json roles = json::array();
                    for (const std::string_view role : t.roles) {
                        roles.push_back(role);
                    }
                    types.push_back({{"type", t.name},
                                     {"purpose", record_type_purpose(t.name)},
                                     {"initial_state", t.initial_state},
                                     {"transitions", transitions},
                                     {"roles", roles}});
                }
                return json{{"record_types", types}};
            });

        add("cexchain_get_record",
            "A record's type, state, endorsements, and next possible states.",
            {{"record",
              {{"type", "string"}, {"description", "Record id or unique prefix (8+ hex)."}}}},
            json::array({"record"}), read_only, [this](const Tool&, const json& arguments) {
                Session session(args_);
                const protocol::Id id = session.record_id(text_arg(arguments, "record"));
                const protocol::RecordState& r = *session.state().record(id);
                json endorsements = json::array();
                for (const protocol::Endorsement& e : r.endorsements) {
                    endorsements.push_back(
                        {{"role", e.role}, {"by", session.state().actor(e.actor)->display_name}});
                }
                json next = json::array();
                if (const protocol::RecordType* t = protocol::find_record_type(r.record_type)) {
                    for (const protocol::Transition& tr : t->transitions) {
                        if (tr.from == r.state) {
                            next.push_back(tr.to);
                        }
                    }
                }
                return json{{"record_id", hex_id(id)},
                            {"record_type", r.record_type},
                            {"state", r.state},
                            {"revoked", r.revoked},
                            {"registered_by", session.state().actor(r.registrant)->display_name},
                            {"endorsements", endorsements},
                            {"next_states", next}};
            });

        add("cexchain_issue_record",
            "Issue a record: a document of any kind, of a type your organization names (a "
            "report, a photo, a statement). Field values stay private until disclosed; only "
            "commitments are recorded.",
            {{"record_type",
              {{"type", "string"},
               {"description",
                "A type name of your own, e.g. example.org.photo/1 (names beginning with "
                "\"cexchain.\" are the protocol's)."}}},
             {"fields",
              {{"type", "object"},
               {"additionalProperties", {{"type", "string"}}},
               {"description", "Field name to value."}}},
             {"metadata",
              {{"type", "object"},
               {"additionalProperties", {{"type", "string"}}},
               {"description", "Public metadata, recorded in the clear."}}},
             {"attachments",
              {{"type", "array"}, {"items", {{"type", "string"}}}, {"description", "File paths."}}},
             {"inputs", inputs_property}},
            json::array({"record_type", "fields"}), writes,
            [this](const Tool& tool, const json& arguments) {
                Session session(args_);
                IssueRequest request;
                request.record_type = text_arg(arguments, "record_type");
                request.fields = string_map(arguments, "fields");
                request.metadata = string_map(arguments, "metadata");
                if (arguments.contains("attachments")) {
                    for (const json& path : arguments["attachments"]) {
                        if (!path.is_string()) {
                            throw ToolError{"attachments must be file paths"};
                        }
                        request.attachments.emplace_back(path.get<std::string>());
                    }
                }
                request.provenance = provenance(tool, arguments, session);
                const protocol::Id id = issue_record(session, *key_, request);
                return json{{"record_id", hex_id(id)},
                            {"state", session.state().record(id)->state}};
            });

        add("cexchain_endorse_record",
            "Endorse a record in a role (any role name, e.g. author, reviewer, approver).",
            {{"record", {{"type", "string"}}},
             {"role", {{"type", "string"}}},
             {"inputs", inputs_property}},
            json::array({"record", "role"}), writes,
            [this](const Tool& tool, const json& arguments) {
                Session session(args_);
                const protocol::RecordEndorseBody body{
                    session.record_id(text_arg(arguments, "record")), text_arg(arguments, "role")};
                const protocol::Id id =
                    session.submit(*key_, body, std::nullopt, provenance(tool, arguments, session));
                return json{{"statement_id", hex_id(id)},
                            {"record_id", hex_id(body.record)},
                            {"role", body.role}};
            });

        add("cexchain_transition_record", "Move a record to its next state.",
            {{"record", {{"type", "string"}}},
             {"to_state", {{"type", "string"}}},
             {"inputs", inputs_property}},
            json::array({"record", "to_state"}), writes,
            [this](const Tool& tool, const json& arguments) {
                Session session(args_);
                const protocol::Id record = session.record_id(text_arg(arguments, "record"));
                const std::string from = session.state().record(record)->state;
                const protocol::RecordTransitionBody body{record, from,
                                                          text_arg(arguments, "to_state")};
                session.submit(*key_, body, std::nullopt, provenance(tool, arguments, session));
                return json{{"record_id", hex_id(record)}, {"from", from}, {"to", body.to_state}};
            });

        add("cexchain_list_contracts",
            "This ledger's contracts: their functions (create makes an instance, call acts on "
            "one), language, whether retired, and how many instances each governs.",
            json::object(), json::array(), read_only, [this](const Tool&, const json&) {
                Session session(args_);
                json contracts = json::array();
                for (const auto& [key, contract] : session.state().contracts()) {
                    contracts.push_back(json::parse(contract_json(session, contract).dump()));
                }
                return json{{"contracts", contracts}};
            });

        add("cexchain_get_instance",
            "A contract instance (one thing the contract's rules govern): its status, parties, "
            "state, head (which calls and consents must name), whether final, and every call "
            "with its arguments and consents. A call may create parts of an instance (such as "
            "one thing divided among several holders): a part shows its parent, depth, "
            "position, and "
            "ancestors, and an instance lists the parts its calls created (children). A part is "
            "called, proposed on, and verified like any instance. It also lists the requests "
            "its calls made (work outside the ledger), open or answered, and each call shows the "
            "requests it made and the request it answers.",
            {{"instance",
              {{"type", "string"}, {"description", "Instance id or unique prefix (8+ hex)."}}}},
            json::array({"instance"}), read_only, [this](const Tool&, const json& arguments) {
                Session session(args_);
                const protocol::Id id = session.instance_id(text_arg(arguments, "instance"));
                return json::parse(instance_json(session, *session.state().instance(id)).dump());
            });

        add("cexchain_verify_contract_evidence",
            "Verify a contract instance's evidence offline (every call, run again, and every "
            "party's consent on its own ledger) before relying on the instance.",
            {{"evidence_path", {{"type", "string"}}},
             {"expected_ledger_id",
              {{"type", "string"},
               {"description", "The instance's home ledger id, learned out of band."}}}},
            json::array({"evidence_path"}), read_only, [](const Tool&, const json& arguments) {
                const crypto::openssl::Provider provider;
                protocol::VerifyOptions options;
                if (const auto ledger_id = optional_text(arguments, "expected_ledger_id")) {
                    options.expected_ledger = unwrap(
                        protocol::to_id(unwrap(from_hex(*ledger_id), "ledger id")), "ledger id");
                }
                const auto report = protocol::verify_contract_evidence(
                    provider, read_file(text_arg(arguments, "evidence_path")), options);
                if (!report) {
                    return json{{"verified", false}, {"error", report.error().detail}};
                }
                const bool checked = options.expected_ledger.has_value();
                json out = json::parse(verifier::contract_report_json(*report, checked).dump());
                out["evidence"] = std::move(out["report"]);
                out["report"] = verifier::contract_report_text(*report, checked);
                return out;
            });

        // Contracts with other organizations (D-053). Their homes' servers
        // are reached as peers of this ledger.
        const json remote_read = {{"readOnlyHint", true}, {"openWorldHint", true}};
        const json remote_writes = {{"readOnlyHint", false},
                                    {"destructiveHint", false},
                                    {"idempotentHint", false},
                                    {"openWorldHint", true}};
        const json home_property = {{"type", "string"},
                                    {"description",
                                     "The instance's home: a peer of this ledger, by name "
                                     "(cexchain_ledger_status lists them)."}};
        const json arguments_property = {
            {"description",
             "The call's arguments in CBOR diagnostic notation (RFC 8949, section 8): JSON "
             "without floating point, plus byte strings h'00ff', keys of any type, tags, and "
             "embedded CBOR <<...>>. A string is read as diagnostic notation, any other JSON "
             "value as it is. Default: null."}};
        const json reference_property = {
            {"type", "string"},
            {"description", "A reference of your organization's, such as a file or approval "
                            "number; recorded in the clear."}};

        add("cexchain_call_contract",
            "Act on a contract whose home is your organization's ledger: create an instance (give "
            "'contract' and a function that creates) or call a function on one (give "
            "'instance'). Signed with your key under your delegation, which may cover only some "
            "contracts. The contract runs here first, exactly as the ledger will run it, and the "
            "call is recorded only if the contract accepts it; otherwise the result says what it "
            "decided: the parties whose consents it still needs, or its reason for refusing "
            "(or the ledger's, for parts it may not create). A call that creates parts lists "
            "them in 'children'. 'dry_run' shows the decision and records nothing.",
            {{"contract",
              {{"type", "string"},
               {"description", "To create an instance: the contract's id or a unique prefix."}}},
             {"instance",
              {{"type", "string"},
               {"description", "To call one: the instance's id or a unique prefix."}}},
             {"function", {{"type", "string"}, {"description", "The contract's function."}}},
             {"arguments", arguments_property},
             {"reference", reference_property},
             {"consents",
              {{"type", "array"},
               {"items", {{"type", "string"}}},
               {"description", "Files holding the evidence of the parties' consents to this "
                               "call, one per party."}}},
             {"dry_run",
              {{"type", "boolean"},
               {"description", "Only show what the contract would decide (default: false)."}}},
             {"inputs", inputs_property}},
            json::array({"function"}), writes, [this](const Tool& tool, const json& arguments) {
                Session session(args_);
                const auto contract = optional_text(arguments, "contract");
                const auto instance = optional_text(arguments, "instance");
                if (contract.has_value() == instance.has_value()) {
                    throw ToolError{"give 'contract' (to create an instance) or 'instance' (to "
                                    "call one)"};
                }
                const std::string function = text_arg(arguments, "function");
                protocol::ContractCallBody body = contract
                                                      ? creation_call(session, *contract, function)
                                                      : instance_call(session, *instance, function);
                body.arguments = contract_arguments(arguments);
                body.reference = optional_text(arguments, "reference");
                const std::vector<std::string> paths = string_list(arguments, "consents");
                if (contract && !paths.empty()) {
                    throw ToolError{"a creation takes no consents"};
                }
                const std::vector<Bytes> bundles = cite_consents(session, body, paths);
                CallOptions options;
                options.provenance = provenance(tool, arguments, session);
                options.dry_run = optional_flag(arguments, "dry_run", false);
                const CallAttempt attempt =
                    attempt_call(session, *key_, std::move(body), bundles, options);
                json out = plain(run_json(session, attempt));
                out["function"] = function;
                out["dry_run"] = options.dry_run;
                out["recorded"] = attempt.recorded.has_value();
                if (attempt.recorded) {
                    const auto& call =
                        std::get<protocol::ContractCallBody>(attempt.statement.statement.body);
                    const protocol::Id id = call.instance ? *call.instance : *attempt.recorded;
                    out["statement_id"] = hex_id(*attempt.recorded);
                    out["instance"] = plain(instance_json(session, *session.state().instance(id)));
                    json children = json::array();
                    for (const protocol::Id& child : created_children(session, *attempt.recorded)) {
                        children.push_back(hex_id(child));
                    }
                    out["children"] = std::move(children);
                } else if (!options.dry_run && out["verdict"] == "needs") {
                    out["advice"] = "Each party named consents on its own ledger. Cite their "
                                    "consents' evidence files in 'consents', or have the call "
                                    "proposed to this ledger's registrar, which collects them.";
                }
                return out;
            });

        add("cexchain_list_pending_calls",
            "Calls an instance's home holds until the parties consent (its registrar), as far as "
            "they concern your ledger: the instance and its head, the function, the arguments, "
            "which ledgers the contract still waits for, and when each call lapses. Review a "
            "call's terms here before consenting to it.",
            {{"home", home_property},
             {"call",
              {{"type", "string"},
               {"description", "Only this call: its full id (64 hex digits)."}}}},
            json::array({"home"}), remote_read, [this](const Tool&, const json& arguments) {
                const Session session(args_);
                const node::Peer home = peer_named(peers_dir(), text_arg(arguments, "home"));
                std::optional<std::string> call;
                if (const auto text = optional_text(arguments, "call")) {
                    call = hex_id(full_id(*text, "call"));
                }
                json calls = json::array();
                for (const Json& held : pending_at(home, call)) {
                    json item = plain(held);
                    item["waiting_for"] =
                        ledgers_text(session, held.value("missing", Json::array()));
                    calls.push_back(std::move(item));
                }
                return json{{"home", home.name}, {"calls", std::move(calls)}};
            });

        add("cexchain_fetch_instance",
            "A contract instance whose home is another organization's ledger (a peer), fetched "
            "and verified: every call run again and every consent checked on its own ledger. "
            "Shows its status, parties, state, head, and calls; for a part, its parent and its "
            "ancestors, whose calls up to each split are run again too. Homes show an instance "
            "only to its parties.",
            {{"home", home_property},
             {"instance",
              {{"type", "string"}, {"description", "The instance's full id (64 hex digits)."}}}},
            json::array({"home", "instance"}), remote_read,
            [this](const Tool&, const json& arguments) {
                const node::Peer home = peer_named(peers_dir(), text_arg(arguments, "home"));
                const protocol::ContractReport report =
                    fetch_instance(home, full_id(text_arg(arguments, "instance"), "instance"))
                        .second;
                json out = plain(verifier::contract_report_json(report, true));
                out["evidence"] = std::move(out["report"]);
                out["report"] = verifier::contract_report_text(report, true);
                return out;
            });

        add("cexchain_propose_contract_call",
            "Propose a call on a contract instance whose home is another organization's ledger "
            "(a peer) to that home's registrar, as one of the instance's parties. The registrar "
            "runs the contract and holds the call until every party it names has consented on "
            "its own ledger (cexchain_consent_contract_call); nothing is recorded before that. A "
            "call the contract would take without consents, or rejects, is refused. Proposals "
            "go out under your organization's peer token, so you need a delegation to consent to "
            "contract calls.",
            {{"home", home_property},
             {"instance",
              {{"type", "string"}, {"description", "The instance's full id (64 hex digits)."}}},
             {"function", {{"type", "string"}, {"description", "The contract's function."}}},
             {"arguments", arguments_property},
             {"reference", reference_property},
             {"head",
              {{"type", "integer"},
               {"minimum", 0},
               {"description", "The instance's head the call is on (default: its current head, "
                               "from the home's verified evidence)."}}},
             {"days",
              {{"type", "integer"},
               {"minimum", 1},
               {"maximum", 30},
               {"description", "The call lapses after this many days (default: the home's, 7)."}}}},
            json::array({"home", "instance", "function"}), remote_writes,
            [this](const Tool&, const json& arguments) {
                const Session session(args_);
                require_consent_delegation(session);
                const node::Peer home = peer_named(peers_dir(), text_arg(arguments, "home"));
                node::PendingCall proposal;
                proposal.instance = full_id(text_arg(arguments, "instance"), "instance");
                proposal.function = text_arg(arguments, "function");
                proposal.arguments = contract_arguments(arguments);
                proposal.reference = optional_text(arguments, "reference");
                if (const auto head = optional_number(arguments, "head", 0,
                                                      std::numeric_limits<std::uint64_t>::max())) {
                    proposal.head = *head;
                } else {
                    proposal.head =
                        fetch_instance(home, proposal.instance).second.instance.instance->head;
                }
                if (const auto days = optional_number(arguments, "days", 1, 30)) {
                    proposal.until = ledger::SystemClock{}.now() + *days * day_ms;
                }
                const Json answer =
                    peer_call(home, "POST", "/v1/contracts/calls",
                              unwrap(node::encode_call_proposal(proposal), "the proposal"));
                json out = plain(held_json(answer));
                out["waiting_for"] = ledgers_text(session, answer.value("missing", Json::array()));
                return out;
            });

        add("cexchain_consent_contract_call",
            "Consent, on your organization's ledger, to a call another organization's registrar "
            "holds (find it with cexchain_list_pending_calls, and check the instance with "
            "cexchain_fetch_instance, first). Records a cexchain.contract-consent/1 record signed "
            "with your key and naming the call's exact terms: the instance and its head, the "
            "function, and a digest of the arguments. Its evidence goes to the home, which "
            "records the call once the contract has every consent it asks for. A consent applies "
            "to that one call only, once, until it lapses.",
            {{"home", home_property},
             {"call",
              {{"type", "string"}, {"description", "The held call's full id (64 hex digits)."}}},
             {"reference", reference_property},
             {"days",
              {{"type", "integer"},
               {"minimum", 1},
               {"maximum", 30},
               {"description", "The consent lapses after this many days (default: 7)."}}},
             {"send",
              {{"type", "boolean"},
               {"description", "Send the consent's evidence to the home (default: true)."}}},
             {"out",
              {{"type", "string"},
               {"description", "Also write the consent's evidence to this file."}}},
             {"inputs", inputs_property}},
            json::array({"home", "call"}), remote_writes,
            [this](const Tool& tool, const json& arguments) {
                if (!args_.has("log-key")) {
                    throw ToolError{"this MCP server cannot export a consent's evidence: its "
                                    "operator starts it with --log-key (the ledger's log key)"};
                }
                Session session(args_);
                const node::Peer home = peer_named(peers_dir(), text_arg(arguments, "home"));
                const protocol::Id call = full_id(text_arg(arguments, "call"), "call");
                const bool send = optional_flag(arguments, "send", true);
                const auto out_path = optional_text(arguments, "out");
                if (!send && !out_path) {
                    throw ToolError{"with 'send' false, give 'out' to keep the consent's evidence"};
                }
                ConsentOptions options;
                options.days = optional_number(arguments, "days", 1, 30).value_or(7);
                options.reference = optional_text(arguments, "reference");
                options.provenance = provenance(tool, arguments, session);
                HeldTerms terms = held_call_terms(session, home, call, std::nullopt);
                const GivenConsent given =
                    give_consent(session, *key_, terms.consent, options, args_);
                if (out_path) {
                    write_file(*out_path, given.bundle, false);
                }
                json out = plain(consent_json(given.record, terms.consent, terms.arguments));
                if (send) {
                    try {
                        const Json answer =
                            peer_call(home, "POST", "/v1/contracts/consents", given.bundle);
                        json result = plain(answer);
                        if (answer.contains("missing")) {
                            result["waiting_for"] = ledgers_text(session, answer["missing"]);
                        }
                        out["home_answer"] = std::move(result);
                    } catch (const CommandError& e) {
                        out["home_answer"] = {{"status", "refused"}, {"error", e.message}};
                        out["note"] = "Your consent is recorded on your ledger, but the home did "
                                      "not take it. Unused, it lapses; you may also withdraw it "
                                      "(cexchain_transition_record to \"withdrawn\") if your "
                                      "delegation allows.";
                    }
                }
                return out;
            });

        // Requests and answers (spec v0.8, 6b): work a contract asked for
        // outside the ledger, and the answers that close them.
        const json request_property = {
            {"type", "string"}, {"description", "The request's id or a unique prefix (8+ hex)."}};
        add("cexchain_list_requests",
            "Requests that contract calls on this ledger made: work outside the ledger (send a "
            "notice, call a system), each with a kind, params, a deadline, and the function an "
            "answer calls (its reply). A request stays open until one answer closes it: done, "
            "failed, or expired. Shows each request's status, whether it is overdue, the call "
            "that made it, and its answer (who gave it, with kind, delegation, and model; when; "
            "how late).",
            {{"state",
              {{"type", "string"},
               {"enum", json::array({"open", "answered", "failed", "overdue", "all"})},
               {"description", "Which requests: open ones, answered ones, those answered failed "
                               "or expired, open ones past their deadline, or all (default)."}}},
             {"kinds",
              {{"type", "array"},
               {"items", {{"type", "string"}}},
               {"description", "Only requests of these kinds."}}},
             {"contract",
              {{"type", "string"}, {"description", "Only requests on this contract's instances."}}},
             {"instance", {{"type", "string"}, {"description", "Only this instance's requests."}}}},
            json::array(), read_only, [this](const Tool&, const json& arguments) {
                Session session(args_);
                RequestFilter filter;
                const std::string state = optional_text(arguments, "state").value_or("all");
                if (state == "open") {
                    filter.which = RequestFilter::Which::open;
                } else if (state == "answered") {
                    filter.which = RequestFilter::Which::answered;
                } else if (state == "failed") {
                    filter.which = RequestFilter::Which::failed;
                } else if (state == "overdue") {
                    filter.which = RequestFilter::Which::overdue;
                } else if (state != "all") {
                    throw ToolError{"state is open, answered, failed, overdue, or all"};
                }
                const std::vector<std::string> kinds = string_list(arguments, "kinds");
                if (!kinds.empty()) {
                    std::string list;
                    for (const std::string& k : kinds) {
                        list += (list.empty() ? "" : ",") + k;
                    }
                    filter.kinds = parse_request_kinds(list, "kinds");
                }
                if (const auto contract = optional_text(arguments, "contract")) {
                    filter.contract = session.contract_id(*contract);
                }
                if (const auto instance = optional_text(arguments, "instance")) {
                    filter.instance = session.instance_id(*instance);
                }
                const protocol::Timestamp now = ledger::SystemClock{}.now();
                json requests = json::array();
                for (const protocol::RequestState* r : select_requests(session, filter, now)) {
                    requests.push_back(plain(request_json(session, *r, now)));
                }
                return json{{"requests", std::move(requests)}};
            });

        add("cexchain_get_request",
            "One request: what was asked (kind, params), by which call, its deadline and reply, "
            "whether it is open or overdue, and its answer if it has one.",
            {{"request", request_property}}, json::array({"request"}), read_only,
            [this](const Tool&, const json& arguments) {
                Session session(args_);
                const protocol::RequestState& r =
                    *session.state().request(session.request_id(text_arg(arguments, "request")));
                return plain(request_json(session, r, ledger::SystemClock{}.now()));
            });

        add("cexchain_answer_request",
            "Answer a request, as its executor: say what became of the work it asked for. done: "
            "it was done; failed: it was not (give a reason code); expired: nobody did it in "
            "time (valid once its deadline has come). The answer is a call of the request's "
            "reply on its instance, signed with your key under your delegation (which may cover "
            "only some kinds of request) and recorded with your provenance. Its arguments carry "
            "the result as the contract defines it: codes, ids, amounts, never personal data or "
            "an outside system's raw text. A request takes one answer; the contract runs here "
            "first, and an answer it does not take is not recorded. 'dry_run' shows the decision "
            "and records nothing.",
            {{"request", request_property},
             {"status",
              {{"type", "string"},
               {"enum", json::array({"done", "failed", "expired"})},
               {"description", "What became of the work."}}},
             {"arguments", arguments_property},
             {"reason",
              {{"type", "string"},
               {"description", "For failed or expired: a reason code (lowercase, like a request "
                               "kind, e.g. unavailable), added to the arguments as \"reason\"."}}},
             {"reference", reference_property},
             {"dry_run",
              {{"type", "boolean"},
               {"description", "Only show what the contract and the ledger would decide "
                               "(default: false)."}}},
             {"inputs", inputs_property}},
            json::array({"request", "status"}), writes,
            [this](const Tool& tool, const json& arguments) {
                Session session(args_);
                const protocol::Id id = session.request_id(text_arg(arguments, "request"));
                const auto status = parse_answer_status(text_arg(arguments, "status"));
                if (!status) {
                    throw ToolError{"status is done, failed, or expired"};
                }
                const auto reason = optional_text(arguments, "reason");
                if (reason && *status == protocol::AnswerStatus::done) {
                    throw ToolError{"a reason explains a failure or an expiry, not done"};
                }
                cbor::Value values =
                    answer_arguments(arguments.contains("arguments")
                                         ? std::optional<cbor::Value>(contract_arguments(arguments))
                                         : std::nullopt,
                                     reason);
                CallOptions options;
                options.provenance = provenance(tool, arguments, session);
                options.dry_run = optional_flag(arguments, "dry_run", false);
                protocol::ContractCallBody body =
                    answer_call(session, *session.state().request(id), *status, std::move(values),
                                ledger::SystemClock{}.now());
                body.reference = optional_text(arguments, "reference");
                const CallAttempt attempt =
                    attempt_answer(session, *key_, std::move(body), options);
                json out = plain(run_json(session, attempt));
                out["request"] = hex_id(id);
                out["status"] = std::string(protocol::name(*status));
                out["dry_run"] = options.dry_run;
                out["recorded"] = attempt.recorded.has_value();
                if (attempt.recorded) {
                    out["statement_id"] = hex_id(*attempt.recorded);
                    out["answered"] = plain(request_json(session, *session.state().request(id),
                                                         ledger::SystemClock{}.now()));
                } else if (!options.dry_run) {
                    out["note"] = "Not recorded: the request stays open.";
                }
                return out;
            });

        add("cexchain_verify_evidence",
            "Verify an evidence bundle offline before acting on a document from someone else.",
            {{"bundle_path", {{"type", "string"}}},
             {"expected_ledger_id",
              {{"type", "string"},
               {"description", "The issuer's ledger id, learned out of band."}}},
             {"attachments",
              {{"type", "object"},
               {"additionalProperties", {{"type", "string"}}},
               {"description", "Attachment name to file path, to check contents."}}}},
            json::array({"bundle_path"}), read_only, [](const Tool&, const json& arguments) {
                const crypto::openssl::Provider provider;
                protocol::VerifyOptions options;
                if (const auto ledger_id = optional_text(arguments, "expected_ledger_id")) {
                    options.expected_ledger = unwrap(
                        protocol::to_id(unwrap(from_hex(*ledger_id), "ledger id")), "ledger id");
                }
                for (const auto& [name, path] : string_map(arguments, "attachments")) {
                    options.attachment_contents[name] = read_file(path);
                }
                const auto report = protocol::verify_bundle(
                    provider, read_file(text_arg(arguments, "bundle_path")), options);
                if (!report) {
                    throw ToolError{"VERIFICATION FAILED: " + std::string(report.error().detail)};
                }
                return json{{"verified", true},
                            {"record_type", report->record_type},
                            {"state", report->state},
                            {"revoked", report->revoked},
                            {"report",
                             verifier::report_text(*report, options.expected_ledger.has_value())}};
            });
    }

    /// The ledger directory, whose peers the contract tools reach; empty in
    /// client mode (--server), where those tools are refused.
    [[nodiscard]] const std::filesystem::path& peers_dir() const {
        if (ledger_.empty()) {
            throw ToolError{"this tool works on a ledger directory, with its peers (peer add); "
                            "this MCP server works through a server (--server)"};
        }
        return ledger_;
    }

    const Args& args_;
    std::filesystem::path ledger_;
    std::unique_ptr<crypto::Signer> key_;
    std::vector<Tool> tools_;
    std::string instructions_;
};

} // namespace

int cmd_mcp(const Args& args) {
    if (args.has("log-key") && args.has("server")) {
        throw UsageError{"--log-key goes with a ledger directory: through --server, the tools "
                         "that send consents to other organizations are not available"};
    }
    if (const auto log_key = args.get("log-key")) {
        // Opened now, so that a wrong passphrase shows before any client connects.
        static_cast<void>(load_signer(*log_key, args));
    }
    Server server(args, load_signer(args.need("as"), args));
    std::println(stderr, "cexchain MCP server ready (stdio)");
    return server.run();
}

} // namespace cexchain::cli
