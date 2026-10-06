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
#include <functional>
#include <iostream>
#include <print>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/record_types.hpp>

#include "commands.hpp"
#include "records.hpp"
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
    if (scope.not_after) {
        out["valid_until"] = format_time(*scope.not_after);
    }
    return out;
}

class Server {
public:
    Server(std::filesystem::path ledger, std::filesystem::path key_path)
        : ledger_(std::move(ledger)), key_(load_key(key_path)) {
        define_tools();
        Session session(ledger_);
        const protocol::ActorState& me = session.actor_for(key_);
        std::string responsible = "your organization";
        if (me.responsible) {
            responsible = session.state().actor(*me.responsible)->display_name;
        }
        instructions_ =
            "You act on the CexChain ledger of " + session.state().organization() + " as \"" +
            me.display_name + "\" (" + std::string(kind_name(me.kind)) +
            "). Every action you take is signed with your own key, recorded as performed by "
            "you, and attributed to " +
            responsible +
            ", who is accountable for you. You can only do what your delegations allow "
            "(cexchain_whoami lists them); if the ledger refuses an action, do not try to work "
            "around it, report it. Before acting on a document from someone else, verify its "
            "evidence with cexchain_verify_evidence. When issuing or changing records, pass "
            "'inputs' describing what you based the action on: only its hash is recorded.";
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
                Session session(ledger_);
                const protocol::ActorState& me = session.actor_for(key_);
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
                            {"kind", std::string(kind_name(me.kind))},
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

        add("cexchain_ledger_status", "The ledger's identity, size, and latest checkpoint.",
            json::object(), json::array(), read_only, [this](const Tool&, const json&) {
                Session session(ledger_);
                json out = {{"ledger_id", hex_id(session.state().ledger_id())},
                            {"organization", session.state().organization()},
                            {"hash", std::string(crypto::name(session.state().hash()))},
                            {"entries", session.ledger().size()},
                            {"records", session.state().records().size()}};
                if (const auto& c = session.ledger().latest_checkpoint()) {
                    out["checkpoint"] = {{"tree_size", c->checkpoint.tree_size},
                                         {"time", format_time(c->checkpoint.timestamp)}};
                }
                return out;
            });

        add("cexchain_record_types",
            "Built-in record types with their initial state, allowed transitions, and "
            "endorsement roles.",
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
                Session session(ledger_);
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
            "Issue a record (e.g. a quality certificate). Field values stay private until "
            "disclosed; only commitments are recorded.",
            {{"record_type", {{"type", "string"}, {"description", "e.g. cexchain.certificate/1"}}},
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
                Session session(ledger_);
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
                const protocol::Id id = issue_record(session, key_, request);
                return json{{"record_id", hex_id(id)},
                            {"state", session.state().record(id)->state}};
            });

        add("cexchain_endorse_record", "Endorse a record in a role (e.g. inspector, receiver).",
            {{"record", {{"type", "string"}}},
             {"role", {{"type", "string"}}},
             {"inputs", inputs_property}},
            json::array({"record", "role"}), writes,
            [this](const Tool& tool, const json& arguments) {
                Session session(ledger_);
                const protocol::RecordEndorseBody body{
                    session.record_id(text_arg(arguments, "record")), text_arg(arguments, "role")};
                const protocol::Id id =
                    session.submit(key_, body, std::nullopt, provenance(tool, arguments, session));
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
                Session session(ledger_);
                const protocol::Id record = session.record_id(text_arg(arguments, "record"));
                const std::string from = session.state().record(record)->state;
                const protocol::RecordTransitionBody body{record, from,
                                                          text_arg(arguments, "to_state")};
                session.submit(key_, body, std::nullopt, provenance(tool, arguments, session));
                return json{{"record_id", hex_id(record)}, {"from", from}, {"to", body.to_state}};
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
                return json{
                    {"verified", true},
                    {"record_type", report->record_type},
                    {"state", report->state},
                    {"revoked", report->revoked},
                    {"report", format_report(*report, options.expected_ledger.has_value())}};
            });
    }

    std::filesystem::path ledger_;
    crypto::openssl::KeyPair key_;
    std::vector<Tool> tools_;
    std::string instructions_;
};

} // namespace

int mcp(const Args& args) {
    Server server(args.need("ledger"), args.need("as"));
    std::println(stderr, "cexchain MCP server ready (stdio)");
    return server.run();
}

} // namespace cexchain::cli
