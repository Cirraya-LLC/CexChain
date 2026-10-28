// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The rules editor's server side: the compiler on what the page sends (a
// rules sheet, or a source), run as `cexchain bo ...` in a child process.
// The compiler checks its own contracts and ends its process on a broken
// one; in a child, that ends the child, never the node. Each run has its
// time, memory, and output limited, one at a time per session and a few at
// a time in all, on files in a private directory removed after it.

#include <algorithm>
#include <filesystem>
#include <map>
#include <mutex>
#include <string>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/app/support.hpp>
#include <cexchain/bo/source.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/node/process.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

constexpr std::string_view rules_prefix = "/console/api/rules/";

bool known_language(std::string_view language) {
    return language == "en" || language == "zh-Hant-HK" || language == "zh-Hans-CN";
}

/// Removes a directory when it goes.
struct Scratch {
    explicit Scratch(std::filesystem::path where) : path(std::move(where)) {}
    std::filesystem::path path;
    ~Scratch() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    Scratch(const Scratch&) = delete;
    Scratch& operator=(const Scratch&) = delete;
};

} // namespace

std::variant<Console::CompilerRun, http::Response>
Console::run_compiler(const Signed& who, std::vector<std::string> args,
                      const std::vector<std::pair<std::string, std::string>>& files,
                      const std::vector<std::string>& outputs) const {
    if (services_.compiler.empty()) {
        return error(501, "unsupported", "this console runs no compiler");
    }
    {
        const std::lock_guard lock(mutex_);
        if (compiling_.contains(who.session.id)) {
            return error(429, "unavailable", "the compiler is still busy with your last request");
        }
        if (compiling_.size() >= max_compiler_runs) {
            return error(429, "unavailable", "the compiler is busy; try again in a moment");
        }
        compiling_.insert(who.session.id);
    }
    struct Done {
        const Console& console;
        std::string id;
        ~Done() {
            const std::lock_guard lock(console.mutex_);
            console.compiling_.erase(id);
        }
    } const done{*this, who.session.id};

    const Scratch scratch{services_.directory / "compiler" /
                          to_hex(services_.entropy->bytes<12>())};
    std::filesystem::create_directories(scratch.path);
    for (const auto& [name, content] : files) {
        app::write_file(scratch.path / name, as_bytes(content), true);
    }
    for (std::string& arg : args) {
        const bool given =
            std::ranges::any_of(files, [&](const auto& f) { return f.first == arg; });
        if (given || std::ranges::contains(outputs, arg)) {
            arg = (scratch.path / arg).string();
        }
    }
    args.insert(args.begin(), "bo");
    args.insert(args.end(), {"--json", "--max-memory", std::to_string(compiler_memory_mib)});
    auto child = node::ChildProcess::start(services_.compiler, args);
    if (!child) {
        return error(500, "internal", "the compiler did not start");
    }
    const auto run = child->communicate(
        {}, std::chrono::duration_cast<std::chrono::milliseconds>(compiler_time), compiler_output);
    if (!run.exit) {
        return error(504, "unavailable", "the compiler took too long (30 seconds at most)");
    }
    if (run.exit->signal != 0) {
        return error(500, "internal", "the compiler stopped: it may have run out of memory");
    }
    if (run.truncated) {
        return error(500, "internal", "the compiler's answer is too large");
    }
    CompilerRun out;
    out.answer = nlohmann::json::parse(run.output.begin(), run.output.end(), nullptr, false);
    if (!out.answer.is_object() && !out.answer.is_array()) {
        return error(500, "internal", "the compiler's answer does not read");
    }
    for (const std::string& name : outputs) {
        const std::filesystem::path file = scratch.path / name;
        if (std::filesystem::is_regular_file(file) &&
            std::filesystem::file_size(file) <= bo::max_built_size) {
            out.files.emplace(name, app::read_file(file));
        }
    }
    return out;
}

std::variant<protocol::ContractDeployBody, http::Response>
Console::deploy_body(const Signed& who, const std::string& source) const {
    if (source.size() > max_rules_input) {
        return error(413, "limit_exceeded", "a source is at most 256 KiB");
    }
    const ledger::Ledger* served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger to deploy to");
    }
    const std::string hash = served->hash() == crypto::HashAlg::sm3 ? "sm3" : "sha256";
    auto ran = run_compiler(who, {"build", "source.bo", "--out", "built.boc", "--hash", hash},
                            {{"source.bo", source}}, {"built.boc"});
    if (auto* refused = std::get_if<http::Response>(&ran)) {
        return std::move(*refused);
    }
    const CompilerRun& run = std::get<CompilerRun>(ran);
    const auto built = run.files.find("built.boc");
    if (built == run.files.end()) {
        http::Response answer = json(
            422,
            {{"error", {{"code", "verification_failed"}, {"message", "the rules do not build"}}},
             {"compiler", run.answer}});
        return answer;
    }
    const auto contract = bo::decode_built(built->second);
    if (!contract) {
        return error(500, "internal", "the compiler's build does not read");
    }
    return protocol::ContractDeployBody{contract->code,     contract->interface, "bo",
                                        contract->compiler, contract->source,    contract->name};
}

http::Response Console::contracts_route(const Signed& /*who*/) const {
    const ledger::Ledger* served = ledger();
    if (served == nullptr) {
        return services_.keys != nullptr && services_.keys->initialized() &&
                       !services_.keys->unlocked()
                   ? error(423, "locked", "the console is locked: unlock it first")
                   : error(503, "unavailable", "the console has no ledger yet");
    }
    nlohmann::json list = nlohmann::json::array();
    served->read_state([&](const protocol::LedgerState& state) {
        std::map<std::string, std::size_t> instances;
        for (const auto& [key, i] : state.instances()) {
            ++instances[to_hex(protocol::Id(i.contract).bytes())];
        }
        for (const auto& [key, c] : state.contracts()) {
            const std::string id = to_hex(protocol::Id(c.id).bytes());
            nlohmann::json functions = nlohmann::json::array();
            for (const auto& [name, kind] : c.interface) {
                functions.push_back(name);
            }
            list.push_back({{"id", id},
                            {"name", c.name ? nlohmann::json(*c.name) : nlohmann::json()},
                            {"language", c.language},
                            {"compiler", c.compiler},
                            {"functions", functions},
                            {"retired", c.retired},
                            {"index", c.deployed_at_index},
                            {"instances", instances[id]}});
        }
    });
    std::sort(list.begin(), list.end(), [](const nlohmann::json& a, const nlohmann::json& b) {
        return a["index"].get<std::uint64_t>() > b["index"].get<std::uint64_t>();
    });
    return json(200, {{"contracts", list}});
}

http::Response Console::rules_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    if (request.path == "/console/api/rules") {
        return request.method == "GET" ? contracts_route(signer)
                                       : error(405, "unsupported", "method not allowed");
    }
    const std::string_view what = std::string_view(request.path).substr(rules_prefix.size());
    // A contract's page: what its calls take, for everyone who may create
    // or act (and read, for viewers).
    if (what.size() == 64 && what.find_first_not_of("0123456789abcdef") == std::string_view::npos) {
        if (request.method != "GET") {
            return error(405, "unsupported", "method not allowed");
        }
        std::optional<protocol::Id> id;
        if (const auto bytes = from_hex(what)) {
            if (auto made = protocol::to_id(*bytes)) {
                id = *made;
            }
        }
        if (!id) {
            return error(400, "invalid_argument", "a contract id is 64 hex digits");
        }
        return contract_route(signer, *id, request);
    }
    if (signer.role != Role::owner && signer.role != Role::admin) {
        return error(403, "forbidden", "only an owner or an admin writes rules");
    }
    if (what == "packs") {
        if (request.method != "GET") {
            return error(405, "unsupported", "method not allowed");
        }
        auto answer = run_compiler(signer, {"vocab", "list"}, {});
        if (auto* refused = std::get_if<http::Response>(&answer)) {
            return std::move(*refused);
        }
        return json(200, {{"packs", std::get<CompilerRun>(answer).answer}});
    }
    if (request.method != "POST") {
        http::Response refused = error(405, "unsupported", "method not allowed");
        refused.headers.emplace_back("Allow", "POST");
        return refused;
    }
    if (request.body.size() > max_rules_input + 4096) {
        return error(413, "limit_exceeded", "a source or a sheet is at most 256 KiB");
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    const std::string language = body.value("language", "");
    if (!language.empty() && !known_language(language)) {
        return error(400, "invalid_argument", "a language is en, zh-Hant-HK, or zh-Hans-CN");
    }
    std::vector<std::string> args;
    std::vector<std::pair<std::string, std::string>> files;
    if (what == "form") {
        const auto sheet = body.find("sheet");
        if (sheet == body.end() || !sheet->is_object()) {
            return error(400, "invalid_argument", "send the rules sheet as \"sheet\"");
        }
        std::string text = sheet->dump();
        if (text.size() > max_rules_input) {
            return error(413, "limit_exceeded", "a sheet is at most 256 KiB");
        }
        files.emplace_back("sheet.json", std::move(text));
        args = {"form", "sheet.json"};
    } else if (what == "from" || what == "check" || what == "explain" || what == "test" ||
               what == "fmt") {
        const auto source = body.find("source");
        if (source == body.end() || !source->is_string()) {
            return error(400, "invalid_argument", "send the Bo source as \"source\"");
        }
        if (source->get_ref<const std::string&>().size() > max_rules_input) {
            return error(413, "limit_exceeded", "a source is at most 256 KiB");
        }
        files.emplace_back("source.bo", source->get<std::string>());
        if (what == "from") {
            args = {"form", "--from", "source.bo"};
        } else {
            args = {std::string(what), "source.bo"};
        }
    } else {
        return error(404, "not_found", "no such console route");
    }
    if (!language.empty()) {
        args.insert(args.end(), {"--language", language});
    }
    auto answer = run_compiler(signer, std::move(args), files);
    if (auto* refused = std::get_if<http::Response>(&answer)) {
        return std::move(*refused);
    }
    return json(200, std::get<CompilerRun>(answer).answer);
}

} // namespace cexchain::console
