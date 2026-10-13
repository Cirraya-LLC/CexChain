// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <print>
#include <span>

#include <cexchain/core/protocol/common.hpp>
#include <cexchain/crypto/openssl.hpp>
#if defined(CEXCHAIN_HAVE_BO)
#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/pack.hpp>
#endif

#include "commands.hpp"
#include "output.hpp"
#include "registry.hpp"

namespace cexchain::cli {

namespace {

std::string join(const std::vector<std::string_view>& words) {
    std::string out;
    for (const std::string_view w : words) {
        out += (out.empty() ? "" : " ") + std::string(w);
    }
    return out;
}

Json spec_json(const CommandSpec& spec) {
    Json options = Json::array();
    for (const OptionSpec& o : spec.options) {
        options.push_back({{"name", "--" + std::string(o.name)},
                           {"value", o.value.empty() ? Json(nullptr) : Json(std::string(o.value))},
                           {"help", o.help},
                           {"required", o.required},
                           {"repeatable", o.repeatable}});
    }
    return {{"command", join(spec.path)},
            {"summary", spec.summary},
            {"group", spec.group},
            {"arguments", spec.arguments},
            {"options", std::move(options)}};
}

} // namespace

int cmd_version(const Args& args) {
    const crypto::openssl::Provider provider;
    Json algorithms = Json::array();
    for (const crypto::SigAlg alg : crypto::all_sig_algs) {
        if (provider.supports(alg)) {
            algorithms.push_back(crypto::name(alg));
        }
    }
    Json hashes = Json::array();
    for (const crypto::HashAlg alg : {crypto::HashAlg::sha256, crypto::HashAlg::sm3}) {
        if (provider.supports(alg)) {
            hashes.push_back(crypto::name(alg));
        }
    }
    // The Bo compiler, if this build has it: its edition and official packs.
    Json bo = nullptr;
#if defined(CEXCHAIN_HAVE_BO)
    Json packs = Json::array();
    for (const bo::Pack& pack : bo::official_packs()) {
        packs.push_back(pack.id + " " + std::to_string(pack.version));
    }
    bo = {{"edition", bo::edition}, {"packs", packs}};
#endif
    if (args.json()) {
        print_json({{"version", CEXCHAIN_VERSION},
                    {"protocol_version", protocol::protocol_version},
                    {"spec_revision", protocol::spec_revision},
                    {"crypto_library", crypto::openssl::library_version()},
                    {"signature_algorithms", algorithms},
                    {"ledger_hashes", hashes},
                    {"bo", bo}});
        return exit_ok;
    }
    std::println("cexchain {}", CEXCHAIN_VERSION);
    std::println("protocol:    CexChain spec {} (wire version {})", protocol::spec_revision,
                 protocol::protocol_version);
    std::println("crypto:      {}", crypto::openssl::library_version());
    std::string list;
    for (const auto& a : algorithms) {
        list += (list.empty() ? "" : ", ") + a.get<std::string>();
    }
    std::println("signatures:  {}", list);
    list.clear();
    for (const auto& h : hashes) {
        list += (list.empty() ? "" : ", ") + h.get<std::string>();
    }
    std::println("hashes:      {}", list);
    if (bo.is_null()) {
        std::println("bo:          not in this build (the compiler needs GCC 16)");
    } else {
        list.clear();
        for (const auto& p : bo["packs"]) {
            list += (list.empty() ? "" : ", ") + p.get<std::string>();
        }
        std::println("bo:          edition {}; packs {}", bo["edition"].get<std::uint64_t>(), list);
    }
    return exit_ok;
}

int cmd_help(const Args& args) {
    const auto& words = args.positional();
    std::vector<const CommandSpec*> matches;
    for (const CommandSpec& spec : registry()) {
        if (spec.alias || spec.path.size() < words.size()) {
            continue;
        }
        if (std::ranges::equal(words, std::span(spec.path).first(words.size()),
                               [](const std::string& a, std::string_view b) { return a == b; })) {
            matches.push_back(&spec);
        }
    }
    if (matches.empty()) {
        throw UsageError{"no command '" + join({words.begin(), words.end()}) +
                         "'; run cexchain help"};
    }
    if (args.json()) {
        Json out = Json::array();
        for (const CommandSpec* spec : matches) {
            out.push_back(spec_json(*spec));
        }
        print_json(out);
        return exit_ok;
    }
    if (words.empty()) {
        std::print("{}", overview_help());
    } else if (matches.size() == 1 && matches.front()->path.size() == words.size()) {
        std::print("{}", command_help(*matches.front()));
    } else {
        for (const CommandSpec* spec : matches) {
            std::string name = join(spec->path);
            if (!spec->arguments.empty()) {
                name += " " + std::string(spec->arguments);
            }
            std::println("  cexchain {:<34} {}", name, spec->summary);
        }
    }
    return exit_ok;
}

int cmd_completion(const Args& args) {
    std::print("{}", completion_script(args.positional().front()));
    return exit_ok;
}

} // namespace cexchain::cli
