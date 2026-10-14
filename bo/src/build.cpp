// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Building a source all the way, and rebuilding a deploy from its source
// bundle (build.hpp).

#include <algorithm>
#include <cstdint>
#include <format>
#include <limits>
#include <string>
#include <utility>

#include <cexchain/bo/build.hpp>
#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/parser.hpp>
#include <cexchain/bo/runtime.hpp>
#include <cexchain/bo/wasm.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/vm.hpp>

#if !defined(CEXCHAIN_BO_RELEASE)
#error "CEXCHAIN_BO_RELEASE names the release (bo/CMakeLists.txt sets it)"
#endif

namespace cexchain::bo {

namespace {

void append(std::vector<Diagnostic>& to, const std::vector<Diagnostic>& from) {
    to.insert(to.end(), from.begin(), from.end());
}

/// "6,001 bytes, SHA-256 f292eabc214383d3": a module for people.
std::string code_text(ByteView code, const crypto::Provider& provider, crypto::HashAlg hash) {
    const auto digest = provider.digest(hash, code);
    const std::string hex = digest ? to_hex(digest->bytes()).substr(0, 16) : std::string("?");
    return std::format("{} bytes, {} {}", code.size(), crypto::name(hash), hex);
}

std::string interface_text(const std::map<std::string, protocol::FunctionKind>& interface) {
    std::string out;
    for (const auto& [name, kind] : interface) {
        out += (out.empty() ? "" : ", ") + name +
               (kind == protocol::FunctionKind::create ? " (creates)" : "");
    }
    return out;
}

} // namespace

const CompilerId& this_compiler() noexcept {
    static const CompilerId id{CEXCHAIN_BO_RELEASE, wasm::codegen_version, edition};
    return id;
}

std::string compiler_string() {
    return format_compiler(this_compiler());
}

Compiled compile(std::string_view source, const PackSet& packs, const CompileOptions& options) {
    Compiled out;
    const Lexicon lexicon(packs);
    const Lexed lexed = lex(source, lexicon);
    out.edition = lexed.edition;
    out.comments = lexed.comments.size();
    const Parsed parsed = parse(source, lexed);
    out.diagnostics = lexed.diagnostics;
    append(out.diagnostics, parsed.diagnostics);
    if (!has_errors(out.diagnostics)) {
        const Checked checked = check(source, parsed.file);
        append(out.diagnostics, checked.diagnostics);
        out.name = checked.model.name;
        if (!has_errors(out.diagnostics)) {
            out.model = checked.model;
            Lowered lowered = lower(source, checked.model, options.codegen);
            append(out.diagnostics, lowered.diagnostics);
            out.build = std::move(lowered.build);
            if (out.build && options.check_bounds) {
                // Milestone 18: no call may run out of fuel; an output beyond
                // the code's region is refused, which the author should know.
                bool refused = false;
                for (const auto& [function, bound] : out.build->bounds) {
                    const auto args = [&](std::uint64_t value, std::uint64_t limit) {
                        return std::vector<std::pair<std::string_view, std::string>>{
                            {"function", function},
                            {"bound", std::to_string(value)},
                            {"limit", std::to_string(limit)}};
                    };
                    if (bound.fuel > vm::fuel_limit) {
                        out.diagnostics.push_back(
                            Diagnostic{"build.fuel", args(bound.fuel, vm::fuel_limit), Span{}});
                        refused = true;
                    } else if (bound.output > max_build_output) {
                        out.diagnostics.push_back(Diagnostic{
                            "build.output", args(bound.output, max_build_output), Span{}});
                    }
                }
                if (refused) {
                    out.build.reset();
                }
            }
            if (out.build && out.comments > 0) {
                out.diagnostics.push_back(Diagnostic{
                    "build.comments", {{"count", std::to_string(out.comments)}}, Span{}});
            }
        }
    }
    std::ranges::stable_sort(out.diagnostics, {}, [](const Diagnostic& d) {
        return d.span.line == 0 ? std::numeric_limits<std::uint64_t>::max()
                                : std::uint64_t{d.span.offset};
    });
    return out;
}

namespace {

/// Counts a value's items and map keys, as read_input reads them; false if
/// a key is longer than read_input_fuel allows for.
bool count_items(const cbor::Value& v, std::uint64_t& items, std::uint64_t& keys) {
    ++items;
    if (const cbor::Array* a = v.as_array()) {
        return std::ranges::all_of(
            *a, [&](const cbor::Value& x) { return count_items(x, items, keys); });
    }
    if (const cbor::Map* m = v.as_map()) {
        for (const cbor::MapEntry& e : *m) {
            ++keys;
            const auto key = cbor::encode(e.key);
            if (!key || key->size() > std::size_t{runtime::max_key_size} + 2 ||
                !count_items(e.key, items, keys) || !count_items(e.value, items, keys)) {
                return false;
            }
        }
        return true;
    }
    if (const cbor::Tagged* t = v.as_tagged()) {
        return count_items(t->item, items, keys);
    }
    return true;
}

} // namespace

std::optional<std::uint64_t> bound_for(const Build& build, const ByteView input) {
    auto value = cbor::decode(input);
    if (!value) {
        return std::nullopt;
    }
    const cbor::Map* root = value->as_map();
    if (root == nullptr) {
        return std::nullopt;
    }
    const std::string* function = nullptr;
    for (const cbor::MapEntry& e : *root) {
        if (e.key.as_uint64() == 1U) {
            function = e.value.as_text();
        }
    }
    if (function == nullptr) {
        return std::nullopt;
    }
    const auto it = build.bounds.find(*function);
    if (it == build.bounds.end()) {
        return std::nullopt;
    }
    std::uint64_t items = 0;
    std::uint64_t keys = 0;
    if (!count_items(*value, items, keys)) {
        return std::nullopt;
    }
    const FunctionBound& b = it->second;
    return wasm::add_saturating(b.fuel - b.input, runtime::read_input_fuel(items, keys));
}

Rebuild rebuild(const protocol::ContractDeployBody& deploy, const crypto::Provider& provider,
                const crypto::HashAlg home_hash) {
    Rebuild r;
    const CompilerId& ours = this_compiler();
    r.deployed = parse_compiler(deploy.compiler);
    // A codegen version this compiler still writes, and its edition.
    const bool same_codegen = r.deployed && r.deployed->codegen >= wasm::oldest_codegen_version &&
                              r.deployed->codegen <= ours.codegen &&
                              r.deployed->edition == ours.edition;
    const bool same_release = same_codegen && r.deployed->release == ours.release;
    const auto result = [&](RebuildStatus status, std::string detail) {
        r.status = status;
        r.detail = std::move(detail);
        return std::move(r);
    };
    // Another compiler's output: say whose, and that this one does not
    // reproduce it.
    const auto other = [&](const std::string& what) {
        const std::string by =
            r.deployed
                ? std::format("built with {}; this compiler is {}, and {}: rebuild with "
                              "cexchain-bo {}",
                              deploy.compiler, compiler_string(), what, r.deployed->release)
                : std::format("built with \"{}\", which is not cexchain-bo, and {}: the code "
                              "cannot be checked against its source here",
                              deploy.compiler, what);
        return result(RebuildStatus::other_compiler, by);
    };

    if (deploy.language != "bo") {
        return result(RebuildStatus::malformed,
                      std::format("the contract is written in {}, not Bo", deploy.language));
    }
    if (!deploy.source) {
        return result(RebuildStatus::malformed,
                      "a Bo deploy carries its source, and this one does not: its code cannot be "
                      "checked against a source");
    }
    auto bundle = decode_source_bundle(*deploy.source);
    if (!bundle) {
        return result(RebuildStatus::malformed,
                      std::format("the deploy's source is not a bo-source bundle: {}",
                                  bundle.error().detail));
    }
    r.bundle = std::move(*bundle);
    OpenedSource opened = open_source_bundle(*r.bundle, provider, home_hash);
    switch (opened.problem) {
    case OpenProblem::none:
        break;
    case OpenProblem::embedded:
    case OpenProblem::conflict:
        return result(RebuildStatus::malformed, opened.detail);
    case OpenProblem::unknown_official:
    case OpenProblem::official_differs:
    case OpenProblem::official_missing:
    case OpenProblem::unknown_edition:
        // The official packs come with a release.
        if (same_release) {
            return result(RebuildStatus::differs,
                          opened.detail + ", although the deploy names this compiler");
        }
        return other(opened.detail);
    }

    Compiled compiled =
        compile(r.bundle->source, *opened.packs,
                CompileOptions{same_codegen ? static_cast<std::uint32_t>(r.deployed->codegen)
                                            : wasm::codegen_version,
                               false});
    if (compiled.edition != r.bundle->edition) {
        return result(RebuildStatus::malformed,
                      std::format("the bundle says the source is Bo edition {}, but it is "
                                  "edition {}",
                                  r.bundle->edition, compiled.edition));
    }
    if (!compiled.build) {
        const auto first = std::ranges::find_if(compiled.diagnostics, [](const Diagnostic& d) {
            return d.severity() == Severity::error;
        });
        const std::string why =
            first == compiled.diagnostics.end()
                ? std::string("it does not build")
                : std::format("{} ({}{})", render(*first, nullptr), first->code,
                              first->span.line == 0 ? std::string()
                                                    : std::format(", line {}", first->span.line));
        r.diagnostics = std::move(compiled.diagnostics);
        if (same_codegen) {
            return result(RebuildStatus::differs,
                          "the source does not build with the compiler the deploy names: " + why);
        }
        return other("the source does not build here: " + why);
    }
    r.build = std::move(compiled.build);
    const Build& build = *r.build;
    std::string difference;
    if (build.code != deploy.code) {
        difference = std::format("the source builds to other code ({}) than the deployed ({})",
                                 code_text(build.code, provider, home_hash),
                                 code_text(deploy.code, provider, home_hash));
    } else if (build.interface != deploy.interface) {
        difference = std::format("the source builds to the functions {}, not the deployed {}",
                                 interface_text(build.interface), interface_text(deploy.interface));
    } else if (deploy.name && *deploy.name != compiled.name) {
        difference = std::format("the deploy is named \"{}\", but the contract is {}", *deploy.name,
                                 compiled.name);
    }
    if (difference.empty()) {
        return result(RebuildStatus::rebuilds,
                      std::format("the source rebuilds to the deployed code ({}) with {}",
                                  code_text(deploy.code, provider, home_hash), compiler_string()));
    }
    if (same_codegen) {
        return result(RebuildStatus::differs, difference + ", with the compiler the deploy names");
    }
    return other(difference);
}

} // namespace cexchain::bo
