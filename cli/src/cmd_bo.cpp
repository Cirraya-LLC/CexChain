// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Bo commands (D-053, step 6): checking and building Bo source, and the
// language packs it is read with; building the deploy of `contract deploy
// --bo`. Built only with the Bo compiler (cexchain::bo: GCC 16, for C++26
// reflection and contracts).

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <limits>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <cexchain/bo/build.hpp>
#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/explain.hpp>
#include <cexchain/bo/format.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/names.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>
#include <cexchain/bo/scenario.hpp>
#include <cexchain/bo/source.hpp>
#include <cexchain/bo/stdlib.hpp>
#include <cexchain/bo/values.hpp>
#include <cexchain/bo/vocab.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "bo_support.hpp"
#include "commands.hpp"
#include "output.hpp"

namespace cexchain::cli {

namespace {

/// A pack file as read, with what was found.
struct PackFile {
    std::string file;
    bo::PackRead read;
};

PackFile read_pack_file(const std::string& file) {
    const Bytes bytes = read_file(file);
    const std::string_view text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    return {file, bo::read_pack(text)};
}

/// The language for messages: --language, else $CEXCHAIN_LANGUAGE, else
/// English. Any official pack, or one given with --pack.
const bo::Pack* message_language(const Args& args, std::span<const bo::Pack> extra) {
    return reader_language(args.get("language"), extra);
}

Json span_json(const bo::Span& span) {
    return {{"line", span.line},
            {"column", span.column},
            {"offset", span.offset},
            {"length", span.length}};
}

Json diagnostic_json(const bo::Diagnostic& diagnostic, const bo::Pack* language) {
    Json args = Json::object();
    for (const auto& [name, value] : diagnostic.args) {
        args[std::string(name)] = value;
    }
    Json out = {{"severity", bo::name_of(diagnostic.severity())},
                {"code", diagnostic.code},
                {"message", bo::render(diagnostic, language)},
                {"args", args}};
    if (diagnostic.span.line != 0) {
        out["span"] = span_json(diagnostic.span);
    }
    return out;
}

Json diagnostics_json(const std::vector<bo::Diagnostic>& diagnostics, const bo::Pack* language) {
    Json out = Json::array();
    for (const bo::Diagnostic& diagnostic : diagnostics) {
        out.push_back(diagnostic_json(diagnostic, language));
    }
    return out;
}

void print_diagnostics(std::FILE* stream, std::string_view where,
                       const std::vector<bo::Diagnostic>& diagnostics, const bo::Pack* language) {
    for (const bo::Diagnostic& diagnostic : diagnostics) {
        std::println(stream, "{}: {}: {} ({})", where, bo::name_of(diagnostic.severity()),
                     bo::render(diagnostic, language), diagnostic.code);
    }
}

/// The official packs plus those given with --pack (and `more`), checked
/// together; any problem ends the command.
bo::PackSet pack_set(const Args& args, const std::vector<std::string>& more = {}) {
    std::vector<std::string> files = args.all("pack");
    files.insert(files.end(), more.begin(), more.end());
    std::vector<PackFile> read;
    for (const std::string& file : files) {
        read.push_back(read_pack_file(file));
    }
    std::vector<bo::Pack> valid;
    for (const PackFile& file : read) {
        if (file.read.pack) {
            valid.push_back(*file.read.pack);
        }
    }
    const bo::Pack* language = message_language(args, valid);
    bool failed = false;
    for (const PackFile& file : read) {
        if (bo::has_errors(file.read.diagnostics)) {
            print_diagnostics(stderr, file.file, file.read.diagnostics, language);
            failed = true;
        }
    }
    if (failed) {
        throw CommandError{"a pack does not read (bo packs check shows why)"};
    }
    bo::PackSetRead set = bo::make_pack_set(std::move(valid));
    if (!set.set) {
        print_diagnostics(stderr, "packs", set.diagnostics, language);
        throw CommandError{"the packs cannot be read together"};
    }
    return std::move(*set.set);
}

const crypto::openssl::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

bo::PackFacts pack_facts(const bo::Pack& pack, crypto::HashAlg hash) {
    return unwrap(bo::facts(pack, provider(), hash), "digest");
}

std::string spellings_text(const bo::Word& word) {
    std::string out;
    for (const std::string& spelling : word.spellings) {
        out += (out.empty() ? "" : ", ") + spelling;
    }
    if (!word.forms.empty()) {
        std::string forms;
        for (const auto& [name, spelling] : word.forms) {
            forms += (forms.empty() ? "" : ", ") + name + ": " + spelling;
        }
        out += " (" + forms + ")";
    }
    return out;
}

Json word_json(const bo::Word& word) {
    Json forms = Json::object();
    for (const auto& [name, spelling] : word.forms) {
        forms[name] = spelling;
    }
    return {{"spellings", word.spellings}, {"forms", forms}};
}

std::string categories_text(const std::vector<bo::Category>& categories) {
    std::string out;
    for (const bo::Category category : categories) {
        out += (out.empty() ? "" : ", ") + std::string(bo::name_of(category));
    }
    return out;
}

Json categories_json(const std::vector<bo::Category>& categories) {
    Json out = Json::array();
    for (const bo::Category category : categories) {
        out.push_back(bo::name_of(category));
    }
    return out;
}

Json reading_json(const bo::ReadingRules& reading) {
    Json attach = Json::array();
    for (const bo::Attachment& a : reading.attach) {
        attach.push_back({{"word", a.word},
                          {"before", categories_json(a.before)},
                          {"after", categories_json(a.after)}});
    }
    Json punctuation = Json::object();
    for (const auto& [character, ascii] : reading.punctuation) {
        punctuation[character] = std::string(1, ascii);
    }
    Json multipliers = Json::object();
    for (const auto& [spelling, value] : reading.multipliers) {
        multipliers[spelling] = value;
    }
    return {{"separation", bo::name_of(reading.separation)},
            {"prefixes", reading.prefixes},
            {"attach", attach},
            {"punctuation", punctuation},
            {"multipliers", multipliers},
            {"dates",
             {{"read", reading.dates.read},
              {"write", reading.dates.write},
              {"months", reading.dates.months}}}};
}

void print_reading(const bo::Pack& pack) {
    const bo::ReadingRules& r = pack.reading;
    const auto spelled = [&](const std::string& id) {
        const bo::Word* word = pack.word(id);
        return (word == nullptr ? std::string("?") : word->spellings.front()) + " (" + id + ")";
    };
    std::println("Reading rules");
    std::println("  {:<13}{}", "separation", bo::name_of(r.separation));
    std::string prefixes;
    for (const std::string& id : r.prefixes) {
        prefixes += (prefixes.empty() ? "" : ", ") + spelled(id);
    }
    std::println("  {:<13}{}", "prefixes", prefixes.empty() ? "(none)" : prefixes);
    if (r.attach.empty()) {
        std::println("  {:<13}(none)", "attach");
    }
    for (std::size_t i = 0; i < r.attach.size(); ++i) {
        const bo::Attachment& a = r.attach[i];
        std::string where;
        if (!a.before.empty()) {
            where += "before " + categories_text(a.before);
        }
        if (!a.after.empty()) {
            where += (where.empty() ? "" : "; ") + std::string("after ") + categories_text(a.after);
        }
        std::println("  {:<13}{} {}", i == 0 ? "attach" : "", spelled(a.word), where);
    }
    std::string punctuation;
    for (const auto& [character, ascii] : r.punctuation) {
        punctuation += (punctuation.empty() ? "" : "  ") + bo::visible(character) + "\u2192" +
                       (ascii == ' ' ? std::string("space") : std::string(1, ascii));
    }
    std::println("  {:<13}{}", "punctuation", punctuation.empty() ? "(none)" : punctuation);
    std::string multipliers;
    for (const auto& [spelling, value] : r.multipliers) {
        multipliers +=
            (multipliers.empty() ? "" : ", ") + spelling + " \u00D7" + std::to_string(value);
    }
    std::println("  {:<13}{}", "multipliers", multipliers.empty() ? "(none)" : multipliers);
    std::string read = "ISO 8601";
    for (const std::string& pattern : r.dates.read) {
        read += ", " + pattern;
    }
    std::println("  {:<13}read {}; written {}", "dates", read,
                 r.dates.write.empty() ? "as ISO 8601" : r.dates.write);
}

/// The pack PACK names: an id in the set, or a file to read into it.
const bo::Pack& chosen_pack(const bo::PackSet& set, const std::string& name) {
    if (const bo::Pack* pack = set.find(name)) {
        return *pack;
    }
    throw UsageError{"no pack " + name +
                     " (bo packs list shows the packs; give a file with --pack)"};
}

constexpr std::string_view sections[] = {"reading", "keywords", "vocabulary", "messages",
                                         "sentences"};

Json token_json(std::string_view source, const bo::Token& token) {
    Json out = {{"kind", bo::name_of(token.kind)}, {"span", span_json(token.span)}};
    switch (token.kind) {
    case bo::TokenKind::word:
        out["concept"] = token.concept_entry->id;
        out["category"] = bo::name_of(token.concept_entry->category);
        out["piece"] = bo::name_of(token.piece);
        if (!token.form.empty()) {
            out["form"] = token.form;
        }
        break;
    case bo::TokenKind::name: {
        out["name"] = token.text;
        Json splits = Json::array();
        for (const bo::NameSplit& split : token.splits) {
            splits.push_back({{"prefix", split.prefix->id},
                              {"rest", std::string_view(token.text).substr(split.length)}});
        }
        out["splits"] = splits;
        break;
    }
    case bo::TokenKind::edition_line:
    case bo::TokenKind::number:
    case bo::TokenKind::rate:
        out["value"] = bo::to_string(token.number);
        break;
    case bo::TokenKind::money:
    case bo::TokenKind::quantity:
    case bo::TokenKind::duration:
        out["value"] = bo::to_string(token.number);
        out["unit"] = token.concept_entry->id;
        break;
    case bo::TokenKind::date:
        out["date"] =
            std::format("{:04}-{:02}-{:02}", token.date.year, token.date.month, token.date.day);
        break;
    case bo::TokenKind::text:
        out["text"] = token.text;
        break;
    case bo::TokenKind::symbol:
        out["symbol"] = bo::symbol_texts[static_cast<std::size_t>(token.symbol)];
        break;
    case bo::TokenKind::newline:
    case bo::TokenKind::indent:
    case bo::TokenKind::dedent:
    case bo::TokenKind::end:
        break;
    }
    if (token.span.length > 0) {
        out["source"] = source.substr(token.span.offset, token.span.length);
    }
    return out;
}

/// "FILE:LINE:COLUMN: error: message (code)", as compilers write it.
void print_source_diagnostics(std::FILE* stream, std::string_view file,
                              const std::vector<bo::Diagnostic>& diagnostics,
                              const bo::Pack* language) {
    for (const bo::Diagnostic& d : diagnostics) {
        const std::string where = d.span.line == 0
                                      ? std::string(file)
                                      : std::format("{}:{}:{}", file, d.span.line, d.span.column);
        std::println(stream, "{}: {}: {} ({})", where, bo::name_of(d.severity()),
                     bo::render(d, language), d.code);
    }
}

/// The packs given with --pack (for the language of messages).
std::vector<bo::Pack> given_packs(const bo::PackSet& set) {
    std::vector<bo::Pack> given;
    for (const bo::Pack& pack : set.packs()) {
        if (!pack.official) {
            given.push_back(pack);
        }
    }
    return given;
}

std::string read_text_file(const std::string& file) {
    const Bytes bytes = read_file(file);
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

/// A source built, and its bundle made under the home's hash.
struct SourceBuild {
    std::string source;
    bo::Compiled compiled;
    /// Set if it built.
    std::optional<bo::SourceBundle> bundle;
    Bytes bundle_bytes;
};

SourceBuild build_source(const bo::PackSet& set, const std::string& file,
                         const crypto::HashAlg hash) {
    SourceBuild out;
    out.source = read_text_file(file);
    out.compiled = bo::compile(out.source, set);
    if (out.compiled.build) {
        out.bundle =
            unwrap(bo::make_source_bundle(out.source, out.compiled.edition, set, provider(), hash),
                   "the source bundle (the source and the packs that are not official) cannot be "
                   "deployed");
        out.bundle_bytes = unwrap(bo::encode_source_bundle(*out.bundle), "the source bundle");
    }
    return out;
}

Json functions_json(const std::map<std::string, protocol::FunctionKind>& interface) {
    Json out = Json::object();
    for (const auto& [name, kind] : interface) {
        out[name] = kind == protocol::FunctionKind::create ? "create" : "call";
    }
    return out;
}

std::string functions_text(const std::map<std::string, protocol::FunctionKind>& interface) {
    std::string out;
    for (const auto& [name, kind] : interface) {
        out += (out.empty() ? "" : ", ") + name +
               (kind == protocol::FunctionKind::create ? " (creates)" : "");
    }
    return out;
}

/// What a build holds, as `bo build --json` and `contract deploy --bo
/// --json` show it.
Json build_json(const protocol::ContractDeployBody& body, const bo::SourceBundle& bundle,
                std::size_t comments, const crypto::HashAlg hash) {
    const auto code_hash = unwrap(provider().digest(hash, body.code), "hashing the code");
    // References without an embedded pack name official packs.
    std::vector<std::string> embedded;
    for (const cbor::Value& pack : bundle.embedded) {
        if (const cbor::Value* id = pack.find("id"); id != nullptr && id->as_text() != nullptr) {
            embedded.push_back(*id->as_text());
        }
    }
    Json packs = Json::array();
    for (const bo::PackRef& ref : bundle.packs) {
        packs.push_back({{"id", ref.id},
                         {"version", ref.version},
                         {"digest", to_hex(ref.digest)},
                         {"official", std::ranges::find(embedded, ref.id) == embedded.end()}});
    }
    // The vocabulary packs the source uses (key 6).
    Json vocabulary = Json::array();
    for (const bo::PackRef& ref : bundle.vocabulary) {
        vocabulary.push_back(
            {{"id", ref.id}, {"version", ref.version}, {"digest", to_hex(ref.digest)}});
    }
    return {{"contract", body.name ? Json(*body.name) : Json(nullptr)},
            {"language", body.language},
            {"compiler", body.compiler},
            {"edition", bundle.edition},
            {"functions", functions_json(body.interface)},
            {"code_size", body.code.size()},
            {"code_hash", to_hex(code_hash.bytes())},
            {"hash", crypto::name(hash)},
            {"source_size", bundle.source.size()},
            {"comments", comments},
            {"bundle_size", body.source ? body.source->size() : std::size_t{0}},
            {"packs", packs},
            {"vocabulary", vocabulary}};
}

/// "1,234,567": a bound for people.
std::string grouped(const std::uint64_t n) {
    std::string digits = std::to_string(n);
    for (std::size_t at = digits.size(); at > 3; at -= 3) {
        digits.insert(at - 3, ",");
    }
    return digits;
}

/// Each function's bound (milestone 18), as `bo build --json` shows it.
Json bounds_json(const bo::Build& build) {
    Json out = Json::object();
    for (const auto& [name, b] : build.bounds) {
        out[name] = {{"fuel", b.fuel},
                     {"input", b.input},
                     {"input_items", b.input_items},
                     {"input_keys", b.input_keys},
                     {"output", b.output}};
    }
    return out;
}

/// The highest bounds, one line; with `every`, one line per function.
void print_bounds(const bo::Build& build, const bool every) {
    if (build.bounds.empty()) {
        return;
    }
    const auto most = [&](auto member) {
        auto best = build.bounds.begin();
        for (auto it = build.bounds.begin(); it != build.bounds.end(); ++it) {
            if (it->second.*member > best->second.*member) {
                best = it;
            }
        }
        return best;
    };
    const auto fuel = most(&bo::FunctionBound::fuel);
    const auto output = most(&bo::FunctionBound::output);
    std::println("  {:<10} at most {} a call ({}), of {}; output at most {} bytes ({}), of {}",
                 "fuel", grouped(fuel->second.fuel), fuel->first, grouped(vm::fuel_limit),
                 grouped(output->second.output), output->first, grouped(bo::max_build_output));
    if (!every) {
        return;
    }
    std::size_t width = 8;
    for (const auto& [name, b] : build.bounds) {
        width = std::max(width, name.size());
    }
    std::println("  {:<{}}  {:>12}  {:>12}  {:>9}", "function", width + 2, "fuel", "reading",
                 "output");
    for (const auto& [name, b] : build.bounds) {
        std::println("  {:<{}}  {:>12}  {:>12}  {:>9}", name, width + 2, grouped(b.fuel),
                     grouped(b.input), grouped(b.output));
    }
}

/// The build's lines after its first: functions, code, compiler, source.
void print_build(const protocol::ContractDeployBody& body, const Json& j) {
    std::println("  {:<10} {}", "functions", functions_text(body.interface));
    std::println("  {:<10} {} bytes, {} {}", "code", j["code_size"].get<std::size_t>(),
                 j["hash"].get<std::string>(), j["code_hash"].get<std::string>());
    std::println("  {:<10} {}", "compiler", body.compiler);
    std::string packs;
    for (const Json& p : j["packs"]) {
        packs += std::format("{}{} {}{}", packs.empty() ? "" : ", ", p["id"].get<std::string>(),
                             p["version"].get<std::uint64_t>(),
                             p["official"].get<bool>() ? "" : " (embedded)");
    }
    std::string vocabulary;
    for (const Json& p : j["vocabulary"]) {
        vocabulary += std::format("{}{} {}", vocabulary.empty() ? "" : ", ",
                                  p["id"].get<std::string>(), p["version"].get<std::uint64_t>());
    }
    const std::size_t comments = j["comments"].get<std::size_t>();
    std::println("  {:<10} bo-source bundle of {} bytes: the source ({} bytes{}, Bo edition {}), "
                 "the packs {}{} ({} digests)",
                 "source", j["bundle_size"].get<std::size_t>(), j["source_size"].get<std::size_t>(),
                 comments == 0 ? std::string() : std::format(", {} comment lines", comments),
                 j["edition"].get<std::uint64_t>(), packs,
                 vocabulary.empty() ? std::string()
                                    : std::format(", and the vocabulary packs {}", vocabulary),
                 j["hash"].get<std::string>());
}

// --- bo test.

/// A test ledger as JSON names it: a role's name in compiled code
/// ("supplier"), or a name as written ("bank1").
std::string ledger_key(const bo::TestResults& results, const protocol::Id& id) {
    const bo::TestLedger* l = results.ledger(id);
    return l == nullptr ? to_hex(id.bytes()) : bo::wire_name(l->word, l->name);
}

Json ledger_keys(const bo::TestResults& results, const std::vector<protocol::Id>& ids) {
    Json out = Json::array();
    for (const protocol::Id& id : ids) {
        out.push_back(ledger_key(results, id));
    }
    return out;
}

Json expectation_json(const bo::model::Step& step, const bo::StepResult& r,
                      const bo::TestResults& results) {
    Json out = {{"outcome", bo::model::expectation_names[static_cast<std::size_t>(step.expect)]}};
    switch (step.expect) {
    case bo::model::Expectation::state:
        out["state"] = bo::wire_name(step.state_word, step.state_name);
        break;
    case bo::model::Expectation::refused:
        out["reason"] = step.reason ? Json(*step.reason) : Json(nullptr);
        break;
    case bo::model::Expectation::waits:
        out["parties"] = ledger_keys(results, r.expected_waits);
        break;
    case bo::model::Expectation::accepted:
    case bo::model::Expectation::proposed:
        break;
    }
    return out;
}

Json call_json(const bo::TestCall& call, const bo::TestResults& results) {
    std::vector<protocol::Id> consents;
    for (const auto& [id, signer] : call.input.consents) {
        consents.push_back(id);
    }
    std::string outcome = "aborted";
    if (call.run.trap) {
        outcome = std::string(vm::name(*call.run.trap));
    } else if (call.output) {
        outcome =
            std::holds_alternative<protocol::ContractAccept>(*call.output) ? "accept" : "needs";
    }
    return {{"function", call.input.function},
            {"time", call.input.time},
            {"consents", ledger_keys(results, consents)},
            {"outcome", outcome},
            {"fuel", call.run.fuel_used},
            {"input", to_hex(call.encoded)}};
}

Json step_json(const bo::model::Model& model, const bo::Explained& text,
               const bo::model::Step& step, const bo::StepResult& r, const bo::TestResults& results,
               std::size_t number, std::string_view source, const bo::Pack* language) {
    Json result = {{"outcome", bo::happened_names[static_cast<std::size_t>(r.happened)]}};
    switch (r.happened) {
    case bo::Happened::accepted: {
        result["state"] = r.state;
        result["events"] = r.events;
        result["final"] = r.final;
        result["consents"] = ledger_keys(results, r.consents);
        if (!r.proposed.empty()) {
            result["proposed"] = r.proposed;
        }
        if (r.parts > 0) {
            // The parts the call created (R30).
            result["parts"] = r.parts;
        }
        break;
    }
    case bo::Happened::waits:
        result["parties"] = ledger_keys(results, r.waits);
        break;
    case bo::Happened::refused:
    case bo::Happened::broken:
        result["reason"] = r.reason;
        break;
    default:
        break;
    }
    Json out = {{"number", number},
                {"line", step.span.line},
                {"text", bo::step_source(source, step)},
                {"subject", bo::wire_name(step.subject.word, step.subject.name)},
                {"action", step.creation ? std::string(bo::model::creation_function(model))
                                         : bo::wire_name(step.word, step.name)},
                {"status", bo::step_status_names[static_cast<std::size_t>(r.status)]},
                {"time", r.time},
                {"expected", expectation_json(step, r, results)}};
    // The part the step acted on, by its path ("1.2"), once a split made parts.
    out["part"] = r.part.empty() ? Json(nullptr) : Json(r.part);
    if (r.status == bo::StepStatus::skipped) {
        out["result"] = nullptr;
        return out;
    }
    result["message"] = bo::outcome_text(r, results, language);
    const bo::ExplainedClause* clause = bo::refusal_clause(text, model, step, r);
    result["clause"] = clause != nullptr ? Json{{"number", clause->number}, {"text", clause->text}}
                                         : Json(nullptr);
    out["result"] = result;
    Json calls = Json::array();
    for (const bo::TestCall& call : r.calls) {
        calls.push_back(call_json(call, results));
    }
    out["calls"] = calls;
    return out;
}

Json tests_json(const bo::model::Model& model, const bo::TestResults& results,
                std::string_view source, const bo::Pack* language) {
    const bo::Explained text = bo::explain(model, language);
    Json out = Json::array();
    for (std::size_t i = 0; i < model.tests.size() && i < results.tests.size(); ++i) {
        const bo::model::Test& test = model.tests[i];
        const bo::TestResult& result = results.tests[i];
        Json steps = Json::array();
        for (std::size_t j = 0; j < test.steps.size() && j < result.steps.size(); ++j) {
            steps.push_back(step_json(model, text, test.steps[j], result.steps[j], results, j + 1,
                                      source, language));
        }
        out.push_back({{"name", test.name.empty() ? Json(nullptr) : Json(test.name)},
                       {"line", test.span.line},
                       {"passed", result.passed},
                       {"home", ledger_key(results, result.home)},
                       {"steps", steps}});
    }
    return out;
}

} // namespace

/// "2 parties, 5 fields, 1 state, ...": what a checked model holds.
std::string model_summary(const bo::model::Model& model) {
    std::string out;
    const auto count = [&](std::size_t n, std::string_view one, std::string_view many) {
        out += std::format("{}{} {}", out.empty() ? "" : ", ", n, n == 1 ? one : many);
    };
    count(model.parties.size(), "party", "parties");
    count(model.fields.size(), "field", "fields");
    count(model.charges.size(), "charge", "charges");
    count(model.states.size(), "state", "states");
    count(model.actions.size(), "action", "actions");
    count(model.rules.size(), "time rule", "time rules");
    return out;
}

int cmd_bo_check(const Args& args) {
    const std::string file = args.positional().front();
    const std::optional<std::string> stage = args.get("stage");
    if (stage && *stage != "lex" && *stage != "parse" && *stage != "model") {
        throw UsageError{
            "--stage must be lex (the tokens), parse (the tree), or model (the checked model)"};
    }
    const bo::PackSet set = pack_set(args);
    std::vector<bo::Pack> given;
    for (const bo::Pack& pack : set.packs()) {
        if (!pack.official) {
            given.push_back(pack);
        }
    }
    const bo::Pack* language = message_language(args, given);
    const Bytes bytes = read_file(file);
    const std::string_view source(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    const bo::Lexicon lexicon(set);
    const bo::Lexed lexed = bo::lex(source, lexicon);
    const bo::Parsed parsed = bo::parse(source, lexed);
    // The lexer's problems and the parser's, then, on a tree without errors
    // and unless only the tokens or the tree are asked for, the checker's,
    // in source order.
    std::vector<bo::Diagnostic> diagnostics = lexed.diagnostics;
    diagnostics.insert(diagnostics.end(), parsed.diagnostics.begin(), parsed.diagnostics.end());
    std::optional<bo::Checked> checked;
    if (stage != "lex" && stage != "parse" && !bo::has_errors(diagnostics)) {
        checked = bo::check(source, parsed.file);
        diagnostics.insert(diagnostics.end(), checked->diagnostics.begin(),
                           checked->diagnostics.end());
    }
    std::ranges::stable_sort(diagnostics, {}, [](const bo::Diagnostic& d) {
        return d.span.line == 0 ? std::numeric_limits<std::uint64_t>::max()
                                : std::uint64_t{d.span.offset};
    });
    const bool ok = !bo::has_errors(diagnostics);
    const std::size_t clauses = parsed.file.clauses.size();

    if (args.json()) {
        Json out = {{"file", file},
                    {"ok", ok},
                    {"stage", stage.value_or("check")},
                    {"edition", lexed.edition},
                    {"clauses", clauses},
                    {"checked", checked.has_value()},
                    {"diagnostics", diagnostics_json(diagnostics, language)}};
        if (stage == "lex") {
            Json tokens = Json::array();
            for (const bo::Token& token : lexed.tokens) {
                tokens.push_back(token_json(source, token));
            }
            Json comments = Json::array();
            for (const bo::Comment& comment : lexed.comments) {
                comments.push_back({{"span", span_json(comment.span)}, {"text", comment.text}});
            }
            out["tokens"] = tokens;
            out["comments"] = comments;
        } else if (stage == "parse") {
            out["tree"] = bo::dump(parsed.file);
            out["ast"] = cbor_json(bo::to_cbor(parsed.file));
        } else if (stage == "model" && checked) {
            out["dump"] = bo::dump(checked->model);
            out["model"] = cbor_json(bo::to_cbor(checked->model));
        }
        print_json(out);
        return ok ? exit_ok : exit_failure;
    }
    if (stage == "lex") {
        // The tokens on stdout; the problems after them, as below.
        bo::Lexed quiet;
        quiet.tokens = lexed.tokens;
        quiet.comments = lexed.comments;
        std::print("{}", bo::dump(source, quiet, language));
    } else if (stage == "parse") {
        std::print("{}", bo::dump(parsed.file));
    } else if (stage == "model" && checked) {
        std::print("{}", bo::dump(checked->model));
    }
    print_source_diagnostics(stage ? stdout : stderr, file, diagnostics, language);
    std::size_t errors = 0;
    std::size_t warnings = 0;
    for (const bo::Diagnostic& d : diagnostics) {
        (d.severity() == bo::Severity::error ? errors : warnings) += 1;
    }
    if (ok) {
        std::println("{}: ok: {} tokens, {} comments, {} clauses, edition {}", file,
                     lexed.tokens.size(), lexed.comments.size(), clauses, lexed.edition);
        if (checked) {
            std::println("{}: checked: {}; {} warning{}", file, model_summary(checked->model),
                         warnings, warnings == 1 ? "" : "s");
        }
    } else {
        std::println("{}: {} error{}", file, errors, errors == 1 ? "" : "s");
    }
    return ok ? exit_ok : exit_failure;
}

int cmd_bo_explain(const Args& args) {
    const std::string file = args.positional().front();
    const bo::PackSet set = pack_set(args);
    const bo::Pack* language = message_language(args, given_packs(set));
    const std::string source = read_text_file(file);
    const bo::Lexicon lexicon(set);
    const bo::Lexed lexed = bo::lex(source, lexicon);
    const bo::Parsed parsed = bo::parse(source, lexed);
    std::vector<bo::Diagnostic> diagnostics = lexed.diagnostics;
    diagnostics.insert(diagnostics.end(), parsed.diagnostics.begin(), parsed.diagnostics.end());
    std::optional<bo::Checked> checked;
    if (!bo::has_errors(diagnostics)) {
        checked = bo::check(source, parsed.file);
        diagnostics.insert(diagnostics.end(), checked->diagnostics.begin(),
                           checked->diagnostics.end());
    }
    std::ranges::stable_sort(diagnostics, {}, [](const bo::Diagnostic& d) {
        return d.span.line == 0 ? std::numeric_limits<std::uint64_t>::max()
                                : std::uint64_t{d.span.offset};
    });
    const bool ok = !bo::has_errors(diagnostics);
    std::optional<bo::Explained> explained;
    if (ok) {
        explained = bo::explain(checked->model, language);
    }
    if (args.json()) {
        Json out = {
            {"file", file}, {"ok", ok}, {"diagnostics", diagnostics_json(diagnostics, language)}};
        if (explained) {
            out.update(explained_json(*explained));
        }
        print_json(out);
        return ok ? exit_ok : exit_failure;
    }
    // Warnings (clauses that need executors) and errors on stderr; the text
    // on stdout.
    print_source_diagnostics(stderr, file, diagnostics, language);
    if (!ok) {
        std::size_t errors = 0;
        for (const bo::Diagnostic& d : diagnostics) {
            errors += d.severity() == bo::Severity::error ? 1U : 0U;
        }
        std::println("{}: {} error{}: there is no contract text until it checks", file, errors,
                     errors == 1 ? "" : "s");
        return exit_failure;
    }
    std::print("{}", explained->text);
    return exit_ok;
}

int cmd_bo_fmt(const Args& args) {
    const std::string file = args.positional().front();
    const bool check = args.has("check");
    const bool write = args.has("write");
    if (check && write) {
        throw UsageError{"--check and --write exclude each other"};
    }
    const bo::PackSet set = pack_set(args);
    const bo::Pack* messages = message_language(args, given_packs(set));
    // --language names the language to write; without it, every word keeps
    // its spelling ($CEXCHAIN_LANGUAGE sets only the messages').
    const bo::Pack* target = nullptr;
    if (const std::optional<std::string> want = args.get("language")) {
        target = bo::find_language(set.packs(), *want);
        if (target == nullptr) {
            throw UsageError{"no pack for the language " + *want +
                             " (en, zh-Hant-HK, zh-Hans-CN, or a pack given with --pack)"};
        }
    }
    const std::string source = read_text_file(file);
    const bo::Lexicon lexicon(set);
    const bo::Formatted formatted = bo::format_source(source, set, lexicon, target);
    const bool ok = formatted.source.has_value();
    const bool changed = ok && *formatted.source != source;
    const bool written = ok && write && changed;
    if (written) {
        write_file(file, as_bytes(*formatted.source), false);
    }
    const int status = !ok ? exit_failure : (check && changed ? exit_not_verified : exit_ok);
    if (args.json()) {
        Json out = {{"file", file},
                    {"ok", ok},
                    {"language", target != nullptr ? Json(target->id) : Json(nullptr)},
                    {"changed", changed},
                    {"written", written},
                    {"diagnostics", diagnostics_json(formatted.diagnostics, messages)}};
        if (ok) {
            out["source"] = *formatted.source;
        }
        print_json(out);
        return status;
    }
    if (!ok) {
        print_source_diagnostics(stderr, file, formatted.diagnostics, messages);
        std::println(stderr, "{}: not formatted", file);
        return status;
    }
    const std::string in = target != nullptr ? " in " + target->id : std::string();
    if (check) {
        std::println("{}: {}{}", file, changed ? "would change when formatted" : "formatted", in);
    } else if (write) {
        std::println("{}: {}{}", file, changed ? "formatted" : "already formatted", in);
    } else {
        std::print("{}", *formatted.source);
    }
    return status;
}

// --- bo stdlib.

/// Words of a list, joined as the language joins them.
std::string joined(const std::vector<std::string>& items, const bo::Pack* language) {
    std::string out;
    const std::string separator = bo::sentence("list-separator", {}, language);
    for (const std::string& item : items) {
        out += (out.empty() ? "" : separator) + item;
    }
    return out;
}

/// A built-in action's terms in short: who starts it, its counterparty,
/// and its states, in a language.
std::string standard_summary(const bo::StandardAction& a, const bo::Pack* language) {
    std::vector<std::string> parts;
    if (a.starter != nullptr) {
        // The sentence asks for the word's object form ("the holder").
        const bo::Word* word = language != nullptr ? language->word(a.starter->id) : nullptr;
        if (word == nullptr) {
            word = bo::english_pack().word(a.starter->id);
        }
        std::string party = bo::spell(a.starter->id, language);
        if (word != nullptr) {
            if (const auto it = word->forms.find("object"); it != word->forms.end()) {
                party = it->second;
            }
        }
        const std::pair<std::string_view, std::string> values[] = {{"party", party},
                                                                   {"party.object", party}};
        parts.push_back(bo::sentence("stdlib-starter", values, language));
    } else {
        parts.push_back(bo::sentence("stdlib-home", {}, language));
    }
    if (a.counterparty) {
        parts.push_back(bo::sentence("stdlib-counterparty", {}, language));
    }
    std::vector<std::string> from;
    std::vector<std::string> to;
    for (const bo::Concept* c : a.from) {
        from.push_back(bo::spell(c->id, language));
    }
    for (const bo::Concept* c : a.to) {
        to.push_back(bo::spell(c->id, language));
    }
    const std::pair<std::string_view, std::string> states[] = {{"from", joined(from, language)},
                                                               {"to", joined(to, language)}};
    parts.push_back(bo::sentence("stdlib-states", states, language));
    std::string out;
    const std::string separator = bo::sentence("value-separator", {}, language);
    for (const std::string& part : parts) {
        out += (out.empty() ? "" : separator) + part;
    }
    return out;
}

Json concept_ids(const std::vector<const bo::Concept*>& concepts) {
    Json out = Json::array();
    for (const bo::Concept* c : concepts) {
        out.push_back(c->id);
    }
    return out;
}

namespace {

/// The core or a vocabulary pack, by id: "core", "finance", ...
bo::Vocab vocab_of(std::string_view id) {
    for (std::size_t i = 0; i < bo::vocab_names.size(); ++i) {
        if (bo::vocab_names[i] == id) {
            return static_cast<bo::Vocab>(i);
        }
    }
    throw UsageError{std::format("Bo has no vocabulary pack {}: core, commerce, finance, or "
                                 "services (bo vocab list shows them)",
                                 id)};
}

} // namespace

int cmd_bo_stdlib_list(const Args& args) {
    const bo::Pack* language = message_language(args, {});
    std::optional<bo::Vocab> only;
    if (!args.positional().empty()) {
        only = vocab_of(args.positional().front());
    }
    Json out = Json::array();
    for (const bo::StandardAction& a : bo::standard_actions()) {
        if (only && a.action->pack != *only) {
            continue;
        }
        const std::string word = bo::spell(a.action->id, language);
        const std::string summary = standard_summary(a, language);
        const std::string_view pack = bo::vocab_name(a.action->pack);
        if (args.json()) {
            out.push_back({{"function", a.function},
                           {"pack", pack},
                           {"action", a.action->id},
                           {"word", word},
                           {"starter", a.starter != nullptr ? Json(a.starter->id) : Json(nullptr)},
                           {"counterparty", a.counterparty},
                           {"from", concept_ids(a.from)},
                           {"to", concept_ids(a.to)},
                           {"summary", summary}});
            continue;
        }
        std::println("{:<16} {:<9} {}: {}", a.function, pack, word, summary);
    }
    if (args.json()) {
        print_json(out);
    }
    return exit_ok;
}

namespace {

/// A pack's words (not the keywords, nor retired ones), by category, then id.
std::vector<const bo::Concept*> vocab_words(bo::Vocab vocab) {
    std::vector<const bo::Concept*> out;
    for (const bo::Concept& c : bo::concepts()) {
        if (c.pack == vocab && !c.retired && c.category != bo::Category::keyword) {
            out.push_back(&c);
        }
    }
    std::ranges::stable_sort(out, {}, [](const bo::Concept* c) { return c->category; });
    return out;
}

/// The functions of the built-in actions whose terms a pack brings.
std::vector<std::string> vocab_actions(bo::Vocab vocab) {
    std::vector<std::string> out;
    for (const bo::StandardAction& a : bo::standard_actions()) {
        if (a.action->pack == vocab) {
            out.push_back(a.function);
        }
    }
    return out;
}

struct VocabFacts {
    std::string id;
    std::optional<std::uint64_t> version;
    std::string name;
    std::size_t words = 0;
    std::vector<std::string> actions;
    std::string hash;
    std::optional<std::string> digest;
    const bo::VocabularyPack* pack = nullptr;
};

VocabFacts vocab_facts(bo::Vocab vocab, const bo::Pack* language, crypto::HashAlg alg) {
    VocabFacts f;
    f.id = std::string(bo::vocab_name(vocab));
    f.name = bo::sentence("vocab-" + f.id, {}, language);
    f.words = vocab_words(vocab).size();
    f.actions = vocab_actions(vocab);
    f.hash = std::string(crypto::name(alg));
    f.pack = bo::vocabulary_pack(vocab);
    if (f.pack != nullptr) {
        f.version = f.pack->version;
        f.digest = to_hex(unwrap(bo::digest(*f.pack, provider(), alg), "digest").bytes());
    }
    return f;
}

Json vocab_json(const VocabFacts& f) {
    return {{"id", f.id},
            {"version", f.version ? Json(*f.version) : Json(nullptr)},
            {"name", f.name},
            {"words", f.words},
            {"actions", f.actions},
            {"hash", f.hash},
            {"digest", f.digest ? Json(*f.digest) : Json(nullptr)}};
}

} // namespace

int cmd_bo_vocab_list(const Args& args) {
    const bo::Pack* language = message_language(args, {});
    const crypto::HashAlg hash = parse_hash(args.get("hash").value_or("sha256"));
    Json out = Json::array();
    for (const bo::Vocab vocab :
         {bo::Vocab::core, bo::Vocab::commerce, bo::Vocab::finance, bo::Vocab::services}) {
        const VocabFacts f = vocab_facts(vocab, language, hash);
        if (args.json()) {
            out.push_back(vocab_json(f));
            continue;
        }
        std::println("{:<9} {:<10} {:<9} {:>2} words, {:>2} built-in actions{}", f.id,
                     f.version ? std::format("version {}", *f.version) : std::string("-"), f.name,
                     f.words, f.actions.size(),
                     f.digest ? std::format("  {} {}", f.hash, *f.digest)
                              : std::string("  (every source)"));
    }
    if (args.json()) {
        print_json(out);
    }
    return exit_ok;
}

int cmd_bo_vocab_show(const Args& args) {
    const bo::Pack* language = message_language(args, {});
    const crypto::HashAlg hash = parse_hash(args.get("hash").value_or("sha256"));
    const bo::Vocab vocab = vocab_of(args.positional().front());
    const VocabFacts f = vocab_facts(vocab, language, hash);
    const auto field_notes = [](const bo::Concept& c) {
        std::string notes(c.type);
        if ((c.flags & bo::field_added) != 0) {
            notes += "; added (R20)";
        }
        if ((c.flags & bo::field_taking) != 0) {
            notes += "; taking (R31)";
        }
        return notes;
    };
    if (args.json()) {
        Json out = vocab_json(f);
        Json words = Json::array();
        for (const bo::Concept* c : vocab_words(vocab)) {
            Json w{{"concept", c->id},
                   {"category", bo::name_of(c->category)},
                   {"word", bo::spell(c->id, language)},
                   {"argument", c->arity > 0}};
            if (!c->type.empty()) {
                w["type"] = c->type;
                w["added"] = (c->flags & bo::field_added) != 0;
                w["taking"] = (c->flags & bo::field_taking) != 0;
            }
            words.push_back(std::move(w));
        }
        out["words"] = std::move(words);
        Json rules = Json::array();
        for (const bo::RuleSpec& rule : bo::rule_specs()) {
            if (rule.pack == vocab) {
                rules.push_back({{"id", rule.id}, {"name", rule.name}});
            }
        }
        out["rules"] = std::move(rules);
        out["canonical"] = f.pack != nullptr ? Json(to_hex(f.pack->canonical)) : Json(nullptr);
        print_json(out);
        return exit_ok;
    }
    if (f.pack != nullptr) {
        std::println("{} version {} ({}): use {}", f.id, *f.version, f.name, f.id);
        std::println("{} {}", f.hash, *f.digest);
    } else {
        std::println("{} ({}): every source", f.id, f.name);
    }
    std::println("\nWords ({})", f.words);
    for (const bo::Concept* c : vocab_words(vocab)) {
        std::println("  {:<10} {:<26} {}{}", bo::name_of(c->category), c->id,
                     bo::spell(c->id, language),
                     c->type.empty() ? std::string() : "  " + field_notes(*c));
    }
    std::println("\nBuilt-in actions ({})", f.actions.size());
    for (const std::string& action : f.actions) {
        std::println("  {}", action);
    }
    std::vector<const bo::RuleSpec*> rules;
    for (const bo::RuleSpec& rule : bo::rule_specs()) {
        if (rule.pack == vocab) {
            rules.push_back(&rule);
        }
    }
    std::println("\nRecognition rules ({})", rules.size());
    for (const bo::RuleSpec* rule : rules) {
        std::println("  {:<4} {}", rule->id, rule->name);
    }
    return exit_ok;
}

int cmd_bo_stdlib_show(const Args& args) {
    const bo::Pack* language = message_language(args, {});
    const std::string& name = args.positional().front();
    const bo::PackSet set = pack_set(args);
    const bo::Concept* action = bo::standard_action(name, set);
    if (action == nullptr) {
        throw UsageError{"the standard library has no built-in action " + name +
                         " (bo stdlib list shows them)"};
    }
    const std::optional<std::string> source = bo::standard_terms_source(action, language);
    if (!source) {
        throw CommandError{"the standard library's terms of " + name + " cannot be written in " +
                           language->id};
    }
    const std::vector<bo::ExplainedClause> terms = bo::standard_terms_text(action, language);
    const auto mark = [&](const bo::ExplainedClause& c) {
        if (c.rules.empty()) {
            return std::string();
        }
        std::vector<std::string> ids(c.rules.begin(), c.rules.end());
        const std::pair<std::string_view, std::string> values[] = {
            {"rules", joined(ids, language)}};
        return bo::sentence("mark", values, language);
    };
    if (args.json()) {
        Json clauses = Json::array();
        for (const bo::ExplainedClause& c : terms) {
            clauses.push_back({{"kind", c.kind}, {"text", c.text}, {"rules", c.rules}});
        }
        print_json({{"function", bo::wire_name(action, {})},
                    {"pack", bo::vocab_name(action->pack)},
                    {"action", action->id},
                    {"word", bo::spell(action->id, language)},
                    {"language", language->id},
                    {"source", *source},
                    {"terms", clauses}});
        return exit_ok;
    }
    if (action->pack != bo::Vocab::core) {
        std::println("{} {}", bo::spell("kw.use", language), bo::vocab_name(action->pack));
    }
    std::print("{}", *source);
    const std::pair<std::string_view, std::string> header[] = {
        {"action", bo::spell(action->id, language)}};
    std::println("\n{}", bo::sentence("stdlib-terms", header, language));
    for (const bo::ExplainedClause& c : terms) {
        // "4.6.4.1": one level below the action's clauses (4.6.4).
        const auto depth = static_cast<std::size_t>(std::ranges::count(c.number, '.'));
        std::println("{}{}{}", std::string(2 * (depth > 1 ? depth - 1 : 1), ' '), c.text, mark(c));
    }
    return exit_ok;
}

int cmd_bo_packs_list(const Args& args) {
    const bo::PackSet set = pack_set(args);
    const crypto::HashAlg hash = parse_hash(args.get("hash").value_or("sha256"));
    Json out = Json::array();
    for (const bo::Pack& pack : set.packs()) {
        const bo::PackFacts facts = pack_facts(pack, hash);
        if (args.json()) {
            out.push_back(cbor_json(bo::to_cbor(facts)));
            continue;
        }
        std::println("{:<12} version {:<3} {:<10} {}", facts.id, facts.version,
                     facts.official ? "official" : "community", facts.name);
        std::println("{:<12} {} {}", "", facts.hash, facts.digest);
    }
    if (args.json()) {
        print_json(out);
    }
    return exit_ok;
}

int cmd_bo_packs_show(const Args& args) {
    // PACK is a pack's id, or a file (read like --pack).
    std::string name = args.positional().front();
    std::vector<std::string> more;
    if (std::filesystem::is_regular_file(name)) {
        const PackFile file = read_pack_file(name);
        more.push_back(name);
        if (file.read.pack) {
            name = file.read.pack->id;
        }
    }
    const bo::PackSet set = pack_set(args, more);
    const bo::Pack& pack = chosen_pack(set, name);
    const crypto::HashAlg hash = parse_hash(args.get("hash").value_or("sha256"));
    const bo::PackFacts facts = pack_facts(pack, hash);
    const std::optional<std::string> section = args.get("section");
    if (section && std::ranges::find(sections, *section) == std::end(sections)) {
        throw UsageError{"--section must be reading, keywords, vocabulary, messages, or sentences"};
    }
    const auto wanted = [&](std::string_view s) {
        return !section || *section == s;
    };

    if (args.json()) {
        Json out = cbor_json(bo::to_cbor(facts));
        if (wanted("reading")) {
            out["reading"] = reading_json(pack.reading);
        }
        if (wanted("keywords")) {
            Json keywords = Json::object();
            for (const auto& [id, word] : pack.keywords) {
                keywords[id] = word.spellings;
            }
            out["keywords"] = keywords;
        }
        if (wanted("vocabulary")) {
            Json vocabulary = Json::object();
            for (const auto& [id, word] : pack.vocabulary) {
                Json j = word_json(word);
                j["category"] = bo::name_of(bo::find_concept(id)->category);
                vocabulary[id] = j;
            }
            out["vocabulary"] = vocabulary;
        }
        if (wanted("messages")) {
            out["messages"] = pack.messages;
        }
        if (wanted("sentences")) {
            out["sentences"] = pack.sentences;
        }
        print_json(out);
        return exit_ok;
    }

    std::println("Pack {}, version {} ({})", facts.id, facts.version,
                 facts.official ? "official" : "community");
    std::println("  {:<13}{}", "name", facts.name);
    std::println("  {:<13}{}", "language", facts.language);
    std::println("  {:<13}{}", "edition", facts.edition);
    std::println("  {:<13}{}", facts.hash, facts.digest);
    std::println("  {:<13}{} bytes of CBOR", "size", facts.size);
    if (wanted("reading")) {
        std::println("");
        print_reading(pack);
    }
    if (wanted("keywords")) {
        std::println("\nKeywords ({})", pack.keywords.size());
        for (const auto& [id, word] : pack.keywords) {
            std::println("  {:<26} {}", id, spellings_text(word));
        }
    }
    if (wanted("vocabulary")) {
        std::size_t total = 0;
        for (const bo::Concept& c : bo::concepts()) {
            total += c.category == bo::Category::keyword ? 0 : 1;
        }
        std::println("\nVocabulary ({} of {})", pack.vocabulary.size(), total);
        // By category, in the edition's order.
        for (std::size_t i = 0; i < bo::category_names.size(); ++i) {
            const auto category = static_cast<bo::Category>(i);
            bool heading = false;
            for (const auto& [id, word] : pack.vocabulary) {
                if (bo::find_concept(id)->category != category) {
                    continue;
                }
                if (!heading) {
                    std::println("  {}", bo::name_of(category));
                    heading = true;
                }
                std::println("    {:<24} {}", id, spellings_text(word));
            }
        }
    }
    if (wanted("messages")) {
        std::println("\nMessages ({} of {})", pack.messages.size(), bo::message_specs().size());
        for (const auto& [code, text] : pack.messages) {
            std::println("  {:<26} {}", code, text);
        }
    }
    if (wanted("sentences")) {
        std::println("\nSentences ({} of {})", pack.sentences.size(), bo::sentence_specs().size());
        for (const auto& [id, text] : pack.sentences) {
            std::println("  {:<26} {}", id, text);
        }
    }
    return exit_ok;
}

int cmd_bo_packs_check(const Args& args) {
    std::vector<PackFile> files;
    std::vector<bo::Pack> valid;
    for (const std::string& file : args.positional()) {
        files.push_back(read_pack_file(file));
        if (files.back().read.pack) {
            valid.push_back(*files.back().read.pack);
        }
    }
    const bo::Pack* language = message_language(args, valid);
    bool ok = valid.size() == files.size();
    std::optional<bo::PackSetRead> set;
    if (ok) {
        // Together with the official packs, as a source would read them.
        set = bo::make_pack_set(valid);
        ok = set->set.has_value();
    }
    if (args.json()) {
        Json packs = Json::array();
        for (const PackFile& file : files) {
            Json j = {{"file", file.file},
                      {"ok", file.read.pack.has_value()},
                      {"diagnostics", diagnostics_json(file.read.diagnostics, language)}};
            if (file.read.pack) {
                j["pack"] =
                    cbor_json(bo::to_cbor(pack_facts(*file.read.pack, crypto::HashAlg::sha256)));
            }
            packs.push_back(j);
        }
        Json out = {{"ok", ok}, {"packs", packs}};
        if (set) {
            out["set"] = {{"ok", set->set.has_value()},
                          {"diagnostics", diagnostics_json(set->diagnostics, language)}};
        }
        print_json(out);
        return ok ? exit_ok : exit_failure;
    }
    for (const PackFile& file : files) {
        print_diagnostics(stdout, file.file, file.read.diagnostics, language);
        if (file.read.pack) {
            const bo::Pack& pack = *file.read.pack;
            std::println("{}: pack {} version {} ({}): {} keywords, {} words, {} messages, {} "
                         "sentences",
                         file.file, pack.id, pack.version, pack.official ? "official" : "community",
                         pack.keywords.size(), pack.vocabulary.size(), pack.messages.size(),
                         pack.sentences.size());
        }
    }
    if (set) {
        print_diagnostics(stdout, "together with the official packs", set->diagnostics, language);
    }
    std::println("{}", ok ? "ok: the packs read, alone and with the official packs"
                          : "failed: see above");
    return ok ? exit_ok : exit_failure;
}

int cmd_bo_build(const Args& args) {
    const std::string file = args.positional().front();
    const crypto::HashAlg hash = parse_hash(args.get("hash").value_or("sha256"));
    const bo::PackSet set = pack_set(args);
    const bo::Pack* language = message_language(args, given_packs(set));
    const SourceBuild built = build_source(set, file, hash);
    const bo::Compiled& c = built.compiled;
    const bool ok = c.build.has_value();
    std::optional<protocol::ContractDeployBody> body;
    Json j = nullptr;
    if (ok) {
        body = protocol::ContractDeployBody{c.build->code,         c.build->interface, "bo",
                                            bo::compiler_string(), built.bundle_bytes, c.name};
        j = build_json(*body, *built.bundle, c.comments, hash);
        if (const auto out = args.get("out")) {
            const bo::BuiltContract boc{body->code,         body->interface, body->compiler,
                                        built.bundle_bytes, c.name,          hash};
            write_file(*out, unwrap(bo::encode_built(boc), "writing the built contract"), false);
        }
        if (const auto out = args.get("code-out")) {
            write_file(*out, body->code, false);
        }
        if (const auto out = args.get("bundle-out")) {
            write_file(*out, built.bundle_bytes, false);
        }
    }
    std::size_t errors = 0;
    for (const bo::Diagnostic& d : c.diagnostics) {
        errors += d.severity() == bo::Severity::error ? 1U : 0U;
    }

    if (args.json()) {
        Json out = {{"file", file}, {"ok", ok}};
        if (ok) {
            out.update(j);
            out["bounds"] = bounds_json(*c.build);
            out["fuel_limit"] = vm::fuel_limit;
            out["output_limit"] = bo::max_build_output;
            for (const char* key : {"out", "code-out", "bundle-out"}) {
                const auto path = args.get(key);
                std::string name(key);
                std::ranges::replace(name, '-', '_');
                out[name] = path ? Json(*path) : Json(nullptr);
            }
        }
        out["diagnostics"] = diagnostics_json(c.diagnostics, language);
        print_json(out);
        return ok ? exit_ok : exit_failure;
    }
    print_source_diagnostics(stderr, file, c.diagnostics, language);
    if (!ok) {
        std::println("{}: {} error{}", file, errors, errors == 1 ? "" : "s");
        return exit_failure;
    }
    std::println("{}: built contract {} (Bo edition {})", file, c.name, c.edition);
    print_build(*body, j);
    print_bounds(*c.build, args.has("fuel"));
    for (const char* key : {"out", "code-out", "bundle-out"}) {
        if (const auto path = args.get(key)) {
            std::println("  {:<10} {}", "wrote", *path);
        }
    }
    return exit_ok;
}

int cmd_bo_test(const Args& args) {
    const std::string file = args.positional().front();
    const bo::PackSet set = pack_set(args);
    const bo::Pack* language = message_language(args, given_packs(set));
    const std::string source = read_text_file(file);
    const bo::Compiled c = bo::compile(source, set);
    // Tests deploy nothing: the note that comments are published is not
    // theirs.
    std::vector<bo::Diagnostic> problems;
    for (const bo::Diagnostic& d : c.diagnostics) {
        if (d.code != "build.comments") {
            problems.push_back(d);
        }
    }
    std::optional<bo::TestResults> results;
    if (c.build && c.model) {
        results = bo::run_tests(*c.model, *c.build, provider());
    }
    const bool ran = results.has_value();
    const bool passed = ran && results->failed == 0;
    const int status = !ran ? exit_failure : (passed ? exit_ok : exit_not_verified);
    std::string report;
    if (ran) {
        report = bo::test_report(*c.model, *results, source, language);
    }
    if (args.json()) {
        Json out = {{"file", file}, {"ok", passed}, {"built", ran}, {"contract", c.name}};
        if (ran) {
            out["tests"] = tests_json(*c.model, *results, source, language);
            out["total"] = results->tests.size();
            out["passed"] = results->passed;
            out["failed"] = results->failed;
            Json ledgers = Json::object();
            for (const bo::TestLedger& l : results->ledgers) {
                ledgers[bo::wire_name(l.word, l.name)] = to_hex(l.id.bytes());
            }
            out["ledgers"] = ledgers;
            out["text"] = report;
        }
        out["diagnostics"] = diagnostics_json(problems, language);
        print_json(out);
        return status;
    }
    print_source_diagnostics(stderr, file, problems, language);
    if (!ran) {
        std::size_t errors = 0;
        for (const bo::Diagnostic& d : problems) {
            errors += d.severity() == bo::Severity::error ? 1U : 0U;
        }
        std::println("{}: {} error{}: the tests run once the contract builds", file, errors,
                     errors == 1 ? "" : "s");
        return status;
    }
    std::print("{}", report);
    return status;
}

BoDeploy bo_deploy_body(const Args& args, const std::string& file,
                        const crypto::Provider& home_provider, const crypto::HashAlg hash) {
    BoDeploy out;
    if (file.ends_with(".boc")) {
        // Built elsewhere: it must rebuild here to its code, so that the
        // deploy passes everyone's rebuild check.
        if (args.has("pack")) {
            throw UsageError{"a .boc file carries its packs: drop --pack"};
        }
        const bo::BuiltContract built =
            unwrap(bo::decode_built(read_file(file)), file + " is not a built contract (.boc)");
        out.body = protocol::ContractDeployBody{built.code,     built.interface, "bo",
                                                built.compiler, built.source,    built.name};
        const bo::Rebuild rebuilt = bo::rebuild(out.body, home_provider, built.hash);
        if (rebuilt.status != bo::RebuildStatus::rebuilds) {
            throw CommandError{file +
                               " does not rebuild here, so it is not deployed: " + rebuilt.detail};
        }
        bo::SourceBundle bundle = *rebuilt.bundle;
        if (built.hash != hash) {
            // The pack digests under the home's hash, from the same packs.
            const bo::OpenedSource opened =
                bo::open_source_bundle(bundle, home_provider, built.hash);
            bundle = unwrap(bo::make_source_bundle(bundle.source, bundle.edition, *opened.packs,
                                                   home_provider, hash),
                            "the source bundle");
            out.body.source = unwrap(bo::encode_source_bundle(bundle), "the source bundle");
        }
        // The comments are counted again: the .boc does not say.
        const bo::OpenedSource opened = bo::open_source_bundle(bundle, home_provider, hash);
        const bo::Compiled compiled = bo::compile(bundle.source, *opened.packs);
        out.build = build_json(out.body, bundle, compiled.comments, hash);
        return out;
    }
    const bo::PackSet set = pack_set(args);
    const bo::Pack* language = message_language(args, given_packs(set));
    const SourceBuild built = build_source(set, file, hash);
    print_source_diagnostics(stderr, file, built.compiled.diagnostics, language);
    if (!built.compiled.build) {
        throw CommandError{file + " does not build (see above; bo build shows the same)"};
    }
    const bo::Compiled& c = built.compiled;
    out.body = protocol::ContractDeployBody{c.build->code,         c.build->interface, "bo",
                                            bo::compiler_string(), built.bundle_bytes, c.name};
    out.build = build_json(out.body, *built.bundle, c.comments, hash);
    return out;
}

} // namespace cexchain::cli
