// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Bo commands (D-053, step 6): checking Bo source, and the language packs it
// is read with. Built only with the Bo compiler (cexchain::bo: GCC 16, for C++26
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
#include <vector>

#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/names.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>
#include <cexchain/crypto/openssl.hpp>

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
    std::optional<std::string> want = args.get("language");
    if (!want) {
        if (const char* env = std::getenv("CEXCHAIN_LANGUAGE"); env != nullptr && *env != '\0') {
            want = env;
        }
    }
    if (!want) {
        return &bo::english_pack();
    }
    if (const bo::Pack* pack = bo::find_language(bo::official_packs(), *want)) {
        return pack;
    }
    if (const bo::Pack* pack = bo::find_language(extra, *want)) {
        return pack;
    }
    throw UsageError{"no pack for the language " + *want +
                     " (en, zh-Hant-HK, zh-Hans-CN, or a pack given with --pack)"};
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

} // namespace cexchain::cli
