// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Vocabulary packs (vocab.hpp): reading a pack file, with every problem
// reported, and the official packs, compiled in from bo/vocab/ (and their
// carried versions from bo/vocab/history/), whose concepts join the core's
// in the edition's table.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/vocab.hpp>
#include <cexchain/core/cbor.hpp>

#include "internal.hpp"
#include "shape.hpp"

namespace cexchain::bo {

namespace {

using detail::Diagnostics;
using detail::join;
using detail::quote;

#if defined(__clang__)
#pragma clang diagnostic push
// Clang 23 accepts #embed in C++ as an extension of C23's.
#pragma clang diagnostic ignored "-Wc23-extensions"
#endif

constexpr unsigned char commerce_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../vocab/commerce.vocab"
#else
#include "commerce.vocab.inc"
#endif
};
constexpr unsigned char finance_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../vocab/finance.vocab"
#else
#include "finance.vocab.inc"
#endif
};
constexpr unsigned char services_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../vocab/services.vocab"
#else
#include "services.vocab.inc"
#endif
};
constexpr unsigned char commerce_1_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../vocab/history/commerce-1.vocab"
#else
#include "history/commerce-1.vocab.inc"
#endif
};
constexpr unsigned char finance_1_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../vocab/history/finance-1.vocab"
#else
#include "history/finance-1.vocab.inc"
#endif
};
constexpr unsigned char services_1_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../vocab/history/services-1.vocab"
#else
#include "history/services-1.vocab.inc"
#endif
};
// Version 2 of commerce and services, from before a service's periods and
// bills (E9).
constexpr unsigned char commerce_2_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../vocab/history/commerce-2.vocab"
#else
#include "history/commerce-2.vocab.inc"
#endif
};
constexpr unsigned char services_2_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../vocab/history/services-2.vocab"
#else
#include "history/services-2.vocab.inc"
#endif
};

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

std::string_view as_text(std::span<const unsigned char> bytes) noexcept {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

// The current versions first (by id), then the carried ones.
const VocabularyText texts[] = {
    {"commerce", 3, as_text(commerce_bytes)},   {"finance", 2, as_text(finance_bytes)},
    {"services", 3, as_text(services_bytes)},   {"commerce", 1, as_text(commerce_1_bytes)},
    {"finance", 1, as_text(finance_1_bytes)},   {"services", 1, as_text(services_1_bytes)},
    {"commerce", 2, as_text(commerce_2_bytes)}, {"services", 2, as_text(services_2_bytes)},
};
constexpr std::size_t current_count = 3;

// Each category's prefix in concept ids, in enumerator order.
constexpr std::array<std::string_view, 18> category_prefixes{
    "kw",    "kind", "act",  "cond", "price", "charge", "time",  "unit", "cur",
    "round", "doc",  "type", "val",  "field", "state",  "actor", "role", "expr"};
static_assert(category_prefixes.size() == category_names.size());

/// What a user's pack may define; the rest are the compiler's mechanisms.
constexpr std::array<Category, 5> user_categories{Category::action, Category::field,
                                                  Category::state, Category::role, Category::unit};

/// Field types a user's pack may give (Concept::type); official packs also
/// give "offset" and "portion", which mechanisms read.
constexpr std::array<std::string_view, 9> user_types{
    "party", "date", "number", "text", "duration", "parties", "quantity", "list", "amount"};
constexpr std::array<std::string_view, 2> official_only_types{"offset", "portion"};

/// The largest unit scale: a unit is at most 10^15 of its dimension's base
/// unit (bytes, bits per second, items, grams, hundredths of a degree).
constexpr std::uint64_t max_unit_scale = 1'000'000'000'000'000;

std::optional<Vocab> official_vocab(std::string_view id) noexcept {
    for (const Vocab v : {Vocab::finance, Vocab::commerce, Vocab::services}) {
        if (vocab_name(v) == id) {
            return v;
        }
    }
    return std::nullopt;
}

} // namespace

bool detail::valid_vocab_id(std::string_view id) noexcept {
    if (id.empty() || id.size() > 32 || id.front() < 'a' || id.front() > 'z') {
        return false;
    }
    return std::ranges::all_of(
        id, [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'; });
}

namespace {

using detail::valid_vocab_id;

/// The name part of a concept id (after the category's prefix).
bool valid_concept_name(std::string_view name) noexcept {
    if (name.empty() || name.size() > 48) {
        return false;
    }
    const auto letter = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    };
    if (!letter(name.front())) {
        return false;
    }
    return std::ranges::all_of(
        name, [&](char c) { return letter(c) || (c >= '0' && c <= '9') || c == '_'; });
}

std::string_view plain_name(std::string_view id) noexcept {
    const std::size_t dot = id.find('.');
    return dot == std::string_view::npos ? id : id.substr(dot + 1);
}

enum class Mode : std::uint8_t { user, official };

class VocabReader : public detail::ShapeReader {
public:
    explicit VocabReader(Mode mode) : mode_(mode), pack_(std::make_shared<VocabularyPack>()) {}

    std::shared_ptr<VocabularyPack> read(const cbor::Value& root, Bytes canonical,
                                         std::vector<Diagnostic>& out) {
        pack_->canonical = std::move(canonical);
        read_root(root);
        const bool ok = !diagnostics_.has_errors();
        out = diagnostics_.take();
        return ok ? pack_ : nullptr;
    }

private:
    // --- The pack ---

    void read_root(const cbor::Value& root) {
        const cbor::Map* map = map_at(root, ".");
        if (map == nullptr) {
            return;
        }
        const auto top = entries(
            *map, ".",
            {"format", "id", "version", "edition", "requires", "concepts", "terms", "languages"});
        const cbor::Value* format = required(top, ".", "format");
        const cbor::Value* edition_value = required(top, ".", "edition");
        if (format == nullptr || edition_value == nullptr) {
            return;
        }
        const auto format_number = integer_at(*format, "format");
        if (!format_number) {
            return;
        }
        if (*format_number != vocab_format) {
            fail("vocab.format", {{"value", std::to_string(*format_number)}});
            return;
        }
        const auto edition_number = integer_at(*edition_value, "edition");
        if (!edition_number) {
            return;
        }
        if (*edition_number != edition) {
            fail("pack.edition", {{"value", std::to_string(*edition_number)}});
            return;
        }
        pack_->edition = *edition_number;
        // Concept ids carry the pack's id: read it first.
        const cbor::Value* id = required(top, ".", "id");
        if (id == nullptr || !read_id(*id)) {
            return;
        }
        if (const cbor::Value* version = required(top, ".", "version")) {
            if (const auto n = integer_at(*version, "version")) {
                if (*n == 0) {
                    fail("pack.bad-version", {{"value", "0"}});
                }
                pack_->version = *n;
            }
        }
        if (const cbor::Value* needed = find(top, "requires")) {
            read_requires(*needed);
        }
        if (const cbor::Value* concepts = required(top, ".", "concepts")) {
            read_concepts(*concepts);
        }
        if (const cbor::Value* terms = find(top, "terms")) {
            read_terms(*terms);
        }
        if (const cbor::Value* languages = find(top, "languages")) {
            read_languages(*languages);
        } else if (mode_ == Mode::user) {
            // Only the official versions of before pack files are spelled by
            // their release's language packs.
            fail("pack.missing-key", {{"path", "."}, {"key", "languages"}});
        }
    }

    bool read_id(const cbor::Value& value) {
        const std::string* text = text_at(value, "id");
        if (text == nullptr) {
            return false;
        }
        if (!valid_vocab_id(*text)) {
            fail("vocab.bad-id", {{"value", quote(*text)}});
            return false;
        }
        const std::optional<Vocab> official = official_vocab(*text);
        if (mode_ == Mode::user && (official || *text == "core" || *text == "user")) {
            fail("vocab.official-id", {{"value", quote(*text)}});
            return false;
        }
        if (mode_ == Mode::official) {
            if (!official) {
                fail("vocab.bad-id", {{"value", quote(*text)}});
                return false;
            }
            pack_->vocab = *official;
        }
        pack_->id = *text;
        return true;
    }

    void read_requires(const cbor::Value& value) {
        const cbor::Array* list = list_at(value, "requires", 8);
        if (list == nullptr) {
            return;
        }
        for (std::size_t i = 0; i < list->size(); ++i) {
            const std::string path = join("requires", std::to_string(i));
            const std::string* text = text_at((*list)[i], path);
            if (text == nullptr) {
                continue;
            }
            if (!valid_vocab_id(*text) || *text == pack_->id || *text == "core" ||
                std::ranges::contains(pack_->required, *text)) {
                fail("vocab.bad-requires", {{"path", path}, {"value", quote(*text)}});
                continue;
            }
            pack_->required.push_back(*text);
        }
        std::ranges::sort(pack_->required);
    }

    // --- Concepts ---

    void read_concepts(const cbor::Value& value) {
        const cbor::Map* map = map_at(value, "concepts");
        if (map == nullptr) {
            return;
        }
        if (map->empty() || map->size() > max_vocab_concepts) {
            fail("pack.too-many",
                 {{"path", "concepts"}, {"limit", std::to_string(max_vocab_concepts)}});
            return;
        }
        for (const auto& [id, item] : entries(*map, "concepts")) {
            read_concept(id, *item);
        }
        std::ranges::sort(pack_->concepts, {}, &Concept::id);
    }

    void read_concept(std::string_view local, const cbor::Value& value) {
        // A concept that does not read is reported once: its spellings are
        // not reported again.
        failed_.emplace(local);
        const std::string path = join("concepts", local);
        const std::size_t dot = local.find('.');
        const std::string_view prefix = local.substr(0, dot);
        const auto at = std::ranges::find(category_prefixes, prefix);
        if (dot == std::string_view::npos || at == category_prefixes.end() ||
            !valid_concept_name(local.substr(dot + 1))) {
            fail("vocab.bad-concept", {{"path", "concepts"}, {"concept", quote(local)}});
            return;
        }
        const auto category = static_cast<Category>(at - category_prefixes.begin());
        const cbor::Map* map = map_at(value, path);
        if (map == nullptr) {
            return;
        }
        const auto fields = entries(
            *map, path, {"category", "argument", "type", "added", "taking", "dimension", "scale"});
        if (const cbor::Value* written = required(fields, path, "category")) {
            const std::string* name = text_at(*written, join(path, "category"));
            if (name == nullptr) {
                return;
            }
            if (*name != category_name(category)) {
                fail("pack.wrong-category",
                     {{"path", path}, {"concept", std::string(local)}, {"category", quote(*name)}});
                return;
            }
        } else {
            return;
        }
        if (mode_ == Mode::user && !std::ranges::contains(user_categories, category)) {
            fail("vocab.category",
                 {{"path", path}, {"category", std::string(category_name(category))}});
            return;
        }
        if (core_has(local)) {
            fail("vocab.shadows", {{"path", "concepts"},
                                   {"concept", std::string(local)},
                                   {"other", std::string(local)}});
            return;
        }
        Concept c{};
        c.category = category;
        c.arity = 0;
        c.pack = pack_->vocab;
        c.owner = pack_.get();
        if (const cbor::Value* argument = find(fields, "argument")) {
            if (!yes(*argument, join(path, "argument"))) {
                return;
            }
            if (mode_ == Mode::user) {
                fail("vocab.argument", {{"path", path}});
                return;
            }
            c.arity = 1;
        }
        const cbor::Value* type = find(fields, "type");
        if ((category == Category::field) != (type != nullptr)) {
            fail(type == nullptr ? "pack.missing-key" : "pack.unknown-key",
                 {{"path", path}, {"key", "type"}});
            return;
        }
        if (type != nullptr) {
            const std::string* name = text_at(*type, join(path, "type"));
            if (name == nullptr) {
                return;
            }
            const bool known =
                std::ranges::contains(user_types, *name) ||
                (mode_ == Mode::official && std::ranges::contains(official_only_types, *name));
            if (!known) {
                fail("vocab.type", {{"path", join(path, "type")}, {"value", quote(*name)}});
                return;
            }
            c.type = keep(*name);
        }
        for (const auto& [key, flag] :
             {std::pair{"added", field_added}, {"taking", field_taking}}) {
            if (const cbor::Value* written = find(fields, key)) {
                if (!yes(*written, join(path, key))) {
                    return;
                }
                // An official pack's added field may be a date, which holds
                // no date until an action sets it (a service's periods, E9).
                if (c.type != "party" && !(c.type == "date" && key == std::string_view("added") &&
                                           mode_ == Mode::official)) {
                    fail("vocab.flag", {{"path", join(path, key)}});
                    return;
                }
                c.flags = static_cast<std::uint8_t>(c.flags | flag);
            }
        }
        const cbor::Value* dimension = find(fields, "dimension");
        const cbor::Value* scale = find(fields, "scale");
        std::optional<UnitInfo> unit;
        if (category == Category::unit) {
            if (dimension == nullptr || scale == nullptr) {
                fail("pack.missing-key",
                     {{"path", path}, {"key", dimension == nullptr ? "dimension" : "scale"}});
                return;
            }
            const std::string* name = text_at(*dimension, join(path, "dimension"));
            const auto n = integer_at(*scale, join(path, "scale"));
            if (name == nullptr || !n) {
                return;
            }
            const auto d = std::ranges::find(model::dimension_names, *name);
            if (d == model::dimension_names.begin() || d == model::dimension_names.end() ||
                *n == 0 || *n > max_unit_scale) {
                fail("vocab.unit", {{"path", path}});
                return;
            }
            unit =
                UnitInfo{{}, static_cast<model::Dimension>(d - model::dimension_names.begin()), *n};
        } else if (dimension != nullptr || scale != nullptr) {
            fail("pack.unknown-key",
                 {{"path", path}, {"key", dimension != nullptr ? "dimension" : "scale"}});
            return;
        }
        // A user's concepts carry the pack's id; compiled code names them by
        // their plain names, which no core or official word of the category
        // may have.
        const std::string id =
            mode_ == Mode::user ? pack_->id + ":" + std::string(local) : std::string(local);
        if (mode_ == Mode::user) {
            for (const Concept* other : concepts()) {
                if (other->category == category && !other->retired &&
                    plain_name(other->id) == plain_name(local)) {
                    fail("vocab.shadows", {{"path", "concepts"},
                                           {"concept", std::string(local)},
                                           {"other", std::string(other->id)}});
                    return;
                }
            }
        }
        c.id = keep(id);
        failed_.erase(std::string(local));
        Concept& stored = pack_->owned.emplace_back(c);
        pack_->concepts.push_back(&stored);
        if (unit) {
            unit->id = stored.id;
            pack_->units.push_back(*unit);
        }
    }

    [[nodiscard]] bool core_has(std::string_view local) const noexcept {
        return find_core_concept(local) != nullptr;
    }

    /// `true`, the only value a flag is written with.
    bool yes(const cbor::Value& value, const std::string& path) {
        const auto flag = value.as_bool();
        if (!flag) {
            fail("pack.expected-boolean", {{"path", path}});
            return false;
        }
        if (!*flag) {
            fail("pack.bad-value", {{"path", path}, {"value", "false"}});
            return false;
        }
        return true;
    }

    std::string_view keep(std::string text) { return pack_->texts.emplace_back(std::move(text)); }

    const Concept* own(std::string_view local) const noexcept {
        const std::string id =
            mode_ == Mode::user ? pack_->id + ":" + std::string(local) : std::string(local);
        return pack_->find(id);
    }

    // --- Terms ---

    void read_terms(const cbor::Value& value) {
        std::string text;
        if (const std::string* whole = value.as_text()) {
            text = *whole;
        } else if (const cbor::Array* lines = list_at(value, "terms", 4096)) {
            if (lines->empty()) {
                fail("vocab.bad-terms", {{"path", "terms"}});
                return;
            }
            for (std::size_t i = 0; i < lines->size(); ++i) {
                const std::string path = join("terms", std::to_string(i));
                const std::string* line = text_at((*lines)[i], path);
                if (line == nullptr) {
                    return;
                }
                if (line->find_first_of("\r\n") != std::string::npos) {
                    fail("vocab.bad-terms", {{"path", path}});
                    return;
                }
                text += *line;
                text += '\n';
            }
        } else {
            return;
        }
        if (text.empty() || text.size() > max_vocab_terms || text.find('\0') != std::string::npos) {
            fail("vocab.bad-terms", {{"path", "terms"}});
            return;
        }
        pack_->terms = std::move(text);
    }

    // --- Languages ---

    void read_languages(const cbor::Value& value) {
        const cbor::Map* map = map_at(value, "languages");
        if (map == nullptr) {
            return;
        }
        if (map->empty() || map->size() > 16) {
            fail("pack.too-many", {{"path", "languages"}, {"limit", "16"}});
            return;
        }
        for (const auto& [language, item] : entries(*map, "languages")) {
            read_language(language, *item);
        }
        // One spelling, one meaning, across the pack's languages.
        std::map<std::string, const Concept*, std::less<>> seen;
        for (const auto& [language, words] : pack_->languages) {
            for (const auto& [id, word] : words.words) {
                const Concept* c = pack_->find(id);
                std::vector<std::string> all = word.spellings;
                for (const auto& [form, spelling] : word.forms) {
                    all.push_back(spelling);
                }
                for (const std::string& spelling : all) {
                    const auto [it, inserted] = seen.try_emplace(spelling, c);
                    if (!inserted && it->second != c) {
                        fail("vocab.duplicate-spelling", {{"pack", pack_->id},
                                                          {"spelling", quote(spelling)},
                                                          {"concept", std::string(it->second->id)},
                                                          {"other", std::string(c->id)}});
                    }
                }
            }
        }
    }

    void read_language(std::string_view language, const cbor::Value& value) {
        const std::string path = join("languages", language);
        if (!detail::valid_pack_id(language)) {
            fail("vocab.bad-language", {{"value", quote(language)}});
            return;
        }
        const cbor::Map* map = map_at(value, path);
        if (map == nullptr) {
            return;
        }
        const auto fields = entries(*map, path, {"name", "words", "attach"});
        VocabularyLanguage out;
        if (const cbor::Value* name = required(fields, path, "name")) {
            if (const std::string* text = text_at(*name, join(path, "name"))) {
                if (detail::valid_text(*text, 64)) {
                    out.name = *text;
                } else {
                    fail("pack.bad-text", {{"path", join(path, "name")}});
                }
            }
        }
        if (const cbor::Value* words = required(fields, path, "words")) {
            read_words(*words, join(path, "words"), out);
        }
        for (const Concept* c : pack_->concepts) {
            if (!out.words.contains(c->id)) {
                fail("vocab.unspelled",
                     {{"language", std::string(language)}, {"concept", std::string(c->id)}});
            }
        }
        if (const cbor::Value* attach = find(fields, "attach")) {
            read_attach(*attach, join(path, "attach"), out);
        }
        pack_->languages.emplace(std::string(language), std::move(out));
    }

    void read_words(const cbor::Value& value, const std::string& path, VocabularyLanguage& out) {
        const cbor::Map* map = map_at(value, path);
        if (map == nullptr) {
            return;
        }
        for (const auto& [local, item] : entries(*map, path)) {
            const std::string word_path = join(path, local);
            const Concept* entry = own(local);
            if (entry == nullptr) {
                if (!failed_.contains(local)) {
                    fail("vocab.not-own", {{"path", path}, {"concept", quote(local)}});
                }
                continue;
            }
            Word word;
            if (const cbor::Map* forms_map = item->as_map()) {
                const auto parts = entries(*forms_map, word_path, {"word", "forms"});
                if (const cbor::Value* spelled = required(parts, word_path, "word")) {
                    word.spellings = spellings(*spelled, join(word_path, "word"), entry);
                }
                if (const cbor::Value* forms = find(parts, "forms")) {
                    read_forms(*forms, join(word_path, "forms"), entry, word);
                }
            } else {
                word.spellings = spellings(*item, word_path, entry);
            }
            if (!word.spellings.empty()) {
                out.words.emplace(std::string(entry->id), std::move(word));
            }
        }
    }

    void read_attach(const cbor::Value& value, const std::string& path, VocabularyLanguage& out) {
        const cbor::Array* list = list_at(value, path, 16);
        if (list == nullptr) {
            return;
        }
        for (std::size_t i = 0; i < list->size(); ++i) {
            const std::string item_path = join(path, std::to_string(i));
            const cbor::Map* map = map_at((*list)[i], item_path);
            if (map == nullptr) {
                continue;
            }
            const auto fields = entries(*map, item_path, {"word", "before", "after"});
            const cbor::Value* word_value = required(fields, item_path, "word");
            if (word_value == nullptr) {
                continue;
            }
            const std::string* local = text_at(*word_value, join(item_path, "word"));
            if (local == nullptr) {
                continue;
            }
            const Concept* entry = own(*local);
            const auto spelled = entry == nullptr ? out.words.end() : out.words.find(entry->id);
            if (spelled == out.words.end()) {
                fail("vocab.bad-attach", {{"path", item_path}, {"concept", quote(*local)}});
                continue;
            }
            Attachment attachment{std::string(entry->id), {}, {}};
            if (const cbor::Value* before = find(fields, "before")) {
                attachment.before = categories(*before, join(item_path, "before"));
            }
            if (const cbor::Value* after = find(fields, "after")) {
                attachment.after = categories(*after, join(item_path, "after"));
            }
            // As a language pack's: each spelling one word, with the
            // argument's place, if any, on the far side.
            const bool shaped =
                std::ranges::all_of(spelled->second.spellings, [&](const std::string& s) {
                    const auto words = detail::split_words(s);
                    if (words.size() == 1) {
                        return words[0] != hole;
                    }
                    return words.size() == 2 &&
                           attachment.before.empty() != attachment.after.empty() &&
                           (attachment.before.empty() ? words[0] == hole && words[1] != hole
                                                      : words[1] == hole && words[0] != hole);
                });
            if (!shaped || (attachment.before.empty() && attachment.after.empty())) {
                fail("vocab.bad-attach", {{"path", item_path}, {"concept", attachment.word}});
                continue;
            }
            out.attach.push_back(std::move(attachment));
        }
    }

    Mode mode_;
    std::shared_ptr<VocabularyPack> pack_;
    std::set<std::string, std::less<>> failed_;
};

/// Reads a pack's CBOR: within the size limit, in canonical order.
std::shared_ptr<VocabularyPack> read_value(const cbor::Value& value, Mode mode,
                                           std::vector<Diagnostic>& diagnostics) {
    const auto single = [&](std::string_view code, detail::Args args) {
        Diagnostics list;
        list.add(code, args);
        diagnostics = list.take();
        return std::shared_ptr<VocabularyPack>();
    };
    auto canonical = cbor::encode(value);
    if (!canonical) {
        return single("vocab.syntax", {{"detail", std::string(canonical.error().detail)}});
    }
    if (canonical->size() > max_vocab_size) {
        return single("vocab.too-large", {{"size", std::to_string(canonical->size())},
                                          {"limit", std::to_string(max_vocab_size)}});
    }
    cbor::DecodeOptions options;
    options.max_depth = cbor::max_nesting_depth;
    const auto ordered = cbor::decode(*canonical, options);
    if (!ordered) {
        return single("vocab.syntax", {{"detail", std::string(ordered.error().detail)}});
    }
    return VocabReader(mode).read(*ordered, std::move(*canonical), diagnostics);
}

std::shared_ptr<VocabularyPack> read_text(std::string_view text, Mode mode,
                                          std::vector<Diagnostic>& diagnostics) {
    if (text.size() > max_vocab_size) {
        Diagnostics list;
        list.add("vocab.too-large", {{"size", std::to_string(text.size())},
                                     {"limit", std::to_string(max_vocab_size)}});
        diagnostics = list.take();
        return nullptr;
    }
    const auto value = cbor::parse_diagnostic(text);
    if (!value) {
        Diagnostics list;
        list.add("vocab.syntax", {{"detail", std::string(value.error().detail)}});
        diagnostics = list.take();
        return nullptr;
    }
    return read_value(*value, mode, diagnostics);
}

// --- The official packs ---

[[noreturn]] void defect(const VocabularyText& text, std::string_view what) {
    std::fprintf(stderr, "bo: the official vocabulary pack %.*s version %llu %.*s\n",
                 static_cast<int>(text.id.size()), text.id.data(),
                 static_cast<unsigned long long>(text.version), static_cast<int>(what.size()),
                 what.data());
    std::abort();
}

bool same_definition(const Concept& a, const Concept& b) noexcept {
    return a.id == b.id && a.category == b.category && a.arity == b.arity && a.type == b.type &&
           a.flags == b.flags;
}

struct Registry {
    std::vector<std::shared_ptr<VocabularyPack>> all;
    std::vector<const VocabularyPack*> current;
    std::vector<const VocabularyPack*> first;
    /// Version 2 of each, from before a service's periods and bills (E9).
    std::vector<const VocabularyPack*> second;
    /// The core's concepts and the current official packs', by id.
    std::vector<const Concept*> table;
};

Registry make_registry() {
    Registry r;
    for (std::size_t i = 0; i < std::size(texts); ++i) {
        const VocabularyText& text = texts[i];
        std::vector<Diagnostic> diagnostics;
        std::shared_ptr<VocabularyPack> pack = read_text(text.text, Mode::official, diagnostics);
        if (pack == nullptr) {
            for (const Diagnostic& d : diagnostics) {
                std::fprintf(stderr, "  %s %s\n", std::string(d.code).c_str(),
                             d.args.empty() ? "" : d.args[0].second.c_str());
            }
            defect(text, "does not read");
        }
        if (pack->id != text.id || pack->version != text.version) {
            defect(text, "has another id or version");
        }
        if (i < current_count) {
            if (pack->languages.empty()) {
                defect(text, "spells no word");
            }
            r.current.push_back(pack.get());
        } else {
            // A carried version defines some of the current one's concepts,
            // each as the current one does, and its terms begin the current
            // terms (the compiler's table and library hold one meaning per
            // word); it points at the current one's concepts.
            const VocabularyPack* now = nullptr;
            for (const VocabularyPack* p : r.current) {
                if (p->id == pack->id) {
                    now = p;
                }
            }
            if (now == nullptr || !now->terms.starts_with(pack->terms)) {
                defect(text, "differs from the current version in its terms");
            }
            std::vector<const Concept*> mine;
            for (const Concept* c : pack->concepts) {
                const Concept* same = now->find(c->id);
                if (same == nullptr || !same_definition(*same, *c)) {
                    defect(text, "differs from the current version in its concepts");
                }
                mine.push_back(same);
            }
            pack->concepts = std::move(mine);
            pack->owned.clear();
            if (pack->version == 1) {
                r.first.push_back(pack.get());
            }
        }
        r.all.push_back(std::move(pack));
    }
    for (const VocabularyPack* now : r.current) {
        const VocabularyPack* two = now;
        for (const auto& pack : r.all) {
            if (pack->id == now->id && pack->version == 2) {
                two = pack.get();
            }
        }
        if (two->version != 2) {
            std::fprintf(stderr, "bo: the official vocabulary pack %s has no version 2\n",
                         now->id.c_str());
            std::abort();
        }
        r.second.push_back(two);
    }
    for (const Concept& c : core_concepts()) {
        r.table.push_back(&c);
    }
    for (const VocabularyPack* pack : r.current) {
        r.table.insert(r.table.end(), pack->concepts.begin(), pack->concepts.end());
    }
    std::ranges::sort(r.table, {}, &Concept::id);
    if (std::ranges::adjacent_find(r.table, {}, &Concept::id) != r.table.end()) {
        std::fprintf(stderr, "bo: two official concepts have one id\n");
        std::abort();
    }
    return r;
}

const Registry& registry() {
    static const Registry r = make_registry();
    return r;
}

} // namespace

const VocabularyLanguage* VocabularyPack::language(std::string_view language_id) const noexcept {
    const auto it = languages.find(language_id);
    return it == languages.end() ? nullptr : &it->second;
}

const Concept* VocabularyPack::find(std::string_view concept_id) const noexcept {
    const auto it = std::ranges::lower_bound(concepts, concept_id, {}, &Concept::id);
    return it != concepts.end() && (*it)->id == concept_id ? *it : nullptr;
}

const UnitInfo* VocabularyPack::unit(const Concept* c) const noexcept {
    if (c == nullptr) {
        return nullptr;
    }
    const auto it = std::ranges::find(units, c->id, &UnitInfo::id);
    return it == units.end() ? nullptr : &*it;
}

const VocabularyPack* Vocabularies::find(std::string_view id) const noexcept {
    const auto it = std::ranges::find(packs, id, &VocabularyPack::id);
    return it == packs.end() ? nullptr : *it;
}

const Concept* Vocabularies::find_concept(std::string_view id) const noexcept {
    const std::size_t colon = id.find(':');
    if (colon == std::string_view::npos) {
        return nullptr;
    }
    for (const VocabularyHandle& pack : users) {
        if (pack->id == id.substr(0, colon)) {
            return pack->find(id);
        }
    }
    return nullptr;
}

VocabularyRead read_vocabulary_pack(std::string_view text) {
    VocabularyRead out;
    out.pack = read_text(text, Mode::user, out.diagnostics);
    return out;
}

VocabularyRead read_vocabulary_pack(const cbor::Value& value) {
    VocabularyRead out;
    out.pack = read_value(value, Mode::user, out.diagnostics);
    return out;
}

std::span<const Concept* const> concepts() noexcept {
    return registry().table;
}

const Concept* find_concept(std::string_view id) noexcept {
    const std::vector<const Concept*>& table = registry().table;
    const auto it = std::ranges::lower_bound(table, id, {}, &Concept::id);
    return it != table.end() && (*it)->id == id ? *it : nullptr;
}

std::span<const VocabularyPack* const> vocabulary_packs() noexcept {
    return registry().current;
}

std::span<const VocabularyPack* const> vocabulary_packs(const Officials officials) noexcept {
    switch (officials) {
    case Officials::current:
        return registry().current;
    case Officials::before_billing:
    case Officials::before_requests:
        return registry().second;
    case Officials::before_pack_files:
    case Officials::before_temperature:
        return registry().first;
    case Officials::before_vocabulary:
        break;
    }
    return {};
}

const VocabularyPack* find_vocabulary_pack(std::string_view id) noexcept {
    for (const VocabularyPack* pack : registry().current) {
        if (pack->id == id) {
            return pack;
        }
    }
    return nullptr;
}

const VocabularyPack* find_vocabulary_pack(std::string_view id,
                                           const std::uint64_t version) noexcept {
    for (const auto& pack : registry().all) {
        if (pack->id == id && pack->version == version) {
            return pack.get();
        }
    }
    return nullptr;
}

const VocabularyPack* vocabulary_pack(const Vocab vocab) noexcept {
    return vocab == Vocab::core || vocab == Vocab::user ? nullptr
                                                        : find_vocabulary_pack(vocab_name(vocab));
}

std::span<const VocabularyText> official_vocabulary_texts() noexcept {
    return texts;
}

std::string_view pack_of(const Concept& c) noexcept {
    return c.owner != nullptr ? std::string_view(c.owner->id) : vocab_name(Vocab::core);
}

std::string vocabulary_name(const VocabularyPack& pack, const Pack* language) {
    if (pack.languages.empty()) {
        const std::string id = "vocab-" + pack.id;
        std::string name = sentence(id, {}, language);
        return name == id ? pack.id : name;
    }
    for (const std::string_view id :
         {language != nullptr ? std::string_view(language->id) : std::string_view("en"),
          std::string_view("en")}) {
        if (const VocabularyLanguage* words = pack.language(id)) {
            return words->name;
        }
    }
    return pack.languages.begin()->second.name;
}

Result<crypto::Digest> digest(const VocabularyPack& pack, const crypto::Provider& provider,
                              crypto::HashAlg alg) {
    return provider.digest(alg, pack.canonical);
}

const Word* concept_word(const Concept* c, const Pack* language) noexcept {
    if (c == nullptr) {
        return nullptr;
    }
    const auto in = [&](const Pack* pack) -> const Word* {
        if (pack == nullptr) {
            return nullptr;
        }
        if (const Word* w = pack->word(c->id); w != nullptr && !w->spellings.empty()) {
            return w;
        }
        if (c->owner != nullptr) {
            if (const VocabularyLanguage* words = c->owner->language(pack->id)) {
                if (const auto it = words->words.find(c->id); it != words->words.end()) {
                    return &it->second;
                }
            }
        }
        return nullptr;
    };
    if (const Word* w = in(language)) {
        return w;
    }
    if (const Word* w = in(&english_pack())) {
        return w;
    }
    if (c->owner != nullptr && !c->owner->languages.empty()) {
        const auto& words = c->owner->languages.begin()->second.words;
        if (const auto it = words.find(c->id); it != words.end()) {
            return &it->second;
        }
    }
    return nullptr;
}

namespace detail {

void merge_vocabulary(Pack& language, const VocabularyPack& pack) {
    const VocabularyLanguage* words = pack.language(language.id);
    if (words == nullptr) {
        return;
    }
    for (const auto& [id, word] : words->words) {
        language.vocabulary.emplace(id, word);
    }
    language.reading.attach.insert(language.reading.attach.end(), words->attach.begin(),
                                   words->attach.end());
}

} // namespace detail

} // namespace cexchain::bo
