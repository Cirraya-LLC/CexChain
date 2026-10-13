// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Reading a language pack: its shape, its spellings, and its reading rules,
// with every problem reported (up to max_diagnostics) rather than the first.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/bo/pack.hpp>
#include <cexchain/core/cbor.hpp>

#include "internal.hpp"

namespace cexchain::bo {

namespace {

using detail::Diagnostics;
using detail::quote;

std::string join(std::string_view path, std::string_view key) {
    if (path.empty() || path == ".") {
        return std::string(key);
    }
    return std::string(path) + "/" + std::string(key);
}

std::string key_text(const cbor::Value& key) {
    if (const std::string* text = key.as_text()) {
        return quote(*text);
    }
    return quote(cbor::diagnostic(key));
}

bool is_ascii_letter(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool is_ascii_alnum(char c) noexcept {
    return is_ascii_letter(c) || (c >= '0' && c <= '9');
}

/// Letters, digits, and hyphens, starting with a letter; at most 64.
bool valid_id(std::string_view id) noexcept {
    if (id.empty() || id.size() > 64 || !is_ascii_letter(id.front()) || id.back() == '-') {
        return false;
    }
    char previous = 0;
    for (const char c : id) {
        if (!is_ascii_alnum(c) && c != '-') {
            return false;
        }
        if (c == '-' && previous == '-') {
            return false;
        }
        previous = c;
    }
    return true;
}

/// BCP 47 in its common shape: a language of 2 to 8 letters, then subtags
/// of 1 to 8 letters or digits.
bool valid_language(std::string_view tag) noexcept {
    if (tag.size() > 64) {
        return false;
    }
    bool first = true;
    while (true) {
        const std::size_t dash = tag.find('-');
        const std::string_view subtag = tag.substr(0, dash);
        if (subtag.empty() || subtag.size() > 8 || (first && subtag.size() < 2)) {
            return false;
        }
        for (const char c : subtag) {
            if (first ? !is_ascii_letter(c) : !is_ascii_alnum(c)) {
                return false;
            }
        }
        if (dash == std::string_view::npos) {
            return true;
        }
        tag.remove_prefix(dash + 1);
        first = false;
    }
}

/// Text for people: 1 to `max` bytes, no control characters.
bool valid_text(std::string_view text, std::size_t max) noexcept {
    if (text.empty() || text.size() > max) {
        return false;
    }
    return std::ranges::none_of(text, [](char c) {
        const auto u = static_cast<unsigned char>(c);
        return u < 0x20 || u == 0x7F;
    });
}

bool lowercase_name(std::string_view name, std::size_t max) noexcept {
    return !name.empty() && name.size() <= max &&
           std::ranges::all_of(name, [](char c) { return (c >= 'a' && c <= 'z') || c == '_'; });
}

/// The ASCII characters punctuation aliases may stand for.
constexpr std::string_view alias_targets = ",:()%0123456789 \"=<>+-*/._";

class Reader {
public:
    PackRead read(const cbor::Value& root, Bytes canonical) {
        pack_.canonical = std::move(canonical);
        read_root(root);
        // Past the format and edition, every problem is worth reporting.
        if (structured_) {
            check_completeness();
            const Pack* packs[] = {&pack_};
            std::map<std::string, Meaning, std::less<>> index;
            detail::index_spellings(packs, index, diagnostics_);
        }
        PackRead out;
        const bool ok = !diagnostics_.has_errors();
        out.diagnostics = diagnostics_.take();
        if (ok) {
            out.pack = std::move(pack_);
        }
        return out;
    }

    void fail(std::string_view code, detail::Args args) { diagnostics_.add(code, args); }

private:
    // --- Shapes ---

    const cbor::Map* map_at(const cbor::Value& value, std::string_view path) {
        const cbor::Map* map = value.as_map();
        if (map == nullptr) {
            fail("pack.expected-map", {{"path", std::string(path)}});
        }
        return map;
    }

    const std::string* text_at(const cbor::Value& value, std::string_view path) {
        const std::string* text = value.as_text();
        if (text == nullptr) {
            fail("pack.expected-text", {{"path", std::string(path)}});
        }
        return text;
    }

    const cbor::Array* list_at(const cbor::Value& value, std::string_view path, std::size_t limit) {
        const cbor::Array* list = value.as_array();
        if (list == nullptr) {
            fail("pack.expected-list", {{"path", std::string(path)}});
            return nullptr;
        }
        if (list->size() > limit) {
            fail("pack.too-many", {{"path", std::string(path)}, {"limit", std::to_string(limit)}});
            return nullptr;
        }
        return list;
    }

    std::optional<std::uint64_t> integer_at(const cbor::Value& value, std::string_view path) {
        const auto n = value.as_uint64();
        if (!n) {
            fail("pack.expected-integer", {{"path", std::string(path)}});
        }
        return n;
    }

    /// A map's entries with text keys; other keys are reported. Keys not in
    /// `known` (when given) are reported too.
    std::vector<std::pair<std::string_view, const cbor::Value*>>
    entries(const cbor::Map& map, std::string_view path,
            std::initializer_list<std::string_view> known = {}) {
        std::vector<std::pair<std::string_view, const cbor::Value*>> out;
        for (const cbor::MapEntry& entry : map) {
            const std::string* key = entry.key.as_text();
            if (key == nullptr ||
                (known.size() > 0 && std::ranges::find(known, *key) == known.end())) {
                fail("pack.unknown-key",
                     {{"path", std::string(path)}, {"key", key_text(entry.key)}});
                continue;
            }
            out.emplace_back(*key, &entry.value);
        }
        return out;
    }

    static const cbor::Value*
    find(const std::vector<std::pair<std::string_view, const cbor::Value*>>& list,
         std::string_view key) {
        const auto it =
            std::ranges::find(list, key, &std::pair<std::string_view, const cbor::Value*>::first);
        return it == list.end() ? nullptr : it->second;
    }

    const cbor::Value*
    required(const std::vector<std::pair<std::string_view, const cbor::Value*>>& list,
             std::string_view path, std::string_view key) {
        const cbor::Value* value = find(list, key);
        if (value == nullptr) {
            fail("pack.missing-key", {{"path", std::string(path)}, {"key", std::string(key)}});
        }
        return value;
    }

    // --- The pack ---

    void read_root(const cbor::Value& root) {
        const cbor::Map* map = map_at(root, ".");
        if (map == nullptr) {
            return;
        }
        const auto top =
            entries(*map, ".",
                    {"format", "id", "version", "language", "name", "official", "edition",
                     "reading", "keywords", "vocabulary", "messages", "sentences"});
        // The format and edition decide how to read the rest.
        const cbor::Value* format = required(top, ".", "format");
        const cbor::Value* edition_value = required(top, ".", "edition");
        if (format == nullptr || edition_value == nullptr) {
            return;
        }
        const auto format_number = integer_at(*format, "format");
        if (!format_number) {
            return;
        }
        if (*format_number != pack_format) {
            fail("pack.format", {{"value", std::to_string(*format_number)}});
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
        pack_.edition = *edition_number;
        structured_ = true;

        if (const cbor::Value* id = required(top, ".", "id")) {
            if (const std::string* text = text_at(*id, "id")) {
                if (valid_id(*text)) {
                    pack_.id = *text;
                } else {
                    fail("pack.bad-id", {{"value", quote(*text)}});
                }
            }
        }
        if (const cbor::Value* version = required(top, ".", "version")) {
            if (const auto n = integer_at(*version, "version")) {
                if (*n == 0) {
                    fail("pack.bad-version", {{"value", "0"}});
                }
                pack_.version = *n;
            }
        }
        if (const cbor::Value* language = required(top, ".", "language")) {
            if (const std::string* text = text_at(*language, "language")) {
                if (valid_language(*text)) {
                    pack_.language = *text;
                } else {
                    fail("pack.bad-language", {{"value", quote(*text)}});
                }
            }
        }
        if (const cbor::Value* name = required(top, ".", "name")) {
            if (const std::string* text = text_at(*name, "name")) {
                if (valid_text(*text, 200)) {
                    pack_.name = *text;
                } else {
                    fail("pack.bad-text", {{"path", "name"}});
                }
            }
        }
        if (const cbor::Value* official = required(top, ".", "official")) {
            if (const auto flag = official->as_bool()) {
                pack_.official = *flag;
            } else {
                fail("pack.expected-boolean", {{"path", "official"}});
            }
        }
        // Reading rules refer to keywords and vocabulary: read those first.
        if (const cbor::Value* keywords = required(top, ".", "keywords")) {
            read_words(*keywords, "keywords", true);
        }
        if (const cbor::Value* vocabulary = find(top, "vocabulary")) {
            read_words(*vocabulary, "vocabulary", false);
        }
        if (const cbor::Value* reading = required(top, ".", "reading")) {
            read_reading(*reading);
        }
        if (const cbor::Value* messages = find(top, "messages")) {
            read_texts(*messages, "messages", false);
        }
        if (const cbor::Value* sentences = find(top, "sentences")) {
            read_texts(*sentences, "sentences", true);
        }
    }

    // --- Spellings ---

    /// Checks one spelling of a concept (or of a multiplier, with no
    /// concept). Returns false if it is not usable.
    bool check(std::string_view spelling, std::string_view path, const Concept* entry) {
        const detail::SpellingCheck check = detail::check_spelling(spelling);
        if (check.problem == detail::SpellingProblem::bad_character) {
            fail("pack.bad-character", {{"path", std::string(path)},
                                        {"spelling", quote(spelling)},
                                        {"character", detail::describe_char(check.character)}});
            return false;
        }
        if (check.problem != detail::SpellingProblem::none) {
            fail("pack.bad-spelling", {{"path", std::string(path)}, {"spelling", quote(spelling)}});
            return false;
        }
        const std::size_t arity = entry == nullptr ? 0 : entry->arity;
        if (check.holes != arity) {
            const std::string concept_id = entry == nullptr ? "" : std::string(entry->id);
            fail(arity > 0 ? "pack.needs-hole" : "pack.unexpected-hole",
                 {{"path", std::string(path)},
                  {"spelling", quote(spelling)},
                  {"concept", concept_id}});
            return false;
        }
        return true;
    }

    /// A text or a list of texts: the spellings of one concept.
    std::vector<std::string> spellings(const cbor::Value& value, std::string_view path,
                                       const Concept* entry) {
        std::vector<std::string> out;
        if (const std::string* text = value.as_text()) {
            if (check(*text, path, entry)) {
                out.push_back(*text);
            }
            return out;
        }
        const cbor::Array* list = value.as_array();
        if (list == nullptr || list->empty()) {
            fail("pack.expected-text", {{"path", std::string(path)}});
            return out;
        }
        if (list->size() > 8) {
            fail("pack.too-many", {{"path", std::string(path)}, {"limit", "8"}});
            return out;
        }
        for (std::size_t i = 0; i < list->size(); ++i) {
            const std::string item_path = join(path, std::to_string(i));
            if (const std::string* text = text_at((*list)[i], item_path)) {
                if (check(*text, item_path, entry)) {
                    out.push_back(*text);
                }
            }
        }
        return out;
    }

    void read_words(const cbor::Value& value, std::string_view section, bool keywords) {
        const cbor::Map* map = map_at(value, section);
        if (map == nullptr) {
            return;
        }
        for (const auto& [id, item] : entries(*map, section)) {
            const std::string path = join(section, id);
            const Concept* entry = find_concept(id);
            if (entry == nullptr) {
                fail("pack.unknown-concept",
                     {{"path", std::string(section)}, {"concept", quote(id)}});
                continue;
            }
            if ((entry->category == Category::keyword) != keywords) {
                fail("pack.wrong-category",
                     {{"path", std::string(section)},
                      {"concept", std::string(id)},
                      {"category", std::string(category_name(entry->category))}});
                continue;
            }
            Word word;
            if (const cbor::Map* forms_map = item->as_map(); forms_map != nullptr && !keywords) {
                const auto fields = entries(*forms_map, path, {"word", "forms"});
                if (const cbor::Value* spelled = required(fields, path, "word")) {
                    word.spellings = spellings(*spelled, join(path, "word"), entry);
                }
                if (const cbor::Value* forms = find(fields, "forms")) {
                    read_forms(*forms, join(path, "forms"), entry, word);
                }
            } else {
                word.spellings = spellings(*item, path, entry);
            }
            if (!word.spellings.empty()) {
                (keywords ? pack_.keywords : pack_.vocabulary)
                    .emplace(std::string(id), std::move(word));
            }
        }
    }

    void read_forms(const cbor::Value& value, const std::string& path, const Concept* entry,
                    Word& word) {
        const cbor::Map* map = map_at(value, path);
        if (map == nullptr) {
            return;
        }
        if (map->size() > 8) {
            fail("pack.too-many", {{"path", path}, {"limit", "8"}});
            return;
        }
        for (const auto& [name, item] : entries(*map, path)) {
            const std::string form_path = join(path, name);
            if (!lowercase_name(name, 16) || name.find('_') != std::string_view::npos) {
                fail("pack.bad-form", {{"path", path}, {"form", quote(name)}});
                continue;
            }
            if (const std::string* text = text_at(*item, form_path)) {
                if (check(*text, form_path, entry)) {
                    word.forms.emplace(std::string(name), *text);
                }
            }
        }
    }

    // --- Reading rules ---

    void read_reading(const cbor::Value& value) {
        const cbor::Map* map = map_at(value, "reading");
        if (map == nullptr) {
            return;
        }
        const auto fields =
            entries(*map, "reading",
                    {"separation", "prefixes", "attach", "punctuation", "multipliers", "dates"});
        if (const cbor::Value* separation = required(fields, "reading", "separation")) {
            if (const std::string* text = text_at(*separation, "reading/separation")) {
                const auto it = std::ranges::find(separation_names, *text);
                if (it == separation_names.end()) {
                    fail("pack.bad-value",
                         {{"path", "reading/separation"}, {"value", quote(*text)}});
                } else {
                    pack_.reading.separation =
                        static_cast<Separation>(it - separation_names.begin());
                }
            }
        }
        if (const cbor::Value* prefixes = find(fields, "prefixes")) {
            read_prefixes(*prefixes);
        }
        if (const cbor::Value* attach = find(fields, "attach")) {
            read_attach(*attach);
        }
        if (const cbor::Value* punctuation = find(fields, "punctuation")) {
            read_punctuation(*punctuation);
        }
        if (const cbor::Value* multipliers = find(fields, "multipliers")) {
            read_multipliers(*multipliers);
        }
        if (const cbor::Value* dates = find(fields, "dates")) {
            read_dates(*dates);
        }
    }

    /// A concept named by a reading rule: known, of an allowed category,
    /// and spelled by this pack.
    const Word* rule_word(const cbor::Value& value, const std::string& path, bool keyword) {
        const std::string* id = text_at(value, path);
        if (id == nullptr) {
            return nullptr;
        }
        const Concept* entry = find_concept(*id);
        if (entry == nullptr) {
            fail("pack.unknown-concept", {{"path", path}, {"concept", quote(*id)}});
            return nullptr;
        }
        if ((entry->category == Category::keyword) != keyword) {
            fail("pack.wrong-category",
                 {{"path", path},
                  {"concept", *id},
                  {"category", std::string(category_name(entry->category))}});
            return nullptr;
        }
        const Word* word = pack_.word(*id);
        if (word == nullptr) {
            fail("pack.bad-attach", {{"path", path}, {"concept", *id}});
        }
        return word;
    }

    void read_prefixes(const cbor::Value& value) {
        const cbor::Array* list = list_at(value, "reading/prefixes", 16);
        if (list == nullptr) {
            return;
        }
        for (std::size_t i = 0; i < list->size(); ++i) {
            const std::string path = join("reading/prefixes", std::to_string(i));
            const Word* word = rule_word((*list)[i], path, true);
            if (word == nullptr) {
                continue;
            }
            // A prefix is one word.
            if (std::ranges::any_of(word->spellings, [](const std::string& s) {
                    return s.find(' ') != std::string::npos;
                })) {
                fail("pack.bad-attach", {{"path", path}, {"concept", *(*list)[i].as_text()}});
                continue;
            }
            pack_.reading.prefixes.push_back(*(*list)[i].as_text());
        }
    }

    std::vector<Category> categories(const cbor::Value& value, const std::string& path) {
        std::vector<Category> out;
        const cbor::Array* list = list_at(value, path, category_names.size());
        if (list == nullptr) {
            return out;
        }
        for (std::size_t i = 0; i < list->size(); ++i) {
            const std::string item_path = join(path, std::to_string(i));
            const std::string* name = text_at((*list)[i], item_path);
            if (name == nullptr) {
                continue;
            }
            const auto category = category_from_name(*name);
            if (!category || *category == Category::keyword) {
                fail("pack.unknown-category", {{"path", item_path}, {"category", quote(*name)}});
                continue;
            }
            if (std::ranges::find(out, *category) == out.end()) {
                out.push_back(*category);
            }
        }
        return out;
    }

    void read_attach(const cbor::Value& value) {
        const cbor::Array* list = list_at(value, "reading/attach", 16);
        if (list == nullptr) {
            return;
        }
        for (std::size_t i = 0; i < list->size(); ++i) {
            const std::string path = join("reading/attach", std::to_string(i));
            const cbor::Map* map = map_at((*list)[i], path);
            if (map == nullptr) {
                continue;
            }
            const auto fields = entries(*map, path, {"word", "before", "after"});
            const cbor::Value* word_value = required(fields, path, "word");
            if (word_value == nullptr) {
                continue;
            }
            const std::string word_path = join(path, "word");
            const Word* word = rule_word(*word_value, word_path, false);
            if (word == nullptr) {
                continue;
            }
            Attachment attachment{*word_value->as_text(), {}, {}};
            if (const cbor::Value* before = find(fields, "before")) {
                attachment.before = categories(*before, join(path, "before"));
            }
            if (const cbor::Value* after = find(fields, "after")) {
                attachment.after = categories(*after, join(path, "after"));
            }
            // Each spelling is one word, with the argument's place, if any,
            // on the far side: "每" or "每 …" before; "內" or "… 內" after.
            const bool shaped = std::ranges::all_of(word->spellings, [&](const std::string& s) {
                const auto words = detail::split_words(s);
                if (words.size() == 1) {
                    return words[0] != hole;
                }
                return words.size() == 2 && attachment.before.empty() != attachment.after.empty() &&
                       (attachment.before.empty() ? words[0] == hole && words[1] != hole
                                                  : words[1] == hole && words[0] != hole);
            });
            if (!shaped || (attachment.before.empty() && attachment.after.empty())) {
                fail("pack.bad-attach", {{"path", path}, {"concept", attachment.word}});
                continue;
            }
            pack_.reading.attach.push_back(std::move(attachment));
        }
    }

    void read_punctuation(const cbor::Value& value) {
        const cbor::Map* map = map_at(value, "reading/punctuation");
        if (map == nullptr) {
            return;
        }
        if (map->size() > 64) {
            fail("pack.too-many", {{"path", "reading/punctuation"}, {"limit", "64"}});
            return;
        }
        for (const auto& [key, item] : entries(*map, "reading/punctuation")) {
            const std::string path = join("reading/punctuation", key);
            const auto points = detail::code_points(key);
            const std::string* target = text_at(*item, path);
            if (target == nullptr) {
                continue;
            }
            // One character that no word may contain, for one ASCII
            // character: aliases can then never change how a word reads.
            if (!points || points->size() != 1 || (*points)[0] < 0x80 ||
                detail::is_word_char((*points)[0])) {
                fail("pack.bad-punctuation",
                     {{"path", "reading/punctuation"}, {"character", quote(key)}});
                continue;
            }
            if (target->size() != 1 || alias_targets.find((*target)[0]) == std::string_view::npos) {
                fail("pack.bad-punctuation", {{"path", path}, {"character", quote(*target)}});
                continue;
            }
            pack_.reading.punctuation.emplace(std::string(key), (*target)[0]);
        }
    }

    void read_multipliers(const cbor::Value& value) {
        const cbor::Map* map = map_at(value, "reading/multipliers");
        if (map == nullptr) {
            return;
        }
        if (map->size() > 16) {
            fail("pack.too-many", {{"path", "reading/multipliers"}, {"limit", "16"}});
            return;
        }
        for (const auto& [key, item] : entries(*map, "reading/multipliers")) {
            const std::string path = join("reading/multipliers", key);
            if (!check(key, "reading/multipliers", nullptr)) {
                continue;
            }
            if (key.find(' ') != std::string_view::npos) {
                fail("pack.bad-spelling",
                     {{"path", "reading/multipliers"}, {"spelling", quote(key)}});
                continue;
            }
            const auto n = integer_at(*item, path);
            if (!n) {
                continue;
            }
            // A power of ten, 10 to 10^18, so decimals stay exact (1.5萬).
            std::uint64_t power = 10;
            bool ok = false;
            for (int i = 1; i <= 18; ++i, power *= 10) {
                if (*n == power) {
                    ok = true;
                    break;
                }
            }
            if (!ok) {
                fail("pack.bad-multiplier", {{"path", path}, {"value", std::to_string(*n)}});
                continue;
            }
            pack_.reading.multipliers.emplace(std::string(key), *n);
        }
    }

    /// A date pattern: {Y}, {M} or (to write) {MONTH}, and {D}, once each,
    /// with literal text between them.
    bool date_pattern(std::string_view pattern, bool write) {
        if (!valid_text(pattern, 64)) {
            return false;
        }
        std::map<std::string_view, int> seen;
        bool after_field = false;
        for (std::size_t i = 0; i < pattern.size();) {
            if (pattern[i] == '}') {
                return false;
            }
            if (pattern[i] != '{') {
                // Literal text; digits would run into the numbers.
                if (pattern[i] >= '0' && pattern[i] <= '9') {
                    return false;
                }
                if (!write && pattern[i] == ' ') {
                    return false;
                }
                after_field = false;
                ++i;
                continue;
            }
            const std::size_t close = pattern.find('}', i);
            if (close == std::string_view::npos || after_field) {
                return false;
            }
            const std::string_view field = pattern.substr(i + 1, close - i - 1);
            if (field != "Y" && field != "M" && field != "D" && !(write && field == "MONTH")) {
                return false;
            }
            ++seen[field == "MONTH" ? "M" : field];
            after_field = true;
            i = close + 1;
        }
        return seen.size() == 3 && seen["Y"] == 1 && seen["M"] == 1 && seen["D"] == 1;
    }

    void read_dates(const cbor::Value& value) {
        const cbor::Map* map = map_at(value, "reading/dates");
        if (map == nullptr) {
            return;
        }
        const auto fields = entries(*map, "reading/dates", {"read", "write", "months"});
        DateForms& dates = pack_.reading.dates;
        if (const cbor::Value* read = find(fields, "read")) {
            if (const cbor::Array* list = list_at(*read, "reading/dates/read", 8)) {
                for (std::size_t i = 0; i < list->size(); ++i) {
                    const std::string path = join("reading/dates/read", std::to_string(i));
                    if (const std::string* pattern = text_at((*list)[i], path)) {
                        if (date_pattern(*pattern, false)) {
                            dates.read.push_back(*pattern);
                        } else {
                            fail("pack.bad-date", {{"path", path}, {"pattern", quote(*pattern)}});
                        }
                    }
                }
            }
        }
        if (const cbor::Value* write = required(fields, "reading/dates", "write")) {
            if (const std::string* pattern = text_at(*write, "reading/dates/write")) {
                if (date_pattern(*pattern, true)) {
                    dates.write = *pattern;
                } else {
                    fail("pack.bad-date",
                         {{"path", "reading/dates/write"}, {"pattern", quote(*pattern)}});
                }
            }
        }
        if (const cbor::Value* months = find(fields, "months")) {
            if (const cbor::Array* list = list_at(*months, "reading/dates/months", 12)) {
                for (std::size_t i = 0; i < list->size(); ++i) {
                    const std::string path = join("reading/dates/months", std::to_string(i));
                    if (const std::string* name = text_at((*list)[i], path)) {
                        if (valid_text(*name, 64)) {
                            dates.months.push_back(*name);
                        } else {
                            fail("pack.bad-text", {{"path", path}});
                        }
                    }
                }
            }
        }
        // Month names exactly when the written form asks for them.
        const bool named = dates.write.find("{MONTH}") != std::string::npos;
        if (named ? dates.months.size() != 12 : !dates.months.empty()) {
            fail("pack.bad-date",
                 {{"path", "reading/dates/months"}, {"pattern", quote(dates.write)}});
        }
    }

    // --- Messages and sentences ---

    /// Checks a text's placeholders against the parameters it may use.
    bool placeholders(std::string_view text, std::string_view params, const std::string& path,
                      bool forms) {
        for (std::size_t i = 0; i < text.size(); ++i) {
            if (text[i] == '}') {
                fail("pack.bad-placeholder", {{"path", path}, {"placeholder", "}"}});
                return false;
            }
            if (text[i] != '{') {
                continue;
            }
            const std::size_t close = text.find('}', i);
            if (close == std::string_view::npos) {
                fail("pack.bad-placeholder", {{"path", path}, {"placeholder", "{"}});
                return false;
            }
            const std::string_view inside = text.substr(i + 1, close - i - 1);
            const std::size_t dot = inside.find('.');
            const std::string_view name = inside.substr(0, dot);
            const bool form_ok = dot == std::string_view::npos ||
                                 (forms && lowercase_name(inside.substr(dot + 1), 16) &&
                                  inside.substr(dot + 1).find('_') == std::string_view::npos);
            if (!lowercase_name(name, 32) || !has_param(params, name) || !form_ok) {
                fail("pack.bad-placeholder", {{"path", path}, {"placeholder", quote(inside)}});
                return false;
            }
            i = close;
        }
        return true;
    }

    void read_texts(const cbor::Value& value, std::string_view section, bool sentences) {
        const cbor::Map* map = map_at(value, section);
        if (map == nullptr) {
            return;
        }
        for (const auto& [key, item] : entries(*map, section)) {
            const std::string path = join(section, key);
            std::string_view params;
            if (sentences) {
                const SentenceSpec* spec = find_sentence(key);
                if (spec == nullptr) {
                    fail("pack.unknown-sentence",
                         {{"path", std::string(section)}, {"id", quote(key)}});
                    continue;
                }
                params = spec->params;
            } else {
                const MessageSpec* spec = find_message(key);
                if (spec == nullptr) {
                    fail("pack.unknown-message",
                         {{"path", std::string(section)}, {"code", quote(key)}});
                    continue;
                }
                params = spec->params;
            }
            const std::string* text = text_at(*item, path);
            if (text == nullptr) {
                continue;
            }
            if (!valid_text(*text, 1000)) {
                fail("pack.bad-text", {{"path", path}});
                continue;
            }
            if (!placeholders(*text, params, path, sentences)) {
                continue;
            }
            (sentences ? pack_.sentences : pack_.messages).emplace(std::string(key), *text);
        }
    }

    // --- The whole ---

    void check_completeness() {
        std::size_t missing = 0;
        std::size_t total = 0;
        for (const Concept& entry : concepts()) {
            if (entry.category == Category::keyword) {
                if (!pack_.keywords.contains(entry.id)) {
                    fail("pack.missing-keyword",
                         {{"pack", pack_.id}, {"concept", std::string(entry.id)}});
                }
                continue;
            }
            ++total;
            if (!pack_.vocabulary.contains(entry.id)) {
                ++missing;
            }
        }
        if (missing > 0) {
            fail("pack.partial", {{"pack", pack_.id},
                                  {"missing", std::to_string(missing)},
                                  {"total", std::to_string(total)}});
        }
    }

    Pack pack_;
    Diagnostics diagnostics_;
    bool structured_ = false;
};

PackRead single_failure(std::string_view code, detail::Args args) {
    Diagnostics diagnostics;
    diagnostics.add(code, args);
    return PackRead{std::nullopt, diagnostics.take()};
}

} // namespace

Severity Diagnostic::severity() const noexcept {
    const MessageSpec* spec = find_message(code);
    BO_ASSERT(spec != nullptr);
    return spec == nullptr ? Severity::error : spec->severity;
}

std::string_view Diagnostic::arg(std::string_view name) const noexcept {
    for (const auto& [key, value] : args) {
        if (key == name) {
            return value;
        }
    }
    return {};
}

bool has_errors(std::span<const Diagnostic> diagnostics) noexcept {
    return std::ranges::any_of(diagnostics,
                               [](const Diagnostic& d) { return d.severity() == Severity::error; });
}

const Word* Pack::word(std::string_view concept_id) const noexcept {
    if (const auto it = keywords.find(concept_id); it != keywords.end()) {
        return &it->second;
    }
    if (const auto it = vocabulary.find(concept_id); it != vocabulary.end()) {
        return &it->second;
    }
    return nullptr;
}

PackRead read_pack(const std::string_view text) {
    if (text.size() > max_pack_size) {
        return single_failure("pack.too-large", {{"size", std::to_string(text.size())},
                                                 {"limit", std::to_string(max_pack_size)}});
    }
    const auto value = cbor::parse_diagnostic(text);
    if (!value) {
        return single_failure("pack.syntax", {{"detail", std::string(value.error().detail)}});
    }
    return read_pack(*value);
}

PackRead read_pack(const cbor::Value& value) {
    auto canonical = cbor::encode(value);
    if (!canonical) {
        return single_failure("pack.syntax", {{"detail", std::string(canonical.error().detail)}});
    }
    if (canonical->size() > max_pack_size) {
        return single_failure("pack.too-large", {{"size", std::to_string(canonical->size())},
                                                 {"limit", std::to_string(max_pack_size)}});
    }
    // Read the canonical form, so map entries come in one order whatever
    // order `value` keeps them in.
    cbor::DecodeOptions options;
    options.max_depth = cbor::max_nesting_depth;
    const auto ordered = cbor::decode(*canonical, options);
    if (!ordered) {
        return single_failure("pack.syntax", {{"detail", std::string(ordered.error().detail)}});
    }
    return Reader{}.read(*ordered, std::move(*canonical));
}

Result<crypto::Digest> digest(const Pack& pack, const crypto::Provider& provider,
                              crypto::HashAlg alg) {
    return provider.digest(alg, pack.canonical);
}

} // namespace cexchain::bo
