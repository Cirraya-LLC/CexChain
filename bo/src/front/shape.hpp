// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The shapes both kinds of pack files share (language packs, pack.cpp;
// vocabulary packs, vocab.cpp): maps, texts, lists, and integers at a path,
// spellings and their forms, and categories, each problem reported with the
// pack.* codes, which name the path.

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/core/cbor.hpp>

#include "internal.hpp"

namespace cexchain::bo::detail {

inline std::string join(std::string_view path, std::string_view key) {
    if (path.empty() || path == ".") {
        return std::string(key);
    }
    return std::string(path) + "/" + std::string(key);
}

inline std::string key_text(const cbor::Value& key) {
    if (const std::string* text = key.as_text()) {
        return quote(*text);
    }
    return quote(cbor::diagnostic(key));
}
/// Text for people: 1 to `max` bytes, no control characters.
inline bool valid_text(std::string_view text, std::size_t max) noexcept {
    if (text.empty() || text.size() > max) {
        return false;
    }
    return std::ranges::none_of(text, [](char c) {
        const auto u = static_cast<unsigned char>(c);
        return u < 0x20 || u == 0x7F;
    });
}

inline bool lowercase_name(std::string_view name, std::size_t max) noexcept {
    return !name.empty() && name.size() <= max &&
           std::ranges::all_of(name, [](char c) { return (c >= 'a' && c <= 'z') || c == '_'; });
}

/// A reader of a pack file's CBOR, collecting every problem.
class ShapeReader {
public:
    void fail(std::string_view code, Args args) { diagnostics_.add(code, args); }

protected:
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

    // --- Spellings ---

    /// Checks one spelling of a concept (or of a multiplier, with no
    /// concept). Returns false if it is not usable.
    bool check(std::string_view spelling, std::string_view path, const Concept* entry) {
        const SpellingCheck check = check_spelling(spelling);
        if (check.problem == SpellingProblem::bad_character) {
            fail("pack.bad-character", {{"path", std::string(path)},
                                        {"spelling", quote(spelling)},
                                        {"character", describe_char(check.character)}});
            return false;
        }
        if (check.problem != SpellingProblem::none) {
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

    /// A concept a pack may spell: a retired one only in an official pack
    /// (the earlier official packs spell them; make_pack_set takes no
    /// official pack the compiler does not carry).
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

    Diagnostics diagnostics_;
};

} // namespace cexchain::bo::detail
