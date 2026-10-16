// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The official vocabulary packs (vocab.hpp): each one's concepts from the
// edition's table, and the standard terms of its actions from bo/stdlib/,
// as canonical CBOR.

#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

#include <cexchain/bo/stdlib.hpp>
#include <cexchain/bo/vocab.hpp>
#include <cexchain/core/cbor.hpp>

namespace cexchain::bo {

namespace {

cbor::Value text(std::string_view s) {
    return cbor::Value::text(std::string(s));
}

Bytes canonical_of(const VocabularyPack& pack) {
    cbor::Map concept_map;
    for (const Concept& c : concepts()) {
        if (c.pack != pack.vocab || c.retired) {
            continue;
        }
        cbor::Map entry{{text("category"), text(category_name(c.category))}};
        if (c.arity > 0) {
            entry.push_back({text("argument"), cbor::Value::boolean(true)});
        }
        if (!c.type.empty()) {
            entry.push_back({text("type"), text(c.type)});
        }
        if ((c.flags & field_added) != 0) {
            entry.push_back({text("added"), cbor::Value::boolean(true)});
        }
        if ((c.flags & field_taking) != 0) {
            entry.push_back({text("taking"), cbor::Value::boolean(true)});
        }
        concept_map.push_back({text(c.id), cbor::Value::map(std::move(entry))});
    }
    cbor::Map map{{text("format"), cbor::Value::unsigned_integer(vocab_format)},
                  {text("id"), text(pack.id)},
                  {text("version"), cbor::Value::unsigned_integer(pack.version)},
                  {text("edition"), cbor::Value::unsigned_integer(edition)},
                  {text("concepts"), cbor::Value::map(std::move(concept_map))}};
    if (!pack.terms.empty()) {
        map.push_back({text("terms"), text(pack.terms)});
    }
    auto encoded = cbor::encode(cbor::Value::map(std::move(map)));
    if (!encoded) {
        std::fprintf(stderr, "bo: the vocabulary pack %.*s does not encode\n",
                     static_cast<int>(pack.id.size()), pack.id.data());
        std::abort();
    }
    return std::move(*encoded);
}

const std::vector<VocabularyPack>& packs() {
    static const std::vector<VocabularyPack> out = [] {
        std::vector<VocabularyPack> list{
            {"commerce", 1, Vocab::commerce, standard_source(Vocab::commerce), {}},
            {"finance", 1, Vocab::finance, standard_source(Vocab::finance), {}},
            {"services", 1, Vocab::services, standard_source(Vocab::services), {}},
        };
        for (VocabularyPack& pack : list) {
            pack.canonical = canonical_of(pack);
        }
        return list;
    }();
    return out;
}

} // namespace

std::span<const VocabularyPack> vocabulary_packs() noexcept {
    return packs();
}

const VocabularyPack* find_vocabulary_pack(std::string_view id) noexcept {
    for (const VocabularyPack& pack : packs()) {
        if (pack.id == id) {
            return &pack;
        }
    }
    return nullptr;
}

const VocabularyPack* vocabulary_pack(const Vocab vocab) noexcept {
    for (const VocabularyPack& pack : packs()) {
        if (pack.vocab == vocab) {
            return &pack;
        }
    }
    return nullptr;
}

Result<crypto::Digest> digest(const VocabularyPack& pack, const crypto::Provider& provider,
                              crypto::HashAlg alg) {
    return provider.digest(alg, pack.canonical);
}

} // namespace cexchain::bo
