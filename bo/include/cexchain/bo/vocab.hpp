// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <span>
#include <string_view>

#include <cexchain/bo/concepts.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>

/// Bo's official vocabulary packs (D-054): `finance`, `commerce`, and
/// `services`. Bo's core words (holder, transfer, money, ...) are in every
/// source; a pack's words are read only in a source that declares the pack
/// (`use finance`). Unlike a language pack, which spells concepts in one
/// language, a vocabulary pack says which concepts exist, their categories
/// and field types, and the standard terms of its built-in actions, so it
/// changes what runs: a deploy pins each pack it uses by version and digest
/// (bo-source key 6, source.hpp), as it pins its language packs.
///
/// The packs are the compiler's tables (concepts.cpp, bo/stdlib/), read as
/// one canonical CBOR map each, which their digests cover:
///
///   {"format": 1, "id": "finance", "version": 1, "edition": 1,
///    "concepts": {"act.pledge": {"category": "action"},
///                 "field.pledgee": {"category": "field", "type": "party",
///                                   "added": true, "taking": true}, ...},
///    "terms": "bo 1\nuse finance\n..."}       # bo/stdlib/finance.bo
///
/// "argument": true marks a concept that takes one; "terms" is absent for a
/// pack whose actions have no standard terms (commerce). Released versions
/// never change: a change is a new version, and a compiler carries every
/// released version.
namespace cexchain::bo {

/// The vocabulary pack format.
inline constexpr std::uint64_t vocab_format = 1;

struct VocabularyPack {
    std::string_view id;
    std::uint64_t version = 0;
    Vocab vocab = Vocab::finance;
    /// The standard terms of its built-in actions, or empty.
    std::string_view terms;
    /// The canonical CBOR above: what digests cover.
    Bytes canonical;
};

/// The official vocabulary packs this compiler carries, by ascending id
/// (commerce, finance, services).
[[nodiscard]] std::span<const VocabularyPack> vocabulary_packs() noexcept;
/// The vocabulary pack with this id, or nullptr ("core" is none).
[[nodiscard]] const VocabularyPack* find_vocabulary_pack(std::string_view id) noexcept;
/// The pack a concept belongs to, or nullptr for a core word.
[[nodiscard]] const VocabularyPack* vocabulary_pack(Vocab vocab) noexcept;

/// The home's hash of the pack's canonical CBOR (SHA-256 or SM3).
[[nodiscard]] Result<crypto::Digest> digest(const VocabularyPack& pack,
                                            const crypto::Provider& provider, crypto::HashAlg alg);

} // namespace cexchain::bo
