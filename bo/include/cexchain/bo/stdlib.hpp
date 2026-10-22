// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/bo/ast.hpp>
#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/explain.hpp>
#include <cexchain/bo/model.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>

/// Bo's standard library: the built-in actions, written in Bo
/// itself and compiled in: the core's (bo/stdlib/core.bo), then each
/// official vocabulary pack's (its file's terms, bo/vocab/). A user's
/// vocabulary pack brings terms of its own (UserTerms, read with the pack
/// set that reads the pack). Each is a `can` clause: who starts the action, its counterparty,
/// the consents it asks for, the states it starts from and leads to, and
/// what it changes. A contract that declares a built-in action
/// (`can transfer to buyer`) gets that action's terms (rule R19), with its
/// own lines first; to change a built-in action, a contract copies it under
/// a name of its own. A pack's terms use the core's words and the pack's.
namespace cexchain::bo {

/// One file of the library: the terms of the core's or of one pack's
/// actions.
struct StandardFile {
    /// The core, or the vocabulary pack whose terms these are.
    Vocab pack = Vocab::core;
    /// That pack (nullptr for the core).
    const VocabularyPack* owner = nullptr;
    /// The source as compiled in, in English, comments included.
    std::string_view source;
    /// The source, read with the official packs (it has no problems).
    Parsed parsed;
};

struct StandardLibrary {
    std::uint64_t edition = 1;
    /// The core's file, then the packs' in the order of Vocab.
    std::vector<StandardFile> files;
    /// Each built-in action's terms, in the library's order: every clause is
    /// a `can` of a vocabulary action.
    std::vector<const ast::Can*> templates;

    /// The terms of a built-in action (its concept id, act.pledge), or
    /// nullptr if the library has none for it (yet).
    [[nodiscard]] const ast::Can* find(std::string_view action) const noexcept;
    /// The source of the file holding a built-in action's terms (the file of
    /// the action's pack), or empty.
    [[nodiscard]] std::string_view source_of(const Concept* action) const noexcept;
};

/// The terms of users' vocabulary packs (vocab.hpp), read with the pack
/// set that reads the packs: a file for each pack with terms, in the order of
/// their ids. Every clause is a `can` of one of its pack's actions.
struct UserTerms {
    std::vector<StandardFile> files;
    std::vector<const ast::Can*> templates;
    /// The packs the files' sources and concepts are in.
    std::vector<std::shared_ptr<const VocabularyPack>> packs;

    /// The terms of a user's pack's action (its concept id), or nullptr.
    [[nodiscard]] const ast::Can* find(std::string_view action) const noexcept;
    /// The source of the file holding an action's terms, or empty.
    [[nodiscard]] std::string_view source_of(const Concept* action) const noexcept;
};

/// The terms of an action of the library or of a user's pack the file reads
/// with (ast::File::vocabularies), or nullptr.
[[nodiscard]] const ast::Can* find_terms(const Concept* action, const Vocabularies* vocabularies);
/// The source holding those terms, or empty.
[[nodiscard]] std::string_view terms_source(const Concept* action,
                                            const Vocabularies* vocabularies);

/// The source of the core's terms or of a pack's, as compiled in; empty for
/// a pack whose actions have no terms yet (commerce).
[[nodiscard]] std::string_view standard_source(Vocab pack) noexcept;

/// The standard library of edition 1, read once. It is part of the
/// compiler: one that does not read is a defect of the build.
[[nodiscard]] const StandardLibrary& standard_library() noexcept;

/// A contract that declares every built-in action of the library, as `bo
/// stdlib` explains them: it uses every pack with terms, and declares an
/// asset with a holder bound at creation and a quantity in items (so that
/// every action's terms apply).
[[nodiscard]] std::string_view standard_showcase();

/// The showcase checked: every built-in action with its terms (R19).
[[nodiscard]] const model::Model& standard_model();

/// A built-in action's terms, in short, as `bo stdlib list` shows them.
struct StandardAction {
    const Concept* action = nullptr;
    /// Its function in compiled code: pledge, confirm_payment.
    std::string function;
    /// The field that names who starts it (field.holder), or nullptr: the
    /// home, on its own word.
    const Concept* starter = nullptr;
    /// It has a counterparty, who consents (`to`).
    bool counterparty = false;
    /// The states it can start from (empty: any), and those it leads to
    /// (expr.previous_state: back to the state before).
    std::vector<const Concept*> from;
    std::vector<const Concept*> to;
};

/// Every built-in action of the library, in its order.
[[nodiscard]] std::vector<StandardAction> standard_actions();
/// The actions with terms of the users' vocabulary packs a set reads, as
/// their terms write them (who starts each, its counterparty, the states it
/// starts from and leads to), by pack and then in the terms' order.
[[nodiscard]] std::vector<StandardAction> user_actions(const PackSet& set);
/// A user's pack's action's terms as Bo source, written in a language with
/// the set (the clause and its block), or nullopt.
[[nodiscard]] std::optional<std::string>
user_terms_source(const Concept* action, const PackSet& set, const Pack* language);

/// The built-in action a word names in any language (质押, pledge), or its
/// function's name (confirm_payment); nullptr if the library has no terms
/// for it.
[[nodiscard]] const Concept* standard_action(std::string_view word, const PackSet& packs);

/// One built-in action's terms as source, without the library's comments,
/// in a language (nullptr: as the library writes them): a contract copies it
/// under a name of its own to change it. Nullopt if the library has no terms
/// for the action.
[[nodiscard]] std::optional<std::string> standard_terms_source(const Concept* action,
                                                               const Pack* language);

/// The clauses of the contract text that state one built-in action's terms
/// (the showcase's, in a language), without their numbers.
[[nodiscard]] std::vector<ExplainedClause> standard_terms_text(const Concept* action,
                                                               const Pack* language);

} // namespace cexchain::bo
