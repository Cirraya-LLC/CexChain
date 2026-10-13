// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/bo/ast.hpp>
#include <cexchain/bo/contracts.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/pack.hpp>

/// The parser: tokens to the tree of ast.hpp. Its grammar is the same in
/// every language, since tokens are concepts; a word whose argument sits in
/// different places in different languages (`7 days before due`,
/// `到期前 7日`) is joined with its argument here, so the tree is where all
/// languages meet.
///
///   file      = [`bo N`] { clause }
///   clause    = `contract` NAME
///             | `parties` PARTY { `,` PARTY }
///             | KIND NAME [block of fields]        KIND: asset, service, resource,
///                                                   record, charge, tax
///             | `can` ACTION { `by` PARTY | `to` PARTY | `with` FIELD {`,` FIELD} }
///               [block of statements]
///             | `when` EVENT [ACTION { `and` ACTION }] [block of statements]
///             | `test` [NAME | TEXT] block of steps
///   field     = OPERAND [SUM] { `,` SUM }                  amount HKD
///   statement = `requires` COND | GUARD `requires` COND    over 5_000_000 requires in person
///             | WHO `can` ACTION                           AI agent can propose
///             | `if` COND [statement] [block] [`otherwise` [statement | if] [block]]
///             | `each` NAME `in` COND block
///             | `reject` TEXT
///             | TARGET `=` COND                            holder = bank
///             | [STATE { `,` STATE }] `->` STATE           active -> suspended
///             | [PARTY] ACTION { OPERAND } { `to` X | `by` X | `with` SET {`,` SET} }
///   step      = PARTY ACTION { OPERAND } {...} [`->` STATE [TEXT]] | `->` STATE [TEXT]
///   COND      = OR;  OR = AND { `or` AND };  AND = NOT { `and` NOT };  NOT = `not` NOT | CMP
///   CMP       = SUM [(`=` `<` `<=` `>` `>=` `in`) SUM]     never chained
///   SUM       = PRODUCT { (`+` `-`) PRODUCT };  PRODUCT = PHRASE { (`*` `/`) PHRASE }
///   PHRASE    = OPERAND { OPERAND }                        monthly HKD 120
///   OPERAND   = (literal | NAME | WORD | `(` COND {`,` COND} `)`
///               | HEAD OPERAND | OPEN OPERAND CLOSE) { TAIL }
///
/// HEAD, TAIL, OPEN, and CLOSE are the pieces of a word with an argument
/// (lexer.hpp): `consent of` bank, 7 days `before due`, `經` 銀行 `同意`.
///
/// Rules that are not in the grammar's shape:
///   - `=` sets a field at the start of an action's line, and compares
///     inside a condition (plan 5.1, item 4).
///   - A word with an argument takes one operand as its argument, so that
///     `consent of bank` and `經 銀行 同意` agree; `applies to` takes the
///     rest of the condition (`applies to customer location = 中国内地`).
///   - Words side by side cannot be operands of `+ - * /` or comparisons:
///     that would be a guess, so it is an error asking for parentheses.
///   - An action begins at a word of category action, or at a name a `can`
///     declares, together with a party (a role, or a name in `parties`) just
///     before it: `when due issuer pays` is the event `due`, then
///     `issuer pays`.
///   - A name that the lexer could split after a prefix keyword (`可提款`) is
///     split when the rest is declared and the whole is not; both declared
///     is an error asking for a space. Declared: the contract, the parties,
///     blocks and their fields, actions and inputs of `can`, and `each`
///     names.
///   - `use` is reserved.
/// After an error, the parser skips to the next line (and past any block
/// under it), so one run reports as much as it can. Problems on lines where
/// the lexer found one are not reported again.
namespace cexchain::bo {

/// The deepest nesting in a line: parentheses, operators, and `otherwise
/// if` chains count.
inline constexpr std::size_t max_parse_depth = 100;

struct Parsed {
    ast::File file;
    /// The parser's problems only (the lexer's are in Lexed), in source
    /// order.
    std::vector<Diagnostic> diagnostics;
};

/// Parses a lexed source. `source` is the text the tokens were read from:
/// messages quote what was written.
[[nodiscard]] Parsed parse(std::string_view source, const Lexed& lexed)
    BO_PRE(!lexed.tokens.empty() && lexed.tokens.back().kind == TokenKind::end);

/// The canonical text of a tree: one clause or statement per line, indented
/// by two spaces per level, expressions as S-expressions of concept ids and
/// names. No places and no spellings, so every language gives the same text:
///
///   contract ReceivableFinancing
///   can act.pledge to=role.bank
///     requires cond.in_person guard=(cond.over 5000000)
[[nodiscard]] std::string dump(const ast::File& file);

/// An expression as in the dump: `act.pledge`, `Receivable`, `5000000`,
/// `(money cur.HKD 0.10)`, `(cond.over (money cur.HKD 100))`, `(= a b)`.
[[nodiscard]] std::string dump(const ast::Expr& expr);

/// The tree, then the parser's diagnostics with their places (messages in
/// `language`, English if null): what `bo check --stage parse` prints, and
/// the parser's goldens.
[[nodiscard]] std::string dump(const Parsed& parsed, const Pack* language);

} // namespace cexchain::bo
