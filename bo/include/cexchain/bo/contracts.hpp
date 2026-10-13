// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

/// Contract assertions (C++26, P2900) for the Bo compiler, as macros, so that
/// the front end also builds with compilers that lack contracts (Clang 23,
/// which libFuzzer needs):
///
///   BO_PRE(cond)       after a function's declarator: a precondition
///   BO_POST(r, cond)   after a function's declarator: a postcondition, where
///                      r names the result (a separate macro argument, so
///                      clang-format leaves the condition alone)
///   BO_ASSERT(cond)    a statement
///
///   [[nodiscard]] Pack read(std::string_view text, const std::size_t limit)
///       BO_PRE(limit > 0) BO_POST(r, r.size() <= limit);
///
/// With contracts (GCC 16 in C++26 mode), they are checked with the
/// "enforce" semantic: a violation prints the predicate, where it is, and
/// terminates. Without, BO_PRE and BO_POST vanish, and BO_ASSERT's condition
/// is still compiled (unevaluated), so it cannot rot.
///
/// Rules of the language: a value parameter that a postcondition reads must
/// be const in every declaration, the definition included; contracts go on a
/// function's first declaration; conditions must not have side effects.
// clang-format would write "post(result : ...)".
// clang-format off
#if defined(__cpp_contracts)
#define BO_CONTRACTS 1
#define BO_PRE(...) pre(__VA_ARGS__)
#define BO_POST(result, ...) post(result: __VA_ARGS__)
#define BO_ASSERT(...) contract_assert(__VA_ARGS__)
#else
#define BO_CONTRACTS 0
#define BO_PRE(...)
#define BO_POST(result, ...)
#define BO_ASSERT(...) static_cast<void>(sizeof((__VA_ARGS__) ? true : false))
#endif
// clang-format on
