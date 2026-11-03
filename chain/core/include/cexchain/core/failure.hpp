// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <string>
#include <string_view>
#include <utility>

#include <cexchain/core/error.hpp>

/// Failures for people: what the programs built on the core (the command
/// lines, the console) throw, each with a message to print or show. Unlike
/// Error, they allocate: they end an action, not a step of verification.
namespace cexchain {

/// A mistake in what was asked: a malformed value, an ambiguous id, options
/// that exclude each other.
struct UsageError {
    std::string message;
};

/// Any other failure.
struct ActionError {
    std::string message;
};

/// Unwraps a result or throws an ActionError that names what failed.
template <class T>
T unwrap(Result<T> result, std::string_view what) {
    if (!result) {
        throw ActionError{std::string(what) + ": " + std::string(result.error().detail) + " (" +
                          std::string(to_string(result.error().code)) + ")"};
    }
    return std::move(*result);
}

inline void unwrap(Status status, std::string_view what) {
    if (!status) {
        throw ActionError{std::string(what) + ": " + std::string(status.error().detail) + " (" +
                          std::string(to_string(status.error().code)) + ")"};
    }
}

} // namespace cexchain
