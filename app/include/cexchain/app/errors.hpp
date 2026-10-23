// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <string>

/// The actions the command line and the console share. They throw these, with
/// a message for people; the command line prints it, the console shows it.
namespace cexchain::app {

/// A mistake in what was asked: a malformed value, an ambiguous id, options
/// that exclude each other.
struct UsageError {
    std::string message;
};

/// Any other failure.
struct ActionError {
    std::string message;
};

} // namespace cexchain::app
