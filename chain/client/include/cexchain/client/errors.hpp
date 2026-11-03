// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cexchain/core/failure.hpp>

/// The actions the command line and the console share throw the core's
/// failures for people, with a message; the command line prints it, the
/// console shows it.
namespace cexchain::client {

using cexchain::ActionError;
using cexchain::UsageError;

} // namespace cexchain::client
