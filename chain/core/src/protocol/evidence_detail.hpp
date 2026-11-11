// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <kanhe/core/protocol/evidence.hpp>

// Internal: not part of the public API.
namespace kanhe::protocol::detail {

/// `verify_bundle` with `provider` as given: `options.signatures` is not
/// asked (a caller that wrapped the provider in a `CheckedProvider` already).
[[nodiscard]] Result<EvidenceReport> verify_bundle_as_given(const crypto::Provider& provider,
                                                            ByteView encoded,
                                                            const VerifyOptions& options);

} // namespace kanhe::protocol::detail
