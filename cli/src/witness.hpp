// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>

namespace cexchain::cli {

/// What a witness does with a cosign request, for `witness cosign` and for
/// `serve --witness-dir`: checks it against the state in `dir` and, if the
/// checkpoint extends what this witness cosigned before, cosigns it and
/// advances the state. Asking again for the checkpoint cosigned last gets
/// it cosigned again (a lost answer can be retried). Fails with
/// Errc::not_found (a ledger this witness does not follow), Errc::rejected
/// (the proof starts elsewhere than the witness's size), or
/// Errc::verification_failed (not signed by the log key, or inconsistent:
/// the ledger was rewritten or forked).
[[nodiscard]] Result<Bytes> witness_cosign(const std::filesystem::path& dir,
                                           const crypto::Signer& key, ByteView request);

} // namespace cexchain::cli
