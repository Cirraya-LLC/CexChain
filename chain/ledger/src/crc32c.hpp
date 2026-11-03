// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>

#include <cexchain/core/bytes.hpp>

namespace cexchain::ledger::detail {

/// CRC-32C (Castagnoli), used to detect torn and corrupted storage records.
/// It is not a security mechanism: integrity against tampering comes from
/// the Merkle tree and signed checkpoints.
[[nodiscard]] std::uint32_t crc32c(ByteView data) noexcept;

} // namespace cexchain::ledger::detail
