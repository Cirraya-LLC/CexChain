// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/statement.hpp>

/// The files a record attaches, kept with it: each sealed to the ledger's
/// vault key as the record's private data is (HPKE, so anyone who registers
/// records can store them, and only holders of the vault private key can
/// read them), bound to the ledger, the record, and the attachment's name.
/// The ledger itself holds only the attachment's salted commitment; a file
/// kept here is checked against it when it is opened.
///
///   sealed file = {1: 1, 2: [kem, kdf, aead], 3: encapsulated key, 4: ciphertext}
///   kept at       <ledger>/vault/files/<record id>/<attachment index>.cbor
///   submission    {1: statement, 2: sealed private data, 4: [[index, sealed file], ...]}
namespace cexchain::node {

/// A kept file holds at most this many bytes; larger files stay with the
/// person, as every file did before.
inline constexpr std::uint64_t max_record_file = 16ULL * 1024 * 1024;
/// What sealing adds to a file's content: the AEAD's tag.
inline constexpr std::uint64_t sealed_file_overhead = 16;

/// A sealed file for the attachment at `index` in its record's registration.
struct SealedFile {
    std::uint64_t index = 0;
    Bytes sealed;

    friend bool operator==(const SealedFile&, const SealedFile&) = default;
};

/// The parts of a sealed file (or of a sealed vault file: the same shape).
struct SealedBox {
    std::array<std::uint64_t, 3> suite{};
    Bytes encapsulated_key;
    Bytes ciphertext;
};

/// A sealed file's parts, if it has exactly that shape.
[[nodiscard]] std::optional<SealedBox> parse_sealed_box(ByteView file);

[[nodiscard]] std::filesystem::path record_files_directory(const std::filesystem::path& ledger,
                                                           const protocol::Id& record);
[[nodiscard]] std::filesystem::path record_file_path(const std::filesystem::path& ledger,
                                                     const protocol::Id& record,
                                                     std::uint64_t index);

/// Whether `file` can be the record's attachment at its index: an
/// attachment there, the shape of a sealed file, and exactly that
/// attachment's size once opened, which is at most max_record_file.
[[nodiscard]] Status check_sealed_file(const protocol::RecordRegisterBody& record,
                                       const SealedFile& file);

/// Keeps a sealed file, once: the same bytes again are fine, other bytes
/// are refused (Errc::rejected), so nobody can swap a kept file.
[[nodiscard]] Status store_record_file(const std::filesystem::path& ledger,
                                       const protocol::Id& record, const SealedFile& file);
/// Removes a kept file; false if none was kept.
bool remove_record_file(const std::filesystem::path& ledger, const protocol::Id& record,
                        std::uint64_t index);
/// The indexes of the files kept for a record, ascending.
[[nodiscard]] std::vector<std::uint64_t> kept_record_files(const std::filesystem::path& ledger,
                                                           const protocol::Id& record);

/// A submission's key 4: [[index, sealed file], ...], indexes ascending and
/// distinct, at most `max`.
[[nodiscard]] cbor::Value encode_sealed_files(std::span<const SealedFile> files);
[[nodiscard]] Result<std::vector<SealedFile>> decode_sealed_files(const cbor::Value& value,
                                                                  std::size_t max = 256);

} // namespace cexchain::node
