// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <charconv>
#include <string>
#include <system_error>
#include <utility>

#include <cexchain/core/bytes.hpp>
#include <cexchain/node/record_files.hpp>

#include "files.hpp"

namespace cexchain::node {

std::optional<SealedBox> parse_sealed_box(ByteView file) {
    const auto value = cbor::decode(file);
    const cbor::Map* map = value ? value->as_map() : nullptr;
    if (map == nullptr || map->size() != 4) {
        return std::nullopt;
    }
    const cbor::Value* version = value->find(1);
    const cbor::Value* suite = value->find(2);
    const cbor::Value* enc = value->find(3);
    const cbor::Value* ciphertext = value->find(4);
    const cbor::Array* ids = suite != nullptr ? suite->as_array() : nullptr;
    if (version == nullptr || version->as_uint64() != 1 || ids == nullptr || ids->size() != 3 ||
        enc == nullptr || enc->as_bytes() == nullptr || ciphertext == nullptr ||
        ciphertext->as_bytes() == nullptr) {
        return std::nullopt;
    }
    SealedBox box;
    for (std::size_t i = 0; i < 3; ++i) {
        const auto id = (*ids)[i].as_uint64();
        if (!id) {
            return std::nullopt;
        }
        box.suite[i] = *id;
    }
    box.encapsulated_key = *enc->as_bytes();
    box.ciphertext = *ciphertext->as_bytes();
    return box;
}

std::filesystem::path record_files_directory(const std::filesystem::path& ledger,
                                             const protocol::Id& record) {
    return ledger / "vault" / "files" / to_hex(record.bytes());
}

std::filesystem::path record_file_path(const std::filesystem::path& ledger,
                                       const protocol::Id& record, std::uint64_t index) {
    return record_files_directory(ledger, record) / (std::to_string(index) + ".cbor");
}

Status check_sealed_file(const protocol::RecordRegisterBody& record, const SealedFile& file) {
    if (file.index >= record.attachments.size()) {
        return fail(Errc::invalid_argument, "the record attaches no file at that index");
    }
    const protocol::Attachment& attachment = record.attachments[file.index];
    if (attachment.size > max_record_file) {
        return fail(Errc::limit_exceeded, "the file is larger than a kept file may be (16 MiB)");
    }
    const auto box = parse_sealed_box(file.sealed);
    if (!box) {
        return fail(Errc::malformed, "a kept file is sealed: {1: 1, 2: suite, 3: key, 4: data}");
    }
    // The content's size is fixed by the record: the sealed file must hold
    // exactly that many bytes.
    if (box->ciphertext.size() != attachment.size + sealed_file_overhead) {
        return fail(Errc::invalid_argument, "the sealed file is not the attachment's size");
    }
    return {};
}

Status store_record_file(const std::filesystem::path& ledger, const protocol::Id& record,
                         const SealedFile& file) {
    const std::filesystem::path path = record_file_path(ledger, record, file.index);
    if (auto held = detail::read_file(path)) {
        if (!std::ranges::equal(*held, file.sealed)) {
            return fail(Errc::rejected, "another file is kept for this attachment");
        }
        return {};
    }
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        return fail(Errc::unavailable, "cannot create the record's files directory");
    }
    return detail::write_file(path, file.sealed, true);
}

bool remove_record_file(const std::filesystem::path& ledger, const protocol::Id& record,
                        std::uint64_t index) {
    std::error_code ec;
    const bool removed = std::filesystem::remove(record_file_path(ledger, record, index), ec);
    if (removed) {
        detail::sync_directory(record_files_directory(ledger, record));
    }
    return removed && !ec;
}

std::vector<std::uint64_t> kept_record_files(const std::filesystem::path& ledger,
                                             const protocol::Id& record) {
    std::vector<std::uint64_t> out;
    std::error_code ec;
    for (const auto& entry :
         std::filesystem::directory_iterator(record_files_directory(ledger, record), ec)) {
        const std::string name = entry.path().filename().string();
        if (!entry.is_regular_file() || !name.ends_with(".cbor")) {
            continue;
        }
        const std::string_view digits(name.data(), name.size() - 5);
        std::uint64_t index = 0;
        const auto [end, error] =
            std::from_chars(digits.data(), digits.data() + digits.size(), index);
        // Only the names this store writes: no sign, no leading zero.
        if (error == std::errc{} && end == digits.data() + digits.size() && !digits.empty() &&
            (digits.size() == 1 || digits.front() != '0')) {
            out.push_back(index);
        }
    }
    std::ranges::sort(out);
    return out;
}

cbor::Value encode_sealed_files(std::span<const SealedFile> files) {
    cbor::Array list;
    for (const SealedFile& f : files) {
        list.push_back(cbor::Value::array(
            {cbor::Value::unsigned_integer(f.index), cbor::Value::bytes(f.sealed)}));
    }
    return cbor::Value::array(std::move(list));
}

Result<std::vector<SealedFile>> decode_sealed_files(const cbor::Value& value, std::size_t max) {
    const cbor::Array* items = value.as_array();
    if (items == nullptr) {
        return fail(Errc::malformed, "the files are [[index, sealed file], ...]");
    }
    if (items->size() > max) {
        return fail(Errc::limit_exceeded, "too many files");
    }
    std::vector<SealedFile> out;
    for (const cbor::Value& item : *items) {
        const cbor::Array* parts = item.as_array();
        if (parts == nullptr || parts->size() != 2) {
            return fail(Errc::malformed, "a file is [index, sealed file]");
        }
        const auto index = (*parts)[0].as_uint64();
        const Bytes* sealed = (*parts)[1].as_bytes();
        if (!index || sealed == nullptr) {
            return fail(Errc::malformed, "a file is [index, sealed file]");
        }
        if (!out.empty() && *index <= out.back().index) {
            return fail(Errc::non_canonical, "the files' indexes ascend and differ");
        }
        out.push_back({*index, *sealed});
    }
    return out;
}

} // namespace cexchain::node
