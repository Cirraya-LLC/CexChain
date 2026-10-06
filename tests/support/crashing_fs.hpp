// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <memory>
#include <string_view>

#include <cexchain/core/error.hpp>
#include <cexchain/ledger/storage.hpp>

namespace cexchain::test {

/// Wraps a file system so that the process "dies" after a fixed number of
/// appends and syncs: every later operation fails, as if nothing after that
/// point ever reached the kernel.
class CrashingFileSystem final : public cexchain::ledger::FileSystem {
public:
    CrashingFileSystem(cexchain::ledger::FileSystem& inner, std::uint64_t budget)
        : inner_(inner), budget_(std::make_shared<std::uint64_t>(budget)) {}

    Result<std::unique_ptr<cexchain::ledger::AppendFile>> open(std::string_view name) override {
        auto file = inner_.open(name);
        if (!file) {
            return file;
        }
        return std::unique_ptr<cexchain::ledger::AppendFile>(
            std::make_unique<CrashingFile>(std::move(*file), budget_));
    }
    bool exists(std::string_view name) const override { return inner_.exists(name); }

private:
    class CrashingFile final : public cexchain::ledger::AppendFile {
    public:
        CrashingFile(std::unique_ptr<cexchain::ledger::AppendFile> inner,
                     std::shared_ptr<std::uint64_t> budget)
            : inner_(std::move(inner)), budget_(std::move(budget)) {}
        std::uint64_t size() const override { return inner_->size(); }
        Result<Bytes> read(std::uint64_t offset, std::size_t length) const override {
            return inner_->read(offset, length);
        }
        Status append(ByteView data) override {
            if (!spend()) {
                return fail(Errc::invalid_argument, "crashed");
            }
            return inner_->append(data);
        }
        Status sync() override {
            if (!spend()) {
                return fail(Errc::invalid_argument, "crashed");
            }
            return inner_->sync();
        }
        Status truncate(std::uint64_t size) override { return inner_->truncate(size); }

    private:
        bool spend() {
            if (*budget_ == 0) {
                return false;
            }
            --*budget_;
            return true;
        }
        std::unique_ptr<cexchain::ledger::AppendFile> inner_;
        std::shared_ptr<std::uint64_t> budget_;
    };

    cexchain::ledger::FileSystem& inner_;
    std::shared_ptr<std::uint64_t> budget_;
};

} // namespace cexchain::test
