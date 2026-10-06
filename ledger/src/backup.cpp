// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <array>
#include <optional>
#include <vector>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/ledger/backup.hpp>

namespace cexchain::ledger {

namespace {

constexpr std::string_view magic = "cexchain-backup";
constexpr std::uint64_t version = 1;
constexpr std::size_t max_item = 64 * 1024 * 1024;
constexpr std::size_t restore_batch = 1000;

cbor::MapEntry entry(std::uint64_t key, cbor::Value value) {
    return {cbor::Value::unsigned_integer(key), std::move(value)};
}

/// The running chain hash over framed items.
class Chain {
public:
    explicit Chain(const crypto::Provider& provider) : provider_(&provider) {
        auto first = provider.digest(crypto::HashAlg::sha256, as_bytes("CexChain backup v1"));
        if (first) {
            value_.assign(first->bytes().begin(), first->bytes().end());
        }
    }

    Status add(ByteView framed) {
        Bytes input = value_;
        input.insert(input.end(), framed.begin(), framed.end());
        auto next = provider_->digest(crypto::HashAlg::sha256, input);
        if (!next) {
            return std::unexpected(next.error());
        }
        value_.assign(next->bytes().begin(), next->bytes().end());
        return {};
    }

    [[nodiscard]] const Bytes& value() const { return value_; }

private:
    const crypto::Provider* provider_;
    Bytes value_;
};

Bytes frame(ByteView item) {
    Bytes out;
    out.reserve(4 + item.size());
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(item.size() >> shift));
    }
    out.insert(out.end(), item.begin(), item.end());
    return out;
}

class Writer {
public:
    Writer(std::ostream& out, const crypto::Provider& provider) : out_(&out), chain_(provider) {}

    Status write(const cbor::Value& value) {
        auto encoded = cbor::encode(value);
        if (!encoded) {
            return std::unexpected(encoded.error());
        }
        const Bytes framed = frame(*encoded);
        if (auto s = chain_.add(framed); !s) {
            return s;
        }
        out_->write(reinterpret_cast<const char*>(framed.data()),
                    static_cast<std::streamsize>(framed.size()));
        if (!*out_) {
            return fail(Errc::unavailable, "cannot write the backup");
        }
        return {};
    }

    [[nodiscard]] const Chain& chain() const { return chain_; }

private:
    std::ostream* out_;
    Chain chain_;
};

class Reader {
public:
    Reader(std::istream& in, const crypto::Provider& provider) : in_(&in), chain_(provider) {}

    /// The next item; Errc::truncated at the end of the input.
    Result<cbor::Value> next() {
        std::array<char, 4> header{};
        in_->read(header.data(), header.size());
        if (in_->gcount() != 4) {
            return fail(Errc::truncated, "the backup ends early");
        }
        std::size_t length = 0;
        for (const char c : header) {
            length = (length << 8) | static_cast<unsigned char>(c);
        }
        if (length > max_item) {
            return fail(Errc::malformed, "the backup holds an oversized item");
        }
        Bytes framed(4 + length);
        std::copy(header.begin(), header.end(), framed.begin());
        in_->read(reinterpret_cast<char*>(framed.data() + 4), static_cast<std::streamsize>(length));
        if (static_cast<std::size_t>(in_->gcount()) != length) {
            return fail(Errc::truncated, "the backup ends early");
        }
        if (auto s = chain_.add(framed); !s) {
            return std::unexpected(s.error());
        }
        cbor::DecodeOptions options;
        options.max_items = 1u << 20;
        return cbor::decode(ByteView(framed).subspan(4), options);
    }

    /// The chain before the item read last (for the trailer).
    [[nodiscard]] const Chain& chain() const { return chain_; }
    [[nodiscard]] bool at_end() { return in_->peek() == std::char_traits<char>::eof(); }

private:
    std::istream* in_;
    Chain chain_;
};

std::optional<std::uint64_t> uint_at(const cbor::Map& map, std::uint64_t key) {
    for (const auto& [k, v] : map) {
        if (k.as_uint64() == key) {
            return v.as_uint64();
        }
    }
    return std::nullopt;
}

const cbor::Value* value_at(const cbor::Map& map, std::uint64_t key) {
    for (const auto& [k, v] : map) {
        if (k.as_uint64() == key) {
            return &v;
        }
    }
    return nullptr;
}

} // namespace

Result<BackupSummary> write_backup(const Ledger& ledger, const crypto::Provider& provider,
                                   std::span<const BackupFile> files, protocol::Timestamp created,
                                   std::ostream& out) {
    auto checkpoints = ledger.checkpoints();
    if (!checkpoints) {
        return std::unexpected(checkpoints.error());
    }
    auto cosignatures = ledger.cosignatures();
    if (!cosignatures) {
        return std::unexpected(cosignatures.error());
    }
    BackupSummary summary{ledger.id(),          created,     ledger.size(), checkpoints->size(),
                          cosignatures->size(), files.size()};
    Writer writer(out, provider);
    if (auto s = writer.write(cbor::Value::map({
            entry(1, cbor::Value::text(std::string(magic))),
            entry(2, cbor::Value::unsigned_integer(version)),
            entry(3, cbor::Value::bytes(ledger.id().bytes())),
            entry(4, cbor::Value::integer(crypto::cose_id(ledger.hash()))),
            entry(5, cbor::Value::unsigned_integer(created)),
            entry(6, cbor::Value::unsigned_integer(summary.entries)),
            entry(7, cbor::Value::unsigned_integer(summary.checkpoints)),
            entry(8, cbor::Value::unsigned_integer(summary.cosignatures)),
            entry(9, cbor::Value::unsigned_integer(summary.files)),
        }));
        !s) {
        return std::unexpected(s.error());
    }
    for (std::uint64_t i = 0; i < ledger.size(); ++i) {
        auto bytes = ledger.entry(i);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        if (auto s = writer.write(cbor::Value::bytes(*bytes)); !s) {
            return std::unexpected(s.error());
        }
    }
    for (const auto& c : *checkpoints) {
        if (auto s = writer.write(cbor::Value::bytes(c.encoded)); !s) {
            return std::unexpected(s.error());
        }
    }
    for (const auto& c : *cosignatures) {
        if (auto s = writer.write(cbor::Value::array(
                {cbor::Value::bytes(c.encoded), protocol::encode_public_key(c.witness)}));
            !s) {
            return std::unexpected(s.error());
        }
    }
    for (const BackupFile& f : files) {
        if (auto s = writer.write(
                cbor::Value::array({cbor::Value::text(f.path), cbor::Value::bytes(f.content)}));
            !s) {
            return std::unexpected(s.error());
        }
    }
    const Bytes chain = writer.chain().value();
    if (auto s = writer.write(cbor::Value::map({entry(1, cbor::Value::bytes(chain))})); !s) {
        return std::unexpected(s.error());
    }
    out.flush();
    if (!out) {
        return fail(Errc::unavailable, "cannot write the backup");
    }
    return summary;
}

Result<BackupSummary> restore_backup(std::istream& in, FileSystem& fs, Clock& clock,
                                     const crypto::Provider& provider,
                                     const std::function<Status(const BackupFile&)>& on_file) {
    Reader reader(in, provider);
    auto header = reader.next();
    const cbor::Map* map = header ? header->as_map() : nullptr;
    const cbor::Value* name = map != nullptr ? value_at(*map, 1) : nullptr;
    if (map == nullptr || name == nullptr || name->as_text() == nullptr ||
        *name->as_text() != magic) {
        return fail(Errc::malformed, "this is not a CexChain backup");
    }
    if (uint_at(*map, 2) != version) {
        return fail(Errc::unsupported, "this backup's format version is not supported");
    }
    const auto created = uint_at(*map, 5);
    const auto entries = uint_at(*map, 6);
    const auto checkpoints = uint_at(*map, 7);
    const auto cosignatures = uint_at(*map, 8);
    const auto files = uint_at(*map, 9);
    if (!created || !entries || !checkpoints || !cosignatures || !files || *entries == 0) {
        return fail(Errc::malformed, "the backup's header is malformed");
    }
    auto next_bytes = [&]() -> Result<Bytes> {
        auto item = reader.next();
        if (!item) {
            return std::unexpected(item.error());
        }
        if (item->as_bytes() == nullptr) {
            return fail(Errc::malformed, "the backup holds a malformed item");
        }
        return *item->as_bytes();
    };

    auto genesis = next_bytes();
    if (!genesis) {
        return std::unexpected(genesis.error());
    }
    auto ledger = Ledger::create_replica(fs, clock, provider, *genesis);
    if (!ledger) {
        return std::unexpected(ledger.error());
    }
    std::vector<Bytes> pending;
    for (std::uint64_t i = 1; i < *entries; ++i) {
        auto bytes = next_bytes();
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        pending.push_back(std::move(*bytes));
        if (pending.size() == restore_batch || i + 1 == *entries) {
            if (auto s = ledger->append_entries(pending); !s) {
                return std::unexpected(s.error());
            }
            pending.clear();
        }
    }
    for (std::uint64_t i = 0; i < *checkpoints; ++i) {
        auto bytes = next_bytes();
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        if (auto s = ledger->store_checkpoint(*bytes); !s) {
            return std::unexpected(s.error());
        }
    }
    for (std::uint64_t i = 0; i < *cosignatures; ++i) {
        auto item = reader.next();
        const cbor::Array* parts = item ? item->as_array() : nullptr;
        if (parts == nullptr || parts->size() != 2 || (*parts)[0].as_bytes() == nullptr) {
            return fail(Errc::malformed, "the backup holds a malformed cosignature");
        }
        auto witness = protocol::decode_public_key((*parts)[1]);
        if (!witness) {
            return std::unexpected(witness.error());
        }
        if (auto s = ledger->add_cosignature(*(*parts)[0].as_bytes(), *witness); !s) {
            return fail(Errc::verification_failed, "a cosignature in the backup does not verify");
        }
    }
    std::vector<BackupFile> held;
    for (std::uint64_t i = 0; i < *files; ++i) {
        auto item = reader.next();
        const cbor::Array* parts = item ? item->as_array() : nullptr;
        if (parts == nullptr || parts->size() != 2 || (*parts)[0].as_text() == nullptr ||
            (*parts)[1].as_bytes() == nullptr) {
            return fail(Errc::malformed, "the backup holds a malformed file");
        }
        held.push_back({*(*parts)[0].as_text(), *(*parts)[1].as_bytes()});
    }
    // The trailer seals everything before it; files are handed over only
    // once it matches.
    const Bytes expected = reader.chain().value();
    auto trailer = reader.next();
    const cbor::Map* trailer_map = trailer ? trailer->as_map() : nullptr;
    const cbor::Value* chain = trailer_map != nullptr ? value_at(*trailer_map, 1) : nullptr;
    if (chain == nullptr || chain->as_bytes() == nullptr || *chain->as_bytes() != expected) {
        return fail(Errc::verification_failed, "the backup is damaged (its chain does not match)");
    }
    if (!reader.at_end()) {
        return fail(Errc::malformed, "the backup has data after its trailer");
    }
    for (const BackupFile& f : held) {
        if (auto s = on_file(f); !s) {
            return std::unexpected(s.error());
        }
    }
    return BackupSummary{ledger->id(), *created, *entries, *checkpoints, *cosignatures, *files};
}

} // namespace cexchain::ledger
