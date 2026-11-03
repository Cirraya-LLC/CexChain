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
constexpr std::uint64_t version = 2;
constexpr std::size_t max_item = 16 * 1024 * 1024; // a log record's limit
constexpr std::size_t restore_batch = 1000;
/// Entries after the last checkpoint wait in memory for the signature that
/// vouches for them: at most this much.
constexpr std::size_t max_tail_bytes = 64 * 1024 * 1024;
constexpr std::string_view signature_context = "CexChain backup v2 signature";

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

/// What the log key signs: the context, then the chain over everything
/// before the trailer.
Bytes signed_message(ByteView chain) {
    Bytes message(signature_context.begin(), signature_context.end());
    message.push_back(0);
    message.insert(message.end(), chain.begin(), chain.end());
    return message;
}

Result<BackupSummary> write_backup(const Ledger& ledger, const crypto::Provider& provider,
                                   std::span<const BackupFile> files, protocol::Timestamp created,
                                   std::ostream& out, const crypto::Signer* log_key) {
    if (log_key != nullptr && log_key->public_key() != ledger.state().log_key()) {
        return fail(Errc::invalid_argument, "the signer is not this ledger's log key");
    }
    auto checkpoints = ledger.checkpoints();
    if (!checkpoints) {
        return std::unexpected(checkpoints.error());
    }
    auto cosignatures = ledger.cosignatures();
    if (!cosignatures) {
        return std::unexpected(cosignatures.error());
    }
    BackupSummary summary;
    summary.ledger_id = ledger.id();
    summary.created = created;
    summary.entries = ledger.size();
    summary.checkpoints = checkpoints->size();
    summary.cosignatures = cosignatures->size();
    summary.files = files.size();
    summary.is_signed = log_key != nullptr;
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
    auto write_entry = [&](std::uint64_t i) -> Status {
        auto bytes = ledger.entry(i);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        return writer.write(cbor::Value::bytes(*bytes));
    };
    // Genesis, then the checkpoints: a restore knows what is signed before
    // it takes any other entry.
    if (auto s = write_entry(0); !s) {
        return std::unexpected(s.error());
    }
    for (const auto& c : *checkpoints) {
        if (auto s = writer.write(cbor::Value::bytes(c.encoded)); !s) {
            return std::unexpected(s.error());
        }
    }
    for (std::uint64_t i = 1; i < ledger.size(); ++i) {
        if (auto s = write_entry(i); !s) {
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
    cbor::Map trailer{entry(1, cbor::Value::bytes(chain))};
    if (log_key != nullptr) {
        auto signature = log_key->sign(signed_message(chain));
        if (!signature) {
            return std::unexpected(signature.error());
        }
        trailer.push_back(entry(2, cbor::Value::bytes(*signature)));
    }
    if (auto s = writer.write(cbor::Value::map(std::move(trailer))); !s) {
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
        return fail(Errc::unsupported,
                    "this backup's format version is not supported (make a new one)");
    }
    const cbor::Value* header_id = value_at(*map, 3);
    const cbor::Value* header_hash = value_at(*map, 4);
    const auto created = uint_at(*map, 5);
    const auto entries = uint_at(*map, 6);
    const auto checkpoints = uint_at(*map, 7);
    const auto cosignatures = uint_at(*map, 8);
    const auto files = uint_at(*map, 9);
    if (!created || !entries || !checkpoints || !cosignatures || !files || *entries == 0 ||
        header_id == nullptr || header_id->as_bytes() == nullptr || header_hash == nullptr ||
        !header_hash->as_int64()) {
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
    if (!std::ranges::equal(ledger->id().bytes(), *header_id->as_bytes()) ||
        *header_hash->as_int64() != crypto::cose_id(ledger->hash())) {
        return fail(Errc::verification_failed, "the backup's header is not its ledger's");
    }

    // The checkpoints first, in order: they say how far the log is signed.
    // Each one's signature is checked when it is stored, once the entries it
    // covers are in, so with the log key in effect at its size (a rotation
    // among them changes it). A restore that fails leaves nothing behind.
    std::vector<Bytes> signed_checkpoints;
    std::optional<protocol::Checkpoint> last;
    for (std::uint64_t i = 0; i < *checkpoints; ++i) {
        auto bytes = next_bytes();
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        auto checked = protocol::parse_checkpoint(*bytes);
        if (!checked) {
            return std::unexpected(checked.error());
        }
        const protocol::Checkpoint& c = checked->checkpoint;
        if (c.ledger_id != ledger->id() || c.tree_hash != ledger->hash()) {
            return fail(Errc::verification_failed,
                        "a checkpoint in the backup is another ledger's");
        }
        if (last && (c.tree_size < last->tree_size || c.timestamp < last->timestamp)) {
            return fail(Errc::verification_failed, "the backup's checkpoints go back");
        }
        last = c;
        signed_checkpoints.push_back(std::move(*bytes));
    }
    const std::uint64_t covered = last ? last->tree_size : 1;
    if (covered > *entries) {
        return fail(Errc::verification_failed, "a checkpoint covers more than the backup holds");
    }

    // Entries a checkpoint covers are taken (and re-validated) at once, each
    // checkpoint once its entries are in. The rest wait for the signature.
    std::size_t stored = 0;
    auto store_covered = [&]() -> Status {
        while (stored < signed_checkpoints.size()) {
            auto parsed = protocol::parse_checkpoint(signed_checkpoints[stored]);
            if (!parsed || parsed->checkpoint.tree_size > ledger->size()) {
                break;
            }
            if (auto s = ledger->store_checkpoint(signed_checkpoints[stored]); !s) {
                return s;
            }
            ++stored;
        }
        return {};
    };
    if (auto s = store_covered(); !s) {
        return std::unexpected(s.error());
    }
    std::vector<Bytes> pending;
    std::vector<Bytes> tail;
    std::size_t tail_bytes = 0;
    for (std::uint64_t i = 1; i < *entries; ++i) {
        auto bytes = next_bytes();
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        if (i >= covered) {
            tail_bytes += bytes->size();
            if (tail_bytes > max_tail_bytes) {
                return fail(Errc::limit_exceeded,
                            "too many entries after the last checkpoint: checkpoint, then back up");
            }
            tail.push_back(std::move(*bytes));
            continue;
        }
        pending.push_back(std::move(*bytes));
        if (pending.size() == restore_batch || i + 1 == covered) {
            if (auto s = ledger->append_entries(pending); !s) {
                return std::unexpected(s.error());
            }
            pending.clear();
            if (auto s = store_covered(); !s) {
                return std::unexpected(s.error());
            }
        }
    }
    if (stored != signed_checkpoints.size()) {
        return fail(Errc::verification_failed, "a checkpoint in the backup was not stored");
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
    // The trailer seals everything before it; the log key's signature, if
    // any, vouches for what no checkpoint covers: the tail and the files.
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
    const cbor::Value* signature = value_at(*trailer_map, 2);
    if (signature != nullptr) {
        // Signed with the newest log key: follow any rotation in the tail.
        protocol::LedgerKeys keys = ledger->keys();
        for (std::size_t k = 0; k < tail.size(); ++k) {
            if (!protocol::follow_key_rotation(provider, keys, ledger->size() + k, tail[k])) {
                return fail(Errc::verification_failed,
                            "a key rotation after the last checkpoint does not verify");
            }
        }
        if (signature->as_bytes() == nullptr ||
            !provider.verify(keys.log_key(), signed_message(expected), *signature->as_bytes())) {
            return fail(Errc::verification_failed, "the backup's signature does not verify");
        }
    }
    BackupSummary summary;
    summary.ledger_id = ledger->id();
    summary.created = *created;
    summary.checkpoints = *checkpoints;
    summary.cosignatures = *cosignatures;
    summary.is_signed = signature != nullptr;
    if (summary.is_signed) {
        for (std::size_t at = 0; at < tail.size(); at += restore_batch) {
            const std::size_t end = std::min(tail.size(), at + restore_batch);
            if (auto s = ledger->append_entries(std::span(tail).subspan(at, end - at)); !s) {
                return std::unexpected(s.error());
            }
        }
        for (const BackupFile& f : held) {
            if (auto s = on_file(f); !s) {
                return std::unexpected(s.error());
            }
        }
        summary.files = held.size();
    } else {
        summary.skipped_entries = tail.size();
        summary.skipped_files = held.size();
    }
    summary.entries = ledger->size();
    summary.size = ledger->size();
    if (auto root = ledger->root(ledger->size())) {
        summary.root = *root;
    }
    if (const auto latest = ledger->latest_checkpoint()) {
        summary.checkpoint = latest->checkpoint;
    }
    return summary;
}

} // namespace cexchain::ledger
