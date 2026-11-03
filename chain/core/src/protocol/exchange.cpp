// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <utility>

#include <cexchain/core/protocol/exchange.hpp>
#include <cexchain/core/protocol/statement.hpp>

#include "reader.hpp"

namespace cexchain::protocol {

namespace {

using detail::entry;
using detail::MapReader;

/// Checks what both directions share: the shape and the limits.
Status check(const ExchangeFile& f) {
    if (f.function.empty() || f.function.size() > 64) {
        return fail(Errc::invalid_argument, "a function's name is 1 to 64 bytes");
    }
    if (f.hash != crypto::HashAlg::sha256 && f.hash != crypto::HashAlg::sm3) {
        return fail(Errc::invalid_argument, "a home's hash is SHA-256 or SM3");
    }
    if (f.evidence.empty()) {
        return fail(Errc::invalid_argument, "a file carries its evidence");
    }
    if (f.kind == ExchangeKind::proposal &&
        (f.needs.empty() || f.needs.size() > max_exchange_needs)) {
        return fail(Errc::invalid_argument, "a proposal names 1 to 16 ledgers whose consents "
                                            "the call waits for");
    }
    if (f.kind == ExchangeKind::consent && !f.needs.empty()) {
        return fail(Errc::invalid_argument, "a consent names no ledgers");
    }
    if (f.note && (f.note->empty() || f.note->size() > max_exchange_note)) {
        return fail(Errc::invalid_argument, "a note is 1 to 1000 bytes");
    }
    const auto arguments = cbor::encode(f.arguments);
    if (!arguments || arguments->size() > max_contract_value) {
        return fail(Errc::limit_exceeded, "a call's arguments are at most 65,536 bytes");
    }
    return {};
}

} // namespace

std::string_view name(ExchangeKind kind) noexcept {
    return kind == ExchangeKind::proposal ? "proposal" : "consent";
}

Result<Bytes> encode_exchange_file(const ExchangeFile& f) {
    CEXCHAIN_CHECK(check(f));
    cbor::Map map{entry(1, cbor::Value::unsigned_integer(exchange_format)),
                  entry(2, cbor::Value::text(std::string(name(f.kind)))),
                  entry(3, cbor::Value::bytes(f.home.bytes())),
                  entry(4, cbor::Value::bytes(f.instance.bytes())),
                  entry(5, cbor::Value::unsigned_integer(f.head)),
                  entry(6, cbor::Value::text(f.function)),
                  entry(7, f.arguments),
                  entry(8, cbor::Value::integer(crypto::cose_id(f.hash))),
                  entry(9, cbor::Value::bytes(f.evidence))};
    if (!f.needs.empty()) {
        cbor::Array needs;
        for (const Id& id : f.needs) {
            needs.push_back(cbor::Value::bytes(id.bytes()));
        }
        map.push_back(entry(10, cbor::Value::array(std::move(needs))));
    }
    if (f.note) {
        map.push_back(entry(11, cbor::Value::text(*f.note)));
    }
    auto encoded = cbor::encode(cbor::Value::map(std::move(map)));
    if (encoded && encoded->size() > max_exchange_file) {
        return fail(Errc::limit_exceeded, "a proposal or consent file is at most 16 MiB");
    }
    return encoded;
}

Result<ExchangeFile> decode_exchange_file(ByteView encoded) {
    if (encoded.size() > max_exchange_file) {
        return fail(Errc::limit_exceeded, "a proposal or consent file is at most 16 MiB");
    }
    CEXCHAIN_TRY(cbor::Value value, cbor::decode(encoded));
    CEXCHAIN_TRY(MapReader reader, MapReader::open(value));
    CEXCHAIN_TRY(std::uint64_t version, reader.need_uint(1));
    if (version != exchange_format) {
        return fail(Errc::unsupported, "a proposal or consent file of another format version");
    }
    ExchangeFile f;
    CEXCHAIN_TRY(std::string kind, reader.need_text(2));
    if (kind == "proposal") {
        f.kind = ExchangeKind::proposal;
    } else if (kind == "consent") {
        f.kind = ExchangeKind::consent;
    } else {
        return fail(Errc::invalid_argument, "a file is a proposal or a consent");
    }
    CEXCHAIN_TRY(f.home, reader.need_id(3));
    CEXCHAIN_TRY(f.instance, reader.need_id(4));
    CEXCHAIN_TRY(f.head, reader.need_uint(5));
    CEXCHAIN_TRY(f.function, reader.need_text(6));
    CEXCHAIN_TRY(const cbor::Value* arguments, reader.need(7));
    f.arguments = *arguments;
    CEXCHAIN_TRY(std::int64_t hash, reader.need_int(8));
    const auto alg = crypto::hash_alg_from_cose(hash);
    if (!alg) {
        return fail(Errc::invalid_argument, "a home's hash is SHA-256 or SM3");
    }
    f.hash = *alg;
    CEXCHAIN_TRY(f.evidence, reader.need_bytes(9));
    if (const cbor::Value* list = reader.get(10)) {
        CEXCHAIN_TRY(const cbor::Array* needs, detail::as_array(*list));
        if (needs->size() > max_exchange_needs) {
            return fail(Errc::limit_exceeded, "a proposal names at most 16 ledgers");
        }
        for (const cbor::Value& item : *needs) {
            CEXCHAIN_TRY(Bytes bytes, detail::as_bytes_value(item));
            CEXCHAIN_TRY(Id id, to_id(bytes));
            f.needs.push_back(id);
        }
        if (needs->empty()) {
            return fail(Errc::invalid_argument, "a proposal names 1 to 16 ledgers");
        }
    }
    CEXCHAIN_TRY(f.note, reader.opt_text(11));
    CEXCHAIN_CHECK(reader.finish());
    CEXCHAIN_CHECK(check(f));
    return f;
}

} // namespace cexchain::protocol
