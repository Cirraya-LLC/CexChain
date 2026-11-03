// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <utility>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/deploy_file.hpp>
#include <cexchain/core/vm.hpp>

namespace cexchain::protocol {

namespace {

constexpr std::unexpected<Error> malformed(std::string_view detail) {
    return fail(Errc::malformed, detail);
}

} // namespace

Result<Bytes> encode_deploy_file(const DeployFile& file) {
    const ContractDeployBody& b = file.body;
    cbor::Map interface;
    for (const auto& [function, kind] : b.interface) {
        interface.push_back({cbor::Value::text(function),
                             cbor::Value::unsigned_integer(static_cast<std::uint64_t>(kind))});
    }
    cbor::Map map{{cbor::Value::unsigned_integer(1), cbor::Value::bytes(b.code)},
                  {cbor::Value::unsigned_integer(2), cbor::Value::map(std::move(interface))},
                  {cbor::Value::unsigned_integer(3), cbor::Value::text(b.language)},
                  {cbor::Value::unsigned_integer(4), cbor::Value::text(b.compiler)}};
    if (b.source) {
        map.push_back({cbor::Value::unsigned_integer(5), cbor::Value::bytes(*b.source)});
    }
    if (b.name) {
        map.push_back({cbor::Value::unsigned_integer(6), cbor::Value::text(*b.name)});
    }
    map.push_back(
        {cbor::Value::unsigned_integer(7), cbor::Value::integer(crypto::cose_id(file.hash))});
    auto encoded = cbor::encode(cbor::Value::map(std::move(map)));
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    if (auto again = decode_deploy_file(*encoded); !again) {
        return std::unexpected(again.error());
    }
    return encoded;
}

Result<DeployFile> decode_deploy_file(ByteView encoded) {
    if (encoded.size() > max_deploy_file) {
        return fail(Errc::limit_exceeded, "a deploy file is at most 1 MiB");
    }
    auto value = cbor::decode(encoded);
    if (!value) {
        return std::unexpected(value.error());
    }
    const cbor::Map* map = value->as_map();
    if (map == nullptr) {
        return malformed("a deploy file is a map");
    }
    for (const cbor::MapEntry& e : *map) {
        const auto key = e.key.as_uint64();
        if (!key || *key < 1 || *key > 7) {
            return malformed("a deploy file's keys are 1 to 7");
        }
    }
    const cbor::Value* code = value->find(1);
    const cbor::Value* interface = value->find(2);
    const cbor::Value* language = value->find(3);
    const cbor::Value* compiler = value->find(4);
    const cbor::Value* source = value->find(5);
    const cbor::Value* name = value->find(6);
    const cbor::Value* hash = value->find(7);
    DeployFile file;
    ContractDeployBody& b = file.body;
    if (code == nullptr || code->as_bytes() == nullptr || code->as_bytes()->empty() ||
        code->as_bytes()->size() > vm::max_module_size) {
        return malformed("a deploy file's code (key 1) is a module of at most 512 KiB");
    }
    b.code = *code->as_bytes();
    if (interface == nullptr || interface->as_map() == nullptr || interface->as_map()->empty() ||
        interface->as_map()->size() > max_contract_functions) {
        return malformed("a deploy file's interface (key 2) maps 1 to 256 functions");
    }
    bool creates = false;
    for (const cbor::MapEntry& e : *interface->as_map()) {
        const std::string* function = e.key.as_text();
        const auto kind = e.value.as_uint64();
        if (function == nullptr || function->empty() || function->size() > max_function_name ||
            !kind || (*kind != 1 && *kind != 2)) {
            return malformed("a deploy file's function is a name of 1 to 64 bytes and a kind, "
                             "1 or 2");
        }
        creates = creates || *kind == 1;
        b.interface.emplace(*function, static_cast<FunctionKind>(*kind));
    }
    if (!creates) {
        return malformed("a deploy file has a function that creates instances");
    }
    if (language == nullptr || language->as_text() == nullptr || language->as_text()->empty() ||
        language->as_text()->size() > max_contract_language) {
        return malformed("a deploy file names its language (key 3) in 1 to 32 bytes");
    }
    b.language = *language->as_text();
    if (compiler == nullptr || compiler->as_text() == nullptr || compiler->as_text()->empty() ||
        compiler->as_text()->size() > max_contract_compiler) {
        return malformed("a deploy file names its compiler (key 4) in 1 to 128 bytes");
    }
    b.compiler = *compiler->as_text();
    if (source != nullptr) {
        if (source->as_bytes() == nullptr || source->as_bytes()->size() > max_contract_source) {
            return malformed("a deploy file's source (key 5) is at most 256 KiB of bytes");
        }
        b.source = *source->as_bytes();
    }
    if (name != nullptr) {
        if (name->as_text() == nullptr || name->as_text()->empty() ||
            name->as_text()->size() > max_contract_name) {
            return malformed("a deploy file's name (key 6) is 1 to 256 bytes");
        }
        b.name = *name->as_text();
    }
    const auto alg = hash != nullptr && hash->as_int64()
                         ? crypto::hash_alg_from_cose(*hash->as_int64())
                         : std::optional<crypto::HashAlg>();
    if (!alg || (*alg != crypto::HashAlg::sha256 && *alg != crypto::HashAlg::sm3)) {
        return malformed("a deploy file names the hash of its digests (key 7): SHA-256 or SM3");
    }
    file.hash = *alg;
    return file;
}

} // namespace cexchain::protocol
