// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cexchain/core/protocol/common.hpp>

namespace cexchain::protocol {

bool is_ledger_hash(crypto::HashAlg alg) noexcept {
    return alg == crypto::HashAlg::sha256 || alg == crypto::HashAlg::sm3;
}

cbor::Value encode_public_key(const crypto::PublicKey& key) {
    return cbor::Value::array(
        {cbor::Value::integer(crypto::cose_id(key.algorithm)), cbor::Value::bytes(key.bytes)});
}

Result<crypto::PublicKey> decode_public_key(const cbor::Value& value) {
    const cbor::Array* parts = value.as_array();
    if (parts == nullptr || parts->size() != 2) {
        return fail(Errc::malformed, "public key must be [alg, key]");
    }
    const auto alg_id = (*parts)[0].as_int64();
    const Bytes* bytes = (*parts)[1].as_bytes();
    if (!alg_id || bytes == nullptr) {
        return fail(Errc::malformed, "public key must be [alg, key]");
    }
    const auto alg = crypto::sig_alg_from_cose(*alg_id);
    if (!alg) {
        return fail(Errc::unsupported, "public key uses an unsupported algorithm");
    }
    if (bytes->size() != crypto::public_key_size(*alg)) {
        return fail(Errc::malformed, "public key has the wrong size for its algorithm");
    }
    return crypto::PublicKey{*alg, *bytes};
}

Result<Id> key_id(const crypto::Provider& provider, crypto::HashAlg alg,
                  const crypto::PublicKey& key) {
    if (!is_ledger_hash(alg)) {
        return fail(Errc::unsupported, "not a ledger hash algorithm");
    }
    auto encoded = cbor::encode(encode_public_key(key));
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    return provider.digest(alg, *encoded);
}

Result<Id> to_id(ByteView bytes) {
    if (bytes.size() != id_size) {
        return fail(Errc::malformed, "identifier must be 32 bytes");
    }
    return crypto::Digest::from_bytes(bytes);
}

} // namespace cexchain::protocol
