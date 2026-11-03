// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <cexchain/core/cose.hpp>

namespace cexchain::cose {

namespace {

constexpr std::string_view sign1_context = "Signature1";
constexpr std::size_t sign1_fields = 4;

bool is_label(const cbor::Value& key, std::int64_t label) {
    return key.as_int64() == label;
}

/// Rejects caller-supplied header parameters that the profile reserves.
Status check_caller_header(const cbor::Map& header) {
    for (const cbor::MapEntry& entry : header) {
        if (is_label(entry.key, label_alg)) {
            return fail(Errc::invalid_argument,
                        "alg is set from the signer and must not be supplied");
        }
        if (is_label(entry.key, label_crit)) {
            return fail(Errc::unsupported, "critical header parameters are not supported");
        }
    }
    return {};
}

/// Checks the shape of a header map: at most `max_header_parameters` entries,
/// and every label an integer or text string (RFC 9052 §3).
Status check_labels(const cbor::Map& header, Errc code) {
    if (header.size() > max_header_parameters) {
        return fail(Errc::limit_exceeded, "header has too many parameters");
    }
    for (const cbor::MapEntry& entry : header) {
        const cbor::Type type = entry.key.type();
        if (type != cbor::Type::unsigned_integer && type != cbor::Type::negative_integer &&
            type != cbor::Type::text) {
            return fail(code, "header label must be an integer or a text string");
        }
    }
    return {};
}

/// The deterministic encodings of a map's keys, sorted.
Result<std::vector<Bytes>> encoded_keys(const cbor::Map& map) {
    std::vector<Bytes> keys;
    keys.reserve(map.size());
    for (const cbor::MapEntry& entry : map) {
        auto key = cbor::encode(entry.key);
        if (!key) {
            return std::unexpected(key.error());
        }
        keys.push_back(std::move(*key));
    }
    std::ranges::sort(keys);
    return keys;
}

/// Fails if any key appears in both maps. Keys are compared by their
/// deterministic encodings, so in-memory ordering cannot hide a duplicate.
/// Runs in O(n log n).
Status check_disjoint(const cbor::Map& a, const cbor::Map& b, Errc code) {
    auto keys_a = encoded_keys(a);
    if (!keys_a) {
        return fail(code, "header label cannot be encoded");
    }
    auto keys_b = encoded_keys(b);
    if (!keys_b) {
        return fail(code, "header label cannot be encoded");
    }
    auto it_a = keys_a->begin();
    auto it_b = keys_b->begin();
    while (it_a != keys_a->end() && it_b != keys_b->end()) {
        if (*it_a == *it_b) {
            return fail(code, "a header parameter appears in both protected and unprotected");
        }
        if (*it_a < *it_b) {
            ++it_a;
        } else {
            ++it_b;
        }
    }
    return {};
}

} // namespace

Result<Bytes> sig_structure(ByteView protected_bytes, ByteView external_aad, ByteView payload) {
    return cbor::encode(cbor::Value::array({
        cbor::Value::text(std::string(sign1_context)),
        cbor::Value::bytes(protected_bytes),
        cbor::Value::bytes(external_aad),
        cbor::Value::bytes(payload),
    }));
}

Result<Bytes> sign(const crypto::Signer& signer, ByteView payload, const SignOptions& options) {
    // One slot of the protected header is reserved for alg.
    if (options.protected_header.size() + 1 > max_header_parameters) {
        return fail(Errc::limit_exceeded, "header has too many parameters");
    }
    if (auto s = check_labels(options.protected_header, Errc::invalid_argument); !s) {
        return std::unexpected(s.error());
    }
    if (auto s = check_labels(options.unprotected_header, Errc::invalid_argument); !s) {
        return std::unexpected(s.error());
    }
    if (auto s = check_caller_header(options.protected_header); !s) {
        return std::unexpected(s.error());
    }
    if (auto s = check_caller_header(options.unprotected_header); !s) {
        return std::unexpected(s.error());
    }
    if (auto s = check_disjoint(options.protected_header, options.unprotected_header,
                                Errc::invalid_argument);
        !s) {
        return std::unexpected(s.error());
    }

    cbor::Map protected_map;
    protected_map.reserve(options.protected_header.size() + 1);
    protected_map.push_back({cbor::Value::integer(label_alg),
                             cbor::Value::integer(crypto::cose_id(signer.algorithm()))});
    protected_map.insert(protected_map.end(), options.protected_header.begin(),
                         options.protected_header.end());
    auto protected_bytes = cbor::encode(cbor::Value::map(std::move(protected_map)));
    if (!protected_bytes) {
        return std::unexpected(protected_bytes.error());
    }

    auto to_be_signed = sig_structure(*protected_bytes, options.external_aad, payload);
    if (!to_be_signed) {
        return std::unexpected(to_be_signed.error());
    }
    auto signature = signer.sign(*to_be_signed);
    if (!signature) {
        return std::unexpected(signature.error());
    }

    return cbor::encode(cbor::Value::tagged(
        tag_sign1, cbor::Value::array({
                       cbor::Value::bytes(std::move(*protected_bytes)),
                       cbor::Value::map(options.unprotected_header),
                       options.detached ? cbor::Value::null() : cbor::Value::bytes(payload),
                       cbor::Value::bytes(std::move(*signature)),
                   })));
}

Result<Sign1> parse(ByteView message) {
    auto decoded = cbor::decode(message);
    if (!decoded) {
        return std::unexpected(decoded.error());
    }
    const cbor::Tagged* tagged = decoded->as_tagged();
    if (tagged == nullptr || tagged->tag != tag_sign1) {
        return fail(Errc::malformed, "message is not a tagged COSE_Sign1");
    }
    const cbor::Array* fields = tagged->item.as_array();
    if (fields == nullptr || fields->size() != sign1_fields) {
        return fail(Errc::malformed, "COSE_Sign1 must be an array of four elements");
    }

    const Bytes* protected_bytes = (*fields)[0].as_bytes();
    const cbor::Map* unprotected = (*fields)[1].as_map();
    const cbor::Value& payload = (*fields)[2];
    const Bytes* signature = (*fields)[3].as_bytes();
    if (protected_bytes == nullptr || unprotected == nullptr || signature == nullptr ||
        (!payload.is_null() && payload.as_bytes() == nullptr)) {
        return fail(Errc::malformed, "COSE_Sign1 element has the wrong type");
    }

    auto protected_header = cbor::decode(*protected_bytes);
    if (!protected_header) {
        return std::unexpected(protected_header.error());
    }
    const cbor::Map* protected_map = protected_header->as_map();
    if (protected_map == nullptr) {
        return fail(Errc::malformed, "protected header is not a map");
    }
    if (auto s = check_labels(*protected_map, Errc::malformed); !s) {
        return std::unexpected(s.error());
    }
    if (auto s = check_labels(*unprotected, Errc::malformed); !s) {
        return std::unexpected(s.error());
    }
    if (protected_header->find(label_crit) != nullptr || (*fields)[1].find(label_crit) != nullptr) {
        return fail(Errc::unsupported, "critical header parameters are not supported");
    }
    if ((*fields)[1].find(label_alg) != nullptr) {
        return fail(Errc::malformed, "alg must be in the protected header only");
    }
    if (auto s = check_disjoint(*protected_map, *unprotected, Errc::malformed); !s) {
        return std::unexpected(s.error());
    }

    const cbor::Value* alg_value = protected_header->find(label_alg);
    if (alg_value == nullptr) {
        return fail(Errc::malformed, "protected header has no alg");
    }
    const auto alg_id = alg_value->as_int64();
    const auto alg = alg_id ? crypto::sig_alg_from_cose(*alg_id) : std::nullopt;
    if (!alg) {
        return fail(Errc::unsupported, "signature algorithm is not supported");
    }

    Sign1 parsed{
        .protected_bytes = *protected_bytes,
        .protected_header = std::move(*protected_header),
        .unprotected_header = (*fields)[1],
        .payload = std::nullopt,
        .signature = *signature,
        .algorithm = *alg,
    };
    if (!payload.is_null()) {
        parsed.payload = *payload.as_bytes();
    }
    return parsed;
}

Status verify(const crypto::Provider& provider, const Sign1& message, const crypto::PublicKey& key,
              ByteView external_aad, std::optional<ByteView> detached_payload) {
    if (key.algorithm != message.algorithm) {
        return fail(Errc::verification_failed,
                    "key algorithm does not match the message's declared algorithm");
    }
    if (message.payload.has_value() == detached_payload.has_value()) {
        return fail(Errc::invalid_argument,
                    "supply a detached payload exactly when the message omits its payload");
    }
    const ByteView payload = message.payload ? ByteView(*message.payload) : *detached_payload;
    auto to_be_signed = sig_structure(message.protected_bytes, external_aad, payload);
    if (!to_be_signed) {
        return std::unexpected(to_be_signed.error());
    }
    return provider.verify(key, *to_be_signed, message.signature);
}

} // namespace cexchain::cose
