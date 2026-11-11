// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <utility>

#include <kanhe/core/merkle.hpp>
#include <kanhe/core/protocol/record.hpp>

#include "reader.hpp"

namespace kanhe::protocol {

Result<Bytes> encode_field(const RecordField& field) {
    if (field.name.empty()) {
        return fail(Errc::invalid_argument, "field name must not be empty");
    }
    return cbor::encode(cbor::Value::array(
        {cbor::Value::text(field.name), cbor::Value::bytes(field.salt), field.value}));
}

Result<RecordField> decode_field(ByteView leaf) {
    KANHE_TRY(cbor::Value value, cbor::decode(leaf));
    const cbor::Array* parts = value.as_array();
    if (parts == nullptr || parts->size() != 3) {
        return fail(Errc::malformed, "record field must be [name, salt, value]");
    }
    RecordField field;
    KANHE_TRY(field.name, detail::as_text((*parts)[0]));
    if (field.name.empty()) {
        return fail(Errc::malformed, "field name must not be empty");
    }
    KANHE_TRY(Bytes salt, detail::as_bytes_value((*parts)[1]));
    if (salt.size() != field.salt.size()) {
        return fail(Errc::malformed, "field salt must be 16 bytes");
    }
    std::ranges::copy(salt, field.salt.begin());
    field.value = (*parts)[2];
    return field;
}

Result<FieldCommitment> commit_fields(const crypto::Provider& provider, crypto::HashAlg hash,
                                      std::vector<RecordField> fields) {
    if (!is_ledger_hash(hash)) {
        return fail(Errc::unsupported, "hash must be SHA-256 or SM3");
    }
    if (fields.empty()) {
        return fail(Errc::invalid_argument, "a record must have at least one field");
    }
    std::ranges::sort(fields, std::ranges::less{}, &RecordField::name);
    const auto duplicate =
        std::ranges::adjacent_find(fields, std::ranges::equal_to{}, &RecordField::name);
    if (duplicate != fields.end()) {
        return fail(Errc::invalid_argument, "field names must be unique");
    }

    merkle::Tree tree(provider, hash);
    std::vector<Bytes> leaves;
    leaves.reserve(fields.size());
    for (const RecordField& field : fields) {
        KANHE_TRY(Bytes leaf, encode_field(field));
        KANHE_TRY(std::uint64_t index, tree.append(leaf));
        static_cast<void>(index);
        leaves.push_back(std::move(leaf));
    }
    KANHE_TRY(crypto::Digest root, tree.root());
    return FieldCommitment{root, std::move(fields), std::move(leaves)};
}

Result<FieldDisclosure> disclose_field(const crypto::Provider& provider, crypto::HashAlg hash,
                                       const FieldCommitment& commitment, std::string_view name) {
    const auto it = std::ranges::find(commitment.fields, name, &RecordField::name);
    if (it == commitment.fields.end()) {
        return fail(Errc::invalid_argument, "the record has no field with this name");
    }
    const auto index = static_cast<std::uint64_t>(it - commitment.fields.begin());

    merkle::Tree tree(provider, hash);
    for (const Bytes& leaf : commitment.leaves) {
        KANHE_TRY(std::uint64_t appended, tree.append(leaf));
        static_cast<void>(appended);
    }
    KANHE_TRY(std::vector<crypto::Digest> path, tree.inclusion_proof(index, tree.size()));
    return FieldDisclosure{commitment.leaves[static_cast<std::size_t>(index)], index,
                           std::move(path)};
}

Result<RecordField> verify_disclosure(const crypto::Provider& provider, crypto::HashAlg hash,
                                      ByteView root, std::uint64_t field_count,
                                      const FieldDisclosure& disclosure) {
    KANHE_TRY(crypto::Digest expected_root, crypto::Digest::from_bytes(root));
    KANHE_TRY(crypto::Digest leaf, merkle::leaf_hash(provider, hash, disclosure.leaf));
    KANHE_CHECK(merkle::verify_inclusion(provider, hash, leaf, disclosure.index, field_count,
                                         disclosure.path, expected_root));
    return decode_field(disclosure.leaf);
}

Result<crypto::Digest> attachment_commitment(const crypto::Provider& provider, crypto::HashAlg hash,
                                             const Nonce& salt, ByteView content) {
    if (!is_ledger_hash(hash)) {
        return fail(Errc::unsupported, "hash must be SHA-256 or SM3");
    }
    return provider.digest(hash, {ByteView(salt), content});
}

} // namespace kanhe::protocol
