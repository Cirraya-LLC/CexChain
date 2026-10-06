// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>

/// Field-level commitments for records, enabling selective disclosure.
/// See `record-field` in spec/cexchain-v0.1.cddl.
namespace cexchain::protocol {

/// One field of a record. The salt keeps undisclosed fields from being
/// guessed by hashing candidate values.
struct RecordField {
    std::string name;
    Nonce salt{};
    cbor::Value value;

    friend bool operator==(const RecordField&, const RecordField&) = default;
};

[[nodiscard]] Result<Bytes> encode_field(const RecordField& field);
[[nodiscard]] Result<RecordField> decode_field(ByteView leaf);

/// The commitment to a record's fields: an RFC 9162 tree over the encoded
/// fields, sorted by name.
struct FieldCommitment {
    crypto::Digest root;
    /// Fields sorted by name (bytewise).
    std::vector<RecordField> fields;
    /// Encoded fields, in the same order.
    std::vector<Bytes> leaves;
};

/// Commits to `fields`. Names must be non-empty and unique.
[[nodiscard]] Result<FieldCommitment> commit_fields(const crypto::Provider& provider,
                                                    crypto::HashAlg hash,
                                                    std::vector<RecordField> fields);

/// One disclosed field and the proof that it belongs to the commitment.
struct FieldDisclosure {
    Bytes leaf;
    std::uint64_t index = 0;
    std::vector<crypto::Digest> path;

    friend bool operator==(const FieldDisclosure&, const FieldDisclosure&) = default;
};

[[nodiscard]] Result<FieldDisclosure> disclose_field(const crypto::Provider& provider,
                                                     crypto::HashAlg hash,
                                                     const FieldCommitment& commitment,
                                                     std::string_view name);

/// Checks a disclosure against a record's field root and count, and returns
/// the disclosed field.
[[nodiscard]] Result<RecordField> verify_disclosure(const crypto::Provider& provider,
                                                    crypto::HashAlg hash, ByteView root,
                                                    std::uint64_t field_count,
                                                    const FieldDisclosure& disclosure);

/// Commitment to an attachment: HASH(salt || content).
[[nodiscard]] Result<crypto::Digest> attachment_commitment(const crypto::Provider& provider,
                                                           crypto::HashAlg hash, const Nonce& salt,
                                                           ByteView content);

} // namespace cexchain::protocol
