// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cexchain/core/merkle.hpp>
#include <cexchain/core/protocol/witness.hpp>

#include "reader.hpp"

namespace cexchain::protocol {

using detail::entry;
using detail::MapReader;

Result<Bytes> encode_cosign_request(const CosignRequest& request) {
    if (request.proof.size() > merkle::max_consistency_proof_length) {
        return fail(Errc::invalid_argument, "consistency proof is too long");
    }
    cbor::Array proof;
    for (const crypto::Digest& node : request.proof) {
        proof.push_back(cbor::Value::bytes(node.bytes()));
    }
    cbor::Map map{
        entry(1, cbor::Value::bytes(request.checkpoint)),
        entry(2, cbor::Value::unsigned_integer(request.old_size)),
        entry(3, cbor::Value::array(std::move(proof))),
    };
    if (!request.rotations.empty()) {
        if (request.rotations.size() > max_key_rotations) {
            return fail(Errc::invalid_argument, "too many key rotations");
        }
        cbor::Array rotations;
        for (const KeyRotationProof& r : request.rotations) {
            if (r.path.size() > merkle::max_consistency_proof_length) {
                return fail(Errc::invalid_argument, "an inclusion proof is too long");
            }
            cbor::Array path;
            for (const crypto::Digest& node : r.path) {
                path.push_back(cbor::Value::bytes(node.bytes()));
            }
            rotations.push_back(cbor::Value::array({cbor::Value::unsigned_integer(r.index),
                                                    cbor::Value::bytes(r.entry),
                                                    cbor::Value::array(std::move(path))}));
        }
        map.push_back(entry(4, cbor::Value::array(std::move(rotations))));
    }
    return cbor::encode(cbor::Value::map(std::move(map)));
}

Result<CosignRequest> decode_cosign_request(ByteView encoded) {
    CEXCHAIN_TRY(cbor::Value value, cbor::decode(encoded));
    CEXCHAIN_TRY(MapReader reader, MapReader::open(value));
    CosignRequest request;
    CEXCHAIN_TRY(request.checkpoint, reader.need_bytes(1));
    CEXCHAIN_TRY(request.old_size, reader.need_uint(2));
    CEXCHAIN_TRY(const cbor::Value* proof_value, reader.need(3));
    CEXCHAIN_TRY(const cbor::Array* proof, detail::as_array(*proof_value));
    if (proof->size() > merkle::max_consistency_proof_length) {
        return fail(Errc::malformed, "consistency proof is too long");
    }
    for (const cbor::Value& node : *proof) {
        CEXCHAIN_TRY(Bytes bytes, detail::as_bytes_value(node));
        CEXCHAIN_TRY(crypto::Digest digest, crypto::Digest::from_bytes(bytes));
        request.proof.push_back(digest);
    }
    if (const cbor::Value* list_value = reader.get(4)) {
        CEXCHAIN_TRY(const cbor::Array* list, detail::as_array(*list_value));
        if (list->empty()) {
            return fail(Errc::non_canonical, "an empty list of key rotations must be omitted");
        }
        if (list->size() > max_key_rotations) {
            return fail(Errc::malformed, "too many key rotations");
        }
        for (const cbor::Value& item : *list) {
            const cbor::Array* parts = item.as_array();
            if (parts == nullptr || parts->size() != 3) {
                return fail(Errc::malformed, "a key rotation must be [index, entry, path]");
            }
            KeyRotationProof r;
            CEXCHAIN_TRY(r.index, detail::as_uint((*parts)[0]));
            CEXCHAIN_TRY(r.entry, detail::as_bytes_value((*parts)[1]));
            CEXCHAIN_TRY(const cbor::Array* path, detail::as_array((*parts)[2]));
            if (path->size() > merkle::max_consistency_proof_length) {
                return fail(Errc::malformed, "an inclusion proof is too long");
            }
            for (const cbor::Value& node : *path) {
                CEXCHAIN_TRY(Bytes bytes, detail::as_bytes_value(node));
                CEXCHAIN_TRY(crypto::Digest digest, crypto::Digest::from_bytes(bytes));
                r.path.push_back(digest);
            }
            request.rotations.push_back(std::move(r));
        }
    }
    CEXCHAIN_CHECK(reader.finish());
    return request;
}

namespace {

/// Follows the request's key rotations that `log` has not seen, each proven
/// to be in the checkpoint's log.
Result<WitnessedLog> follow_rotations(const crypto::Provider& provider, const WitnessedLog& log,
                                      const Checkpoint& c,
                                      std::span<const KeyRotationProof> rotations) {
    WitnessedLog next = log;
    if (rotations.empty()) {
        return next;
    }
    if (!log.root_key) {
        return fail(Errc::verification_failed,
                    "this witness does not know the ledger's root key, so it cannot follow a key "
                    "rotation: add the log again from its genesis entry");
    }
    LedgerKeys keys{
        log.ledger_id, c.tree_hash, *log.root_key, {{0, log.log_key}}, log.last_rotation};
    std::optional<std::uint64_t> previous;
    for (const KeyRotationProof& r : rotations) {
        if (r.index == 0 || r.index >= c.tree_size || (previous && r.index <= *previous)) {
            return fail(Errc::verification_failed,
                        "key rotations must ascend, below the checkpoint's size");
        }
        previous = r.index;
        CEXCHAIN_TRY(crypto::Digest leaf, merkle::leaf_hash(provider, c.tree_hash, r.entry));
        auto root = merkle::root_from_inclusion_proof(provider, c.tree_hash, leaf, r.index,
                                                      c.tree_size, r.path);
        if (!root || *root != c.root) {
            return fail(Errc::verification_failed, "a key rotation is not in the checkpoint's log");
        }
        if (r.index <= keys.last_rotation) {
            continue; // followed before
        }
        if (!is_key_rotation(provider, keys, r.entry)) {
            return fail(Errc::verification_failed,
                        "an entry sent as a key rotation rotates no key");
        }
        if (auto s = follow_key_rotation(provider, keys, r.index, r.entry); !s) {
            return std::unexpected(s.error());
        }
    }
    next.root_key = keys.root_key;
    next.log_key = keys.log_key();
    next.last_rotation = keys.last_rotation;
    return next;
}

} // namespace

Result<CosignApproval> check_cosign_request(const crypto::Provider& provider,
                                            const WitnessedLog& log, const CosignRequest& request) {
    CEXCHAIN_TRY(SignedCheckpoint signed_checkpoint, parse_checkpoint(request.checkpoint));
    const Checkpoint& c = signed_checkpoint.checkpoint;
    if (c.ledger_id != log.ledger_id) {
        return fail(Errc::verification_failed, "the checkpoint belongs to another ledger");
    }
    if (log.tree_hash && c.tree_hash != *log.tree_hash) {
        return fail(Errc::verification_failed,
                    "the checkpoint uses a different tree hash than before");
    }
    CEXCHAIN_TRY(WitnessedLog next, follow_rotations(provider, log, c, request.rotations));
    if (!verify_checkpoint(provider, signed_checkpoint, next.log_key)) {
        return fail(Errc::verification_failed,
                    "the checkpoint is not signed by the ledger's log key");
    }
    if (request.old_size != log.size) {
        return fail(Errc::rejected,
                    "the proof does not start at the size this witness last cosigned");
    }
    if (c.tree_size < log.size) {
        return fail(Errc::verification_failed,
                    "the ledger went backwards: this witness cosigned a larger tree");
    }
    crypto::Digest old_root = log.root;
    if (log.size == 0) {
        CEXCHAIN_TRY(old_root, merkle::empty_root(provider, c.tree_hash));
    }
    if (!merkle::verify_consistency(provider, c.tree_hash, log.size, c.tree_size, old_root, c.root,
                                    request.proof)) {
        return fail(
            Errc::verification_failed,
            "INCONSISTENT HISTORY: the checkpoint does not extend what this witness cosigned; "
            "the ledger may have been rewritten or forked");
    }
    return CosignApproval{signed_checkpoint, advance(std::move(next), c)};
}

WitnessedLog advance(WitnessedLog log, const Checkpoint& checkpoint) {
    log.tree_hash = checkpoint.tree_hash;
    log.size = checkpoint.tree_size;
    log.root = checkpoint.root;
    return log;
}

} // namespace cexchain::protocol
