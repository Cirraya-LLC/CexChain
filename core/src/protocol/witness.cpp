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
    return cbor::encode(cbor::Value::map({
        entry(1, cbor::Value::bytes(request.checkpoint)),
        entry(2, cbor::Value::unsigned_integer(request.old_size)),
        entry(3, cbor::Value::array(std::move(proof))),
    }));
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
    CEXCHAIN_CHECK(reader.finish());
    return request;
}

Result<SignedCheckpoint> check_cosign_request(const crypto::Provider& provider,
                                              const WitnessedLog& log,
                                              const CosignRequest& request) {
    CEXCHAIN_TRY(SignedCheckpoint signed_checkpoint, parse_checkpoint(request.checkpoint));
    const Checkpoint& c = signed_checkpoint.checkpoint;
    if (c.ledger_id != log.ledger_id) {
        return fail(Errc::verification_failed, "the checkpoint belongs to another ledger");
    }
    if (!verify_checkpoint(provider, signed_checkpoint, log.log_key)) {
        return fail(Errc::verification_failed,
                    "the checkpoint is not signed by the ledger's log key");
    }
    if (log.tree_hash && c.tree_hash != *log.tree_hash) {
        return fail(Errc::verification_failed,
                    "the checkpoint uses a different tree hash than before");
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
    return signed_checkpoint;
}

WitnessedLog advance(WitnessedLog log, const Checkpoint& checkpoint) {
    log.tree_hash = checkpoint.tree_hash;
    log.size = checkpoint.tree_size;
    log.root = checkpoint.root;
    return log;
}

} // namespace cexchain::protocol
