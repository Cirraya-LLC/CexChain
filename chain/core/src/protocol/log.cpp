// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <string>
#include <utility>

#include <cexchain/core/cose.hpp>
#include <cexchain/core/merkle.hpp>
#include <cexchain/core/protocol/log.hpp>

#include "envelope.hpp"
#include "reader.hpp"

namespace cexchain::protocol {

namespace {

using detail::entry;
using detail::MapReader;

Result<crypto::HashAlg> decode_ledger_hash(std::int64_t id) {
    const auto alg = crypto::hash_alg_from_cose(id);
    if (!alg || !is_ledger_hash(*alg)) {
        return fail(Errc::unsupported, "tree hash must be SHA-256 or SM3");
    }
    return *alg;
}

std::optional<std::int64_t> vds_for(crypto::HashAlg alg) {
    switch (alg) {
    case crypto::HashAlg::sha256:
        return vds_rfc9162_sha256;
    case crypto::HashAlg::sm3:
        return vds_rfc9162_sm3;
    default:
        return std::nullopt;
    }
}

Result<SignedCheckpoint> to_signed_checkpoint(detail::Envelope envelope, ByteView encoded) {
    CEXCHAIN_TRY(Checkpoint checkpoint, decode_checkpoint(*envelope.message.payload));
    return SignedCheckpoint{
        .encoded = Bytes(encoded.begin(), encoded.end()),
        .envelope = std::move(envelope.message),
        .checkpoint = std::move(checkpoint),
        .kid = envelope.kid,
    };
}

Result<SignedCheckpoint> sign_checkpoint_as(const crypto::Signer& signer,
                                            const crypto::Provider& provider,
                                            const Checkpoint& checkpoint,
                                            std::string_view content_type) {
    CEXCHAIN_TRY(Bytes payload, encode_checkpoint(checkpoint));
    CEXCHAIN_TRY(Bytes encoded, detail::sign_envelope(signer, provider, checkpoint.tree_hash,
                                                      payload, content_type));
    CEXCHAIN_TRY(detail::Envelope envelope, detail::parse_envelope(encoded, content_type));
    return to_signed_checkpoint(std::move(envelope), encoded);
}

} // namespace

// ---------------------------------------------------------------------------
// Log entries
// ---------------------------------------------------------------------------

Result<Bytes> encode_log_entry(const LogEntry& log_entry) {
    if (log_entry.statement.empty() == log_entry.state_commitment.empty()) {
        return fail(Errc::invalid_argument, "a log entry holds a statement or a state commitment");
    }
    if (log_entry.statement_id.size() != id_size) {
        return fail(Errc::invalid_argument, "log entry ids are 32 bytes");
    }
    return cbor::encode(cbor::Value::map({
        entry(1, cbor::Value::bytes(log_entry.statement_id.bytes())),
        entry(2, cbor::Value::unsigned_integer(log_entry.registered_at)),
        log_entry.is_state_commitment() ? entry(4, cbor::Value::bytes(log_entry.state_commitment))
                                        : entry(3, cbor::Value::bytes(log_entry.statement)),
    }));
}

Result<LogEntry> decode_log_entry(ByteView encoded) {
    CEXCHAIN_TRY(cbor::Value value, cbor::decode(encoded));
    CEXCHAIN_TRY(MapReader reader, MapReader::open(value));
    LogEntry log_entry;
    CEXCHAIN_TRY(log_entry.statement_id, reader.need_id(1));
    CEXCHAIN_TRY(log_entry.registered_at, reader.need_uint(2));
    CEXCHAIN_TRY(std::optional<Bytes> statement, reader.opt_bytes(3));
    CEXCHAIN_TRY(std::optional<Bytes> commitment, reader.opt_bytes(4));
    if (statement.has_value() == commitment.has_value() || (statement && statement->empty()) ||
        (commitment && commitment->empty())) {
        return fail(Errc::malformed, "a log entry holds exactly one statement or state commitment");
    }
    log_entry.statement = statement.value_or(Bytes{});
    log_entry.state_commitment = commitment.value_or(Bytes{});
    CEXCHAIN_CHECK(reader.finish());
    return log_entry;
}

// ---------------------------------------------------------------------------
// Checkpoints and cosignatures
// ---------------------------------------------------------------------------

Result<Bytes> encode_checkpoint(const Checkpoint& checkpoint) {
    if (!is_ledger_hash(checkpoint.tree_hash)) {
        return fail(Errc::unsupported, "tree hash must be SHA-256 or SM3");
    }
    if (checkpoint.tree_size == 0) {
        return fail(Errc::invalid_argument, "a checkpoint covers at least the genesis entry");
    }
    if (checkpoint.ledger_id.size() != id_size ||
        checkpoint.root.size() != crypto::digest_size(checkpoint.tree_hash)) {
        return fail(Errc::invalid_argument, "checkpoint identifiers have the wrong size");
    }
    cbor::Map map{
        entry(1, cbor::Value::bytes(checkpoint.ledger_id.bytes())),
        entry(2, cbor::Value::integer(crypto::cose_id(checkpoint.tree_hash))),
        entry(3, cbor::Value::unsigned_integer(checkpoint.tree_size)),
        entry(4, cbor::Value::bytes(checkpoint.root.bytes())),
        entry(5, cbor::Value::unsigned_integer(checkpoint.timestamp)),
    };
    return cbor::encode(cbor::Value::map(std::move(map)));
}

Result<Checkpoint> decode_checkpoint(ByteView encoded) {
    CEXCHAIN_TRY(cbor::Value value, cbor::decode(encoded));
    CEXCHAIN_TRY(MapReader reader, MapReader::open(value));
    Checkpoint checkpoint;
    CEXCHAIN_TRY(checkpoint.ledger_id, reader.need_id(1));
    CEXCHAIN_TRY(std::int64_t hash_id, reader.need_int(2));
    CEXCHAIN_TRY(checkpoint.tree_hash, decode_ledger_hash(hash_id));
    CEXCHAIN_TRY(checkpoint.tree_size, reader.need_uint(3));
    if (checkpoint.tree_size == 0) {
        return fail(Errc::malformed, "a checkpoint covers at least the genesis entry");
    }
    CEXCHAIN_TRY(Bytes root, reader.need_bytes(4));
    if (root.size() != crypto::digest_size(checkpoint.tree_hash)) {
        return fail(Errc::malformed, "checkpoint root has the wrong size");
    }
    CEXCHAIN_TRY(checkpoint.root, crypto::Digest::from_bytes(root));
    CEXCHAIN_TRY(checkpoint.timestamp, reader.need_uint(5));
    CEXCHAIN_CHECK(reader.finish());
    return checkpoint;
}

Result<SignedCheckpoint> sign_checkpoint(const crypto::Signer& log_key,
                                         const crypto::Provider& provider,
                                         const Checkpoint& checkpoint) {
    return sign_checkpoint_as(log_key, provider, checkpoint, checkpoint_content_type);
}

Result<SignedCheckpoint> parse_checkpoint(ByteView encoded) {
    CEXCHAIN_TRY(detail::Envelope envelope,
                 detail::parse_envelope(encoded, checkpoint_content_type));
    return to_signed_checkpoint(std::move(envelope), encoded);
}

Status verify_checkpoint(const crypto::Provider& provider, const SignedCheckpoint& checkpoint,
                         const crypto::PublicKey& log_key) {
    return detail::verify_envelope(provider, checkpoint.checkpoint.tree_hash,
                                   detail::Envelope{checkpoint.envelope, checkpoint.kid}, log_key);
}

Result<SignedCheckpoint> cosign_checkpoint(const crypto::Signer& witness_key,
                                           const crypto::Provider& provider,
                                           const Checkpoint& checkpoint) {
    return sign_checkpoint_as(witness_key, provider, checkpoint, cosignature_content_type);
}

Result<SignedCheckpoint> parse_cosignature(ByteView encoded) {
    CEXCHAIN_TRY(detail::Envelope envelope,
                 detail::parse_envelope(encoded, cosignature_content_type));
    return to_signed_checkpoint(std::move(envelope), encoded);
}

Status verify_cosignature(const crypto::Provider& provider, const SignedCheckpoint& cosignature,
                          const crypto::PublicKey& witness_key) {
    return detail::verify_envelope(provider, cosignature.checkpoint.tree_hash,
                                   detail::Envelope{cosignature.envelope, cosignature.kid},
                                   witness_key);
}

// ---------------------------------------------------------------------------
// State commitments
// ---------------------------------------------------------------------------

Result<Bytes> encode_state_commitment(const StateCommitment& c) {
    if (!is_ledger_hash(c.tree_hash)) {
        return fail(Errc::unsupported, "tree hash must be SHA-256 or SM3");
    }
    if (c.ledger_id.size() != id_size || c.state_root.size() != crypto::digest_size(c.tree_hash)) {
        return fail(Errc::invalid_argument, "state commitment identifiers have the wrong size");
    }
    if (c.tree_size == 0) {
        return fail(Errc::invalid_argument,
                    "a state commitment follows at least the genesis entry");
    }
    return cbor::encode(cbor::Value::map({
        entry(1, cbor::Value::bytes(c.ledger_id.bytes())),
        entry(2, cbor::Value::integer(crypto::cose_id(c.tree_hash))),
        entry(3, cbor::Value::unsigned_integer(c.tree_size)),
        entry(4, cbor::Value::bytes(c.state_root.bytes())),
        entry(5, cbor::Value::unsigned_integer(c.timestamp)),
    }));
}

Result<StateCommitment> decode_state_commitment(ByteView encoded) {
    CEXCHAIN_TRY(cbor::Value value, cbor::decode(encoded));
    CEXCHAIN_TRY(MapReader reader, MapReader::open(value));
    StateCommitment c;
    CEXCHAIN_TRY(c.ledger_id, reader.need_id(1));
    CEXCHAIN_TRY(std::int64_t hash_id, reader.need_int(2));
    CEXCHAIN_TRY(c.tree_hash, decode_ledger_hash(hash_id));
    CEXCHAIN_TRY(c.tree_size, reader.need_uint(3));
    if (c.tree_size == 0) {
        return fail(Errc::malformed, "a state commitment follows at least the genesis entry");
    }
    CEXCHAIN_TRY(Bytes root, reader.need_bytes(4));
    if (root.size() != crypto::digest_size(c.tree_hash)) {
        return fail(Errc::malformed, "state root has the wrong size");
    }
    CEXCHAIN_TRY(c.state_root, crypto::Digest::from_bytes(root));
    CEXCHAIN_TRY(c.timestamp, reader.need_uint(5));
    CEXCHAIN_CHECK(reader.finish());
    return c;
}

Result<SignedStateCommitment> parse_state_commitment(const crypto::Provider& provider,
                                                     ByteView encoded) {
    CEXCHAIN_TRY(detail::Envelope envelope,
                 detail::parse_envelope(encoded, state_commitment_content_type));
    CEXCHAIN_TRY(StateCommitment commitment, decode_state_commitment(*envelope.message.payload));
    CEXCHAIN_TRY(Bytes to_be_signed, cose::sig_structure(envelope.message.protected_bytes, {},
                                                         *envelope.message.payload));
    CEXCHAIN_TRY(Id id, provider.digest(commitment.tree_hash, to_be_signed));
    return SignedStateCommitment{
        .encoded = Bytes(encoded.begin(), encoded.end()),
        .envelope = std::move(envelope.message),
        .commitment = std::move(commitment),
        .id = id,
        .kid = envelope.kid,
    };
}

Result<SignedStateCommitment> sign_state_commitment(const crypto::Signer& log_key,
                                                    const crypto::Provider& provider,
                                                    const StateCommitment& commitment) {
    CEXCHAIN_TRY(Bytes payload, encode_state_commitment(commitment));
    CEXCHAIN_TRY(Bytes encoded, detail::sign_envelope(log_key, provider, commitment.tree_hash,
                                                      payload, state_commitment_content_type));
    return parse_state_commitment(provider, encoded);
}

Status verify_state_commitment(const crypto::Provider& provider,
                               const SignedStateCommitment& commitment,
                               const crypto::PublicKey& log_key) {
    return detail::verify_envelope(provider, commitment.commitment.tree_hash,
                                   detail::Envelope{commitment.envelope, commitment.kid}, log_key);
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

Result<ReceiptSeal> seal_receipts(const crypto::Signer& log_key, const crypto::Provider& provider,
                                  crypto::HashAlg tree_hash, const crypto::Digest& root) {
    const auto vds = vds_for(tree_hash);
    if (!vds) {
        return fail(Errc::unsupported, "tree hash must be SHA-256 or SM3");
    }
    CEXCHAIN_TRY(Id kid, key_id(provider, tree_hash, log_key.public_key()));
    CEXCHAIN_TRY(
        Bytes protected_bytes,
        cbor::encode(cbor::Value::map({
            entry(cose::label_alg, cbor::Value::integer(crypto::cose_id(log_key.algorithm()))),
            entry(cose::label_kid, cbor::Value::bytes(kid.bytes())),
            entry(label_vds, cbor::Value::integer(*vds)),
        })));
    CEXCHAIN_TRY(Bytes to_be_signed, cose::sig_structure(protected_bytes, {}, root.bytes()));
    CEXCHAIN_TRY(Bytes signature, log_key.sign(to_be_signed));
    return ReceiptSeal{std::move(protected_bytes), std::move(signature)};
}

Result<Bytes> issue_receipt(const ReceiptSeal& seal, const InclusionProof& proof) {
    if (proof.leaf_index >= proof.tree_size) {
        return fail(Errc::invalid_argument, "leaf index is outside the tree");
    }
    cbor::Array path;
    for (const crypto::Digest& node : proof.path) {
        path.push_back(cbor::Value::bytes(node.bytes()));
    }
    CEXCHAIN_TRY(Bytes proof_bytes,
                 cbor::encode(cbor::Value::array({cbor::Value::unsigned_integer(proof.tree_size),
                                                  cbor::Value::unsigned_integer(proof.leaf_index),
                                                  cbor::Value::array(std::move(path))})));
    // As cose::sign lays out a detached COSE_Sign1.
    return cbor::encode(cbor::Value::tagged(
        cose::tag_sign1,
        cbor::Value::array({
            cbor::Value::bytes(seal.protected_bytes),
            cbor::Value::map(
                {entry(label_vdp, cbor::Value::map({entry(vdp_inclusion_proofs,
                                                          cbor::Value::array({cbor::Value::bytes(
                                                              std::move(proof_bytes))}))}))}),
            cbor::Value::null(),
            cbor::Value::bytes(seal.signature),
        })));
}

Result<Bytes> issue_receipt(const crypto::Signer& log_key, const crypto::Provider& provider,
                            crypto::HashAlg tree_hash, const crypto::Digest& root,
                            const InclusionProof& proof) {
    if (proof.leaf_index >= proof.tree_size) {
        return fail(Errc::invalid_argument, "leaf index is outside the tree");
    }
    CEXCHAIN_TRY(ReceiptSeal seal, seal_receipts(log_key, provider, tree_hash, root));
    return issue_receipt(seal, proof);
}

Result<Receipt> parse_receipt(ByteView encoded) {
    CEXCHAIN_TRY(cose::Sign1 message, cose::parse(encoded));
    if (message.payload) {
        return fail(Errc::malformed, "receipt payload must be detached");
    }

    const cbor::Map* protected_map = message.protected_header.as_map();
    if (protected_map == nullptr || protected_map->size() != 3) {
        return fail(Errc::malformed, "receipt protected header must be exactly {alg, kid, vds}");
    }
    const cbor::Value* kid_value = message.protected_header.find(cose::label_kid);
    const cbor::Value* vds_value = message.protected_header.find(label_vds);
    if (kid_value == nullptr || vds_value == nullptr || kid_value->as_bytes() == nullptr) {
        return fail(Errc::malformed, "receipt protected header must be exactly {alg, kid, vds}");
    }
    CEXCHAIN_TRY(Id kid, to_id(*kid_value->as_bytes()));
    const auto vds = vds_value->as_int64();
    crypto::HashAlg tree_hash{};
    if (vds == vds_rfc9162_sha256) {
        tree_hash = crypto::HashAlg::sha256;
    } else if (vds == vds_rfc9162_sm3) {
        tree_hash = crypto::HashAlg::sm3;
    } else {
        return fail(Errc::unsupported, "unsupported verifiable data structure");
    }

    const cbor::Map* unprotected = message.unprotected_header.as_map();
    const cbor::Value* vdp = message.unprotected_header.find(label_vdp);
    if (unprotected == nullptr || unprotected->size() != 1 || vdp == nullptr) {
        return fail(Errc::malformed, "receipt unprotected header must be exactly {vdp}");
    }
    const cbor::Map* vdp_map = vdp->as_map();
    const cbor::Value* proofs = vdp->find(vdp_inclusion_proofs);
    if (vdp_map == nullptr || vdp_map->size() != 1 || proofs == nullptr) {
        return fail(Errc::malformed, "vdp must hold exactly one inclusion proof list");
    }
    const cbor::Array* proof_list = proofs->as_array();
    if (proof_list == nullptr || proof_list->size() != 1 ||
        (*proof_list)[0].as_bytes() == nullptr) {
        return fail(Errc::malformed, "a receipt carries exactly one inclusion proof");
    }

    CEXCHAIN_TRY(cbor::Value proof_value, cbor::decode(*(*proof_list)[0].as_bytes()));
    const cbor::Array* parts = proof_value.as_array();
    if (parts == nullptr || parts->size() != 3) {
        return fail(Errc::malformed, "inclusion proof must be [tree size, leaf index, path]");
    }
    InclusionProof proof;
    CEXCHAIN_TRY(proof.tree_size, detail::as_uint((*parts)[0]));
    CEXCHAIN_TRY(proof.leaf_index, detail::as_uint((*parts)[1]));
    CEXCHAIN_TRY(const cbor::Array* path, detail::as_array((*parts)[2]));
    if (path->size() > merkle::max_inclusion_proof_length) {
        return fail(Errc::malformed, "inclusion path is too long");
    }
    for (const cbor::Value& node : *path) {
        CEXCHAIN_TRY(Bytes bytes, detail::as_bytes_value(node));
        if (bytes.size() != crypto::digest_size(tree_hash)) {
            return fail(Errc::malformed, "inclusion path node has the wrong size");
        }
        CEXCHAIN_TRY(crypto::Digest digest, crypto::Digest::from_bytes(bytes));
        proof.path.push_back(digest);
    }
    if (proof.leaf_index >= proof.tree_size) {
        return fail(Errc::malformed, "leaf index is outside the tree");
    }

    return Receipt{
        .encoded = Bytes(encoded.begin(), encoded.end()),
        .envelope = std::move(message),
        .tree_hash = tree_hash,
        .proof = std::move(proof),
        .kid = kid,
    };
}

Result<crypto::Digest> receipt_root(const crypto::Provider& provider, const Receipt& receipt,
                                    ByteView entry_bytes, merkle::InclusionMemo* memo) {
    CEXCHAIN_TRY(crypto::Digest leaf, merkle::leaf_hash(provider, receipt.tree_hash, entry_bytes));
    return merkle::root_from_inclusion_proof(provider, receipt.tree_hash, leaf,
                                             receipt.proof.leaf_index, receipt.proof.tree_size,
                                             receipt.proof.path, memo);
}

Status verify_receipt_signature(const crypto::Provider& provider, const Receipt& receipt,
                                const crypto::Digest& root, const crypto::PublicKey& log_key) {
    CEXCHAIN_TRY(Id expected_kid, key_id(provider, receipt.tree_hash, log_key));
    if (expected_kid != receipt.kid) {
        return fail(Errc::verification_failed, "key does not match the kid in the receipt");
    }
    return cose::verify(provider, receipt.envelope, log_key, {}, root.bytes());
}

Result<crypto::Digest> verify_receipt(const crypto::Provider& provider, const Receipt& receipt,
                                      ByteView entry_bytes, const crypto::PublicKey& log_key) {
    CEXCHAIN_TRY(crypto::Digest root, receipt_root(provider, receipt, entry_bytes));
    CEXCHAIN_CHECK(verify_receipt_signature(provider, receipt, root, log_key));
    return root;
}

} // namespace cexchain::protocol
