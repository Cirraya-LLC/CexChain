// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <utility>
#include <variant>

#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/state.hpp>

#include "reader.hpp"

namespace cexchain::protocol {

namespace {

using detail::entry;
using detail::MapReader;

struct Included {
    std::uint64_t index = 0;
    LogEntry log_entry;
    SignedStatement statement;
};

std::unexpected<Error> verification_failure(std::string_view detail) {
    return fail(Errc::verification_failed, detail);
}

ActorSummary summarize(const LedgerState& state, const Id& id) {
    ActorSummary summary;
    summary.id = id;
    if (const ActorState* actor = state.actor(id)) {
        summary.kind = actor->kind;
        summary.name = actor->display_name;
        summary.agent = actor->agent;
        if (actor->responsible) {
            if (const ActorState* responsible = state.actor(*actor->responsible)) {
                summary.responsible = responsible->display_name;
            }
        }
    }
    return summary;
}

std::vector<ActorSummary> authority_chain(const LedgerState& state,
                                          const std::optional<Id>& delegation_id) {
    std::vector<ActorSummary> chain;
    std::optional<Id> next = delegation_id;
    while (next) {
        const DelegationState* delegation = state.delegation(*next);
        if (delegation == nullptr) {
            break;
        }
        chain.push_back(summarize(state, delegation->grantor));
        next = delegation->parent;
    }
    return chain;
}

std::string event_detail(const Statement& statement) {
    if (const auto* b = std::get_if<RecordEndorseBody>(&statement.body)) {
        return b->role;
    }
    if (const auto* b = std::get_if<RecordTransitionBody>(&statement.body)) {
        return b->from_state + " -> " + b->to_state;
    }
    if (const auto* b = std::get_if<RecordRevokeBody>(&statement.body)) {
        return b->reason.value_or("");
    }
    return {};
}

} // namespace

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

Result<Bytes> encode_bundle(const EvidenceBundle& bundle) {
    if (bundle.entries.empty()) {
        return fail(Errc::invalid_argument, "a bundle needs at least the genesis entry");
    }
    cbor::Array entries;
    for (const EvidenceEntry& e : bundle.entries) {
        entries.push_back(
            cbor::Value::array({cbor::Value::bytes(e.entry), cbor::Value::bytes(e.receipt)}));
    }
    cbor::Map map{
        entry(0, cbor::Value::unsigned_integer(evidence_bundle_version)),
        entry(1, cbor::Value::bytes(bundle.record.bytes())),
        entry(2, cbor::Value::array(std::move(entries))),
        entry(3, cbor::Value::bytes(bundle.checkpoint)),
    };
    if (!bundle.cosignatures.empty()) {
        cbor::Array cosignatures;
        for (const Bytes& c : bundle.cosignatures) {
            cosignatures.push_back(cbor::Value::bytes(c));
        }
        map.push_back(entry(4, cbor::Value::array(std::move(cosignatures))));
    }
    if (!bundle.disclosures.empty()) {
        cbor::Array disclosures;
        for (const FieldDisclosure& d : bundle.disclosures) {
            cbor::Array path;
            for (const crypto::Digest& node : d.path) {
                path.push_back(cbor::Value::bytes(node.bytes()));
            }
            disclosures.push_back(cbor::Value::array({cbor::Value::bytes(d.leaf),
                                                      cbor::Value::unsigned_integer(d.index),
                                                      cbor::Value::array(std::move(path))}));
        }
        map.push_back(entry(5, cbor::Value::array(std::move(disclosures))));
    }
    if (!bundle.attachments.empty()) {
        cbor::Array attachments;
        for (const AttachmentOpening& a : bundle.attachments) {
            attachments.push_back(
                cbor::Value::array({cbor::Value::text(a.name), cbor::Value::bytes(a.salt)}));
        }
        map.push_back(entry(6, cbor::Value::array(std::move(attachments))));
    }
    return cbor::encode(cbor::Value::map(std::move(map)));
}

Result<EvidenceBundle> decode_bundle(ByteView encoded) {
    // Bundles hold many signed objects; allow more items than the default.
    cbor::DecodeOptions options;
    options.max_items = std::size_t{1} << 20;
    CEXCHAIN_TRY(cbor::Value value, cbor::decode(encoded, options));
    CEXCHAIN_TRY(MapReader reader, MapReader::open(value));
    EvidenceBundle bundle;

    CEXCHAIN_TRY(std::uint64_t version, reader.need_uint(0));
    if (version != evidence_bundle_version) {
        return fail(Errc::unsupported, "unsupported evidence bundle version");
    }
    CEXCHAIN_TRY(bundle.record, reader.need_id(1));

    CEXCHAIN_TRY(const cbor::Value* entries_value, reader.need(2));
    CEXCHAIN_TRY(const cbor::Array* entries, detail::as_array(*entries_value));
    if (entries->empty()) {
        return fail(Errc::malformed, "a bundle needs at least the genesis entry");
    }
    for (const cbor::Value& item : *entries) {
        const cbor::Array* pair = item.as_array();
        if (pair == nullptr || pair->size() != 2) {
            return fail(Errc::malformed, "evidence entry must be [entry, receipt]");
        }
        EvidenceEntry e;
        CEXCHAIN_TRY(e.entry, detail::as_bytes_value((*pair)[0]));
        CEXCHAIN_TRY(e.receipt, detail::as_bytes_value((*pair)[1]));
        bundle.entries.push_back(std::move(e));
    }
    CEXCHAIN_TRY(bundle.checkpoint, reader.need_bytes(3));

    auto non_empty_list = [](const cbor::Value& list_value) -> Result<const cbor::Array*> {
        const cbor::Array* list = list_value.as_array();
        if (list == nullptr) {
            return fail(Errc::malformed, "expected an array");
        }
        if (list->empty()) {
            return fail(Errc::non_canonical, "an empty list must be omitted");
        }
        return list;
    };
    if (const cbor::Value* list_value = reader.get(4)) {
        CEXCHAIN_TRY(const cbor::Array* list, non_empty_list(*list_value));
        for (const cbor::Value& item : *list) {
            CEXCHAIN_TRY(Bytes cosignature, detail::as_bytes_value(item));
            bundle.cosignatures.push_back(std::move(cosignature));
        }
    }
    if (const cbor::Value* list_value = reader.get(5)) {
        CEXCHAIN_TRY(const cbor::Array* list, non_empty_list(*list_value));
        for (const cbor::Value& item : *list) {
            const cbor::Array* parts = item.as_array();
            if (parts == nullptr || parts->size() != 3) {
                return fail(Errc::malformed, "field disclosure must be [leaf, index, path]");
            }
            FieldDisclosure d;
            CEXCHAIN_TRY(d.leaf, detail::as_bytes_value((*parts)[0]));
            CEXCHAIN_TRY(d.index, detail::as_uint((*parts)[1]));
            CEXCHAIN_TRY(const cbor::Array* path, detail::as_array((*parts)[2]));
            for (const cbor::Value& node : *path) {
                CEXCHAIN_TRY(Bytes bytes, detail::as_bytes_value(node));
                CEXCHAIN_TRY(crypto::Digest digest, crypto::Digest::from_bytes(bytes));
                d.path.push_back(digest);
            }
            bundle.disclosures.push_back(std::move(d));
        }
    }
    if (const cbor::Value* list_value = reader.get(6)) {
        CEXCHAIN_TRY(const cbor::Array* list, non_empty_list(*list_value));
        for (const cbor::Value& item : *list) {
            const cbor::Array* parts = item.as_array();
            if (parts == nullptr || parts->size() != 2) {
                return fail(Errc::malformed, "attachment opening must be [name, salt]");
            }
            AttachmentOpening a;
            CEXCHAIN_TRY(a.name, detail::as_text((*parts)[0]));
            CEXCHAIN_TRY(Bytes salt, detail::as_bytes_value((*parts)[1]));
            if (salt.size() != a.salt.size()) {
                return fail(Errc::malformed, "attachment salt must be 16 bytes");
            }
            std::ranges::copy(salt, a.salt.begin());
            bundle.attachments.push_back(std::move(a));
        }
    }
    CEXCHAIN_CHECK(reader.finish());
    return bundle;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

Result<EvidenceReport> verify_bundle(const crypto::Provider& provider, ByteView encoded,
                                     const VerifyOptions& options) {
    CEXCHAIN_TRY(EvidenceBundle bundle, decode_bundle(encoded));

    // Genesis fixes the ledger's identity, hash, and keys.
    CEXCHAIN_TRY(LogEntry genesis_entry, decode_log_entry(bundle.entries.front().entry));
    CEXCHAIN_TRY(SignedStatement genesis, parse_statement(provider, genesis_entry.statement));
    if (genesis.id != genesis_entry.statement_id) {
        return verification_failure("the genesis entry has the wrong statement id");
    }
    auto state = LedgerState::from_genesis(provider, genesis);
    if (!state) {
        return verification_failure("the genesis statement does not verify");
    }
    if (options.expected_ledger && *options.expected_ledger != state->ledger_id()) {
        return verification_failure("the bundle comes from a different ledger");
    }

    // The checkpoint every receipt must lead to.
    CEXCHAIN_TRY(SignedCheckpoint checkpoint, parse_checkpoint(bundle.checkpoint));
    if (!verify_checkpoint(provider, checkpoint, state->log_key())) {
        return verification_failure("the checkpoint is not signed by the ledger's log key");
    }
    if (checkpoint.checkpoint.ledger_id != state->ledger_id() ||
        checkpoint.checkpoint.tree_hash != state->hash()) {
        return verification_failure("the checkpoint belongs to a different ledger");
    }

    // Every entry is proven to be in the checkpointed log, in order.
    std::vector<Included> included;
    std::optional<std::uint64_t> previous_index;
    Timestamp previous_time = 0;
    for (const EvidenceEntry& e : bundle.entries) {
        auto receipt = parse_receipt(e.receipt);
        if (!receipt) {
            return verification_failure("a receipt is malformed");
        }
        auto root = verify_receipt(provider, *receipt, e.entry, state->log_key());
        if (!root || receipt->tree_hash != state->hash() ||
            receipt->proof.tree_size != checkpoint.checkpoint.tree_size ||
            *root != checkpoint.checkpoint.root) {
            return verification_failure("an entry is not proven to be in the checkpointed log");
        }
        const std::uint64_t index = receipt->proof.leaf_index;
        if ((!previous_index && index != 0) || (previous_index && index <= *previous_index)) {
            return verification_failure("entries must start at genesis and ascend by log index");
        }
        CEXCHAIN_TRY(LogEntry log_entry, decode_log_entry(e.entry));
        if (log_entry.registered_at < previous_time) {
            return verification_failure("entries go back in time");
        }
        Included item{index, log_entry, genesis};
        if (index != 0) {
            CEXCHAIN_TRY(item.statement,
                         parse_statement(provider, log_entry.statement, state->hash()));
            if (item.statement.id != log_entry.statement_id) {
                return verification_failure("an entry has the wrong statement id");
            }
        } else if (log_entry != genesis_entry) {
            return verification_failure("the genesis entry is inconsistent");
        }
        previous_index = index;
        previous_time = log_entry.registered_at;
        included.push_back(std::move(item));
    }

    // Replay the included statements under the ledger rules.
    for (const Included& item : included) {
        if (item.index == 0) {
            continue;
        }
        if (!state->validate(provider, item.statement, item.log_entry.registered_at)) {
            return verification_failure(
                "an included statement fails the ledger rules or depends on a missing statement");
        }
        CEXCHAIN_CHECK(state->apply(provider, item.statement, item.index));
    }

    const RecordState* record = state->record(bundle.record);
    if (record == nullptr) {
        return verification_failure("the bundle does not include the record's registration");
    }

    EvidenceReport report;
    report.ledger_id = state->ledger_id();
    report.organization = state->organization();
    report.hash = state->hash();
    report.checkpoint = checkpoint.checkpoint;
    report.record = record->id;
    report.record_type = record->record_type;
    report.state = record->state;
    report.revoked = record->revoked;

    const RecordRegisterBody* registration = nullptr;
    for (const std::uint64_t index : record->history) {
        const auto it = std::ranges::find(included, index, &Included::index);
        const Statement& statement = it->statement.statement;
        if (const auto* body = std::get_if<RecordRegisterBody>(&statement.body)) {
            registration = body;
            report.metadata = body->metadata;
        }
        report.events.push_back(RecordEvent{
            .index = index,
            .registered_at = it->log_entry.registered_at,
            .issued_at = statement.issued_at,
            .type = statement.type(),
            .actor = summarize(*state, *statement.actor_id),
            .authority = authority_chain(*state, statement.delegation_id),
            .provenance = statement.provenance,
            .detail = event_detail(statement),
        });
    }

    for (const FieldDisclosure& disclosure : bundle.disclosures) {
        auto field = verify_disclosure(provider, state->hash(), record->field_root,
                                       record->field_count, disclosure);
        if (!field) {
            return verification_failure("a disclosed field does not match the record's commitment");
        }
        report.disclosed_fields.push_back(std::move(*field));
    }

    if (registration == nullptr) {
        return verification_failure("the bundle does not include the record's registration");
    }
    for (const AttachmentOpening& opening : bundle.attachments) {
        const bool known = std::ranges::any_of(
            registration->attachments, [&](const Attachment& a) { return a.name == opening.name; });
        if (!known) {
            return verification_failure("an attachment opening names no attachment of the record");
        }
    }
    for (const Attachment& attachment : registration->attachments) {
        AttachmentCheck check{attachment.name, attachment.media_type, attachment.size,
                              AttachmentStatus::not_provided};
        const auto opening =
            std::ranges::find(bundle.attachments, attachment.name, &AttachmentOpening::name);
        const auto content = options.attachment_contents.find(attachment.name);
        if (opening != bundle.attachments.end() && content != options.attachment_contents.end()) {
            CEXCHAIN_TRY(
                crypto::Digest commitment,
                attachment_commitment(provider, state->hash(), opening->salt, content->second));
            const bool matches = std::ranges::equal(commitment.bytes(), attachment.commitment) &&
                                 content->second.size() == attachment.size;
            check.status = matches ? AttachmentStatus::verified : AttachmentStatus::mismatch;
        }
        report.attachments.push_back(std::move(check));
    }

    for (const Bytes& encoded_cosignature : bundle.cosignatures) {
        auto cosignature = parse_cosignature(encoded_cosignature);
        if (!cosignature || cosignature->checkpoint != checkpoint.checkpoint) {
            return verification_failure("a cosignature does not cover the bundle's checkpoint");
        }
        bool trusted = false;
        for (const crypto::PublicKey& witness : options.trusted_witnesses) {
            auto kid = key_id(provider, state->hash(), witness);
            if (kid && *kid == cosignature->kid) {
                if (!verify_cosignature(provider, *cosignature, witness)) {
                    return verification_failure("a trusted witness's cosignature does not verify");
                }
                trusted = true;
                break;
            }
        }
        ++(trusted ? report.trusted_cosignatures : report.untrusted_cosignatures);
    }
    return report;
}

} // namespace cexchain::protocol
