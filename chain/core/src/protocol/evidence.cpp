// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <map>
#include <set>
#include <span>
#include <utility>
#include <variant>
#include <vector>

#include <cexchain/core/merkle.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/state.hpp>

#include "evidence_detail.hpp"
#include "reader.hpp"

namespace cexchain::protocol {

namespace {

using detail::entry;
using detail::MapReader;

struct Included {
    std::uint64_t index = 0;
    LogEntry log_entry;
    SignedStatement statement;
    /// Set for a state commitment entry, which carries no statement.
    std::optional<SignedStateCommitment> commitment;
    Receipt receipt;
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
        summary.revoked = actor->revoked;
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
    if (const auto* b = std::get_if<ContractCallBody>(&statement.body)) {
        return b->function;
    }
    return {};
}

/// A request (v0.8) as the replayed state has it, as of a checkpoint signed
/// at `checkpoint_time`.
RequestReport request_report(const RequestState& r, Timestamp checkpoint_time) {
    return RequestReport{
        .id = r.id,
        .instance = r.instance,
        .call = r.call,
        .position = r.position,
        .kind = r.kind,
        .params = r.params,
        .deadline = r.deadline,
        .reply = r.reply,
        .asked_at = r.asked_at,
        .status = r.status,
        .answered_by = r.answered_by,
        .answered_at = r.answered_at,
        .late_by = r.late_by(),
        .overdue = r.open() && checkpoint_time >= r.deadline,
    };
}

} // namespace

std::vector<std::size_t> InstanceReport::open_requests() const {
    std::vector<std::size_t> out;
    for (std::size_t i = 0; i < requests.size(); ++i) {
        if (!requests[i].status) {
            out.push_back(i);
        }
    }
    return out;
}

std::vector<std::size_t> InstanceReport::overdue_requests() const {
    std::vector<std::size_t> out;
    for (std::size_t i = 0; i < requests.size(); ++i) {
        if (requests[i].overdue) {
            out.push_back(i);
        }
    }
    return out;
}

std::vector<Id> involved_objects(const LedgerState& state, const Id& record,
                                 std::span<const Statement> events) {
    std::vector<Id> out;
    auto add = [&](const Id& id) {
        if (!std::ranges::contains(out, id)) {
            out.push_back(id);
        }
    };
    add(record);
    if (const InstanceState* instance = state.instance(record)) {
        add(instance->contract);
    }
    if (const auto source = claim_source(events)) {
        add(*source);
    }
    for (const Statement& statement : events) {
        if (!statement.actor_id) {
            continue;
        }
        add(*statement.actor_id);
        if (const ActorState* actor = state.actor(*statement.actor_id);
            actor != nullptr && actor->kind == ActorKind::agent && actor->responsible) {
            add(*actor->responsible);
        }
        std::optional<Id> next = statement.delegation_id;
        for (std::size_t links = 0; next && links < 64; ++links) {
            add(*next);
            const DelegationState* delegation = state.delegation(*next);
            if (delegation == nullptr) {
                break;
            }
            add(delegation->grantor);
            next = delegation->parent;
        }
    }
    return out;
}

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
    if (!bundle.state_proofs.empty()) {
        cbor::Array proofs;
        for (const StateProof& p : bundle.state_proofs) {
            CEXCHAIN_TRY(Bytes leaf, encode_state_leaf(p.leaf));
            CEXCHAIN_TRY(cbor::Value leaf_value, cbor::decode(leaf));
            cbor::Array siblings;
            for (const crypto::Digest& s : p.siblings) {
                siblings.push_back(cbor::Value::bytes(s.bytes()));
            }
            proofs.push_back(cbor::Value::array(
                {std::move(leaf_value), cbor::Value::array(std::move(siblings))}));
        }
        map.push_back(entry(7, cbor::Value::array(std::move(proofs))));
    }
    if (!bundle.anchors.empty()) {
        cbor::Array anchors;
        for (const Anchor& a : bundle.anchors) {
            if (a.timestamps.empty() && a.network_cosignatures.empty()) {
                return fail(Errc::invalid_argument,
                            "an anchor needs a time-stamp token or a network cosignature");
            }
            cbor::Map anchor{entry(1, cbor::Value::bytes(a.checkpoint))};
            if (!a.timestamps.empty()) {
                cbor::Array tokens;
                for (const Bytes& token : a.timestamps) {
                    tokens.push_back(cbor::Value::bytes(token));
                }
                anchor.push_back(entry(2, cbor::Value::array(std::move(tokens))));
            }
            if (!a.consistency.empty()) {
                cbor::Array proof;
                for (const crypto::Digest& node : a.consistency) {
                    proof.push_back(cbor::Value::bytes(node.bytes()));
                }
                anchor.push_back(entry(3, cbor::Value::array(std::move(proof))));
            }
            if (!a.network_cosignatures.empty()) {
                cbor::Array cosignatures;
                for (const network::NoteSignature& s : a.network_cosignatures) {
                    cosignatures.push_back(cbor::Value::array(
                        {cbor::Value::text(s.name), cbor::Value::bytes(s.bytes)}));
                }
                anchor.push_back(entry(4, cbor::Value::array(std::move(cosignatures))));
            }
            anchors.push_back(cbor::Value::map(std::move(anchor)));
        }
        map.push_back(entry(8, cbor::Value::array(std::move(anchors))));
    }
    if (!bundle.memberships.empty()) {
        if (bundle.memberships.size() > max_membership_proofs) {
            return fail(Errc::invalid_argument, "a bundle carries at most 16 membership proofs");
        }
        cbor::Array proofs;
        for (const Bytes& proof : bundle.memberships) {
            proofs.push_back(cbor::Value::bytes(proof));
        }
        map.push_back(entry(9, cbor::Value::array(std::move(proofs))));
    }
    return cbor::encode(cbor::Value::map(std::move(map)));
}

Result<Id> bundle_ledger_id(ByteView encoded) {
    CEXCHAIN_TRY(EvidenceBundle bundle, decode_bundle(encoded));
    if (bundle.entries.empty()) {
        return fail(Errc::malformed, "the bundle has no genesis entry");
    }
    CEXCHAIN_TRY(LogEntry genesis, decode_log_entry(bundle.entries.front().entry));
    return genesis.statement_id;
}

Result<EvidenceBundle> decode_bundle(ByteView encoded) {
    if (encoded.size() > max_bundle_size) {
        return fail(Errc::limit_exceeded, "the evidence bundle is too large");
    }
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
    if (const cbor::Value* list_value = reader.get(7)) {
        CEXCHAIN_TRY(const cbor::Array* list, non_empty_list(*list_value));
        for (const cbor::Value& item : *list) {
            const cbor::Array* parts = item.as_array();
            const cbor::Array* leaf =
                parts == nullptr || parts->size() != 2 ? nullptr : (*parts)[0].as_array();
            if (leaf == nullptr || leaf->size() != 3 || (*parts)[1].as_array() == nullptr) {
                return fail(Errc::malformed,
                            "a state proof must be [[kind, id, history], siblings]");
            }
            StateProof p;
            CEXCHAIN_TRY(std::uint64_t kind, detail::as_uint((*leaf)[0]));
            if (kind < 1 || kind > static_cast<std::uint64_t>(ObjectKind::instance)) {
                return fail(Errc::malformed, "a state proof names an unknown kind of object");
            }
            p.leaf.kind = static_cast<ObjectKind>(kind);
            CEXCHAIN_TRY(Bytes id, detail::as_bytes_value((*leaf)[1]));
            CEXCHAIN_TRY(p.leaf.id, to_id(id));
            CEXCHAIN_TRY(const cbor::Array* history, detail::as_array((*leaf)[2]));
            for (const cbor::Value& index : *history) {
                CEXCHAIN_TRY(std::uint64_t i, detail::as_uint(index));
                p.leaf.history.push_back(i);
            }
            const cbor::Array& siblings = *(*parts)[1].as_array();
            if (siblings.size() > id_size * 8) {
                return fail(Errc::malformed, "a state proof is deeper than the tree");
            }
            for (const cbor::Value& node : siblings) {
                CEXCHAIN_TRY(Bytes bytes, detail::as_bytes_value(node));
                CEXCHAIN_TRY(crypto::Digest digest, crypto::Digest::from_bytes(bytes));
                p.siblings.push_back(digest);
            }
            if (!encode_state_leaf(p.leaf)) {
                return fail(Errc::malformed,
                            "a state proof's history must be non-empty and ascending");
            }
            bundle.state_proofs.push_back(std::move(p));
        }
    }
    if (const cbor::Value* list_value = reader.get(8)) {
        CEXCHAIN_TRY(const cbor::Array* list, non_empty_list(*list_value));
        for (const cbor::Value& item : *list) {
            CEXCHAIN_TRY(MapReader anchor_reader, MapReader::open(item));
            Anchor a;
            CEXCHAIN_TRY(a.checkpoint, anchor_reader.need_bytes(1));
            if (const cbor::Value* tokens_value = anchor_reader.get(2)) {
                CEXCHAIN_TRY(const cbor::Array* tokens, non_empty_list(*tokens_value));
                for (const cbor::Value& token : *tokens) {
                    CEXCHAIN_TRY(Bytes bytes, detail::as_bytes_value(token));
                    a.timestamps.push_back(std::move(bytes));
                }
            }
            if (const cbor::Value* proof_value = anchor_reader.get(3)) {
                CEXCHAIN_TRY(const cbor::Array* proof, non_empty_list(*proof_value));
                if (proof->size() > merkle::max_consistency_proof_length) {
                    return fail(Errc::malformed, "an anchor's consistency proof is too long");
                }
                for (const cbor::Value& node : *proof) {
                    CEXCHAIN_TRY(Bytes bytes, detail::as_bytes_value(node));
                    CEXCHAIN_TRY(crypto::Digest digest, crypto::Digest::from_bytes(bytes));
                    a.consistency.push_back(digest);
                }
            }
            if (const cbor::Value* cosignatures_value = anchor_reader.get(4)) {
                CEXCHAIN_TRY(const cbor::Array* cosignatures, non_empty_list(*cosignatures_value));
                for (const cbor::Value& item_value : *cosignatures) {
                    const cbor::Array* pair = item_value.as_array();
                    const std::string* name =
                        pair != nullptr && pair->size() == 2 ? (*pair)[0].as_text() : nullptr;
                    const Bytes* bytes =
                        pair != nullptr && pair->size() == 2 ? (*pair)[1].as_bytes() : nullptr;
                    if (name == nullptr || bytes == nullptr || !network::valid_name(*name) ||
                        bytes->size() < 12 || bytes->size() > 8192) {
                        return fail(Errc::malformed,
                                    "a network cosignature is not [name, 12 to 8,192 bytes]");
                    }
                    a.network_cosignatures.push_back({*name, *bytes});
                }
            }
            if (a.timestamps.empty() && a.network_cosignatures.empty()) {
                return fail(Errc::malformed,
                            "an anchor holds no time-stamp token and no network cosignature");
            }
            CEXCHAIN_CHECK(anchor_reader.finish());
            bundle.anchors.push_back(std::move(a));
        }
    }
    if (const cbor::Value* list_value = reader.get(9)) {
        CEXCHAIN_TRY(const cbor::Array* list, non_empty_list(*list_value));
        if (list->size() > max_membership_proofs) {
            return fail(Errc::malformed, "a bundle carries at most 16 membership proofs");
        }
        for (const cbor::Value& item : *list) {
            CEXCHAIN_TRY(Bytes proof, detail::as_bytes_value(item));
            bundle.memberships.push_back(std::move(proof));
        }
    }
    CEXCHAIN_CHECK(reader.finish());
    return bundle;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

namespace {

/// Counts the witnesses that cosigned the bundle's checkpoint into `report`.
Result<EvidenceReport> count_witnesses(const crypto::Provider& provider, const LedgerState& state,
                                       const SignedCheckpoint& checkpoint,
                                       const EvidenceBundle& bundle, const VerifyOptions& options,
                                       EvidenceReport report) {
    // Count witnesses, not cosignatures: a witness that signed twice (or a
    // bundle that repeats its cosignature) is still one witness.
    std::vector<Id> counted;
    for (const Bytes& encoded_cosignature : bundle.cosignatures) {
        auto cosignature = parse_cosignature(encoded_cosignature);
        if (!cosignature || cosignature->checkpoint != checkpoint.checkpoint) {
            return verification_failure("a cosignature does not cover the bundle's checkpoint");
        }
        if (std::ranges::contains(counted, cosignature->kid)) {
            continue;
        }
        counted.push_back(cosignature->kid);
        bool trusted = false;
        for (const crypto::PublicKey& witness : options.trusted_witnesses) {
            auto kid = key_id(provider, state.hash(), witness);
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

/// Checks the bundle's anchors (v0.11) into `report`: each checkpoint signed
/// by the log key in effect at its size and consistent with the bundle's,
/// each token over its payload. A trusted token bounds when the entries below
/// its checkpoint's size existed, and the ledger's clock must agree with it.
Result<EvidenceReport> check_anchors(const crypto::Provider& provider, const LedgerState& state,
                                     const SignedCheckpoint& checkpoint,
                                     const EvidenceBundle& bundle,
                                     std::span<const Included> included,
                                     const VerifyOptions& options, EvidenceReport report) {
    std::vector<Bytes> trusted_authorities;
    // Open-network witnesses, each counted once: (name, key ID).
    std::set<std::pair<std::string, Bytes>> trusted_network;
    std::set<std::pair<std::string, Bytes>> untrusted_network;
    for (const Anchor& anchor : bundle.anchors) {
        auto stamped = parse_checkpoint(anchor.checkpoint);
        if (!stamped || !stamped->envelope.payload) {
            return verification_failure("an anchor's checkpoint is malformed");
        }
        const Checkpoint& at = stamped->checkpoint;
        if (at.ledger_id != state.ledger_id() || at.tree_hash != state.hash()) {
            return verification_failure("an anchor's checkpoint belongs to a different ledger");
        }
        if (at.tree_size > checkpoint.checkpoint.tree_size) {
            return verification_failure("an anchor's checkpoint is later than the bundle's");
        }
        if (!verify_checkpoint(provider, *stamped, state.log_key_for(at.tree_size))) {
            return verification_failure(
                "an anchor's checkpoint is not signed by the ledger's log key");
        }
        if (at.tree_size == checkpoint.checkpoint.tree_size) {
            if (at.root != checkpoint.checkpoint.root || !anchor.consistency.empty()) {
                return verification_failure("an anchor's checkpoint disagrees with the bundle's");
            }
        } else if (!merkle::verify_consistency(provider, state.hash(), at.tree_size,
                                               checkpoint.checkpoint.tree_size, at.root,
                                               checkpoint.checkpoint.root, anchor.consistency)) {
            return verification_failure(
                "an anchor's checkpoint is not consistent with the bundle's");
        }
        CEXCHAIN_TRY(crypto::Digest stamped_digest,
                     provider.digest(state.hash(), *stamped->envelope.payload));

        // Open-network witnesses' cosignatures of the checkpoint's note
        // (v0.13): SHA-256 trees only.
        if (!anchor.network_cosignatures.empty() && state.hash() != crypto::HashAlg::sha256) {
            return verification_failure("an SM3 ledger's anchor carries network cosignatures");
        }
        const std::string origin = network::origin(state.ledger_id());
        for (const network::NoteSignature& cosignature : anchor.network_cosignatures) {
            auto time = network::cosignature_time(cosignature.bytes);
            if (!time) {
                return verification_failure("a network cosignature is malformed");
            }
            const Bytes id(cosignature.bytes.begin(), cosignature.bytes.begin() + 4);
            const auto key = std::ranges::find_if(
                options.trusted_network_witnesses, [&](const network::VerifierKey& k) {
                    return k.name == cosignature.name && std::ranges::equal(k.id, id);
                });
            const bool trusted = key != options.trusted_network_witnesses.end();
            if (trusted && !network::verify_cosignature(provider, *key, origin, at.tree_size,
                                                        at.root, cosignature)) {
                return verification_failure(
                    "a trusted network witness's cosignature does not verify");
            }
            (trusted ? trusted_network : untrusted_network).emplace(cosignature.name, id);
            report.network_cosignatures.push_back(NetworkCosignatureCheck{
                .witness = cosignature.name,
                .size = at.tree_size,
                .time = *time,
                .trusted = trusted,
            });
        }

        // The earliest time a trusted authority vouches for, its accuracy
        // added: everything below the checkpoint's size existed by then.
        std::optional<Timestamp> existed_by;
        for (const Bytes& encoded_token : anchor.timestamps) {
            auto token = provider.read_timestamp(encoded_token, options.trusted_timestamp_roots);
            if (!token) {
                if (token.error().code == Errc::unsupported) {
                    return std::unexpected(token.error());
                }
                return verification_failure("a time-stamp token does not verify");
            }
            if (token->imprint_alg != state.hash() ||
                !std::ranges::equal(token->imprint, stamped_digest.bytes())) {
                return verification_failure(
                    "a time-stamp token stamps something other than its anchor's checkpoint");
            }
            report.timestamps.push_back(TimestampCheck{
                .size = at.tree_size,
                .time = token->time,
                .accuracy = token->accuracy,
                .authority = token->authority,
                .trusted = token->trusted,
            });
            if (!token->trusted) {
                continue;
            }
            if (!std::ranges::contains(trusted_authorities, token->authority_key)) {
                trusted_authorities.push_back(token->authority_key);
            }
            const Timestamp latest = token->time + token->accuracy;
            existed_by = existed_by ? std::min(*existed_by, latest) : latest;
        }
        if (!existed_by) {
            continue;
        }
        // The ledger dated nothing it had by then later than the authority's
        // time allows.
        const Timestamp bound = *existed_by + timestamp_clock_slack;
        const bool contradicted =
            at.timestamp > bound || std::ranges::any_of(included, [&](const Included& i) {
                return i.index < at.tree_size && i.log_entry.registered_at > bound;
            });
        if (contradicted) {
            return verification_failure("the ledger's clock contradicts a time-stamp authority: "
                                        "it dates an entry after the authority saw it");
        }
        for (RecordEvent& event : report.events) {
            if (event.index < at.tree_size) {
                event.existed_by =
                    event.existed_by ? std::min(*event.existed_by, *existed_by) : *existed_by;
            }
        }
    }
    report.trusted_timestamp_authorities = trusted_authorities.size();
    report.trusted_cosignatures += trusted_network.size();
    for (const auto& witness : untrusted_network) {
        if (!trusted_network.contains(witness)) {
            ++report.untrusted_cosignatures;
        }
    }
    return report;
}

/// Step 9 (v0.16): each membership proof is a complete bundle of its own
/// ledger, about a membership that names this bundle's ledger; it says where
/// the membership stood when the record was registered (an instance's
/// creating call) and at the proof's checkpoint.
Result<EvidenceReport> check_memberships(const crypto::Provider& provider,
                                         const EvidenceBundle& bundle, const VerifyOptions& options,
                                         EvidenceReport report) {
    if (bundle.memberships.empty()) {
        return report;
    }
    const RecordEvent* registered = nullptr;
    if (report.instance) {
        const auto it =
            std::ranges::find(report.events, report.instance->created_by, &RecordEvent::index);
        registered = it == report.events.end() ? nullptr : &*it;
    } else if (!report.events.empty()) {
        registered = &report.events.front();
    }
    if (registered == nullptr) {
        return verification_failure("the bundle does not show when its record was registered");
    }
    // The proofs are other ledgers' evidence: none is expected, and the
    // verifier's trust in witnesses and authorities applies to them too.
    VerifyOptions inner;
    inner.trusted_witnesses = options.trusted_witnesses;
    inner.trusted_timestamp_roots = options.trusted_timestamp_roots;
    inner.trusted_network_witnesses = options.trusted_network_witnesses;
    inner.modules = options.modules;
    std::vector<std::pair<Id, Id>> seen;
    for (const Bytes& proof : bundle.memberships) {
        auto decoded = decode_bundle(proof);
        if (!decoded) {
            return verification_failure("a membership proof is malformed");
        }
        if (!decoded->memberships.empty()) {
            return verification_failure("a membership proof carries membership proofs");
        }
        auto checked = detail::verify_bundle_as_given(provider, proof, inner);
        if (!checked) {
            return verification_failure("a membership proof does not verify");
        }
        if (!checked->complete) {
            return verification_failure("a membership proof is not complete");
        }
        if (checked->record_type != membership_type || !checked->metadata ||
            checked->events.empty()) {
            return verification_failure("a membership proof is not of a membership");
        }
        auto membership = decode_membership(*checked->metadata);
        if (!membership) {
            return verification_failure("a membership proof's metadata is not a membership");
        }
        if (membership->member != report.ledger_id) {
            return verification_failure("a membership proof names another ledger as its member");
        }
        std::pair key{checked->ledger_id, checked->record};
        if (std::ranges::contains(seen, key)) {
            return verification_failure("a membership is proven twice");
        }
        seen.push_back(std::move(key));
        // Its history after its registration: transitions ("from -> to")
        // and a revocation.
        std::vector<MembershipChange> changes;
        for (const RecordEvent& e : checked->events) {
            if (e.type == StatementType::record_transition) {
                const std::size_t arrow = e.detail.find(" -> ");
                changes.push_back({e.registered_at,
                                   arrow == std::string::npos ? "" : e.detail.substr(arrow + 4)});
            } else if (e.type == StatementType::record_revoke) {
                changes.push_back({e.registered_at, ""});
            }
        }
        EvidenceReport::MembershipReport m;
        m.trust_node = checked->ledger_id;
        const auto node = std::ranges::find(options.trust_nodes, m.trust_node, &TrustNode::ledger);
        m.trusted = node != options.trust_nodes.end();
        if (m.trusted) {
            m.trust_node_name = node->name;
        }
        m.record = checked->record;
        m.registered_at = checked->events.front().registered_at;
        m.membership = std::move(*membership);
        m.record_time = registered->registered_at;
        m.at_record = standing_at(m.membership, m.registered_at, changes, m.record_time);
        m.checkpoint_time = checked->checkpoint.timestamp;
        m.at_checkpoint = standing_at(m.membership, m.registered_at, changes, m.checkpoint_time);
        report.memberships.push_back(std::move(m));
    }
    return report;
}

/// The last steps of a verification: witnesses, anchors, then memberships.
Result<EvidenceReport> finish_report(const crypto::Provider& provider, const LedgerState& state,
                                     const SignedCheckpoint& checkpoint,
                                     const EvidenceBundle& bundle,
                                     std::span<const Included> included,
                                     const VerifyOptions& options, EvidenceReport report) {
    CEXCHAIN_TRY(report,
                 count_witnesses(provider, state, checkpoint, bundle, options, std::move(report)));
    CEXCHAIN_TRY(report, check_anchors(provider, state, checkpoint, bundle, included, options,
                                       std::move(report)));
    return check_memberships(provider, bundle, options, std::move(report));
}

} // namespace

Result<crypto::Digest> CheckedProvider::do_digest(crypto::HashAlg alg,
                                                  std::span<const ByteView> parts) const {
    return provider_.digest(alg, parts);
}

Status CheckedProvider::do_verify(const crypto::PublicKey& key, ByteView message,
                                  ByteView signature) const {
    if (std::optional<Status> known = checks_.find(key, message, signature)) {
        return std::move(*known);
    }
    Status outcome = provider_.verify(key, message, signature);
    checks_.checked(key, message, signature, outcome);
    return outcome;
}

Result<crypto::TimestampToken>
CheckedProvider::do_read_timestamp(ByteView token, std::span<const Bytes> trusted_roots) const {
    return provider_.read_timestamp(token, trusted_roots);
}

Result<EvidenceReport> verify_bundle(const crypto::Provider& provider, ByteView encoded,
                                     const VerifyOptions& options) {
    if (options.signatures == nullptr) {
        return detail::verify_bundle_as_given(provider, encoded, options);
    }
    const CheckedProvider checked(provider, *options.signatures);
    return detail::verify_bundle_as_given(checked, encoded, options);
}

Result<EvidenceReport> detail::verify_bundle_as_given(const crypto::Provider& provider,
                                                      ByteView encoded,
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
    state->replay_bundle();
    state->load_modules_with(options.modules);
    if (options.expected_ledger && *options.expected_ledger != state->ledger_id()) {
        return verification_failure("the bundle comes from a different ledger");
    }

    // The checkpoint every receipt must lead to. Its signature, and the
    // receipts', are checked with the log key in effect at its size, which
    // the replay below learns (the bundle carries every key rotation).
    CEXCHAIN_TRY(SignedCheckpoint checkpoint, parse_checkpoint(bundle.checkpoint));
    if (checkpoint.checkpoint.ledger_id != state->ledger_id() ||
        checkpoint.checkpoint.tree_hash != state->hash()) {
        return verification_failure("the checkpoint belongs to a different ledger");
    }

    // Every entry is proven to lead to the checkpoint's root, in order.
    // Receipts share the upper parts of their paths: each part is hashed
    // once (the memo points into the receipts, kept in `included`, which
    // never reallocates).
    std::vector<Included> included;
    included.reserve(bundle.entries.size());
    merkle::InclusionMemo memo;
    std::optional<std::uint64_t> previous_index;
    Timestamp previous_time = 0;
    for (const EvidenceEntry& e : bundle.entries) {
        auto receipt = parse_receipt(e.receipt);
        if (!receipt) {
            return verification_failure("a receipt is malformed");
        }
        auto root = receipt_root(provider, *receipt, e.entry, &memo);
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
        Included item{index, log_entry, genesis, std::nullopt, std::move(*receipt)};
        if (index != 0 && log_entry.is_state_commitment()) {
            auto commitment = parse_state_commitment(provider, log_entry.state_commitment);
            if (!commitment || commitment->id != log_entry.statement_id ||
                commitment->commitment.ledger_id != state->ledger_id() ||
                commitment->commitment.tree_hash != state->hash() ||
                commitment->commitment.tree_size != index) {
                return verification_failure("a state commitment in the bundle does not verify");
            }
            item.commitment = std::move(*commitment);
        } else if (index != 0) {
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

    // Replay the included statements under the ledger rules, noting each
    // proof of presence against the credentials of the moment, and what the
    // contract made of each call (on the bundle's instance, or, for a child,
    // on its ancestors).
    std::map<std::uint64_t, PresenceCheck> presence;
    std::map<std::uint64_t, ContractAccept> outcomes;
    for (const Included& item : included) {
        if (item.index == 0 || item.commitment) {
            continue;
        }
        if (const Statement& s = item.statement.statement; s.presence && s.actor_id) {
            if (const ActorState* signer = state->actor(*s.actor_id)) {
                if (auto check = verify_presence(provider, state->hash(), s, item.statement.kid,
                                                 signer->presence)) {
                    presence[item.index] = std::move(*check);
                }
            }
        }
        // A contract call runs once: what validate ran is the outcome, and
        // apply takes it.
        Validation validation;
        if (!state->validate(provider, item.statement, item.log_entry.registered_at, nullptr,
                             &validation)) {
            return verification_failure(
                "an included statement fails the ledger rules or depends on a missing statement");
        }
        if (const ContractRun* run = validation.run()) {
            if (const ContractAccept* accept = run->accepted()) {
                outcomes.emplace(item.index, *accept);
            }
        }
        CEXCHAIN_CHECK(state->apply(provider, item.statement, item.index,
                                    item.log_entry.registered_at, &validation));
    }

    // Now the keys: the checkpoint and every receipt with the log key in
    // effect at its size, each state commitment with the one at its index.
    // (Receipts against one checkpoint usually share one signature.)
    const crypto::PublicKey& log_key = state->log_key_for(checkpoint.checkpoint.tree_size);
    if (!verify_checkpoint(provider, checkpoint, log_key)) {
        return verification_failure("the checkpoint is not signed by the ledger's log key");
    }
    std::set<std::pair<Bytes, Bytes>> verified;
    for (const Included& item : included) {
        auto seal =
            std::pair(item.receipt.envelope.protected_bytes, item.receipt.envelope.signature);
        if (!verified.contains(seal)) {
            if (!verify_receipt_signature(provider, item.receipt, checkpoint.checkpoint.root,
                                          log_key)) {
                return verification_failure("a receipt is not signed by the ledger's log key");
            }
            verified.insert(std::move(seal));
        }
        if (item.commitment &&
            !verify_state_commitment(provider, *item.commitment, state->log_key_for(item.index))) {
            return verification_failure("a state commitment in the bundle does not verify");
        }
    }

    const RecordState* record = state->record(bundle.record);
    const InstanceState* instance = record == nullptr ? state->instance(bundle.record) : nullptr;
    if (record == nullptr && instance == nullptr) {
        return verification_failure("the bundle does not include the record's registration");
    }
    // The events to show: the record's, or the instance's calls; for a child,
    // its ancestors' first, up to each call that created the next generation
    // (v0.7). Replaying them made the child, at its position, from its
    // parent's call: it exists in the replayed state only so.
    const std::vector<std::uint64_t> history =
        record != nullptr ? record->history.to_vector() : instance_events(*state, *instance);

    EvidenceReport report;
    report.ledger_id = state->ledger_id();
    report.organization = state->organization();
    report.hash = state->hash();
    report.checkpoint = checkpoint.checkpoint;
    report.log_key = log_key;
    report.log_key_rotations = state->log_keys().size() - 1;
    report.root_key_rotations = state->root_keys().size() - 1;
    report.record = bundle.record;
    if (record != nullptr) {
        report.record_type = record->record_type;
        report.state = record->state;
        report.revoked = record->revoked;
        if (record->supersedes) {
            report.supersedes = Id(*record->supersedes);
        }
        if (record->superseded_by) {
            report.superseded_by = Id(*record->superseded_by);
        }
    } else {
        const ContractState* contract = state->contract(instance->contract);
        // The deploy is in the bundle: the contract was loaded from it while
        // replaying (entries ascend by index, checked above).
        const auto deploy =
            std::ranges::lower_bound(included, contract->deployed_at_index, {}, &Included::index);
        const auto* body = deploy == included.end() || deploy->index != contract->deployed_at_index
                               ? nullptr
                               : std::get_if<ContractDeployBody>(&deploy->statement.statement.body);
        if (body == nullptr) {
            return verification_failure("the bundle does not include the contract's deploy");
        }
        report.instance = InstanceReport{
            .contract = instance->contract,
            .contract_name = contract->name,
            .language = contract->language,
            .compiler = contract->compiler,
            .code = body->code,
            .interface = body->interface,
            .source = body->source,
            .contract_retired = contract->retired,
            .head = instance->head,
            .state = instance->state,
            .status = instance->status,
            .parties = instance->parties,
            .final = instance->final,
            .created_by = instance->created_by,
            .parent = instance->parent ? std::optional<Id>(instance->parent->id()) : std::nullopt,
            .position = instance->position,
            .depth = instance->depth,
            .ancestors = {},
            .first_own_event = static_cast<std::size_t>(
                std::ranges::lower_bound(history, instance->created_by) - history.begin()),
            .requests = {},
        };
        // Its own requests (v0.8), derived by the replay: the bundle holds
        // every call on the instance, so every request and every answer.
        for (const auto& [key, request] : state->requests()) {
            if (request.instance == instance->id) {
                report.instance->requests.push_back(
                    request_report(request, checkpoint.checkpoint.timestamp));
            }
        }
        for (const InstanceAncestor& a : instance_ancestors(*state, *instance)) {
            AncestorReport ancestor{
                .id = a.instance->id,
                .depth = a.instance->depth,
                .parent =
                    a.instance->parent ? std::optional<Id>(a.instance->parent->id()) : std::nullopt,
                .position = a.instance->position,
                .created_by = a.instance->created_by,
                .until = a.until,
                .events = {},
            };
            for (std::size_t i = 0; i < history.size(); ++i) {
                if (history[i] >= a.instance->created_by && history[i] <= a.until &&
                    std::ranges::binary_search(a.instance->history, history[i])) {
                    ancestor.events.push_back(i);
                }
            }
            report.instance->ancestors.push_back(std::move(ancestor));
        }
        if (instance->status) {
            report.state = *instance->status;
        }
    }

    // Entries ascend by index (checked above): find them by binary search,
    // so a long history costs O(h log n), not O(h n).
    auto included_at = [&](std::uint64_t index) {
        return std::ranges::lower_bound(included, index, {}, &Included::index);
    };
    const RecordRegisterBody* registration = nullptr;
    for (const std::uint64_t index : history) {
        const auto it = included_at(index);
        const Statement& statement = it->statement.statement;
        // The record's own registration; another in its history registered
        // the version that superseded it (v0.10).
        std::optional<Id> new_version;
        std::string detail = event_detail(statement);
        if (const auto* body = std::get_if<RecordRegisterBody>(&statement.body)) {
            if (it->statement.id == bundle.record) {
                registration = body;
                report.metadata = body->metadata;
            } else {
                new_version = it->statement.id;
                detail = body->record_type;
            }
        }
        // The instances a call created (v0.7), and the requests it made
        // (v0.8), by the ids derived from it.
        std::vector<Id> children;
        std::vector<Id> requests;
        if (const auto outcome = outcomes.find(index); outcome != outcomes.end()) {
            for (std::size_t n = 0; n < outcome->second.children.size(); ++n) {
                auto child = child_instance_id(provider, state->hash(), it->statement.id, n);
                if (!child) {
                    return std::unexpected(child.error());
                }
                children.push_back(*child);
            }
            for (std::size_t n = 0; n < outcome->second.requests.size(); ++n) {
                auto request = request_id(provider, state->hash(), it->statement.id, n);
                if (!request) {
                    return std::unexpected(request.error());
                }
                requests.push_back(*request);
            }
        }
        // An answer (v0.8): the request it closed, which the replay made.
        std::optional<RequestReport> answered;
        if (const auto* call = std::get_if<ContractCallBody>(&statement.body);
            call && call->answer) {
            if (const RequestState* request = state->request(call->answer->request)) {
                answered = request_report(*request, checkpoint.checkpoint.timestamp);
            }
        }
        report.events.push_back(RecordEvent{
            .index = index,
            .registered_at = it->log_entry.registered_at,
            .issued_at = statement.issued_at,
            .type = statement.type(),
            .actor = summarize(*state, *statement.actor_id),
            .authority = authority_chain(*state, statement.delegation_id),
            .provenance = statement.provenance,
            .presence = presence.contains(index) ? std::optional(presence.at(index)) : std::nullopt,
            .detail = std::move(detail),
            .contract_call = std::holds_alternative<ContractCallBody>(statement.body)
                                 ? std::optional(std::get<ContractCallBody>(statement.body))
                                 : std::nullopt,
            .outcome = outcomes.contains(index) ? std::optional(outcomes.at(index)) : std::nullopt,
            .children = std::move(children),
            .requests = std::move(requests),
            .answered = std::move(answered),
            .new_version = new_version,
            .existed_by = std::nullopt,
        });
    }

    // A claim (v0.14): its terms, and its source as the bundle shows it.
    if (record != nullptr && record->record_type == claim_type && report.metadata) {
        auto claim = decode_claim(*report.metadata);
        const RecordState* source = claim ? state->record(claim->source) : nullptr;
        if (source == nullptr) {
            return verification_failure("a claim's source is not in its evidence");
        }
        EvidenceReport::ClaimReport c;
        c.text = claim_text(*claim);
        c.source_type = source->record_type;
        c.source_status = source->revoked ? "revoked" : source->superseded_by ? "replaced" : "live";
        c.lapsed = claim->until && checkpoint.checkpoint.timestamp > *claim->until;
        c.claim = std::move(*claim);
        report.claim = std::move(c);
    }

    // Completeness: every involved object's history, as replayed from the
    // bundle, must be exactly the history the checkpoint's state root commits
    // to. A left-out statement (a later revocation, say) shows as a mismatch.
    // The state commitment the ledger appended just before signing the
    // checkpoint: the last entry the checkpoint covers.
    const auto last = std::ranges::find_if(included, [&](const Included& i) {
        return i.commitment && i.index + 1 == checkpoint.checkpoint.tree_size;
    });
    if (last != included.end()) {
        const crypto::Digest* state_root = &last->commitment->commitment.state_root;
        report.state_commitment = last->commitment->commitment;
        std::vector<Statement> events;
        for (const std::uint64_t index : history) {
            events.push_back(included_at(index)->statement.statement);
        }
        // A claim's source (v0.14): its statements count as events too
        // (each one included: the replayed state knows no other).
        if (const auto source = claim_source(events); source && state->record(*source)) {
            for (const std::uint64_t index : state->record(*source)->history.to_vector()) {
                events.push_back(included_at(index)->statement.statement);
            }
        }
        std::map<IdKey, const StateProof*> proven;
        for (const StateProof& proof : bundle.state_proofs) {
            if (!proven.emplace(key_of(proof.leaf.id), &proof).second) {
                return verification_failure("a state proof is repeated");
            }
            if (!verify_state_proof(provider, state->hash(), proof, *state_root)) {
                return verification_failure(
                    "a state proof does not match the ledger's state commitment");
            }
        }
        for (const Id& id : involved_objects(*state, bundle.record, events)) {
            const auto proof = proven.find(key_of(id));
            if (proof == proven.end()) {
                return verification_failure(
                    "the bundle does not prove the complete history of everyone involved");
            }
            const auto replayed = state_leaf(*state, id);
            if (!replayed || *replayed != proof->second->leaf) {
                return verification_failure("the bundle leaves out part of a history it must show "
                                            "in full (for example a revocation)");
            }
        }
        report.complete = true;
    } else if (!bundle.state_proofs.empty()) {
        return verification_failure(
            "state proofs need the state commitment the checkpoint ends with");
    }

    if (instance != nullptr) {
        // An instance has no fields or attachments: its state is public to
        // whoever holds its evidence.
        if (!bundle.disclosures.empty() || !bundle.attachments.empty()) {
            return verification_failure("an instance has no fields or attachments to disclose");
        }
        return finish_report(provider, *state, checkpoint, bundle, included, options,
                             std::move(report));
    }

    // Leaves are sorted by name, one per name: disclosures must agree (a
    // record committing two leaves of one name could otherwise show each
    // party a different value).
    std::map<std::uint64_t, std::string> disclosed_at;
    for (const FieldDisclosure& disclosure : bundle.disclosures) {
        auto field = verify_disclosure(provider, state->hash(), record->field_root,
                                       record->field_count, disclosure);
        if (!field) {
            return verification_failure("a disclosed field does not match the record's commitment");
        }
        if (!disclosed_at.emplace(disclosure.index, field->name).second) {
            return verification_failure("a field is disclosed twice");
        }
        report.disclosed_fields.push_back(std::move(*field));
    }
    for (auto it = disclosed_at.begin(); it != disclosed_at.end(); ++it) {
        if (const auto next = std::next(it);
            next != disclosed_at.end() && !(it->second < next->second)) {
            return verification_failure("disclosed fields are not in the record's name order");
        }
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

    return finish_report(provider, *state, checkpoint, bundle, included, options,
                         std::move(report));
}

} // namespace cexchain::protocol
