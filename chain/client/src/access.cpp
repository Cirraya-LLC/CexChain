// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>

#include <kanhe/client/access.hpp>
#include <kanhe/client/peers.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/evidence.hpp>

namespace kanhe::client {

std::filesystem::path request_key_path(const std::filesystem::path& dir,
                                       const protocol::Id& request) {
    return dir / "vault" / "access" / (hex_id(request) + ".cbor");
}

Bytes seal_request_key(ByteView vault_public, const protocol::Id& request,
                       const crypto::openssl::HpkeKey& key) {
    const auto pkcs8 = unwrap(key.to_pkcs8(), "the request's key");
    const auto sealed = unwrap(crypto::openssl::hpke_seal(vault_public, as_bytes(access_key_info),
                                                          request.bytes(), pkcs8.view()),
                               "sealing the request's key");
    return unwrap(cbor::encode(cbor::Value::map(
                      {{cbor::Value::integer(1), cbor::Value::bytes(sealed.encapsulated_key)},
                       {cbor::Value::integer(2), cbor::Value::bytes(sealed.ciphertext)}})),
                  "encoding the request's key");
}

crypto::openssl::HpkeKey open_request_key(ByteView file, const protocol::Id& request,
                                          const crypto::openssl::HpkeKey& vault_key) {
    const auto value = unwrap(cbor::decode(file), "reading the request's key");
    const cbor::Value* enc = value.find(1);
    const cbor::Value* ciphertext = value.find(2);
    if (enc == nullptr || ciphertext == nullptr || enc->as_bytes() == nullptr ||
        ciphertext->as_bytes() == nullptr) {
        throw ActionError{"the request's key file is corrupted"};
    }
    const auto pkcs8 = unwrap(vault_key.open({*enc->as_bytes(), *ciphertext->as_bytes()},
                                             as_bytes(access_key_info), request.bytes()),
                              "opening the request's key");
    return unwrap(crypto::openssl::HpkeKey::from_pkcs8(pkcs8.view()), "the request's key");
}

node::Peer peer_for_bundle(const std::filesystem::path& dir, ByteView bundle) {
    const auto ledger = protocol::bundle_ledger_id(bundle);
    if (!ledger) {
        throw ActionError{"the evidence is malformed: " + std::string(ledger.error().detail)};
    }
    for (node::Peer& p : peers_of(dir)) {
        if (p.ledger_id == *ledger) {
            return p;
        }
    }
    throw ActionError{"the evidence comes from ledger " + hex_id(*ledger) +
                      ", which is not a peer (kanhe peer add)"};
}

std::string acted_by(const protocol::EvidenceReport& report) {
    if (report.events.empty()) {
        return report.organization;
    }
    const auto& e = report.events.front();
    std::string out =
        e.actor.kind ? e.actor.name + " of " + report.organization : report.organization;
    if (e.presence) {
        out += e.presence->method == protocol::PresenceMethod::hardware_key
                   ? " (present: hardware key)"
                   : " (present: passkey)";
    }
    return out;
}

namespace {

ReceivedRequest check_received(const std::filesystem::path& dir, const crypto::Provider& provider,
                               const protocol::Id& own, std::filesystem::path file,
                               protocol::Timestamp now) {
    ReceivedRequest item;
    item.file = std::move(file);
    try {
        item.bundle = read_file(item.file);
        item.peer = peer_for_bundle(dir, item.bundle);
        auto checked =
            protocol::check_access_request(provider, item.bundle, item.peer->ledger_id, own, now);
        if (!checked) {
            item.problem = checked.error().detail;
        } else {
            item.granted = std::filesystem::exists(
                node::access_path(dir, node::AccessBox::outbox, checked->report.record));
            item.checked = std::move(*checked);
        }
    } catch (const ActionError& e) {
        item.problem = e.message;
    }
    return item;
}

} // namespace

std::vector<ReceivedRequest> received_requests(const std::filesystem::path& dir,
                                               const crypto::Provider& provider,
                                               const protocol::Id& own, protocol::Timestamp now) {
    const std::filesystem::path inbox = dir / "access" / "inbox";
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (auto it = std::filesystem::directory_iterator(inbox, ec);
         !ec && it != std::filesystem::directory_iterator(); it.increment(ec)) {
        files.push_back(it->path());
    }
    std::ranges::sort(files);
    std::vector<ReceivedRequest> out;
    for (auto& file : files) {
        out.push_back(check_received(dir, provider, own, std::move(file), now));
    }
    return out;
}

ReceivedRequest received_request(const std::filesystem::path& dir, const crypto::Provider& provider,
                                 const protocol::Id& own, const protocol::Id& request,
                                 protocol::Timestamp now) {
    const std::filesystem::path file = node::access_path(dir, node::AccessBox::inbox, request);
    if (!std::filesystem::exists(file)) {
        throw ActionError{"no request " + short_id(request) + " in this ledger's inbox"};
    }
    return check_received(dir, provider, own, file, now);
}

Bytes seal_delivery(const crypto::Provider& provider, const protocol::Id& own,
                    ByteView grant_bundle, const protocol::AccessGrant& grant,
                    const protocol::DeliveryContents& contents) {
    protocol::VerifyOptions options;
    options.expected_ledger = own;
    const protocol::Checked<protocol::AccessGrant> checked{
        unwrap(protocol::verify_bundle(provider, grant_bundle, options), "the grant"), grant};
    if (const auto check = protocol::check_delivered_record(provider, contents, own, checked);
        !check) {
        throw ActionError{"the delivery does not check out: " + std::string(check.error().detail)};
    }
    const auto sealed = unwrap(
        crypto::openssl::hpke_seal(
            grant.recipient, as_bytes(protocol::delivery_info), checked.report.record.bytes(),
            unwrap(protocol::encode_delivery_contents(contents), "contents")),
        "sealing the delivery");
    return unwrap(protocol::encode_delivery({Bytes(grant_bundle.begin(), grant_bundle.end()),
                                             sealed.encapsulated_key, sealed.ciphertext}),
                  "encoding the delivery");
}

OpenedDelivery open_delivery(const ledger::Ledger& ledger, const std::filesystem::path& dir,
                             const crypto::Provider& provider, ByteView delivery_bytes,
                             const VaultKeySource& vault_key, protocol::Timestamp now) {
    const auto delivery = unwrap(protocol::decode_delivery(delivery_bytes), "reading the delivery");
    OpenedDelivery out{peer_for_bundle(dir, delivery.grant_bundle), {}, {}, {}, {}};

    // Which of our requests it answers, from the grant; then the grant is
    // checked fully against that request and its key.
    protocol::VerifyOptions pinned;
    pinned.expected_ledger = out.peer.ledger_id;
    const auto report =
        unwrap(protocol::verify_bundle(provider, delivery.grant_bundle, pinned), "the grant");
    if (!report.metadata) {
        throw ActionError{"the delivery's grant has no access metadata"};
    }
    const auto claimed = unwrap(protocol::decode_access_grant(*report.metadata), "the grant");
    out.request = claimed.request;
    bool ours = false;
    bool live = false;
    ledger.read_state([&](const protocol::LedgerState& state) {
        const protocol::RecordState* r = state.record(claimed.request);
        ours = r != nullptr && r->record_type == protocol::access_request_type;
        live = ours && !r->revoked && r->state == "requested";
    });
    if (!ours) {
        throw ActionError{"the delivery answers request " + short_id(claimed.request) +
                          ", which this ledger did not make"};
    }
    if (!live) {
        throw ActionError{"request " + short_id(claimed.request) + " was withdrawn"};
    }
    const auto request = unwrap(
        protocol::decode_access_request(unwrap(
            node::record_metadata(provider, ledger, claimed.request), "reading our request")),
        "our request");
    const std::filesystem::path key_file = request_key_path(dir, claimed.request);
    if (!std::filesystem::exists(key_file)) {
        throw ActionError{"no key for request " + short_id(claimed.request) +
                          " in this ledger's vault (was it made here?)"};
    }
    const auto key = open_request_key(read_file(key_file), claimed.request, vault_key());
    if (!std::ranges::equal(key.public_key(), request.recipient)) {
        throw ActionError{"the key in the vault for request " + short_id(claimed.request) +
                          " is not the request's"};
    }
    auto grant = protocol::check_access_grant(provider, delivery.grant_bundle, out.peer.ledger_id,
                                              ledger.id(), claimed.request, request, now);
    if (!grant) {
        throw NotAccepted{std::string(grant.error().detail),
                          grant.error().code == Errc::verification_failed};
    }
    out.grant = std::move(*grant);
    const auto opened =
        key.open({delivery.encapsulated_key, delivery.ciphertext},
                 as_bytes(protocol::delivery_info), out.grant.report.record.bytes());
    if (!opened) {
        throw NotAccepted{"the delivery is not sealed to this request's key"};
    }
    out.contents =
        unwrap(protocol::decode_delivery_contents(opened->view()), "the delivery's contents");
    auto record =
        protocol::check_delivered_record(provider, out.contents, out.peer.ledger_id, out.grant);
    if (!record) {
        throw NotAccepted{std::string(record.error().detail)};
    }
    out.record = std::move(*record);
    return out;
}

protocol::AccessReceipt receipt_for(const crypto::Provider& provider, const OpenedDelivery& opened,
                                    ByteView delivery) {
    const auto digest = unwrap(provider.digest(crypto::HashAlg::sha256, delivery), "hashing");
    return {opened.peer.ledger_id, opened.grant.report.record,
            Bytes(digest.bytes().begin(), digest.bytes().end())};
}

bool is_claim_answer(ByteView answer) {
    return protocol::decode_bundle(answer).has_value();
}

AnsweredClaim open_claim_answer(const ledger::Ledger& ledger, const std::filesystem::path& dir,
                                const crypto::Provider& provider, ByteView bundle,
                                protocol::Timestamp now) {
    AnsweredClaim out{peer_for_bundle(dir, bundle), {}, {}};
    // Which of our requests it answers, from the claim's "for"; then it is
    // checked fully against that request.
    protocol::VerifyOptions pinned;
    pinned.expected_ledger = out.peer.ledger_id;
    auto verified = protocol::verify_bundle(provider, bundle, pinned);
    if (!verified) {
        throw NotAccepted{"the claim: " + std::string(verified.error().detail),
                          verified.error().code == Errc::verification_failed};
    }
    const protocol::EvidenceReport& report = *verified;
    if (report.record_type != protocol::claim_type || !report.metadata) {
        throw ActionError{"the answer is not a claim"};
    }
    const auto claimed = unwrap(protocol::decode_claim(*report.metadata), "the claim");
    if (!claimed.answers || claimed.answers->first != ledger.id()) {
        throw ActionError{"the claim answers no request of this ledger's"};
    }
    out.request = claimed.answers->second;
    bool ours = false;
    bool live = false;
    ledger.read_state([&](const protocol::LedgerState& state) {
        const protocol::RecordState* r = state.record(out.request);
        ours = r != nullptr && r->record_type == protocol::access_request_type;
        live = ours && !r->revoked && r->state == "requested";
    });
    if (!ours) {
        throw ActionError{"the claim answers request " + short_id(out.request) +
                          ", which this ledger did not make"};
    }
    if (!live) {
        throw ActionError{"request " + short_id(out.request) + " was withdrawn"};
    }
    const auto request =
        unwrap(protocol::decode_access_request(unwrap(
                   node::record_metadata(provider, ledger, out.request), "reading our request")),
               "our request");
    auto checked = protocol::check_claim_answer(provider, bundle, out.peer.ledger_id, ledger.id(),
                                                out.request, request, now);
    if (!checked) {
        throw NotAccepted{std::string(checked.error().detail),
                          checked.error().code == Errc::verification_failed};
    }
    out.claim = std::move(*checked);
    return out;
}

protocol::AccessReceipt receipt_for(const crypto::Provider& provider, const AnsweredClaim& answered,
                                    ByteView bundle) {
    const auto digest = unwrap(provider.digest(crypto::HashAlg::sha256, bundle), "hashing");
    return {answered.peer.ledger_id, answered.claim.report.record,
            Bytes(digest.bytes().begin(), digest.bytes().end())};
}

bool plain_file_name(std::string_view name) {
    return !name.empty() && name.find('/') == std::string_view::npos &&
           name.find('\\') == std::string_view::npos && name != ".." && name != ".";
}

} // namespace kanhe::client
