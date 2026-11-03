// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <utility>

#include <cexchain/core/protocol/access.hpp>

#include "reader.hpp"

namespace cexchain::protocol {

namespace {

constexpr std::uint64_t delivery_version = 1;
constexpr std::size_t max_names = 256;

cbor::MapEntry text_entry(std::string_view key, cbor::Value value) {
    return {cbor::Value::text(std::string(key)), std::move(value)};
}

cbor::Value names_value(const std::vector<std::string>& names) {
    cbor::Array out;
    for (const std::string& n : names) {
        out.push_back(cbor::Value::text(n));
    }
    return cbor::Value::array(std::move(out));
}

Status check_names(const std::vector<std::string>& names) {
    if (names.size() > max_names) {
        return fail(Errc::limit_exceeded, "too many names in access metadata");
    }
    for (std::size_t i = 0; i < names.size(); ++i) {
        if (names[i].empty()) {
            return fail(Errc::malformed, "names in access metadata must not be empty");
        }
        for (std::size_t j = i + 1; j < names.size(); ++j) {
            if (names[i] == names[j]) {
                return fail(Errc::malformed, "names in access metadata must be unique");
            }
        }
    }
    return {};
}

/// Reads access metadata: a map with text keys, every one known.
class Fields {
public:
    static Result<Fields> open(const cbor::Value& metadata,
                               std::initializer_list<std::string_view> known) {
        const cbor::Map* map = metadata.as_map();
        if (map == nullptr) {
            return fail(Errc::malformed, "access metadata must be a map");
        }
        for (const cbor::MapEntry& e : *map) {
            const std::string* key = e.key.as_text();
            if (key == nullptr || std::ranges::find(known, std::string_view(*key)) == known.end()) {
                return fail(Errc::malformed, "access metadata has an unknown key");
            }
        }
        return Fields(*map);
    }

    [[nodiscard]] const cbor::Value* get(std::string_view key) const {
        for (const cbor::MapEntry& e : *map_) {
            if (*e.key.as_text() == key) {
                return &e.value;
            }
        }
        return nullptr;
    }

    Result<Id> id(std::string_view key) const {
        const cbor::Value* v = get(key);
        if (v == nullptr || v->as_bytes() == nullptr) {
            return fail(Errc::malformed, "access metadata lacks an id");
        }
        return to_id(*v->as_bytes());
    }

    Result<Bytes> bytes(std::string_view key, std::size_t size) const {
        const cbor::Value* v = get(key);
        if (v == nullptr || v->as_bytes() == nullptr || v->as_bytes()->size() != size) {
            return fail(Errc::malformed, "access metadata lacks a key or hash of the right size");
        }
        return *v->as_bytes();
    }

    Result<Timestamp> time(std::string_view key) const {
        const cbor::Value* v = get(key);
        const auto value = v == nullptr ? std::nullopt : v->as_uint64();
        if (!value || *value == 0) {
            return fail(Errc::malformed, "access metadata lacks a time");
        }
        return *value;
    }

    Result<std::string> text(std::string_view key) const {
        const cbor::Value* v = get(key);
        if (v == nullptr || v->as_text() == nullptr || v->as_text()->empty()) {
            return fail(Errc::malformed, "access metadata lacks a text");
        }
        return *v->as_text();
    }

    Result<std::optional<std::vector<std::string>>> names(std::string_view key) const {
        const cbor::Value* v = get(key);
        if (v == nullptr) {
            return std::optional<std::vector<std::string>>{};
        }
        const cbor::Array* array = v->as_array();
        if (array == nullptr) {
            return fail(Errc::malformed, "access metadata names must be a list");
        }
        std::vector<std::string> out;
        for (const cbor::Value& item : *array) {
            if (item.as_text() == nullptr) {
                return fail(Errc::malformed, "access metadata names must be text");
            }
            out.push_back(*item.as_text());
        }
        if (auto s = check_names(out); !s) {
            return std::unexpected(s.error());
        }
        return std::optional(std::move(out));
    }

private:
    explicit Fields(const cbor::Map& map) : map_(&map) {}
    const cbor::Map* map_;
};

/// The verified record must be a live record of `type`.
Status require_live(const EvidenceReport& report, std::string_view type,
                    std::string_view initial_state) {
    if (report.record_type != type) {
        return fail(Errc::verification_failed, "the evidence is not of the expected record type");
    }
    if (report.revoked || report.state != initial_state) {
        return fail(Errc::rejected, "the record has been revoked or withdrawn");
    }
    if (!report.complete) {
        return fail(Errc::verification_failed,
                    "the evidence does not prove the record's complete history");
    }
    if (!report.metadata) {
        return fail(Errc::verification_failed, "the record has no access metadata");
    }
    return {};
}

} // namespace

Result<cbor::Value> encode_access_request(const AccessRequest& r) {
    if (r.purpose.empty() || r.until == 0 || r.recipient.size() != recipient_key_size) {
        return fail(Errc::invalid_argument, "an access request needs a purpose, an end, and a key");
    }
    cbor::Map map{text_entry("ledger", cbor::Value::bytes(r.ledger.bytes())),
                  text_entry("record", cbor::Value::bytes(r.record.bytes())),
                  text_entry("purpose", cbor::Value::text(r.purpose)),
                  text_entry("until", cbor::Value::unsigned_integer(r.until)),
                  text_entry("recipient", cbor::Value::bytes(r.recipient))};
    if (r.fields) {
        if (auto s = check_names(*r.fields); !s) {
            return std::unexpected(Error{Errc::invalid_argument, s.error().detail});
        }
        map.push_back(text_entry("fields", names_value(*r.fields)));
    }
    if (r.attachments) {
        if (auto s = check_names(*r.attachments); !s) {
            return std::unexpected(Error{Errc::invalid_argument, s.error().detail});
        }
        map.push_back(text_entry("attachments", names_value(*r.attachments)));
    }
    return cbor::Value::map(std::move(map));
}

Result<AccessRequest> decode_access_request(const cbor::Value& metadata) {
    CEXCHAIN_TRY(Fields f, Fields::open(metadata, {"ledger", "record", "purpose", "until",
                                                   "recipient", "fields", "attachments"}));
    AccessRequest r;
    CEXCHAIN_TRY(r.ledger, f.id("ledger"));
    CEXCHAIN_TRY(r.record, f.id("record"));
    CEXCHAIN_TRY(r.purpose, f.text("purpose"));
    CEXCHAIN_TRY(r.until, f.time("until"));
    CEXCHAIN_TRY(r.recipient, f.bytes("recipient", recipient_key_size));
    CEXCHAIN_TRY(r.fields, f.names("fields"));
    CEXCHAIN_TRY(r.attachments, f.names("attachments"));
    return r;
}

Result<cbor::Value> encode_access_grant(const AccessGrant& g) {
    if (g.until == 0 || g.recipient.size() != recipient_key_size) {
        return fail(Errc::invalid_argument, "an access grant needs an end and a key");
    }
    if (auto s = check_names(g.fields); !s) {
        return std::unexpected(Error{Errc::invalid_argument, s.error().detail});
    }
    if (auto s = check_names(g.attachments); !s) {
        return std::unexpected(Error{Errc::invalid_argument, s.error().detail});
    }
    return cbor::Value::map({text_entry("ledger", cbor::Value::bytes(g.ledger.bytes())),
                             text_entry("request", cbor::Value::bytes(g.request.bytes())),
                             text_entry("record", cbor::Value::bytes(g.record.bytes())),
                             text_entry("fields", names_value(g.fields)),
                             text_entry("attachments", names_value(g.attachments)),
                             text_entry("until", cbor::Value::unsigned_integer(g.until)),
                             text_entry("recipient", cbor::Value::bytes(g.recipient))});
}

Result<AccessGrant> decode_access_grant(const cbor::Value& metadata) {
    CEXCHAIN_TRY(Fields f, Fields::open(metadata, {"ledger", "request", "record", "fields",
                                                   "attachments", "until", "recipient"}));
    AccessGrant g;
    CEXCHAIN_TRY(g.ledger, f.id("ledger"));
    CEXCHAIN_TRY(g.request, f.id("request"));
    CEXCHAIN_TRY(g.record, f.id("record"));
    CEXCHAIN_TRY(auto fields, f.names("fields"));
    CEXCHAIN_TRY(auto attachments, f.names("attachments"));
    if (!fields || !attachments) {
        return fail(Errc::malformed, "an access grant lists its fields and attachments");
    }
    g.fields = std::move(*fields);
    g.attachments = std::move(*attachments);
    CEXCHAIN_TRY(g.until, f.time("until"));
    CEXCHAIN_TRY(g.recipient, f.bytes("recipient", recipient_key_size));
    return g;
}

Result<cbor::Value> encode_access_receipt(const AccessReceipt& r) {
    if (r.delivery.size() != 32) {
        return fail(Errc::invalid_argument, "an access receipt holds a SHA-256 of the delivery");
    }
    return cbor::Value::map({text_entry("ledger", cbor::Value::bytes(r.ledger.bytes())),
                             text_entry("grant", cbor::Value::bytes(r.grant.bytes())),
                             text_entry("delivery", cbor::Value::bytes(r.delivery))});
}

Result<AccessReceipt> decode_access_receipt(const cbor::Value& metadata) {
    CEXCHAIN_TRY(Fields f, Fields::open(metadata, {"ledger", "grant", "delivery"}));
    AccessReceipt r;
    CEXCHAIN_TRY(r.ledger, f.id("ledger"));
    CEXCHAIN_TRY(r.grant, f.id("grant"));
    CEXCHAIN_TRY(r.delivery, f.bytes("delivery", 32));
    return r;
}

Result<Bytes> encode_delivery(const Delivery& d) {
    if (d.grant_bundle.empty() || d.encapsulated_key.empty() || d.ciphertext.empty()) {
        return fail(Errc::invalid_argument, "a delivery needs a grant and sealed contents");
    }
    return cbor::encode(cbor::Value::map(
        {{cbor::Value::unsigned_integer(1), cbor::Value::unsigned_integer(delivery_version)},
         {cbor::Value::unsigned_integer(2), cbor::Value::bytes(d.grant_bundle)},
         {cbor::Value::unsigned_integer(3),
          cbor::Value::map(
              {{cbor::Value::unsigned_integer(1), cbor::Value::bytes(d.encapsulated_key)},
               {cbor::Value::unsigned_integer(2), cbor::Value::bytes(d.ciphertext)}})}}));
}

Result<Delivery> decode_delivery(ByteView encoded) {
    cbor::DecodeOptions options;
    options.max_items = 64;
    CEXCHAIN_TRY(cbor::Value value, cbor::decode(encoded, options));
    const cbor::Map* map = value.as_map();
    if (map == nullptr || map->size() != 3) {
        return fail(Errc::malformed, "a delivery is a map of three items");
    }
    const auto& version = (*map)[0];
    const auto& grant = (*map)[1];
    const auto& sealed = (*map)[2];
    if (version.key.as_uint64() != 1U || grant.key.as_uint64() != 2U ||
        sealed.key.as_uint64() != 3U) {
        return fail(Errc::malformed, "a delivery has keys 1, 2, and 3");
    }
    if (version.value.as_uint64() != delivery_version) {
        return fail(Errc::unsupported, "this delivery's version is not supported");
    }
    const cbor::Map* parts = sealed.value.as_map();
    if (grant.value.as_bytes() == nullptr || parts == nullptr || parts->size() != 2 ||
        (*parts)[0].key.as_uint64() != 1U || (*parts)[1].key.as_uint64() != 2U ||
        (*parts)[0].value.as_bytes() == nullptr || (*parts)[1].value.as_bytes() == nullptr) {
        return fail(Errc::malformed, "a delivery is malformed");
    }
    return Delivery{*grant.value.as_bytes(), *(*parts)[0].value.as_bytes(),
                    *(*parts)[1].value.as_bytes()};
}

Result<Bytes> encode_delivery_contents(const DeliveryContents& c) {
    cbor::Map map{{cbor::Value::unsigned_integer(1), cbor::Value::bytes(c.record_bundle)}};
    if (!c.attachments.empty()) {
        cbor::Map files;
        for (const auto& [name, content] : c.attachments) {
            files.push_back({cbor::Value::text(name), cbor::Value::bytes(content)});
        }
        map.push_back({cbor::Value::unsigned_integer(2), cbor::Value::map(std::move(files))});
    }
    return cbor::encode(cbor::Value::map(std::move(map)));
}

Result<DeliveryContents> decode_delivery_contents(ByteView encoded) {
    cbor::DecodeOptions options;
    options.max_items = 4096;
    CEXCHAIN_TRY(cbor::Value value, cbor::decode(encoded, options));
    const cbor::Map* map = value.as_map();
    if (map == nullptr || map->empty() || map->size() > 2 || (*map)[0].key.as_uint64() != 1U ||
        (*map)[0].value.as_bytes() == nullptr) {
        return fail(Errc::malformed, "a delivery's contents are malformed");
    }
    DeliveryContents c;
    c.record_bundle = *(*map)[0].value.as_bytes();
    if (map->size() == 2) {
        const cbor::Map* files = (*map)[1].value.as_map();
        if ((*map)[1].key.as_uint64() != 2U || files == nullptr || files->empty()) {
            return fail(Errc::malformed, "a delivery's contents are malformed");
        }
        for (const auto& [name, content] : *files) {
            if (name.as_text() == nullptr || content.as_bytes() == nullptr) {
                return fail(Errc::malformed, "a delivery's attachments are malformed");
            }
            c.attachments.emplace(*name.as_text(), *content.as_bytes());
        }
    }
    return c;
}

Result<Checked<AccessRequest>> check_access_request(const crypto::Provider& provider,
                                                    ByteView request_bundle,
                                                    const Id& requester_ledger,
                                                    const Id& this_ledger, Timestamp now) {
    VerifyOptions options;
    options.expected_ledger = requester_ledger;
    CEXCHAIN_TRY(EvidenceReport report, verify_bundle(provider, request_bundle, options));
    CEXCHAIN_CHECK(require_live(report, access_request_type, "requested"));
    auto request = decode_access_request(*report.metadata);
    if (!request) {
        return fail(Errc::verification_failed, "the access request's metadata is malformed");
    }
    if (request->ledger != this_ledger) {
        return fail(Errc::rejected, "the access request is for another ledger");
    }
    if (request->until <= now) {
        return fail(Errc::rejected, "the access request has expired");
    }
    return Checked<AccessRequest>{std::move(report), std::move(*request)};
}

Result<Checked<AccessGrant>> check_access_grant(const crypto::Provider& provider,
                                                ByteView grant_bundle, const Id& granter_ledger,
                                                const Id& this_ledger, const Id& request_id,
                                                const AccessRequest& request, Timestamp now) {
    if (request.ledger != granter_ledger) {
        return fail(Errc::rejected, "the grant comes from another ledger than the one asked");
    }
    VerifyOptions options;
    options.expected_ledger = granter_ledger;
    CEXCHAIN_TRY(EvidenceReport report, verify_bundle(provider, grant_bundle, options));
    CEXCHAIN_CHECK(require_live(report, access_grant_type, "granted"));
    auto grant = decode_access_grant(*report.metadata);
    if (!grant) {
        return fail(Errc::verification_failed, "the access grant's metadata is malformed");
    }
    if (grant->ledger != this_ledger || grant->request != request_id) {
        return fail(Errc::rejected, "the access grant is for another ledger or request");
    }
    if (grant->record != request.record) {
        return fail(Errc::rejected, "the access grant is for another record than requested");
    }
    if (!std::ranges::equal(grant->recipient, request.recipient)) {
        return fail(Errc::rejected, "the access grant is for another recipient key");
    }
    auto within = [](const std::vector<std::string>& granted,
                     const std::optional<std::vector<std::string>>& asked) {
        return !asked || std::ranges::all_of(granted, [&](const std::string& name) {
            return std::ranges::contains(*asked, name);
        });
    };
    if (!within(grant->fields, request.fields) ||
        !within(grant->attachments, request.attachments)) {
        return fail(Errc::rejected, "the access grant covers more than was requested");
    }
    if (grant->until > request.until) {
        return fail(Errc::rejected, "the access grant lasts longer than was requested");
    }
    if (grant->until <= now) {
        return fail(Errc::rejected, "the access grant has expired");
    }
    return Checked<AccessGrant>{std::move(report), std::move(*grant)};
}

Result<EvidenceReport> check_delivered_record(const crypto::Provider& provider,
                                              const DeliveryContents& contents,
                                              const Id& granter_ledger,
                                              const Checked<AccessGrant>& checked) {
    const AccessGrant& grant = checked.value;
    VerifyOptions options;
    options.expected_ledger = granter_ledger;
    options.attachment_contents = contents.attachments;
    CEXCHAIN_TRY(EvidenceReport report, verify_bundle(provider, contents.record_bundle, options));
    if (report.record != grant.record) {
        return fail(Errc::verification_failed, "the delivery holds another record than granted");
    }
    // As current as the grant, and nothing (such as a revocation) left out.
    if (report.checkpoint != checked.report.checkpoint) {
        return fail(Errc::verification_failed,
                    "the delivered record is not proven at the grant's checkpoint");
    }
    if (!report.complete) {
        return fail(Errc::verification_failed,
                    "the delivered record's evidence does not prove its complete history");
    }
    if (report.revoked) {
        return fail(Errc::rejected, "the delivered record has been revoked");
    }
    // Exactly the granted fields: nothing more, nothing withheld.
    std::vector<std::string> disclosed;
    for (const RecordField& field : report.disclosed_fields) {
        if (!std::ranges::contains(grant.fields, field.name)) {
            return fail(Errc::verification_failed, "the delivery discloses a field not granted");
        }
        if (std::ranges::contains(disclosed, field.name)) {
            return fail(Errc::verification_failed, "the delivery discloses a field twice");
        }
        disclosed.push_back(field.name);
    }
    if (disclosed.size() != grant.fields.size()) {
        return fail(Errc::verification_failed, "the delivery withholds a granted field");
    }
    // Exactly the granted attachments, each one checked against the
    // record's commitment.
    for (const auto& [name, content] : contents.attachments) {
        if (!std::ranges::contains(grant.attachments, name)) {
            return fail(Errc::verification_failed, "the delivery holds an attachment not granted");
        }
    }
    for (const std::string& name : grant.attachments) {
        const auto check = std::ranges::find(report.attachments, name, &AttachmentCheck::name);
        if (check == report.attachments.end()) {
            return fail(Errc::verification_failed,
                        "the grant names an attachment the record does not have");
        }
        if (check->status != AttachmentStatus::verified) {
            return fail(Errc::verification_failed,
                        check->status == AttachmentStatus::mismatch
                            ? "a delivered attachment does not match its commitment"
                            : "a granted attachment is missing or not opened");
        }
    }
    return report;
}

Result<Checked<AccessReceipt>>
check_access_receipt(const crypto::Provider& provider, ByteView receipt_bundle,
                     const Id& recipient_ledger, const Id& this_ledger, const Id& grant_id,
                     const AccessGrant& grant, ByteView delivery_hash) {
    if (grant.ledger != recipient_ledger) {
        return fail(Errc::rejected, "the receipt comes from another ledger than the grant's");
    }
    VerifyOptions options;
    options.expected_ledger = recipient_ledger;
    CEXCHAIN_TRY(EvidenceReport report, verify_bundle(provider, receipt_bundle, options));
    CEXCHAIN_CHECK(require_live(report, access_receipt_type, "received"));
    auto receipt = decode_access_receipt(*report.metadata);
    if (!receipt) {
        return fail(Errc::verification_failed, "the access receipt's metadata is malformed");
    }
    if (receipt->ledger != this_ledger || receipt->grant != grant_id) {
        return fail(Errc::rejected, "the access receipt is for another ledger or grant");
    }
    if (!std::ranges::equal(receipt->delivery, delivery_hash)) {
        return fail(Errc::rejected, "the access receipt acknowledges another delivery");
    }
    return Checked<AccessReceipt>{std::move(report), std::move(*receipt)};
}

} // namespace cexchain::protocol
