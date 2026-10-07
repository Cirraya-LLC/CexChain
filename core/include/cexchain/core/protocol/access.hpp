// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/evidence.hpp>

/// Access across organizations (D-046): one organization asks for a record
/// on another's ledger, the other grants it and delivers the record's
/// private data sealed to the asker, and the asker acknowledges it. Each step
/// is a record on the acting organization's own ledger; the other side
/// checks it with the offline evidence verifier, pinned to the peer's ledger
/// id. See `access-request`, `access-grant`, `access-receipt`, and
/// `delivery` in spec/cexchain.cddl.
namespace cexchain::protocol {

inline constexpr std::string_view access_request_type = "cexchain.access-request/1";
inline constexpr std::string_view access_grant_type = "cexchain.access-grant/1";
inline constexpr std::string_view access_receipt_type = "cexchain.access-receipt/1";

/// The HPKE `info` for deliveries; the `aad` is the grant id.
inline constexpr std::string_view delivery_info = "CexChain delivery v1";
inline constexpr std::size_t recipient_key_size = 32; // X25519

/// Metadata of an access request, on the requester's ledger.
struct AccessRequest {
    /// The ledger asked.
    Id ledger;
    /// The record wanted there.
    Id record;
    std::string purpose;
    /// Access is wanted until then (ms since the epoch).
    Timestamp until = 0;
    /// Deliveries are sealed to this X25519 public key.
    Bytes recipient;
    /// Fields and attachments wanted, by name; nullopt asks for all.
    std::optional<std::vector<std::string>> fields;
    std::optional<std::vector<std::string>> attachments;

    friend bool operator==(const AccessRequest&, const AccessRequest&) = default;
};

/// Metadata of an access grant, on the granter's ledger.
struct AccessGrant {
    /// The requester's ledger, and the request record there.
    Id ledger;
    Id request;
    /// The record granted, on the granter's ledger.
    Id record;
    std::vector<std::string> fields;
    std::vector<std::string> attachments;
    Timestamp until = 0;
    Bytes recipient;

    friend bool operator==(const AccessGrant&, const AccessGrant&) = default;
};

/// Metadata of an access receipt, on the requester's ledger.
struct AccessReceipt {
    /// The granter's ledger, and the grant record there.
    Id ledger;
    Id grant;
    /// SHA-256 of the delivery received.
    Bytes delivery;

    friend bool operator==(const AccessReceipt&, const AccessReceipt&) = default;
};

[[nodiscard]] Result<cbor::Value> encode_access_request(const AccessRequest& request);
[[nodiscard]] Result<AccessRequest> decode_access_request(const cbor::Value& metadata);
[[nodiscard]] Result<cbor::Value> encode_access_grant(const AccessGrant& grant);
[[nodiscard]] Result<AccessGrant> decode_access_grant(const cbor::Value& metadata);
[[nodiscard]] Result<cbor::Value> encode_access_receipt(const AccessReceipt& receipt);
[[nodiscard]] Result<AccessReceipt> decode_access_receipt(const cbor::Value& metadata);

/// What a granter sends: its grant's evidence, and the granted record's
/// evidence sealed to the request's recipient key.
struct Delivery {
    Bytes grant_bundle;
    Bytes encapsulated_key;
    Bytes ciphertext;

    friend bool operator==(const Delivery&, const Delivery&) = default;
};

[[nodiscard]] Result<Bytes> encode_delivery(const Delivery& delivery);
[[nodiscard]] Result<Delivery> decode_delivery(ByteView encoded);

/// The sealed part of a delivery.
struct DeliveryContents {
    /// The record's evidence bundle, with the granted field disclosures and
    /// attachment openings.
    Bytes record_bundle;
    /// Attachment contents, by name.
    std::map<std::string, Bytes> attachments;

    friend bool operator==(const DeliveryContents&, const DeliveryContents&) = default;
};

[[nodiscard]] Result<Bytes> encode_delivery_contents(const DeliveryContents& contents);
[[nodiscard]] Result<DeliveryContents> decode_delivery_contents(ByteView encoded);

template <class T>
struct Checked {
    EvidenceReport report;
    T value;
};

/// Checks a request, for the granter: its evidence verifies for the
/// requester's ledger; it is a live access request; it names this ledger
/// and has not expired at `now`. (Whether the record exists, and whether to
/// grant, is the granter's decision.)
[[nodiscard]] Result<Checked<AccessRequest>>
check_access_request(const crypto::Provider& provider, ByteView request_bundle,
                     const Id& requester_ledger, const Id& this_ledger, Timestamp now);

/// Checks a grant, for the requester, against its own request
/// `request_id` (decoded from its own ledger): the grant's evidence verifies
/// for the granter's ledger, which is the ledger the request asked; it is a
/// live, complete grant that names this ledger and that request; it grants
/// the record asked, sealed to the request's key, within the fields and
/// attachments asked and no longer than asked; and it has not expired.
[[nodiscard]] Result<Checked<AccessGrant>>
check_access_grant(const crypto::Provider& provider, ByteView grant_bundle,
                   const Id& granter_ledger, const Id& this_ledger, const Id& request_id,
                   const AccessRequest& request, Timestamp now);

/// Checks what a delivery opened to, against the checked grant: the
/// record's evidence verifies for the granter's ledger at the grant's
/// checkpoint, completely, and the record is not revoked; it is the granted
/// record; it discloses exactly the granted fields; and it holds exactly the
/// granted attachments, each opened and matching its commitment.
[[nodiscard]] Result<EvidenceReport> check_delivered_record(const crypto::Provider& provider,
                                                            const DeliveryContents& contents,
                                                            const Id& granter_ledger,
                                                            const Checked<AccessGrant>& grant);

/// Checks a receipt, for the granter: its evidence verifies for the
/// recipient's ledger, which is the ledger `grant` (this ledger's grant
/// `grant_id`) was made to; and it acknowledges that grant, on this ledger,
/// with `delivery_hash`.
[[nodiscard]] Result<Checked<AccessReceipt>>
check_access_receipt(const crypto::Provider& provider, ByteView receipt_bundle,
                     const Id& recipient_ledger, const Id& this_ledger, const Id& grant_id,
                     const AccessGrant& grant, ByteView delivery_hash);

} // namespace cexchain::protocol
