// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstdint>
#include <optional>
#include <span>

#include <catch2/catch_test_macros.hpp>

#include <kanhe/core/protocol/evidence.hpp>

#include "support/ledger_world.hpp"
#include "support/timestamp_authority.hpp"

namespace {

using namespace kanhe::test;
using kanhe::Bytes;
using kanhe::Errc;

/// A token over `checkpoint`'s payload, dated `at`.
Bytes stamp(const TimestampAuthority& authority, const protocol::SignedCheckpoint& checkpoint,
            protocol::Timestamp at, crypto::HashAlg hash = crypto::HashAlg::sha256) {
    const auto digest = provider().digest(hash, *checkpoint.envelope.payload);
    REQUIRE(digest);
    return authority.token(hash, digest->bytes(), at);
}

protocol::VerifyOptions trusting(const TimestampAuthority& authority) {
    protocol::VerifyOptions options;
    options.trusted_timestamp_roots.push_back(authority.root_der());
    return options;
}

kanhe::Result<protocol::EvidenceReport> verify(const protocol::EvidenceBundle& bundle,
                                               const protocol::VerifyOptions& options) {
    auto encoded = protocol::encode_bundle(bundle);
    REQUIRE(encoded);
    return protocol::verify_bundle(provider(), *encoded, options);
}

void grow(World& w, int records) {
    for (int i = 0; i < records; ++i) {
        w.ok(w.org(), w.statement(w.org_id(), std::nullopt, w.record_body(note_type)));
    }
}

} // namespace

TEST_CASE("a ledger keeps time-stamp tokens and exports them as anchors", "[timestamp]") {
    World w;
    const TimestampAuthority authority;
    const protocol::Id record =
        w.ok(w.org(), w.statement(w.org_id(), std::nullopt, w.record_body(document_type)));
    auto first = w.ledger().checkpoint(w.log_key());
    REQUIRE(first);
    const protocol::Timestamp first_time = w.clock().now();
    const Bytes token = stamp(authority, *first, first_time);
    REQUIRE(w.ledger().add_timestamp(token, first->checkpoint.tree_size));
    REQUIRE(w.ledger().add_timestamp(token, first->checkpoint.tree_size)); // again: no change
    CHECK(w.ledger().timestamp_count() == 1);

    // Later entries and a later checkpoint: the anchor comes with its
    // consistency proof.
    grow(w, 3);
    w.clock().advance(60'000);
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    auto bundle = w.ledger().export_evidence(w.log_key(), record);
    REQUIRE(bundle);
    REQUIRE(bundle->anchors.size() == 1);
    CHECK(bundle->anchors[0].checkpoint == first->encoded);
    CHECK(bundle->anchors[0].timestamps == std::vector<Bytes>{token});
    CHECK_FALSE(bundle->anchors[0].consistency.empty());
    auto encoded = protocol::encode_bundle(*bundle);
    REQUIRE(encoded);
    CHECK(*protocol::decode_bundle(*encoded) == *bundle);

    // A verifier that trusts the authority knows when the record existed by.
    auto report = verify(*bundle, trusting(authority));
    INFO((report ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    REQUIRE(report->timestamps.size() == 1);
    CHECK(report->timestamps[0].trusted);
    CHECK(report->timestamps[0].size == first->checkpoint.tree_size);
    CHECK(report->timestamps[0].time == first_time);
    CHECK(report->timestamps[0].authority == "CN=Test Time-Stamp Authority");
    CHECK(report->trusted_timestamp_authorities == 1);
    REQUIRE_FALSE(report->events.empty());
    CHECK(report->events.front().existed_by == first_time + 1000);

    // One that does not, counts the token but relies on nothing.
    auto untrusting = verify(*bundle, {});
    REQUIRE(untrusting);
    REQUIRE(untrusting->timestamps.size() == 1);
    CHECK_FALSE(untrusting->timestamps[0].trusted);
    CHECK(untrusting->trusted_timestamp_authorities == 0);
    CHECK_FALSE(untrusting->events.front().existed_by);

    // A stamp of the latest checkpoint too: two anchors, the earliest bound
    // kept for the record's registration.
    auto latest = w.ledger().latest_checkpoint();
    REQUIRE(latest);
    REQUIRE(w.ledger().add_timestamp(stamp(authority, *latest, w.clock().now()),
                                     latest->checkpoint.tree_size));
    bundle = w.ledger().export_evidence(w.log_key(), record);
    REQUIRE(bundle);
    REQUIRE(bundle->anchors.size() == 2);
    CHECK(bundle->anchors[1].consistency.empty());
    report = verify(*bundle, trusting(authority));
    REQUIRE(report);
    CHECK(report->timestamps.size() == 2);
    CHECK(report->trusted_timestamp_authorities == 1);
    CHECK(report->events.front().existed_by == first_time + 1000);

    // Kept across a reopen, and audited.
    auto reopened = ledger::Ledger::open(w.fs(), w.clock(), provider());
    REQUIRE(reopened);
    CHECK(reopened->timestamp_count() == 2);
    auto audit = reopened->audit();
    REQUIRE(audit);
    CHECK(audit->timestamps == 2);
}

TEST_CASE("a ledger refuses tokens that do not fit", "[timestamp]") {
    World w;
    const TimestampAuthority authority;
    grow(w, 2);
    auto checkpoint = w.ledger().checkpoint(w.log_key());
    REQUIRE(checkpoint);
    const std::uint64_t size = checkpoint->checkpoint.tree_size;

    // For another checkpoint, or another size.
    const auto other = provider().digest(crypto::HashAlg::sha256, kanhe::as_bytes("other"));
    CHECK(w.ledger()
              .add_timestamp(
                  authority.token(crypto::HashAlg::sha256, other->bytes(), w.clock().now()), size)
              .error()
              .code == Errc::not_found);
    CHECK(w.ledger()
              .add_timestamp(stamp(authority, *checkpoint, w.clock().now()), size + 1)
              .error()
              .code == Errc::not_found);
    // Dated by the authority well before the ledger dated the checkpoint:
    // the ledger's clock runs ahead, and evidence would fail.
    CHECK(w.ledger()
              .add_timestamp(stamp(authority, *checkpoint, w.clock().now() - 600'000), size)
              .error()
              .code == Errc::rejected);
    // Not a token.
    CHECK_FALSE(w.ledger().add_timestamp(Bytes{1, 2, 3}, size));
    CHECK(w.ledger().timestamp_count() == 0);
}

TEST_CASE("a verifier refuses anchors that do not hold", "[timestamp]") {
    World w;
    const TimestampAuthority authority;
    const protocol::Id record =
        w.ok(w.org(), w.statement(w.org_id(), std::nullopt, w.record_body(document_type)));
    auto first = w.ledger().checkpoint(w.log_key());
    REQUIRE(first);
    REQUIRE(w.ledger().add_timestamp(stamp(authority, *first, w.clock().now()),
                                     first->checkpoint.tree_size));
    grow(w, 2);
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    auto good = w.ledger().export_evidence(w.log_key(), record);
    REQUIRE(good);
    REQUIRE(good->anchors.size() == 1);
    const auto options = trusting(authority);
    REQUIRE(verify(*good, options));

    auto failure = [&](const protocol::EvidenceBundle& bundle) {
        auto report = verify(bundle, options);
        REQUIRE_FALSE(report);
        return report.error().code;
    };
    // A token over something else.
    auto changed = *good;
    const auto other = provider().digest(crypto::HashAlg::sha256, kanhe::as_bytes("other"));
    changed.anchors[0].timestamps = {
        authority.token(crypto::HashAlg::sha256, other->bytes(), w.clock().now())};
    CHECK(failure(changed) == Errc::verification_failed);
    // A consistency proof that does not lead to the bundle's checkpoint.
    changed = *good;
    changed.anchors[0].consistency.pop_back();
    CHECK(failure(changed) == Errc::verification_failed);
    // The ledger's clock against the authority's: a token dated five minutes
    // before the entries it covers.
    changed = *good;
    changed.anchors[0].timestamps = {
        stamp(authority, *first, first->checkpoint.timestamp - 300'000)};
    CHECK(failure(changed) == Errc::verification_failed);
    // Untrusted, the same token proves nothing and contradicts nothing.
    CHECK(verify(changed, {}));
    // An anchor later than the bundle's checkpoint: the older bundle, with
    // the newer checkpoint stamped.
    auto older = *good;
    grow(w, 1);
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    auto later = w.ledger().latest_checkpoint();
    REQUIRE(later);
    older.anchors[0] = protocol::Anchor{
        .checkpoint = later->encoded,
        .timestamps = {stamp(authority, *later, w.clock().now())},
        .consistency = {},
        .network_cosignatures = {},
    };
    CHECK(failure(older) == Errc::verification_failed);
}
