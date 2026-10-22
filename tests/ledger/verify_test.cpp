// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Evidence verified on all cores: signatures checked ahead and
// remembered give exactly core's outcome, report or refusal, for every
// evidence vector, ledger-made bundles with rotations and witnesses, and
// damaged copies of them; a remembered or pre-checked signature counts only
// for the same algorithm, key, message, and signature bytes.

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/ledger/verify.hpp>

#include "signature_table.hpp"
#include "support/ledger_world.hpp"
#include "support/vectors.hpp"

namespace {

using namespace cexchain::test;
using cexchain::Bytes;
using cexchain::ByteView;
using cexchain::Errc;
using cexchain::Status;

/// The checks a verification makes, counted (each passed to `inner`).
class Counting final : public crypto::Provider {
public:
    explicit Counting(const crypto::Provider& inner) : inner_(inner) {}
    [[nodiscard]] bool supports(crypto::HashAlg alg) const noexcept override {
        return inner_.supports(alg);
    }
    [[nodiscard]] bool supports(crypto::SigAlg alg) const noexcept override {
        return inner_.supports(alg);
    }
    [[nodiscard]] std::size_t checks() const noexcept { return checks_.load(); }

private:
    [[nodiscard]] cexchain::Result<crypto::Digest>
    do_digest(crypto::HashAlg alg, std::span<const ByteView> parts) const override {
        return inner_.digest(alg, parts);
    }
    [[nodiscard]] Status do_verify(const crypto::PublicKey& key, ByteView message,
                                   ByteView signature) const override {
        ++checks_;
        return inner_.verify(key, message, signature);
    }
    const crypto::Provider& inner_;
    mutable std::atomic<std::size_t> checks_{0};
};

/// A hook that knows nothing and counts what it was asked.
struct Asked final : protocol::SignatureChecks {
    protocol::SignatureChecks* inner = nullptr;
    std::size_t found = 0;
    std::size_t missed = 0;
    std::optional<Status> find(const crypto::PublicKey& key, ByteView message,
                               ByteView signature) override {
        auto known = inner != nullptr ? inner->find(key, message, signature) : std::nullopt;
        ++(known ? found : missed);
        return known;
    }
    void checked(const crypto::PublicKey& /*key*/, ByteView /*message*/, ByteView /*signature*/,
                 const Status& /*outcome*/) override {}
};

/// Every variant of (key, message, signature) one byte or the algorithm off.
std::vector<std::tuple<crypto::PublicKey, Bytes, Bytes>>
neighbours(const crypto::PublicKey& key, const Bytes& message, const Bytes& signature) {
    std::vector<std::tuple<crypto::PublicKey, Bytes, Bytes>> out;
    for (std::size_t i = 0; i < key.bytes.size(); ++i) {
        auto k = key;
        k.bytes[i] ^= 0x01;
        out.emplace_back(k, message, signature);
    }
    for (std::size_t i = 0; i < message.size(); ++i) {
        auto m = message;
        m[i] ^= 0x80;
        out.emplace_back(key, m, signature);
    }
    for (std::size_t i = 0; i < signature.size(); ++i) {
        auto s = signature;
        s[i] ^= 0x01;
        out.emplace_back(key, message, s);
    }
    out.emplace_back(crypto::PublicKey{crypto::SigAlg::esp256, key.bytes}, message, signature);
    out.emplace_back(key, Bytes(message.begin(), message.end() - 1), signature);
    auto longer = message;
    longer.push_back(0);
    out.emplace_back(key, longer, signature);
    return out;
}

template <class T>
void same(const cexchain::Result<T>& expected, const cexchain::Result<T>& got) {
    REQUIRE(expected.has_value() == got.has_value());
    if (expected) {
        CHECK(*expected == *got);
    } else {
        CHECK(expected.error() == got.error());
    }
}

/// Verifies contract evidence (or a bundle) every way: core alone, then
/// checked ahead, remembered, both, and with `pristine` (remembered from the
/// evidence before it was damaged); each must give core's outcome.
template <class T, class Core, class Ledger>
cexchain::Result<T> every_way(ByteView encoded, const protocol::VerifyOptions& options,
                              ledger::SignatureCache& pristine, bool fresh_too, const Core& core,
                              const Ledger& on_cores) {
    const cexchain::Result<T> expected = core(encoded, options);
    same(expected, on_cores(encoded, options, ledger::Verifying{true, nullptr}));
    same(expected, on_cores(encoded, options, ledger::Verifying{false, &pristine}));
    same(expected, on_cores(encoded, options, ledger::Verifying{true, &pristine}));
    if (!fresh_too) {
        return expected;
    }
    // Modules remembered across every verification in the test.
    static ledger::LoadedModules modules;
    auto with_modules = options;
    with_modules.modules = &modules;
    same(expected, on_cores(encoded, with_modules, ledger::Verifying{false, &pristine}));
    ledger::SignatureCache fresh;
    same(expected, on_cores(encoded, options, ledger::Verifying{true, &fresh}));
    same(expected, on_cores(encoded, options, ledger::Verifying{false, &fresh}));
    same(expected, on_cores(encoded, options, ledger::Verifying{true, &fresh}));
    return expected;
}

cexchain::Result<protocol::ContractReport>
every_way_evidence(ByteView encoded, const protocol::VerifyOptions& options,
                   ledger::SignatureCache& pristine, bool fresh_too = true) {
    return every_way<protocol::ContractReport>(
        encoded, options, pristine, fresh_too,
        [](ByteView e, const protocol::VerifyOptions& o) {
            return protocol::verify_contract_evidence(provider(), e, o);
        },
        [](ByteView e, const protocol::VerifyOptions& o, const ledger::Verifying& how) {
            return ledger::verify_contract_evidence(provider(), e, o, how);
        });
}

cexchain::Result<protocol::EvidenceReport> every_way_bundle(ByteView encoded,
                                                            const protocol::VerifyOptions& options,
                                                            ledger::SignatureCache& pristine,
                                                            bool fresh_too = true) {
    return every_way<protocol::EvidenceReport>(
        encoded, options, pristine, fresh_too,
        [](ByteView e, const protocol::VerifyOptions& o) {
            return protocol::verify_bundle(provider(), e, o);
        },
        [](ByteView e, const protocol::VerifyOptions& o, const ledger::Verifying& how) {
            return ledger::verify_bundle(provider(), e, o, how);
        });
}

/// Damaged copies of a bundle: each byte (if `full`, else every
/// seventeenth) of its checkpoint and cosignatures, every fifth of its first
/// and last receipts' (if `full`), and a few of each entry's and receipt's
/// flipped in turn.
std::vector<Bytes> damaged(const protocol::EvidenceBundle& bundle, bool full) {
    const std::size_t step = full ? 1 : 17;
    std::vector<Bytes> out;
    const auto flip = [&](auto&& pick, std::size_t at) {
        auto copy = bundle;
        Bytes& bytes = pick(copy);
        bytes[at] ^= 0x01;
        if (auto encoded = protocol::encode_bundle(copy)) {
            out.push_back(std::move(*encoded));
        }
    };
    for (std::size_t i = 0; i < bundle.checkpoint.size(); i += step) {
        flip([](protocol::EvidenceBundle& b) -> Bytes& { return b.checkpoint; }, i);
    }
    for (std::size_t c = 0; c < bundle.cosignatures.size(); ++c) {
        for (std::size_t i = 0; i < bundle.cosignatures[c].size(); i += step) {
            flip([c](protocol::EvidenceBundle& b) -> Bytes& { return b.cosignatures[c]; }, i);
        }
    }
    for (std::size_t e = 0; e < bundle.entries.size(); ++e) {
        const auto receipt = [e](protocol::EvidenceBundle& b) -> Bytes& {
            return b.entries[e].receipt;
        };
        const auto entry = [e](protocol::EvidenceBundle& b) -> Bytes& {
            return b.entries[e].entry;
        };
        const std::size_t r = bundle.entries[e].receipt.size();
        const std::size_t n = bundle.entries[e].entry.size();
        if (full && (e == 0 || e + 1 == bundle.entries.size())) {
            for (std::size_t i = 0; i < r; i += 5) {
                flip(receipt, i);
            }
        } else {
            flip(receipt, r / 2);
        }
        for (const std::size_t i : {n / 3, n > 40 ? n - 40 : 0, n - 1}) {
            flip(entry, i);
        }
    }
    return out;
}

/// Contract evidence with each bundle in it damaged in turn (the instance's
/// fully if `full`).
std::vector<Bytes> damaged(const protocol::ContractEvidence& evidence, bool full) {
    std::vector<Bytes> out;
    for (std::size_t b = 0; b <= evidence.consent_bundles.size(); ++b) {
        const Bytes& encoded = b == 0 ? evidence.instance_bundle : evidence.consent_bundles[b - 1];
        const auto bundle = protocol::decode_bundle(encoded);
        REQUIRE(bundle);
        for (Bytes& d : damaged(*bundle, full && b == 0)) {
            auto copy = evidence;
            (b == 0 ? copy.instance_bundle : copy.consent_bundles[b - 1]) = std::move(d);
            out.push_back(*protocol::encode_contract_evidence(copy));
        }
    }
    return out;
}

} // namespace

TEST_CASE("a remembered signature counts only for the same algorithm, key, message, and signature",
          "[ledger][verify][signatures][security]") {
    const auto signer = key("signer");
    const auto text = cexchain::as_bytes("a message");
    const Bytes message(text.begin(), text.end());
    const Bytes signature = *signer.sign(message);
    const crypto::PublicKey& k = signer.public_key();
    REQUIRE(provider().verify(k, message, signature));

    ledger::SignatureCache cache;
    CHECK_FALSE(cache.find(k, message, signature));
    cache.checked(k, message, signature, Status{});
    CHECK(cache.find(k, message, signature) == Status{});
    for (const auto& [k2, m2, s2] : neighbours(k, message, signature)) {
        CHECK_FALSE(cache.find(k2, m2, s2));
    }
    // Failures are never kept.
    const Status failed = std::unexpected(cexchain::Error{Errc::verification_failed, "no"});
    for (const auto& [k2, m2, s2] : neighbours(k, message, signature)) {
        cache.checked(k2, m2, s2, failed);
    }
    CHECK(cache.stats().entries == 1);

    // Checks made ahead: found exactly, failures included.
    std::vector<ledger::detail::CheckedSignature> checks;
    checks.push_back({k, message, signature, Status{}});
    auto bad = signature;
    bad[0] ^= 0x01;
    checks.push_back({k, message, bad, failed});
    ledger::detail::SignatureTable table(std::move(checks));
    CHECK(table.find(k, message, signature) == Status{});
    CHECK(table.find(k, message, bad) == failed);
    for (const auto& [k2, m2, s2] : neighbours(k, message, signature)) {
        if (s2 != bad || !(k2 == k) || m2 != message) {
            CHECK_FALSE(table.find(k2, m2, s2));
        }
    }
}

TEST_CASE("the signature cache is bounded and shared between threads",
          "[ledger][verify][signatures]") {
    const auto signer = key("signer");
    const crypto::PublicKey& k = signer.public_key();
    const auto entry = [](std::size_t i) {
        return Bytes{static_cast<std::uint8_t>(i), static_cast<std::uint8_t>(i >> 8U)};
    };
    // 64 KiB: entries of ~260 bytes, at most 1 KiB each.
    ledger::SignatureCache cache(std::size_t{64} << 10);
    for (std::size_t i = 0; i < 1000; ++i) {
        cache.checked(k, entry(i), Bytes(64, 1), Status{});
    }
    const auto stats = cache.stats();
    CHECK(stats.bytes <= std::size_t{64} << 10);
    CHECK(stats.entries > 200);
    CHECK(stats.entries < 1000);
    CHECK(cache.find(k, entry(999), Bytes(64, 1)));
    CHECK_FALSE(cache.find(k, entry(0), Bytes(64, 1)));       // the oldest went first
    cache.checked(k, Bytes(2048, 1), Bytes(64, 1), Status{}); // over a sixty-fourth
    CHECK_FALSE(cache.find(k, Bytes(2048, 1), Bytes(64, 1)));

    // Many threads remembering and asking at once (TSan watches this).
    std::vector<std::thread> threads;
    std::atomic<std::size_t> hits{0};
    for (std::size_t t = 0; t < 8; ++t) {
        threads.emplace_back([&, t] {
            for (std::size_t i = 0; i < 2000; ++i) {
                const Bytes m = entry(1000 + (i * 7 + t) % 600);
                if (cache.find(k, m, Bytes(64, 2))) {
                    ++hits;
                } else {
                    cache.checked(k, m, Bytes(64, 2), Status{});
                }
            }
        });
    }
    for (std::thread& t : threads) {
        t.join();
    }
    CHECK(hits.load() > 0);
    CHECK(cache.stats().bytes <= std::size_t{64} << 10);
}

namespace {

/// The contract evidence in the protocol vectors (v0.7 and v0.8; v0.6's
/// shows only the encoding, around placeholder bundles).
std::vector<Bytes> evidence_vectors() {
    std::vector<Bytes> out;
    for (const char* file : {"protocol-v0.7.json", "protocol-v0.8.json"}) {
        for (const auto& ledger : load_vectors(file)["ledgers"]) {
            for (const auto& [what, expected] : ledger["evidence"].items()) {
                out.push_back(hex(expected["contract_evidence"].get<std::string>()));
            }
        }
    }
    return out;
}

} // namespace

TEST_CASE("every evidence vector verifies on all cores as core alone, damaged copies included",
          "[ledger][verify][vectors]") {
    const auto vectors = evidence_vectors();
    REQUIRE(vectors.size() == 12);
    std::size_t refused = 0;
    std::size_t unsigned_checkpoints = 0;
    for (std::size_t v = 0; v < vectors.size(); ++v) {
        const Bytes& encoded = vectors[v];
        ledger::SignatureCache pristine;
        REQUIRE(ledger::verify_contract_evidence(provider(), encoded, {}, {true, &pristine}));
        const auto report = every_way_evidence(encoded, {}, pristine);
        REQUIRE(report);
        const auto evidence = protocol::decode_contract_evidence(encoded);
        REQUIRE(evidence);
        CHECK(every_way_bundle(evidence->instance_bundle, {}, pristine));
        protocol::VerifyOptions options;
        options.expected_ledger = report->instance.ledger_id;
        CHECK(every_way_evidence(encoded, options, pristine));
        options.expected_ledger = report->instance.record;
        CHECK_FALSE(every_way_evidence(encoded, options, pristine));

        // Fully for the first (v0.7, SHA-256) only.
        for (const Bytes& d : damaged(*evidence, v == 0)) {
            const auto outcome = every_way_evidence(d, {}, pristine, false);
            if (!outcome) {
                ++refused;
                unsigned_checkpoints += outcome.error().detail ==
                                        "the checkpoint is not signed by the ledger's log key";
            }
        }
    }
    CHECK(refused > 500);
    // Damage that reaches a signature check (a checkpoint whose time or size
    // changed, say): what was remembered of the undamaged one must not count.
    CHECK(unsigned_checkpoints > 0);
}

TEST_CASE("checks made ahead are exactly the checks core makes", "[ledger][verify][vectors]") {
    for (const Bytes& encoded : evidence_vectors()) {
        const Counting alone(provider());
        const auto verified = protocol::verify_contract_evidence(alone, encoded);
        INFO((verified ? std::string() : std::string(verified.error().detail)));
        REQUIRE(verified);
        const Counting ahead(provider());
        ledger::detail::SignatureTable table(
            ledger::detail::check_ahead(ahead, encoded, true, {}, nullptr));
        CHECK(ahead.checks() == alone.checks()); // nothing checked in vain
        CHECK(table.size() == alone.checks());
        Asked asked;
        asked.inner = &table;
        protocol::VerifyOptions options;
        options.signatures = &asked;
        const Counting after(provider());
        REQUIRE(protocol::verify_contract_evidence(after, encoded, options));
        CHECK(asked.missed == 0); // nothing left to check one by one
        CHECK(asked.found == alone.checks());
        CHECK(after.checks() == 0);
    }
}

TEST_CASE("bundles across key rotations, with witnesses, verify on all cores as core alone",
          "[ledger][verify][rotation][witness]") {
    World w;
    const Cast c = build_cast(w);
    const auto log2 = key("log 2");
    const auto root2 = key("root 2");
    const auto first = w.ok(c.agent, agent_record(w, c, document_type));
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    w.ok(w.org(), w.statement(w.org_id(), std::nullopt,
                              protocol::LedgerRotateLogKeyBody{log2.public_key()}));
    w.ok(w.org(), w.statement(w.org_id(), std::nullopt,
                              protocol::ActorRotateKeyBody{w.org_id(), root2.public_key()}));
    const auto second = w.ok(c.agent, agent_record(w, c, document_type));
    const auto checkpoint = w.ledger().checkpoint(log2);
    REQUIRE(checkpoint);
    const auto witness = key("witness");
    const auto other = key("other witness");
    for (const KeyPair* k : {&witness, &other}) {
        REQUIRE(w.ledger().add_cosignature(
            protocol::cosign_checkpoint(*k, provider(), checkpoint->checkpoint)->encoded,
            k->public_key()));
    }
    const crypto::Signer* both[] = {&w.log_key(), &log2};
    for (const protocol::Id& record : {first, second}) {
        const auto bundle = w.ledger().export_evidence(ledger::LogKeys(both), record);
        REQUIRE(bundle);
        REQUIRE(bundle->cosignatures.size() == 2);
        const Bytes encoded = *protocol::encode_bundle(*bundle);
        protocol::VerifyOptions options;
        options.trusted_witnesses.push_back(witness.public_key());
        ledger::SignatureCache pristine;
        REQUIRE(ledger::verify_bundle(provider(), encoded, options, {true, &pristine}));
        const auto report = every_way_bundle(encoded, options, pristine);
        REQUIRE(report);
        CHECK(report->trusted_cosignatures == 1);
        CHECK(report->untrusted_cosignatures == 1);
        CHECK(report->log_key_rotations == 1);
        CHECK(report->root_key_rotations == 1);

        // Every check predicted, none in vain.
        const Counting alone(provider());
        REQUIRE(protocol::verify_bundle(alone, encoded, options));
        const Counting ahead(provider());
        ledger::detail::SignatureTable table(
            ledger::detail::check_ahead(ahead, encoded, false, options.trusted_witnesses, nullptr));
        CHECK(ahead.checks() == alone.checks());
        Asked asked;
        asked.inner = &table;
        auto hooked = options;
        hooked.signatures = &asked;
        REQUIRE(protocol::verify_bundle(provider(), encoded, hooked));
        CHECK(asked.missed == 0);
        CHECK(asked.found == alone.checks());

        std::size_t refused = 0;
        for (const Bytes& d : damaged(*bundle, record == first)) {
            if (!every_way_bundle(d, options, pristine, false)) {
                ++refused;
            }
        }
        CHECK(refused > 50);
    }
}

TEST_CASE("a remembered module is found only for the same code", "[ledger][verify][modules]") {
    const auto contracts = load_vectors("protocol-v0.7.json")["contracts"];
    const Bytes split = hex(contracts["split"].get<std::string>());
    const Bytes oracle = hex(contracts["oracle"].get<std::string>());
    ledger::LoadedModules modules(1);
    CHECK_FALSE(modules.find(split));
    const auto loaded = cexchain::vm::load(split);
    REQUIRE(loaded);
    modules.loaded(*loaded);
    const auto found = modules.find(split);
    REQUIRE(found);
    CHECK(std::ranges::equal(found->bytes(), split));
    for (std::size_t i = 0; i < split.size(); i += 97) {
        auto other = split;
        other[i] ^= 0x01;
        CHECK_FALSE(modules.find(other));
    }
    CHECK_FALSE(modules.find(Bytes(split.begin(), split.end() - 1)));
    modules.loaded(*cexchain::vm::load(oracle)); // capacity 1: split goes
    CHECK_FALSE(modules.find(split));
    CHECK(modules.find(oracle));
    CHECK(modules.size() == 1);
    CHECK(modules.hits() == 2);
}
