// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <cstring>
#include <functional>
#include <iterator>
#include <list>
#include <map>
#include <mutex>
#include <set>
#include <utility>

#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/ledger/parallel.hpp>
#include <cexchain/ledger/verify.hpp>

#include "signature_table.hpp"

namespace cexchain::ledger {

namespace detail {

namespace {

std::strong_ordering compare_bytes(ByteView a, ByteView b) noexcept {
    const std::size_t common = std::min(a.size(), b.size());
    if (common != 0) {
        if (const int c = std::memcmp(a.data(), b.data(), common); c != 0) {
            return c < 0 ? std::strong_ordering::less : std::strong_ordering::greater;
        }
    }
    return a.size() <=> b.size();
}

} // namespace

std::strong_ordering compare(const crypto::PublicKey& a_key, ByteView a_message,
                             ByteView a_signature, const crypto::PublicKey& b_key,
                             ByteView b_message, ByteView b_signature) noexcept {
    if (const auto c = compare_bytes(a_signature, b_signature); c != 0) {
        return c;
    }
    if (const auto c = a_key.algorithm <=> b_key.algorithm; c != 0) {
        return c;
    }
    if (const auto c = compare_bytes(a_key.bytes, b_key.bytes); c != 0) {
        return c;
    }
    return compare_bytes(a_message, b_message);
}

SignatureTable::SignatureTable(std::vector<CheckedSignature> checks) : checks_(std::move(checks)) {
    const auto less = [](const CheckedSignature& a, const CheckedSignature& b) {
        return compare(a.key, a.message, a.signature, b.key, b.message, b.signature) < 0;
    };
    std::ranges::sort(checks_, less);
    // The same check twice has the same outcome: keep one.
    const auto same = [](const CheckedSignature& a, const CheckedSignature& b) {
        return compare(a.key, a.message, a.signature, b.key, b.message, b.signature) == 0;
    };
    const auto [first, last] = std::ranges::unique(checks_, same);
    checks_.erase(first, last);
}

std::optional<Status> SignatureTable::find(const crypto::PublicKey& key, ByteView message,
                                           ByteView signature) {
    const auto at = std::ranges::partition_point(checks_, [&](const CheckedSignature& c) {
        return compare(c.key, c.message, c.signature, key, message, signature) < 0;
    });
    if (at == checks_.end() ||
        compare(at->key, at->message, at->signature, key, message, signature) != 0) {
        return std::nullopt;
    }
    return at->outcome;
}

namespace {

/// Checks signatures with `inner` (after `cache`) and records each check.
class Recorder final : public crypto::Provider {
public:
    Recorder(const crypto::Provider& inner, SignatureCache* cache,
             std::vector<CheckedSignature>& out) noexcept
        : inner_(inner), cache_(cache), out_(out) {}

    [[nodiscard]] bool supports(crypto::HashAlg alg) const noexcept override {
        return inner_.supports(alg);
    }
    [[nodiscard]] bool supports(crypto::SigAlg alg) const noexcept override {
        return inner_.supports(alg);
    }

private:
    [[nodiscard]] Result<crypto::Digest> do_digest(crypto::HashAlg alg,
                                                   std::span<const ByteView> parts) const override {
        return inner_.digest(alg, parts);
    }
    [[nodiscard]] Status do_verify(const crypto::PublicKey& key, ByteView message,
                                   ByteView signature) const override {
        std::optional<Status> outcome;
        if (cache_ != nullptr) {
            outcome = cache_->find(key, message, signature);
        }
        if (!outcome) {
            outcome = inner_.verify(key, message, signature);
            if (cache_ != nullptr) {
                cache_->checked(key, message, signature, *outcome);
            }
        }
        out_.push_back(CheckedSignature{key, Bytes(message.begin(), message.end()),
                                        Bytes(signature.begin(), signature.end()), *outcome});
        return *outcome;
    }

    const crypto::Provider& inner_;
    SignatureCache* cache_;
    std::vector<CheckedSignature>& out_;
};

struct ParsedEntry {
    std::optional<protocol::SignedStatement> statement;
    std::optional<protocol::SignedStateCommitment> commitment;
    std::optional<protocol::Receipt> receipt;
};

/// A bundle read as far as checking its signatures ahead needs.
struct ParsedBundle {
    protocol::EvidenceBundle bundle;
    crypto::HashAlg hash = crypto::HashAlg::sha256;
    std::vector<ParsedEntry> entries;
    std::optional<protocol::SignedCheckpoint> checkpoint;
    std::vector<protocol::SignedCheckpoint> cosignatures;
};

/// Decodes a bundle and reads its genesis (which names the ledger's hash).
std::optional<ParsedBundle> read_bundle(const crypto::Provider& provider, ByteView encoded) {
    auto bundle = protocol::decode_bundle(encoded);
    if (!bundle || bundle->entries.empty()) {
        return std::nullopt;
    }
    ParsedBundle out;
    out.bundle = std::move(*bundle);
    out.entries.resize(out.bundle.entries.size());
    auto genesis_entry = protocol::decode_log_entry(out.bundle.entries.front().entry);
    if (!genesis_entry || genesis_entry->is_state_commitment()) {
        return std::nullopt;
    }
    auto genesis = protocol::parse_statement(provider, genesis_entry->statement);
    if (!genesis) {
        return std::nullopt;
    }
    out.hash = genesis->hash_alg;
    out.entries.front().statement = std::move(*genesis);
    if (auto checkpoint = protocol::parse_checkpoint(out.bundle.checkpoint)) {
        out.checkpoint = std::move(*checkpoint);
    }
    for (const Bytes& encoded_cosignature : out.bundle.cosignatures) {
        if (auto cosignature = protocol::parse_cosignature(encoded_cosignature)) {
            out.cosignatures.push_back(std::move(*cosignature));
        }
    }
    return out;
}

/// Reads entry `i` (after genesis) of a bundle, and its receipt.
void read_entry(const crypto::Provider& provider, ParsedBundle& b, std::size_t i) {
    ParsedEntry& out = b.entries[i];
    if (auto receipt = protocol::parse_receipt(b.bundle.entries[i].receipt)) {
        out.receipt = std::move(*receipt);
    }
    if (i == 0) {
        return;
    }
    auto entry = protocol::decode_log_entry(b.bundle.entries[i].entry);
    if (!entry) {
        return;
    }
    if (entry->is_state_commitment()) {
        if (auto c = protocol::parse_state_commitment(provider, entry->state_commitment)) {
            out.commitment = std::move(*c);
        }
    } else if (auto s = protocol::parse_statement(provider, entry->statement, b.hash)) {
        out.statement = std::move(*s);
    }
}

using Job = std::function<void(const crypto::Provider&)>;
using LogKeyFor = std::function<const crypto::PublicKey*(std::uint64_t tree_size)>;

/// The checkpoint's, each distinct receipt seal's, and each trusted
/// witness's first cosignature's checks (as `verify_bundle` makes them).
void add_checkpoint_jobs(const crypto::Provider& provider, const ParsedBundle& b,
                         std::span<const crypto::PublicKey> trusted, const LogKeyFor& log_key_for,
                         std::vector<Job>& jobs) {
    if (!b.checkpoint) {
        return;
    }
    const protocol::SignedCheckpoint* checkpoint = &*b.checkpoint;
    const crypto::PublicKey* log_key = log_key_for(checkpoint->checkpoint.tree_size);
    jobs.emplace_back([checkpoint, log_key](const crypto::Provider& p) {
        static_cast<void>(protocol::verify_checkpoint(p, *checkpoint, *log_key));
    });
    std::set<std::pair<Bytes, Bytes>> seals;
    for (const ParsedEntry& e : b.entries) {
        if (!e.receipt) {
            continue;
        }
        if (seals.emplace(e.receipt->envelope.protected_bytes, e.receipt->envelope.signature)
                .second) {
            jobs.emplace_back([r = &*e.receipt, checkpoint, log_key](const crypto::Provider& p) {
                static_cast<void>(protocol::verify_receipt_signature(
                    p, *r, checkpoint->checkpoint.root, *log_key));
            });
        }
    }
    std::vector<protocol::IdKey> witnesses;
    for (const crypto::PublicKey& witness : trusted) {
        auto kid = protocol::key_id(provider, b.hash, witness);
        witnesses.push_back(kid ? protocol::key_of(*kid) : protocol::IdKey{});
    }
    std::set<protocol::IdKey> counted;
    for (const protocol::SignedCheckpoint& cosignature : b.cosignatures) {
        if (cosignature.checkpoint != checkpoint->checkpoint ||
            !counted.insert(protocol::key_of(cosignature.kid)).second) {
            continue;
        }
        for (std::size_t w = 0; w < trusted.size(); ++w) {
            if (witnesses[w] == protocol::key_of(cosignature.kid)) {
                jobs.emplace_back([c = &cosignature, k = &trusted[w]](const crypto::Provider& p) {
                    static_cast<void>(protocol::verify_cosignature(p, *c, *k));
                });
                break;
            }
        }
    }
}

/// The checks a bundle's verification will make, as far as the bundle tells
/// the keys: each statement's with the key its kid names (genesis's root
/// key, or one an actor registration or key rotation introduces), the state
/// commitments', checkpoint's, and receipt seals' with the log key in effect,
/// and trusted witnesses' cosignatures. `b` must outlive the jobs.
void add_jobs(const crypto::Provider& provider, const ParsedBundle& b,
              std::span<const crypto::PublicKey> trusted, std::vector<Job>& jobs) {
    std::map<protocol::IdKey, const crypto::PublicKey*> keys;
    const auto introduce = [&](const crypto::PublicKey& key) {
        if (auto kid = protocol::key_id(provider, b.hash, key)) {
            keys.emplace(protocol::key_of(*kid), &key);
        }
    };
    // Log keys by the index of the entry that set them (0: genesis).
    std::vector<std::pair<std::uint64_t, const crypto::PublicKey*>> log_keys;
    for (std::size_t i = 0; i < b.entries.size(); ++i) {
        const ParsedEntry& e = b.entries[i];
        if (!e.statement) {
            continue;
        }
        const protocol::Body& body = e.statement->statement.body;
        if (const auto* g = std::get_if<protocol::GenesisBody>(&body); g != nullptr && i == 0) {
            introduce(g->root_key);
            log_keys.emplace_back(0, &g->log_key);
        } else if (const auto* r = std::get_if<protocol::ActorRegisterBody>(&body)) {
            introduce(r->key);
        } else if (const auto* k = std::get_if<protocol::ActorRotateKeyBody>(&body)) {
            introduce(k->key);
        } else if (const auto* l = std::get_if<protocol::LedgerRotateLogKeyBody>(&body);
                   l != nullptr && e.receipt) {
            log_keys.emplace_back(e.receipt->proof.leaf_index, &l->key);
        }
    }
    if (log_keys.empty() || log_keys.front().first != 0) {
        return; // no genesis: the verification fails before any other check
    }
    std::ranges::stable_sort(log_keys, {},
                             &std::pair<std::uint64_t, const crypto::PublicKey*>::first);
    // As protocol::key_in_effect.
    const auto log_key_for = [&](std::uint64_t size) {
        const auto after = std::ranges::lower_bound(
            log_keys, size, {}, &std::pair<std::uint64_t, const crypto::PublicKey*>::first);
        return after == log_keys.begin() ? log_keys.front().second : std::prev(after)->second;
    };
    for (const ParsedEntry& e : b.entries) {
        if (e.statement) {
            if (const auto key = keys.find(protocol::key_of(e.statement->kid)); key != keys.end()) {
                jobs.emplace_back([s = &*e.statement, k = key->second](const crypto::Provider& p) {
                    static_cast<void>(protocol::verify_statement(p, *s, *k));
                });
            }
        } else if (e.commitment && e.receipt) {
            jobs.emplace_back([c = &*e.commitment, k = log_key_for(e.receipt->proof.leaf_index)](
                                  const crypto::Provider& p) {
                static_cast<void>(protocol::verify_state_commitment(p, *c, *k));
            });
        }
    }
    add_checkpoint_jobs(provider, b, trusted, log_key_for, jobs);
}

} // namespace

std::vector<CheckedSignature> check_ahead(const crypto::Provider& provider, ByteView encoded,
                                          bool contract_evidence,
                                          std::span<const crypto::PublicKey> trusted_witnesses,
                                          SignatureCache* cache) {
    std::optional<protocol::ContractEvidence> evidence;
    std::vector<ByteView> encoded_bundles;
    if (contract_evidence) {
        auto decoded = protocol::decode_contract_evidence(encoded);
        if (!decoded) {
            return {};
        }
        evidence = std::move(*decoded);
        encoded_bundles.emplace_back(evidence->instance_bundle);
        for (const Bytes& bundle : evidence->consent_bundles) {
            encoded_bundles.emplace_back(bundle);
        }
    } else {
        encoded_bundles.push_back(encoded);
    }
    // Read every bundle's entries on all cores, then check on all cores.
    std::vector<ParsedBundle> bundles(encoded_bundles.size());
    std::vector<std::uint8_t> read(encoded_bundles.size(), 0); // not vector<bool>: written apart
    parallel_for(
        encoded_bundles.size(),
        [&](std::size_t begin, std::size_t end) {
            for (std::size_t i = begin; i < end; ++i) {
                if (auto b = read_bundle(provider, encoded_bundles[i])) {
                    bundles[i] = std::move(*b);
                    read[i] = 1;
                }
            }
        },
        2);
    std::vector<std::pair<std::size_t, std::size_t>> entries;
    for (std::size_t i = 0; i < bundles.size(); ++i) {
        for (std::size_t e = 0; read[i] && e < bundles[i].entries.size(); ++e) {
            entries.emplace_back(i, e);
        }
    }
    parallel_for(entries.size(), [&](std::size_t begin, std::size_t end) {
        for (std::size_t k = begin; k < end; ++k) {
            read_entry(provider, bundles[entries[k].first], entries[k].second);
        }
    });
    std::vector<Job> jobs;
    for (std::size_t i = 0; i < bundles.size(); ++i) {
        if (read[i]) {
            add_jobs(provider, bundles[i], trusted_witnesses, jobs);
        }
    }
    std::vector<std::vector<CheckedSignature>> made(jobs.size());
    parallel_for(
        jobs.size(),
        [&](std::size_t begin, std::size_t end) {
            for (std::size_t i = begin; i < end; ++i) {
                const Recorder recorder(provider, cache, made[i]);
                jobs[i](recorder);
            }
        },
        2);
    std::vector<CheckedSignature> out;
    for (std::vector<CheckedSignature>& m : made) {
        std::ranges::move(m, std::back_inserter(out));
    }
    return out;
}

} // namespace detail

namespace {

struct CacheEntry {
    crypto::PublicKey key;
    Bytes message;
    Bytes signature;
    std::size_t cost = 0;
};
using Lru = std::list<CacheEntry>;

struct Probe {
    const crypto::PublicKey& key;
    ByteView message;
    ByteView signature;
};

/// Orders the index by each entry's bytes (as `detail::compare`).
struct EntryLess {
    using is_transparent = void;
    bool operator()(Lru::iterator a, Lru::iterator b) const noexcept {
        return detail::compare(a->key, a->message, a->signature, b->key, b->message, b->signature) <
               0;
    }
    bool operator()(Lru::iterator a, const Probe& b) const noexcept {
        return detail::compare(a->key, a->message, a->signature, b.key, b.message, b.signature) < 0;
    }
    bool operator()(const Probe& a, Lru::iterator b) const noexcept {
        return detail::compare(a.key, a.message, a.signature, b->key, b->message, b->signature) < 0;
    }
};

/// What an entry costs besides its bytes (list and tree nodes, vectors).
constexpr std::size_t entry_allowance = 160;

} // namespace

struct SignatureCache::Impl {
    std::size_t capacity = 0;
    mutable std::mutex mutex;
    /// Most recently used first.
    Lru lru;
    std::set<Lru::iterator, EntryLess> index;
    std::size_t bytes = 0;
    std::uint64_t hits = 0;
    std::uint64_t misses = 0;
};

SignatureCache::SignatureCache(std::size_t capacity) : impl_(std::make_unique<Impl>()) {
    impl_->capacity = capacity;
}

SignatureCache::~SignatureCache() = default;

std::optional<Status> SignatureCache::find(const crypto::PublicKey& key, ByteView message,
                                           ByteView signature) {
    const std::lock_guard lock(impl_->mutex);
    const auto found = impl_->index.find(Probe{key, message, signature});
    if (found == impl_->index.end()) {
        ++impl_->misses;
        return std::nullopt;
    }
    ++impl_->hits;
    impl_->lru.splice(impl_->lru.begin(), impl_->lru, *found);
    return Status{};
}

void SignatureCache::checked(const crypto::PublicKey& key, ByteView message, ByteView signature,
                             const Status& outcome) {
    const std::size_t cost = key.bytes.size() + message.size() + signature.size() + entry_allowance;
    if (!outcome || cost > impl_->capacity / 64) {
        return;
    }
    Lru fresh;
    fresh.push_back(CacheEntry{key, Bytes(message.begin(), message.end()),
                               Bytes(signature.begin(), signature.end()), cost});
    const std::lock_guard lock(impl_->mutex);
    if (impl_->index.contains(Probe{key, message, signature})) {
        return;
    }
    impl_->lru.splice(impl_->lru.begin(), fresh);
    impl_->index.insert(impl_->lru.begin());
    impl_->bytes += cost;
    while (impl_->bytes > impl_->capacity) {
        const auto oldest = std::prev(impl_->lru.end());
        impl_->index.erase(oldest);
        impl_->bytes -= oldest->cost;
        impl_->lru.erase(oldest);
    }
}

SignatureCache::Stats SignatureCache::stats() const {
    const std::lock_guard lock(impl_->mutex);
    return {impl_->hits, impl_->misses, impl_->lru.size(), impl_->bytes};
}

void SignatureCache::clear() {
    const std::lock_guard lock(impl_->mutex);
    impl_->index.clear();
    impl_->lru.clear();
    impl_->bytes = 0;
}

namespace {

/// Asks the signatures checked ahead, then the cache, which it tells every
/// new outcome.
class Chain final : public protocol::SignatureChecks {
public:
    Chain(detail::SignatureTable* table, SignatureCache* cache) noexcept
        : table_(table), cache_(cache) {}

    std::optional<Status> find(const crypto::PublicKey& key, ByteView message,
                               ByteView signature) override {
        std::optional<Status> found;
        if (table_ != nullptr) {
            found = table_->find(key, message, signature);
        }
        if (!found && cache_ != nullptr) {
            found = cache_->find(key, message, signature);
        }
        return found;
    }
    void checked(const crypto::PublicKey& key, ByteView message, ByteView signature,
                 const Status& outcome) override {
        if (cache_ != nullptr) {
            cache_->checked(key, message, signature, outcome);
        }
    }

private:
    detail::SignatureTable* table_;
    SignatureCache* cache_;
};

template <class Verify>
auto verify_with(const crypto::Provider& provider, ByteView encoded,
                 const protocol::VerifyOptions& options, const Verifying& how,
                 bool contract_evidence, const Verify& verify) {
    std::optional<detail::SignatureTable> table;
    if (how.ahead) {
        table.emplace(detail::check_ahead(provider, encoded, contract_evidence,
                                          options.trusted_witnesses, how.cache));
    }
    Chain chain(table ? &*table : nullptr, how.cache);
    // A hook in the options is core's to ask, before this one.
    const protocol::CheckedProvider checked(provider, chain);
    return verify(checked, encoded, options);
}

} // namespace

Result<protocol::EvidenceReport> verify_bundle(const crypto::Provider& provider, ByteView encoded,
                                               const protocol::VerifyOptions& options,
                                               const Verifying& how) {
    return verify_with(provider, encoded, options, how, false,
                       [](const crypto::Provider& p, ByteView e, const protocol::VerifyOptions& o) {
                           return protocol::verify_bundle(p, e, o);
                       });
}

Result<protocol::ContractReport> verify_contract_evidence(const crypto::Provider& provider,
                                                          ByteView encoded,
                                                          const protocol::VerifyOptions& options,
                                                          const Verifying& how) {
    return verify_with(provider, encoded, options, how, true,
                       [](const crypto::Provider& p, ByteView e, const protocol::VerifyOptions& o) {
                           return protocol::verify_contract_evidence(p, e, o);
                       });
}

struct LoadedModules::Impl {
    std::size_t capacity = 0;
    mutable std::mutex mutex;
    /// Most recently used first.
    std::list<vm::Module> modules;
    std::uint64_t hits = 0;
};

LoadedModules::LoadedModules(std::size_t capacity) : impl_(std::make_unique<Impl>()) {
    impl_->capacity = capacity;
}

LoadedModules::~LoadedModules() = default;

std::optional<vm::Module> LoadedModules::find(ByteView code) {
    const std::lock_guard lock(impl_->mutex);
    const auto found = std::ranges::find_if(
        impl_->modules, [&](const vm::Module& m) { return std::ranges::equal(m.bytes(), code); });
    if (found == impl_->modules.end()) {
        return std::nullopt;
    }
    ++impl_->hits;
    impl_->modules.splice(impl_->modules.begin(), impl_->modules, found);
    return *found;
}

void LoadedModules::loaded(const vm::Module& module) {
    if (module.bytes().size() > max_code_size || impl_->capacity == 0) {
        return;
    }
    const std::lock_guard lock(impl_->mutex);
    if (std::ranges::any_of(impl_->modules, [&](const vm::Module& m) {
            return std::ranges::equal(m.bytes(), module.bytes());
        })) {
        return;
    }
    impl_->modules.push_front(module);
    if (impl_->modules.size() > impl_->capacity) {
        impl_->modules.pop_back();
    }
}

std::size_t LoadedModules::size() const {
    const std::lock_guard lock(impl_->mutex);
    return impl_->modules.size();
}

std::uint64_t LoadedModules::hits() const {
    const std::lock_guard lock(impl_->mutex);
    return impl_->hits;
}

LoadedModules& loaded_modules() {
    static auto* modules = new LoadedModules();
    return *modules;
}

SignatureCache& signature_cache() {
    // Never destroyed, as the pool: threads may still use it at exit.
    static auto* cache = new SignatureCache();
    return *cache;
}

} // namespace cexchain::ledger
