// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The ledger state written whole, for a ledger's own snapshot: a plain binary
// form (big-endian integers, length-prefixed strings, objects in log order),
// written and read in one pass without building trees. Equal states give
// equal bytes: maps are written in their insertion (log) order, which a
// decoded state keeps, and the nonces sorted. Not part of the protocol: a
// snapshot never leaves its machine, and the ledger checks it against the
// log it came from.

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/state.hpp>

namespace kanhe::protocol {

namespace {

class Out {
public:
    void u8(std::uint8_t v) { bytes_.push_back(v); }
    void u32(std::uint32_t v) {
        for (int shift = 24; shift >= 0; shift -= 8) {
            bytes_.push_back(static_cast<std::uint8_t>(v >> static_cast<unsigned>(shift)));
        }
    }
    void u64(std::uint64_t v) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            bytes_.push_back(static_cast<std::uint8_t>(v >> static_cast<unsigned>(shift)));
        }
    }
    void flag(bool v) { u8(v ? 1 : 0); }
    void raw(ByteView b) { bytes_.insert(bytes_.end(), b.begin(), b.end()); }
    void blob(ByteView b) {
        u32(static_cast<std::uint32_t>(b.size()));
        raw(b);
    }
    void text(std::string_view s) { blob(as_bytes(s)); }
    /// Ids are 32 bytes (`id_size`).
    void id(ByteView b) { raw(b); }
    void key(const crypto::PublicKey& k) {
        u32(static_cast<std::uint32_t>(crypto::cose_id(k.algorithm)));
        blob(k.bytes);
    }
    template <class T, class F>
    void opt(const std::optional<T>& value, F&& write) {
        flag(value.has_value());
        if (value) {
            write(*value);
        }
    }
    void indices(std::span<const std::uint64_t> values) {
        u32(static_cast<std::uint32_t>(values.size()));
        for (const std::uint64_t v : values) {
            u64(v);
        }
    }
    void texts(const std::vector<std::string>& values) {
        u32(static_cast<std::uint32_t>(values.size()));
        for (const std::string& v : values) {
            text(v);
        }
    }

    [[nodiscard]] Bytes take() { return std::move(bytes_); }

private:
    Bytes bytes_;
};

class In {
public:
    explicit In(ByteView bytes) noexcept : bytes_(bytes) {}

    [[nodiscard]] bool ok() const noexcept { return !bad_; }
    [[nodiscard]] bool done() const noexcept { return !bad_ && at_ == bytes_.size(); }
    void spoil() noexcept { bad_ = true; }

    std::uint8_t u8() { return need(1) ? bytes_[at_++] : 0; }
    std::uint32_t u32() {
        std::uint32_t v = 0;
        if (need(4)) {
            for (int i = 0; i < 4; ++i) {
                v = (v << 8U) | bytes_[at_++];
            }
        }
        return v;
    }
    std::uint64_t u64() {
        std::uint64_t v = 0;
        if (need(8)) {
            for (int i = 0; i < 8; ++i) {
                v = (v << 8U) | bytes_[at_++];
            }
        }
        return v;
    }
    bool flag() {
        const std::uint8_t v = u8();
        if (v > 1) {
            bad_ = true;
        }
        return v == 1;
    }
    ByteView raw(std::size_t n) {
        if (!need(n)) {
            return {};
        }
        const ByteView out = bytes_.subspan(at_, n);
        at_ += n;
        return out;
    }
    Bytes blob() {
        const ByteView b = raw(u32());
        return Bytes(b.begin(), b.end());
    }
    std::string text() {
        const ByteView b = raw(u32());
        return std::string(b.begin(), b.end());
    }
    IdKey key_bytes() {
        IdKey out{};
        const ByteView b = raw(id_size);
        if (b.size() == id_size) {
            std::ranges::copy(b, out.begin());
        }
        return out;
    }
    CompactId compact() { return CompactId(key_bytes()); }
    Id id() { return CompactId(key_bytes()).id(); }
    crypto::PublicKey key() {
        const auto alg = crypto::sig_alg_from_cose(static_cast<std::int32_t>(u32()));
        crypto::PublicKey out{alg.value_or(crypto::SigAlg::ed25519), blob()};
        if (!alg) {
            bad_ = true;
        }
        return out;
    }
    /// A count of items each at least `least` bytes long: never more than
    /// what is left could hold.
    std::uint32_t count(std::size_t least = 1) {
        const std::uint32_t n = u32();
        if (!bad_ && static_cast<std::uint64_t>(n) * least > bytes_.size() - at_) {
            bad_ = true;
            return 0;
        }
        return bad_ ? 0 : n;
    }
    template <class T, class F>
    std::optional<T> opt(F&& read) {
        if (!flag()) {
            return std::nullopt;
        }
        return read();
    }
    std::vector<std::uint64_t> indices() {
        std::vector<std::uint64_t> out(count(8));
        for (std::uint64_t& v : out) {
            v = u64();
        }
        return out;
    }
    IndexList index_list() {
        IndexList out;
        for (std::uint32_t n = count(8); n > 0; --n) {
            out.push_back(u64());
        }
        return out;
    }
    std::vector<std::string> texts() {
        std::vector<std::string> out(count(4));
        for (std::string& v : out) {
            v = text();
        }
        return out;
    }
    /// An enumerator, refused unless it is one of `known`.
    template <class E>
    E choice(std::initializer_list<E> known) {
        const auto raw_value = u8();
        for (const E e : known) {
            if (static_cast<std::uint8_t>(e) == raw_value) {
                return e;
            }
        }
        bad_ = true;
        return *known.begin();
    }

private:
    bool need(std::size_t n) noexcept {
        if (bad_ || bytes_.size() - at_ < n) {
            bad_ = true;
            return false;
        }
        return true;
    }

    ByteView bytes_;
    std::size_t at_ = 0;
    bool bad_ = false;
};

/// Strings that repeat across many records (types and states), written once.
class Strings {
public:
    std::uint32_t at(const std::string& s) {
        const auto [it, added] = index_.try_emplace(s, static_cast<std::uint32_t>(list_.size()));
        if (added) {
            list_.push_back(s);
        }
        return it->second;
    }
    [[nodiscard]] const std::vector<std::string>& list() const noexcept { return list_; }

private:
    std::map<std::string, std::uint32_t> index_;
    std::vector<std::string> list_;
};

constexpr std::initializer_list<ActorKind> actor_kinds{ActorKind::person, ActorKind::agent,
                                                       ActorKind::device};
constexpr std::initializer_list<PresenceMethod> presence_methods{PresenceMethod::webauthn,
                                                                 PresenceMethod::hardware_key};
constexpr std::initializer_list<FunctionKind> function_kinds{FunctionKind::create,
                                                             FunctionKind::call};
constexpr std::initializer_list<AnswerStatus> answer_statuses{
    AnswerStatus::done, AnswerStatus::failed, AnswerStatus::expired};

void write_scope(Out& out, const Scope& s) {
    out.u32(static_cast<std::uint32_t>(s.statement_types.size()));
    for (const StatementType t : s.statement_types) {
        out.u8(static_cast<std::uint8_t>(t));
    }
    out.opt(s.record_types, [&](const auto& v) { out.texts(v); });
    out.opt(s.not_before, [&](Timestamp v) { out.u64(v); });
    out.opt(s.not_after, [&](Timestamp v) { out.u64(v); });
    out.flag(s.may_delegate);
    out.flag(s.require_presence);
    out.opt(s.contracts, [&](const std::vector<Id>& v) {
        out.u32(static_cast<std::uint32_t>(v.size()));
        for (const Id& id : v) {
            out.id(id.bytes());
        }
    });
    out.opt(s.functions, [&](const auto& v) { out.texts(v); });
    out.opt(s.request_kinds, [&](const auto& v) { out.texts(v); });
}

Scope read_scope(In& in) {
    Scope s;
    for (std::uint32_t n = in.count(); n > 0; --n) {
        s.statement_types.push_back(static_cast<StatementType>(in.u8()));
    }
    s.record_types = in.opt<std::vector<std::string>>([&] { return in.texts(); });
    s.not_before = in.opt<Timestamp>([&] { return in.u64(); });
    s.not_after = in.opt<Timestamp>([&] { return in.u64(); });
    s.may_delegate = in.flag();
    s.require_presence = in.flag();
    s.contracts = in.opt<std::vector<Id>>([&] {
        std::vector<Id> v(in.count(id_size));
        for (Id& id : v) {
            id = in.id();
        }
        return v;
    });
    s.functions = in.opt<std::vector<std::string>>([&] { return in.texts(); });
    s.request_kinds = in.opt<std::vector<std::string>>([&] { return in.texts(); });
    return s;
}

/// Fails if a map's value names another id than its key.
template <class T>
bool keyed_by_id(const IdMap<T>& map) {
    return std::ranges::all_of(map, [](const auto& entry) {
        const auto& [key, value] = entry;
        return value.id.key() == key;
    });
}

} // namespace

Result<Bytes> LedgerState::encode() const {
    if (!keyed_by_id(actors_) || !keyed_by_id(delegations_) || !keyed_by_id(records_) ||
        !keyed_by_id(contracts_) || !keyed_by_id(instances_) || !keyed_by_id(requests_)) {
        return fail(Errc::invalid_argument, "a state object is kept under another id");
    }
    Out out;
    out.id(ledger_id_.bytes());
    out.u32(static_cast<std::uint32_t>(crypto::cose_id(hash_)));
    out.text(organization_);
    for (const auto* epochs : {&root_keys_, &log_keys_}) {
        out.u32(static_cast<std::uint32_t>(epochs->size()));
        for (const KeyEpoch& e : *epochs) {
            out.u64(e.index);
            out.key(e.key);
        }
    }

    out.u32(static_cast<std::uint32_t>(actors_.size()));
    for (const auto& [key, a] : actors_) {
        out.id(key);
        out.opt(a.kind, [&](ActorKind k) { out.u8(static_cast<std::uint8_t>(k)); });
        out.text(a.display_name);
        out.key(a.key);
        out.id(a.kid.bytes());
        out.opt(a.responsible, [&](const CompactId& r) { out.id(r.bytes()); });
        out.opt(a.agent, [&](const AgentProfile& p) {
            for (const auto* field : {&p.model, &p.model_version, &p.runtime}) {
                out.opt(*field, [&](const std::string& v) { out.text(v); });
            }
        });
        out.flag(a.revoked);
        out.u64(a.registered_at_index);
        out.opt(a.revoked_at_index, [&](std::uint64_t v) { out.u64(v); });
        out.indices(a.rotations);
        out.u32(static_cast<std::uint32_t>(a.presence.size()));
        for (const PresenceCredential& c : a.presence) {
            out.text(c.rp_id);
            out.blob(c.credential_id);
            out.key(c.key);
            out.opt(c.label, [&](const std::string& v) { out.text(v); });
            out.u8(static_cast<std::uint8_t>(c.method));
        }
        out.indices(a.presence_updates);
    }
    out.u32(static_cast<std::uint32_t>(actors_by_kid_.size()));
    for (const auto& [kid, actor] : actors_by_kid_) {
        out.id(kid);
        out.id(actor);
    }

    out.u32(static_cast<std::uint32_t>(delegations_.size()));
    for (const auto& [key, d] : delegations_) {
        out.id(key);
        out.id(d.grantor.bytes());
        out.opt(d.parent, [&](const CompactId& p) { out.id(p.bytes()); });
        out.id(d.grantee.bytes());
        write_scope(out, d.scope);
        out.flag(d.revoked);
        out.u64(d.granted_at_index);
        out.opt(d.revoked_at_index, [&](std::uint64_t v) { out.u64(v); });
    }

    // Records, the most numerous: their types and states as positions in a
    // table written first.
    Strings strings;
    Out records;
    records.u32(static_cast<std::uint32_t>(records_.size()));
    for (const auto& [key, r] : records_) {
        records.id(key);
        records.u32(strings.at(r.record_type));
        records.id(r.registrant.bytes());
        records.u32(strings.at(r.state));
        records.raw(r.field_root);
        records.u64(r.field_count);
        records.u32(static_cast<std::uint32_t>(r.endorsements.size()));
        for (const Endorsement& e : r.endorsements) {
            records.text(e.role);
            records.id(e.actor.bytes());
            records.u64(e.index);
        }
        records.flag(r.revoked);
        records.u64(r.registered_at_index);
        records.opt(r.supersedes, [&](const CompactId& s) { records.id(s.bytes()); });
        records.opt(r.superseded_by, [&](const CompactId& s) { records.id(s.bytes()); });
        records.u64(r.superseded_at_index);
        records.indices(std::span(r.history.begin(), r.history.end()));
    }
    out.texts(strings.list());
    out.raw(records.take());

    out.u32(static_cast<std::uint32_t>(contracts_.size()));
    for (const auto& [key, c] : contracts_) {
        out.id(key);
        out.id(c.deployer.bytes());
        out.u32(static_cast<std::uint32_t>(c.interface.size()));
        for (const auto& [name, kind] : c.interface) {
            out.text(name);
            out.u8(static_cast<std::uint8_t>(kind));
        }
        out.text(c.language);
        out.text(c.compiler);
        out.opt(c.name, [&](const std::string& v) { out.text(v); });
        out.flag(c.retired);
        out.u64(c.deployed_at_index);
        out.opt(c.retired_at_index, [&](std::uint64_t v) { out.u64(v); });
    }

    out.u32(static_cast<std::uint32_t>(instances_.size()));
    for (const auto& [key, i] : instances_) {
        out.id(key);
        out.id(i.contract.bytes());
        out.u64(i.head);
        out.blob(i.state.bytes());
        out.opt(i.status, [&](const std::string& v) { out.text(v); });
        out.u32(static_cast<std::uint32_t>(i.parties.size()));
        for (const auto& [role, ledger] : i.parties) {
            out.text(role);
            out.id(ledger.bytes());
        }
        out.flag(i.final);
        out.indices(std::span(i.history.begin(), i.history.end()));
        out.u64(i.created_by);
        out.opt(i.parent, [&](const CompactId& p) { out.id(p.bytes()); });
        out.u32(i.position);
        out.u32(i.depth);
        out.u32(static_cast<std::uint32_t>(i.open_requests.size()));
        for (const CompactId& r : i.open_requests) {
            out.id(r.bytes());
        }
    }

    out.u32(static_cast<std::uint32_t>(requests_.size()));
    for (const auto& [key, r] : requests_) {
        out.id(key);
        out.id(r.instance.bytes());
        out.u64(r.call);
        out.u32(r.position);
        out.text(r.kind);
        auto params = cbor::encode(r.params);
        if (!params) {
            return std::unexpected(params.error());
        }
        out.blob(*params);
        out.u64(r.deadline);
        out.text(r.reply);
        out.u64(r.asked_at);
        out.opt(r.status, [&](AnswerStatus s) { out.u8(static_cast<std::uint8_t>(s)); });
        out.opt(r.answered_by, [&](std::uint64_t v) { out.u64(v); });
        out.u64(r.answered_at);
    }

    out.u32(static_cast<std::uint32_t>(statements_.size()));
    for (const auto& [key, index] : statements_) {
        out.id(key);
        out.u64(index);
    }
    const auto nonces = nonces_.sorted();
    out.u32(static_cast<std::uint32_t>(nonces.size()));
    for (const auto& [actor, nonce] : nonces) {
        out.u32(actor);
        out.raw(nonce);
    }
    out.u32(static_cast<std::uint32_t>(changes_.size()));
    for (const IdKey& c : changes_) {
        out.id(c);
    }
    return out.take();
}

Result<LedgerState>
LedgerState::decode(ByteView bytes,
                    const std::function<Result<Bytes>(std::uint64_t)>& deploy_code) {
    In in(bytes);
    LedgerState s;
    s.ledger_id_ = in.id();
    const auto hash = crypto::hash_alg_from_cose(static_cast<std::int32_t>(in.u32()));
    if (!hash) {
        in.spoil();
    }
    s.hash_ = hash.value_or(crypto::HashAlg::sha256);
    s.organization_ = in.text();
    for (auto* epochs : {&s.root_keys_, &s.log_keys_}) {
        for (std::uint32_t n = in.count(12); n > 0; --n) {
            KeyEpoch e;
            e.index = in.u64();
            e.key = in.key();
            epochs->push_back(std::move(e));
        }
    }

    for (std::uint32_t n = in.count(id_size); n > 0 && in.ok(); --n) {
        const IdKey key = in.key_bytes();
        ActorState a;
        a.id = CompactId(key);
        a.kind = in.opt<ActorKind>([&] { return in.choice(actor_kinds); });
        a.display_name = in.text();
        a.key = in.key();
        a.kid = in.compact();
        a.responsible = in.opt<CompactId>([&] { return in.compact(); });
        a.agent = in.opt<AgentProfile>([&] {
            AgentProfile p;
            for (auto* field : {&p.model, &p.model_version, &p.runtime}) {
                *field = in.opt<std::string>([&] { return in.text(); });
            }
            return p;
        });
        a.revoked = in.flag();
        a.registered_at_index = in.u64();
        a.revoked_at_index = in.opt<std::uint64_t>([&] { return in.u64(); });
        a.rotations = in.indices();
        for (std::uint32_t c = in.count(); c > 0 && in.ok(); --c) {
            PresenceCredential credential;
            credential.rp_id = in.text();
            credential.credential_id = in.blob();
            credential.key = in.key();
            credential.label = in.opt<std::string>([&] { return in.text(); });
            credential.method = in.choice(presence_methods);
            a.presence.push_back(std::move(credential));
        }
        a.presence_updates = in.indices();
        s.actors_.insert_or_assign(key, std::move(a));
    }
    for (std::uint32_t n = in.count(2 * id_size); n > 0 && in.ok(); --n) {
        const IdKey kid = in.key_bytes();
        s.actors_by_kid_[kid] = in.key_bytes();
    }

    for (std::uint32_t n = in.count(id_size); n > 0 && in.ok(); --n) {
        const IdKey key = in.key_bytes();
        DelegationState d;
        d.id = CompactId(key);
        d.grantor = in.compact();
        d.parent = in.opt<CompactId>([&] { return in.compact(); });
        d.grantee = in.compact();
        d.scope = read_scope(in);
        d.revoked = in.flag();
        d.granted_at_index = in.u64();
        d.revoked_at_index = in.opt<std::uint64_t>([&] { return in.u64(); });
        s.delegations_.insert_or_assign(key, std::move(d));
    }

    const std::vector<std::string> strings = in.texts();
    auto string_at = [&](std::uint32_t i) -> std::string {
        if (i >= strings.size()) {
            in.spoil();
            return {};
        }
        return strings[i];
    };
    for (std::uint32_t n = in.count(id_size); n > 0 && in.ok(); --n) {
        const IdKey key = in.key_bytes();
        RecordState r;
        r.id = CompactId(key);
        r.record_type = string_at(in.u32());
        r.registrant = in.compact();
        r.state = string_at(in.u32());
        const ByteView root = in.raw(id_size);
        if (root.size() == id_size) {
            std::ranges::copy(root, r.field_root.begin());
        }
        r.field_count = in.u64();
        for (std::uint32_t e = in.count(); e > 0 && in.ok(); --e) {
            Endorsement endorsement;
            endorsement.role = in.text();
            endorsement.actor = in.compact();
            endorsement.index = in.u64();
            r.endorsements.push_back(std::move(endorsement));
        }
        r.revoked = in.flag();
        r.registered_at_index = in.u64();
        r.supersedes = in.opt<CompactId>([&] { return in.compact(); });
        r.superseded_by = in.opt<CompactId>([&] { return in.compact(); });
        r.superseded_at_index = in.u64();
        r.history = in.index_list();
        s.records_.insert_or_assign(key, std::move(r));
    }

    for (std::uint32_t n = in.count(id_size); n > 0 && in.ok(); --n) {
        const IdKey key = in.key_bytes();
        ContractState c;
        c.id = CompactId(key);
        c.deployer = in.compact();
        for (std::uint32_t f = in.count(); f > 0 && in.ok(); --f) {
            std::string name = in.text();
            c.interface.emplace(std::move(name), in.choice(function_kinds));
        }
        c.language = in.text();
        c.compiler = in.text();
        c.name = in.opt<std::string>([&] { return in.text(); });
        c.retired = in.flag();
        c.deployed_at_index = in.u64();
        c.retired_at_index = in.opt<std::uint64_t>([&] { return in.u64(); });
        if (in.ok()) {
            // The module, loaded again from the deploy's code.
            auto code = deploy_code(c.deployed_at_index);
            if (!code) {
                return std::unexpected(code.error());
            }
            auto module = s.load_module(*code);
            if (!module) {
                return std::unexpected(module.error());
            }
            c.module = std::move(*module);
        }
        s.contracts_.insert_or_assign(key, std::move(c));
    }

    for (std::uint32_t n = in.count(id_size); n > 0 && in.ok(); --n) {
        const IdKey key = in.key_bytes();
        InstanceState i;
        i.id = CompactId(key);
        i.contract = in.compact();
        i.head = in.u64();
        auto state = cbor::Encoded::from_bytes(in.blob());
        if (!state) {
            in.spoil();
        } else {
            i.state = std::move(*state);
        }
        i.status = in.opt<std::string>([&] { return in.text(); });
        for (std::uint32_t p = in.count(); p > 0 && in.ok(); --p) {
            std::string role = in.text();
            i.parties.emplace(std::move(role), in.id());
        }
        i.final = in.flag();
        i.history = in.index_list();
        i.created_by = in.u64();
        i.parent = in.opt<CompactId>([&] { return in.compact(); });
        i.position = in.u32();
        i.depth = in.u32();
        for (std::uint32_t r = in.count(id_size); r > 0 && in.ok(); --r) {
            i.open_requests.push_back(in.compact());
        }
        s.instances_.insert_or_assign(key, std::move(i));
    }

    for (std::uint32_t n = in.count(id_size); n > 0 && in.ok(); --n) {
        const IdKey key = in.key_bytes();
        RequestState r;
        r.id = CompactId(key);
        r.instance = in.compact();
        r.call = in.u64();
        r.position = in.u32();
        r.kind = in.text();
        auto params = cbor::decode(in.blob());
        if (!params) {
            in.spoil();
        } else {
            r.params = std::move(*params);
        }
        r.deadline = in.u64();
        r.reply = in.text();
        r.asked_at = in.u64();
        r.status = in.opt<AnswerStatus>([&] { return in.choice(answer_statuses); });
        r.answered_by = in.opt<std::uint64_t>([&] { return in.u64(); });
        r.answered_at = in.u64();
        s.requests_.insert_or_assign(key, std::move(r));
    }

    for (std::uint32_t n = in.count(id_size + 8); n > 0 && in.ok(); --n) {
        const IdKey key = in.key_bytes();
        s.statements_.insert_or_assign(key, in.u64());
    }
    for (std::uint32_t n = in.count(4 + std::tuple_size_v<Nonce>); n > 0 && in.ok(); --n) {
        const std::uint32_t actor = in.u32();
        Nonce nonce{};
        const ByteView b = in.raw(nonce.size());
        if (b.size() == nonce.size()) {
            std::ranges::copy(b, nonce.begin());
        }
        s.nonces_.insert(actor, nonce);
    }
    for (std::uint32_t n = in.count(id_size); n > 0 && in.ok(); --n) {
        s.changes_.push_back(in.key_bytes());
    }
    if (!in.done()) {
        return fail(Errc::malformed, "a snapshot's state is malformed");
    }
    return s;
}

} // namespace kanhe::protocol
