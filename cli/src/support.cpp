// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "support.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <unistd.h>
#include <variant>

namespace cexchain::cli {

namespace {

constexpr std::size_t min_prefix = 8;

template <class Map>
protocol::Id resolve(const Map& map, std::string_view text, std::string_view what) {
    std::string lower(text);
    std::ranges::transform(lower, lower.begin(), [](unsigned char c) { return std::tolower(c); });
    if (lower.size() < min_prefix) {
        throw UsageError{std::string(what) + " id must have at least 8 hex digits"};
    }
    const protocol::Id* found = nullptr;
    for (const auto& [key, value] : map) {
        if (hex_id(value.id).starts_with(lower)) {
            if (found != nullptr) {
                throw UsageError{"ambiguous " + std::string(what) + " id " + std::string(text)};
            }
            found = &value.id;
        }
    }
    if (found == nullptr) {
        throw CommandError{"no " + std::string(what) + " with id " + std::string(text)};
    }
    return *found;
}

std::optional<std::string> record_type_for(const protocol::LedgerState& state,
                                           const protocol::Body& body) {
    return std::visit(
        [&](const auto& b) -> std::optional<std::string> {
            using T = std::decay_t<decltype(b)>;
            if constexpr (std::is_same_v<T, protocol::RecordRegisterBody>) {
                return b.record_type;
            } else if constexpr (std::is_same_v<T, protocol::RecordEndorseBody> ||
                                 std::is_same_v<T, protocol::RecordTransitionBody> ||
                                 std::is_same_v<T, protocol::RecordRevokeBody>) {
                const protocol::RecordState* r = state.record(b.record);
                return r == nullptr ? std::nullopt : std::optional(r->record_type);
            } else {
                return std::nullopt;
            }
        },
        body);
}

} // namespace

Bytes read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw CommandError{"cannot read " + path.string()};
    }
    return Bytes(std::istreambuf_iterator<char>(in), {});
}

void write_file(const std::filesystem::path& path, ByteView data, bool private_file) {
    const std::filesystem::path temporary = path.string() + ".tmp";
    const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                          private_file ? 0600 : 0644);
    if (fd < 0) {
        throw CommandError{"cannot write " + path.string()};
    }
    std::size_t done = 0;
    while (done < data.size()) {
        const ssize_t n = ::write(fd, data.data() + done, data.size() - done);
        if (n <= 0) {
            ::close(fd);
            throw CommandError{"cannot write " + path.string()};
        }
        done += static_cast<std::size_t>(n);
    }
    const bool synced = ::fsync(fd) == 0;
    ::close(fd);
    if (!synced || std::rename(temporary.c_str(), path.c_str()) != 0) {
        throw CommandError{"cannot write " + path.string()};
    }
}

std::string hex_id(const protocol::Id& id) {
    return to_hex(id.bytes());
}

std::string short_id(const protocol::Id& id) {
    return hex_id(id).substr(0, 12);
}

std::string format_time(protocol::Timestamp ms) {
    using namespace std::chrono;
    const sys_time<milliseconds> time{milliseconds{static_cast<std::int64_t>(ms)}};
    return std::format("{:%Y-%m-%d %H:%M:%S} UTC", floor<seconds>(time));
}

protocol::Timestamp parse_time(std::string_view text) {
    int y = 0;
    unsigned mo = 0;
    unsigned d = 0;
    unsigned h = 0;
    unsigned mi = 0;
    unsigned s = 0;
    const std::string str(text);
    const int fields = std::sscanf(str.c_str(), "%d-%u-%uT%u:%u:%u", &y, &mo, &d, &h, &mi, &s);
    if (fields != 3 && fields != 6) {
        throw UsageError{"time must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ"};
    }
    using namespace std::chrono;
    const year_month_day date{year{y}, month{mo}, day{d}};
    if (!date.ok() || h > 23 || mi > 59 || s > 59) {
        throw UsageError{"invalid date " + str};
    }
    const auto time = sys_days{date} + hours{h} + minutes{mi} + seconds{s};
    return static_cast<protocol::Timestamp>(
        duration_cast<milliseconds>(time.time_since_epoch()).count());
}

crypto::openssl::KeyPair load_key(const std::filesystem::path& path) {
    return unwrap(crypto::openssl::KeyPair::from_pkcs8(read_file(path)),
                  "loading " + path.string());
}

crypto::SigAlg parse_algorithm(std::string_view name) {
    for (const crypto::SigAlg alg : crypto::all_sig_algs) {
        std::string lower(crypto::name(alg));
        std::ranges::transform(lower, lower.begin(),
                               [](unsigned char c) { return std::tolower(c); });
        if (lower == name) {
            return alg;
        }
    }
    throw UsageError{"unknown algorithm " + std::string(name) +
                     " (ed25519, esp256, sm2-sm3, ml-dsa-44, ml-dsa-65, ml-dsa-87)"};
}

crypto::HashAlg parse_hash(std::string_view name) {
    if (name == "sha256" || name == "sha-256") {
        return crypto::HashAlg::sha256;
    }
    if (name == "sm3") {
        return crypto::HashAlg::sm3;
    }
    throw UsageError{"hash must be sha256 or sm3"};
}

protocol::StatementType parse_statement_type(std::string_view name) {
    for (std::uint64_t value = 1; value < 32; ++value) {
        const auto type = protocol::statement_type_from(value);
        if (type && protocol::name(*type) == name) {
            return *type;
        }
    }
    throw UsageError{"unknown statement type " + std::string(name)};
}

protocol::ActorKind parse_actor_kind(std::string_view name) {
    if (name == "person") {
        return protocol::ActorKind::person;
    }
    if (name == "agent") {
        return protocol::ActorKind::agent;
    }
    if (name == "device") {
        return protocol::ActorKind::device;
    }
    throw UsageError{"actor kind must be person, agent, or device"};
}

std::string_view kind_name(const std::optional<protocol::ActorKind>& kind) {
    if (!kind) {
        return "organization";
    }
    switch (*kind) {
    case protocol::ActorKind::person:
        return "person";
    case protocol::ActorKind::agent:
        return "AI agent";
    case protocol::ActorKind::device:
        return "device";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

Session::Session(const std::filesystem::path& directory) : directory_(directory) {
    if (!std::filesystem::is_directory(directory)) {
        throw CommandError{"no ledger directory at " + directory.string()};
    }
    fs_.emplace(unwrap(ledger::PosixFileSystem::open_directory(directory), "opening the ledger"));
    ledger_.emplace(unwrap(ledger::Ledger::open(*fs_, clock_, provider_), "opening the ledger"));
}

protocol::Id Session::actor_id(std::string_view text) const {
    return resolve(state().actors(), text, "actor");
}

protocol::Id Session::record_id(std::string_view text) const {
    return resolve(state().records(), text, "record");
}

protocol::Id Session::delegation_id(std::string_view text) const {
    return resolve(state().delegations(), text, "delegation");
}

const protocol::ActorState& Session::actor_for(const crypto::Signer& key) const {
    const auto kid =
        unwrap(protocol::key_id(provider_, state().hash(), key.public_key()), "key id");
    for (const auto& [id, actor] : state().actors()) {
        if (actor.kid == kid) {
            if (actor.revoked) {
                throw CommandError{"the actor holding this key has been revoked"};
            }
            return actor;
        }
    }
    throw CommandError{"this key does not belong to any actor of the ledger"};
}

std::optional<protocol::Id>
Session::choose_delegation(const protocol::ActorState& actor, protocol::StatementType type,
                           const std::optional<std::string>& record_type) const {
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    std::optional<protocol::Id> chosen;
    std::uint64_t newest = 0;
    for (const auto& [key, d] : state().delegations()) {
        const bool usable = d.grantee == actor.id && !d.revoked &&
                            std::ranges::contains(d.scope.statement_types, type) &&
                            (!record_type || !d.scope.record_types ||
                             std::ranges::contains(*d.scope.record_types, *record_type)) &&
                            (!d.scope.not_before || *d.scope.not_before <= now) &&
                            (!d.scope.not_after || now <= *d.scope.not_after);
        if (usable && (!chosen || d.granted_at_index > newest)) {
            chosen = d.id;
            newest = d.granted_at_index;
        }
    }
    return chosen;
}

protocol::Id Session::submit(const crypto::Signer& signer, protocol::Body body,
                             const std::optional<std::string>& delegation,
                             std::optional<protocol::Provenance> provenance) {
    const protocol::ActorState& actor = actor_for(signer);
    protocol::Statement statement;
    statement.ledger_id = state().ledger_id();
    statement.actor_id = actor.id;
    statement.issued_at = clock_.now();
    statement.nonce = entropy_.bytes<16>();
    if (!actor.is_organization()) {
        const bool self_rotation = std::holds_alternative<protocol::ActorRotateKeyBody>(body) &&
                                   std::get<protocol::ActorRotateKeyBody>(body).actor == actor.id;
        if (delegation) {
            statement.delegation_id = delegation_id(*delegation);
        } else if (!self_rotation) {
            statement.delegation_id =
                choose_delegation(actor, protocol::type_of(body), record_type_for(state(), body));
            if (!statement.delegation_id) {
                throw CommandError{"no valid delegation lets " + actor.display_name + " do this"};
            }
        }
    }
    if (actor.kind == protocol::ActorKind::agent) {
        if (!provenance) {
            provenance = protocol::Provenance{};
        }
        if (!provenance->model && actor.agent) {
            provenance->model = actor.agent->model;
            provenance->model_version = actor.agent->model_version;
        }
    }
    statement.provenance = std::move(provenance);
    statement.body = std::move(body);

    const auto signed_statement =
        unwrap(protocol::sign_statement(signer, provider_, state().hash(), statement), "signing");
    const auto registration =
        unwrap(ledger_->submit(signed_statement.encoded), "the ledger refused the statement");
    return registration.statement_id;
}

std::filesystem::path Session::vault_path(const protocol::Id& record) const {
    return directory_ / "vault" / (hex_id(record) + ".cbor");
}

void create_ledger(const std::filesystem::path& directory, const crypto::Signer& root_key,
                   const crypto::PublicKey& log_key, crypto::HashAlg hash,
                   const std::string& organization) {
    const crypto::openssl::Provider provider;
    ledger::SystemClock clock;
    ledger::SystemEntropy entropy;
    auto fs = unwrap(ledger::PosixFileSystem::open_directory(directory), "creating the directory");

    protocol::Statement genesis;
    genesis.issued_at = clock.now();
    genesis.nonce = entropy.bytes<16>();
    genesis.body = protocol::GenesisBody{hash, organization, root_key.public_key(), log_key};
    const auto signed_genesis =
        unwrap(protocol::sign_statement(root_key, provider, hash, genesis), "signing genesis");
    static_cast<void>(unwrap(ledger::Ledger::create(fs, clock, provider, signed_genesis.encoded),
                             "creating the ledger"));
}

} // namespace cexchain::cli
