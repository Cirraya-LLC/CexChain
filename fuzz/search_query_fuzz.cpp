// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Searches and reports come from untrusted query parameters (the HTTP API's,
// the console's, MCP's). Each input is lines of NAME=VALUE. Properties:
// parsing never crashes; a query that parses always runs against an index
// (the SQL it builds, the full-text phrase it quotes, are always valid), or
// is refused for a limit, never for its SQL; a page holds at most its limit.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <unistd.h>

#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/crypto/openssl.hpp>
#include <kanhe/ledger/environment.hpp>
#include <kanhe/ledger/ledger.hpp>
#include <kanhe/ledger/storage.hpp>
#include <kanhe/search/index.hpp>
#include <kanhe/search/query.hpp>

namespace {

using namespace kanhe;

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

/// A ledger with a few records, and its index, made once.
struct World {
    crypto::openssl::Provider provider;
    ledger::MemoryFileSystem fs;
    ledger::ManualClock clock{1'793'491'200'000};
    std::optional<ledger::Ledger> ledger;
    std::unique_ptr<search::Index> index;
    std::filesystem::path file = std::filesystem::temp_directory_path() /
                                 ("kanhe-search-fuzz-" + std::to_string(::getpid()) + ".sqlite");

    World() {
        const Bytes seed(32, 7);
        auto org = crypto::openssl::KeyPair::from_ed25519_seed(seed);
        auto log = crypto::openssl::KeyPair::from_ed25519_seed(Bytes(32, 9));
        require(org && log);
        protocol::Statement genesis;
        genesis.issued_at = clock.now();
        genesis.nonce = {1};
        genesis.body = protocol::GenesisBody{crypto::HashAlg::sha256, "Fuzz School",
                                             org->public_key(), log->public_key()};
        auto signed_genesis =
            protocol::sign_statement(*org, provider, crypto::HashAlg::sha256, genesis);
        require(signed_genesis.has_value());
        auto created = ledger::Ledger::create(fs, clock, provider, signed_genesis->encoded);
        require(created.has_value());
        ledger.emplace(std::move(*created));
        for (std::uint8_t n = 0; n < 4; ++n) {
            protocol::Statement s;
            s.ledger_id = ledger->id();
            s.actor_id = ledger->id();
            s.issued_at = clock.now();
            s.nonce = {static_cast<std::uint8_t>(n + 2)};
            cbor::Map metadata{
                {cbor::Value::text("student"), cbor::Value::text("李明 " + std::to_string(n))},
                {cbor::Value::text("year"), cbor::Value::text(std::to_string(2024 + n))}};
            s.body = protocol::RecordRegisterBody{
                "example.form/1", Bytes(32, n), 1, {}, cbor::Value::map(std::move(metadata)),
                std::nullopt};
            auto signed_statement =
                protocol::sign_statement(*org, provider, crypto::HashAlg::sha256, s);
            require(signed_statement && ledger->submit(signed_statement->encoded).has_value());
            clock.advance(86'400'000);
        }
        std::filesystem::remove(file);
        auto opened = search::Index::open(*ledger, file);
        require(opened.has_value());
        index = std::move(*opened);
        require(index->update().has_value());
    }
    ~World() {
        index.reset();
        for (const char* suffix : {"", "-wal", "-shm"}) {
            std::filesystem::remove(file.string() + suffix);
        }
    }
    World(const World&) = delete;
    World& operator=(const World&) = delete;
};

World& world() {
    static World w;
    return w;
}

/// Refused only for what a caller may get wrong: a limit, an offset, a
/// cursor, a group that does not fit; never the SQL.
template <typename T>
void ran(const Result<T>& result) {
    require(result.has_value() || result.error().code == Errc::invalid_argument);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view input(reinterpret_cast<const char*>(data), size);
    search::Params params;
    std::size_t at = 0;
    while (at <= input.size() && params.size() < 16) {
        const std::size_t end = std::min(input.find('\n', at), input.size());
        const std::string_view line = input.substr(at, end - at);
        const std::size_t equals = line.find('=');
        if (equals != std::string_view::npos) {
            params.emplace_back(std::string(line.substr(0, equals)),
                                std::string(line.substr(equals + 1)));
        }
        at = end + 1;
    }
    World& w = world();
    if (const auto q = search::parse_record_search(params);
        const auto* s = std::get_if<search::RecordSearch>(&q)) {
        const auto page = w.index->records(s->filter, s->page);
        ran(page);
        require(!page || page->rows.size() <= s->page.limit);
    }
    if (const auto q = search::parse_instance_search(params);
        const auto* s = std::get_if<search::InstanceSearch>(&q)) {
        const auto page = w.index->instances(s->filter, s->page);
        ran(page);
        require(!page || page->rows.size() <= s->page.limit);
    }
    if (const auto q = search::parse_record_report(params);
        const auto* s = std::get_if<search::RecordReport>(&q)) {
        ran(w.index->report(s->filter, s->report));
    }
    if (const auto q = search::parse_instance_report(params);
        const auto* s = std::get_if<search::InstanceReport>(&q)) {
        ran(w.index->report(s->filter, s->report));
    }
    return 0;
}
