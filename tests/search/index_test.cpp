// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The search index: it follows the log, finds records and instances by what
// the ledger holds in the clear, pages through them, and counts them.

#include <atomic>
#include <filesystem>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/search/index.hpp>
#include <cexchain/search/query.hpp>

#include "support/ledger_world.hpp"
#include "support/vectors.hpp"

namespace {

using namespace cexchain::test;
using cexchain::Bytes;
namespace search = cexchain::search;

struct TempFile {
    std::filesystem::path path;
    TempFile() {
        static int counter = 0;
        path = std::filesystem::temp_directory_path() /
               ("cexchain-search-test-" + std::to_string(::getpid()) + "-" +
                std::to_string(++counter) + ".sqlite");
        remove();
    }
    ~TempFile() { remove(); }
    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;
    void remove() const {
        for (const char* suffix : {"", "-wal", "-shm"}) {
            std::filesystem::remove(path.string() + suffix);
        }
    }
};

cbor::Value metadata(std::vector<std::pair<std::string, cbor::Value>> entries) {
    cbor::Map map;
    for (auto& [k, v] : entries) {
        map.push_back({cbor::Value::text(k), std::move(v)});
    }
    return cbor::Value::map(std::move(map));
}

protocol::RecordRegisterBody form(const std::string& type, cbor::Value meta,
                                  std::optional<protocol::Id> supersedes = std::nullopt) {
    return {type, Bytes(32, 0x42), 3, {}, std::move(meta), supersedes};
}

std::vector<std::string> types_of(const search::Page<search::RecordRow>& page) {
    std::vector<std::string> out;
    for (const auto& r : page.rows) {
        out.push_back(r.type);
    }
    return out;
}

} // namespace

TEST_CASE("the index finds records by what the ledger holds in the clear", "[search]") {
    World w;
    TempFile file;
    auto index = search::Index::open(w.ledger(), file.path);
    REQUIRE(index);
    const auto org = w.org_id();
    auto reg = [&](const protocol::RecordRegisterBody& b) {
        return w.ok(w.org(), w.statement(org, std::nullopt, b));
    };
    const auto li = reg(form("example.school.application/1",
                             metadata({{"student", cbor::Value::text("李明")},
                                       {"class", cbor::Value::text("S5B")},
                                       {"year", cbor::Value::unsigned_integer(2025)}})));
    w.clock().advance(day);
    const auto chan = reg(form("example.school.application/1",
                               metadata({{"student", cbor::Value::text("陳永康")},
                                         {"class", cbor::Value::text("S4A")},
                                         {"year", cbor::Value::unsigned_integer(2026)}})));
    const auto blank1 = reg(form("example.school.blank-form/1",
                                 metadata({{"title", cbor::Value::text("走讀申請表")}})));
    w.clock().advance(day);
    const auto blank2 = reg(form("example.school.blank-form/1",
                                 metadata({{"title", cbor::Value::text("走讀申請表")}}), blank1));
    w.ok(w.org(), w.statement(org, std::nullopt, protocol::RecordEndorseBody{li, "counsellor"}));
    w.ok(w.org(), w.statement(org, std::nullopt, protocol::RecordRevokeBody{chan, "withdrawn"}));

    auto updated = (*index)->update();
    REQUIRE(updated);
    CHECK(*updated == w.ledger().size());
    const search::PageRequest page;

    auto apps = (*index)->records({.type = "example.school.application/1"}, page);
    REQUIRE(apps);
    REQUIRE(apps->rows.size() == 1); // the revoked one left out
    CHECK(apps->rows[0].id == li);
    CHECK(apps->rows[0].endorsements == 1);
    CHECK(apps->rows[0].metadata.size() == 3);
    CHECK(apps->as_of == w.ledger().size());
    CHECK((*index)
              ->records({.type = "example.school.application/1",
                         .revoked = search::RecordFilter::Revoked::any},
                        page)
              ->rows.size() == 2);
    CHECK((*index)->records({.revoked = search::RecordFilter::Revoked::yes}, page)->rows[0].id ==
          chan);

    // Versions: the old one is superseded, and `current` leaves it out.
    auto blanks = (*index)->records({.type = "example.school.blank-form/1"}, page);
    REQUIRE(blanks->rows.size() == 2);
    CHECK(blanks->rows[0].id == blank2); // newest first
    CHECK(blanks->rows[1].superseded_by == blank2);
    CHECK(blanks->rows[0].supersedes == blank1);
    auto current =
        (*index)->records({.type = "example.school.blank-form/1", .current = true}, page);
    REQUIRE(current->rows.size() == 1);
    CHECK(current->rows[0].id == blank2);

    // Metadata: exactly, by number, and by text (Chinese, short and long).
    using M = search::RecordFilter::Metadata;
    CHECK((*index)->records({.metadata = {M{"class", "S5B", {}, {}}}}, page)->rows.size() == 1);
    CHECK((*index)
              ->records({.revoked = search::RecordFilter::Revoked::any,
                         .metadata = {M{"year", {}, 2026, {}}}},
                        page)
              ->rows[0]
              .id == chan);
    CHECK((*index)->records({.metadata = {M{"year", {}, {}, 2024}}}, page)->rows.empty());
    CHECK((*index)->records({.text = "走讀申請"}, page)->rows.size() == 2);
    CHECK((*index)->records({.text = "李明"}, page)->rows.size() == 1); // two characters
    CHECK((*index)->records({.text = "s5b"}, page)->rows.size() == 1);  // any case
    CHECK((*index)->records({.text = "nothing like it"}, page)->rows.empty());

    // Time and registrant.
    CHECK(types_of(*(*index)->records({.until = t0 + day / 2}, page)) ==
          std::vector<std::string>{"example.school.application/1"});
    CHECK((*index)->records({.registrant = org}, page)->rows.size() == 3);
    CHECK((*index)->records({.registrant = li}, page)->rows.empty()); // not an actor

    // Pages: one at a time, both ways, with a cursor that runs out.
    std::vector<protocol::Id> seen;
    search::PageRequest one{.limit = 1};
    for (;;) {
        auto p = (*index)->records({.revoked = search::RecordFilter::Revoked::any}, one);
        REQUIRE(p);
        for (const auto& r : p->rows) {
            seen.push_back(r.id);
        }
        if (!p->next) {
            break;
        }
        one.cursor = p->next;
    }
    CHECK(seen == std::vector<protocol::Id>{blank2, blank1, chan, li});
    auto oldest = (*index)->records({.revoked = search::RecordFilter::Revoked::any},
                                    {.limit = 2, .oldest_first = true});
    REQUIRE(oldest->rows.size() == 2);
    CHECK(oldest->rows[0].id == li);
    CHECK(oldest->next);
    CHECK_FALSE((*index)->records({}, {.limit = 0}));
    CHECK_FALSE((*index)->records({}, {.limit = 1001}));
    CHECK_FALSE((*index)->records({}, {.cursor = "x1"}));

    // Reports: by type and state, by day in Hong Kong's time.
    auto by_type =
        (*index)->report(search::RecordFilter{.revoked = search::RecordFilter::Revoked::any},
                         {.by = {search::Group::type, search::Group::state}});
    REQUIRE(by_type);
    REQUIRE(by_type->rows.size() == 2);
    CHECK(by_type->rows[0].count == 2);
    auto by_day =
        (*index)->report(search::RecordFilter{.revoked = search::RecordFilter::Revoked::any},
                         {.by = {search::Group::day}, .utc_offset_minutes = 8 * 60});
    REQUIRE(by_day);
    REQUIRE(by_day->rows.size() == 3);
    CHECK(by_day->rows[0].key == std::vector<std::string>{"2026-10-06"});
    CHECK(by_day->rows[2].key == std::vector<std::string>{"2026-10-08"});
    auto by_week =
        (*index)->report(search::RecordFilter{.revoked = search::RecordFilter::Revoked::any},
                         {.by = {search::Group::week}});
    REQUIRE(by_week->rows.size() == 1);
    CHECK(by_week->rows[0].key == std::vector<std::string>{"2026-10-05"}); // a Monday
    CHECK_FALSE((*index)->report(search::RecordFilter{}, {.by = {search::Group::contract}}));
    CHECK_FALSE((*index)->report(search::RecordFilter{}, {.utc_offset_minutes = 15 * 60}));

    // It follows the log: later statements change the rows.
    w.ok(w.org(), w.statement(org, std::nullopt, protocol::RecordEndorseBody{li, "office"}));
    REQUIRE((*index)->update());
    CHECK((*index)->records({.type = "example.school.application/1"}, page)->rows[0].endorsements ==
          2);
    auto status = (*index)->status();
    REQUIRE(status);
    CHECK(status->records == 4);
    CHECK(status->indexed == w.ledger().size());
}

TEST_CASE("the index finds instances by their contract, state, parties, and fields", "[search]") {
    World home{crypto::HashAlg::sha256, "School"};
    World other{crypto::HashAlg::sm3, "Parent"};
    TempFile file;
    auto index = search::Index::open(home.ledger(), file.path);
    REQUIRE(index);
    protocol::ContractDeployBody deploy;
    deploy.code = hex(load_vectors("protocol-v0.6.json")["contract"].get<std::string>());
    deploy.interface = {{"apply", protocol::FunctionKind::create},
                        {"approve", protocol::FunctionKind::call}};
    deploy.language = "wasm";
    deploy.compiler = "hand-assembled 1";
    deploy.name = "Day student";
    const auto contract = home.ok(home.org(), home.statement(home.org_id(), std::nullopt, deploy));
    // The oracle contract writes the output its byte-string argument holds:
    // a Bo-shaped state, with fields.
    auto output = [&](const std::string& status, std::int64_t fee, const std::string& klass,
                      bool parties) {
        cbor::Map fields{{cbor::Value::text("class"), cbor::Value::text(klass)},
                         {cbor::Value::text("fee"), cbor::Value::integer(fee)},
                         {cbor::Value::text("guardian_agrees"), cbor::Value::boolean(true)}};
        const cbor::Value state =
            cbor::Value::map({{cbor::Value::text("fields"), cbor::Value::map(std::move(fields))},
                              {cbor::Value::text("state"), cbor::Value::text(status)}});
        protocol::ContractAccept accept{
            *cbor::Encoded::encode(state),
            status,
            parties ? std::optional(protocol::Parties{{"parent", other.ledger().id()}})
                    : std::nullopt,
            {},
            false,
            {},
            {}};
        auto encoded = protocol::encode_contract_output(accept);
        REQUIRE(encoded);
        return cbor::Value::bytes(*encoded);
    };
    auto create = [&](const std::string& klass, std::int64_t fee, bool parties,
                      std::optional<std::string> reference) {
        protocol::ContractCallBody b;
        b.contract = contract;
        b.function = "apply";
        b.arguments = output("submitted", fee, klass, parties);
        b.reference = std::move(reference);
        return home.ok(home.org(), home.statement(home.org_id(), std::nullopt, b));
    };
    const auto a = create("S5B", 300, true, "APP-1");
    home.clock().advance(day);
    const auto b = create("S4A", 500, false, std::nullopt);
    const auto c = create("S5B", 700, false, "APP-3");
    protocol::ContractCallBody approve;
    approve.instance = a;
    approve.function = "approve";
    approve.arguments = output("approved", 300, "S5B", true);
    approve.head = home.ledger().state().instance(a)->head;
    home.ok(home.org(), home.statement(home.org_id(), std::nullopt, approve));

    REQUIRE((*index)->update(std::chrono::hours(1), 2)); // in small batches
    const search::PageRequest page;
    auto all = (*index)->instances({}, page);
    REQUIRE(all);
    REQUIRE(all->rows.size() == 3);
    CHECK(all->rows[0].id == c);
    CHECK(all->rows[1].id == b);
    CHECK(all->rows[2].id == a);
    CHECK(all->rows[2].status == "approved");
    CHECK(all->rows[2].calls == 2);
    CHECK(all->rows[2].contract_name == "Day student");
    CHECK(all->rows[2].reference == "APP-1");
    CHECK(all->rows[2].parties.size() == 1);
    CHECK(all->rows[1].fields ==
          std::vector<std::pair<std::string, std::string>>{
              {"class", "S4A"}, {"fee", "500"}, {"guardian_agrees", "true"}});

    using F = search::InstanceFilter::Field;
    CHECK((*index)->instances({.status = "submitted"}, page)->rows.size() == 2);
    CHECK((*index)->instances({.contract = contract}, page)->rows.size() == 3);
    CHECK((*index)->instances({.contract_name = "Day student"}, page)->rows.size() == 3);
    CHECK((*index)->instances({.contract_name = "Other"}, page)->rows.empty());
    CHECK((*index)->instances({.party = other.ledger().id()}, page)->rows[0].id == a);
    CHECK((*index)->instances({.reference = "APP-3"}, page)->rows[0].id == c);
    CHECK((*index)->instances({.fields = {F{"class", "S5B", {}, {}}}}, page)->rows.size() == 2);
    CHECK((*index)->instances({.fields = {F{"fee", {}, 400, {}}}}, page)->rows.size() == 2);
    CHECK((*index)
              ->instances({.fields = {F{"guardian_agrees", "true", {}, {}}}}, page)
              ->rows.size() == 3);
    CHECK((*index)->instances({.until = t0 + day / 2}, page)->rows.size() == 1);

    // Reports: by state, with the fee's total, least, and greatest.
    auto by_state =
        (*index)->report(search::InstanceFilter{}, {.by = {search::Group::state}, .sum = "fee"});
    REQUIRE(by_state);
    REQUIRE(by_state->rows.size() == 2);
    CHECK(by_state->rows[0].key == std::vector<std::string>{"submitted"});
    CHECK(by_state->rows[0].count == 2);
    CHECK(by_state->rows[0].sum == 1200);
    CHECK(by_state->rows[0].min == 500);
    CHECK(by_state->rows[0].max == 700);
    auto by_contract =
        (*index)->report(search::InstanceFilter{}, {.by = {search::Group::contract}});
    REQUIRE(by_contract->rows.size() == 1);
    CHECK(by_contract->rows[0].key[0] == cexchain::to_hex(contract.bytes()));
    auto total = (*index)->report(search::InstanceFilter{.fields = {F{"class", "S5B", {}, {}}}},
                                  {.sum = "fee"});
    REQUIRE(total->rows.size() == 1);
    CHECK(total->rows[0].count == 2);
    CHECK(total->rows[0].sum == 1000);
    CHECK_FALSE((*index)->report(search::InstanceFilter{}, {.by = {search::Group::type}}));
    CHECK_FALSE((*index)->report(search::RecordFilter{}, {.sum = "fee"}));

    // Built in bulk, the same answers.
    TempFile bulk_file;
    auto bulk = search::Index::open(home.ledger(), bulk_file.path, 1);
    REQUIRE(bulk);
    REQUIRE((*bulk)->update());
    CHECK(search::to_json(*(*bulk)->instances({}, page)) == search::to_json(*all));
    CHECK(search::to_json(*(*bulk)->report(search::InstanceFilter{},
                                           {.by = {search::Group::state}, .sum = "fee"})) ==
          search::to_json(*by_state));
    CHECK((*bulk)->instances({.fields = {F{"fee", {}, 400, {}}}}, page)->rows.size() == 2);
}

TEST_CASE("an index of another ledger, or of none, is rebuilt from the log", "[search]") {
    World first;
    World second{crypto::HashAlg::sha256, "Second"};
    TempFile file;
    first.ok(first.org(),
             first.statement(first.org_id(), std::nullopt,
                             form("example.note/1", metadata({{"a", cbor::Value::text("b")}}))));
    {
        auto index = search::Index::open(first.ledger(), file.path);
        REQUIRE(index);
        REQUIRE((*index)->update());
        CHECK((*index)->records({}, {})->rows.size() == 1);
    }
    {
        // Opened again, it carries on where it was.
        auto again = search::Index::open(first.ledger(), file.path);
        REQUIRE(again);
        CHECK((*again)->status()->indexed == first.ledger().size());
        CHECK((*again)->records({}, {})->rows.size() == 1);
        // Emptied, it is rebuilt from the log.
        REQUIRE((*again)->clear());
        CHECK((*again)->records({}, {})->rows.empty());
        REQUIRE((*again)->update());
        CHECK((*again)->records({}, {})->rows.size() == 1);
    }
    // Another ledger's index starts again.
    auto other = search::Index::open(second.ledger(), file.path);
    REQUIRE(other);
    CHECK((*other)->status()->indexed == 0);
    CHECK((*other)->records({}, {})->rows.empty());
    REQUIRE((*other)->update());
    CHECK((*other)->records({}, {})->rows.empty());
}

TEST_CASE("an index built in bulk answers as one built entry by entry", "[search]") {
    World w;
    const auto org = w.org_id();
    std::vector<protocol::Id> ids;
    auto add = [&](int from, int to) {
        for (int i = from; i < to; ++i) {
            std::optional<protocol::Id> older;
            if (i % 10 == 9) {
                older = ids[static_cast<std::size_t>(i - 3)]; // same type: i % 3 alike
            }
            ids.push_back(w.ok(
                w.org(),
                w.statement(
                    org, std::nullopt,
                    form(i % 3 == 0 ? "example.note/1" : "example.memo/1",
                         metadata(
                             {{"class", cbor::Value::text("S" + std::to_string(i % 4))},
                              {"n", cbor::Value::unsigned_integer(static_cast<std::uint64_t>(i))},
                              {"name", cbor::Value::text("學生 " + std::to_string(i))}}),
                         older))));
            if (i % 7 == 6) {
                w.clock().advance(day);
            }
        }
    };
    add(0, 60);
    w.ok(w.org(), w.statement(org, std::nullopt, protocol::RecordEndorseBody{ids[1], "checked"}));
    w.ok(w.org(), w.statement(org, std::nullopt, protocol::RecordRevokeBody{ids[2], "withdrawn"}));

    TempFile by_entry_file;
    TempFile bulk_file;
    // Far behind by any count: built in bulk, its secondary indexes made at
    // the end; the other entry by entry, in small batches.
    auto by_entry = search::Index::open(w.ledger(), by_entry_file.path, 1'000'000);
    auto bulk = search::Index::open(w.ledger(), bulk_file.path, 10);
    REQUIRE(by_entry);
    REQUIRE(bulk);
    REQUIRE((*by_entry)->update(std::chrono::hours(1), 7));
    REQUIRE((*bulk)->update());

    auto same = [&] {
        const search::PageRequest all{.limit = 1000};
        using M = search::RecordFilter::Metadata;
        const std::vector<search::RecordFilter> filters{
            {},
            {.revoked = search::RecordFilter::Revoked::any},
            {.type = "example.note/1", .current = true},
            {.metadata = {M{"class", "S2", {}, {}}}},
            {.metadata = {M{"n", {}, 10, 30}}},
            {.text = "學生 4"},
            {.since = w.clock().now() - 3 * day}};
        for (const auto& f : filters) {
            auto a = (*by_entry)->records(f, all);
            auto b = (*bulk)->records(f, all);
            REQUIRE(a);
            REQUIRE(b);
            CHECK_FALSE(a->rows.empty());
            CHECK(search::to_json(*a) == search::to_json(*b));
        }
        for (const auto& by : {std::vector{search::Group::type, search::Group::state},
                               std::vector{search::Group::day}}) {
            auto a = (*by_entry)->report(search::RecordFilter{}, {.by = by});
            auto b = (*bulk)->report(search::RecordFilter{}, {.by = by});
            REQUIRE(a);
            REQUIRE(b);
            CHECK(search::to_json(*a) == search::to_json(*b));
        }
        auto row = (*bulk)->record(ids[5]);
        REQUIRE(row);
        REQUIRE(row->has_value());
        CHECK((*row)->metadata.size() == 3);
    };
    same();
    CHECK((*bulk)->status()->indexed == w.ledger().size());

    // A little more, under the threshold: followed entry by entry, as usual.
    add(60, 65);
    REQUIRE((*by_entry)->update());
    REQUIRE((*bulk)->update());
    same();
    // A lot more: in bulk again.
    add(65, 90);
    REQUIRE((*by_entry)->update());
    REQUIRE((*bulk)->update());
    same();
    // Opened again (as after a stop), it carries on.
    bulk->reset();
    auto again = search::Index::open(w.ledger(), bulk_file.path, 10);
    REQUIRE(again);
    CHECK((*again)->as_of() == w.ledger().size());
    CHECK(search::to_json(*(*again)->records({}, {.limit = 1000})) ==
          search::to_json(*(*by_entry)->records({}, {.limit = 1000})));
}

TEST_CASE("searches run beside the index's updates, each on one update's view", "[search]") {
    World w;
    const auto org = w.org_id();
    TempFile file;
    auto opened = search::Index::open(w.ledger(), file.path);
    REQUIRE(opened);
    search::Index& index = **opened;
    auto add = [&](int count) {
        for (int i = 0; i < count; ++i) {
            w.ok(w.org(), w.statement(org, std::nullopt,
                                      form("example.note/1",
                                           metadata({{"class", cbor::Value::text("S1")}}))));
        }
    };
    add(5);
    REQUIRE(index.update());

    std::atomic<bool> done = false;
    std::atomic<int> problems = 0;
    std::vector<std::jthread> readers;
    for (int t = 0; t < 4; ++t) {
        readers.emplace_back([&] {
            std::uint64_t last = 0;
            while (!done) {
                auto page = index.records({.metadata = {{"class", "S1", {}, {}}}}, {.limit = 1000});
                auto report = index.report(search::RecordFilter{}, {.by = {search::Group::type}});
                if (!page || !report || page->as_of < last) {
                    ++problems;
                    return;
                }
                last = page->as_of;
                // What a page shows is what its update left: every record
                // registered below its as_of, none above.
                for (const auto& r : page->rows) {
                    if (r.registered_index >= page->as_of) {
                        ++problems;
                    }
                }
                std::uint64_t counted = 0;
                for (const auto& row : report->rows) {
                    counted += row.count;
                }
                if (counted > report->as_of) {
                    ++problems;
                }
            }
        });
    }
    for (int round = 0; round < 10; ++round) {
        add(3);
        REQUIRE(index.update());
    }
    done = true;
    readers.clear();
    CHECK(problems == 0);
    const auto all = index.records({}, {.limit = 1000});
    REQUIRE(all);
    CHECK(all->rows.size() == 35);
    CHECK(all->as_of == w.ledger().size());
}
