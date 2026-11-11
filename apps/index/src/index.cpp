// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <variant>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/contracts.hpp>
#include <kanhe/core/protocol/id_map.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/search/index.hpp>

#include "sqlite.hpp"

namespace kanhe::search {

namespace {

// The layout's version: an index of another is emptied and rebuilt.
constexpr std::int64_t layout = 3;

constexpr std::string_view tables = R"sql(
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value BLOB) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS records(
    pos INTEGER PRIMARY KEY,
    id BLOB NOT NULL,
    type TEXT NOT NULL,
    state TEXT NOT NULL,
    revoked INTEGER NOT NULL,
    registrant BLOB NOT NULL,
    registered_at INTEGER NOT NULL,
    supersedes BLOB,
    superseded_by BLOB,
    endorsements INTEGER NOT NULL,
    last_index INTEGER NOT NULL,
    last_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS record_meta(
    pos INTEGER NOT NULL,
    n INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    num INTEGER,
    PRIMARY KEY(pos, n)) WITHOUT ROWID;
CREATE VIRTUAL TABLE IF NOT EXISTS record_text USING fts5(text, tokenize='trigram', content='');
CREATE TABLE IF NOT EXISTS contracts(
    id BLOB PRIMARY KEY,
    name TEXT,
    retired INTEGER NOT NULL,
    deployed_index INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS instances(
    pos INTEGER PRIMARY KEY,
    id BLOB NOT NULL,
    contract BLOB NOT NULL,
    status TEXT,
    final INTEGER NOT NULL,
    created_index INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_index INTEGER NOT NULL,
    last_at INTEGER NOT NULL,
    calls INTEGER NOT NULL,
    open_requests INTEGER NOT NULL,
    parent BLOB,
    reference TEXT);
CREATE TABLE IF NOT EXISTS instance_parties(
    pos INTEGER NOT NULL,
    role TEXT NOT NULL,
    ledger BLOB NOT NULL,
    PRIMARY KEY(pos, role)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS instance_fields(
    pos INTEGER NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    num INTEGER,
    PRIMARY KEY(pos, name)) WITHOUT ROWID;
)sql";

/// The secondary indexes: what searches and reports read.
constexpr std::string_view indexes = R"sql(
CREATE INDEX IF NOT EXISTS records_id ON records(id);
CREATE INDEX IF NOT EXISTS instances_id ON instances(id);
CREATE INDEX IF NOT EXISTS records_type ON records(type, pos);
CREATE INDEX IF NOT EXISTS records_report ON records(type, state, revoked);
CREATE INDEX IF NOT EXISTS records_state ON records(state, pos);
CREATE INDEX IF NOT EXISTS records_registrant ON records(registrant, pos);
CREATE INDEX IF NOT EXISTS records_time ON records(registered_at, revoked, type, state);
CREATE INDEX IF NOT EXISTS record_meta_value ON record_meta(key, value);
CREATE INDEX IF NOT EXISTS record_meta_num ON record_meta(key, num) WHERE num IS NOT NULL;
CREATE INDEX IF NOT EXISTS contracts_name ON contracts(name);
CREATE INDEX IF NOT EXISTS instances_contract ON instances(contract, pos);
CREATE INDEX IF NOT EXISTS instances_report ON instances(contract, status);
CREATE INDEX IF NOT EXISTS instances_status ON instances(status, pos);
CREATE INDEX IF NOT EXISTS instances_created ON instances(created_at, contract, status);
CREATE INDEX IF NOT EXISTS instances_changed ON instances(last_at);
CREATE INDEX IF NOT EXISTS instances_reference ON instances(reference) WHERE reference IS NOT NULL;
CREATE INDEX IF NOT EXISTS instance_parties_ledger ON instance_parties(ledger, pos);
CREATE INDEX IF NOT EXISTS instance_fields_value ON instance_fields(name, value);
CREATE INDEX IF NOT EXISTS instance_fields_num ON instance_fields(name, num) WHERE num IS NOT NULL;
)sql";

/// The secondary indexes, dropped for a first build (made again at its
/// end: sorting once costs far less than inserting at random).
constexpr std::string_view drop_indexes = R"sql(
DROP INDEX IF EXISTS records_id;
DROP INDEX IF EXISTS instances_id;
DROP INDEX IF EXISTS records_type;
DROP INDEX IF EXISTS records_report;
DROP INDEX IF EXISTS records_state;
DROP INDEX IF EXISTS records_registrant;
DROP INDEX IF EXISTS records_time;
DROP INDEX IF EXISTS record_meta_value;
DROP INDEX IF EXISTS record_meta_num;
DROP INDEX IF EXISTS contracts_name;
DROP INDEX IF EXISTS instances_contract;
DROP INDEX IF EXISTS instances_report;
DROP INDEX IF EXISTS instances_status;
DROP INDEX IF EXISTS instances_created;
DROP INDEX IF EXISTS instances_changed;
DROP INDEX IF EXISTS instances_reference;
DROP INDEX IF EXISTS instance_parties_ledger;
DROP INDEX IF EXISTS instance_fields_value;
DROP INDEX IF EXISTS instance_fields_num;
)sql";

constexpr std::string_view drop = R"sql(
DROP TABLE IF EXISTS records;
DROP TABLE IF EXISTS record_meta;
DROP TABLE IF EXISTS record_text;
DROP TABLE IF EXISTS contracts;
DROP TABLE IF EXISTS instances;
DROP TABLE IF EXISTS instance_parties;
DROP TABLE IF EXISTS instance_fields;
DROP TABLE IF EXISTS meta;
)sql";

std::int64_t signed_of(std::uint64_t value) noexcept {
    return static_cast<std::int64_t>(std::min<std::uint64_t>(
        value, static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())));
}

std::optional<Id> id_of(const Bytes& bytes) {
    if (bytes.empty()) {
        return std::nullopt;
    }
    auto id = protocol::to_id(bytes);
    return id ? std::optional(*id) : std::nullopt;
}

std::string hex_of(ByteView bytes) {
    return to_hex(bytes);
}

/// A value as the index keeps it: text, and a number if it is an integer.
struct Scalar {
    std::string text;
    std::optional<std::int64_t> number;
};

/// A whole number written as text ("2026", "-15"), as forms and the
/// command line write numbers into metadata.
std::optional<std::int64_t> number_in(std::string_view text) {
    if (text.empty() || text.size() > 18) {
        return std::nullopt;
    }
    std::int64_t value = 0;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || ptr != text.data() + text.size() || text.front() == '+') {
        return std::nullopt;
    }
    return value;
}

std::optional<Scalar> scalar_of(const cbor::Value& value) {
    if (const std::string* t = value.as_text()) {
        return Scalar{*t, number_in(*t)};
    }
    if (const auto n = value.as_int64()) {
        return Scalar{std::to_string(*n), *n};
    }
    if (const auto u = value.as_uint64()) {
        return Scalar{std::to_string(*u), std::nullopt};
    }
    if (const auto b = value.as_bool()) {
        return Scalar{*b ? "true" : "false", std::nullopt};
    }
    if (const Bytes* b = value.as_bytes()) {
        return Scalar{hex_of(*b), std::nullopt};
    }
    return std::nullopt;
}

/// Characters, not bytes: the trigram tokenizer needs three.
std::size_t characters(std::string_view text) {
    return static_cast<std::size_t>(std::ranges::count_if(
        text, [](char c) { return (static_cast<unsigned char>(c) & 0xC0) != 0x80; }));
}

/// A query's text as one FTS5 phrase (control characters left out: they
/// are no part of a word, and a NUL would end the query).
std::string phrase(std::string_view text) {
    std::string out = "\"";
    for (const char c : text) {
        if (static_cast<unsigned char>(c) < 0x20) {
            continue;
        }
        out += c;
        if (c == '"') {
            out += '"';
        }
    }
    return out + "\"";
}

/// A query's parts and the values they bind, in order.
struct Query {
    std::string where;
    std::vector<std::variant<std::int64_t, std::string, Bytes>> values;

    void add(std::string_view condition) {
        where += where.empty() ? " WHERE " : " AND ";
        where += condition;
    }
    void bind(std::int64_t v) { values.emplace_back(v); }
    void bind(std::string v) { values.emplace_back(std::move(v)); }
    void bind(ByteView v) { values.emplace_back(Bytes(v.begin(), v.end())); }

    void apply(sql::Statement& statement, int from = 1) const {
        int at = from;
        for (const auto& v : values) {
            std::visit(
                [&](const auto& value) {
                    using T = std::decay_t<decltype(value)>;
                    if constexpr (std::is_same_v<T, Bytes>) {
                        statement.bind(at, ByteView(value));
                    } else if constexpr (std::is_same_v<T, std::string>) {
                        statement.bind(at, std::string_view(value));
                    } else {
                        statement.bind(at, value);
                    }
                },
                v);
            ++at;
        }
    }
};

void record_conditions(const RecordFilter& f, Query& q) {
    if (f.type) {
        q.add("r.type = ?");
        q.bind(*f.type);
    }
    if (f.state) {
        q.add("r.state = ?");
        q.bind(*f.state);
    }
    if (f.registrant) {
        q.add("r.registrant = ?");
        q.bind(f.registrant->bytes());
    }
    if (f.since) {
        q.add("r.registered_at >= ?");
        q.bind(signed_of(*f.since));
    }
    if (f.until) {
        q.add("r.registered_at < ?");
        q.bind(signed_of(*f.until));
    }
    if (f.current) {
        q.add("r.superseded_by IS NULL");
    }
    if (f.revoked == RecordFilter::Revoked::no) {
        q.add("r.revoked = 0");
    } else if (f.revoked == RecordFilter::Revoked::yes) {
        q.add("r.revoked = 1");
    }
    for (const RecordFilter::Metadata& m : f.metadata) {
        if (m.equals) {
            q.add("EXISTS (SELECT 1 FROM record_meta m WHERE m.pos = r.pos AND m.key = ? AND "
                  "m.value = ?)");
            q.bind(m.key);
            q.bind(*m.equals);
        }
        if (m.at_least || m.at_most) {
            q.add("EXISTS (SELECT 1 FROM record_meta m WHERE m.pos = r.pos AND m.key = ? AND "
                  "m.num IS NOT NULL AND m.num >= ? AND m.num <= ?)");
            q.bind(m.key);
            q.bind(m.at_least.value_or(std::numeric_limits<std::int64_t>::min()));
            q.bind(m.at_most.value_or(std::numeric_limits<std::int64_t>::max()));
        }
    }
    if (f.text && !f.text->empty()) {
        if (characters(*f.text) >= 3) {
            q.add("r.pos IN (SELECT rowid FROM record_text WHERE record_text MATCH ?)");
            q.bind(phrase(*f.text));
        } else {
            // Shorter than the trigram tokenizer reads (a two-character
            // name): a scan of the metadata's values.
            q.add("EXISTS (SELECT 1 FROM record_meta m WHERE m.pos = r.pos AND "
                  "instr(lower(m.value), lower(?)) > 0)");
            q.bind(*f.text);
        }
    }
}

void instance_conditions(const InstanceFilter& f, Query& q) {
    if (f.contract) {
        q.add("i.contract = ?");
        q.bind(f.contract->bytes());
    }
    if (f.contract_name) {
        q.add("i.contract IN (SELECT id FROM contracts WHERE name = ?)");
        q.bind(*f.contract_name);
    }
    if (f.status) {
        q.add("i.status = ?");
        q.bind(*f.status);
    }
    if (f.final) {
        q.add("i.final = ?");
        q.bind(std::int64_t{*f.final ? 1 : 0});
    }
    if (f.party) {
        q.add("EXISTS (SELECT 1 FROM instance_parties p WHERE p.pos = i.pos AND p.ledger = ?)");
        q.bind(f.party->bytes());
    }
    if (f.since) {
        q.add("i.created_at >= ?");
        q.bind(signed_of(*f.since));
    }
    if (f.until) {
        q.add("i.created_at < ?");
        q.bind(signed_of(*f.until));
    }
    if (f.changed_since) {
        q.add("i.last_at >= ?");
        q.bind(signed_of(*f.changed_since));
    }
    if (f.reference) {
        q.add("i.reference = ?");
        q.bind(*f.reference);
    }
    for (const InstanceFilter::Field& field : f.fields) {
        if (field.equals) {
            q.add("EXISTS (SELECT 1 FROM instance_fields f WHERE f.pos = i.pos AND f.name = ? "
                  "AND f.value = ?)");
            q.bind(field.name);
            q.bind(*field.equals);
        }
        if (field.at_least || field.at_most) {
            q.add("EXISTS (SELECT 1 FROM instance_fields f WHERE f.pos = i.pos AND f.name = ? "
                  "AND f.num IS NOT NULL AND f.num >= ? AND f.num <= ?)");
            q.bind(field.name);
            q.bind(field.at_least.value_or(std::numeric_limits<std::int64_t>::min()));
            q.bind(field.at_most.value_or(std::numeric_limits<std::int64_t>::max()));
        }
    }
}

/// The page's cursor: the position the last page ended at.
Result<std::optional<std::int64_t>> cursor_of(const PageRequest& page) {
    if (!page.cursor || page.cursor->empty()) {
        return std::optional<std::int64_t>{};
    }
    const std::string& c = *page.cursor;
    if (c.size() < 2 || c.size() > 19 || c.front() != 'p' ||
        !std::ranges::all_of(c.substr(1), [](char d) { return d >= '0' && d <= '9'; })) {
        return fail(Errc::invalid_argument, "the cursor is not one this index gave");
    }
    return std::optional<std::int64_t>(std::stoll(c.substr(1)));
}

Status check_limit(const PageRequest& page) {
    if (page.limit == 0 || page.limit > max_page) {
        return fail(Errc::invalid_argument, "a page holds 1 to 1,000 items");
    }
    return {};
}

/// A report's group: what rows are grouped by (`inner`, for `?` a time's
/// offset in seconds), and how a group's key is written (`outer`, `@` for
/// the grouped value).
struct Key {
    std::string inner;
    std::string outer = "@";
};

/// Times bucketed in a fixed offset: days and weeks as whole numbers (the
/// day since 1970; weeks from Monday, since 1970-01-01 was a Thursday), so
/// that rows are grouped by arithmetic and each group's date written once.
Key bucket(Group g, std::string_view column) {
    const std::string days = "((" + std::string(column) + " / 1000 + ?) / 86400)";
    switch (g) {
    case Group::day:
        return {days, "date(@ * 86400, 'unixepoch')"};
    case Group::week:
        return {"((" + days + " + 3) / 7)", "date((@ * 7 - 3) * 86400, 'unixepoch')"};
    case Group::month:
        return {"strftime('%Y-%m', " + std::string(column) + " / 1000 + ?, 'unixepoch')", "@"};
    default:
        return {};
    }
}

bool is_time(Group g) {
    return g == Group::day || g == Group::week || g == Group::month;
}

/// What the writer gathered for one object, read from the state.
struct RecordWrite {
    std::int64_t pos = 0;
    Bytes id;
    std::string type;
    std::string state;
    bool revoked = false;
    Bytes registrant;
    std::uint64_t registered_index = 0;
    std::optional<Bytes> supersedes;
    std::optional<Bytes> superseded_by;
    std::uint64_t endorsements = 0;
    std::uint64_t last_index = 0;
};

struct InstanceWrite {
    std::int64_t pos = 0;
    Bytes id;
    Bytes contract;
    std::optional<std::string> status;
    bool final = false;
    std::uint64_t created_index = 0;
    std::uint64_t last_index = 0;
    std::uint64_t calls = 0;
    std::uint64_t open_requests = 0;
    std::optional<Bytes> parent;
    std::vector<std::pair<std::string, Bytes>> parties;
    std::vector<std::pair<std::string, Scalar>> fields;
};

struct ContractWrite {
    Bytes id;
    std::optional<std::string> name;
    bool retired = false;
    std::uint64_t deployed_index = 0;
};

std::int64_t instance_pos(std::uint64_t created_by, std::uint32_t position) {
    // At most max_contract_children (16) children a call: 32 positions.
    return signed_of(created_by * 32 + position);
}

} // namespace

std::optional<Group> group_from(std::string_view name) noexcept {
    for (const Group g : {Group::type, Group::state, Group::registrant, Group::contract, Group::day,
                          Group::week, Group::month}) {
        if (search::name(g) == name) {
            return g;
        }
    }
    return std::nullopt;
}

std::string_view name(Group group) noexcept {
    switch (group) {
    case Group::type:
        return "type";
    case Group::state:
        return "state";
    case Group::registrant:
        return "registrant";
    case Group::contract:
        return "contract";
    case Group::day:
        return "day";
    case Group::week:
        return "week";
    case Group::month:
        return "month";
    }
    return {};
}

struct Index::Impl {
    const ledger::Ledger& ledger;
    std::filesystem::path file;
    /// The writer's connection, under `mutex`.
    sql::Database db;
    mutable std::mutex mutex;
    std::atomic<std::uint64_t> indexed = 0;
    /// A first build is under way: the secondary indexes are dropped until
    /// it reaches the log's end.
    bool bulk = false;
    std::uint64_t bulk_from = Index::bulk_from;

    /// Readers' connections, idle: searches and reports run on them, side
    /// by side and beside the writer (WAL).
    mutable std::mutex pool_mutex;
    mutable std::vector<sql::Database> idle;

    Impl(const ledger::Ledger& l, std::filesystem::path f, sql::Database d)
        : ledger(l), file(std::move(f)), db(std::move(d)) {}

    /// A reader's connection for one query, back in the pool afterwards, in
    /// a read transaction: the rows and `as_of` are of one moment.
    class Lease {
    public:
        Lease(const Impl& impl, sql::Database db) : impl_(impl), db_(std::move(db)) {}
        Lease(Lease&& other) noexcept
            : impl_(other.impl_), db_(std::move(other.db_)),
              open_(std::exchange(other.open_, false)) {}
        Lease& operator=(Lease&&) = delete;
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        ~Lease() {
            if (!db_.valid()) {
                return;
            }
            // A connection left in a transaction is not reused.
            if (open_ && !db_.exec("COMMIT") && !db_.exec("ROLLBACK")) {
                return;
            }
            const std::lock_guard lock(impl_.pool_mutex);
            if (impl_.idle.size() < 16) {
                impl_.idle.push_back(std::move(db_));
            }
        }
        [[nodiscard]] sql::Database& db() { return db_; }
        /// Begins the read transaction and answers the log size it sees.
        Result<std::uint64_t> begin() {
            SEARCH_CHECK(db_.exec("BEGIN"));
            open_ = true;
            SEARCH_TRY(sql::Statement s,
                       db_.prepare("SELECT value FROM meta WHERE key = 'indexed'"));
            SEARCH_TRY(const bool row, s.step());
            return row ? static_cast<std::uint64_t>(s.integer(0)) : 0;
        }

    private:
        const Impl& impl_;
        sql::Database db_;
        bool open_ = false;
    };

    Result<Lease> lease() const {
        {
            const std::lock_guard lock(pool_mutex);
            if (!idle.empty()) {
                sql::Database reused = std::move(idle.back());
                idle.pop_back();
                return Lease(*this, std::move(reused));
            }
        }
        SEARCH_TRY(sql::Database fresh, sql::Database::open(file, true));
        SEARCH_CHECK(fresh.exec("PRAGMA cache_size = -16384; PRAGMA temp_store = MEMORY;"));
        return Lease(*this, std::move(fresh));
    }

    Status set_meta(std::string_view key, std::int64_t value) {
        SEARCH_TRY(sql::Statement s,
                   db.prepare("INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO "
                              "UPDATE SET value = excluded.value"));
        s.bind(1, key).bind(2, value);
        return s.run();
    }

    Status set_meta(std::string_view key, ByteView value) {
        SEARCH_TRY(sql::Statement s,
                   db.prepare("INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO "
                              "UPDATE SET value = excluded.value"));
        s.bind(1, key).bind(2, value);
        return s.run();
    }

    /// Empty tables of the current layout, for this ledger.
    Status reset() {
        SEARCH_CHECK(db.exec(drop));
        SEARCH_CHECK(db.exec(tables));
        SEARCH_CHECK(db.exec(indexes));
        bulk = false;
        SEARCH_CHECK(set_meta("layout", layout));
        SEARCH_CHECK(set_meta("ledger", ledger.id().bytes()));
        SEARCH_CHECK(set_meta("indexed", std::int64_t{0}));
        indexed = 0;
        return {};
    }

    /// The log entry's time, from the batch or the log.
    Result<Timestamp> time_of(std::uint64_t index,
                              std::map<std::uint64_t, Timestamp>& times) const {
        if (const auto it = times.find(index); it != times.end()) {
            return it->second;
        }
        SEARCH_TRY(const Bytes bytes, ledger.entry(index));
        SEARCH_TRY(const protocol::LogEntry entry, protocol::decode_log_entry(bytes));
        times.emplace(index, entry.registered_at);
        return entry.registered_at;
    }

    Result<std::uint64_t> step(std::uint64_t end);
};

Result<std::uint64_t> Index::Impl::step(std::uint64_t end) {
    const crypto::Provider& provider = ledger.provider();
    const crypto::HashAlg hash = ledger.hash();
    std::map<std::uint64_t, Timestamp> times;
    std::set<protocol::IdKey> records;
    std::set<protocol::IdKey> instances;
    std::set<protocol::IdKey> contracts;
    // Registrations in this batch, for their metadata; creations and calls
    // that may have made children, for their references.
    std::map<protocol::IdKey, std::optional<cbor::Value>> registered;
    struct Creation {
        Id call;
        std::optional<std::string> reference;
        bool creates = false;
    };
    std::vector<Creation> calls;

    // Reading and parsing the entries, on several threads for a large
    // batch: each part in order, merged in order.
    struct Part {
        std::vector<std::pair<std::uint64_t, Timestamp>> times;
        std::vector<protocol::IdKey> records;
        std::vector<protocol::IdKey> instances;
        std::vector<protocol::IdKey> contracts;
        std::vector<std::pair<protocol::IdKey, std::optional<cbor::Value>>> registered;
        std::vector<Creation> calls;
        Status status;
    };
    auto parse = [&](std::uint64_t from, std::uint64_t to, Part& part) -> Status {
        for (std::uint64_t index = from; index < to; ++index) {
            SEARCH_TRY(const Bytes bytes, ledger.entry(index));
            SEARCH_TRY(protocol::LogEntry entry, protocol::decode_log_entry(bytes));
            part.times.emplace_back(index, entry.registered_at);
            if (entry.is_state_commitment()) {
                continue;
            }
            SEARCH_TRY(const protocol::SignedStatement s,
                       protocol::parse_statement(provider, entry.statement, hash));
            std::visit(
                [&](const auto& body) {
                    using Body = std::decay_t<decltype(body)>;
                    if constexpr (std::is_same_v<Body, protocol::RecordRegisterBody>) {
                        part.records.push_back(protocol::key_of(s.id));
                        part.registered.emplace_back(protocol::key_of(s.id), body.metadata);
                        if (body.supersedes) {
                            part.records.push_back(protocol::key_of(*body.supersedes));
                        }
                    } else if constexpr (std::is_same_v<Body, protocol::RecordEndorseBody> ||
                                         std::is_same_v<Body, protocol::RecordTransitionBody> ||
                                         std::is_same_v<Body, protocol::RecordRevokeBody>) {
                        part.records.push_back(protocol::key_of(body.record));
                    } else if constexpr (std::is_same_v<Body, protocol::ContractDeployBody>) {
                        part.contracts.push_back(protocol::key_of(s.id));
                    } else if constexpr (std::is_same_v<Body, protocol::ContractRetireBody>) {
                        part.contracts.push_back(protocol::key_of(body.contract));
                    } else if constexpr (std::is_same_v<Body, protocol::ContractCallBody>) {
                        if (body.instance) {
                            part.instances.push_back(protocol::key_of(*body.instance));
                        }
                        part.calls.push_back({s.id, body.reference, !body.instance});
                    }
                },
                s.statement.body);
        }
        return {};
    };
    const std::uint64_t entries = end - indexed;
    const std::uint64_t threads =
        entries < 4096 ? 1 : std::clamp<std::uint64_t>(std::thread::hardware_concurrency(), 1, 8);
    std::vector<Part> parts(static_cast<std::size_t>(threads));
    {
        const std::uint64_t chunk = (entries + threads - 1) / threads;
        std::vector<std::jthread> workers;
        for (std::uint64_t t = 1; t < threads; ++t) {
            const std::uint64_t from = std::min(end, indexed + t * chunk);
            const std::uint64_t to = std::min(end, from + chunk);
            workers.emplace_back([&, t, from, to] {
                parts[static_cast<std::size_t>(t)].status =
                    parse(from, to, parts[static_cast<std::size_t>(t)]);
            });
        }
        parts[0].status = parse(indexed, std::min(end, indexed + chunk), parts[0]);
    }
    for (Part& part : parts) {
        SEARCH_CHECK(part.status);
        for (const auto& [index, at] : part.times) {
            times.emplace(index, at);
        }
        records.insert(part.records.begin(), part.records.end());
        instances.insert(part.instances.begin(), part.instances.end());
        contracts.insert(part.contracts.begin(), part.contracts.end());
        for (auto& [key, metadata] : part.registered) {
            registered.emplace(key, std::move(metadata));
        }
        for (Creation& c : part.calls) {
            calls.push_back(std::move(c));
        }
    }
    // What the state holds now for each object touched, copied out so that
    // the writer is held up for no longer than that.
    std::vector<RecordWrite> record_rows;
    std::vector<InstanceWrite> instance_rows;
    std::vector<ContractWrite> contract_rows;
    std::map<protocol::IdKey, std::optional<std::string>> references;
    Status problem;
    ledger.read_state([&](const protocol::LedgerState& state) {
        // The instances the calls created: a creation's own, and children.
        for (const Creation& c : calls) {
            if (c.creates && state.instance(c.call) != nullptr) {
                instances.insert(protocol::key_of(c.call));
                references.emplace(protocol::key_of(c.call), c.reference);
            }
            for (std::size_t n = 0; n < protocol::max_contract_children; ++n) {
                auto child = protocol::child_instance_id(provider, hash, c.call, n);
                if (!child) {
                    problem = std::unexpected(child.error());
                    return;
                }
                if (state.instance(*child) == nullptr) {
                    break;
                }
                instances.insert(protocol::key_of(*child));
                references.emplace(protocol::key_of(*child), c.reference);
            }
        }
        auto last_below = [end](const protocol::IndexList& history, std::uint64_t first) {
            std::uint64_t last = first;
            std::uint64_t count = 0;
            for (const std::uint64_t i : history) {
                if (i < end) {
                    last = std::max(last, i);
                    ++count;
                }
            }
            return std::pair(last, count);
        };
        for (const protocol::IdKey& key : records) {
            const protocol::RecordState* r = state.record(protocol::CompactId(key).id());
            if (r == nullptr) {
                continue;
            }
            RecordWrite w;
            w.pos = signed_of(r->registered_at_index);
            w.id = Bytes(r->id.bytes().begin(), r->id.bytes().end());
            w.type = r->record_type;
            w.state = r->state;
            w.revoked = r->revoked;
            w.registrant = Bytes(r->registrant.bytes().begin(), r->registrant.bytes().end());
            w.registered_index = r->registered_at_index;
            if (r->supersedes) {
                w.supersedes = Bytes(r->supersedes->bytes().begin(), r->supersedes->bytes().end());
            }
            if (r->superseded_by && r->superseded_at_index < end) {
                w.superseded_by =
                    Bytes(r->superseded_by->bytes().begin(), r->superseded_by->bytes().end());
            }
            w.endorsements = static_cast<std::uint64_t>(std::ranges::count_if(
                r->endorsements, [end](const protocol::Endorsement& e) { return e.index < end; }));
            w.last_index = last_below(r->history, r->registered_at_index).first;
            record_rows.push_back(std::move(w));
        }
        for (const protocol::IdKey& key : instances) {
            const protocol::InstanceState* i = state.instance(protocol::CompactId(key).id());
            if (i == nullptr || i->created_by >= end) {
                continue;
            }
            InstanceWrite w;
            w.pos = instance_pos(i->created_by, i->position);
            w.id = Bytes(i->id.bytes().begin(), i->id.bytes().end());
            w.contract = Bytes(i->contract.bytes().begin(), i->contract.bytes().end());
            w.status = i->status;
            w.final = i->final;
            w.created_index = i->created_by;
            const auto [last, count] = last_below(i->history, i->created_by);
            w.last_index = last;
            w.calls = count;
            w.open_requests = i->open_requests.size();
            if (i->parent) {
                w.parent = Bytes(i->parent->bytes().begin(), i->parent->bytes().end());
            }
            for (const auto& [role, ledger_id] : i->parties) {
                w.parties.emplace_back(role,
                                       Bytes(ledger_id.bytes().begin(), ledger_id.bytes().end()));
            }
            // A Bo contract's state: {"state": NAME, "fields": {NAME: VALUE}}.
            const cbor::Value value = i->state.value();
            if (const cbor::Value* fields = value.find(cbor::Value::text("fields"))) {
                if (const cbor::Map* map = fields->as_map()) {
                    for (const cbor::MapEntry& e : *map) {
                        const std::string* name = e.key.as_text();
                        if (name == nullptr) {
                            continue;
                        }
                        if (auto scalar = scalar_of(e.value)) {
                            w.fields.emplace_back(*name, std::move(*scalar));
                        }
                    }
                }
            }
            instance_rows.push_back(std::move(w));
        }
        for (const protocol::IdKey& key : contracts) {
            const protocol::ContractState* c = state.contract(protocol::CompactId(key).id());
            if (c == nullptr) {
                continue;
            }
            contract_rows.push_back(
                {Bytes(c->id.bytes().begin(), c->id.bytes().end()), c->name,
                 c->retired && c->retired_at_index && *c->retired_at_index < end,
                 c->deployed_at_index});
        }
    });
    if (!problem) {
        return std::unexpected(problem.error());
    }
    // In log order: appends to every table, and the text index takes rows
    // in rising order only (out of order, it writes a segment each time).
    std::ranges::sort(record_rows, {}, &RecordWrite::pos);
    std::ranges::sort(instance_rows, {}, &InstanceWrite::pos);

    SEARCH_CHECK(db.exec("BEGIN IMMEDIATE"));
    auto write = [&]() -> Status {
        SEARCH_TRY(sql::Statement record,
                   db.prepare("INSERT INTO records(pos, id, type, state, revoked, registrant, "
                              "registered_at, supersedes, superseded_by, endorsements, "
                              "last_index, last_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                              "ON CONFLICT(pos) DO UPDATE SET state = excluded.state, revoked = "
                              "excluded.revoked, superseded_by = excluded.superseded_by, "
                              "endorsements = excluded.endorsements, last_index = "
                              "excluded.last_index, last_at = excluded.last_at"));
        SEARCH_TRY(sql::Statement meta,
                   db.prepare("INSERT OR REPLACE INTO record_meta(pos, n, key, value, num) "
                              "VALUES(?, ?, ?, ?, ?)"));
        SEARCH_TRY(sql::Statement text,
                   db.prepare("INSERT INTO record_text(rowid, text) VALUES(?, ?)"));
        for (const RecordWrite& w : record_rows) {
            SEARCH_TRY(const Timestamp registered_at, time_of(w.registered_index, times));
            SEARCH_TRY(const Timestamp last_at, time_of(w.last_index, times));
            record.bind(1, w.pos).bind(2, ByteView(w.id)).bind(3, w.type).bind(4, w.state);
            record.bind(5, std::int64_t{w.revoked ? 1 : 0}).bind(6, ByteView(w.registrant));
            record.bind(7, signed_of(registered_at));
            w.supersedes ? record.bind(8, ByteView(*w.supersedes)) : record.bind_null(8);
            w.superseded_by ? record.bind(9, ByteView(*w.superseded_by)) : record.bind_null(9);
            record.bind(10, signed_of(w.endorsements)).bind(11, signed_of(w.last_index));
            record.bind(12, signed_of(last_at));
            SEARCH_CHECK(record.run());
            // Metadata never changes: written with the registration.
            const auto found = registered.find(protocol::CompactId(*protocol::to_id(w.id)).key());
            if (found == registered.end() || !found->second) {
                continue;
            }
            const cbor::Map* map = found->second->as_map();
            if (map == nullptr) {
                continue;
            }
            std::string all;
            std::int64_t n = 0;
            for (const cbor::MapEntry& e : *map) {
                const std::string* key = e.key.as_text();
                const auto scalar = scalar_of(e.value);
                if (key == nullptr || !scalar) {
                    continue;
                }
                meta.bind(1, w.pos).bind(2, n++).bind(3, *key).bind(4, scalar->text);
                scalar->number ? meta.bind(5, *scalar->number) : meta.bind_null(5);
                SEARCH_CHECK(meta.run());
                all += scalar->text + "\n";
            }
            if (!all.empty()) {
                text.bind(1, w.pos).bind(2, all);
                SEARCH_CHECK(text.run());
            }
        }

        SEARCH_TRY(sql::Statement contract,
                   db.prepare("INSERT INTO contracts(id, name, retired, deployed_index) "
                              "VALUES(?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET retired = "
                              "excluded.retired"));
        for (const ContractWrite& c : contract_rows) {
            contract.bind(1, ByteView(c.id));
            c.name ? contract.bind(2, *c.name) : contract.bind_null(2);
            contract.bind(3, std::int64_t{c.retired ? 1 : 0}).bind(4, signed_of(c.deployed_index));
            SEARCH_CHECK(contract.run());
        }

        SEARCH_TRY(sql::Statement instance,
                   db.prepare("INSERT INTO instances(pos, id, contract, status, final, "
                              "created_index, created_at, last_index, last_at, calls, "
                              "open_requests, parent, reference) VALUES(?, ?, ?, ?, ?, ?, ?, ?, "
                              "?, ?, ?, ?, ?) ON CONFLICT(pos) DO UPDATE SET status = "
                              "excluded.status, final = excluded.final, last_index = "
                              "excluded.last_index, last_at = excluded.last_at, calls = "
                              "excluded.calls, open_requests = excluded.open_requests"));
        SEARCH_TRY(sql::Statement clear_parties,
                   db.prepare("DELETE FROM instance_parties WHERE pos = ?"));
        SEARCH_TRY(sql::Statement party,
                   db.prepare("INSERT OR REPLACE INTO instance_parties(pos, role, ledger) "
                              "VALUES(?, ?, ?)"));
        SEARCH_TRY(sql::Statement clear_fields,
                   db.prepare("DELETE FROM instance_fields WHERE pos = ?"));
        SEARCH_TRY(sql::Statement field,
                   db.prepare("INSERT OR REPLACE INTO instance_fields(pos, name, value, num) "
                              "VALUES(?, ?, ?, ?)"));
        for (const InstanceWrite& w : instance_rows) {
            SEARCH_TRY(const Timestamp created_at, time_of(w.created_index, times));
            SEARCH_TRY(const Timestamp last_at, time_of(w.last_index, times));
            instance.bind(1, w.pos).bind(2, ByteView(w.id)).bind(3, ByteView(w.contract));
            w.status ? instance.bind(4, *w.status) : instance.bind_null(4);
            instance.bind(5, std::int64_t{w.final ? 1 : 0}).bind(6, signed_of(w.created_index));
            instance.bind(7, signed_of(created_at)).bind(8, signed_of(w.last_index));
            instance.bind(9, signed_of(last_at)).bind(10, signed_of(w.calls));
            instance.bind(11, signed_of(w.open_requests));
            w.parent ? instance.bind(12, ByteView(*w.parent)) : instance.bind_null(12);
            const auto ref = references.find(protocol::CompactId(*protocol::to_id(w.id)).key());
            ref != references.end() && ref->second ? instance.bind(13, *ref->second)
                                                   : instance.bind_null(13);
            SEARCH_CHECK(instance.run());
            clear_parties.bind(1, w.pos);
            SEARCH_CHECK(clear_parties.run());
            for (const auto& [role, ledger_id] : w.parties) {
                party.bind(1, w.pos).bind(2, role).bind(3, ByteView(ledger_id));
                SEARCH_CHECK(party.run());
            }
            clear_fields.bind(1, w.pos);
            SEARCH_CHECK(clear_fields.run());
            for (const auto& [name, value] : w.fields) {
                field.bind(1, w.pos).bind(2, name).bind(3, value.text);
                value.number ? field.bind(4, *value.number) : field.bind_null(4);
                SEARCH_CHECK(field.run());
            }
        }
        return set_meta("indexed", signed_of(end));
    };
    if (auto s = write(); !s) {
        static_cast<void>(db.exec("ROLLBACK"));
        return std::unexpected(s.error());
    }
    SEARCH_CHECK(db.exec("COMMIT"));
    indexed = end;
    return end;
}

Index::Index(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Index::~Index() = default;

std::filesystem::path Index::file_for(const std::filesystem::path& ledger) {
    return ledger / "search.sqlite";
}

Result<std::unique_ptr<Index>> Index::open(const ledger::Ledger& ledger, std::filesystem::path file,
                                           std::uint64_t bulk) {
    SEARCH_TRY(sql::Database db, sql::Database::open(file));
    // A cache big enough that ids' random inserts mostly hit memory.
    SEARCH_CHECK(db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; "
                         "PRAGMA cache_size = -65536; "
                         "PRAGMA temp_store = MEMORY;"));
    auto impl = std::make_unique<Impl>(ledger, std::move(file), std::move(db));
    impl->bulk_from = bulk;
    SEARCH_CHECK(impl->db.exec(tables));
    // A first build cut short leaves its indexes dropped: made again here.
    SEARCH_CHECK(impl->db.exec(indexes));
    // The layout and ledger it is for; anything else starts again.
    std::optional<std::int64_t> found_layout;
    std::optional<Bytes> found_ledger;
    std::optional<std::int64_t> indexed;
    {
        SEARCH_TRY(sql::Statement read, impl->db.prepare("SELECT key, value FROM meta"));
        for (;;) {
            SEARCH_TRY(const bool row, read.step());
            if (!row) {
                break;
            }
            const std::string key = read.text(0);
            if (key == "layout") {
                found_layout = read.integer(1);
            } else if (key == "ledger") {
                found_ledger = read.blob(1);
            } else if (key == "indexed") {
                indexed = read.integer(1);
            }
        }
    }
    const bool ours = found_layout == layout && found_ledger &&
                      std::ranges::equal(*found_ledger, ledger.id().bytes()) && indexed &&
                      *indexed >= 0 && static_cast<std::uint64_t>(*indexed) <= ledger.size();
    if (!ours) {
        SEARCH_CHECK(impl->reset());
    } else {
        impl->indexed = static_cast<std::uint64_t>(*indexed);
    }
    return std::unique_ptr<Index>(new Index(std::move(impl)));
}

Result<std::uint64_t> Index::update(std::chrono::milliseconds budget, std::size_t batch) {
    const std::lock_guard lock(impl_->mutex);
    const auto deadline = std::chrono::steady_clock::now() + budget;
    batch = std::max<std::size_t>(batch, 1);
    // Far behind (a first build, or a long way to catch up): rows first,
    // the secondary indexes made once at the end, in large batches.
    if (!impl_->bulk && impl_->ledger.size() > impl_->indexed + impl_->bulk_from) {
        SEARCH_CHECK(impl_->db.exec(drop_indexes));
        impl_->bulk = true;
    }
    for (;;) {
        const std::uint64_t size = impl_->ledger.size();
        if (impl_->indexed >= size) {
            if (impl_->bulk) {
                SEARCH_CHECK(impl_->db.exec(indexes));
                impl_->bulk = false;
            }
            return impl_->indexed.load();
        }
        const std::uint64_t step_batch =
            impl_->bulk ? std::max<std::uint64_t>(batch, 65'536) : batch;
        const std::uint64_t end = std::min<std::uint64_t>(size, impl_->indexed + step_batch);
        SEARCH_TRY(const std::uint64_t reached, impl_->step(end));
        if (reached >= size) {
            continue; // to make the indexes, if this was a first build
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            return reached;
        }
    }
}

Status Index::clear() {
    const std::lock_guard lock(impl_->mutex);
    return impl_->reset();
}

namespace {

constexpr std::string_view record_columns =
    "SELECT r.pos, r.id, r.type, r.state, r.revoked, r.registrant, r.registered_at, "
    "r.supersedes, r.superseded_by, r.endorsements, r.last_index, r.last_at FROM records r";

/// The row `s` is on (record_columns), and its metadata through `meta`.
Result<RecordRow> read_record(sql::Statement& s, sql::Statement& meta) {
    RecordRow r;
    const std::int64_t pos = s.integer(0);
    r.id = *id_of(s.blob(1));
    r.type = s.text(2);
    r.state = s.text(3);
    r.revoked = s.integer(4) != 0;
    r.registrant = *id_of(s.blob(5));
    r.registered_index = static_cast<std::uint64_t>(pos);
    r.registered_at = static_cast<Timestamp>(s.integer(6));
    r.supersedes = s.is_null(7) ? std::nullopt : id_of(s.blob(7));
    r.superseded_by = s.is_null(8) ? std::nullopt : id_of(s.blob(8));
    r.endorsements = static_cast<std::uint64_t>(s.integer(9));
    r.last_index = static_cast<std::uint64_t>(s.integer(10));
    r.last_at = static_cast<Timestamp>(s.integer(11));
    meta.bind(1, pos);
    for (;;) {
        SEARCH_TRY(const bool m, meta.step());
        if (!m) {
            break;
        }
        r.metadata.emplace_back(meta.text(0), meta.text(1));
    }
    meta.reset();
    return r;
}

} // namespace

std::uint64_t Index::as_of() const {
    return impl_->indexed.load();
}

Result<std::optional<RecordRow>> Index::record(const Id& id) const {
    SEARCH_TRY(auto lease, impl_->lease());
    SEARCH_TRY(const std::uint64_t seen, lease.begin());
    static_cast<void>(seen);
    SEARCH_TRY(sql::Statement s,
               lease.db().prepare(std::string(record_columns) + " WHERE r.id = ?"));
    s.bind(1, id.bytes());
    SEARCH_TRY(sql::Statement meta,
               lease.db().prepare("SELECT key, value FROM record_meta WHERE pos = ? ORDER BY n"));
    SEARCH_TRY(const bool row, s.step());
    if (!row) {
        return std::optional<RecordRow>{};
    }
    SEARCH_TRY(RecordRow r, read_record(s, meta));
    return std::optional<RecordRow>(std::move(r));
}

Result<Page<RecordRow>> Index::records(const RecordFilter& filter, const PageRequest& page) const {
    SEARCH_CHECK(check_limit(page));
    SEARCH_TRY(const auto cursor, cursor_of(page));
    SEARCH_TRY(auto lease, impl_->lease());
    SEARCH_TRY(const std::uint64_t seen, lease.begin());
    Query q;
    record_conditions(filter, q);
    if (cursor) {
        q.add(page.oldest_first ? "r.pos > ?" : "r.pos < ?");
        q.bind(*cursor);
    }
    const std::string sql = std::string(record_columns) + q.where + " ORDER BY r.pos " +
                            (page.oldest_first ? "ASC" : "DESC") + " LIMIT ?";
    SEARCH_TRY(sql::Statement s, lease.db().prepare(sql));
    q.apply(s);
    s.bind(static_cast<int>(q.values.size()) + 1, signed_of(page.limit + 1));
    SEARCH_TRY(sql::Statement meta,
               lease.db().prepare("SELECT key, value FROM record_meta WHERE pos = ? ORDER BY n"));
    Page<RecordRow> out;
    out.as_of = seen;
    for (;;) {
        SEARCH_TRY(const bool row, s.step());
        if (!row) {
            break;
        }
        if (out.rows.size() == page.limit) {
            out.next = "p" + std::to_string(out.rows.back().registered_index);
            break;
        }
        SEARCH_TRY(RecordRow r, read_record(s, meta));
        out.rows.push_back(std::move(r));
    }
    return out;
}

Result<Page<InstanceRow>> Index::instances(const InstanceFilter& filter,
                                           const PageRequest& page) const {
    SEARCH_CHECK(check_limit(page));
    SEARCH_TRY(const auto cursor, cursor_of(page));
    SEARCH_TRY(auto lease, impl_->lease());
    SEARCH_TRY(const std::uint64_t seen, lease.begin());
    Query q;
    instance_conditions(filter, q);
    if (cursor) {
        q.add(page.oldest_first ? "i.pos > ?" : "i.pos < ?");
        q.bind(*cursor);
    }
    const std::string sql =
        "SELECT i.pos, i.id, i.contract, c.name, i.status, i.final, i.created_index, "
        "i.created_at, i.last_index, i.last_at, i.calls, i.open_requests, i.parent, i.reference "
        "FROM instances i LEFT JOIN contracts c ON c.id = i.contract" +
        q.where + " ORDER BY i.pos " + (page.oldest_first ? "ASC" : "DESC") + " LIMIT ?";
    SEARCH_TRY(sql::Statement s, lease.db().prepare(sql));
    q.apply(s);
    s.bind(static_cast<int>(q.values.size()) + 1, signed_of(page.limit + 1));
    SEARCH_TRY(sql::Statement parties,
               lease.db().prepare("SELECT role, ledger FROM instance_parties WHERE pos = ? "
                                  "ORDER BY role"));
    SEARCH_TRY(sql::Statement fields,
               lease.db().prepare("SELECT name, value FROM instance_fields WHERE pos = ? "
                                  "ORDER BY name"));
    Page<InstanceRow> out;
    out.as_of = seen;
    std::int64_t last = 0;
    for (;;) {
        SEARCH_TRY(const bool row, s.step());
        if (!row) {
            break;
        }
        if (out.rows.size() == page.limit) {
            out.next = "p" + std::to_string(last);
            break;
        }
        InstanceRow r;
        last = s.integer(0);
        r.id = *id_of(s.blob(1));
        r.contract = *id_of(s.blob(2));
        r.contract_name = s.is_null(3) ? std::nullopt : std::optional(s.text(3));
        r.status = s.is_null(4) ? std::nullopt : std::optional(s.text(4));
        r.final = s.integer(5) != 0;
        r.created_index = static_cast<std::uint64_t>(s.integer(6));
        r.created_at = static_cast<Timestamp>(s.integer(7));
        r.last_index = static_cast<std::uint64_t>(s.integer(8));
        r.last_at = static_cast<Timestamp>(s.integer(9));
        r.calls = static_cast<std::uint64_t>(s.integer(10));
        r.open_requests = static_cast<std::uint64_t>(s.integer(11));
        r.parent = s.is_null(12) ? std::nullopt : id_of(s.blob(12));
        r.reference = s.is_null(13) ? std::nullopt : std::optional(s.text(13));
        parties.bind(1, last);
        for (;;) {
            SEARCH_TRY(const bool p, parties.step());
            if (!p) {
                break;
            }
            r.parties.emplace_back(parties.text(0), *id_of(parties.blob(1)));
        }
        parties.reset();
        fields.bind(1, last);
        for (;;) {
            SEARCH_TRY(const bool f, fields.step());
            if (!f) {
                break;
            }
            r.fields.emplace_back(fields.text(0), fields.text(1));
        }
        fields.reset();
        out.rows.push_back(std::move(r));
    }
    return out;
}

namespace {

Result<Report> run_report(sql::Database& db, std::uint64_t as_of, const ReportRequest& request,
                          std::string_view from, const std::vector<Key>& keys, const Query& where,
                          const std::vector<std::int64_t>& key_values, bool summed) {
    // Grouped inside, keys written outside: once a group, not once a row.
    std::string inner;
    std::string outer;
    std::string group;
    for (std::size_t n = 0; n < keys.size(); ++n) {
        const std::string k = "k" + std::to_string(n);
        inner += keys[n].inner + " AS " + k + ", ";
        std::string written = keys[n].outer;
        for (std::size_t at = written.find('@'); at != std::string::npos;
             at = written.find('@', at + k.size())) {
            written.replace(at, 1, k);
        }
        outer += written + ", ";
        group += (n == 0 ? "" : ", ") + k;
    }
    const bool by_time = std::ranges::any_of(request.by, is_time);
    const std::string sums = summed ? ", SUM(s.num) AS sm, MIN(s.num) AS mn, MAX(s.num) AS mx" : "";
    std::string sql =
        "SELECT " + inner + "COUNT(*) AS c" + sums + " " + std::string(from) + where.where;
    if (!keys.empty()) {
        sql = "SELECT " + outer + "c" + (summed ? ", sm, mn, mx" : "") + " FROM (" + sql +
              " GROUP BY " + group + ")" +
              (by_time ? " ORDER BY " + group : " ORDER BY c DESC, " + group);
    }
    sql += " LIMIT ?";
    SEARCH_TRY(sql::Statement s, db.prepare(sql));
    // The keys' values (time offsets) come first, then the sum's field, then
    // the conditions', then the limit.
    int at = 1;
    for (const std::int64_t v : key_values) {
        s.bind(at++, v);
    }
    if (summed) {
        s.bind(at++, std::string_view(*request.sum));
    }
    where.apply(s, at);
    at += static_cast<int>(where.values.size());
    s.bind(at, signed_of(max_groups + 1));
    Report out;
    out.by = request.by;
    out.as_of = as_of;
    const int columns = static_cast<int>(keys.size());
    for (;;) {
        SEARCH_TRY(const bool row, s.step());
        if (!row) {
            break;
        }
        if (out.rows.size() == max_groups) {
            out.truncated = true;
            break;
        }
        ReportRow r;
        for (int c = 0; c < columns; ++c) {
            r.key.push_back(s.text(c));
        }
        r.count = static_cast<std::uint64_t>(s.integer(columns));
        if (summed && !s.is_null(columns + 1)) {
            r.sum = s.integer(columns + 1);
            r.min = s.integer(columns + 2);
            r.max = s.integer(columns + 3);
        }
        out.rows.push_back(std::move(r));
    }
    return out;
}

Status check_offset(const ReportRequest& request) {
    if (request.utc_offset_minutes < -14 * 60 || request.utc_offset_minutes > 14 * 60) {
        return fail(Errc::invalid_argument, "a UTC offset is at most 14 hours");
    }
    if (request.by.size() > 4) {
        return fail(Errc::invalid_argument, "a report groups by at most four things");
    }
    return {};
}

} // namespace

Result<Report> Index::report(const RecordFilter& filter, const ReportRequest& request) const {
    SEARCH_CHECK(check_offset(request));
    if (request.sum) {
        return fail(Errc::invalid_argument, "records have no fields to sum: only instances do");
    }
    std::vector<Key> keys;
    std::vector<std::int64_t> values;
    for (const Group g : request.by) {
        switch (g) {
        case Group::type:
            keys.push_back({"r.type"});
            break;
        case Group::state:
            keys.push_back({"r.state"});
            break;
        case Group::registrant:
            keys.push_back({"r.registrant", "lower(hex(@))"});
            break;
        case Group::day:
        case Group::week:
        case Group::month:
            keys.push_back(bucket(g, "r.registered_at"));
            values.push_back(std::int64_t{request.utc_offset_minutes} * 60);
            break;
        case Group::contract:
            return fail(Errc::invalid_argument, "records are grouped by type, state, "
                                                "registrant, day, week, or month");
        }
    }
    Query q;
    record_conditions(filter, q);
    SEARCH_TRY(auto lease, impl_->lease());
    SEARCH_TRY(const std::uint64_t seen, lease.begin());
    return run_report(lease.db(), seen, request, "FROM records r", keys, q, values, false);
}

Result<Report> Index::report(const InstanceFilter& filter, const ReportRequest& request) const {
    SEARCH_CHECK(check_offset(request));
    std::vector<Key> keys;
    std::vector<std::int64_t> values;
    for (const Group g : request.by) {
        switch (g) {
        case Group::contract:
            keys.push_back({"i.contract", "lower(hex(@))"});
            break;
        case Group::state:
            keys.push_back({"coalesce(i.status, '')"});
            break;
        case Group::day:
        case Group::week:
        case Group::month:
            keys.push_back(bucket(g, "i.created_at"));
            values.push_back(std::int64_t{request.utc_offset_minutes} * 60);
            break;
        case Group::type:
        case Group::registrant:
            return fail(Errc::invalid_argument, "things are grouped by contract, state, day, "
                                                "week, or month");
        }
    }
    Query q;
    instance_conditions(filter, q);
    const std::string from =
        request.sum ? "FROM instances i LEFT JOIN instance_fields s ON s.pos = i.pos AND s.name = ?"
                    : "FROM instances i";
    SEARCH_TRY(auto lease, impl_->lease());
    SEARCH_TRY(const std::uint64_t seen, lease.begin());
    return run_report(lease.db(), seen, request, from, keys, q, values, request.sum.has_value());
}

Result<IndexStatus> Index::status() const {
    SEARCH_TRY(auto lease, impl_->lease());
    SEARCH_TRY(const std::uint64_t seen, lease.begin());
    IndexStatus out;
    out.file = impl_->file;
    out.indexed = seen;
    out.log_size = impl_->ledger.size();
    for (const auto& [table, count] :
         {std::pair<std::string_view, std::uint64_t*>{"records", &out.records},
          {"instances", &out.instances},
          {"contracts", &out.contracts}}) {
        SEARCH_TRY(sql::Statement s,
                   lease.db().prepare("SELECT COUNT(*) FROM " + std::string(table)));
        SEARCH_TRY(const bool row, s.step());
        *count = row ? static_cast<std::uint64_t>(s.integer(0)) : 0;
    }
    std::error_code ec;
    const auto size = std::filesystem::file_size(impl_->file, ec);
    out.bytes = ec ? 0 : static_cast<std::uint64_t>(size);
    return out;
}

} // namespace kanhe::search
