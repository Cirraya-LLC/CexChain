// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/ledger/ledger.hpp>

/// The search index: what a ledger holds in the clear, kept in SQLite beside
/// it for searches and reports at scale.
///
/// It follows the log: each step reads the entries it has not seen, finds the
/// objects they touched, and writes those objects' rows as the state has
/// them now, in one transaction. It is derived data: a missing index, or one
/// of another ledger or layout, is rebuilt from the log. It is never
/// evidence (answers are hints, as of the log size they name) and holds no
/// private data: a record's field values stay sealed in the vault.
namespace cexchain::search {

using protocol::Id;
using protocol::Timestamp;

/// Which records or instances a search or report takes. Times are
/// milliseconds since the epoch, ranges half-open [since, until).
struct RecordFilter {
    std::optional<std::string> type{};
    std::optional<std::string> state{};
    std::optional<Id> registrant{};
    std::optional<Timestamp> since{};
    std::optional<Timestamp> until{};
    /// Leave out records a newer version superseded.
    bool current = false;
    enum class Revoked : std::uint8_t { no, yes, any };
    Revoked revoked = Revoked::no;
    /// A public metadata key's value: exactly `equals`, or a number in
    /// [at_least, at_most].
    struct Metadata {
        std::string key{};
        std::optional<std::string> equals{};
        std::optional<std::int64_t> at_least{};
        std::optional<std::int64_t> at_most{};
    };
    std::vector<Metadata> metadata{};
    /// Words or a part of a word (three characters at least) in the public
    /// metadata's values.
    std::optional<std::string> text{};
};

struct InstanceFilter {
    std::optional<Id> contract{};
    /// The contract's name, as deployed.
    std::optional<std::string> contract_name{};
    std::optional<std::string> status{};
    std::optional<bool> final{};
    /// A ledger among its parties (any role).
    std::optional<Id> party{};
    /// When the call that created it registered.
    std::optional<Timestamp> since{};
    std::optional<Timestamp> until{};
    /// When its latest call registered.
    std::optional<Timestamp> changed_since{};
    /// The creating call's reference.
    std::optional<std::string> reference{};
    /// A field of its state (a Bo contract's `fields`): text or yes/no
    /// exactly (`equals`: "true" or "false" for yes/no), or a number in
    /// [at_least, at_most].
    struct Field {
        std::string name{};
        std::optional<std::string> equals{};
        std::optional<std::int64_t> at_least{};
        std::optional<std::int64_t> at_most{};
    };
    std::vector<Field> fields{};
};

/// A page: newest first unless `oldest_first`; `cursor` is where the last
/// page ended (opaque).
struct PageRequest {
    std::size_t limit = 100;
    std::optional<std::string> cursor{};
    bool oldest_first = false;
};

inline constexpr std::size_t max_page = 1000;
inline constexpr std::size_t max_groups = 10'000;

struct RecordRow {
    Id id;
    std::string type;
    std::string state;
    bool revoked = false;
    Id registrant;
    std::uint64_t registered_index = 0;
    Timestamp registered_at = 0;
    std::optional<Id> supersedes;
    std::optional<Id> superseded_by;
    std::uint64_t endorsements = 0;
    /// Its latest statement.
    std::uint64_t last_index = 0;
    Timestamp last_at = 0;
    /// Its public metadata, as text, in the registration's order.
    std::vector<std::pair<std::string, std::string>> metadata;
};

struct InstanceRow {
    Id id;
    Id contract;
    std::optional<std::string> contract_name;
    std::optional<std::string> status;
    bool final = false;
    std::uint64_t created_index = 0;
    Timestamp created_at = 0;
    std::uint64_t last_index = 0;
    Timestamp last_at = 0;
    std::uint64_t calls = 0;
    std::uint64_t open_requests = 0;
    std::optional<Id> parent;
    std::optional<std::string> reference;
    std::vector<std::pair<std::string, Id>> parties;
    /// Its state's fields, as text (numbers in decimal, yes/no as true or
    /// false, bytes in hex).
    std::vector<std::pair<std::string, std::string>> fields;
};

template <typename Row>
struct Page {
    std::vector<Row> rows;
    /// Set if there is more: the next page's cursor.
    std::optional<std::string> next;
    /// The log size the index reflects.
    std::uint64_t as_of = 0;
};

/// What a report groups by. Times are bucketed in `utc_offset_minutes`.
enum class Group : std::uint8_t {
    type,       // records
    state,      // records: the state; instances: the status
    registrant, // records
    contract,   // instances
    day,        // records: registration; instances: creation
    week,       // starting on Monday
    month,
};
[[nodiscard]] std::optional<Group> group_from(std::string_view name) noexcept;
[[nodiscard]] std::string_view name(Group group) noexcept;

struct ReportRequest {
    std::vector<Group> by{};
    std::int32_t utc_offset_minutes = 0;
    /// Instances only: the integer field to sum (and take the least and
    /// greatest of), where it is an integer.
    std::optional<std::string> sum{};
};

struct ReportRow {
    /// One per group, in `by`'s order: ids in hex, times as dates
    /// (2026-11-01), weeks by their Monday, months as 2026-11.
    std::vector<std::string> key;
    std::uint64_t count = 0;
    std::optional<std::int64_t> sum;
    std::optional<std::int64_t> min;
    std::optional<std::int64_t> max;
};

struct Report {
    std::vector<Group> by;
    std::vector<ReportRow> rows;
    /// More than max_groups groups: only the largest are given.
    bool truncated = false;
    std::uint64_t as_of = 0;
};

struct IndexStatus {
    std::filesystem::path file;
    std::uint64_t indexed = 0;
    std::uint64_t log_size = 0;
    std::uint64_t records = 0;
    std::uint64_t instances = 0;
    std::uint64_t contracts = 0;
    /// The file's size, in bytes.
    std::uint64_t bytes = 0;
};

/// The index of one ledger, in `file`. Safe to use from several threads:
/// searches and reports run side by side, each on a reader of its own that
/// sees the index as one update left it; updates run one at a time.
class Index {
public:
    /// Behind by more than this many log entries (a first build, or a long
    /// way to catch up), `update` loads the rows first and makes the
    /// secondary indexes once at the end.
    static constexpr std::uint64_t bulk_from = 50'000;

    /// Opens (or makes) the index of `ledger` at `file`; one of another
    /// ledger, or of another layout, is emptied, to be rebuilt by `update`.
    [[nodiscard]] static Result<std::unique_ptr<Index>>
    open(const ledger::Ledger& ledger, std::filesystem::path file, std::uint64_t bulk = bulk_from);
    /// The index file beside a ledger's directory: `<ledger>/search.sqlite`.
    [[nodiscard]] static std::filesystem::path file_for(const std::filesystem::path& ledger);

    ~Index();
    Index(const Index&) = delete;
    Index& operator=(const Index&) = delete;

    /// Takes in the log entries the index has not seen, in transactions of
    /// at most `batch` entries, until it reaches the log's size or `budget`
    /// runs out (then it carries on next time). Returns the log size it
    /// reflects.
    Result<std::uint64_t> update(std::chrono::milliseconds budget = std::chrono::hours(24),
                                 std::size_t batch = 16384);
    /// Empties the index, to be rebuilt by `update`.
    Status clear();

    [[nodiscard]] Result<Page<RecordRow>> records(const RecordFilter& filter,
                                                  const PageRequest& page) const;
    [[nodiscard]] Result<Page<InstanceRow>> instances(const InstanceFilter& filter,
                                                      const PageRequest& page) const;
    /// One record's row, if the index has it.
    [[nodiscard]] Result<std::optional<RecordRow>> record(const Id& id) const;
    /// The log size the index reflects.
    [[nodiscard]] std::uint64_t as_of() const;
    [[nodiscard]] Result<Report> report(const RecordFilter& filter,
                                        const ReportRequest& request) const;
    [[nodiscard]] Result<Report> report(const InstanceFilter& filter,
                                        const ReportRequest& request) const;
    [[nodiscard]] Result<IndexStatus> status() const;

private:
    struct Impl;
    explicit Index(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

} // namespace cexchain::search
