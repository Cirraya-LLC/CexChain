// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <charconv>
#include <format>
#include <map>
#include <optional>
#include <utility>

#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/access.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/core/protocol/witness.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/peers.hpp>
#include <cexchain/node/tokens.hpp>

#include "files.hpp"

namespace cexchain::node {

namespace {

using json = nlohmann::json;
using steady = std::chrono::steady_clock;

constexpr std::uint64_t max_batch = 1000;
constexpr std::size_t max_batch_bytes = 8 * 1024 * 1024;

std::string_view errc_name(Errc code) {
    switch (code) {
    case Errc::invalid_argument:
        return "invalid_argument";
    case Errc::truncated:
        return "truncated";
    case Errc::malformed:
        return "malformed";
    case Errc::non_canonical:
        return "non_canonical";
    case Errc::unsupported:
        return "unsupported";
    case Errc::limit_exceeded:
        return "limit_exceeded";
    case Errc::verification_failed:
        return "verification_failed";
    case Errc::crypto_failure:
        return "crypto_failure";
    case Errc::rejected:
        return "rejected";
    case Errc::not_found:
        return "not_found";
    case Errc::unavailable:
        return "unavailable";
    }
    return "unknown";
}

int status_of(Errc code) {
    switch (code) {
    case Errc::limit_exceeded:
        return 413;
    case Errc::verification_failed:
        return 422;
    case Errc::rejected:
        return 409;
    case Errc::not_found:
        return 404;
    case Errc::unavailable:
        return 503;
    case Errc::crypto_failure:
        return 500;
    default:
        return 400;
    }
}

http::Response json_response(int status, const json& body) {
    http::Response r;
    r.status = status;
    const std::string text = body.dump() + "\n";
    r.body.assign(text.begin(), text.end());
    return r;
}

http::Response error_response(int status, std::string_view code, std::string_view message) {
    return json_response(status, {{"error", {{"code", code}, {"message", message}}}});
}

http::Response error_response(const Error& error) {
    return error_response(status_of(error.code), errc_name(error.code), error.detail);
}

http::Response binary(std::string_view content_type, Bytes body) {
    http::Response r;
    r.content_type = std::string(content_type);
    r.body = std::move(body);
    return r;
}

http::Response cbor_response(const cbor::Value& value) {
    auto encoded = cbor::encode(value);
    if (!encoded) {
        return error_response(encoded.error());
    }
    return binary("application/cbor", std::move(*encoded));
}

/// A query parameter as an unsigned integer.
std::optional<std::uint64_t> number(const http::Request& r, std::string_view name) {
    const auto it = r.query.find(name);
    if (it == r.query.end()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    const std::string& text = it->second;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || ptr != text.data() + text.size() || text.empty()) {
        return std::nullopt;
    }
    return value;
}

std::optional<protocol::Id> id_from(std::string_view hex) {
    if (hex.size() != 64) {
        return std::nullopt;
    }
    auto bytes = from_hex(hex);
    if (!bytes) {
        return std::nullopt;
    }
    auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

std::string hex(const protocol::Id& id) {
    return to_hex(id.bytes());
}

json checkpoint_json(const protocol::Checkpoint& c) {
    return {
        {"tree_size", c.tree_size}, {"root", to_hex(c.root.bytes())}, {"timestamp", c.timestamp}};
}

cbor::Value digests_value(const std::vector<crypto::Digest>& digests) {
    cbor::Array out;
    for (const crypto::Digest& d : digests) {
        out.push_back(cbor::Value::bytes(d.bytes()));
    }
    return cbor::Value::array(std::move(out));
}

enum class Access { open, read, submit, admin, peer };

} // namespace

struct LedgerApi::State {
    ApiOptions options;
    const crypto::Provider* provider = nullptr;
    ledger::SystemClock clock;
    std::optional<ledger::PosixFileSystem> fs;
    std::optional<ledger::Ledger> ledger;
    bool replica = false;
    /// Set once the ledger's files hold something that does not validate:
    /// every route but /healthz then answers 503.
    std::optional<std::string> failure;

    std::vector<ApiToken> tokens;
    std::optional<std::filesystem::file_time_type> tokens_time;
    steady::time_point tokens_checked{};
    steady::time_point last_auto_checkpoint = steady::now();
    std::string principal;

    std::map<int, std::uint64_t> responses;
    std::map<std::string, std::uint64_t, std::less<>> statements;
    std::uint64_t auto_checkpoints = 0;

    void event(std::string_view what, std::string_view detail = {}) const {
        if (options.event_log == nullptr) {
            return;
        }
        const auto now =
            std::chrono::floor<std::chrono::milliseconds>(std::chrono::system_clock::now());
        json line = {{"time", std::format("{:%FT%T}Z", now)}, {"event", what}};
        if (!detail.empty()) {
            line["detail"] = detail;
        }
        *options.event_log << line.dump() << "\n";
        options.event_log->flush();
    }

    void reload_tokens(bool force) {
        const auto now = steady::now();
        if (!force && now - tokens_checked < std::chrono::seconds(1)) {
            return;
        }
        tokens_checked = now;
        std::error_code ec;
        const auto path = options.directory / tokens_file;
        const auto time = std::filesystem::last_write_time(path, ec);
        const std::optional<std::filesystem::file_time_type> current =
            ec ? std::nullopt : std::optional(time);
        if (!force && current == tokens_time) {
            return;
        }
        auto loaded = load_tokens(options.directory);
        if (!loaded) {
            // Keep serving with no tokens rather than with stale ones.
            tokens.clear();
            event("tokens-unreadable", loaded.error().detail);
        } else {
            tokens = std::move(*loaded);
        }
        tokens_time = current;
    }

    /// Picks up what other processes appended, so every request sees all
    /// that was durable when it arrived. Writers, under the lock, also
    /// recover what a crashed writer left half-written.
    Status refresh(bool for_write) {
        auto report = ledger->refresh(*fs, for_write);
        if (!report) {
            failure = std::string(report.error().detail);
            event("ledger-unusable", report.error().detail);
            return std::unexpected(report.error());
        }
        return {};
    }

    /// Runs `write` holding the ledger's lock, after catching up.
    template <class F>
    http::Response with_lock(F&& write) {
        if (options.read_only || replica) {
            return error_response(403, "read_only",
                                  replica ? "this ledger is a replica; write to its primary"
                                          : "this server is read-only");
        }
        auto lock = ledger::DirectoryLock::acquire(options.directory, 2000);
        if (!lock) {
            auto r = error_response(503, "unavailable", "the ledger is busy; retry");
            r.headers.emplace_back("Retry-After", "1");
            return r;
        }
        if (auto s = refresh(true); !s) {
            return error_response(503, "unavailable", "the ledger is unusable");
        }
        return write();
    }

    /// Who is calling, and whether they may.
    std::optional<http::Response> authorize(const http::Request& r, Access access) {
        if (access == Access::open || (access == Access::read && options.public_read)) {
            principal = "public";
            return std::nullopt;
        }
        reload_tokens(false);
        const auto header = r.header("authorization");
        constexpr std::string_view bearer = "Bearer ";
        const ApiToken* token = nullptr;
        if (header && header->size() > bearer.size() &&
            std::equal(bearer.begin(), bearer.end(), header->begin(), [](char a, char b) {
                return a == b || (a >= 'A' && a <= 'Z' && b == a - 'A' + 'a');
            })) {
            token = find_token(tokens, *provider, header->substr(bearer.size()));
        }
        if (token == nullptr) {
            auto response = error_response(401, "unauthorized", "a valid API token is required");
            response.headers.emplace_back("WWW-Authenticate", R"(Bearer realm="cexchain")");
            return response;
        }
        principal = token->name;
        const Scope needed = access == Access::read     ? Scope::read
                             : access == Access::submit ? Scope::submit
                             : access == Access::peer   ? Scope::peer
                                                        : Scope::admin;
        if (!has_scope(token->scopes, needed)) {
            return error_response(403, "forbidden", "the API token lacks the scope for this");
        }
        return std::nullopt;
    }

    // ---- routes --------------------------------------------------------

    http::Response status() const {
        const auto& latest = ledger->latest_checkpoint();
        return json_response(
            200, {{"ledger_id", hex(ledger->id())},
                  {"organization", ledger->state().organization()},
                  {"hash", crypto::name(ledger->hash())},
                  {"size", ledger->size()},
                  {"checkpoint", latest ? checkpoint_json(latest->checkpoint) : json(nullptr)},
                  {"role", replica ? "replica" : "primary"},
                  {"writable", !replica && !options.read_only},
                  {"receipts", options.log_key != nullptr},
                  {"version", options.version}});
    }

    http::Response checkpoint(const http::Request& r) const {
        if (const auto it = r.query.find("size"); it != r.query.end()) {
            const auto size = number(r, "size");
            auto all = ledger->checkpoints();
            if (!size || !all) {
                return error_response(400, "invalid_argument", "size must be a number");
            }
            for (const auto& c : *all) {
                if (c.checkpoint.tree_size == *size) {
                    return binary("application/cose", c.encoded);
                }
            }
            return error_response(404, "not_found", "no checkpoint of this size");
        }
        if (!ledger->latest_checkpoint()) {
            return error_response(404, "not_found", "no checkpoint yet");
        }
        return binary("application/cose", ledger->latest_checkpoint()->encoded);
    }

    http::Response consistency(const http::Request& r) const {
        const auto old_size = number(r, "old");
        const auto new_size = number(r, "new");
        if (!old_size || !new_size || *old_size == 0 || *old_size > *new_size ||
            *new_size > ledger->size()) {
            return error_response(400, "invalid_argument",
                                  "old and new must be sizes with 0 < old <= new <= size");
        }
        auto proof = ledger->consistency_proof(*old_size, *new_size);
        return proof ? cbor_response(digests_value(*proof)) : error_response(proof.error());
    }

    /// [start, start + count) of a list of `total`, with sane limits.
    static std::optional<std::pair<std::uint64_t, std::uint64_t>> range(const http::Request& r,
                                                                        std::uint64_t total) {
        const auto start =
            r.query.contains("start") ? number(r, "start") : std::optional<std::uint64_t>(0);
        const auto count =
            r.query.contains("count") ? number(r, "count") : std::optional<std::uint64_t>(100);
        if (!start || !count || *start > total || *count == 0) {
            return std::nullopt;
        }
        return std::pair(*start, std::min({*start + std::min(*count, max_batch), total}));
    }

    http::Response entries(const http::Request& r) const {
        const auto span = range(r, ledger->size());
        if (!span) {
            return error_response(400, "invalid_argument", "start <= size and 0 < count");
        }
        cbor::Array out;
        std::size_t bytes = 0;
        for (std::uint64_t i = span->first; i < span->second && bytes < max_batch_bytes; ++i) {
            auto entry = ledger->entry(i);
            if (!entry) {
                return error_response(entry.error());
            }
            bytes += entry->size();
            out.push_back(cbor::Value::bytes(*entry));
        }
        return cbor_response(cbor::Value::array(std::move(out)));
    }

    http::Response checkpoints(const http::Request& r) const {
        auto all = ledger->checkpoints();
        if (!all) {
            return error_response(all.error());
        }
        const auto span = range(r, all->size());
        if (!span) {
            return error_response(400, "invalid_argument", "start <= count and 0 < count");
        }
        cbor::Array out;
        for (std::uint64_t i = span->first; i < span->second; ++i) {
            out.push_back(cbor::Value::bytes((*all)[static_cast<std::size_t>(i)].encoded));
        }
        return cbor_response(cbor::Value::array(std::move(out)));
    }

    http::Response cosignatures(const http::Request& r) const {
        auto all = ledger->cosignatures();
        if (!all) {
            return error_response(all.error());
        }
        const auto span = range(r, all->size());
        if (!span) {
            return error_response(400, "invalid_argument", "start <= count and 0 < count");
        }
        cbor::Array out;
        for (std::uint64_t i = span->first; i < span->second; ++i) {
            const auto& s = (*all)[static_cast<std::size_t>(i)];
            out.push_back(cbor::Value::array(
                {cbor::Value::bytes(s.encoded), protocol::encode_public_key(s.witness)}));
        }
        return cbor_response(cbor::Value::array(std::move(out)));
    }

    http::Response inclusion(const http::Request& r) const {
        const auto index = number(r, "index");
        const auto size = number(r, "size");
        if (!index || !size || *index >= *size || *size > ledger->size()) {
            return error_response(400, "invalid_argument", "index < size <= the log's size");
        }
        auto proof = ledger->inclusion_proof(*index, *size);
        return proof ? cbor_response(digests_value(*proof)) : error_response(proof.error());
    }

    http::Response statement(std::string_view id_text) const {
        const auto id = id_from(id_text);
        if (!id) {
            return error_response(400, "invalid_argument", "a statement id is 64 hex digits");
        }
        const auto index = ledger->state().statement_index(*id);
        if (!index) {
            return error_response(404, "not_found", "no such statement");
        }
        auto bytes = ledger->entry(*index);
        auto entry = bytes ? protocol::decode_log_entry(*bytes)
                           : Result<protocol::LogEntry>(std::unexpected(bytes.error()));
        if (!entry) {
            return error_response(entry.error());
        }
        return json_response(200, {{"statement_id", hex(*id)},
                                   {"index", *index},
                                   {"registered_at", entry->registered_at}});
    }

    http::Response receipt(std::string_view index_text) const {
        if (!options.log_key) {
            return error_response(501, "unsupported", "this server has no log key");
        }
        std::uint64_t index = 0;
        const auto [ptr, ec] =
            std::from_chars(index_text.data(), index_text.data() + index_text.size(), index);
        if (ec != std::errc{} || ptr != index_text.data() + index_text.size()) {
            return error_response(400, "invalid_argument", "an entry index is a number");
        }
        auto receipt = ledger->receipt(*options.log_key, index);
        return receipt ? binary("application/cose", std::move(*receipt))
                       : error_response(receipt.error());
    }

    http::Response state_proof(std::string_view id_text) const {
        const auto id = id_from(id_text);
        if (!id) {
            return error_response(400, "invalid_argument", "an id is 64 hex digits");
        }
        auto proof = ledger->state_proof(*id);
        if (!proof) {
            return error_response(proof.error());
        }
        static constexpr std::array kinds{"", "actor", "delegation", "record"};
        const auto& commitment = *ledger->state_commitment();
        json siblings = json::array();
        for (const auto& s : proof->siblings) {
            siblings.push_back(to_hex(s.bytes()));
        }
        return json_response(200, {{"kind", kinds[static_cast<std::size_t>(proof->leaf.kind)]},
                                   {"id", hex(proof->leaf.id)},
                                   {"history", proof->leaf.history},
                                   {"commitment_index", commitment.tree_size},
                                   {"state_root", to_hex(commitment.state_root.bytes())},
                                   {"siblings", siblings}});
    }

    http::Response evidence(std::string_view id_text) const {
        if (!options.log_key) {
            return error_response(501, "unsupported", "this server has no log key");
        }
        const auto id = id_from(id_text);
        if (!id) {
            return error_response(400, "invalid_argument", "a record id is 64 hex digits");
        }
        if (ledger->state().record(*id) == nullptr) {
            return error_response(404, "not_found", "no such record");
        }
        auto bundle = ledger->export_evidence(*options.log_key, *id);
        if (!bundle) {
            return error_response(bundle.error());
        }
        auto encoded = protocol::encode_bundle(*bundle);
        return encoded ? binary("application/cbor", std::move(*encoded))
                       : error_response(encoded.error());
    }

    http::Response vault_file(const std::filesystem::path& relative) const {
        auto bytes = detail::read_file(options.directory / "vault" / relative);
        if (!bytes) {
            return bytes.error().code == Errc::not_found
                       ? error_response(404, "not_found", "no such vault file")
                       : error_response(bytes.error());
        }
        return binary("application/cbor", std::move(*bytes));
    }

    http::Response submit(const http::Request& r) {
        const auto type = r.header("content-type");
        if (type && !type->starts_with("application/cose") &&
            !type->starts_with("application/cbor") &&
            !type->starts_with("application/octet-stream")) {
            return error_response(415, "unsupported",
                                  "send the signed statement as application/cose");
        }
        if (r.body.empty()) {
            return error_response(400, "invalid_argument", "send a signed statement");
        }
        return with_lock([&] {
            auto registration = ledger->submit(r.body);
            if (!registration) {
                ++statements["refused"];
                return error_response(registration.error());
            }
            ++statements[registration->newly_registered ? "registered" : "duplicate"];
            return json_response(registration->newly_registered ? 201 : 200,
                                 {{"statement_id", hex(registration->statement_id)},
                                  {"index", registration->index},
                                  {"registered_at", registration->registered_at},
                                  {"newly_registered", registration->newly_registered}});
        });
    }

    http::Response make_checkpoint() {
        if (!options.log_key) {
            return error_response(501, "unsupported", "this server has no log key");
        }
        return with_lock([&] {
            auto made = ledger->checkpoint(*options.log_key);
            return made ? binary("application/cose", made->encoded) : error_response(made.error());
        });
    }

    http::Response add_cosignature(const http::Request& r) {
        auto value = cbor::decode(r.body);
        const cbor::Array* parts = value ? value->as_array() : nullptr;
        if (parts == nullptr || parts->size() != 2 || (*parts)[0].as_bytes() == nullptr) {
            return error_response(400, "malformed", "send [cosignature, witness public key]");
        }
        auto witness = protocol::decode_public_key((*parts)[1]);
        if (!witness) {
            return error_response(witness.error());
        }
        const Bytes cosignature = *(*parts)[0].as_bytes();
        return with_lock([&] {
            auto stored = ledger->add_cosignature(cosignature, *witness);
            return stored ? json_response(200, {{"stored", true}}) : error_response(stored.error());
        });
    }

    /// The peer whose ledger produced `bundle`, which must verify.
    Result<Peer> peer_of(ByteView bundle) const {
        auto report = protocol::verify_bundle(*provider, bundle, {});
        if (!report) {
            return std::unexpected(report.error());
        }
        auto peers = load_peers(options.directory);
        if (!peers) {
            return std::unexpected(peers.error());
        }
        for (const Peer& p : *peers) {
            if (p.ledger_id == report->ledger_id) {
                return p;
            }
        }
        return fail(Errc::rejected, "the evidence comes from a ledger that is not a peer");
    }

    Status store(const std::filesystem::path& path, ByteView bytes) const {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) {
            return fail(Errc::unavailable, "cannot create the access directory");
        }
        return detail::write_file(path, bytes, true);
    }

    /// Peer tokens are named after their peer: each peer sees and sends
    /// only its own exchanges.
    std::optional<http::Response> require_peer_token(const Peer& peer) const {
        if (peer.name != principal) {
            return error_response(403, "forbidden",
                                  "this token is not the peer's (name it after the peer)");
        }
        return std::nullopt;
    }

    http::Response access_request(const http::Request& r) {
        auto peer = peer_of(r.body);
        if (!peer) {
            return error_response(peer.error());
        }
        if (auto denied = require_peer_token(*peer)) {
            return std::move(*denied);
        }
        auto checked = protocol::check_access_request(*provider, r.body, peer->ledger_id,
                                                      ledger->id(), clock.now());
        if (!checked) {
            return error_response(checked.error());
        }
        if (auto s = store(access_path(options.directory, AccessBox::inbox, checked->report.record),
                           r.body);
            !s) {
            return error_response(s.error());
        }
        event("access-request", peer->name + " " + hex(checked->report.record));
        return json_response(202, {{"request", hex(checked->report.record)},
                                   {"peer", peer->name},
                                   {"record", hex(checked->value.record)},
                                   {"purpose", checked->value.purpose}});
    }

    http::Response access_delivery(std::string_view request_text) const {
        const auto request = id_from(request_text);
        if (!request) {
            return error_response(400, "invalid_argument", "a request id is 64 hex digits");
        }
        auto bytes = detail::read_file(access_path(options.directory, AccessBox::outbox, *request));
        if (!bytes) {
            return bytes.error().code == Errc::not_found
                       ? error_response(404, "not_found", "not granted (yet)")
                       : error_response(bytes.error());
        }
        // Only to the peer it was granted to; to anyone else it does not exist.
        auto delivery = protocol::decode_delivery(*bytes);
        protocol::VerifyOptions own;
        own.expected_ledger = ledger->id();
        auto report = delivery
                          ? protocol::verify_bundle(*provider, delivery->grant_bundle, own)
                          : Result<protocol::EvidenceReport>(std::unexpected(delivery.error()));
        auto grant = report && report->metadata
                         ? protocol::decode_access_grant(*report->metadata)
                         : Result<protocol::AccessGrant>(fail(Errc::malformed, "no grant"));
        auto peers = load_peers(options.directory);
        const bool theirs = grant && peers && std::ranges::any_of(*peers, [&](const Peer& p) {
                                return p.ledger_id == grant->ledger && p.name == principal;
                            });
        if (!theirs) {
            return error_response(404, "not_found", "not granted (yet)");
        }
        return binary("application/cbor", std::move(*bytes));
    }

    http::Response access_receipt(const http::Request& r) {
        auto peer = peer_of(r.body);
        if (!peer) {
            return error_response(peer.error());
        }
        if (auto denied = require_peer_token(*peer)) {
            return std::move(*denied);
        }
        // Which grant: from the receipt's metadata, checked below.
        auto report = protocol::verify_bundle(*provider, r.body, {});
        auto receipt =
            report && report->metadata
                ? protocol::decode_access_receipt(*report->metadata)
                : Result<protocol::AccessReceipt>(fail(Errc::malformed, "not an access receipt"));
        if (!receipt) {
            return error_response(receipt.error());
        }
        auto grant = record_metadata(*provider, *ledger, receipt->grant);
        auto decoded = grant ? protocol::decode_access_grant(*grant)
                             : Result<protocol::AccessGrant>(std::unexpected(grant.error()));
        if (!decoded) {
            return error_response(404, "not_found", "no such grant on this ledger");
        }
        auto delivery =
            detail::read_file(access_path(options.directory, AccessBox::outbox, decoded->request));
        auto digest = delivery ? provider->digest(crypto::HashAlg::sha256, *delivery)
                               : Result<crypto::Digest>(std::unexpected(delivery.error()));
        if (!digest) {
            return error_response(404, "not_found", "nothing was delivered for this grant");
        }
        auto checked = protocol::check_access_receipt(
            *provider, r.body, peer->ledger_id, ledger->id(), receipt->grant, digest->bytes());
        if (!checked) {
            return error_response(checked.error());
        }
        if (auto s =
                store(access_path(options.directory, AccessBox::receipts, receipt->grant), r.body);
            !s) {
            return error_response(s.error());
        }
        event("access-receipt", peer->name + " " + hex(receipt->grant));
        return json_response(202, {{"grant", hex(receipt->grant)}, {"peer", peer->name}});
    }

    http::Response witness_cosign(const http::Request& r) const {
        if (!options.witness) {
            return error_response(501, "unsupported", "this server is not a witness");
        }
        auto cosignature = options.witness(r.body);
        if (!cosignature) {
            return error_response(cosignature.error());
        }
        return binary("application/cose", std::move(*cosignature));
    }

    http::Response metrics() const {
        const auto& latest = ledger->latest_checkpoint();
        const std::uint64_t checkpointed = latest ? latest->checkpoint.tree_size : 0;
        std::string out;
        auto gauge = [&](std::string_view name, std::string_view help, std::uint64_t value) {
            out += std::format("# HELP {0} {1}\n# TYPE {0} gauge\n{0} {2}\n", name, help, value);
        };
        gauge("cexchain_ledger_usable", "1 while the ledger's files validate.", failure ? 0 : 1);
        gauge("cexchain_log_entries", "Entries in the log.", ledger->size());
        gauge("cexchain_checkpoint_tree_size", "Entries the latest checkpoint covers.",
              checkpointed);
        gauge("cexchain_checkpoint_timestamp_seconds", "When the latest checkpoint was signed.",
              latest ? latest->checkpoint.timestamp / 1000 : 0);
        gauge("cexchain_unchecked_entries", "Entries no checkpoint covers yet.",
              ledger->size() - checkpointed);
        out += "# HELP cexchain_http_responses_total Responses by status code.\n"
               "# TYPE cexchain_http_responses_total counter\n";
        for (const auto& [code, n] : responses) {
            out += std::format("cexchain_http_responses_total{{code=\"{}\"}} {}\n", code, n);
        }
        out += "# HELP cexchain_statements_total Submitted statements by outcome.\n"
               "# TYPE cexchain_statements_total counter\n";
        for (const auto& [result, n] : statements) {
            out += std::format("cexchain_statements_total{{result=\"{}\"}} {}\n", result, n);
        }
        out += std::format("# HELP cexchain_auto_checkpoints_total Automatic checkpoints.\n"
                           "# TYPE cexchain_auto_checkpoints_total counter\n"
                           "cexchain_auto_checkpoints_total {}\n",
                           auto_checkpoints);
        http::Response r;
        r.content_type = "text/plain; version=0.0.4";
        r.body.assign(out.begin(), out.end());
        return r;
    }

    http::Response route(const http::Request& r) {
        principal.clear();
        const std::string_view path = r.path;
        const bool get = r.method == "GET";
        const bool post = r.method == "POST";
        auto method_not_allowed = [](std::string_view allow) {
            auto response = error_response(405, "unsupported", "method not allowed");
            response.headers.emplace_back("Allow", std::string(allow));
            return response;
        };

        if (path == "/healthz") {
            if (!get) {
                return method_not_allowed("GET");
            }
            principal = "public";
            http::Response h;
            h.content_type = "text/plain";
            h.status = failure ? 503 : 200;
            const std::string text = failure ? "unusable: " + *failure + "\n" : "ok\n";
            h.body.assign(text.begin(), text.end());
            return h;
        }
        if (failure) {
            return error_response(503, "unavailable",
                                  "the ledger's files do not validate; run cexchain audit");
        }

        // (path, method) -> access, handler
        struct Route {
            Access access;
            bool post;
        };
        std::optional<Route> found;
        std::string_view rest;
        auto match = [&](std::string_view prefix) {
            if (path.starts_with(prefix) && path.size() > prefix.size()) {
                rest = path.substr(prefix.size());
                return rest.find('/') == std::string_view::npos;
            }
            return false;
        };
        if (path == "/v1/checkpoint" || path == "/v1/consistency") {
            found = Route{post ? Access::admin : Access::open, post};
            if (post && path == "/v1/consistency") {
                return method_not_allowed("GET");
            }
        } else if (path == "/v1/access/requests" || path == "/v1/access/receipts" ||
                   path == "/v1/witness/cosign") {
            if (!post) {
                return method_not_allowed("POST");
            }
            found = Route{Access::peer, true};
        } else if (match("/v1/access/deliveries/")) {
            if (!get) {
                return method_not_allowed("GET");
            }
            found = Route{Access::peer, false};
        } else if (path == "/v1/statements" || path == "/v1/cosignatures") {
            found = Route{post ? (path == "/v1/statements" ? Access::submit : Access::admin)
                               : Access::read,
                          post};
            if (!post && path == "/v1/statements") {
                return method_not_allowed("POST");
            }
        } else if (path == "/metrics" || path == "/v1/status" || path == "/v1/entries" ||
                   path == "/v1/checkpoints" || path == "/v1/inclusion" ||
                   path == "/v1/vault/public-key" || match("/v1/statements/") ||
                   match("/v1/receipts/") || match("/v1/state/") || match("/v1/evidence/") ||
                   match("/v1/vault/records/")) {
            if (!get) {
                return method_not_allowed("GET");
            }
            found = Route{Access::read, false};
        }
        if (!found) {
            return error_response(404, "not_found", "no such route");
        }
        if (!get && !post) {
            return method_not_allowed(found->post ? "POST" : "GET");
        }
        if (auto denied = authorize(r, found->access)) {
            return std::move(*denied);
        }
        if (!found->post || found->access == Access::peer) {
            if (auto s = refresh(false); !s) {
                return error_response(503, "unavailable", "the ledger is unusable");
            }
        }

        if (post && path == "/v1/access/requests") {
            return access_request(r);
        }
        if (post && path == "/v1/access/receipts") {
            return access_receipt(r);
        }
        if (post && path == "/v1/witness/cosign") {
            return witness_cosign(r);
        }
        if (path.starts_with("/v1/access/deliveries/")) {
            return access_delivery(rest);
        }
        if (post) {
            if (options.read_only || replica) {
                return error_response(403, "read_only",
                                      replica ? "this ledger is a replica; write to its primary"
                                              : "this server is read-only");
            }
            if (path == "/v1/statements") {
                return submit(r);
            }
            if (path == "/v1/checkpoint") {
                return make_checkpoint();
            }
            return add_cosignature(r);
        }
        if (path == "/metrics") {
            return metrics();
        }
        if (path == "/v1/status") {
            return status();
        }
        if (path == "/v1/checkpoint") {
            return checkpoint(r);
        }
        if (path == "/v1/consistency") {
            return consistency(r);
        }
        if (path == "/v1/entries") {
            return entries(r);
        }
        if (path == "/v1/checkpoints") {
            return checkpoints(r);
        }
        if (path == "/v1/cosignatures") {
            return cosignatures(r);
        }
        if (path == "/v1/inclusion") {
            return inclusion(r);
        }
        if (path == "/v1/vault/public-key") {
            return vault_file("vault.pub");
        }
        if (path.starts_with("/v1/statements/")) {
            return statement(rest);
        }
        if (path.starts_with("/v1/receipts/")) {
            return receipt(rest);
        }
        if (path.starts_with("/v1/state/")) {
            return state_proof(rest);
        }
        if (path.starts_with("/v1/evidence/")) {
            return evidence(rest);
        }
        // /v1/vault/records/{record}
        if (!id_from(rest)) {
            return error_response(400, "invalid_argument", "a record id is 64 hex digits");
        }
        return vault_file(std::filesystem::path("records") / (std::string(rest) + ".cbor"));
    }

    void auto_checkpoint() {
        if (failure || !options.log_key || replica || options.read_only ||
            options.checkpoint_interval.count() == 0 ||
            steady::now() - last_auto_checkpoint < options.checkpoint_interval) {
            return;
        }
        last_auto_checkpoint = steady::now();
        if (auto s = refresh(false); !s) {
            return;
        }
        const auto& latest = ledger->latest_checkpoint();
        if (latest && latest->checkpoint.tree_size >= ledger->size()) {
            return;
        }
        auto lock = ledger::DirectoryLock::acquire(options.directory, 1000);
        if (!lock) {
            return; // busy: next time
        }
        if (auto s = refresh(true); !s) {
            return;
        }
        auto made = ledger->checkpoint(*options.log_key);
        if (!made) {
            event("checkpoint-failed", made.error().detail);
            return;
        }
        ++auto_checkpoints;
        event("checkpoint", std::format("tree size {}", made->checkpoint.tree_size));
    }
};

Result<std::unique_ptr<LedgerApi>> LedgerApi::open(ApiOptions options,
                                                   const crypto::Provider& provider) {
    auto state = std::make_unique<State>();
    state->provider = &provider;
    std::error_code ec;
    if (!std::filesystem::is_directory(options.directory, ec)) {
        return fail(Errc::not_found, "no ledger directory");
    }
    state->replica = std::filesystem::exists(options.directory / replica_file, ec);
    {
        auto lock = ledger::DirectoryLock::acquire(options.directory);
        if (!lock) {
            return std::unexpected(lock.error());
        }
        auto fs = ledger::PosixFileSystem::open_directory(options.directory);
        if (!fs) {
            return std::unexpected(fs.error());
        }
        state->fs.emplace(std::move(*fs));
        auto opened = ledger::Ledger::open(*state->fs, state->clock, provider);
        if (!opened) {
            return std::unexpected(opened.error());
        }
        state->ledger.emplace(std::move(*opened));
    }
    if (options.log_key && options.log_key->public_key() != state->ledger->state().log_key()) {
        return fail(Errc::invalid_argument, "the log key is not this ledger's");
    }
    state->options = std::move(options);
    state->reload_tokens(true);
    return std::unique_ptr<LedgerApi>(new LedgerApi(std::move(state)));
}

LedgerApi::LedgerApi(std::unique_ptr<State> state) : state_(std::move(state)) {}
LedgerApi::~LedgerApi() = default;

http::Response LedgerApi::handle(const http::Request& request, std::string_view) {
    http::Response response = state_->route(request);
    ++state_->responses[response.status];
    response.headers.emplace_back("Cache-Control", "no-store");
    response.headers.emplace_back("X-Content-Type-Options", "nosniff");
    return response;
}

void LedgerApi::tick() {
    state_->reload_tokens(false);
    state_->auto_checkpoint();
}

std::string LedgerApi::principal() const {
    return state_->principal;
}

bool LedgerApi::is_replica() const noexcept {
    return state_->replica;
}

const ledger::Ledger& LedgerApi::ledger() const noexcept {
    return *state_->ledger;
}

} // namespace cexchain::node
