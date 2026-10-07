// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <libnuraft/nuraft.hxx>
#include <map>
#include <mutex>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/node/cluster.hpp>

#include "cluster_parts.hpp"

namespace cexchain::node {

namespace {

using namespace cluster_detail;
// ---------------------------------------------------------------------------
// Every Raft message is authenticated with HMAC-SHA256 under the cluster's
// secret: the header and every entry of a request; for a response, the
// request's header too, so it answers that request.
// ---------------------------------------------------------------------------

void mac_header(Bytes& out, const nuraft::asio_service::meta_cb_params& p) {
    put64(out, static_cast<std::uint64_t>(p.msg_type_));
    put64(out, static_cast<std::uint64_t>(p.src_id_));
    put64(out, static_cast<std::uint64_t>(p.dst_id_));
    put64(out, p.term_);
    put64(out, p.log_term_);
    put64(out, p.log_idx_);
    put64(out, p.commit_idx_);
}

std::string mac(ByteView secret, const nuraft::asio_service::meta_cb_params& p, bool response) {
    Bytes message{static_cast<std::uint8_t>(response ? 'R' : 'Q')};
    mac_header(message, p);
    if (!response && p.req_ != nullptr) {
        for (const ptr<nuraft::log_entry>& e : p.req_->log_entries()) {
            put64(message, e->get_term());
            put64(message, static_cast<std::uint64_t>(e->get_val_type()));
            const ptr<buffer> b = e->get_buf_ptr();
            put64(message, b ? b->size() : 0);
            if (b) {
                message.insert(message.end(), b->data_begin(), b->data_begin() + b->size());
            }
        }
    }
    if (response && p.resp_ != nullptr) {
        put64(message, static_cast<std::uint64_t>(p.resp_->get_type()));
        put64(message, static_cast<std::uint64_t>(p.resp_->get_src()));
        put64(message, static_cast<std::uint64_t>(p.resp_->get_dst()));
        put64(message, p.resp_->get_term());
        put64(message, p.resp_->get_next_idx());
        message.push_back(p.resp_->get_accepted() ? 1 : 0);
        if (const ptr<buffer> ctx = p.resp_->get_ctx()) {
            put64(message, ctx->size());
            message.insert(message.end(), ctx->data_begin(), ctx->data_begin() + ctx->size());
        }
    }
    std::array<unsigned char, 32> tag{};
    std::size_t length = 0;
    if (EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, secret.data(), secret.size(),
                  message.data(), message.size(), tag.data(), tag.size(), &length) == nullptr ||
        length != tag.size()) {
        return {};
    }
    return std::string(reinterpret_cast<const char*>(tag.data()), tag.size());
}

bool mac_matches(ByteView secret, const nuraft::asio_service::meta_cb_params& p, bool response,
                 const std::string& meta) {
    const std::string expected = mac(secret, p, response);
    return !expected.empty() && meta.size() == expected.size() &&
           CRYPTO_memcmp(meta.data(), expected.data(), expected.size()) == 0;
}

/// NuRaft's own log lines: errors only, as events.
class RaftLogger final : public nuraft::logger {
public:
    explicit RaftLogger(LedgerMachine::Event event) : event_(std::move(event)) {}
    void put_details(int level, const char*, const char*, size_t,
                     const std::string& line) override {
        if (level <= 2 && event_) {
            event_("raft", line);
        }
    }
    int get_level() override { return 2; }

private:
    LedgerMachine::Event event_;
};

Error cluster_error(nuraft::cmd_result_code code) {
    switch (code) {
    case nuraft::cmd_result_code::NOT_LEADER:
        return {Errc::unavailable, "this node no longer leads; retry"};
    case nuraft::cmd_result_code::TIMEOUT:
        return {Errc::unavailable, "no majority confirmed it in time: the outcome is unknown; "
                                   "retry"};
    case nuraft::cmd_result_code::SERVER_ALREADY_EXISTS:
        return {Errc::rejected, "a member with this id exists already"};
    case nuraft::cmd_result_code::SERVER_NOT_FOUND:
        return {Errc::not_found, "no member with this id"};
    case nuraft::cmd_result_code::CANNOT_REMOVE_LEADER:
        return {Errc::rejected, "the leader cannot be removed: step down first"};
    case nuraft::cmd_result_code::CONFIG_CHANGING:
    case nuraft::cmd_result_code::SERVER_IS_JOINING:
    case nuraft::cmd_result_code::SERVER_IS_LEAVING:
        return {Errc::unavailable, "the membership is changing; retry"};
    default:
        return {Errc::unavailable, "the cluster did not take it: the outcome is unknown; retry"};
    }
}

} // namespace

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

Status init_cluster(const std::filesystem::path& ledger_directory, const ClusterNode& node,
                    ByteView secret) {
    if (node.id < 1 || node.id > 1000) {
        return fail(Errc::invalid_argument, "a member's id is 1 to 1000");
    }
    if (secret.size() != cluster_secret_size) {
        return fail(Errc::invalid_argument, "the cluster secret is 32 bytes");
    }
    std::error_code ec;
    std::filesystem::create_directories(ledger_directory / cluster_directory, ec);
    std::filesystem::permissions(ledger_directory / cluster_directory,
                                 std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
    if (ec) {
        return fail(Errc::unavailable, "cannot create the cluster directory");
    }
    const nlohmann::json document{{"id", node.id},
                                  {"raft_endpoint", node.raft_endpoint},
                                  {"raft_port", node.raft_port},
                                  {"api_url", node.api_url},
                                  {"founder", node.founder}};
    const std::string text = document.dump(2) + "\n";
    if (auto s = detail::write_file(cluster_path(ledger_directory, secret_file), secret, true);
        !s) {
        return s;
    }
    return detail::write_file(cluster_path(ledger_directory, node_file), as_bytes(text), false);
}

Result<ClusterNode> read_cluster_node(const std::filesystem::path& ledger_directory) {
    auto bytes = detail::read_file(cluster_path(ledger_directory, node_file));
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    const auto document = nlohmann::json::parse(bytes->begin(), bytes->end(), nullptr, false);
    if (!document.is_object() || !document.contains("id") || !document["id"].is_number_integer() ||
        !document.contains("raft_endpoint") || !document["raft_endpoint"].is_string() ||
        !document.contains("raft_port") || !document["raft_port"].is_number_unsigned() ||
        !document.contains("api_url") || !document["api_url"].is_string()) {
        return fail(Errc::malformed, "the cluster's node.json is malformed");
    }
    return ClusterNode{document["id"].get<int>(), document["raft_endpoint"].get<std::string>(),
                       document["raft_port"].get<std::uint16_t>(),
                       document["api_url"].get<std::string>(), document.value("founder", false)};
}

bool is_cluster_member(const std::filesystem::path& ledger_directory) {
    std::error_code ec;
    return std::filesystem::exists(cluster_path(ledger_directory, node_file), ec);
}

// ---------------------------------------------------------------------------
// The cluster
// ---------------------------------------------------------------------------

struct Cluster::Impl {
    std::filesystem::path directory;
    ClusterNode node;
    Bytes secret;
    ledger::Ledger* ledger = nullptr;
    LedgerMachine::Event event;
    ptr<RaftLog> log;
    ptr<StateManager> state;
    ptr<LedgerMachine> machine;
    nuraft::raft_launcher launcher;
    ptr<nuraft::raft_server> raft;

    /// Nothing on its way: the leader's own entries are applied.
    bool settled() const { return raft->get_last_log_idx() <= machine->last_commit_index(); }

    /// Appends an entry and waits for it here; its outcome.
    Result<std::variant<BatchResult, Status>> replicate(ByteView entry) {
        if (!raft->is_leader()) {
            return fail(Errc::unavailable, "this node does not lead; retry with the leader");
        }
        const auto result = raft->append_entries({to_buffer(entry)});
        if (!result->get_accepted() || result->get_result_code() != nuraft::cmd_result_code::OK) {
            return std::unexpected(cluster_error(result->get_result_code()));
        }
        const ptr<buffer> index = result->get();
        if (!index || index->size() < sizeof(ulong)) {
            return fail(Errc::unavailable, "the outcome is unknown; retry");
        }
        index->pos(0);
        auto outcome = machine->take(index->get_ulong());
        if (!outcome) {
            return fail(Errc::unavailable, "the outcome is unknown; retry");
        }
        return std::move(*outcome);
    }

    /// Waits a little for entries on their way to apply.
    Status settle() {
        for (int i = 0; i < 100 && !settled(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (!settled()) {
            return fail(Errc::unavailable, "the cluster is catching up; retry");
        }
        return {};
    }
};

Cluster::Cluster(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

Cluster::~Cluster() {
    impl_->launcher.shutdown(5);
}

Result<std::unique_ptr<Cluster>>
Cluster::start(const std::filesystem::path& ledger_directory, ledger::Ledger& ledger,
               std::function<void(std::string_view, std::string_view)> on_event,
               const ClusterTuning& tuning) {
    auto impl = std::make_unique<Impl>();
    impl->directory = ledger_directory;
    impl->ledger = &ledger;
    impl->event = std::move(on_event);
    auto node = read_cluster_node(ledger_directory);
    if (!node) {
        return std::unexpected(node.error());
    }
    impl->node = std::move(*node);
    auto secret = detail::read_file(cluster_path(ledger_directory, secret_file));
    if (!secret || secret->size() != cluster_secret_size) {
        return fail(Errc::malformed, "the cluster secret is missing or not 32 bytes");
    }
    impl->secret = std::move(*secret);
    auto log = RaftLog::open(cluster_path(ledger_directory, log_file));
    if (!log) {
        return std::unexpected(log.error());
    }
    impl->log = std::move(*log);
    impl->state = cs_new<StateManager>(ledger_directory / cluster_directory, impl->node, impl->log);
    impl->machine = cs_new<LedgerMachine>(ledger_directory, ledger, impl->event);

    nuraft::raft_params params;
    params.heart_beat_interval_ = tuning.heartbeat_ms;
    params.election_timeout_lower_bound_ = tuning.election_min_ms;
    params.election_timeout_upper_bound_ = tuning.election_max_ms;
    params.reserved_log_items_ = tuning.reserved_log_items;
    params.snapshot_distance_ = tuning.snapshot_distance;
    params.client_req_timeout_ = 10000;
    params.return_method_ = nuraft::raft_params::blocking;
    params.use_new_joiner_type_ = true;

    nuraft::asio_service::options asio;
    asio.thread_pool_size_ = 4;
    const Bytes key = impl->secret;
    asio.write_req_meta_ = [key](const nuraft::asio_service::meta_cb_params& p) {
        return mac(key, p, false);
    };
    asio.read_req_meta_ = [key](const nuraft::asio_service::meta_cb_params& p,
                                const std::string& meta) {
        return mac_matches(key, p, false, meta);
    };
    asio.write_resp_meta_ = [key](const nuraft::asio_service::meta_cb_params& p) {
        return mac(key, p, true);
    };
    asio.read_resp_meta_ = [key](const nuraft::asio_service::meta_cb_params& p,
                                 const std::string& meta) {
        return mac_matches(key, p, true, meta);
    };
    asio.invoke_req_cb_on_empty_meta_ = true;
    asio.invoke_resp_cb_on_empty_meta_ = true;

    // A member not yet added waits for the leader's first heartbeat instead
    // of electing itself the leader of a cluster of one.
    const bool alone = impl->state->load_config()->get_servers().size() <= 1;
    nuraft::raft_server::init_options options;
    options.skip_initial_election_timeout_ = alone && !impl->node.founder;
    Impl* raw = impl.get();
    options.raft_callback_ = [raw](nuraft::cb_func::Type type,
                                   nuraft::cb_func::Param* param) -> nuraft::cb_func::ReturnCode {
        if (raw->event &&
            (type == nuraft::cb_func::BecomeLeader || type == nuraft::cb_func::BecomeFollower)) {
            raw->event(type == nuraft::cb_func::BecomeLeader ? "cluster-leader"
                                                             : "cluster-follower",
                       "leader " + std::to_string(param != nullptr ? param->leaderId : 0));
        }
        return nuraft::cb_func::ReturnCode::Ok;
    };
    impl->raft = impl->launcher.init(impl->machine, impl->state, cs_new<RaftLogger>(impl->event),
                                     impl->node.raft_port, asio, params, options);
    if (!impl->raft) {
        return fail(Errc::unavailable, "cannot start Raft (is the Raft port free?)");
    }
    for (int i = 0; i < 200 && !impl->raft->is_initialized(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return std::unique_ptr<Cluster>(new Cluster(std::move(impl)));
}

bool Cluster::leads() const {
    return impl_->raft->is_leader();
}

std::optional<std::string> Cluster::leader_api_url() const {
    const int leader = impl_->raft->get_leader();
    if (leader < 1) {
        return std::nullopt;
    }
    const ptr<nuraft::srv_config> config = impl_->raft->get_srv_config(leader);
    if (!config || config->get_aux().empty()) {
        return std::nullopt;
    }
    return config->get_aux();
}

ClusterStatus Cluster::status() const {
    ClusterStatus out;
    out.id = impl_->node.id;
    out.leads = impl_->raft->is_leader();
    if (const int leader = impl_->raft->get_leader(); leader >= 1) {
        out.leader = leader;
    }
    out.term = impl_->raft->get_term();
    out.committed = impl_->raft->get_committed_log_idx();
    out.applied = impl_->machine->last_commit_index();
    out.ledger_size = impl_->ledger->size();
    std::vector<ptr<nuraft::srv_config>> configs;
    impl_->raft->get_srv_config_all(configs);
    for (const ptr<nuraft::srv_config>& c : configs) {
        out.members.push_back({c->get_id(), c->get_endpoint(), c->get_aux()});
    }
    return out;
}

Result<BatchResult> Cluster::submit(std::span<const ByteView> statements,
                                    std::span<const std::optional<Bytes>> vault_files,
                                    protocol::Timestamp at) {
    if (auto s = impl_->settle(); !s) {
        return std::unexpected(s.error());
    }
    cbor::Array list;
    for (const ByteView s : statements) {
        list.push_back(cbor::Value::bytes(s));
    }
    cbor::Array vaults;
    for (std::size_t i = 0; i < vault_files.size(); ++i) {
        if (vault_files[i]) {
            vaults.push_back(cbor::Value::array(
                {cbor::Value::unsigned_integer(i), cbor::Value::bytes(*vault_files[i])}));
        }
    }
    auto entry = cbor::encode(cbor::Value::array(
        {cbor::Value::unsigned_integer(entry_batch), cbor::Value::unsigned_integer(at),
         cbor::Value::unsigned_integer(impl_->ledger->size()), cbor::Value::array(std::move(list)),
         cbor::Value::array(std::move(vaults))}));
    if (!entry) {
        return std::unexpected(entry.error());
    }
    auto outcome = impl_->replicate(*entry);
    if (!outcome) {
        return std::unexpected(outcome.error());
    }
    if (auto* results = std::get_if<BatchResult>(&*outcome)) {
        return std::move(*results);
    }
    return std::unexpected(std::get<Status>(*outcome).error());
}

Result<protocol::SignedCheckpoint> Cluster::checkpoint(ledger::LogKeys log_keys) {
    if (auto s = impl_->settle(); !s) {
        return std::unexpected(s.error());
    }
    Result<ledger::Ledger::PreparedCheckpoint> prepared = fail(Errc::unavailable, "");
    {
        const std::lock_guard guard(impl_->machine->apply_mutex);
        if (!impl_->settled()) {
            return fail(Errc::unavailable, "the cluster is catching up; retry");
        }
        prepared = impl_->ledger->prepare_checkpoint(log_keys);
    }
    if (!prepared) {
        return std::unexpected(prepared.error());
    }
    const auto latest = impl_->ledger->latest_checkpoint();
    if (!prepared->commitment && latest && latest->encoded == prepared->checkpoint.encoded) {
        return prepared->checkpoint; // nothing new
    }
    auto entry = cbor::encode(cbor::Value::array(
        {cbor::Value::unsigned_integer(entry_checkpoint),
         prepared->commitment ? cbor::Value::bytes(*prepared->commitment) : cbor::Value::null(),
         cbor::Value::bytes(prepared->checkpoint.encoded)}));
    if (!entry) {
        return std::unexpected(entry.error());
    }
    auto outcome = impl_->replicate(*entry);
    if (!outcome) {
        return std::unexpected(outcome.error());
    }
    if (const auto* status = std::get_if<Status>(&*outcome); status != nullptr && !*status) {
        return std::unexpected(status->error());
    }
    return prepared->checkpoint;
}

Status Cluster::add_cosignature(ByteView cosignature, const crypto::PublicKey& witness) {
    auto entry = cbor::encode(cbor::Value::array({cbor::Value::unsigned_integer(entry_cosignature),
                                                  cbor::Value::bytes(cosignature),
                                                  protocol::encode_public_key(witness)}));
    if (!entry) {
        return std::unexpected(entry.error());
    }
    auto outcome = impl_->replicate(*entry);
    if (!outcome) {
        return std::unexpected(outcome.error());
    }
    if (const auto* status = std::get_if<Status>(&*outcome)) {
        return *status;
    }
    return {};
}

Status Cluster::add_member(const ClusterMember& member) {
    if (member.id < 1 || member.id > 1000) {
        return fail(Errc::invalid_argument, "a member's id is 1 to 1000");
    }
    const nuraft::srv_config config(member.id, 0, member.raft_endpoint, member.api_url, false);
    const auto result = impl_->raft->add_srv(config);
    if (!result->get_accepted()) {
        return std::unexpected(cluster_error(result->get_result_code()));
    }
    return {};
}

Status Cluster::remove_member(int id) {
    const auto result = impl_->raft->remove_srv(id);
    if (!result->get_accepted()) {
        return std::unexpected(cluster_error(result->get_result_code()));
    }
    return {};
}

Status Cluster::step_down() {
    if (!impl_->raft->is_leader()) {
        return fail(Errc::rejected, "this node does not lead");
    }
    impl_->raft->yield_leadership();
    return {};
}

} // namespace cexchain::node
