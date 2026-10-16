// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The HTTP API over real sockets, and replicas that copy from it.

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <memory>
#include <netinet/in.h>
#include <optional>
#include <set>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/replica.hpp>
#include <cexchain/node/server.hpp>
#include <cexchain/node/tokens.hpp>

#include "support/ledger_world.hpp"

namespace {

using namespace cexchain::test;
namespace node = cexchain::node;
using cexchain::Bytes;
using cexchain::Errc;
using json = nlohmann::json;

std::filesystem::path fresh_directory() {
    static int counter = 0;
    const auto dir =
        std::filesystem::temp_directory_path() /
        ("cexchain-api-test-" + std::to_string(::getpid()) + "-" + std::to_string(counter++));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

json parse_json(const node::http::ClientResponse& r) {
    return json::parse(r.body.begin(), r.body.end());
}

/// Runs an application on a server on a free port, in a thread.
class Running {
public:
    explicit Running(node::Application& app, node::ServerOptions o = options())
        : server_(app, std::move(o)) {
        REQUIRE(server_.listen());
        thread_ = std::thread([this] { server_.run(); });
    }
    Running(const Running&) = delete;
    Running& operator=(const Running&) = delete;
    ~Running() {
        server_.stop();
        thread_.join();
    }

    [[nodiscard]] node::Client client(std::optional<std::string> token = std::nullopt,
                                      std::optional<std::filesystem::path> ca = std::nullopt,
                                      bool tls = false) const {
        node::ClientOptions o;
        o.bearer_token = std::move(token);
        o.timeout = std::chrono::seconds(10);
        o.ca_file = std::move(ca);
        return node::Client(*node::Url::parse((tls ? "https" : "http") +
                                              std::string("://127.0.0.1:") +
                                              std::to_string(server_.port())),
                            o);
    }

    [[nodiscard]] std::uint16_t port() const { return server_.port(); }

    static node::ServerOptions options() {
        node::ServerOptions o;
        o.port = 0;
        o.request_timeout = std::chrono::seconds(5);
        return o;
    }

private:
    node::Server server_;
    std::thread thread_;
};

/// A self-signed certificate (and key) for `san`, e.g. "IP:127.0.0.1".
std::pair<std::filesystem::path, std::filesystem::path>
self_signed(const std::filesystem::path& dir, const std::string& san) {
    EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
    REQUIRE(key != nullptr);
    X509* cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), -60);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_set_pubkey(cert, key);
    X509_NAME* name = X509_get_subject_name(cert);
    const std::string cn = "cexchain test";
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509V3_CTX context;
    X509V3_set_ctx(&context, cert, cert, nullptr, nullptr, 0);
    for (const auto& [nid, value] : {std::pair{NID_subject_alt_name, san},
                                     std::pair{NID_basic_constraints, std::string("CA:TRUE")}}) {
        X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, &context, nid, value.c_str());
        REQUIRE(extension != nullptr);
        X509_add_ext(cert, extension, -1);
        X509_EXTENSION_free(extension);
    }
    REQUIRE(X509_sign(cert, key, EVP_sha256()) > 0);
    const auto cert_path = dir / "cert.pem";
    const auto key_path = dir / "key.pem";
    FILE* out = std::fopen(cert_path.c_str(), "w");
    PEM_write_X509(out, cert);
    std::fclose(out);
    out = std::fopen(key_path.c_str(), "w");
    PEM_write_PrivateKey(out, key, nullptr, nullptr, 0, nullptr, nullptr);
    std::fclose(out);
    X509_free(cert);
    EVP_PKEY_free(key);
    return {cert_path, key_path};
}

/// A ledger in a real directory, with an organization and tokens.
struct Primary {
    std::filesystem::path dir = fresh_directory();
    ledger::ManualClock clock{t0};
    ledger::SeededEntropy entropy;
    KeyPair org = key("org");
    std::shared_ptr<const KeyPair> log_key = std::make_shared<const KeyPair>(key("log"));
    protocol::Id ledger_id;
    std::string read_token;
    std::string submit_token;
    std::string admin_token;

    explicit Primary(std::uint64_t seed = 11) : entropy(seed) {
        auto fs = ledger::PosixFileSystem::open_directory(dir);
        REQUIRE(fs);
        protocol::Statement genesis;
        genesis.issued_at = t0;
        genesis.nonce = entropy.bytes<16>();
        genesis.body = protocol::GenesisBody{crypto::HashAlg::sha256, "API Org", org.public_key(),
                                             log_key->public_key()};
        auto signed_genesis =
            protocol::sign_statement(org, provider(), crypto::HashAlg::sha256, genesis);
        REQUIRE(signed_genesis);
        auto created = ledger::Ledger::create(*fs, clock, provider(), signed_genesis->encoded);
        REQUIRE(created);
        ledger_id = created->id();
        read_token = node::generate_token(entropy);
        submit_token = node::generate_token(entropy);
        admin_token = node::generate_token(entropy);
        REQUIRE(node::save_tokens(dir, {{"reader", static_cast<node::Scopes>(node::Scope::read),
                                         node::token_hash(provider(), read_token), t0},
                                        {"app", static_cast<node::Scopes>(node::Scope::submit),
                                         node::token_hash(provider(), submit_token), t0},
                                        {"ops",
                                         static_cast<node::Scopes>(node::Scope::admin) |
                                             static_cast<node::Scopes>(node::Scope::read),
                                         node::token_hash(provider(), admin_token), t0}}));
    }
    Primary(const Primary&) = delete;
    Primary& operator=(const Primary&) = delete;
    ~Primary() { std::filesystem::remove_all(dir); }

    std::unique_ptr<node::LedgerApi> api(bool read_only = false, bool public_read = false) const {
        node::ApiOptions o;
        o.directory = dir;
        o.log_keys = {log_key};
        o.read_only = read_only;
        o.public_read = public_read;
        auto opened = node::LedgerApi::open(o, provider());
        REQUIRE(opened);
        return std::move(*opened);
    }

    /// A statement by the organization registering a person.
    Bytes register_person(const std::string& name) {
        protocol::Statement s;
        s.ledger_id = ledger_id;
        s.actor_id = ledger_id;
        s.issued_at = t0 + 1;
        s.nonce = entropy.bytes<16>();
        s.body = protocol::ActorRegisterBody{protocol::ActorKind::person, name,
                                             key(name).public_key(), std::nullopt, std::nullopt};
        auto signed_statement =
            protocol::sign_statement(org, provider(), crypto::HashAlg::sha256, s);
        REQUIRE(signed_statement);
        return signed_statement->encoded;
    }
};

Bytes read_bytes(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(in), {});
}

node::http::ClientResponse post(const node::Client& c, const std::string& path, const Bytes& body) {
    auto r = c.request("POST", path, body, "application/cose");
    REQUIRE(r);
    return std::move(*r);
}

node::http::ClientResponse get(const node::Client& c, const std::string& path) {
    auto r = c.request("GET", path);
    REQUIRE(r);
    return std::move(*r);
}

/// Serves `inner`, altering one entry in /v1/entries answers: a primary (or
/// someone in between) handing out a forged history.
class Tampering final : public node::Application {
public:
    Tampering(node::Application& inner, std::uint64_t index) : inner_(&inner), index_(index) {}

    void handle(node::http::Request r, std::string peer, Respond respond) override {
        const bool entries = r.path == "/v1/entries";
        const std::uint64_t start = entries ? std::stoull(r.query.at("start")) : 0;
        inner_->handle(std::move(r), std::move(peer),
                       [this, entries, start,
                        respond = std::move(respond)](node::http::Response response) mutable {
                           if (entries && response.status == 200) {
                               tamper(response, start);
                           }
                           respond(std::move(response));
                       });
    }

private:
    /// On a server thread: no test assertions here.
    void tamper(node::http::Response& response, std::uint64_t start) const {
        auto value = cbor::decode(response.body, {.max_depth = 32, .max_items = 1u << 20});
        if (!value || value->as_array() == nullptr) {
            return;
        }
        cbor::Array entries = *value->as_array();
        if (index_ >= start && index_ < start + entries.size()) {
            Bytes altered = *entries[index_ - start].as_bytes();
            altered[altered.size() - 3] ^= 1;
            entries[index_ - start] = cbor::Value::bytes(altered);
        }
        response.body = *cbor::encode(cbor::Value::array(std::move(entries)));
    }

private:
    node::Application* inner_;
    std::uint64_t index_;
};

} // namespace

TEST_CASE("the API answers only those it should", "[node][api]") {
    Primary p;
    auto api = p.api();
    Running server(*api);
    const auto anonymous = server.client();
    const auto reader = server.client(p.read_token);
    const auto app = server.client(p.submit_token);

    CHECK(get(anonymous, "/healthz").status == 200);
    CHECK(get(anonymous, "/v1/status").status == 401);
    CHECK(get(anonymous, "/v1/consistency?old=1&new=1").status == 200);
    CHECK(get(server.client("cxt_wrong"), "/v1/status").status == 401);
    const auto status = get(reader, "/v1/status");
    REQUIRE(status.status == 200);
    CHECK(parse_json(status)["organization"] == "API Org");
    CHECK(parse_json(status)["role"] == "primary");

    // Scopes: a reader cannot submit, an app cannot read or checkpoint.
    const Bytes statement = p.register_person("alice");
    CHECK(post(reader, "/v1/statements", statement).status == 403);
    CHECK(get(app, "/v1/status").status == 403);
    CHECK(post(app, "/v1/checkpoint", {}).status == 403);

    CHECK(get(reader, "/v1/nothing").status == 404);
    // Spec v0.9 removed the routes of D-052's assets.
    CHECK(get(reader, "/v1/assets/" + std::string(64, 'a')).status == 404);
    CHECK(post(app, "/v1/assets/consents", Bytes{0xa0}).status == 404);
    CHECK(get(reader, "/v1/statements").status == 405);
    CHECK(get(reader, "/v1/entries?start=x").status == 400);
    CHECK(get(reader, "/v1/statements/zz").status == 400);

    // A read-only server refuses writes whatever the token.
    auto read_only = p.api(true);
    Running second(*read_only);
    CHECK(post(second.client(p.submit_token), "/v1/statements", statement).status == 403);

    // A public portal: the log without a token, never the vault or metrics.
    auto portal = p.api(true, true);
    Running third(*portal);
    CHECK(get(third.client(), "/v1/status").status == 200);
    CHECK(get(third.client(), "/metrics").status == 401);
    CHECK(get(third.client(), "/v1/vault/public-key").status == 401);
    CHECK(get(third.client(), "/v1/contracts/due").status == 401); // runs contracts
    CHECK(get(third.client(p.read_token), "/metrics").status == 200);
    CHECK(get(third.client(p.read_token), "/v1/contracts/due").status == 200);
}

TEST_CASE("statements, checkpoints, proofs, and evidence over HTTP", "[node][api]") {
    Primary p;
    auto api = p.api();
    Running server(*api);
    const auto reader = server.client(p.read_token);
    const auto app = server.client(p.submit_token);
    const auto ops = server.client(p.admin_token);

    const Bytes statement = p.register_person("alice");
    const auto created = post(app, "/v1/statements", statement);
    REQUIRE(created.status == 201);
    const json registration = parse_json(created);
    CHECK(registration["index"] == 1);
    CHECK(registration["newly_registered"] == true);
    // Retrying is safe.
    const auto again = post(app, "/v1/statements", statement);
    CHECK(again.status == 200);
    CHECK(parse_json(again)["newly_registered"] == false);
    // Refusals carry the reason. (A copy with another signature over the same
    // payload is the same statement, already registered: retries are safe.)
    Bytes broken = p.register_person("mallory");
    broken[broken.size() - 2] ^= 1;
    const auto refused = post(app, "/v1/statements", broken);
    CHECK(refused.status == 422);
    CHECK(parse_json(refused)["error"]["code"] == "verification_failed");
    const auto garbage = post(app, "/v1/statements", Bytes{0xd2, 0x84});
    CHECK(garbage.status == 400);

    const auto looked_up =
        get(reader, "/v1/statements/" + registration["statement_id"].get<std::string>());
    REQUIRE(looked_up.status == 200);
    CHECK(parse_json(looked_up)["index"] == 1);

    // A checkpoint (admin), then everything verifies against it.
    const auto made = post(ops, "/v1/checkpoint", {});
    REQUIRE(made.status == 200);
    const auto checkpoint = protocol::parse_checkpoint(made.body);
    REQUIRE(checkpoint);
    CHECK(protocol::verify_checkpoint(provider(), *checkpoint, p.log_key->public_key()));
    CHECK(get(server.client(), "/v1/checkpoint").body == made.body);

    const auto entries = get(reader, "/v1/entries?start=0&count=10");
    REQUIRE(entries.status == 200);
    const auto list = cbor::decode(entries.body);
    REQUIRE(list);
    REQUIRE(list->as_array()->size() == checkpoint->checkpoint.tree_size);

    const auto receipt = get(reader, "/v1/receipts/1");
    REQUIRE(receipt.status == 200);
    const auto parsed_receipt = protocol::parse_receipt(receipt.body);
    REQUIRE(parsed_receipt);
    const auto root = protocol::verify_receipt(
        provider(), *parsed_receipt, *(*list->as_array())[1].as_bytes(), p.log_key->public_key());
    REQUIRE(root);
    CHECK(*root == checkpoint->checkpoint.root);

    const auto state = get(reader, "/v1/state/" + registration["statement_id"].get<std::string>());
    REQUIRE(state.status == 200);
    CHECK(parse_json(state)["kind"] == "actor");

    const auto metrics = get(reader, "/metrics");
    const std::string text(metrics.body.begin(), metrics.body.end());
    CHECK(text.find("cexchain_log_entries 3") != std::string::npos);
    CHECK(text.find(R"(cexchain_statements_total{result="registered"} 1)") != std::string::npos);
}

TEST_CASE("the server sees what other processes write", "[node][api]") {
    Primary p;
    auto api = p.api();
    Running server(*api);
    const auto reader = server.client(p.read_token);
    CHECK(parse_json(get(reader, "/v1/status"))["size"] == 1);
    {
        // Another process (the command line, say) takes the lock and writes.
        auto lock = ledger::DirectoryLock::acquire(p.dir);
        REQUIRE(lock);
        auto fs = ledger::PosixFileSystem::open_directory(p.dir);
        auto other = ledger::Ledger::open(*fs, p.clock, provider());
        REQUIRE(other);
        REQUIRE(other->submit(p.register_person("bob")));
    }
    // At once: a read finds the ledger behind the files and waits for it.
    CHECK(parse_json(get(reader, "/v1/status"))["size"] == 2);
    // And writes after it, without losing its entry.
    CHECK(
        post(server.client(p.submit_token), "/v1/statements", p.register_person("carol")).status ==
        201);
    CHECK(parse_json(get(reader, "/v1/status"))["size"] == 3);
}

TEST_CASE("many clients at once: writes commit in groups, reads run alongside",
          "[node][api][concurrency]") {
    Primary p;
    auto api = p.api();
    auto options = Running::options();
    options.threads = 4;
    Running server(*api, options);
    constexpr std::size_t writers = 8;
    constexpr std::size_t each = 16;
    std::vector<std::vector<Bytes>> statements(writers);
    std::vector<node::Client> clients;
    for (std::size_t w = 0; w < writers; ++w) {
        for (std::size_t i = 0; i < each; ++i) {
            statements[w].push_back(p.register_person(std::format("person-{}-{}", w, i)));
        }
        clients.push_back(server.client(p.submit_token));
    }
    const auto reader = server.client(p.read_token);

    // No test assertions off the main thread: results are checked after.
    std::vector<std::vector<int>> codes(writers);
    std::vector<std::vector<std::uint64_t>> indices(writers);
    std::atomic<bool> finished = false;
    std::uint64_t reads = 0;
    std::uint64_t bad_reads = 0;
    std::thread reading([&] {
        std::uint64_t last = 0;
        while (!finished) {
            auto r = reader.request("GET", "/v1/status");
            ++reads;
            if (!r || r->status != 200) {
                ++bad_reads;
                continue;
            }
            const auto size =
                json::parse(r->body.begin(), r->body.end())["size"].get<std::uint64_t>();
            bad_reads += size < last ? 1 : 0; // never backwards
            last = size;
        }
    });
    std::vector<std::thread> writing;
    for (std::size_t w = 0; w < writers; ++w) {
        writing.emplace_back([&, w] {
            for (const Bytes& s : statements[w]) {
                auto r = clients[w].request("POST", "/v1/statements", s, "application/cose");
                codes[w].push_back(r ? r->status : 0);
                if (r && r->status == 201) {
                    indices[w].push_back(json::parse(r->body.begin(), r->body.end())["index"]);
                }
            }
        });
    }
    for (std::thread& t : writing) {
        t.join();
    }
    finished = true;
    reading.join();

    std::set<std::uint64_t> all;
    for (std::size_t w = 0; w < writers; ++w) {
        CHECK(std::ranges::all_of(codes[w], [](int c) { return c == 201; }));
        all.insert(indices[w].begin(), indices[w].end());
    }
    CHECK(all.size() == writers * each);
    CHECK(*all.begin() == 1);
    CHECK(*all.rbegin() == writers * each);
    CHECK(reads > 0);
    CHECK(bad_reads == 0);
    CHECK(parse_json(get(reader, "/v1/status"))["size"] == writers * each + 1);
    const auto metrics = get(reader, "/metrics");
    const std::string text(metrics.body.begin(), metrics.body.end());
    CHECK(text.find(std::format(R"(cexchain_statements_total{{result="registered"}} {})",
                                writers * each)) != std::string::npos);

    // Everything is durable: a fresh open sees it all.
    auto fs = ledger::PosixFileSystem::open_directory(p.dir);
    REQUIRE(fs);
    auto reopened = ledger::Ledger::open(*fs, p.clock, provider());
    REQUIRE(reopened);
    CHECK(reopened->size() == writers * each + 1);
}

/// A plain TCP connection, to drive the server byte by byte.
class Socket {
public:
    explicit Socket(std::uint16_t port) : fd_(::socket(AF_INET, SOCK_STREAM, 0)) {
        REQUIRE(fd_ >= 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        REQUIRE(::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
        REQUIRE(::connect(fd_, reinterpret_cast<const sockaddr*>(&address), sizeof address) == 0);
        const timeval wait{5, 0};
        ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
    }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    ~Socket() { ::close(fd_); }

    void send(std::string_view text) const {
        REQUIRE(::send(fd_, text.data(), text.size(), 0) == static_cast<ssize_t>(text.size()));
    }
    /// Reads until `text` ends what was read; false if the server closed or
    /// went quiet first.
    [[nodiscard]] bool read_until(std::string_view text) const {
        return read_through(text).ends_with(text);
    }
    /// Everything read until `text` ends it (or the server closed or went
    /// quiet).
    [[nodiscard]] std::string read_through(std::string_view text) const {
        std::string got;
        std::array<char, 4096> chunk{};
        while (!got.ends_with(text)) {
            const ssize_t n = ::recv(fd_, chunk.data(), chunk.size(), 0);
            if (n <= 0) {
                break;
            }
            got.append(chunk.data(), static_cast<std::size_t>(n));
        }
        return got;
    }
    /// Whether the server closes the connection (rather than the read timing
    /// out).
    [[nodiscard]] bool closed_by_server() const {
        std::array<char, 4096> chunk{};
        ssize_t n = 0;
        while ((n = ::recv(fd_, chunk.data(), chunk.size(), 0)) > 0) {
        }
        return n == 0;
    }

private:
    int fd_;
};

TEST_CASE("the server closes stalled and idle connections, never busy ones", "[node][server]") {
    Primary p;
    auto api = p.api();
    auto options = Running::options();
    options.threads = 2;
    options.request_timeout = std::chrono::seconds(1);
    options.idle_timeout = std::chrono::seconds(1);
    Running server(*api, options);
    using steady = std::chrono::steady_clock;

    // A request that never finishes arriving.
    {
        const Socket stalled(server.port());
        const auto start = steady::now();
        stalled.send("GET /healthz HTTP/1.1\r\nHost: x\r\n");
        CHECK(stalled.closed_by_server());
        const auto waited = steady::now() - start;
        CHECK(waited >= std::chrono::milliseconds(800));
        CHECK(waited < std::chrono::seconds(4));
    }
    // A kept-alive connection in use for longer than the timeouts stays open,
    // then closes once idle.
    const Socket busy(server.port());
    const auto start = steady::now();
    int answered = 0;
    while (steady::now() - start < std::chrono::milliseconds(2500)) {
        busy.send("GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
        answered += busy.read_until("ok\n") ? 1 : 0;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    CHECK(answered >= 8);
    const auto idle = steady::now();
    CHECK(busy.closed_by_server());
    CHECK(steady::now() - idle < std::chrono::seconds(4));
}

/// Answers /healthz, and drops every other request without answering.
class Forgetful final : public node::Application {
public:
    void handle(node::http::Request r, std::string, Respond respond) override {
        if (r.path == "/healthz") {
            node::http::Response ok;
            ok.content_type = "text/plain";
            ok.body = Bytes{'o', 'k', '\n'};
            respond(std::move(ok));
        }
        // Otherwise `respond` is dropped here, unanswered.
    }
};

TEST_CASE("the server sheds idle connections and stays strict", "[node][server]") {
    Forgetful app;
    auto options = Running::options();
    options.threads = 2;
    options.max_connections = 2;
    options.header_timeout = std::chrono::seconds(1);
    Running server(app, options);

    SECTION("a full server lets its longest-idle connection go") {
        const Socket idle_a(server.port());
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const Socket idle_b(server.port());
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const Socket active(server.port());
        active.send("GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
        CHECK(active.read_until("ok\n"));
        CHECK(idle_a.closed_by_server());
    }
    SECTION("a new connection that says nothing is closed soon") {
        const Socket silent(server.port());
        const auto start = std::chrono::steady_clock::now();
        CHECK(silent.closed_by_server());
        CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(4));
    }
    SECTION("HEAD has no body, so the next response is read right") {
        const Socket s(server.port());
        s.send("HEAD /healthz HTTP/1.1\r\nHost: x\r\n\r\n"
               "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
        const std::string got = s.read_through("\r\n\r\nok\n");
        // The HEAD answer's headers, then at once the GET answer: no body
        // between them.
        CHECK(got.starts_with("HTTP/1.1 200 OK\r\n"));
        CHECK(got.contains("Content-Length: 3\r\nConnection: keep-alive\r\n\r\nHTTP/1.1 200 OK"));
        CHECK(got.ends_with("\r\n\r\nok\n"));
    }
    SECTION("an unanswered request gets a 500, not silence") {
        const Socket s(server.port());
        s.send("GET /forgotten HTTP/1.1\r\nHost: x\r\n\r\n");
        CHECK(s.read_until("never answered\"}}"));
    }
    SECTION("two Connection fields are refused") {
        const Socket s(server.port());
        s.send("GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n"
               "Connection: close\r\n\r\n");
        CHECK(s.read_until("repeated Connection\"}}"));
    }
}

TEST_CASE("connections can be capped per peer address", "[node][server]") {
    Forgetful app;
    auto options = Running::options();
    options.max_connections_per_peer = 1;
    Running server(app, options);
    const Socket first(server.port());
    first.send("GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
    REQUIRE(first.read_until("ok\n"));
    const Socket second(server.port());
    CHECK(second.read_until("too many connections\"}}"));
}

TEST_CASE("a replica copies over HTTP and refuses a forged history", "[node][replica]") {
    Primary p;
    auto api = p.api();
    Running server(*api);
    const auto app = server.client(p.submit_token);
    const auto ops = server.client(p.admin_token);
    REQUIRE(post(app, "/v1/statements", p.register_person("alice")).status == 201);
    REQUIRE(post(ops, "/v1/checkpoint", {}).status == 200);
    REQUIRE(post(app, "/v1/statements", p.register_person("bob")).status == 201);

    const auto replica_dir = fresh_directory();
    {
        ledger::MemoryFileSystem fs;
        ledger::ManualClock clock(t0);
        const auto reader = server.client(p.read_token);
        auto replica = node::create_replica(reader, fs, clock, provider());
        REQUIRE(replica);
        auto report = node::sync_replica(reader, *replica, replica_dir);
        REQUIRE(report);
        CHECK(report->checkpoints == 1);
        // Up to the checkpoint (genesis, alice, its state commitment): bob,
        // whom no checkpoint covers yet, waits.
        CHECK(replica->size() == 3);
        CHECK(api->ledger().size() == 4);
        CHECK(*replica->root(3) == *api->ledger().root(3));

        // A checkpoint on the primary; the next sync takes just what it adds.
        REQUIRE(post(ops, "/v1/checkpoint", {}).status == 200);
        report = node::sync_replica(reader, *replica, replica_dir);
        REQUIRE(report);
        CHECK(report->entries == 2); // bob and the new state commitment
        CHECK(report->checkpoints == 1);
        CHECK(replica->size() == api->ledger().size());
        CHECK(replica->latest_checkpoint()->encoded == api->ledger().latest_checkpoint()->encoded);

        // A token that was revoked, or never was.
        const auto stranger = server.client("cxt_nobody");
        CHECK(node::sync_replica(stranger, *replica, replica_dir).error().code == Errc::rejected);
    }
    {
        // Through a primary that alters entry 2: the entries no longer lead
        // to the signed root, so none of them is taken.
        Tampering tampering(*api, 2);
        Running forged(tampering);
        const auto reader = forged.client(p.read_token);
        ledger::MemoryFileSystem fs;
        ledger::ManualClock clock(t0);
        auto replica = node::create_replica(reader, fs, clock, provider());
        REQUIRE(replica);
        const auto report = node::sync_replica(reader, *replica, replica_dir);
        REQUIRE_FALSE(report);
        CHECK(report.error().code == Errc::verification_failed);
        CHECK(replica->size() == 1);
    }
    {
        // A replica of another ledger is refused outright.
        Primary other(12);
        auto other_api = other.api();
        Running elsewhere(*other_api);
        ledger::MemoryFileSystem fs;
        ledger::ManualClock clock(t0);
        auto replica = node::create_replica(server.client(p.read_token), fs, clock, provider());
        REQUIRE(replica);
        CHECK(node::sync_replica(elsewhere.client(other.read_token), *replica, replica_dir)
                  .error()
                  .code == Errc::verification_failed);
        // And pinned at creation, it is never started.
        ledger::MemoryFileSystem pinned;
        CHECK(node::create_replica(elsewhere.client(other.read_token), pinned, clock, provider(),
                                   p.ledger_id)
                  .error()
                  .code == Errc::verification_failed);
    }
    std::filesystem::remove_all(replica_dir);
}

TEST_CASE("TLS: the server's certificate must be trusted and name it", "[node][api][tls]") {
    Primary p;
    auto api = p.api();
    const auto dir = fresh_directory();
    const auto [cert, key] = self_signed(dir, "IP:127.0.0.1");
    auto options = Running::options();
    options.tls_certificate = cert;
    options.tls_private_key = key;
    Running server(*api, options);

    const auto trusted = server.client(p.read_token, cert, true).request("GET", "/v1/status");
    REQUIRE(trusted);
    CHECK(trusted->status == 200);
    // Not trusted: the system's CAs never signed it.
    const auto untrusted =
        server.client(p.read_token, std::nullopt, true).request("GET", "/healthz");
    REQUIRE_FALSE(untrusted);
    CHECK(untrusted.error().code == Errc::verification_failed);
    // Plain HTTP to a TLS port fails rather than talking in the clear.
    CHECK_FALSE(server.client().request("GET", "/healthz"));

    // Trusted, but for another name.
    const auto other_dir = fresh_directory();
    const auto [other_cert, other_key] = self_signed(other_dir, "DNS:ledger.example.com");
    auto other_options = Running::options();
    other_options.tls_certificate = other_cert;
    other_options.tls_private_key = other_key;
    Running elsewhere(*api, other_options);
    const auto wrong_name =
        elsewhere.client(p.read_token, other_cert, true).request("GET", "/healthz");
    REQUIRE_FALSE(wrong_name);
    CHECK(wrong_name.error().code == Errc::verification_failed);

    // A key that does not match its certificate is refused at startup.
    node::ServerOptions mismatched = Running::options();
    mismatched.tls_certificate = cert;
    mismatched.tls_private_key = other_key;
    node::Server broken(*api, mismatched);
    CHECK(broken.listen().error().code == Errc::invalid_argument);
    std::filesystem::remove_all(dir);
    std::filesystem::remove_all(other_dir);
}

TEST_CASE("a record's private data arrives with it, and is kept once", "[node][api][vault]") {
    Primary p;
    std::filesystem::create_directories(p.dir / "vault" / "records");
    {
        std::ofstream(p.dir / "vault" / "vault.pub") << "key";
    }
    auto api = p.api();
    Running server(*api);
    const auto app = server.client(p.submit_token);

    auto record = [&](std::uint8_t seed) {
        protocol::Statement s;
        s.ledger_id = p.ledger_id;
        s.actor_id = p.ledger_id;
        s.issued_at = t0 + 1;
        s.nonce = p.entropy.bytes<16>();
        s.body = protocol::RecordRegisterBody{
            "example.document/1", Bytes(32, seed), 1, {}, std::nullopt};
        return protocol::sign_statement(p.org, provider(), crypto::HashAlg::sha256, s);
    };
    auto sealed = [](std::uint8_t fill) {
        return *cbor::encode(cbor::Value::map(
            {{cbor::Value::integer(1), cbor::Value::unsigned_integer(1)},
             {cbor::Value::integer(2), cbor::Value::array({cbor::Value::unsigned_integer(32),
                                                           cbor::Value::unsigned_integer(1),
                                                           cbor::Value::unsigned_integer(2)})},
             {cbor::Value::integer(3), cbor::Value::bytes(Bytes(32, fill))},
             {cbor::Value::integer(4), cbor::Value::bytes(Bytes(64, fill))}}));
    };
    auto send = [&](const Bytes& statement, const Bytes& vault) {
        const Bytes body = *cbor::encode(
            cbor::Value::map({{cbor::Value::integer(1), cbor::Value::bytes(statement)},
                              {cbor::Value::integer(2), cbor::Value::bytes(vault)}}));
        auto r = app.request("POST", "/v1/statements", body, node::submission_content_type);
        REQUIRE(r);
        return std::move(*r);
    };

    const auto first = record(1);
    REQUIRE(first);
    CHECK(send(first->encoded, sealed(7)).status == 201);
    const auto file = p.dir / "vault" / "records" / (cexchain::to_hex(first->id.bytes()) + ".cbor");
    REQUIRE(std::filesystem::exists(file));
    // A retry with the same data is fine; other data for it is refused.
    CHECK(send(first->encoded, sealed(7)).status == 200);
    const auto swapped = send(first->encoded, sealed(8));
    CHECK(swapped.status == 409);
    CHECK(read_bytes(file) == sealed(7));

    // Only a record's registration carries private data, and only sealed.
    CHECK(send(p.register_person("alice"), sealed(7)).status == 400);
    const auto second = record(2);
    REQUIRE(second);
    CHECK(send(second->encoded, Bytes{0xa0}).status == 400);
    CHECK_FALSE(std::filesystem::exists(p.dir / "vault" / "records" /
                                        (cexchain::to_hex(second->id.bytes()) + ".cbor")));
}
