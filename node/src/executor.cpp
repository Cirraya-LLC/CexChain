// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <asio/ip/address.hpp>
#include <deque>
#include <fcntl.h>
#include <format>
#include <random>
#include <set>
#include <sys/file.h>
#include <thread>
#include <unistd.h>
#include <utility>

#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/node/executor.hpp>
#include <cexchain/node/process.hpp>

#include "files.hpp"
#include "json_cbor.hpp"

namespace cexchain::node::executor {

namespace {

using detail::json;
using namespace std::chrono_literals;

constexpr std::uint64_t max_connector_timeout = 300;
constexpr std::uint64_t max_backoff_ms = 300'000;

std::string hex(const protocol::Id& id) {
    return to_hex(id.bytes());
}

std::string hex(ByteView bytes) {
    return to_hex(bytes);
}

std::optional<Bytes> unhex(const json& v) {
    if (!v.is_string()) {
        return std::nullopt;
    }
    auto bytes = from_hex(v.get_ref<const std::string&>());
    return bytes ? std::optional<Bytes>(std::move(*bytes)) : std::nullopt;
}

std::string dump(const json& j, int indent = -1) {
    return j.dump(indent, ' ', false, json::error_handler_t::replace);
}

using Fail = std::unexpected<std::string>;

std::expected<std::vector<std::string>, std::string> names_of(const json& entry,
                                                              std::string_view key) {
    std::vector<std::string> out;
    const auto it = entry.find(key);
    if (it == entry.end()) {
        return out;
    }
    if (!it->is_array()) {
        return Fail(std::format("{} is a list of names", key));
    }
    for (const json& n : *it) {
        if (!n.is_string() || !connector::is_name(n.get_ref<const std::string&>())) {
            return Fail(std::format("{} is a list of names (letters, digits, '.', '-', '_')", key));
        }
        out.push_back(n.get<std::string>());
    }
    return out;
}

std::expected<ConnectorConfig, std::string> connector_of(const json& entry) {
    ConnectorConfig c;
    if (!entry.is_object()) {
        return Fail("each connector is a JSON object");
    }
    const auto name = entry.find("name");
    if (name == entry.end() || !name->is_string() ||
        !connector::is_name(name->get_ref<const std::string&>())) {
        return Fail("each connector has a name (letters, digits, '.', '-', '_')");
    }
    c.name = name->get<std::string>();
    auto bad = [&](std::string_view why) {
        return Fail(std::format("connector {}: {}", c.name, why));
    };
    const auto type = entry.find("type");
    if (type == entry.end() || !type->is_string() ||
        (*type != "webhook" && *type != "command" && *type != "program")) {
        return bad("its type is webhook, command, or program");
    }
    c.type = type->get<std::string>();
    const auto kinds = entry.find("kinds");
    if (kinds == entry.end() || !kinds->is_array() || kinds->empty()) {
        return bad("it names the request kinds it serves");
    }
    for (const json& k : *kinds) {
        if (!k.is_string() || !protocol::is_request_kind(k.get_ref<const std::string&>())) {
            return bad("kinds are request kinds ([a-z][a-z0-9._-]*)");
        }
        c.kinds.push_back(k.get<std::string>());
    }
    std::ranges::sort(c.kinds);
    c.kinds.erase(std::ranges::unique(c.kinds).begin(), c.kinds.end());
    if (const auto contracts = entry.find("contracts"); contracts != entry.end()) {
        if (!contracts->is_array()) {
            return bad("contracts is a list of contract ids");
        }
        for (const json& id : *contracts) {
            const auto parsed = id.is_string()
                                    ? detail::id_from_hex(id.get_ref<const std::string&>())
                                    : std::nullopt;
            if (!parsed) {
                return bad("contracts are ids of 64 hex digits");
            }
            c.contracts.push_back(*parsed);
        }
    }
    if (const auto t = entry.find("timeout"); t != entry.end()) {
        if (!t->is_number_unsigned() || t->get<std::uint64_t>() == 0 ||
            t->get<std::uint64_t>() > max_connector_timeout) {
            return bad("its timeout is 1 to 300 seconds");
        }
        c.timeout = std::chrono::seconds(t->get<std::uint64_t>());
    }
    auto secrets = names_of(entry, "secrets");
    if (!secrets) {
        return bad(secrets.error());
    }
    json config = json::object();
    config["timeout"] = c.timeout.count();
    if (c.type == "webhook") {
        const auto url = entry.find("url");
        const auto secret = entry.find("secret");
        if (url == entry.end() || !url->is_string()) {
            return bad("a webhook has a url");
        }
        if (secret == entry.end() || !secret->is_string() ||
            !connector::is_name(secret->get_ref<const std::string&>())) {
            return bad("a webhook names its secret, the key it signs with");
        }
        auto parsed = Url::parse(url->get<std::string>());
        if (!parsed) {
            return bad(std::format("its url: {}", parsed.error().detail));
        }
        asio::error_code not_an_address;
        const auto address = asio::ip::make_address(parsed->host, not_an_address);
        const bool loopback =
            parsed->host == "localhost" || (!not_an_address && address.is_loopback());
        if (!parsed->tls && !loopback) {
            return bad("a webhook's url is https:// (http:// only to this computer: 127.0.0.1, "
                       "::1, localhost)");
        }
        config["url"] = *url;
        config["secret"] = *secret;
        c.secrets = {secret->get<std::string>()};
        if (const auto ca = entry.find("ca_file"); ca != entry.end()) {
            if (!ca->is_string()) {
                return bad("ca_file is a file name");
            }
            config["ca_file"] = *ca;
        }
    } else {
        const auto program = entry.find("program");
        if (program == entry.end() || !program->is_string() ||
            program->get_ref<const std::string&>().empty()) {
            return bad("it names its program");
        }
        std::vector<std::string> args;
        if (const auto a = entry.find("args"); a != entry.end()) {
            if (!a->is_array() ||
                !std::ranges::all_of(*a, [](const json& x) { return x.is_string(); })) {
                return bad("args is a list of texts");
            }
            args = a->get<std::vector<std::string>>();
        }
        c.secrets = *secrets;
        if (c.type == "command") {
            config["program"] = *program;
            config["args"] = args;
            config["secrets"] = c.secrets;
        } else {
            c.program = program->get<std::string>();
            c.arguments = std::move(args);
            if (const auto own = entry.find("config"); own != entry.end()) {
                if (!own->is_object()) {
                    return bad("its config is a JSON object");
                }
                config = *own;
            } else {
                config = json::object();
            }
        }
    }
    c.config = dump(config);
    return c;
}

/// Both serve a kind on the same contracts. A connector for some contracts
/// takes them over from one for any contract.
bool overlap(const ConnectorConfig& a, const ConnectorConfig& b) {
    if (a.contracts.empty() || b.contracts.empty()) {
        return a.contracts.empty() && b.contracts.empty();
    }
    return std::ranges::any_of(
        a.contracts, [&](const protocol::Id& c) { return std::ranges::contains(b.contracts, c); });
}

json connector_json(const ConnectorConfig& c) {
    json o = {{"name", c.name}, {"type", c.type}, {"kinds", c.kinds}};
    if (!c.contracts.empty()) {
        json contracts = json::array();
        for (const auto& id : c.contracts) {
            contracts.push_back(hex(id));
        }
        o["contracts"] = std::move(contracts);
    }
    o["timeout"] = c.timeout.count();
    const json config = json::parse(c.config, nullptr, false);
    if (c.type == "program") {
        o["program"] = c.program;
        o["args"] = c.arguments;
        o["secrets"] = c.secrets;
        o["config"] = config.is_object() ? config : json::object();
    } else if (config.is_object()) {
        for (const auto& [key, value] : config.items()) {
            if (key != "timeout") {
                o[key] = value;
            }
        }
    }
    return o;
}

} // namespace

// ---- config -------------------------------------------------------------

const ConnectorConfig* Config::route(const protocol::Id& contract, std::string_view kind) const {
    const ConnectorConfig* any = nullptr;
    for (const ConnectorConfig& c : connectors) {
        if (!std::ranges::contains(c.kinds, kind)) {
            continue;
        }
        if (std::ranges::contains(c.contracts, contract)) {
            return &c;
        }
        if (c.contracts.empty()) {
            any = &c;
        }
    }
    return any;
}

std::vector<std::string> Config::kinds() const {
    std::vector<std::string> out;
    for (const ConnectorConfig& c : connectors) {
        out.insert(out.end(), c.kinds.begin(), c.kinds.end());
    }
    std::ranges::sort(out);
    out.erase(std::ranges::unique(out).begin(), out.end());
    return out;
}

std::expected<Config, std::string> parse_config(std::string_view text) {
    const auto parsed = detail::parse_integral_json(text);
    if (!parsed || !parsed->is_object()) {
        return Fail("the config is not a JSON object (numbers are integers)");
    }
    const json& o = *parsed;
    if (const auto v = o.find("version"); v != o.end() && *v != 1) {
        return Fail("the config's version is 1");
    }
    Config config;
    for (const auto& [key, target] :
         {std::pair{"ledger_id", &config.ledger}, std::pair{"actor", &config.actor},
          std::pair{"delegation", &config.delegation}}) {
        const auto it = o.find(key);
        const auto id = it != o.end() && it->is_string()
                            ? detail::id_from_hex(it->get_ref<const std::string&>())
                            : std::nullopt;
        if (!id) {
            return Fail(std::format("the config names {} (64 hex digits)", key));
        }
        *target = *id;
    }
    for (const auto& [key, target] :
         {std::pair{"model", &config.model}, std::pair{"model_version", &config.model_version}}) {
        if (const auto it = o.find(key); it != o.end() && !it->is_null()) {
            if (!it->is_string() || it->get_ref<const std::string&>().empty()) {
                return Fail(std::format("{} is a text", key));
            }
            *target = it->get<std::string>();
        }
    }
    if (const auto list = o.find("connectors"); list != o.end()) {
        if (!list->is_array()) {
            return Fail("connectors is a list");
        }
        for (const json& entry : *list) {
            auto c = connector_of(entry);
            if (!c) {
                return Fail(c.error());
            }
            for (const ConnectorConfig& other : config.connectors) {
                if (other.name == c->name) {
                    return Fail(std::format("two connectors are named {}", c->name));
                }
                for (const std::string& kind : c->kinds) {
                    if (std::ranges::contains(other.kinds, kind) && overlap(other, *c)) {
                        return Fail(std::format("connectors {} and {} both serve {} on the same "
                                                "contracts",
                                                other.name, c->name, kind));
                    }
                }
            }
            config.connectors.push_back(std::move(*c));
        }
    }
    return config;
}

std::string config_text(const Config& config) {
    json o = {{"version", 1},
              {"ledger_id", hex(config.ledger)},
              {"actor", hex(config.actor)},
              {"delegation", hex(config.delegation)}};
    if (config.model) {
        o["model"] = *config.model;
    }
    if (config.model_version) {
        o["model_version"] = *config.model_version;
    }
    json list = json::array();
    for (const ConnectorConfig& c : config.connectors) {
        list.push_back(connector_json(c));
    }
    o["connectors"] = std::move(list);
    return dump(o, 2) + "\n";
}

// ---- the journal ----------------------------------------------------------

std::string_view stage_name(Stage stage) noexcept {
    switch (stage) {
    case Stage::seen:
        return "seen";
    case Stage::unverified:
        return "unverified";
    case Stage::verified:
        return "verified";
    case Stage::acting:
        return "acting";
    case Stage::outcome:
        return "outcome";
    case Stage::answering:
        return "answering";
    case Stage::answered:
        return "answered";
    case Stage::closed:
        return "closed";
    }
    return "seen";
}

bool is_final(Stage stage) noexcept {
    return stage == Stage::answered || stage == Stage::closed;
}

std::string entry_text(const JournalEntry& e) {
    json o = {{"request", hex(e.request)},
              {"instance", hex(e.instance)},
              {"contract", e.contract ? json(hex(*e.contract)) : json(nullptr)},
              {"kind", e.kind},
              {"reply", e.reply},
              {"connector", e.connector},
              {"params", hex(e.params)},
              {"deadline", e.deadline},
              {"asked_at", e.asked_at},
              {"stage", std::string(stage_name(e.stage))},
              {"attempts", e.attempts},
              {"failures", e.failures},
              {"next_at", e.next_at},
              {"first_seen", e.first_seen},
              {"updated", e.updated},
              {"note", e.note}};
    auto put_bytes = [&](const char* key, const std::optional<Bytes>& v) {
        o[key] = v ? json(hex(*v)) : json(nullptr);
    };
    o["status"] = e.status ? json(*e.status) : json(nullptr);
    put_bytes("result", e.result);
    o["reason"] = e.reason ? json(*e.reason) : json(nullptr);
    put_bytes("response", e.response);
    put_bytes("salt", e.salt);
    put_bytes("digest", e.digest);
    put_bytes("statement", e.statement);
    o["statement_id"] = e.statement_id ? json(hex(*e.statement_id)) : json(nullptr);
    o["head"] = e.head ? json(*e.head) : json(nullptr);
    o["index"] = e.index ? json(*e.index) : json(nullptr);
    o["answered_status"] = e.answered_status ? json(*e.answered_status) : json(nullptr);
    o["answered_by"] = e.answered_by ? json(hex(*e.answered_by)) : json(nullptr);
    return dump(o, 2) + "\n";
}

std::optional<JournalEntry> parse_entry(std::string_view text) {
    const auto parsed = detail::parse_integral_json(text);
    if (!parsed || !parsed->is_object()) {
        return std::nullopt;
    }
    const json& o = *parsed;
    JournalEntry e;
    auto id = [&](const char* key) -> std::optional<protocol::Id> {
        const auto it = o.find(key);
        return it != o.end() && it->is_string()
                   ? detail::id_from_hex(it->get_ref<const std::string&>())
                   : std::nullopt;
    };
    auto text_of = [&](const char* key) -> std::optional<std::string> {
        const auto it = o.find(key);
        return it != o.end() && it->is_string() ? std::optional(it->get<std::string>())
                                                : std::nullopt;
    };
    auto number = [&](const char* key) -> std::uint64_t {
        const auto it = o.find(key);
        return it != o.end() && it->is_number_unsigned() ? it->get<std::uint64_t>() : 0;
    };
    auto bytes = [&](const char* key) -> std::optional<Bytes> {
        const auto it = o.find(key);
        return it != o.end() ? unhex(*it) : std::nullopt;
    };
    const auto request = id("request");
    const auto instance = id("instance");
    if (!request || !instance) {
        return std::nullopt;
    }
    e.request = *request;
    e.instance = *instance;
    e.contract = id("contract");
    e.kind = text_of("kind").value_or("");
    e.reply = text_of("reply").value_or("");
    e.connector = text_of("connector").value_or("");
    e.params = bytes("params").value_or(Bytes{});
    e.deadline = number("deadline");
    e.asked_at = number("asked_at");
    const std::string stage = text_of("stage").value_or("");
    bool known = false;
    for (const Stage s : {Stage::seen, Stage::unverified, Stage::verified, Stage::acting,
                          Stage::outcome, Stage::answering, Stage::answered, Stage::closed}) {
        if (stage_name(s) == stage) {
            e.stage = s;
            known = true;
        }
    }
    if (!known) {
        return std::nullopt;
    }
    e.attempts = static_cast<std::uint32_t>(std::min<std::uint64_t>(number("attempts"), 1u << 30));
    e.failures = static_cast<std::uint32_t>(std::min<std::uint64_t>(number("failures"), 1u << 30));
    e.next_at = number("next_at");
    e.first_seen = number("first_seen");
    e.updated = number("updated");
    e.note = text_of("note").value_or("");
    e.status = text_of("status");
    e.result = bytes("result");
    e.reason = text_of("reason");
    e.response = bytes("response");
    e.salt = bytes("salt");
    e.digest = bytes("digest");
    e.statement = bytes("statement");
    e.statement_id = id("statement_id");
    if (const auto it = o.find("head"); it != o.end() && it->is_number_unsigned()) {
        e.head = it->get<std::uint64_t>();
    }
    if (const auto it = o.find("index"); it != o.end() && it->is_number_unsigned()) {
        e.index = it->get<std::uint64_t>();
    }
    e.answered_status = text_of("answered_status");
    e.answered_by = id("answered_by");
    return e;
}

Journal::Journal(std::filesystem::path state) : state_(std::move(state)) {}

std::vector<JournalEntry> Journal::entries() const {
    std::vector<JournalEntry> out;
    std::error_code ec;
    const auto dir = state_ / "journal";
    for (const auto& file : std::filesystem::directory_iterator(dir, ec)) {
        if (file.path().extension() != ".json") {
            continue;
        }
        const auto bytes = detail::read_file(file.path());
        if (!bytes) {
            continue;
        }
        if (auto e = parse_entry(
                std::string_view(reinterpret_cast<const char*>(bytes->data()), bytes->size()))) {
            out.push_back(std::move(*e));
        }
    }
    std::ranges::sort(out, [](const JournalEntry& a, const JournalEntry& b) {
        if (a.first_seen != b.first_seen) {
            return a.first_seen < b.first_seen;
        }
        return std::ranges::lexicographical_compare(a.request.bytes(), b.request.bytes());
    });
    return out;
}

std::optional<JournalEntry> Journal::find(const protocol::Id& request) const {
    const auto bytes = detail::read_file(state_ / "journal" / (hex(request) + ".json"));
    if (!bytes) {
        return std::nullopt;
    }
    return parse_entry(
        std::string_view(reinterpret_cast<const char*>(bytes->data()), bytes->size()));
}

Status Journal::save(const JournalEntry& entry) const {
    std::error_code ec;
    std::filesystem::create_directories(state_ / "journal", ec);
    std::filesystem::permissions(state_ / "journal", std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
    const std::string text = entry_text(entry);
    return detail::write_file(state_ / "journal" / (hex(entry.request) + ".json"),
                              as_bytes(std::string_view(text)), true);
}

std::uint64_t Journal::cursor(std::string_view server) const {
    const auto bytes = detail::read_file(state_ / "cursor.json");
    if (!bytes) {
        return 0;
    }
    const auto parsed = detail::parse_integral_json(
        std::string_view(reinterpret_cast<const char*>(bytes->data()), bytes->size()));
    if (!parsed || !parsed->is_object() || !parsed->contains("server") ||
        (*parsed)["server"] != server || !(*parsed)["after"].is_number_unsigned()) {
        return 0;
    }
    return (*parsed)["after"].get<std::uint64_t>();
}

Status Journal::save_cursor(std::string_view server, std::uint64_t cursor) const {
    const std::string text = dump({{"server", server}, {"after", cursor}}) + "\n";
    return detail::write_file(state_ / "cursor.json", as_bytes(std::string_view(text)), true);
}

cbor::Value answer_arguments(const JournalEntry& e) {
    cbor::Map entries;
    if (e.result) {
        if (auto value = cbor::decode(*e.result)) {
            entries.push_back({cbor::Value::text("result"), std::move(*value)});
        }
    }
    if (e.status == "failed") {
        entries.push_back(
            {cbor::Value::text("reason"), cbor::Value::text(e.reason.value_or("rejected"))});
    }
    if (e.digest) {
        entries.push_back({cbor::Value::text("response"), cbor::Value::bytes(*e.digest)});
    }
    return entries.empty() ? cbor::Value::null() : cbor::Value::map(std::move(entries));
}

// ---- channels -------------------------------------------------------------

namespace {

class ProcessChannel final : public Channel {
public:
    explicit ProcessChannel(ChildProcess child) : child_(std::move(child)) {}
    Status send(std::string_view line) override { return child_.write(line, 10s); }
    Result<std::optional<std::string>> receive(std::chrono::milliseconds timeout) override {
        return child_.read_line(timeout, connector::max_line);
    }
    void close() override {
        child_.close_input();
        (void)child_.terminate(2s);
    }

private:
    ChildProcess child_;
};

class LocalChannel final : public Channel {
public:
    explicit LocalChannel(connector::PerformerFactory make) : make_(std::move(make)) {}
    Status send(std::string_view line) override {
        if (closed_) {
            return fail(Errc::unavailable, "the connector stopped");
        }
        auto message = connector::decode_to_connector(line);
        if (!message) {
            return {};
        }
        if (auto* hello = std::get_if<connector::Hello>(&*message)) {
            std::string error;
            performer_ = make_(*hello, error);
            if (!performer_) {
                out_.push_back(connector::encode(connector::FromConnector(
                    connector::Log{connector::LogLevel::error, error, std::nullopt})));
                closed_ = true;
                return {};
            }
            out_.push_back(connector::encode(connector::FromConnector(connector::Ready{
                connector::protocol_version, "local", "test", performer_->kinds()})));
        } else if (const auto* perform = std::get_if<connector::Perform>(&*message)) {
            if (performer_) {
                out_.push_back(
                    connector::encode(connector::FromConnector(performer_->perform(*perform))));
            }
        } else if (std::holds_alternative<connector::Stop>(*message)) {
            closed_ = true;
        }
        return {};
    }
    Result<std::optional<std::string>> receive(std::chrono::milliseconds) override {
        if (!out_.empty()) {
            std::string line = std::move(out_.front());
            out_.pop_front();
            return std::optional<std::string>(std::move(line));
        }
        if (closed_) {
            return fail(Errc::unavailable, "the connector stopped");
        }
        return std::optional<std::string>();
    }
    void close() override { closed_ = true; }

private:
    connector::PerformerFactory make_;
    std::unique_ptr<connector::Performer> performer_;
    std::deque<std::string> out_;
    bool closed_ = false;
};

} // namespace

ChannelFactory process_channels(std::string self) {
    return [self = std::move(self)](const ConnectorConfig& c) -> Result<std::unique_ptr<Channel>> {
        auto child = c.type == "program" ? ChildProcess::start(c.program, c.arguments)
                                         : ChildProcess::start(self, {"connector", c.type});
        if (!child) {
            return std::unexpected(child.error());
        }
        return std::make_unique<ProcessChannel>(std::move(*child));
    };
}

ChannelFactory local_channels(connector::PerformerFactory make) {
    return [make = std::move(make)](const ConnectorConfig&) -> Result<std::unique_ptr<Channel>> {
        return std::make_unique<LocalChannel>(make);
    };
}

std::expected<Opened, std::string>
open_connector(const ConnectorConfig& config, const ChannelFactory& channels,
               const std::map<std::string, SecureBytes>& secrets,
               const std::function<void(const connector::Log&)>& on_log) {
    auto channel = channels(config);
    if (!channel) {
        return Fail(
            std::format("connector {} does not start: {}", config.name, channel.error().detail));
    }
    connector::Hello hello;
    hello.connector = config.name;
    hello.config = config.config;
    for (const std::string& name : config.secrets) {
        const auto secret = secrets.find(name);
        if (secret == secrets.end()) {
            (*channel)->close();
            return Fail(std::format("connector {} needs the secret {}: executor secret set {}",
                                    config.name, name, name));
        }
        const ByteView v = secret->second.view();
        hello.secrets[name] = connector::Secret{SecureBytes(Bytes(v.begin(), v.end()))};
    }
    std::string line = connector::encode(connector::ToConnector(std::move(hello)));
    const auto sent = (*channel)->send(line);
    secure_wipe(std::span(reinterpret_cast<std::uint8_t*>(line.data()), line.size()));
    std::string last_log;
    const auto until = std::chrono::steady_clock::now() + 10s;
    while (sent && std::chrono::steady_clock::now() < until) {
        auto received = (*channel)->receive(std::chrono::duration_cast<std::chrono::milliseconds>(
            until - std::chrono::steady_clock::now()));
        if (!received) {
            break;
        }
        if (!*received) {
            continue;
        }
        auto message = connector::decode_from_connector(**received);
        if (!message) {
            continue;
        }
        if (const auto* log = std::get_if<connector::Log>(&*message)) {
            last_log = log->message;
            if (on_log) {
                on_log(*log);
            }
        } else if (auto* ready = std::get_if<connector::Ready>(&*message)) {
            if (ready->protocol != connector::protocol_version) {
                (*channel)->close();
                return Fail(std::format("connector {} speaks protocol {}, not {}", config.name,
                                        ready->protocol, connector::protocol_version));
            }
            for (const std::string& kind : config.kinds) {
                if (!ready->kinds.empty() && !std::ranges::contains(ready->kinds, kind)) {
                    (*channel)->close();
                    return Fail(std::format("connector {} does not serve {}", config.name, kind));
                }
            }
            return Opened{std::move(*channel), std::move(*ready)};
        }
    }
    (*channel)->close();
    return Fail(std::format("connector {} did not start{}", config.name,
                            last_log.empty() ? std::string() : ": " + last_log));
}

// ---- the runtime ------------------------------------------------------------

namespace {

/// A failure on the ledger's side: transient (try again later) or not.
struct Trouble {
    bool transient = true;
    std::string message;
};

/// The state directory's lock: one copy per directory.
class StateLock {
public:
    explicit StateLock(const std::filesystem::path& state) {
        fd_ = ::open((state / "lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        held_ = fd_ >= 0 && ::flock(fd_, LOCK_EX | LOCK_NB) == 0;
    }
    StateLock(const StateLock&) = delete;
    StateLock& operator=(const StateLock&) = delete;
    ~StateLock() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }
    [[nodiscard]] bool held() const noexcept { return held_; }

private:
    int fd_ = -1;
    bool held_ = false;
};

class Runtime {
public:
    Runtime(const Config& config, RunOptions& options)
        : config_(config), options_(options), journal_(options.state),
          url_(*Url::parse(options.server)), client_(url_, options.client),
          poller_(url_, polling(options)) {}

    std::expected<void, std::string> run();

private:
    struct Connector {
        const ConnectorConfig* config = nullptr;
        std::unique_ptr<Channel> channel;
    };

    static ClientOptions polling(const RunOptions& options) {
        ClientOptions o = options.client;
        o.stop = options.stop;
        o.timeout = options.wait + 15s;
        return o;
    }

    [[nodiscard]] protocol::Timestamp now() const {
        return options_.now ? options_.now() : ledger_now();
    }
    static protocol::Timestamp ledger_now() {
        return static_cast<protocol::Timestamp>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
    }
    [[nodiscard]] bool stopping() const {
        return options_.stop != nullptr && options_.stop->load();
    }

    void event(json e) {
        if (!options_.on_event) {
            return;
        }
        json line = {{"at", now()}};
        line.update(e);
        options_.on_event(dump(line));
    }
    void event(std::string_view name, const JournalEntry& e, json more = json::object()) {
        json o = {{"event", name}, {"request", hex(e.request)}};
        if (!e.kind.empty()) {
            o["kind"] = e.kind;
        }
        o.update(more);
        event(std::move(o));
    }

    /// Sleeps up to `ms`, waking early to stop.
    void pause(std::uint64_t ms) const {
        const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (!stopping() && std::chrono::steady_clock::now() < until) {
            std::this_thread::sleep_for(std::min<std::chrono::steady_clock::duration>(
                100ms, until - std::chrono::steady_clock::now()));
        }
    }

    std::uint64_t backoff(std::uint32_t failures, std::optional<std::uint64_t> after = {}) {
        const std::uint32_t shift = std::min<std::uint32_t>(failures == 0 ? 0 : failures - 1, 9);
        std::uint64_t base = std::min<std::uint64_t>(1000ull << shift, max_backoff_ms);
        std::uniform_int_distribution<std::uint64_t> jitter(base * 8 / 10, base * 12 / 10);
        base = std::min<std::uint64_t>(jitter(random_), max_backoff_ms);
        if (after) {
            base = std::max(base, std::min<std::uint64_t>(*after, max_backoff_ms));
        }
        return base;
    }

    void save(JournalEntry& e) {
        e.updated = now();
        if (const auto saved = journal_.save(e); !saved) {
            throw std::runtime_error("cannot write the journal in " + options_.state.string());
        }
    }

    // ---- connectors --------------------------------------------------

    std::expected<void, std::string> start(Connector& c) {
        auto opened =
            open_connector(*c.config, options_.channels, options_.secrets,
                           [&](const connector::Log& log) { connector_log(*c.config, log); });
        if (!opened) {
            return Fail(opened.error());
        }
        c.channel = std::move(opened->channel);
        event({{"event", "connector-ready"},
               {"connector", c.config->name},
               {"name", opened->ready.name},
               {"version", opened->ready.version}});
        return {};
    }

    void connector_log(const ConnectorConfig& c, const connector::Log& log) {
        json o = {{"event", "connector-log"},
                  {"connector", c.name},
                  {"level", std::string(connector::level_name(log.level))},
                  {"message", log.message}};
        if (log.request) {
            o["request"] = hex(*log.request);
        }
        event(std::move(o));
    }

    Connector* connector_for(const std::string& name) {
        const auto it = connectors_.find(name);
        if (it == connectors_.end()) {
            return nullptr;
        }
        if (!it->second.channel) {
            if (auto started = start(it->second); !started) {
                event({{"event", "error"}, {"message", started.error()}});
                return nullptr;
            }
        }
        return &it->second;
    }

    void drop(Connector& c) {
        if (c.channel) {
            c.channel->close();
            c.channel.reset();
        }
    }

    /// Hands the request to its connector and waits for the outcome. A
    /// connector that fails or does not answer in time is restarted, and the
    /// attempt counts as one to retry.
    connector::Outcome act(const ConnectorConfig& route, const JournalEntry& e) {
        connector::Outcome retry;
        retry.request = e.request;
        retry.status = connector::OutcomeStatus::retry;
        retry.reason = "connector";
        Connector* c = connector_for(route.name);
        if (c == nullptr) {
            return retry;
        }
        connector::Perform p;
        p.request = e.request;
        p.kind = e.kind;
        auto params = cbor::decode(e.params);
        p.params = params ? std::move(*params) : cbor::Value::null();
        p.deadline = e.deadline;
        p.asked_at = e.asked_at;
        p.home = config_.ledger;
        p.contract = *e.contract;
        p.instance = e.instance;
        p.reply = e.reply;
        p.attempt = e.attempts;
        p.timeout_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(route.timeout).count());
        if (!c->channel->send(connector::encode(connector::ToConnector(std::move(p))))) {
            drop(*c);
            return retry;
        }
        const auto until = std::chrono::steady_clock::now() + route.timeout + 5s;
        while (std::chrono::steady_clock::now() < until) {
            auto received =
                c->channel->receive(std::chrono::duration_cast<std::chrono::milliseconds>(
                    until - std::chrono::steady_clock::now()));
            if (!received) {
                drop(*c);
                return retry;
            }
            if (!*received) {
                continue;
            }
            auto message = connector::decode_from_connector(**received);
            if (!message) {
                if (message.error().code != Errc::unsupported) {
                    event({{"event", "connector-error"},
                           {"connector", route.name},
                           {"message", std::string(message.error().detail)}});
                }
                continue;
            }
            if (const auto* log = std::get_if<connector::Log>(&*message)) {
                connector_log(route, *log);
            } else if (auto* outcome = std::get_if<connector::Outcome>(&*message)) {
                if (outcome->request == e.request) {
                    return std::move(*outcome);
                }
            }
        }
        drop(*c);
        retry.reason = "timeout";
        return retry;
    }

    void cancel(const JournalEntry& e, std::string_view reason) {
        const auto it = connectors_.find(e.connector);
        if (it != connectors_.end() && it->second.channel) {
            (void)it->second.channel->send(connector::encode(
                connector::ToConnector(connector::Cancel{e.request, std::string(reason)})));
        }
    }

    // ---- the server ---------------------------------------------------

    struct Poll {
        bool granted = true;
        std::uint64_t retry_ms = 0;
        json requests = json::array();
        std::uint64_t cursor = 0;
        bool more = false;
    };

    std::expected<Poll, std::string> poll(std::uint64_t after, std::chrono::seconds wait,
                                          const std::optional<protocol::Id>& instance = {},
                                          std::uint64_t limit = 100) {
        std::string kinds;
        for (const std::string& k : config_.kinds()) {
            kinds += (kinds.empty() ? "" : ",") + k;
        }
        std::string path = std::format(
            "/v1/requests?state=open&kind={}&after={}&limit={}&wait={}&executor={}&lease={}&ttl={}",
            kinds, after, limit, wait.count(), hex(config_.actor), holder_,
            options_.lease_ttl.count());
        if (instance) {
            path += "&instance=" + hex(*instance);
        }
        const auto response = (wait.count() > 0 ? poller_ : client_).request("GET", path);
        if (!response) {
            return Fail(std::format("the server: {}", response.error().detail));
        }
        const json body = json::parse(response->body.begin(), response->body.end(), nullptr, false);
        if (response->status != 200 || !body.is_object() || !body.contains("requests")) {
            const std::string message = body.is_object() && body.contains("error")
                                            ? body["error"].value("message", std::string("?"))
                                            : std::format("status {}", response->status);
            return Fail(std::format("the server refused the poll: {}", message));
        }
        Poll p;
        p.requests = body["requests"];
        p.cursor = body.value("cursor", after);
        p.more = body.value("more", false);
        if (body.contains("lease") && body["lease"].is_object()) {
            p.granted = body["lease"].value("granted", false);
            p.retry_ms = body["lease"].value("retry_ms", std::uint64_t{1000});
        }
        if (p.granted) {
            lease_at_ = std::chrono::steady_clock::now();
        }
        return p;
    }

    /// Renews the lease before an action if a third of its time has passed.
    bool hold_lease(const protocol::Id& instance) {
        if (std::chrono::steady_clock::now() - lease_at_ < options_.lease_ttl / 3) {
            return true;
        }
        auto p = poll(0, 0s, instance, 1);
        if (!p) {
            event({{"event", "error"}, {"message", p.error()}});
            return false;
        }
        if (!p->granted) {
            holding_ = false;
            event({{"event", "lease"}, {"granted", false}, {"holder", holder_}});
        }
        return p->granted;
    }

    /// The instance's contract evidence, verified for the home ledger.
    std::expected<protocol::ContractReport, Trouble> evidence(const protocol::Id& instance) {
        const auto response = client_.request("GET", "/v1/contracts/instances/" + hex(instance));
        if (!response) {
            return std::unexpected(
                Trouble{true, std::format("the server: {}", response.error().detail)});
        }
        if (response->status != 200) {
            const json body =
                json::parse(response->body.begin(), response->body.end(), nullptr, false);
            const std::string message = body.is_object() && body.contains("error")
                                            ? body["error"].value("message", std::string("?"))
                                            : std::format("status {}", response->status);
            const bool transient = response->status == 409 || response->status >= 500 ||
                                   response->status == 401 || response->status == 403 ||
                                   response->status == 429;
            return std::unexpected(
                Trouble{transient, std::format("the instance's evidence: {}", message)});
        }
        protocol::VerifyOptions verify;
        verify.expected_ledger = config_.ledger;
        auto report =
            protocol::verify_contract_evidence(*options_.provider, response->body, verify);
        if (!report) {
            return std::unexpected(Trouble{
                false, std::format("the evidence does not verify: {}", report.error().detail)});
        }
        if (!report->instance.instance || !report->instance.complete ||
            !(report->instance.record == instance)) {
            return std::unexpected(
                Trouble{false, "the evidence is not the instance's complete history"});
        }
        return std::move(*report);
    }

    static const protocol::RequestReport* find_request(const protocol::ContractReport& r,
                                                       const protocol::Id& request) {
        for (const protocol::RequestReport& q : r.instance.instance->requests) {
            if (q.id == request) {
                return &q;
            }
        }
        return nullptr;
    }

    // ---- one request ----------------------------------------------------

    void later(JournalEntry& e, std::string note, std::optional<std::uint64_t> after = {}) {
        ++e.failures;
        const std::uint64_t delay = backoff(e.failures, after);
        e.next_at = now() + delay;
        e.note = std::move(note);
        save(e);
        event("retry-later", e,
              {{"in_ms", delay}, {"note", e.note}, {"stage", stage_name(e.stage)}});
    }

    /// The request was answered, by this executor (earlier, or a copy of
    /// it) or by someone else (a keeper's expiry, a person by hand).
    void closed_by(JournalEntry& e, const protocol::RequestReport& q,
                   const protocol::ContractReport& r) {
        std::optional<protocol::Id> by;
        for (const protocol::RecordEvent& ev : r.instance.events) {
            if (q.answered_by && ev.index == *q.answered_by) {
                by = ev.actor.id;
            }
        }
        const char* status = q.status == protocol::AnswerStatus::done     ? "done"
                             : q.status == protocol::AnswerStatus::failed ? "failed"
                                                                          : "expired";
        const bool acted = e.attempts > 0 || e.status.has_value();
        if (by && *by == config_.actor && e.status) {
            e.stage = Stage::answered;
            e.index = q.answered_by;
            e.note = "recorded earlier";
            save(e);
            event("answered", e, {{"index", *e.index}, {"status", *e.status}});
            return;
        }
        if (acted) {
            cancel(e, "answered");
        }
        e.stage = Stage::closed;
        e.answered_status = status;
        e.answered_by = by;
        e.note = acted ? "answered elsewhere while it worked on it: its own answer is not sent"
                       : "answered elsewhere";
        save(e);
        json more = {{"why", "answered-elsewhere"}, {"status", status}, {"acted", acted}};
        if (by) {
            more["by"] = hex(*by);
        }
        event("closed", e, std::move(more));
    }

    void work(JournalEntry& e) {
        if (e.stage == Stage::outcome || e.stage == Stage::answering) {
            answer(e);
            return;
        }
        auto report = evidence(e.instance);
        if (!report) {
            if (report.error().transient) {
                later(e, report.error().message);
            } else {
                unverified(e, report.error().message);
            }
            return;
        }
        const protocol::RequestReport* q = find_request(*report, e.request);
        if (q == nullptr) {
            unverified(e, "the request is not in the instance's signed evidence");
            return;
        }
        if (q->status) {
            closed_by(e, *q, *report);
            return;
        }
        // From here on, what the signed log says, not the hint.
        e.contract = report->instance.instance->contract;
        e.kind = q->kind;
        e.reply = q->reply;
        e.deadline = q->deadline;
        e.asked_at = q->asked_at;
        e.params = cbor::encode(q->params).value_or(Bytes{});
        const ConnectorConfig* route = config_.route(*e.contract, e.kind);
        if (route == nullptr) {
            e.stage = Stage::closed;
            e.note = "no connector serves this kind on this contract";
            save(e);
            event("closed", e, {{"why", "no-connector"}});
            return;
        }
        e.connector = route->name;
        if (e.stage == Stage::seen || e.stage == Stage::unverified) {
            e.stage = Stage::verified;
            save(e);
            event("verified", e, {{"instance", hex(e.instance)}, {"deadline", e.deadline}});
        }
        const auto longest = static_cast<protocol::Timestamp>(
            std::chrono::duration_cast<std::chrono::milliseconds>(route->timeout).count());
        if (now() + longest >= e.deadline) {
            // Never start work that could end after the deadline.
            decide(e, *report, connector::OutcomeStatus::failed, "deadline");
            return;
        }
        if (!hold_lease(e.instance)) {
            return;
        }
        e.stage = Stage::acting;
        ++e.attempts;
        save(e); // synced before the outside world is touched
        event("acting", e, {{"connector", route->name}, {"attempt", e.attempts}});
        connector::Outcome o = act(*route, e);
        if (o.status == connector::OutcomeStatus::retry) {
            ++e.failures;
            const std::uint64_t delay = backoff(e.failures, o.retry_after_ms);
            if (now() + delay + longest >= e.deadline) {
                decide(e, *report, connector::OutcomeStatus::failed, "deadline");
                return;
            }
            e.stage = Stage::verified;
            e.next_at = now() + delay;
            e.note = std::format("attempt {}: {}", e.attempts, o.reason.value_or("retry"));
            save(e);
            event("retry", e,
                  {{"attempt", e.attempts},
                   {"in_ms", delay},
                   {"reason", o.reason ? json(*o.reason) : json(nullptr)}});
            return;
        }
        e.failures = 0;
        decide(e, *report, o.status, o.reason, std::move(o.result), std::move(o.response));
    }

    void unverified(JournalEntry& e, std::string why) {
        e.stage = Stage::unverified;
        e.note = std::move(why);
        save(e);
        event("unverified", e, {{"why", e.note}});
    }

    /// Journals the outcome (with the response's salted digest), then
    /// answers.
    void decide(JournalEntry& e, const protocol::ContractReport& r, connector::OutcomeStatus status,
                std::optional<std::string> reason, std::optional<cbor::Value> result = {},
                std::optional<Bytes> response = {}) {
        e.status = status == connector::OutcomeStatus::done ? "done" : "failed";
        e.reason = status == connector::OutcomeStatus::done
                       ? std::nullopt
                       : std::optional<std::string>(reason.value_or("rejected"));
        e.result.reset();
        if (result) {
            if (auto encoded = cbor::encode(*result)) {
                e.result = std::move(*encoded);
            }
        }
        e.response.reset();
        e.salt.reset();
        e.digest.reset();
        if (response) {
            protocol::Nonce salt{};
            if (!crypto::openssl::random_bytes(salt)) {
                throw std::runtime_error("no randomness for a salt");
            }
            auto digest = protocol::attachment_commitment(*options_.provider, r.instance.hash, salt,
                                                          *response);
            if (!digest) {
                throw std::runtime_error("cannot hash a response");
            }
            e.salt = Bytes(salt.begin(), salt.end());
            e.digest = Bytes(digest->bytes().begin(), digest->bytes().end());
            e.response = std::move(*response);
        }
        e.stage = Stage::outcome;
        e.next_at = 0;
        save(e);
        event("outcome", e,
              {{"status", *e.status}, {"reason", e.reason ? json(*e.reason) : json(nullptr)}});
        answer(e);
    }

    std::expected<protocol::SignedStatement, std::string>
    sign_answer(const JournalEntry& e, const protocol::ContractReport& r) {
        protocol::Statement st;
        st.ledger_id = config_.ledger;
        st.actor_id = config_.actor;
        st.delegation_id = config_.delegation;
        st.issued_at = now();
        if (!crypto::openssl::random_bytes(st.nonce)) {
            return Fail("no randomness for a nonce");
        }
        if (config_.model) {
            protocol::Provenance p;
            p.model = config_.model;
            p.model_version = config_.model_version;
            const auto tool = options_.provider->digest(crypto::HashAlg::sha256,
                                                        as_bytes(std::string_view(options_.tool)));
            if (tool) {
                p.tools.push_back(
                    {"executor:cexchain", Bytes(tool->bytes().begin(), tool->bytes().end())});
            }
            st.provenance = std::move(p);
        }
        protocol::ContractCallBody body;
        body.instance = e.instance;
        body.function = e.reply;
        body.arguments = answer_arguments(e);
        body.head = r.instance.instance->head;
        body.answer = protocol::ContractAnswer{e.request, *e.status == "done"
                                                              ? protocol::AnswerStatus::done
                                                              : protocol::AnswerStatus::failed};
        st.body = std::move(body);
        auto signed_statement =
            protocol::sign_statement(*options_.signer, *options_.provider, r.instance.hash, st);
        if (!signed_statement) {
            return Fail(std::format("cannot sign the answer: {}", signed_statement.error().detail));
        }
        return std::move(*signed_statement);
    }

    void answer(JournalEntry& e) {
        std::optional<std::string> refusal;
        std::optional<std::uint64_t> refused_head;
        for (int round = 0; round < 5; ++round) {
            const bool resend = round == 0 && e.stage == Stage::answering && e.statement;
            if (!resend) {
                auto report = evidence(e.instance);
                if (!report) {
                    later(e, report.error().message);
                    return;
                }
                const protocol::RequestReport* q = find_request(*report, e.request);
                if (q == nullptr) {
                    later(e, "the request is missing from the evidence");
                    return;
                }
                if (q->status) {
                    closed_by(e, *q, *report);
                    return;
                }
                if (refusal && refused_head == report->instance.instance->head) {
                    // Refused on the head it named: the contract or a ledger
                    // rule refuses this answer. The request stays open.
                    e.stage = Stage::closed;
                    e.note = "the ledger refused its answer: " + *refusal;
                    save(e);
                    event("refused", e, {{"message", *refusal}});
                    return;
                }
                auto signed_answer = sign_answer(e, *report);
                if (!signed_answer) {
                    later(e, signed_answer.error());
                    return;
                }
                e.stage = Stage::answering;
                e.statement = signed_answer->encoded;
                e.statement_id = signed_answer->id;
                e.head = report->instance.instance->head;
                save(e);
            }
            const auto response =
                client_.request("POST", "/v1/statements", *e.statement, "application/cose");
            if (!response) {
                later(e, std::format("the server: {}", response.error().detail));
                return;
            }
            const json body =
                json::parse(response->body.begin(), response->body.end(), nullptr, false);
            const std::string message = body.is_object() && body.contains("error")
                                            ? body["error"].value("message", std::string("?"))
                                            : std::format("status {}", response->status);
            if (response->status == 200 || response->status == 201) {
                e.stage = Stage::answered;
                e.index = body.value("index", std::uint64_t{0});
                e.note.clear();
                e.failures = 0;
                save(e);
                event("answered", e, {{"index", *e.index}, {"status", *e.status}});
                return;
            }
            if (response->status == 409) {
                refusal = message;
                refused_head = e.head;
                continue;
            }
            if (response->status >= 500 || response->status == 401 || response->status == 403 ||
                response->status == 429 || response->status == 307) {
                later(e, "the server: " + message);
                return;
            }
            e.stage = Stage::closed;
            e.note = "the ledger refused its answer: " + message;
            save(e);
            event("refused", e, {{"message", message}});
            return;
        }
        later(e, "the instance keeps changing; it will answer again");
    }

    // ---- the loop -------------------------------------------------------

    bool schedulable(const JournalEntry& e) const {
        return !is_final(e.stage) && e.stage != Stage::unverified;
    }

    void work_due() {
        // Oldest first; a copy, since work may close entries.
        std::vector<std::string> due;
        for (const auto& [key, e] : pending_) {
            if (schedulable(e) && e.next_at <= now()) {
                due.push_back(key);
            }
        }
        std::ranges::sort(due, [&](const std::string& a, const std::string& b) {
            return pending_[a].first_seen < pending_[b].first_seen;
        });
        for (const std::string& key : due) {
            if (stopping() || !holding_) {
                return;
            }
            JournalEntry& e = pending_[key];
            work(e);
            if (is_final(e.stage)) {
                pending_.erase(key);
            }
        }
    }

    std::uint64_t until_due() {
        std::uint64_t soonest = UINT64_MAX;
        for (const auto& [key, e] : pending_) {
            if (schedulable(e)) {
                soonest = std::min(soonest, e.next_at);
            }
        }
        const protocol::Timestamp t = now();
        return soonest == UINT64_MAX ? UINT64_MAX : (soonest <= t ? 0 : soonest - t);
    }

    void note_listed(const json& listed) {
        for (const json& r : listed) {
            const auto id = detail::id_from_hex(r.value("id", std::string()));
            const auto instance = detail::id_from_hex(r.value("instance", std::string()));
            if (!id || !instance) {
                continue;
            }
            const std::string key = hex(*id);
            if (const auto it = pending_.find(key); it != pending_.end()) {
                if (it->second.stage == Stage::unverified) {
                    // Listed again: look again.
                    it->second.stage = Stage::seen;
                    it->second.next_at = 0;
                }
                continue;
            }
            if (const auto known = journal_.find(*id); known && is_final(known->stage)) {
                continue;
            } else if (known) {
                JournalEntry e = *known;
                if (e.stage == Stage::unverified) {
                    e.stage = Stage::seen;
                    e.next_at = 0;
                }
                pending_[key] = std::move(e);
                continue;
            }
            JournalEntry e;
            e.request = *id;
            e.instance = *instance;
            e.kind = r.value("kind", std::string());
            if (!protocol::is_request_kind(e.kind)) {
                e.kind.clear();
            }
            e.first_seen = now();
            save(e);
            event("seen", e, {{"instance", hex(e.instance)}});
            pending_[key] = std::move(e);
        }
    }

    const Config& config_;
    RunOptions& options_;
    Journal journal_;
    Url url_;
    Client client_;
    Client poller_;
    std::map<std::string, Connector> connectors_;
    std::map<std::string, JournalEntry> pending_;
    std::string holder_;
    bool holding_ = false;
    std::chrono::steady_clock::time_point lease_at_{};
    std::mt19937_64 random_{std::random_device{}()};
};

std::expected<void, std::string> Runtime::run() {
    std::error_code ec;
    std::filesystem::create_directories(options_.state, ec);
    std::filesystem::permissions(options_.state, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
    const StateLock lock(options_.state);
    if (!lock.held()) {
        return Fail(
            std::format("another copy runs with the state directory {}", options_.state.string()));
    }
    if (config_.connectors.empty()) {
        return Fail("the config has no connectors (executor connector add)");
    }
    // The copy's name for the lease: kept in the state directory, so that
    // a copy that restarts takes its own lease back at once.
    if (const auto kept = detail::read_file(options_.state / "holder");
        kept && kept->size() == 24 && std::ranges::all_of(*kept, [](std::uint8_t c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        })) {
        holder_.assign(kept->begin(), kept->end());
    } else {
        std::array<std::uint8_t, 12> random{};
        if (!crypto::openssl::random_bytes(random)) {
            return Fail("no randomness");
        }
        holder_ = to_hex(random);
        if (!detail::write_file(options_.state / "holder", as_bytes(std::string_view(holder_)),
                                true)) {
            return Fail("cannot write in the state directory " + options_.state.string());
        }
    }
    for (const ConnectorConfig& c : config_.connectors) {
        Connector& slot = connectors_[c.name];
        slot.config = &c;
        if (auto started = start(slot); !started) {
            for (auto& [name, other] : connectors_) {
                drop(other);
            }
            return Fail(started.error());
        }
    }
    // An answer waiting to be sent is sent at once after a restart; an
    // action waiting for its retry keeps its backoff (the outside system's).
    for (JournalEntry& e : journal_.entries()) {
        if (!is_final(e.stage)) {
            if (e.stage == Stage::outcome || e.stage == Stage::answering) {
                e.next_at = 0;
            }
            pending_[hex(e.request)] = std::move(e);
        }
    }
    std::uint64_t cursor = journal_.cursor(options_.server);
    event({{"event", "started"},
           {"holder", holder_},
           {"kinds", config_.kinds()},
           {"cursor", cursor},
           {"resumed", pending_.size()}});

    bool more = false;
    bool first = true;
    try {
        while (!stopping()) {
            std::chrono::seconds wait = options_.once || more ? 0s : options_.wait;
            if (const std::uint64_t due = until_due(); due != UINT64_MAX && holding_) {
                // Wake for the next retry (rounded up: never a busy loop).
                wait = std::min(wait, std::chrono::seconds((due + 999) / 1000));
            }
            auto p = poll(cursor, wait);
            if (!p) {
                event({{"event", "error"}, {"message", p.error()}});
                if (options_.once) {
                    break;
                }
                pause(5000);
                continue;
            }
            if (!p->granted) {
                if (holding_ || first) {
                    event({{"event", "lease"}, {"granted", false}, {"holder", holder_}});
                }
                holding_ = false;
                first = false;
                if (options_.once) {
                    break;
                }
                pause(std::min<std::uint64_t>(
                    p->retry_ms + 100, static_cast<std::uint64_t>(options_.wait.count()) * 1000));
                continue;
            }
            if (!holding_) {
                event({{"event", "lease"}, {"granted", true}, {"holder", holder_}});
                holding_ = true;
            }
            first = false;
            note_listed(p->requests);
            cursor = p->cursor;
            more = p->more;
            if (const auto saved = journal_.save_cursor(options_.server, cursor); !saved) {
                throw std::runtime_error("cannot write the cursor in " + options_.state.string());
            }
            if (more) {
                continue;
            }
            work_due();
            if (options_.once) {
                break;
            }
        }
    } catch (const std::exception& error) {
        for (auto& [name, c] : connectors_) {
            drop(c);
        }
        return Fail(error.what());
    }
    for (auto& [name, c] : connectors_) {
        if (c.channel) {
            (void)c.channel->send(connector::encode(connector::ToConnector(connector::Stop{})));
        }
        drop(c);
    }
    std::size_t waiting = 0;
    for (const auto& [key, e] : pending_) {
        waiting += is_final(e.stage) ? 0u : 1u;
    }
    event({{"event", "stopped"}, {"waiting", waiting}});
    return {};
}

} // namespace

std::expected<void, std::string> run(const Config& config, RunOptions& options) {
    if (!Url::parse(options.server)) {
        return Fail("the server's URL starts with http:// or https://");
    }
    if (options.signer == nullptr || options.provider == nullptr || !options.channels) {
        return Fail("the runtime needs a signer, a provider, and connectors");
    }
    if (options.wait > 25s) {
        return Fail("the poll's wait is 0 to 25 seconds");
    }
    if (options.lease_ttl < 5s || options.lease_ttl > 300s) {
        return Fail("the lease's time to live is 5 to 300 seconds");
    }
    Runtime runtime(config, options);
    return runtime.run();
}

} // namespace cexchain::node::executor
