// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "fixture.hpp"

#include <format>
#include <fstream>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <utility>

#if CEXCHAIN_BENCH_BO
#include <cexchain/bo/build.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/source.hpp>
#include <cexchain/bo/vocab.hpp>
#endif

namespace cexchain::bench {

const crypto::openssl::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

crypto::openssl::KeyPair named_key(const std::string& name) {
    const auto seed =
        must(provider().digest(crypto::HashAlg::sha256, as_bytes("bench key " + name)), "seed");
    return must(crypto::openssl::KeyPair::from_ed25519_seed(seed.bytes()), "key");
}

Home::Home(const std::string& name, const std::filesystem::path& directory,
           protocol::Timestamp start)
    : directory_(directory), org_(named_key(name + " org")), log_(named_key(name + " log")),
      clock_(start), entropy_(std::hash<std::string>{}(name) | 1) {
    if (directory.empty()) {
        memory_ = std::make_unique<ledger::MemoryFileSystem>();
    } else {
        std::filesystem::remove_all(directory);
        posix_.emplace(must(ledger::PosixFileSystem::open_directory(directory), "directory"));
    }
    protocol::Statement genesis;
    genesis.issued_at = clock_.now();
    genesis.nonce = entropy_.bytes<16>();
    genesis.body =
        protocol::GenesisBody{crypto::HashAlg::sha256, name, org_.public_key(), log_.public_key()};
    ledger_.emplace(
        must(ledger::Ledger::create(
                 fs(), clock_, provider(),
                 must(protocol::sign_statement(org_, provider(), crypto::HashAlg::sha256, genesis),
                      "sign")
                     .encoded),
             "create"));
    id_ = ledger_->id();
}

ledger::FileSystem& Home::fs() {
    if (posix_) {
        return *posix_;
    }
    return *memory_;
}

protocol::SignedStatement Home::sign(protocol::Body body, const crypto::Signer* signer,
                                     const std::optional<protocol::Id>& actor,
                                     const std::optional<protocol::Id>& delegation) {
    protocol::Statement s;
    s.ledger_id = id_;
    s.actor_id = actor ? *actor : id_;
    s.delegation_id = delegation;
    s.issued_at = clock_.now();
    s.nonce = entropy_.bytes<16>();
    s.body = std::move(body);
    return must(protocol::sign_statement(signer != nullptr ? *signer : org_, provider(),
                                         crypto::HashAlg::sha256, s),
                "sign");
}

ledger::Registration Home::submit(protocol::Body body) {
    return must(ledger_->submit(sign(std::move(body)).encoded), "submit");
}

void Home::submit_all(std::span<const Bytes> statements, std::size_t batch, Latencies* latencies) {
    batch = std::max<std::size_t>(1, batch);
    for (std::size_t i = 0; i < statements.size(); i += batch) {
        const std::size_t end = std::min(statements.size(), i + batch);
        const auto started = Clock::now();
        if (batch == 1) {
            must(ledger_->submit(statements[i]), "submit");
        } else {
            const std::vector<ByteView> views(statements.begin() + static_cast<std::ptrdiff_t>(i),
                                              statements.begin() +
                                                  static_cast<std::ptrdiff_t>(end));
            for (auto& r : ledger_->submit_batch(views)) {
                must(std::move(r), "submit");
            }
        }
        const double us = elapsed_us(started);
        if (latencies != nullptr) {
            for (std::size_t k = i; k < end; ++k) {
                latencies->add(us / static_cast<double>(end - i));
            }
        }
    }
}

double Home::reopen() {
    ledger_.reset();
    const auto started = Clock::now();
    ledger_.emplace(must(ledger::Ledger::open(fs(), clock_, provider()), "open"));
    return elapsed_ms(started);
}

bool have_bo() {
#if CEXCHAIN_BENCH_BO
    return true;
#else
    return false;
#endif
}

protocol::ContractDeployBody bo_deploy(std::string_view source, double* build_ms,
                                       const std::vector<std::string>& vocabularies) {
#if CEXCHAIN_BENCH_BO
    auto read_packs = [](const std::vector<std::string>& texts) {
        std::vector<bo::VocabularyHandle> handles;
        for (const std::string& text : texts) {
            bo::VocabularyRead read = bo::read_vocabulary_pack(text);
            if (read.pack == nullptr) {
                throw std::runtime_error("a vocabulary pack does not read");
            }
            handles.push_back(std::move(read.pack));
        }
        bo::PackSetRead read = bo::make_pack_set({}, bo::Officials::current, std::move(handles));
        if (!read.set) {
            throw std::runtime_error("the packs do not read");
        }
        return std::move(*read.set);
    };
    static const bo::PackSet official = read_packs({});
    std::optional<bo::PackSet> own;
    if (!vocabularies.empty()) {
        own.emplace(read_packs(vocabularies));
    }
    const bo::PackSet& packs = own ? *own : official;
    const auto started = Clock::now();
    const bo::Compiled compiled = bo::compile(source, packs);
    if (build_ms != nullptr) {
        *build_ms = elapsed_ms(started);
    }
    if (!compiled.build) {
        std::string why;
        for (const auto& d : compiled.diagnostics) {
            why += std::format("\n  {}", d.code);
        }
        throw std::runtime_error("a bench contract does not build:" + why);
    }
    const auto bundle = must(bo::make_source_bundle(source, compiled.edition, packs, provider(),
                                                    crypto::HashAlg::sha256),
                             "source bundle");
    return protocol::ContractDeployBody{compiled.build->code,
                                        compiled.build->interface,
                                        "bo",
                                        bo::compiler_string(),
                                        must(bo::encode_source_bundle(bundle), "source bundle"),
                                        compiled.name};
#else
    static_cast<void>(source);
    static_cast<void>(build_ms);
    static_cast<void>(vocabularies);
    throw std::runtime_error("this scenario runs Bo contracts: use a build with the Bo compiler "
                             "(GCC 16, e.g. the gcc-release preset)");
#endif
}

std::filesystem::path examples_directory(const Options& options) {
    return options.text("examples", CEXCHAIN_BENCH_EXAMPLES_DIR);
}

std::string read_text(const std::filesystem::path& file) {
    std::ifstream in(file, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot read " + file.string());
    }
    std::ostringstream out;
    out << in.rdbuf();
    return out.str();
}

std::string bill_source(std::uint64_t max_lines) {
    return std::format(R"(# A bill reviewed again and again: every charge and tax worked out
# over every line in each call (cexchain-bench's heavy workload).
use commerce
contract Statement
parties we, customer

thing Account
  invoice list HKD at most {}

charge fee
  rate 10%
  added
  per line half even

tax vat
  rate 5%
  added
  according to price, fee

can review by customer with payment HKD
  requires payment >= sum of invoice + fee + vat
)",
                       max_lines);
}

cbor::Value text(std::string value) {
    return cbor::Value::text(std::move(value));
}

cbor::Value id_value(const protocol::Id& id) {
    return cbor::Value::bytes(id.bytes());
}

cbor::Value number(std::uint64_t value) {
    return cbor::Value::unsigned_integer(value);
}

cbor::Value object(std::vector<std::pair<std::string, cbor::Value>> entries) {
    cbor::Map map;
    for (auto& [key, value] : entries) {
        map.push_back({text(key), std::move(value)});
    }
    return cbor::Value::map(std::move(map));
}

protocol::ContractCallBody Workload::create(const protocol::Id& contract,
                                            const protocol::Id& home) const {
    protocol::ContractCallBody b;
    b.contract = contract;
    if (name == "small") {
        b.function = "create";
        b.arguments = object({{"fields", object({{"name", text("Camera X100")}})},
                              {"parties", object({{"owner", id_value(home)}})}});
    } else if (name == "heavy") {
        cbor::Array invoice;
        for (std::uint64_t i = 0; i < lines; ++i) {
            invoice.push_back(number(1000 + (i * 7919) % 90000));
        }
        b.function = "create";
        b.arguments =
            object({{"fields", object({{"invoice", cbor::Value::array(std::move(invoice))}})},
                    {"parties", object({{"we", id_value(home)}, {"customer", id_value(home)}})}});
    } else {
        b.function = "issue";
        b.arguments = object(
            {{"fields", object({{"amount", number(100'000'000)},
                                {"due", number(1'814'284'800'000)},
                                {"tier", number(1)}})},
             {"parties", object({{"issuer", id_value(home)}, {"supplier", id_value(home)}})}});
    }
    return b;
}

protocol::ContractCallBody Workload::call(const protocol::Id& instance, std::uint64_t head,
                                          const protocol::Id& home, std::uint64_t round) const {
    protocol::ContractCallBody b;
    b.instance = instance;
    b.head = head;
    if (name == "small") {
        if (round % 2 == 0) {
            b.function = "lend";
            b.arguments = object({{"counterparty", id_value(home)}});
        } else {
            b.function = "bring_back";
            b.arguments = object({});
        }
    } else if (name == "heavy") {
        b.function = "review";
        b.arguments = object({{"payment", number(1'000'000'000'000)}});
    } else {
        b.function = "split";
        b.arguments =
            object({{"parts", cbor::Value::array({number(60'000'000), number(40'000'000)})},
                    {"recipients", cbor::Value::array({id_value(home), id_value(home)})}});
    }
    return b;
}

Workload make_workload(std::string_view name, const Options& options) {
    Workload w;
    w.name = name;
    std::string source;
    if (name == "small") {
        w.title = "lending (examples/lending)";
        source = read_text(examples_directory(options) / "lending" / "lending.bo");
    } else if (name == "heavy") {
        w.lines = options.number("lines", 200);
        w.title = std::format("a bill of {} lines, reviewed", w.lines);
        source = bill_source(std::max<std::uint64_t>(w.lines, 1));
    } else if (name == "split") {
        w.title = "a receivable split in two (examples/multi-tier-split)";
        w.max_rounds = 1;
        source =
            read_text(examples_directory(options) / "multi-tier-split" / "multi-tier-split.bo");
    } else {
        throw std::invalid_argument("--contract is small, heavy, or split");
    }
    w.deploy = bo_deploy(source, &w.build_ms);
    return w;
}

std::vector<std::string> workload_names(const Options& options, const std::string& fallback) {
    std::vector<std::string> out;
    for (const auto part : std::views::split(options.text("contract", fallback), ',')) {
        out.emplace_back(part.begin(), part.end());
    }
    return out;
}

std::vector<Bytes> sign_round(Home& home, const Workload& workload,
                              std::span<const protocol::Id> instances, std::uint64_t round) {
    std::vector<Bytes> out;
    out.reserve(instances.size());
    for (const protocol::Id& id : instances) {
        const protocol::InstanceState* instance = home.state().instance(id);
        if (instance == nullptr || instance->final) {
            continue;
        }
        out.push_back(home.sign(workload.call(id, instance->head, home.id(), round)).encoded);
    }
    return out;
}

} // namespace cexchain::bench
