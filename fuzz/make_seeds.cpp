// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Writes valid inputs for the fuzz targets, to start their corpora from:
// random bytes rarely get past a signature, so the deeper checks (evidence
// replay, access rules, backup restore, passkey registration) are reached
// from real objects mutated, not from nothing. The contract interpreter and
// the contract parsers start from testvectors/vm-v1.json, protocol-v0.6.json,
// protocol-v0.7.json (children), and protocol-v0.8.json (requests and
// answers), and so does the Bo runtime's CBOR reader
// (contract inputs and outputs). A registrar's pending calls
// (node/contracts.hpp) are built here as CBOR, without the node library. The
// Bo pack reader starts from the official packs.
//
//   make_seeds DIR    writes DIR/<target>/<name> for each target

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <print>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#if defined(CEXCHAIN_HAVE_BO_FRONT)
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/source.hpp>
#include <cexchain/bo/stdlib.hpp>
#include <cexchain/bo/vocab.hpp>
#endif
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/access.hpp>
#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/presence.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/backup.hpp>
#include <cexchain/ledger/ledger.hpp>

namespace {

using namespace cexchain;

template <class T>
T must(Result<T> result, const char* what) {
    if (!result) {
        throw std::runtime_error(std::string(what) + ": " + std::string(result.error().detail));
    }
    return std::move(*result);
}

class Seeds {
public:
    explicit Seeds(std::filesystem::path root) : root_(std::move(root)) {}
    void write(const std::string& target, const std::string& name, ByteView bytes) const {
        const auto dir = root_ / target;
        std::filesystem::create_directories(dir);
        std::ofstream out(dir / name, std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    void write(const std::string& target, const std::string& name, std::string_view text) const {
        write(target, name, as_bytes(text));
    }

private:
    std::filesystem::path root_;
};

/// A ledger with a document (fields and an attachment), an access
/// request and a grant, checkpointed: the objects the protocol fuzzers
/// verify.
void ledger_seeds(const Seeds& seeds) {
    const crypto::openssl::Provider provider;
    const auto hash = crypto::HashAlg::sha256;
    auto org = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    auto log = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    ledger::ManualClock clock(1'791'244'800'000);
    ledger::SeededEntropy entropy(1);
    ledger::MemoryFileSystem fs;

    protocol::Statement genesis;
    genesis.issued_at = clock.now();
    genesis.nonce = entropy.bytes<16>();
    genesis.body = protocol::GenesisBody{hash, "Seed Org", org.public_key(), log.public_key()};
    const auto signed_genesis =
        must(protocol::sign_statement(org, provider, hash, genesis), "sign");
    auto ledger =
        must(ledger::Ledger::create(fs, clock, provider, signed_genesis.encoded), "create");
    const crypto::Signer* root = &org;
    auto submit = [&](protocol::Body body) {
        protocol::Statement s;
        s.ledger_id = ledger.id();
        s.actor_id = ledger.id();
        s.issued_at = clock.now();
        s.nonce = entropy.bytes<16>();
        s.body = std::move(body);
        const auto signed_statement =
            must(protocol::sign_statement(*root, provider, hash, s), "sign");
        seeds.write("protocol_parse_fuzz", "statement-" + std::to_string(ledger.size()),
                    signed_statement.encoded);
        return must(ledger.submit(signed_statement.encoded), "submit").statement_id;
    };

    const protocol::Nonce salt{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const Bytes report{'r', 'e', 'p', 'o', 'r', 't'};
    const auto commitment =
        must(protocol::commit_fields(provider, hash,
                                     {{"price", salt, cbor::Value::text("1200")},
                                      {"result", salt, cbor::Value::text("pass")}}),
             "fields");
    const auto attachment =
        must(protocol::attachment_commitment(provider, hash, salt, report), "attachment");
    const auto document = submit(protocol::RecordRegisterBody{
        "example.document/1",
        Bytes(commitment.root.bytes().begin(), commitment.root.bytes().end()),
        commitment.leaves.size(),
        {{"report.pdf", "application/pdf", report.size(),
          Bytes(attachment.bytes().begin(), attachment.bytes().end())}},
        std::nullopt});

    const protocol::AccessRequest request{ledger.id(),
                                          document,
                                          "seed",
                                          clock.now() + 86'400'000,
                                          Bytes(32, 7),
                                          std::vector<std::string>{"result"},
                                          std::vector<std::string>{"report.pdf"}};
    const auto request_metadata = must(protocol::encode_access_request(request), "request");
    seeds.write("access_parse_fuzz", "request", must(cbor::encode(request_metadata), "encode"));
    auto access_fields =
        must(protocol::commit_fields(provider, hash, {{"note", salt, cbor::Value::text("x")}}),
             "fields");
    auto access_record = [&](std::string_view type, cbor::Value metadata) {
        return submit(protocol::RecordRegisterBody{
            std::string(type),
            Bytes(access_fields.root.bytes().begin(), access_fields.root.bytes().end()),
            1,
            {},
            std::move(metadata)});
    };
    const auto request_id = access_record(protocol::access_request_type, request_metadata);
    const protocol::AccessGrant grant{ledger.id(),    request_id,    document,         {"result"},
                                      {"report.pdf"}, request.until, request.recipient};
    const auto grant_metadata = must(protocol::encode_access_grant(grant), "grant");
    seeds.write("access_parse_fuzz", "grant", must(cbor::encode(grant_metadata), "encode"));
    const auto grant_id = access_record(protocol::access_grant_type, grant_metadata);
    const protocol::AccessReceipt receipt{ledger.id(), grant_id, Bytes(32, 9)};
    seeds.write(
        "access_parse_fuzz", "receipt",
        must(cbor::encode(must(protocol::encode_access_receipt(receipt), "receipt")), "encode"));

    must(ledger.checkpoint(log), "checkpoint");
    const auto latest = *ledger.latest_checkpoint();
    seeds.write("protocol_parse_fuzz", "checkpoint", latest.encoded);
    seeds.write("cose_parse_fuzz", "checkpoint", latest.encoded);
    seeds.write("protocol_parse_fuzz", "receipt", must(ledger.receipt(log, 1), "receipt"));
    for (std::uint64_t i = 0; i < ledger.size(); ++i) {
        seeds.write("protocol_parse_fuzz", "entry-" + std::to_string(i),
                    must(ledger.entry(i), "entry"));
    }

    // Evidence: plain, with a disclosure and an opening, and of the access
    // records (what check_access_* take).
    auto bundle = must(ledger.export_evidence(log, document), "export");
    const Bytes plain = must(protocol::encode_bundle(bundle), "encode");
    seeds.write("protocol_parse_fuzz", "bundle", plain);
    bundle.disclosures.push_back(
        must(protocol::disclose_field(provider, hash, commitment, "result"), "disclose"));
    bundle.attachments.push_back({"report.pdf", salt});
    const Bytes disclosed = must(protocol::encode_bundle(bundle), "encode");
    seeds.write("protocol_parse_fuzz", "bundle-disclosed", disclosed);
    seeds.write("protocol_parse_fuzz", "bundle-request",
                must(protocol::encode_bundle(must(ledger.export_evidence(log, request_id), "e")),
                     "encode"));
    const Bytes grant_bundle =
        must(protocol::encode_bundle(must(ledger.export_evidence(log, grant_id), "e")), "encode");
    seeds.write("protocol_parse_fuzz", "bundle-grant", grant_bundle);
    seeds.write(
        "access_parse_fuzz", "delivery",
        must(protocol::encode_delivery({grant_bundle, Bytes(32, 1), Bytes(48, 2)}), "delivery"));
    seeds.write("access_parse_fuzz", "delivery-contents",
                must(protocol::encode_delivery_contents({disclosed, {{"report.pdf", report}}}),
                     "contents"));

    // Key rotations (spec v0.4): a bundle and a cosign request that carry
    // them, and backups signed with the newest log key.
    const auto log2 = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    const auto root2 = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    const std::uint64_t witnessed = ledger.latest_checkpoint()->checkpoint.tree_size;
    submit(protocol::LedgerRotateLogKeyBody{log2.public_key()});
    submit(protocol::ActorRotateKeyBody{ledger.id(), root2.public_key()});
    root = &root2;
    submit(protocol::RecordRegisterBody{
        "other/1",
        Bytes(commitment.root.bytes().begin(), commitment.root.bytes().end()),
        commitment.leaves.size(),
        {},
        std::nullopt});
    must(ledger.checkpoint(log2), "checkpoint");
    seeds.write(
        "protocol_parse_fuzz", "bundle-rotated",
        must(protocol::encode_bundle(must(ledger.export_evidence(log2, document), "e")), "encode"));
    seeds.write(
        "protocol_parse_fuzz", "cosign-request-rotated",
        must(protocol::encode_cosign_request(must(ledger.cosign_request(witnessed), "request")),
             "encode"));

    // Backups, signed and not.
    for (const bool sign : {true, false}) {
        std::ostringstream out;
        const std::vector<ledger::BackupFile> files{{"api-tokens", Bytes{'{', '}'}}};
        must(
            ledger::write_backup(ledger, provider, files, clock.now(), out, sign ? &log2 : nullptr),
            "backup");
        seeds.write("backup_restore_fuzz", sign ? "signed" : "unsigned", out.str());
    }
}

/// One organization's ledger in memory, for the contract seeds.
struct Org {
    crypto::openssl::Provider provider;
    crypto::openssl::KeyPair root =
        must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    crypto::openssl::KeyPair log =
        must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    ledger::ManualClock clock{1'791'244'800'000};
    ledger::SeededEntropy entropy;
    ledger::MemoryFileSystem fs;
    std::optional<ledger::Ledger> ledger;

    Org(const std::string& name, std::uint64_t seed) : entropy(seed) {
        protocol::Statement genesis;
        genesis.issued_at = clock.now();
        genesis.nonce = entropy.bytes<16>();
        genesis.body = protocol::GenesisBody{crypto::HashAlg::sha256, name, root.public_key(),
                                             log.public_key()};
        const auto signed_genesis = must(
            protocol::sign_statement(root, provider, crypto::HashAlg::sha256, genesis), "sign");
        ledger.emplace(
            must(ledger::Ledger::create(fs, clock, provider, signed_genesis.encoded), "create"));
    }

    [[nodiscard]] const protocol::Id& id() const { return ledger->id(); }

    /// Signs and registers a statement by the organization; returns it.
    protocol::SignedStatement submit(protocol::Body body) {
        protocol::Statement s;
        s.ledger_id = ledger->id();
        s.actor_id = ledger->id();
        s.issued_at = clock.now();
        s.nonce = entropy.bytes<16>();
        s.body = std::move(body);
        auto signed_statement =
            must(protocol::sign_statement(root, provider, crypto::HashAlg::sha256, s), "sign");
        must(ledger->submit(signed_statement.encoded), "submit");
        clock.advance(1000);
        return signed_statement;
    }

    protocol::Id record(std::string_view type, cbor::Value metadata) {
        const auto fields = must(protocol::commit_fields(provider, crypto::HashAlg::sha256,
                                                         {{"contract", protocol::Nonce{},
                                                           cbor::Value::text("PO-0815")}}),
                                 "fields");
        return submit(protocol::RecordRegisterBody{
                          std::string(type),
                          Bytes(fields.root.bytes().begin(), fields.root.bytes().end()),
                          1,
                          {},
                          std::move(metadata)})
            .id;
    }

    Bytes evidence(const protocol::Id& record) {
        must(ledger->checkpoint(log), "checkpoint");
        return must(protocol::encode_bundle(must(ledger->export_evidence(log, record), "export")),
                    "encode");
    }
};

/// A passkey registration as a browser returns it: [length][attestation
/// object][client data], for the challenge and site the fuzzer uses.
void webauthn_seed(const Seeds& seeds) {
    const crypto::openssl::Provider provider;
    const auto passkey = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::esp256), "key");
    const Bytes& point = passkey.public_key().bytes; // 0x04 || x || y
    Bytes auth_data;
    const auto rp = must(provider.digest(crypto::HashAlg::sha256, as_bytes("localhost")), "hash");
    auth_data.insert(auth_data.end(), rp.bytes().begin(), rp.bytes().end());
    auth_data.push_back(0x41);                    // user present, credential attested
    auth_data.insert(auth_data.end(), 4 + 16, 0); // counter, AAGUID
    const Bytes credential_id(16, 0xc1);
    auth_data.push_back(0);
    auth_data.push_back(static_cast<std::uint8_t>(credential_id.size()));
    auth_data.insert(auth_data.end(), credential_id.begin(), credential_id.end());
    const Bytes cose_key = must(
        cbor::encode(cbor::Value::map(
            {{cbor::Value::integer(1), cbor::Value::integer(2)},
             {cbor::Value::integer(3), cbor::Value::integer(-7)},
             {cbor::Value::integer(-1), cbor::Value::integer(1)},
             {cbor::Value::integer(-2), cbor::Value::bytes(ByteView(point).subspan(1, 32))},
             {cbor::Value::integer(-3), cbor::Value::bytes(ByteView(point).subspan(33, 32))}})),
        "cose key");
    auth_data.insert(auth_data.end(), cose_key.begin(), cose_key.end());
    const Bytes attestation =
        must(cbor::encode(cbor::Value::map(
                 {{cbor::Value::text("fmt"), cbor::Value::text("none")},
                  {cbor::Value::text("attStmt"), cbor::Value::map({})},
                  {cbor::Value::text("authData"), cbor::Value::bytes(auth_data)}})),
             "attestation");
    const std::string client_data = R"({"type":"webauthn.create","challenge":")" +
                                    to_base64url(Bytes(32, 0x5a)) +
                                    R"(","origin":"http://localhost:8765","crossOrigin":false})";
    Bytes input{static_cast<std::uint8_t>(attestation.size() >> 8U),
                static_cast<std::uint8_t>(attestation.size())};
    input.insert(input.end(), attestation.begin(), attestation.end());
    input.insert(input.end(), client_data.begin(), client_data.end());
    must(protocol::credential_from_registration(provider, attestation, as_bytes(client_data),
                                                Bytes(32, 0x5a), "localhost", std::nullopt),
         "the seed registration must be valid");
    seeds.write("webauthn_registration_fuzz", "registration", input);
}

/// A pending call as a registrar holds it (node/contracts.hpp): with
/// `progress`, the proposer, the ledgers missing, and a consent held.
cbor::Value pending_call(bool progress) {
    using cbor::Value;
    cbor::Map map{{Value::integer(1), Value::bytes(Bytes(32, 0x11))},
                  {Value::integer(2), Value::unsigned_integer(7)},
                  {Value::integer(3), Value::text("sign")},
                  {Value::integer(4), Value::array({Value::bytes(Bytes{0x82, 0x01, 0xa0})})},
                  {Value::integer(5), Value::text("PO-2026-17")},
                  {Value::integer(6), Value::unsigned_integer(1'791'849'600'000)}};
    if (progress) {
        map.push_back({Value::integer(7), Value::text("staff")});
        map.push_back({Value::integer(8), Value::array({Value::bytes(Bytes(32, 0x22))})});
        map.push_back({Value::integer(9),
                       Value::array({Value::array({Value::bytes(Bytes(32, 0x33)),
                                                   Value::bytes(Bytes{0xa1, 0x00, 0x01})})})});
    }
    return Value::map(std::move(map));
}

/// A pending call's file name: "<instance>-<head>-<id>.cbor".
std::string pending_name() {
    return to_hex(Bytes(32, 0x11)) + "-7-" + to_hex(Bytes(32, 0x44)) + ".cbor";
}

void pending_call_seeds(const Seeds& seeds) {
    using cbor::Value;
    seeds.write("pending_call_fuzz", "proposal", must(cbor::encode(pending_call(false)), "encode"));
    seeds.write("pending_call_fuzz", "pending", must(cbor::encode(pending_call(true)), "encode"));
    seeds.write("pending_call_fuzz", "name", pending_name());
    seeds.write(
        "pending_call_fuzz", "changes",
        must(cbor::encode(Value::array(
                 {Value::array({Value::text(pending_name()),
                                Value::bytes(must(cbor::encode(pending_call(true)), "encode"))}),
                  Value::array({Value::text(pending_name()), Value::null()})})),
             "encode"));
}

/// Raft entries and snapshot objects, as a cluster member receives them:
/// [kind][CBOR] (see cluster_entry_fuzz).
void cluster_seeds(const Seeds& seeds) {
    using cbor::Value;
    auto write = [&](const std::string& name, std::uint8_t kind, const Value& value) {
        Bytes input{kind};
        const Bytes encoded = must(cbor::encode(value), "encode");
        input.insert(input.end(), encoded.begin(), encoded.end());
        seeds.write("cluster_entry_fuzz", name, input);
    };
    write("batch", 0,
          Value::array({Value::unsigned_integer(1), Value::unsigned_integer(1'791'244'800'000),
                        Value::unsigned_integer(1), Value::array({Value::bytes(Bytes(40, 0xd2))}),
                        Value::array({Value::array(
                            {Value::unsigned_integer(0), Value::bytes(Bytes{0xa0})})})}));
    // Kind 2 is reserved (spec v0.9 removed the native asset actions' consents): ignored.
    write("batch-reserved-kind", 0,
          Value::array({Value::unsigned_integer(1), Value::unsigned_integer(1'791'244'800'000),
                        Value::unsigned_integer(1), Value::array({Value::bytes(Bytes(40, 0xd2))}),
                        Value::array({Value::array({Value::unsigned_integer(0),
                                                    Value::bytes(Bytes{0x81, 0x41, 0x00}),
                                                    Value::unsigned_integer(2)})})}));
    write("batch-contract-consents", 0,
          Value::array({Value::unsigned_integer(1), Value::unsigned_integer(1'791'244'800'000),
                        Value::unsigned_integer(1), Value::array({Value::bytes(Bytes(40, 0xd2))}),
                        Value::array({Value::array({Value::unsigned_integer(0),
                                                    Value::bytes(Bytes{0x81, 0x41, 0x00}),
                                                    Value::unsigned_integer(3)})})}));
    const Bytes pending = must(cbor::encode(pending_call(true)), "encode");
    write("pending", 2,
          Value::array(
              {Value::unsigned_integer(4),
               Value::array({Value::array({Value::text(pending_name()), Value::bytes(pending)}),
                             Value::array({Value::text(pending_name()), Value::null()})})}));
    write("checkpoint", 1,
          Value::array({Value::unsigned_integer(2), Value::null(), Value::bytes(Bytes(60, 0xd2))}));
    write("cosignature", 2,
          Value::array({Value::unsigned_integer(3), Value::bytes(Bytes(60, 0xd2)),
                        Value::array({Value::integer(-19), Value::bytes(Bytes(32, 7))})}));
    write("snapshot-header", 3,
          Value::array({Value::bytes(Bytes(32, 1)), Value::unsigned_integer(5),
                        Value::unsigned_integer(1)}));
    write("snapshot-entries", 4, Value::array({Value::bytes(Bytes(20, 3))}));
    write("snapshot-files", 5,
          Value::array({Value::array({Value::bytes(Bytes(32, 4)), Value::bytes(Bytes{0xa0})}),
                        Value::array({Value::bytes(Bytes(32, 5)), Value::bytes(Bytes{0x81, 0x40}),
                                      Value::unsigned_integer(2)}),
                        Value::array({Value::bytes(Bytes(32, 6)), Value::bytes(Bytes{0x81, 0x40}),
                                      Value::unsigned_integer(3)}),
                        Value::array({Value::text(pending_name()), Value::bytes(pending),
                                      Value::unsigned_integer(4)})}));
    write("snapshot-extras", 5, Value::array({Value::array({}), Value::array({})}));
}

void text_seeds(const Seeds& seeds) {
    seeds.write("console_request_fuzz", "page",
                "GET /console/ HTTP/1.1\r\nHost: localhost:7470\r\n\r\n");
    seeds.write("console_request_fuzz", "session",
                "GET /console/api/session HTTP/1.1\r\nHost: 127.0.0.1:7470\r\n"
                "Authorization: Bearer cxs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n");
    seeds.write("console_request_fuzz", "sign-out",
                "DELETE /console/api/session HTTP/1.1\r\nHost: [::1]:7470\r\n"
                "Origin: http://[::1]:7470\r\n"
                "Authorization: bearer cxs_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\r\n\r\n");
    seeds.write("console_request_fuzz", "rebinding",
                "GET /console/ HTTP/1.1\r\nHost: attacker.example:7470\r\n"
                "Origin: https://attacker.example\r\n\r\n");
    seeds.write("http_parse_fuzz", "get",
                "GET /v1/entries?start=0&count=10 HTTP/1.1\r\nHost: ledger\r\n"
                "Authorization: Bearer cxt_x\r\n\r\n");
    seeds.write("http_parse_fuzz", "post",
                "POST /v1/statements HTTP/1.1\r\nHost: ledger\r\nContent-Type: application/cose\r\n"
                "Content-Length: 5\r\nExpect: 100-continue\r\n\r\nhello");
    seeds.write("http_parse_fuzz", "pipelined",
                "GET /healthz HTTP/1.1\r\nHost: a\r\n\r\nHEAD /healthz HTTP/1.1\r\nHost: a\r\n"
                "Connection: close\r\n\r\n");
    seeds.write("http_parse_fuzz", "chunked-response",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n");
    seeds.write("http_parse_fuzz", "response",
                "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
    seeds.write("http_parse_fuzz", "requests-poll",
                "GET /v1/requests?state=open&kind=notify,http.post&after=12&limit=50&wait=25 "
                "HTTP/1.1\r\nHost: ledger\r\nAuthorization: Bearer cxt_x\r\n\r\n");
    seeds.write("http_parse_fuzz", "requests-instance",
                "GET /v1/requests?state=all&instance=" + std::string(64, 'a') +
                    "&contract=" + std::string(64, '0') + " HTTP/1.1\r\nHost: ledger\r\n\r\n");
    seeds.write("http_parse_fuzz", "contracts-due",
                "GET /v1/contracts/due?at=1792022400000&grace=900&keeper=" + std::string(64, 'b') +
                    "&start=7&limit=2000 HTTP/1.1\r\nHost: ledger\r\n\r\n");
    // The connector protocol: the first byte chooses the direction (even:
    // from a connector, odd: to it).
    const std::string request(64, 'a');
    const std::string other(64, 'b');
    seeds.write("connector_line_fuzz", "ready",
                std::string(1, '\0') +
                    R"({"type":"ready","protocol":1,"name":"webhook","version":"0.1",)"
                    R"("kinds":["notify","http.post"]})");
    seeds.write("connector_line_fuzz", "outcome-done",
                std::string(1, '\0') + R"({"type":"outcome","id":")" + request +
                    R"(","status":"done","result":{"ref":"N-1","amount":1250,"ok":true,)"
                    R"("lines":[1,-2,null]},"response":"eyJvayI6dHJ1ZX0"})");
    seeds.write("connector_line_fuzz", "outcome-retry",
                std::string(1, '\0') + R"({"type":"outcome","id":")" + request +
                    R"(","status":"retry","reason":"unavailable","retry_after_ms":2000})");
    seeds.write("connector_line_fuzz", "log",
                std::string(1, '\0') + R"({"type":"log","level":"warn","message":"slow","id":")" +
                    request + R"("})");
    seeds.write("connector_line_fuzz", "hello",
                std::string(1, '\1') +
                    R"({"type":"hello","protocol":1,"connector":"hook","config":{"url":)"
                    R"("https://example.com/hook","timeout":10},"secrets":{"hook-key":"k"}})");
    seeds.write("connector_line_fuzz", "perform",
                std::string(1, '\1') + R"({"type":"perform","id":")" + request +
                    R"(","kind":"notify","params":{"about":"welcome"},)"
                    R"("params_cbor":"a16561626f75746777656c636f6d65","deadline":1800000000000,)"
                    R"("asked_at":1799000000000,"home":")" +
                    other + R"(","contract":")" + other + R"(","instance":")" + other +
                    R"(","reply":"result","attempt":2,"timeout_ms":30000})");
    seeds.write("connector_line_fuzz", "cancel",
                std::string(1, '\1') + R"({"type":"cancel","id":")" + request +
                    R"(","reason":"answered"})");
    // An executor's config and state files (executor_state_fuzz): the first
    // byte chooses the reader (0 config, 1 journal entry, 2 cursor, 3 sealed
    // secret, sealed to another key than the fuzzer's).
    seeds.write(
        "executor_state_fuzz", "config",
        std::string(1, '\0') +
            R"({"actor":"ad2b642072ec3bf0f7ec67acbd7cfb8a9591c792570204f328553e7714b6f206",)"
            R"("connectors":[{"args":["/usr/local/bin/notify"],"concurrency":4,"kinds":["notify"],)"
            R"("name":"n)"
            R"(otices","program":"/bin/sh","secrets":["notify-token"],"timeout":10,"type":")"
            R"(command"},{"kinds":["http.post"],"name":"hook","secret":"hook-key","timeo)"
            R"(ut":30,"type":"webhook","url":"https://hooks.example.com/ledger"}],"delegati)"
            R"(on":"121c8bce2e0e28889ccf8ef5349609a6adc5139c28c96ece04c2a80d2ace9954","ledg)"
            R"(er_id":"9b7b02745f0a609a0fdf7ca3562b0a803641d9cdc7fb708c4b9ca816f8f82cf9","v)"
            R"(ersion":1})");
    seeds.write(
        "executor_state_fuzz", "entry",
        std::string(1, '\1') +
            R"({"answered_by":null,"answered_status":null,"asked_at":1792355896652,"attempt)"
            R"(s":1,"connector":"notices","contract":"79a2e9893ce98db050f5e07884f1bfd3b5db8)"
            R"(030a4e76a3351bb7883fca16768","deadline":1792442296652,"digest":"df609e5b1cb9)"
            R"(a24d1fe22390ca0be19ac7d30e49c73681325a9c151a7b29e08d","failures":0,"first_se)"
            R"(en":1792355896661,"head":6,"index":8,"instance":"7eac7697cc4709a495c963f20f6)"
            R"(33c3059060a965524ae24a5580bbca24ec269","kind":"notify","next_at":0,"note":"")"
            R"(,"params":"a262746f58209b7b02745f0a609a0fdf7ca3562b0a803641d9cdc7fb708c4b9ca)"
            R"(816f8f82cf9676d657373616765626869","reason":null,"reply":"result","request":)"
            R"("e526fc7e4bba9f9a0c68ae72097eb49362e5ed47b2e5d9cc1560808051f4fe44","response)"
            R"(":"7b22726573756c74223a20224e2d6535323666633765227d0a","result":"6a4e2d65353)"
            R"(23666633765","salt":"412fed8ce7f14c97ad80d38901316f41","stage":"answered","s)"
            R"(tatement":"d284584ca301320378236170706c69636174696f6e2f636578636861696e2d737)"
            R"(46174656d656e742b63626f7204582015aa39bc1685dcb52f561fd46107f7d7eb1bfb1f2e8dd)"
            R"(dae5ae5fa496db2d413a059011da8000101160258209b7b02745f0a609a0fdf7ca3562b0a803)"
            R"(641d9cdc7fb708c4b9ca816f8f82cf9035820ad2b642072ec3bf0f7ec67acbd7cfb8a9591c79)"
            R"(2570204f328553e7714b6f206045820121c8bce2e0e28889ccf8ef5349609a6adc5139c28c96)"
            R"(ece04c2a80d2ace9954051b000001a150bc8d860650e32ddaab59d176484d05dc1f584388ce0)"
            R"(7a50258207eac7697cc4709a495c963f20f633c3059060a965524ae24a5580bbca24ec269036)"
            R"(6726573756c7404a266726573756c746a4e2d653532366663376568726573706f6e73655820d)"
            R"(f609e5b1cb9a24d1fe22390ca0be19ac7d30e49c73681325a9c151a7b29e08d050608825820e)"
            R"(526fc7e4bba9f9a0c68ae72097eb49362e5ed47b2e5d9cc1560808051f4fe44015840372268d)"
            R"(74814100af5a223854ed5bd811be3bba9618a8d167ec37b4db3e7096327dfb0c629dd50b5b4e)"
            R"(26c2f8b71815a2273959065d71a4a61301babfbbeed04","statement_id":"c374ca2442e79)"
            R"(a5f2c6ce07055b360262b9c9f095133defca679739cee2bcb20","status":"done","update)"
            R"(d":1792355896718})");
    seeds.write("executor_state_fuzz", "cursor",
                std::string(1, '\2') + R"({"after":9,"server":"http://127.0.0.1:8080"})");
    const auto sealed_body =
        must(from_hex("a40101028318200102035820bac16c9f9381ae30de93b8468bf7ec3c52ee911122d933a960f7"
                      "e9815647720f04581c371435ad80bbb1cab639e63f9e93910b17926d111ce26c4d1cc0212f"),
             "a sealed secret");
    Bytes sealed_secret{3};
    sealed_secret.insert(sealed_secret.end(), sealed_body.begin(), sealed_body.end());
    seeds.write("executor_state_fuzz", "sealed", sealed_secret);
    seeds.write("pkcs11_uri_fuzz", "key",
                "pkcs11:token=CexChain;object=alice;type=private?module-path=/usr/lib/"
                "softhsm/libsofthsm2.so&pin-source=file:/run/pin");
    seeds.write("pkcs11_uri_fuzz", "sm2",
                "pkcs11:serial=0123;id=%01%02;slot-id=0?module-path=/opt/ukey.so&"
                "x-sm2-mechanism=0x80000001");
}

} // namespace

/// Every module of the interpreter's vectors, valid and refused: they cover
/// each instruction, trap, and validation rule. And the code of the Bo
/// conformance contracts: what the interpreter runs most, in the sequences
/// it fuses.
void vm_seeds(const Seeds& seeds) {
    std::ifstream in(CEXCHAIN_TESTVECTORS_DIR "/vm-v1.json");
    if (!in) {
        throw std::runtime_error("cannot read vm-v1.json");
    }
    const auto doc = nlohmann::json::parse(in);
    std::size_t n = 0;
    for (const auto& module : doc.at("modules")) {
        const auto wasm = must(from_hex(module.at("wasm").get<std::string>()), "module");
        seeds.write("vm_fuzz", std::format("module-{:03}", n++), ByteView(wasm));
    }
    std::ifstream bo_in(CEXCHAIN_TESTVECTORS_DIR "/bo-v1.json");
    if (!bo_in) {
        throw std::runtime_error("cannot read bo-v1.json");
    }
    const auto bo = nlohmann::json::parse(bo_in);
    for (const auto& contract : bo.at("contracts")) {
        const auto wasm = must(from_hex(contract.at("code").get<std::string>()), "code");
        seeds.write("vm_fuzz", "bo-" + contract.at("name").get<std::string>(), ByteView(wasm));
    }
    // Real contract inputs and outputs, states in them.
    n = 0;
    for (const auto& contract : bo.at("contracts")) {
        for (const auto& run : contract.at("runs")) {
            for (const char* part : {"input", "output"}) {
                const auto bytes = must(from_hex(run.at(part).get<std::string>()), part);
                if (!bytes.empty()) {
                    seeds.write("cbor_validate_fuzz", std::format("bo-{}-{:04}", part, n++),
                                ByteView(bytes));
                }
            }
        }
    }
}

/// Contract outputs (every verdict) and consent metadata from the v0.6
/// vectors, and real contract evidence: the vectors' test contract deployed,
/// an instance created, and a call with a supplier's consent.
void contract_seeds(const Seeds& seeds) {
    std::ifstream in(CEXCHAIN_TESTVECTORS_DIR "/protocol-v0.6.json");
    if (!in) {
        throw std::runtime_error("cannot read protocol-v0.6.json");
    }
    const auto doc = nlohmann::json::parse(in);
    const auto& ledger = doc.at("ledgers").at(0);
    std::size_t n = 0;
    for (const auto& run : ledger.at("runs")) {
        const auto output = must(from_hex(run.at("output").get<std::string>()), "output");
        // The Bo runtime reads contract inputs (and any CBOR): both as seeds.
        const auto input = must(from_hex(run.at("input").get<std::string>()), "input");
        seeds.write("bo_runtime_fuzz", std::format("input-{:02}", n), ByteView(input));
        seeds.write("bo_runtime_fuzz", std::format("output-{:02}", n), ByteView(output));
        seeds.write("contract_parse_fuzz", std::format("output-{:02}", n++), ByteView(output));
    }
    n = 0;
    for (const auto& consent : ledger.at("consents")) {
        const auto metadata = must(from_hex(consent.at("metadata").get<std::string>()), "consent");
        seeds.write("contract_parse_fuzz", std::format("consent-{:02}", n++), ByteView(metadata));
    }

    Org home("Seed Contract Home", 21);
    Org supplier("Seed Contract Supplier", 22);
    protocol::ContractDeployBody deploy;
    deploy.code = must(from_hex(doc.at("contract").get<std::string>()), "contract");
    deploy.interface = {{"propose", protocol::FunctionKind::create},
                        {"sign", protocol::FunctionKind::call}};
    deploy.language = "wasm";
    deploy.compiler = "hand-assembled 1";
    const auto deployed = home.submit(deploy);
    seeds.write("protocol_parse_fuzz", "statement-contract-deploy", deployed.encoded);

    // The test contract writes the content of byte-string arguments.
    auto arguments = [](const protocol::ContractOutput& output) {
        return cbor::Value::bytes(must(protocol::encode_contract_output(output), "output"));
    };
    protocol::ContractCallBody create;
    create.contract = deployed.id;
    create.function = "propose";
    create.arguments =
        arguments(protocol::ContractAccept{*cbor::Encoded::encode(cbor::Value::text("draft")),
                                           "proposed",
                                           protocol::Parties{{"supplier", supplier.id()}},
                                           {},
                                           false,
                                           {},
                                           {}});
    const auto created = home.submit(create);
    seeds.write("protocol_parse_fuzz", "statement-contract-create", created.encoded);

    protocol::ContractCallBody sign;
    sign.instance = created.id;
    sign.function = "sign";
    sign.arguments =
        arguments(protocol::ContractAccept{*cbor::Encoded::encode(cbor::Value::text("signed")),
                                           "effective",
                                           std::nullopt,
                                           {},
                                           false,
                                           {},
                                           {}});
    sign.head = home.ledger->state().instance(created.id)->head;
    const auto digest = must(
        protocol::contract_arguments_digest(home.provider, crypto::HashAlg::sha256, sign.arguments),
        "digest");
    const auto consent_metadata =
        must(protocol::encode_contract_consent({home.id(), created.id, "sign", digest, *sign.head,
                                                home.clock.now() + 86'400'000, std::nullopt}),
             "consent");
    const protocol::Id record = supplier.record(protocol::contract_consent_type, consent_metadata);
    Bytes bundle = supplier.evidence(record);
    sign.consents.push_back({supplier.id(),
                             record,
                             must(home.provider.digest(crypto::HashAlg::sha256, bundle), "hash"),
                             {}});
    const auto signed_call = home.submit(sign);
    seeds.write("protocol_parse_fuzz", "statement-contract-call", signed_call.encoded);
    const Bytes evidence =
        must(protocol::encode_contract_evidence({home.evidence(created.id), {std::move(bundle)}}),
             "evidence");
    must(protocol::verify_contract_evidence(home.provider, evidence),
         "the seed evidence must verify");
    seeds.write("contract_parse_fuzz", "evidence", evidence);

    // Diagnostic notation, as the command line takes contract arguments; and
    // CBOR, whose rendering must parse back.
    seeds.write("diagnostic_fuzz", "arguments", cbor::diagnostic(sign.arguments));
    seeds.write("diagnostic_fuzz", "typed",
                std::string_view(R"([<<[2, [h'0102']]>>, {1: "a", "b": [true, null, -1]}, )"
                                 R"(1(1700000000), "é😀", h'00 ff'])"));
    seeds.write("diagnostic_fuzz", "statement", signed_call.encoded);
}

/// Instances created by a call (v0.7): outputs with children (accepted and
/// malformed), inputs of calls on children (instance view key 6), and the
/// contract evidence of children, ancestors and their consents included,
/// from protocol-v0.7.json (both hashes).
void child_seeds(const Seeds& seeds) {
    std::ifstream in(CEXCHAIN_TESTVECTORS_DIR "/protocol-v0.7.json");
    if (!in) {
        throw std::runtime_error("cannot read protocol-v0.7.json");
    }
    const auto doc = nlohmann::json::parse(in);
    const crypto::openssl::Provider provider;
    std::size_t n = 0;
    std::size_t e = 0;
    for (const auto& ledger : doc.at("ledgers")) {
        for (const auto& run : ledger.at("runs")) {
            const auto output = must(from_hex(run.at("output").get<std::string>()), "output");
            const auto input = must(from_hex(run.at("input").get<std::string>()), "input");
            seeds.write("contract_parse_fuzz", std::format("child-output-{:02}", n),
                        ByteView(output));
            seeds.write("bo_runtime_fuzz", std::format("child-input-{:02}", n++), ByteView(input));
        }
        for (const auto& [what, evidence] : ledger.at("evidence").items()) {
            const auto encoded =
                must(from_hex(evidence.at("contract_evidence").get<std::string>()), "evidence");
            must(protocol::verify_contract_evidence(provider, encoded),
                 "the vectors' child evidence must verify");
            seeds.write("contract_parse_fuzz", std::format("child-evidence-{:02}", e++),
                        ByteView(encoded));
        }
    }
}

/// Requests and answers (v0.8): outputs that make requests (accepted and
/// malformed), answers' inputs (key 9), statements with answers and with
/// scope keys 8 and 9 (well formed and malformed), and the contract evidence
/// of instances with requests, from protocol-v0.8.json (both hashes).
void request_seeds(const Seeds& seeds) {
    std::ifstream in(CEXCHAIN_TESTVECTORS_DIR "/protocol-v0.8.json");
    if (!in) {
        throw std::runtime_error("cannot read protocol-v0.8.json");
    }
    const auto doc = nlohmann::json::parse(in);
    const crypto::openssl::Provider provider;
    std::size_t n = 0;
    std::size_t s = 0;
    std::size_t e = 0;
    for (const auto& ledger : doc.at("ledgers")) {
        for (const auto& run : ledger.at("runs")) {
            const auto output = must(from_hex(run.at("output").get<std::string>()), "output");
            const auto input = must(from_hex(run.at("input").get<std::string>()), "input");
            seeds.write("contract_parse_fuzz", std::format("request-output-{:03}", n),
                        ByteView(output));
            seeds.write("bo_runtime_fuzz", std::format("request-input-{:03}", n++),
                        ByteView(input));
        }
        // Statements that answer or carry scope keys 8 and 9, as payloads
        // and signed; the refused ones too, malformed or not.
        for (const char* list : {"statements", "refused"}) {
            for (const auto& st : ledger.at(list)) {
                const auto payload = must(from_hex(st.at("payload").get<std::string>()), "payload");
                const auto value = must(cbor::decode(payload), "payload CBOR");
                const cbor::Value* type = value.find(1);
                const cbor::Value* body = value.find(7);
                const bool answer = type != nullptr && type->as_uint64() == 22U &&
                                    body != nullptr && body->find(8) != nullptr;
                const cbor::Value* scope =
                    type != nullptr && type->as_uint64() == 5U && body != nullptr ? body->find(2)
                                                                                  : nullptr;
                const bool scoped =
                    scope != nullptr && (scope->find(8) != nullptr || scope->find(9) != nullptr);
                if (!answer && !scoped) {
                    continue;
                }
                const auto encoded =
                    must(from_hex(st.at("encoded").get<std::string>()), "statement");
                seeds.write("protocol_parse_fuzz", std::format("request-payload-{:03}", s),
                            ByteView(payload));
                seeds.write("protocol_parse_fuzz", std::format("request-statement-{:03}", s++),
                            ByteView(encoded));
            }
        }
        for (const auto& [what, evidence] : ledger.at("evidence").items()) {
            const auto encoded =
                must(from_hex(evidence.at("contract_evidence").get<std::string>()), "evidence");
            must(protocol::verify_contract_evidence(provider, encoded),
                 "the vectors' request evidence must verify");
            seeds.write("contract_parse_fuzz", std::format("request-evidence-{:02}", e++),
                        ByteView(encoded));
        }
    }
}

/// The generic core (v0.9): every statement of protocol-v0.9.json, as a
/// payload and signed, the refused ones too: type-20 bodies and a scope
/// naming type 20 (which must not parse), and registrations under the
/// reserved prefix (which parse; the ledger refuses them).
void generic_seeds(const Seeds& seeds) {
    std::ifstream in(CEXCHAIN_TESTVECTORS_DIR "/protocol-v0.9.json");
    if (!in) {
        throw std::runtime_error("cannot read protocol-v0.9.json");
    }
    const auto doc = nlohmann::json::parse(in);
    std::size_t s = 0;
    for (const auto& ledger : doc.at("ledgers")) {
        for (const char* list : {"statements", "refused"}) {
            for (const auto& st : ledger.at(list)) {
                const auto payload = must(from_hex(st.at("payload").get<std::string>()), "payload");
                const auto encoded =
                    must(from_hex(st.at("encoded").get<std::string>()), "statement");
                seeds.write("protocol_parse_fuzz", std::format("generic-payload-{:03}", s),
                            ByteView(payload));
                seeds.write("protocol_parse_fuzz", std::format("generic-statement-{:03}", s++),
                            ByteView(encoded));
            }
        }
    }
}

/// The official language packs, as written and as CBOR (a source bundle
/// embeds packs as CBOR); Bo sources, for the lexer, the parser, and the
/// checker: the goldens, the spec's examples among them, in each language.
void bo_seeds(const Seeds& seeds) {
#if defined(CEXCHAIN_HAVE_BO_FRONT)
    for (const bo::PackText& text : bo::official_pack_texts()) {
        seeds.write("bo_pack_fuzz", std::string(text.id) + ".pack", text.text);
    }
    for (const bo::Pack& pack : bo::official_packs()) {
        seeds.write("bo_pack_fuzz", pack.id + ".cbor", pack.canonical);
    }
    std::vector<std::filesystem::path> cases;
    for (const auto& entry : std::filesystem::directory_iterator(CEXCHAIN_BO_GOLDEN_DIR)) {
        if (std::filesystem::exists(entry.path() / "source.bo")) {
            cases.push_back(entry.path());
        }
    }
    std::ranges::sort(cases);
    for (const auto& path : cases) {
        std::ifstream in(path / "source.bo", std::ios::binary);
        std::stringstream text;
        text << in.rdbuf();
        seeds.write("bo_lex_fuzz", path.filename().string() + ".bo", text.str());
        seeds.write("bo_parse_fuzz", path.filename().string() + ".bo", text.str());
        seeds.write("bo_check_fuzz", path.filename().string() + ".bo", text.str());
    }
    // The formatter's cases (bo_parse_fuzz formats every source it reads):
    // layout, words with arguments on either side, numbers and dates.
    for (const auto& entry : std::filesystem::directory_iterator(
             std::filesystem::path(CEXCHAIN_BO_GOLDEN_DIR) / "format")) {
        std::ifstream in(entry.path() / "source.bo", std::ios::binary);
        std::stringstream text;
        text << in.rdbuf();
        seeds.write("bo_parse_fuzz", "format-" + entry.path().filename().string() + ".bo",
                    text.str());
    }
    // The compiled agreement in four spellings, whose model explains with
    // requirements, choices, and a refusal (bo_check_fuzz writes the text).
    for (const auto& entry : std::filesystem::directory_iterator(
             std::filesystem::path(CEXCHAIN_BO_GOLDEN_DIR) / "build")) {
        std::ifstream in(entry.path() / "source.bo", std::ios::binary);
        std::stringstream text;
        text << in.rdbuf();
        seeds.write("bo_check_fuzz", "build-" + entry.path().filename().string() + ".bo",
                    text.str());
    }
    // Test blocks (bo test): the tests' own cases, the agreement's and the
    // demo's tests among the sources above.
    for (const auto& entry : std::filesystem::directory_iterator(
             std::filesystem::path(CEXCHAIN_BO_GOLDEN_DIR) / "test")) {
        if (!std::filesystem::exists(entry.path() / "source.bo")) {
            continue;
        }
        std::ifstream in(entry.path() / "source.bo", std::ios::binary);
        std::stringstream text;
        text << in.rdbuf();
        seeds.write("bo_parse_fuzz", "test-" + entry.path().filename().string() + ".bo",
                    text.str());
        seeds.write("bo_check_fuzz", "test-" + entry.path().filename().string() + ".bo",
                    text.str());
    }

    // The examples' contracts (examples/): a supply agreement, and a
    // receivable split down a supply chain, with their tests.
    for (const std::string_view demo : {"supply-agreement", "multi-tier-split"}) {
        std::ifstream in(std::filesystem::path(CEXCHAIN_BO_GOLDEN_DIR)
                                 .parent_path()
                                 .parent_path()
                                 .parent_path() /
                             "examples" / demo / (std::string(demo) + ".bo"),
                         std::ios::binary);
        std::stringstream text;
        text << in.rdbuf();
        seeds.write("bo_parse_fuzz", "demo-" + std::string(demo) + ".bo", text.str());
        seeds.write("bo_check_fuzz", "demo-" + std::string(demo) + ".bo", text.str());
    }

    // The standard library (one file for the core and one for
    // each vocabulary pack with terms), and a contract that declares
    // all its actions: built-in actions with their terms.
    for (const bo::StandardFile& file : bo::standard_library().files) {
        const std::string name = "stdlib-" + std::string(bo::vocab_name(file.pack)) + ".bo";
        seeds.write("bo_parse_fuzz", name, file.source);
        seeds.write("bo_check_fuzz", name, file.source);
    }
    seeds.write("bo_check_fuzz", "stdlib-showcase.bo", bo::standard_showcase());

    // Deploys' source bundles: each golden source (the compiled agreement in
    // four spellings among them) with the official packs, under SHA-256 and
    // SM3; one with a company's pack embedded; a .boc of the agreement (its
    // code from bo-v1.json); compiler strings.
    const crypto::openssl::Provider provider;
    const bo::PackSetRead official = bo::make_pack_set({});
    if (!official.set) {
        throw std::runtime_error("the official packs");
    }
    for (const auto& entry : std::filesystem::directory_iterator(
             std::filesystem::path(CEXCHAIN_BO_GOLDEN_DIR) / "build")) {
        cases.push_back(entry.path());
    }
    std::ranges::sort(cases);
    Bytes agreement_bundle;
    for (const auto& path : cases) {
        std::ifstream in(path / "source.bo", std::ios::binary);
        std::stringstream text;
        text << in.rdbuf();
        for (const crypto::HashAlg hash : {crypto::HashAlg::sha256, crypto::HashAlg::sm3}) {
            // Sources that are not UTF-8 make no bundle.
            const auto bundle =
                bo::make_source_bundle(text.str(), 1, *official.set, provider, hash);
            if (!bundle) {
                continue;
            }
            const Bytes bytes = must(bo::encode_source_bundle(*bundle), "bundle");
            seeds.write("bo_source_fuzz",
                        std::format("{}-{}", path.filename().string(), crypto::name(hash)),
                        ByteView(bytes));
            if (path.filename() == "agreement-en" && hash == crypto::HashAlg::sha256) {
                agreement_bundle = bytes;
            }
        }
    }
    std::string keywords;
    for (const auto& [id, word] : bo::english_pack().keywords) {
        keywords += (keywords.empty() ? "" : ", ") +
                    std::format("\"{}\": \"{}\"", id, word.spellings.front());
    }
    const bo::PackRead company =
        bo::read_pack(R"({"format": 1, "id": "acme-terms", "version": 3, "language": "en-x-acme", )"
                      R"("name": "Acme terms", "official": false, "edition": 1, )"
                      R"("reading": {"separation": "spaces"}, "keywords": {)" +
                      keywords + R"(}, "vocabulary": {"role.supplier": "vendor"}})");
    if (!company.pack) {
        throw std::runtime_error("the company pack");
    }
    const bo::PackSetRead with_company = bo::make_pack_set({*company.pack});
    if (!with_company.set) {
        throw std::runtime_error("the company pack with the official ones");
    }
    const auto embedded =
        must(bo::make_source_bundle("contract Supply\nparties we, vendor\nthing Order\n  amount "
                                    "HKD\ncan countersign by vendor\n  proposed -> signed\n",
                                    1, *with_company.set, provider, crypto::HashAlg::sha256),
             "bundle");
    seeds.write("bo_source_fuzz", "embedded-pack",
                ByteView(must(bo::encode_source_bundle(embedded), "bundle")));

    // Vocabulary packs: the official files, current and carried, as
    // written and as CBOR; users' packs (the example's, the goldens'); and a
    // bundle that embeds one (key 7).
    for (const bo::VocabularyText& text : bo::official_vocabulary_texts()) {
        seeds.write("bo_vocab_fuzz", std::format("{}-{}.vocab", text.id, text.version), text.text);
        const bo::VocabularyPack* pack = bo::find_vocabulary_pack(text.id, text.version);
        seeds.write("bo_vocab_fuzz", std::format("{}-{}.cbor", text.id, text.version),
                    pack->canonical);
    }
    const std::filesystem::path events =
        std::filesystem::path(CEXCHAIN_BO_GOLDEN_DIR) / ".." / ".." / ".." / "examples" / "events";
    std::vector<bo::VocabularyHandle> users;
    for (const std::filesystem::path& file :
         {events / "events.vocab",
          std::filesystem::path(CEXCHAIN_BO_GOLDEN_DIR) / "check-vocab" / "alpha.vocab",
          std::filesystem::path(CEXCHAIN_BO_GOLDEN_DIR) / "check-vocab" / "beta.vocab"}) {
        std::ifstream in(file, std::ios::binary);
        std::stringstream text;
        text << in.rdbuf();
        seeds.write("bo_vocab_fuzz", file.filename().string(), text.str());
        const bo::VocabularyRead read = bo::read_vocabulary_pack(text.str());
        if (read.pack == nullptr) {
            throw std::runtime_error("the vocabulary pack " + file.string());
        }
        seeds.write("bo_vocab_fuzz", file.stem().string() + ".cbor", read.pack->canonical);
        if (file.filename() == "events.vocab") {
            users.push_back(read.pack);
        }
    }
    const bo::PackSetRead with_events = bo::make_pack_set({}, bo::Officials::current, users);
    if (!with_events.set) {
        throw std::runtime_error("the events pack with the official ones");
    }
    std::ifstream tickets(events / "tickets.bo", std::ios::binary);
    std::stringstream tickets_text;
    tickets_text << tickets.rdbuf();
    const auto with_vocabulary =
        must(bo::make_source_bundle(tickets_text.str(), 1, *with_events.set, provider,
                                    crypto::HashAlg::sha256),
             "bundle");
    seeds.write("bo_source_fuzz", "embedded-vocabulary",
                ByteView(must(bo::encode_source_bundle(with_vocabulary), "bundle")));

    std::ifstream vectors(CEXCHAIN_TESTVECTORS_DIR "/bo-v1.json");
    if (!vectors) {
        throw std::runtime_error("cannot read bo-v1.json");
    }
    const auto doc = nlohmann::json::parse(vectors);
    bo::BuiltContract built;
    built.code = must(from_hex(doc.at("contracts").at(0).at("code").get<std::string>()), "code");
    built.interface = {{"amend", protocol::FunctionKind::call},
                       {"close", protocol::FunctionKind::call},
                       {"countersign", protocol::FunctionKind::call},
                       {"create", protocol::FunctionKind::create},
                       {"sign", protocol::FunctionKind::call}};
    built.compiler = "cexchain-bo 0.0.1; codegen 1; edition 1";
    built.source = agreement_bundle;
    built.name = "Agreement";
    seeds.write("bo_source_fuzz", "agreement.boc", ByteView(must(bo::encode_built(built), "boc")));
    seeds.write("bo_source_fuzz", "compiler", built.compiler);
    // Bundles deployed with earlier releases of the official packs (version
    // 1, before vocabulary packs, with no key 6; version 2, before
    // temperatures and field defaults), which open with the packs carried
    // for them.
    for (const auto& contract : doc.at("contracts")) {
        std::size_t n = 0;
        for (const auto& earlier : contract.value("earlier", nlohmann::json::array())) {
            const Bytes bundle = must(from_hex(earlier.at("bundle").get<std::string>()), "bundle");
            seeds.write("bo_source_fuzz",
                        std::format("earlier-{}-{}", contract.at("name").get<std::string>(), ++n),
                        ByteView(bundle));
        }
    }
#else
    static_cast<void>(seeds);
#endif
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::println(stderr, "usage: make_seeds DIR");
        return 1;
    }
    try {
        const Seeds seeds(argv[1]);
        ledger_seeds(seeds);
        webauthn_seed(seeds);
        cluster_seeds(seeds);
        pending_call_seeds(seeds);
        text_seeds(seeds);
        vm_seeds(seeds);
        contract_seeds(seeds);
        child_seeds(seeds);
        request_seeds(seeds);
        generic_seeds(seeds);
        bo_seeds(seeds);
    } catch (const std::exception& e) {
        std::println(stderr, "error: {}", e.what());
        return 1;
    }
    return 0;
}
