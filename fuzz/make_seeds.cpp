// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Writes valid inputs for the fuzz targets, to start their corpora from:
// random bytes rarely get past a signature, so the deeper checks (evidence
// replay, access rules, backup restore, passkey registration) are reached
// from real objects mutated, not from nothing.
//
//   make_seeds DIR    writes DIR/<target>/<name> for each target

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <print>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/access.hpp>
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

/// A ledger with a certificate (fields and an attachment), an access
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
    const auto certificate = submit(protocol::RecordRegisterBody{
        "cexchain.certificate/1",
        Bytes(commitment.root.bytes().begin(), commitment.root.bytes().end()),
        commitment.leaves.size(),
        {{"report.pdf", "application/pdf", report.size(),
          Bytes(attachment.bytes().begin(), attachment.bytes().end())}},
        std::nullopt});

    const protocol::AccessRequest request{ledger.id(),
                                          certificate,
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
    const protocol::AccessGrant grant{ledger.id(),    request_id,    certificate,      {"result"},
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
    auto bundle = must(ledger.export_evidence(log, certificate), "export");
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
    seeds.write("protocol_parse_fuzz", "bundle-rotated",
                must(protocol::encode_bundle(must(ledger.export_evidence(log2, certificate), "e")),
                     "encode"));
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
    write("checkpoint", 1,
          Value::array({Value::unsigned_integer(2), Value::null(), Value::bytes(Bytes(60, 0xd2))}));
    write("cosignature", 2,
          Value::array({Value::unsigned_integer(3), Value::bytes(Bytes(60, 0xd2)),
                        Value::array({Value::integer(-19), Value::bytes(Bytes(32, 7))})}));
    write("snapshot-header", 3,
          Value::array({Value::bytes(Bytes(32, 1)), Value::unsigned_integer(5),
                        Value::unsigned_integer(1)}));
    write("snapshot-entries", 4, Value::array({Value::bytes(Bytes(20, 3))}));
    write("snapshot-extras", 5, Value::array({Value::array({}), Value::array({})}));
}

void text_seeds(const Seeds& seeds) {
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
    seeds.write("pkcs11_uri_fuzz", "key",
                "pkcs11:token=CexChain;object=alice;type=private?module-path=/usr/lib/"
                "softhsm/libsofthsm2.so&pin-source=file:/run/pin");
    seeds.write("pkcs11_uri_fuzz", "sm2",
                "pkcs11:serial=0123;id=%01%02;slot-id=0?module-path=/opt/ukey.so&"
                "x-sm2-mechanism=0x80000001");
}

} // namespace

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
        text_seeds(seeds);
    } catch (const std::exception& e) {
        std::println(stderr, "error: {}", e.what());
        return 1;
    }
    return 0;
}
