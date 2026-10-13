// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Writes valid inputs for the fuzz targets, to start their corpora from:
// random bytes rarely get past a signature, so the deeper checks (evidence
// replay, access rules, backup restore, passkey registration) are reached
// from real objects mutated, not from nothing. The contract interpreter and
// the contract parsers start from testvectors/vm-v1.json and
// protocol-v0.6.json. A registrar's pending calls (node/contracts.hpp) are
// built here as CBOR, without the node library. The Bo pack reader starts
// from the official packs.
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
#endif
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/access.hpp>
#include <cexchain/core/protocol/asset_evidence.hpp>
#include <cexchain/core/protocol/assets.hpp>
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

/// One organization's ledger in memory, for the asset seeds.
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

/// A receivable pledged with two consents, and its asset evidence (D-052).
void asset_seeds(const Seeds& seeds) {
    Org home("Seed Core Enterprise", 11);
    Org supplier("Seed Supplier", 12);
    Org bank("Seed Bank", 13);
    const auto metadata =
        must(protocol::encode_asset_metadata(
                 protocol::AssetKind::receivable,
                 {supplier.id(), 12'500'000, "CNY", home.clock.now() + 90 * 86'400'000ULL},
                 {{cbor::Value::text("title"), cbor::Value::text("PO-0815")}}),
             "metadata");
    seeds.write("asset_parse_fuzz", "receivable-metadata", must(cbor::encode(metadata), "encode"));
    seeds.write("asset_parse_fuzz", "receipt-metadata",
                must(cbor::encode(must(
                         protocol::encode_asset_metadata(protocol::AssetKind::warehouse_receipt,
                                                         {supplier.id(), 100, "t", std::nullopt}),
                         "metadata")),
                     "encode"));
    const protocol::Id receivable = home.record(protocol::receivable_type, metadata);

    protocol::AssetActionBody pledge;
    pledge.asset = receivable;
    pledge.action = protocol::AssetAction::pledge;
    pledge.head = home.ledger->state().asset(receivable)->head;
    pledge.to = bank.id();
    const protocol::AssetConsent consent{protocol::terms_of(pledge, home.id()),
                                         home.clock.now() + 86'400'000, "Loan SCF-0042"};
    const auto consent_metadata = must(protocol::encode_asset_consent(consent), "consent");
    seeds.write("asset_parse_fuzz", "consent", must(cbor::encode(consent_metadata), "encode"));

    std::vector<std::pair<protocol::ConsentRef, Bytes>> consents;
    for (Org* party : {&supplier, &bank}) {
        const protocol::Id record = party->record(protocol::asset_consent_type, consent_metadata);
        Bytes bundle = party->evidence(record);
        const auto digest = must(home.provider.digest(crypto::HashAlg::sha256, bundle), "hash");
        consents.emplace_back(protocol::ConsentRef{party->id(), record, digest}, std::move(bundle));
    }
    std::ranges::sort(consents, [](const auto& a, const auto& b) {
        return std::ranges::lexicographical_compare(a.first.ledger.bytes(), b.first.ledger.bytes());
    });
    std::vector<Bytes> bundles;
    for (auto& [ref, bundle] : consents) {
        pledge.consents.push_back(ref);
        bundles.push_back(std::move(bundle));
    }
    const auto action = home.submit(pledge);
    seeds.write("protocol_parse_fuzz", "statement-asset-action", action.encoded);
    seeds.write("protocol_parse_fuzz", "payload-asset-action",
                must(protocol::encode_payload(action.statement), "payload"));
    const Bytes evidence =
        must(protocol::encode_asset_evidence({home.evidence(receivable), std::move(bundles)}),
             "evidence");
    must(protocol::verify_asset_evidence(home.provider, evidence), "the seed evidence must verify");
    seeds.write("asset_parse_fuzz", "evidence", evidence);
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
    write("batch-consents", 0,
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

/// Every module of the interpreter's vectors, valid and refused: they cover
/// each instruction, trap, and validation rule.
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
        arguments(protocol::ContractAccept{cbor::Value::text("draft"),
                                           "proposed",
                                           protocol::Parties{{"supplier", supplier.id()}},
                                           {},
                                           false});
    const auto created = home.submit(create);
    seeds.write("protocol_parse_fuzz", "statement-contract-create", created.encoded);

    protocol::ContractCallBody sign;
    sign.instance = created.id;
    sign.function = "sign";
    sign.arguments = arguments(protocol::ContractAccept{
        cbor::Value::text("signed"), "effective", std::nullopt, {}, false});
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
        asset_seeds(seeds);
        webauthn_seed(seeds);
        cluster_seeds(seeds);
        pending_call_seeds(seeds);
        text_seeds(seeds);
        vm_seeds(seeds);
        contract_seeds(seeds);
        bo_seeds(seeds);
    } catch (const std::exception& e) {
        std::println(stderr, "error: {}", e.what());
        return 1;
    }
    return 0;
}
