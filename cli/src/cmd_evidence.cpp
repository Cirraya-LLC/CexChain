// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <print>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/merkle.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/core/protocol/witness.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "records.hpp"

namespace cexchain::cli {

namespace {

Json digests_json(const std::vector<crypto::Digest>& path) {
    Json out = Json::array();
    for (const crypto::Digest& d : path) {
        out.push_back(to_hex(d.bytes()));
    }
    return out;
}

void print_checkpoint(const protocol::SignedCheckpoint& c) {
    std::println("size:       {}", c.checkpoint.tree_size);
    std::println("root:       {}", to_hex(c.checkpoint.root.bytes()));
    std::println("signed:     {}", format_time(c.checkpoint.timestamp));
    std::println("ledger:     {}", hex_id(c.checkpoint.ledger_id));
    std::println("tree hash:  {}", crypto::name(c.checkpoint.tree_hash));
    std::println("key id:     {}", hex_id(c.kid));
}

std::uint64_t index_argument(const Session& session, const std::string& text) {
    return session.entry_index(text);
}

/// The statement's id under each ledger hash: a statement alone does not say
/// which hash its ledger uses (only genesis does).
Json statement_ids_json(const crypto::Provider& provider, ByteView encoded) {
    Json ids = Json::object();
    for (const crypto::HashAlg hash : {crypto::HashAlg::sha256, crypto::HashAlg::sm3}) {
        if (const auto parsed = protocol::parse_statement(provider, encoded, hash)) {
            ids[std::string(crypto::name(hash))] = id_json(parsed->id);
        }
    }
    return ids;
}

Json inspect_json(const crypto::Provider& provider, const Bytes& content) {
    const auto value = cbor::decode(content);
    if (value) {
        if (const auto key = protocol::decode_public_key(*value)) {
            Json ids = Json::object();
            for (const crypto::HashAlg hash : {crypto::HashAlg::sha256, crypto::HashAlg::sm3}) {
                if (const auto kid = protocol::key_id(provider, hash, *key)) {
                    ids[std::string(crypto::name(hash))] = id_json(*kid);
                }
            }
            return {
                {"kind", "public-key"}, {"public_key", public_key_json(*key)}, {"key_ids", ids}};
        }
    }
    if (const auto key = decode_vault_public_key(content)) {
        return {{"kind", "vault-public-key"},
                {"algorithm", "X25519 (HPKE)"},
                {"public_key", to_hex(*key)}};
    }
    if (is_sealed_vault(content)) {
        return {{"kind", "sealed-vault"},
                {"note", "private record data, readable only with the vault private key"}};
    }
    if (crypto::openssl::is_encrypted_pkcs8(content)) {
        return {{"kind", "private-key"}, {"encrypted", true}};
    }
    if (const auto key = crypto::openssl::HpkeKey::from_pkcs8(content)) {
        return {{"kind", "vault-private-key"},
                {"encrypted", false},
                {"public_key", to_hex(key->public_key())}};
    }
    if (const auto key = crypto::openssl::KeyPair::from_pkcs8(content)) {
        return {{"kind", "private-key"},
                {"encrypted", false},
                {"public_key", public_key_json(key->public_key())}};
    }
    if (!value) {
        throw CommandError{"not a CexChain file (not CBOR, not a PKCS #8 key)"};
    }
    if (const auto bundle = protocol::decode_bundle(content)) {
        Json out{{"kind", "evidence-bundle"},
                 {"record", id_json(bundle->record)},
                 {"entries", bundle->entries.size()},
                 {"cosignatures", bundle->cosignatures.size()},
                 {"disclosed_fields", bundle->disclosures.size()},
                 {"attachment_openings", bundle->attachments.size()}};
        if (const auto checkpoint = protocol::parse_checkpoint(bundle->checkpoint)) {
            out["checkpoint"] = checkpoint_json(checkpoint->checkpoint);
        }
        out["note"] = "decoded only; run cexchain verify to check it";
        return out;
    }
    if (const auto request = protocol::decode_cosign_request(content)) {
        Json out{{"kind", "cosign-request"},
                 {"old_size", request->old_size},
                 {"proof", digests_json(request->proof)}};
        if (const auto checkpoint = protocol::parse_checkpoint(request->checkpoint)) {
            out["checkpoint"] = checkpoint_json(checkpoint->checkpoint);
        }
        return out;
    }
    if (const auto receipt = protocol::parse_receipt(content)) {
        return {{"kind", "receipt"},
                {"tree_hash", crypto::name(receipt->tree_hash)},
                {"tree_size", receipt->proof.tree_size},
                {"leaf_index", receipt->proof.leaf_index},
                {"proof", digests_json(receipt->proof.path)},
                {"kid", id_json(receipt->kid)},
                {"algorithm", crypto::name(receipt->envelope.algorithm)}};
    }
    if (const auto checkpoint = protocol::parse_checkpoint(content)) {
        return {{"kind", "checkpoint"},
                {"checkpoint", checkpoint_json(checkpoint->checkpoint)},
                {"kid", id_json(checkpoint->kid)},
                {"algorithm", crypto::name(checkpoint->envelope.algorithm)}};
    }
    if (const auto cosignature = protocol::parse_cosignature(content)) {
        return {{"kind", "cosignature"},
                {"checkpoint", checkpoint_json(cosignature->checkpoint)},
                {"witness_kid", id_json(cosignature->kid)},
                {"algorithm", crypto::name(cosignature->envelope.algorithm)}};
    }
    if (const auto entry = protocol::decode_log_entry(content)) {
        Json out{{"kind", "log-entry"},
                 {"statement_id", id_json(entry->statement_id)},
                 {"registered_at", iso_time(entry->registered_at)}};
        for (const crypto::HashAlg hash : {crypto::HashAlg::sha256, crypto::HashAlg::sm3}) {
            const auto parsed = protocol::parse_statement(provider, entry->statement, hash);
            if (parsed && parsed->id == entry->statement_id) {
                out["ledger_hash"] = crypto::name(hash);
                out["statement"] = statement_json(parsed->statement);
                break;
            }
        }
        return out;
    }
    if (const auto genesis = protocol::parse_statement(provider, content)) {
        return {{"kind", "statement"},
                {"statement_id", id_json(genesis->id)},
                {"algorithm", crypto::name(genesis->envelope.algorithm)},
                {"statement", statement_json(genesis->statement)}};
    }
    for (const crypto::HashAlg hash : {crypto::HashAlg::sha256, crypto::HashAlg::sm3}) {
        if (const auto statement = protocol::parse_statement(provider, content, hash)) {
            return {{"kind", "statement"},
                    {"statement_ids", statement_ids_json(provider, content)},
                    {"algorithm", crypto::name(statement->envelope.algorithm)},
                    {"kid", id_json(statement->kid)},
                    {"statement", statement_json(statement->statement)}};
        }
    }
    if (const cbor::Array* items = value->as_array();
        items != nullptr &&
        std::ranges::all_of(*items, [](const cbor::Value& v) { return v.as_bytes() != nullptr; })) {
        Json entries = Json::array();
        for (const cbor::Value& item : *items) {
            const auto entry = protocol::decode_log_entry(*item.as_bytes());
            if (!entry) {
                throw CommandError{"not a CexChain file"};
            }
            entries.push_back({{"statement_id", id_json(entry->statement_id)},
                               {"registered_at", iso_time(entry->registered_at)}});
        }
        return {{"kind", "log-export"}, {"entries", std::move(entries)}};
    }
    throw CommandError{"CBOR, but not a CexChain object (use --raw to see it)"};
}

} // namespace

// ---------------------------------------------------------------------------
// Checkpoints
// ---------------------------------------------------------------------------

int cmd_checkpoint_create(const Args& args) {
    Session session(args.ledger());
    const auto log_key = load_key(args.need("log-key"), args);
    const auto c = unwrap(session.ledger().checkpoint(log_key), "checkpointing");
    if (args.json()) {
        print_json(checkpoint_json(c.checkpoint));
    } else {
        std::println("checkpoint: size {}, root {}", c.checkpoint.tree_size,
                     to_hex(c.checkpoint.root.bytes()));
    }
    return exit_ok;
}

int cmd_checkpoint_list(const Args& args) {
    Session session(args.ledger());
    const auto checkpoints = unwrap(session.ledger().checkpoints(), "reading checkpoints");
    Json out = Json::array();
    const auto cosignatures = unwrap(session.ledger().cosignatures(), "reading cosignatures");
    auto witnesses_of = [&](const protocol::Checkpoint& checkpoint) {
        Json kids = Json::array();
        for (const ledger::StoredCosignature& c : cosignatures) {
            if (c.cosignature.checkpoint == checkpoint) {
                kids.push_back(id_json(c.cosignature.kid));
            }
        }
        return kids;
    };
    for (const protocol::SignedCheckpoint& c : checkpoints) {
        if (args.json()) {
            Json item = checkpoint_json(c.checkpoint);
            item["witnesses"] = witnesses_of(c.checkpoint);
            out.push_back(std::move(item));
        } else {
            const std::size_t witnesses = witnesses_of(c.checkpoint).size();
            std::println("size {:<8} {}  root {}{}", c.checkpoint.tree_size,
                         format_time(c.checkpoint.timestamp), to_hex(c.checkpoint.root.bytes()),
                         witnesses == 0 ? "" : std::format("  ({} witnesses)", witnesses));
        }
    }
    if (args.json()) {
        print_json(out);
    } else if (checkpoints.empty()) {
        std::println("no checkpoints yet (cexchain checkpoint create)");
    }
    return exit_ok;
}

int cmd_checkpoint_show(const Args& args) {
    Session session(args.ledger());
    const auto checkpoints = unwrap(session.ledger().checkpoints(), "reading checkpoints");
    if (checkpoints.empty()) {
        throw CommandError{"the ledger has no checkpoints yet"};
    }
    const protocol::SignedCheckpoint* chosen = &checkpoints.back();
    if (!args.positional().empty()) {
        const std::uint64_t size = parse_number(args.positional().front(), "SIZE");
        const auto it = std::ranges::find_if(checkpoints, [&](const protocol::SignedCheckpoint& c) {
            return c.checkpoint.tree_size == size;
        });
        if (it == checkpoints.end()) {
            throw CommandError{"no checkpoint of size " + std::to_string(size)};
        }
        chosen = &*it;
    }
    if (const auto out = args.get("out")) {
        write_file(*out, chosen->encoded, false);
    }
    Json witnesses = Json::array();
    for (const ledger::StoredCosignature& c :
         unwrap(session.ledger().cosignatures(), "reading cosignatures")) {
        if (c.cosignature.checkpoint == chosen->checkpoint) {
            witnesses.push_back(
                {{"kid", id_json(c.cosignature.kid)}, {"key", public_key_json(c.witness)}});
        }
    }
    if (args.json()) {
        Json out = checkpoint_json(chosen->checkpoint);
        out["kid"] = id_json(chosen->kid);
        out["witnesses"] = witnesses;
        out["signed_checkpoint"] = to_hex(chosen->encoded);
        print_json(out);
        return exit_ok;
    }
    print_checkpoint(*chosen);
    for (const auto& w : witnesses) {
        std::println("witness:    {} key {}", w["key"]["algorithm"].get<std::string>(),
                     w["key"]["key"].get<std::string>());
    }
    if (const auto out = args.get("out")) {
        std::println("written to: {}", *out);
    }
    return exit_ok;
}

// ---------------------------------------------------------------------------
// Proofs and receipts
// ---------------------------------------------------------------------------

int cmd_proof_inclusion(const Args& args) {
    Session session(args.ledger());
    const std::uint64_t index = index_argument(session, args.positional().front());
    const std::uint64_t size =
        args.has("size") ? parse_number(*args.get("size"), "--size") : session.ledger().size();
    if (index >= size || size > session.ledger().size()) {
        throw UsageError{std::format("need INDEX < SIZE <= {}", session.ledger().size())};
    }
    const crypto::HashAlg hash = session.state().hash();
    const Bytes entry = unwrap(session.ledger().entry(index), "reading the log");
    const auto leaf = unwrap(merkle::leaf_hash(session.provider(), hash, entry), "hashing");
    const auto root = unwrap(session.ledger().root(size), "computing the root");
    const auto path = unwrap(session.ledger().inclusion_proof(index, size), "building the proof");
    unwrap(merkle::verify_inclusion(session.provider(), hash, leaf, index, size, path, root),
           "self-check of the proof");
    if (args.json()) {
        print_json({{"index", index},
                    {"tree_size", size},
                    {"leaf_hash", to_hex(leaf.bytes())},
                    {"root", to_hex(root.bytes())},
                    {"path", digests_json(path)}});
        return exit_ok;
    }
    std::println("entry:      #{}", index);
    std::println("tree size:  {}", size);
    std::println("leaf hash:  {}", to_hex(leaf.bytes()));
    std::println("root:       {}", to_hex(root.bytes()));
    std::println("path:       {} hashes", path.size());
    for (const crypto::Digest& d : path) {
        std::println("  {}", to_hex(d.bytes()));
    }
    return exit_ok;
}

int cmd_proof_consistency(const Args& args) {
    Session session(args.ledger());
    const std::uint64_t old_size = parse_number(args.positional()[0], "OLD");
    const std::uint64_t new_size = parse_number(args.positional()[1], "NEW");
    if (old_size > new_size || new_size > session.ledger().size()) {
        throw UsageError{std::format("need OLD <= NEW <= {}", session.ledger().size())};
    }
    const auto old_root = unwrap(session.ledger().root(old_size), "computing the root");
    const auto new_root = unwrap(session.ledger().root(new_size), "computing the root");
    const auto path =
        unwrap(session.ledger().consistency_proof(old_size, new_size), "building the proof");
    unwrap(merkle::verify_consistency(session.provider(), session.state().hash(), old_size,
                                      new_size, old_root, new_root, path),
           "self-check of the proof");
    if (args.json()) {
        print_json({{"old_size", old_size},
                    {"new_size", new_size},
                    {"old_root", to_hex(old_root.bytes())},
                    {"new_root", to_hex(new_root.bytes())},
                    {"path", digests_json(path)}});
        return exit_ok;
    }
    std::println("old:        size {}, root {}", old_size, to_hex(old_root.bytes()));
    std::println("new:        size {}, root {}", new_size, to_hex(new_root.bytes()));
    std::println("path:       {} hashes", path.size());
    for (const crypto::Digest& d : path) {
        std::println("  {}", to_hex(d.bytes()));
    }
    return exit_ok;
}

int cmd_receipt(const Args& args) {
    Session session(args.ledger());
    const std::uint64_t index = index_argument(session, args.positional().front());
    const auto log_key = load_key(args.need("log-key"), args);
    const Bytes receipt = unwrap(session.ledger().receipt(log_key, index), "issuing the receipt");
    const std::filesystem::path out = args.need("out");
    write_file(out, receipt, false);
    const auto parsed = unwrap(protocol::parse_receipt(receipt), "parsing the receipt");
    if (args.json()) {
        print_json(
            {{"file", out.string()}, {"index", index}, {"tree_size", parsed.proof.tree_size}});
    } else {
        std::println("wrote the receipt for entry #{} (tree size {}) to {}", index,
                     parsed.proof.tree_size, out.string());
    }
    return exit_ok;
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

int cmd_export(const Args& args) {
    Session session(args.ledger());
    const protocol::Id record = session.record_id(args.positional().front());
    const auto log_key = load_key(args.need("log-key"), args);
    auto bundle = unwrap(session.ledger().export_evidence(log_key, record), "exporting evidence");

    const auto disclose = split(args.get("disclose").value_or(""), ',');
    if (!disclose.empty() || args.has("with-attachments")) {
        const Vault vault = read_vault(session, record, args);
        const auto commitment = unwrap(
            protocol::commit_fields(session.provider(), session.state().hash(), vault.fields),
            "fields");
        for (const std::string& name : disclose) {
            bundle.disclosures.push_back(
                unwrap(protocol::disclose_field(session.provider(), session.state().hash(),
                                                commitment, name),
                       "disclosing " + name));
        }
        if (args.has("with-attachments")) {
            for (const VaultAttachment& a : vault.attachments) {
                bundle.attachments.push_back({a.name, a.salt});
            }
        }
    }
    const auto checkpoint = unwrap(protocol::parse_checkpoint(bundle.checkpoint), "checkpoint");
    for (const std::string& path : args.all("cosignature")) {
        const Bytes encoded = read_file(path);
        const auto cosignature = unwrap(protocol::parse_cosignature(encoded), "reading " + path);
        if (cosignature.checkpoint != checkpoint.checkpoint) {
            throw CommandError{path + " cosigns a different checkpoint (size " +
                               std::to_string(cosignature.checkpoint.tree_size) + ", not " +
                               std::to_string(checkpoint.checkpoint.tree_size) + ")"};
        }
        bundle.cosignatures.push_back(encoded);
    }
    const std::filesystem::path out = args.need("out");
    write_file(out, unwrap(protocol::encode_bundle(bundle), "encoding the bundle"), false);
    if (args.json()) {
        print_json({{"file", out.string()},
                    {"record", id_json(record)},
                    {"entries", bundle.entries.size()},
                    {"checkpoint_size", checkpoint.checkpoint.tree_size},
                    {"disclosed_fields", disclose},
                    {"attachment_openings", bundle.attachments.size()},
                    {"cosignatures", bundle.cosignatures.size()}});
    } else {
        std::println(
            "wrote evidence for {} ({} entries, {} disclosed fields, {} cosignatures) to {}",
            short_id(record), bundle.entries.size(), bundle.disclosures.size(),
            bundle.cosignatures.size(), out.string());
    }
    return exit_ok;
}

int cmd_verify(const Args& args) {
    const crypto::openssl::Provider provider;
    protocol::VerifyOptions options;
    if (const auto ledger_id = args.get("ledger-id")) {
        const auto bytes = from_hex(*ledger_id);
        if (!bytes) {
            throw UsageError{"--ledger-id must be the full hex ledger id"};
        }
        options.expected_ledger = unwrap(protocol::to_id(*bytes), "ledger id");
    }
    for (const std::string& path : args.all("witness")) {
        options.trusted_witnesses.push_back(load_public_key(path));
    }
    for (const std::string& item : args.all("attachment")) {
        auto [name, path] = split_pair(item, "--attachment");
        options.attachment_contents[name] = read_file(path);
    }
    const auto report =
        protocol::verify_bundle(provider, read_file(args.positional().front()), options);
    if (!report) {
        if (args.json()) {
            print_json({{"verified", false}, {"error", report.error().detail}});
        } else {
            std::println("VERIFICATION FAILED: {}", report.error().detail);
        }
        return exit_not_verified;
    }
    const bool mismatch = verifier::has_attachment_mismatch(*report);
    const std::uint64_t min_witnesses =
        args.has("min-witnesses") ? parse_number(*args.get("min-witnesses"), "--min-witnesses") : 0;
    const bool too_few_witnesses = report->trusted_cosignatures < min_witnesses;
    const bool verified = !mismatch && !too_few_witnesses;
    if (args.json()) {
        Json out = report_json(*report, options.expected_ledger.has_value());
        out["verified"] = verified;
        if (too_few_witnesses) {
            out["error"] = std::format("{} trusted witness cosignatures, {} required",
                                       report->trusted_cosignatures, min_witnesses);
        }
        print_json(out);
    } else {
        std::print("{}", verifier::report_text(*report, options.expected_ledger.has_value()));
        if (mismatch) {
            std::println("\nVERIFICATION FAILED: an attachment does not match its commitment");
        }
        if (too_few_witnesses) {
            std::println("\nVERIFICATION FAILED: {} trusted witness cosignatures, {} required",
                         report->trusted_cosignatures, min_witnesses);
        }
    }
    return verified ? exit_ok : exit_not_verified;
}

int cmd_inspect(const Args& args) {
    const crypto::openssl::Provider provider;
    const Bytes content = read_file(args.positional().front());
    Json out = inspect_json(provider, content);
    if (args.has("raw")) {
        if (const auto value = cbor::decode(content)) {
            out["raw"] = cbor::diagnostic(*value);
        }
    }
    if (args.json()) {
        print_json(out);
        return exit_ok;
    }
    std::println("{}", out["kind"].get<std::string>());
    for (const auto& [key, value] : out.items()) {
        if (key == "kind" || key == "raw") {
            continue;
        }
        std::println("{}: {}", key, value.is_string() ? value.get<std::string>() : value.dump(2));
    }
    if (out.contains("raw")) {
        std::println("raw:\n{}", out["raw"].get<std::string>());
    }
    return exit_ok;
}

} // namespace cexchain::cli
