// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <chrono>
#include <print>

#include "commands.hpp"
#include "output.hpp"
#include "records.hpp"

namespace cexchain::cli {

namespace {

std::string fingerprint(ByteView public_key) {
    const crypto::openssl::Provider provider;
    const auto digest = unwrap(provider.digest(crypto::HashAlg::sha256, public_key), "hashing");
    return to_hex(digest.bytes()).substr(0, 16);
}

} // namespace

int cmd_vault_status(const Args& args) {
    Session session(args);
    const bool has_key = std::filesystem::exists(vault_public_key_path(session));
    const std::optional<Bytes> public_key =
        has_key ? std::optional(vault_public_key(session)) : std::nullopt;
    const std::filesystem::path private_path = default_vault_key_path(session);
    const bool private_here = std::filesystem::exists(private_path);
    std::size_t sealed = 0;
    std::size_t plain = 0;
    std::size_t missing = 0;
    for (const auto& [key, record] : session.state().records()) {
        const std::filesystem::path path = session.vault_path(record.id);
        if (!std::filesystem::exists(path)) {
            ++missing;
        } else if (is_sealed_vault(read_file(path))) {
            ++sealed;
        } else {
            ++plain;
        }
    }
    if (args.json()) {
        print_json({{"public_key", public_key ? Json(to_hex(*public_key)) : Json(nullptr)},
                    {"fingerprint", public_key ? Json(fingerprint(*public_key)) : Json(nullptr)},
                    {"private_key", private_here ? Json(private_path.string()) : Json(nullptr)},
                    {"private_key_encrypted",
                     private_here && crypto::openssl::is_encrypted_pkcs8(read_file(private_path))},
                    {"sealed_records", sealed},
                    {"unsealed_records", plain},
                    {"records_without_private_data", missing}});
        return exit_ok;
    }
    if (!public_key) {
        std::println("vault key:     none (create one with: cexchain vault rekey)");
    } else {
        std::println("vault key:     X25519 {} (fingerprint {})", to_hex(*public_key),
                     fingerprint(*public_key));
        std::println("private key:   {}",
                     private_here
                         ? private_path.string() +
                               (crypto::openssl::is_encrypted_pkcs8(read_file(private_path))
                                    ? " (encrypted)"
                                    : " (NOT encrypted)")
                         : "not on this host (pass --vault-key to read records)");
    }
    std::println("sealed:        {} records", sealed);
    if (plain > 0) {
        std::println("NOT sealed:    {} records (seal them with: cexchain vault rekey)", plain);
    }
    if (missing > 0) {
        std::println("no data here:  {} records (issued elsewhere)", missing);
    }
    return exit_ok;
}

int cmd_vault_keygen(const Args& args) {
    const std::filesystem::path out = args.need("out");
    const std::filesystem::path public_out = out.string() + ".pub";
    if (std::filesystem::exists(out) || std::filesystem::exists(public_out)) {
        throw CommandError{out.string() + " or " + public_out.string() +
                           " already exists; keys are never overwritten"};
    }
    const bool encrypt = !args.has("no-passphrase");
    if (!encrypt && args.has("passphrase-file")) {
        throw UsageError{"--no-passphrase and --passphrase-file contradict each other"};
    }
    const std::optional<std::string> secret =
        encrypt ? std::optional(passphrase(args, out.string(), true)) : std::nullopt;
    const auto key = unwrap(crypto::openssl::HpkeKey::generate(), "generating the vault key");
    save_hpke_key(out, key, secret);
    write_file(public_out, encode_vault_public_key(key.public_key()), false);
    if (args.json()) {
        print_json({{"file", out.string()},
                    {"public_file", public_out.string()},
                    {"encrypted", encrypt},
                    {"public_key", to_hex(key.public_key())},
                    {"fingerprint", fingerprint(key.public_key())}});
        return exit_ok;
    }
    std::println("vault key written to {}{}", out.string(),
                 encrypt ? " (encrypted)" : " (NOT encrypted)");
    std::println("public half written to {} (fingerprint {})", public_out.string(),
                 fingerprint(key.public_key()));
    std::println("Use it with: cexchain init --vault-public-key {}   or   cexchain vault rekey "
                 "--new-public-key {}",
                 public_out.string(), public_out.string());
    return exit_ok;
}

int cmd_vault_rekey(const Args& args) {
    Session session(args);
    session.require_primary();
    const std::filesystem::path dir = session.directory();

    // Read every record's private data first, so nothing is written unless
    // all of it can be re-sealed.
    std::vector<protocol::Id> ids;
    bool any_sealed = false;
    for (const auto& [key, record] : session.state().records()) {
        const std::filesystem::path path = session.vault_path(record.id);
        if (std::filesystem::exists(path)) {
            ids.push_back(record.id);
            any_sealed = any_sealed || is_sealed_vault(read_file(path));
        }
    }
    std::optional<crypto::openssl::HpkeKey> current;
    if (any_sealed) {
        current.emplace(load_vault_key(session, args));
    }
    std::vector<Vault> vaults;
    for (const protocol::Id& id : ids) {
        vaults.push_back(load_vault(session, id, current ? &*current : nullptr));
    }

    // Build a complete new vault directory, then swap it in with two renames.
    // COMPLETE is written last; a session that finds vault/ missing finishes
    // the swap (see recover_vault_swap). The old vault, with its key, is kept.
    const std::filesystem::path next = dir / "vault.next";
    std::filesystem::remove_all(next);
    std::filesystem::create_directories(next / "records");

    std::optional<crypto::openssl::HpkeKey> generated;
    Bytes new_public;
    if (const auto file = args.get("new-public-key")) {
        auto key = decode_vault_public_key(read_file(*file));
        if (!key) {
            throw CommandError{
                *file + " is not a vault public key (create one with cexchain vault keygen)"};
        }
        new_public = std::move(*key);
    } else {
        const std::string secret = passphrase(args, "the new vault key", true,
                                              "new-passphrase-file", "CEXCHAIN_NEW_PASSPHRASE");
        generated.emplace(unwrap(crypto::openssl::HpkeKey::generate(), "generating the vault key"));
        new_public.assign(generated->public_key().begin(), generated->public_key().end());
        save_hpke_key(next / "vault.key", *generated, secret);
    }
    for (std::size_t i = 0; i < ids.size(); ++i) {
        write_file(next / "records" / session.vault_path(ids[i]).filename(),
                   seal_vault(session.state().ledger_id(), ids[i], vaults[i], new_public), true);
    }
    write_file(next / "vault.pub", encode_vault_public_key(new_public), false);
    write_file(next / "COMPLETE", as_bytes("complete\n"), false);

    std::optional<std::filesystem::path> previous;
    if (std::filesystem::exists(vault_directory(session))) {
        const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
        previous = dir / std::format("vault.old-{:%Y%m%dT%H%M%SZ}", now);
        for (int n = 2; std::filesystem::exists(*previous); ++n) {
            previous = dir / std::format("vault.old-{:%Y%m%dT%H%M%SZ}-{}", now, n);
        }
        std::filesystem::rename(vault_directory(session), *previous);
    }
    std::filesystem::rename(next, vault_directory(session));
    std::filesystem::remove(vault_directory(session) / "COMPLETE");

    if (args.json()) {
        print_json({{"records", ids.size()},
                    {"public_key", to_hex(new_public)},
                    {"fingerprint", fingerprint(new_public)},
                    {"private_key",
                     generated ? Json(default_vault_key_path(session).string()) : Json(nullptr)},
                    {"previous_vault", previous ? Json(previous->string()) : Json(nullptr)}});
        return exit_ok;
    }
    std::println("re-sealed {} records to vault key {}", ids.size(), fingerprint(new_public));
    if (generated) {
        std::println("new vault key: {} (encrypted)", default_vault_key_path(session).string());
    }
    if (previous) {
        std::println(
            "The previous vault, with its key, was kept in {}; delete it once no backup needs it.",
            previous->string());
    }
    return exit_ok;
}

} // namespace cexchain::cli
