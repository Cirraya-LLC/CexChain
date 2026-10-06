// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <print>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/common.hpp>

#include "commands.hpp"
#include "output.hpp"

namespace cexchain::cli {

namespace {

struct KeyFile {
    crypto::PublicKey public_key;
    bool is_private = false;
    bool encrypted = false;
};

/// Reads a private key file (asking for its passphrase if needed) or a
/// public key file.
KeyFile read_key_file(const std::filesystem::path& path, const Args& args) {
    const Bytes content = read_file(path);
    if (const auto value = cbor::decode(content)) {
        if (auto key = protocol::decode_public_key(*value)) {
            return {*key, false, false};
        }
    }
    const bool encrypted = crypto::openssl::is_encrypted_pkcs8(content);
    return {load_key(path, args).public_key(), true, encrypted};
}

Json key_ids_json(const crypto::Provider& provider, const crypto::PublicKey& key) {
    Json ids = Json::object();
    for (const crypto::HashAlg hash : {crypto::HashAlg::sha256, crypto::HashAlg::sm3}) {
        if (const auto kid = protocol::key_id(provider, hash, key)) {
            ids[std::string(crypto::name(hash))] = id_json(*kid);
        }
    }
    return ids;
}

} // namespace

int cmd_key_generate(const Args& args) {
    const crypto::SigAlg alg = parse_algorithm(args.get("alg").value_or("ed25519"));
    const std::filesystem::path out = args.need("out");
    if (std::filesystem::exists(out)) {
        throw CommandError{out.string() + " already exists; keys are never overwritten"};
    }
    const bool encrypt = !args.has("no-passphrase");
    if (!encrypt && args.has("passphrase-file")) {
        throw UsageError{"--no-passphrase and --passphrase-file contradict each other"};
    }
    const std::optional<std::string> secret =
        encrypt ? std::optional(passphrase(args, out.string(), true)) : std::nullopt;
    const auto key = unwrap(crypto::openssl::KeyPair::generate(alg), "generating the key");
    save_key(out, key, secret);
    if (args.json()) {
        print_json({{"file", out.string()},
                    {"encrypted", encrypt},
                    {"public_key", public_key_json(key.public_key())}});
        return exit_ok;
    }
    std::println("{} key written to {}{}", crypto::name(alg), out.string(),
                 encrypt ? " (encrypted)" : " (NOT encrypted)");
    std::println("public key: {}", to_hex(key.public_key().bytes));
    return exit_ok;
}

int cmd_key_show(const Args& args) {
    const std::filesystem::path path = args.positional().front();
    const KeyFile key = read_key_file(path, args);
    const crypto::openssl::Provider provider;
    const Json ids = key_ids_json(provider, key.public_key);
    if (args.json()) {
        print_json({{"file", path.string()},
                    {"type", key.is_private ? "private" : "public"},
                    {"encrypted", key.encrypted},
                    {"public_key", public_key_json(key.public_key)},
                    {"key_ids", ids}});
        return exit_ok;
    }
    std::println("file:        {}", path.string());
    std::println("type:        {}", key.is_private ? (key.encrypted ? "private key (encrypted)"
                                                                    : "private key (NOT encrypted)")
                                                   : "public key");
    std::println("algorithm:   {}", crypto::name(key.public_key.algorithm));
    std::println("public key:  {}", to_hex(key.public_key.bytes));
    for (const auto& [hash, id] : ids.items()) {
        std::println("key id:      {} ({} ledgers)", id.get<std::string>(), hash);
    }
    return exit_ok;
}

int cmd_key_public(const Args& args) {
    const std::filesystem::path path = args.positional().front();
    const KeyFile key = read_key_file(path, args);
    const Bytes encoded = encode_public_key_file(key.public_key);
    if (const auto out = args.get("out")) {
        write_file(*out, encoded, false);
        if (args.json()) {
            print_json({{"file", *out}, {"public_key", public_key_json(key.public_key)}});
        } else {
            std::println("public key written to {}", *out);
        }
        return exit_ok;
    }
    if (args.json()) {
        print_json(
            {{"public_key", public_key_json(key.public_key)}, {"file_contents", to_hex(encoded)}});
    } else {
        std::println("{}", to_hex(encoded));
    }
    return exit_ok;
}

int cmd_key_passphrase(const Args& args) {
    const std::filesystem::path path = args.positional().front();
    const auto key = load_key(path, args);
    const bool encrypt = !args.has("remove");
    if (!encrypt && args.has("new-passphrase-file")) {
        throw UsageError{"--remove and --new-passphrase-file contradict each other"};
    }
    const std::optional<std::string> secret =
        encrypt ? std::optional(passphrase(args, path.string() + " (new)", true,
                                           "new-passphrase-file", "CEXCHAIN_NEW_PASSPHRASE"))
                : std::nullopt;
    save_key(path, key, secret);
    if (args.json()) {
        print_json({{"file", path.string()}, {"encrypted", encrypt}});
    } else {
        std::println("{} {}", path.string(),
                     encrypt ? "is now encrypted with the new passphrase"
                             : "is now stored WITHOUT encryption");
    }
    return exit_ok;
}

} // namespace cexchain::cli
