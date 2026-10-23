// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <unistd.h>

#include <cexchain/app/support.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/ledger/ledger.hpp>
#include <cexchain/ledger/storage.hpp>

namespace cexchain::app {

Bytes read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw ActionError{"cannot read " + path.string()};
    }
    return Bytes(std::istreambuf_iterator<char>(in), {});
}

void write_file(const std::filesystem::path& path, ByteView data, bool private_file) {
    // A fresh temporary file of our own: never one someone else created (or
    // linked) beforehand in a shared directory, which would receive the
    // data, private keys included, with its own permissions.
    std::array<std::uint8_t, 8> random{};
    ledger::SystemEntropy{}.fill(random);
    const std::filesystem::path temporary = path.string() + "." + to_hex(random) + ".tmp";
    const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                          private_file ? 0600 : 0644);
    if (fd < 0) {
        throw ActionError{"cannot write " + path.string()};
    }
    std::size_t done = 0;
    while (done < data.size()) {
        const ssize_t n = ::write(fd, data.data() + done, data.size() - done);
        if (n <= 0) {
            ::close(fd);
            ::unlink(temporary.c_str());
            throw ActionError{"cannot write " + path.string()};
        }
        done += static_cast<std::size_t>(n);
    }
    const bool synced = ::fsync(fd) == 0;
    ::close(fd);
    if (!synced || std::rename(temporary.c_str(), path.c_str()) != 0) {
        ::unlink(temporary.c_str());
        throw ActionError{"cannot write " + path.string()};
    }
}

std::string redact_pin(std::string_view uri) {
    std::string out(uri);
    const std::size_t at = out.find("pin-value=");
    if (at == std::string::npos) {
        return out;
    }
    const std::size_t value = at + std::string_view("pin-value=").size();
    const std::size_t end = std::min(out.find('&', value), out.size());
    out.replace(value, end - value, "REDACTED");
    return out;
}

std::string hex_id(const protocol::Id& id) {
    return to_hex(id.bytes());
}

std::string short_id(const protocol::Id& id) {
    return hex_id(id).substr(0, 12);
}

protocol::Timestamp parse_time(std::string_view text) {
    int y = 0;
    unsigned mo = 0;
    unsigned d = 0;
    unsigned h = 0;
    unsigned mi = 0;
    unsigned s = 0;
    const std::string str(text);
    const int fields = std::sscanf(str.c_str(), "%d-%u-%uT%u:%u:%u", &y, &mo, &d, &h, &mi, &s);
    if (fields != 3 && fields != 6) {
        throw UsageError{"time must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ"};
    }
    using namespace std::chrono;
    const year_month_day date{year{y}, month{mo}, day{d}};
    if (!date.ok() || h > 23 || mi > 59 || s > 59) {
        throw UsageError{"invalid date " + str};
    }
    const auto time = sys_days{date} + hours{h} + minutes{mi} + seconds{s};
    return static_cast<protocol::Timestamp>(
        duration_cast<milliseconds>(time.time_since_epoch()).count());
}

crypto::openssl::KeyPair load_key(const std::filesystem::path& path,
                                  const PassphraseSource& passphrase) {
    const Bytes der = read_file(path);
    if (crypto::openssl::is_encrypted_pkcs8(der)) {
        auto key = crypto::openssl::KeyPair::from_encrypted_pkcs8(der, passphrase());
        if (!key && key.error().code == Errc::verification_failed) {
            throw ActionError{"wrong passphrase for " + path.string()};
        }
        return unwrap(std::move(key), "loading " + path.string());
    }
    auto key = crypto::openssl::KeyPair::from_pkcs8(der);
    if (!key) {
        if (const auto value = cbor::decode(der); value && protocol::decode_public_key(*value)) {
            throw ActionError{path.string() + " is a public key; this needs the private key file"};
        }
    }
    return unwrap(std::move(key), "loading " + path.string());
}

void save_key(const std::filesystem::path& path, const crypto::openssl::KeyPair& key,
              const std::optional<std::string>& secret) {
    if (secret) {
        write_file(path, unwrap(key.to_encrypted_pkcs8(*secret), "encrypting the key"), true);
    } else {
        write_file(path, unwrap(key.to_pkcs8(), "encoding the key").view(), true);
    }
}

Bytes encode_public_key_file(const crypto::PublicKey& key) {
    return unwrap(cbor::encode(protocol::encode_public_key(key)), "encoding the public key");
}

crypto::PublicKey load_public_key(const std::filesystem::path& path) {
    const Bytes content = read_file(path);
    if (const auto value = cbor::decode(content)) {
        if (auto key = protocol::decode_public_key(*value)) {
            return *key;
        }
    }
    if (crypto::openssl::is_encrypted_pkcs8(content) ||
        crypto::openssl::KeyPair::from_pkcs8(content)) {
        throw ActionError{path.string() +
                          " is a private key; share only its public half (cexchain key public " +
                          path.string() + " --out FILE)"};
    }
    throw ActionError{path.string() + " is not a CexChain public key file"};
}

const crypto::openssl::Provider& shared_provider() {
    static const crypto::openssl::Provider provider;
    return provider;
}

Bytes hash_text(const crypto::Provider& provider, crypto::HashAlg hash, std::string_view text) {
    const auto digest = unwrap(provider.digest(hash, as_bytes(text)), "hashing");
    return Bytes(digest.bytes().begin(), digest.bytes().end());
}

std::vector<std::string> split(const std::string& text, char separator) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t end = std::min(text.find(separator, start), text.size());
        if (end > start) {
            parts.push_back(text.substr(start, end - start));
        }
        start = end + 1;
    }
    return parts;
}

std::pair<std::string, std::string> split_pair(const std::string& text, std::string_view what) {
    const auto eq = text.find('=');
    if (eq == std::string::npos || eq == 0) {
        throw UsageError{std::string(what) + " must be NAME=VALUE: " + text};
    }
    return {text.substr(0, eq), text.substr(eq + 1)};
}

std::uint64_t parse_number(std::string_view text, std::string_view what) {
    std::uint64_t value = 0;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() || ec != std::errc{} || end != text.data() + text.size()) {
        throw UsageError{std::string(what) +
                         " must be a non-negative integer: " + std::string(text)};
    }
    return value;
}

crypto::SigAlg parse_algorithm(std::string_view name) {
    for (const crypto::SigAlg alg : crypto::all_sig_algs) {
        std::string lower(crypto::name(alg));
        std::ranges::transform(lower, lower.begin(),
                               [](unsigned char c) { return std::tolower(c); });
        if (lower == name) {
            return alg;
        }
    }
    throw UsageError{"unknown algorithm " + std::string(name) +
                     " (ed25519, esp256, sm2-sm3, ml-dsa-44, ml-dsa-65, ml-dsa-87)"};
}

crypto::HashAlg parse_hash(std::string_view name) {
    if (name == "sha256" || name == "sha-256") {
        return crypto::HashAlg::sha256;
    }
    if (name == "sm3") {
        return crypto::HashAlg::sm3;
    }
    throw UsageError{"hash must be sha256 or sm3"};
}

protocol::StatementType parse_statement_type(std::string_view name) {
    for (std::uint64_t value = 1; value < 32; ++value) {
        const auto type = protocol::statement_type_from(value);
        if (type && protocol::name(*type) == name) {
            return *type;
        }
    }
    throw UsageError{"unknown statement type " + std::string(name)};
}

protocol::ActorKind parse_actor_kind(std::string_view name) {
    if (name == "person") {
        return protocol::ActorKind::person;
    }
    if (name == "agent") {
        return protocol::ActorKind::agent;
    }
    if (name == "device") {
        return protocol::ActorKind::device;
    }
    throw UsageError{"actor kind must be person, agent, or device"};
}

void recover_vault_swap(const std::filesystem::path& directory) {
    // `vault rekey` builds vault.next/ completely (COMPLETE is written last),
    // then renames vault -> vault.old-<time> and vault.next -> vault. After a
    // crash between the two renames, finish the swap; after a crash before
    // COMPLETE, the old vault is untouched and vault.next is discarded.
    const std::filesystem::path vault = directory / "vault";
    const std::filesystem::path next = directory / "vault.next";
    if (!std::filesystem::exists(vault) && std::filesystem::exists(next / "COMPLETE")) {
        std::filesystem::rename(next, vault);
        std::filesystem::remove(vault / "COMPLETE");
    }
    if (std::filesystem::exists(next)) {
        std::filesystem::remove_all(next);
    }
}

node::Client client_for(const std::string& url, std::optional<std::string> token,
                        const std::optional<std::string>& ca_file) {
    node::ClientOptions options;
    options.bearer_token = std::move(token);
    if (ca_file) {
        options.ca_file = *ca_file;
    }
    return node::Client(unwrap(node::Url::parse(url), "reading the URL"), std::move(options));
}

void create_ledger(const std::filesystem::path& directory, const crypto::Signer& root_key,
                   const crypto::PublicKey& log_key, crypto::HashAlg hash,
                   const std::string& organization) {
    const crypto::openssl::Provider provider;
    ledger::SystemClock clock;
    ledger::SystemEntropy entropy;
    auto fs = unwrap(ledger::PosixFileSystem::open_directory(directory), "creating the directory");
    const auto lock = unwrap(ledger::DirectoryLock::acquire(directory), "locking the ledger");

    protocol::Statement genesis;
    genesis.issued_at = clock.now();
    genesis.nonce = entropy.bytes<16>();
    genesis.body = protocol::GenesisBody{hash, organization, root_key.public_key(), log_key};
    const auto signed_genesis =
        unwrap(protocol::sign_statement(root_key, provider, hash, genesis), "signing genesis");
    static_cast<void>(unwrap(ledger::Ledger::create(fs, clock, provider, signed_genesis.encoded),
                             "creating the ledger"));
}

} // namespace cexchain::app
