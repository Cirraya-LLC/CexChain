// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>

#include <cexchain/app/support.hpp>
#include <cexchain/console/keystore.hpp>
#include <cexchain/core/bytes.hpp>

namespace cexchain::console {

namespace {

constexpr std::string_view node_public_file = "node.pub";
constexpr std::string_view sealed_info = "CexChain console key v1";
constexpr std::string_view base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
constexpr std::size_t recovery_letters = 26;

Bytes decoded(const nlohmann::json& j, std::string_view key) {
    const auto it = j.find(key);
    auto bytes = it != j.end() && it->is_string() ? from_base64url(it->get<std::string>())
                                                  : Result<Bytes>(std::unexpected(Error{}));
    if (!bytes) {
        throw std::runtime_error("a sealed key of the console's is damaged");
    }
    return std::move(*bytes);
}

std::string text_of(const Bytes& bytes) {
    return {bytes.begin(), bytes.end()};
}

} // namespace

std::string_view name_of(SlotKind kind) noexcept {
    switch (kind) {
    case SlotKind::recovery:
        return "recovery";
    case SlotKind::prf:
        return "passkey";
    case SlotKind::passphrase:
        break;
    }
    return "passphrase";
}

std::string make_recovery_code(ledger::Entropy& entropy) {
    const auto bits = entropy.bytes<16>();
    std::string letters;
    std::uint32_t buffer = 0;
    int held = 0;
    for (const std::uint8_t byte : bits) {
        buffer = (buffer << 8U) | byte;
        held += 8;
        while (held >= 5) {
            held -= 5;
            letters += base32[(buffer >> static_cast<unsigned>(held)) & 31U];
        }
    }
    letters += base32[(buffer << static_cast<unsigned>(5 - held)) & 31U];
    std::string code;
    for (std::size_t i = 0; i < letters.size(); ++i) {
        if (i > 0 && i % 4 == 0) {
            code += '-';
        }
        code += letters[i];
    }
    return code;
}

bool is_prf_output(std::string_view text) {
    const auto bytes = from_base64url(text);
    return bytes && bytes->size() == 32;
}

std::optional<std::string> canonical_recovery_code(std::string_view typed) {
    std::string code;
    for (const char c : typed) {
        if (c == '-' || c == ' ') {
            continue;
        }
        const char upper = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (base32.find(upper) == std::string_view::npos) {
            return std::nullopt;
        }
        code += upper;
    }
    if (code.size() != recovery_letters) {
        return std::nullopt;
    }
    return code;
}

bool valid_key_name(std::string_view name) noexcept {
    return !name.empty() && name.size() <= 64 && std::ranges::all_of(name, [](unsigned char c) {
        return std::islower(c) != 0 || std::isdigit(c) != 0 || c == '.' || c == '_' || c == '-';
    });
}

KeyStore::KeyStore(std::filesystem::path directory) : directory_(std::move(directory)) {}

std::filesystem::path KeyStore::slot_file(const Slot& slot) const {
    if (slot.kind == SlotKind::prf) {
        if (slot.id.empty() || slot.id.size() > 128 ||
            !std::ranges::all_of(slot.id, [](unsigned char c) {
                return std::isalnum(c) != 0 || c == '-' || c == '_';
            })) {
            throw std::invalid_argument("a passkey slot needs the passkey's id (base64url)");
        }
        return directory_ / "slots" / ("passkey-" + slot.id + ".p8");
    }
    return directory_ / "slots" / (std::string(name_of(slot.kind)) + ".p8");
}

bool KeyStore::initialized() const {
    return std::filesystem::exists(directory_ / node_public_file);
}

bool KeyStore::unlocked() const {
    const std::lock_guard lock(mutex_);
    return node_.has_value();
}

void KeyStore::lock() {
    const std::lock_guard lock(mutex_);
    node_.reset();
}

std::string KeyStore::initialize(ledger::Entropy& entropy) {
    const std::lock_guard lock(mutex_);
    if (std::filesystem::exists(directory_ / node_public_file)) {
        throw std::runtime_error("the console's keys are set up already");
    }
    auto node = crypto::openssl::HpkeKey::generate();
    if (!node) {
        throw std::runtime_error("making the console's node key failed");
    }
    const std::string code = make_recovery_code(entropy);
    const auto wrapped = node->to_encrypted_pkcs8(*canonical_recovery_code(code));
    if (!wrapped) {
        throw std::runtime_error("sealing the console's node key failed");
    }
    std::filesystem::create_directories(directory_ / "slots");
    app::write_file(slot_file({SlotKind::recovery, {}}), *wrapped, true);
    const std::string public_key = to_base64url(node->public_key()) + "\n";
    app::write_file(directory_ / node_public_file, as_bytes(public_key), true);
    node_.emplace(std::move(*node));
    return code;
}

bool KeyStore::unlock(const Slot& slot, std::string_view secret) {
    const std::filesystem::path file = slot_file(slot);
    if (!std::filesystem::exists(file)) {
        return false;
    }
    std::string passphrase(secret);
    if (slot.kind == SlotKind::recovery) {
        const auto code = canonical_recovery_code(secret);
        if (!code) {
            return false;
        }
        passphrase = *code;
    }
    auto node = crypto::openssl::HpkeKey::from_encrypted_pkcs8(app::read_file(file), passphrase);
    if (!node) {
        return false;
    }
    const std::lock_guard lock(mutex_);
    node_.emplace(std::move(*node));
    return true;
}

void KeyStore::add_slot(const Slot& slot, std::string_view secret) {
    if (slot.kind == SlotKind::recovery) {
        throw std::invalid_argument("the recovery slot is made once, at setup");
    }
    if (secret.size() < 8) {
        throw std::invalid_argument("a slot's secret is at least 8 characters");
    }
    const std::lock_guard lock(mutex_);
    if (!node_) {
        throw std::runtime_error("the console is locked");
    }
    const auto wrapped = node_->to_encrypted_pkcs8(secret);
    if (!wrapped) {
        throw std::runtime_error("sealing the console's node key failed");
    }
    std::filesystem::create_directories(directory_ / "slots");
    app::write_file(slot_file(slot), *wrapped, true);
}

bool KeyStore::remove_slot(const Slot& slot) {
    if (slot.kind == SlotKind::recovery) {
        throw std::invalid_argument("the recovery slot stays: it is how a lost console comes back");
    }
    return std::filesystem::remove(slot_file(slot));
}

std::vector<Slot> KeyStore::slots() const {
    std::vector<Slot> found;
    const std::filesystem::path dir = directory_ / "slots";
    if (!std::filesystem::is_directory(dir)) {
        return found;
    }
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        const std::string name = entry.path().filename().string();
        if (name == "recovery.p8") {
            found.push_back({SlotKind::recovery, {}});
        } else if (name == "passphrase.p8") {
            found.push_back({SlotKind::passphrase, {}});
        } else if (name.starts_with("passkey-") && name.ends_with(".p8")) {
            found.push_back({SlotKind::prf, name.substr(8, name.size() - 11)});
        }
    }
    std::ranges::sort(found, {}, [](const Slot& s) { return std::pair(s.kind, s.id); });
    return found;
}

void KeyStore::seal(std::string_view name, const crypto::openssl::KeyPair& key) const {
    if (!valid_key_name(name)) {
        throw std::invalid_argument("a key's name is 1 to 64 lower-case letters, digits, '.', "
                                    "'_', or '-'");
    }
    const auto public_text = app::read_file(directory_ / node_public_file);
    std::string encoded = text_of(public_text);
    encoded = encoded.substr(0, encoded.find('\n'));
    const auto node_public = from_base64url(encoded);
    const auto pkcs8 = key.to_pkcs8();
    if (!node_public || !pkcs8) {
        throw std::runtime_error("the console's node key or this key cannot be read");
    }
    const auto sealed = crypto::openssl::hpke_seal(*node_public, as_bytes(sealed_info),
                                                   as_bytes(name), pkcs8->view());
    if (!sealed) {
        throw std::runtime_error("sealing the key failed");
    }
    const nlohmann::json file{{"name", name},
                              {"algorithm", crypto::cose_id(key.algorithm())},
                              {"public_key", to_base64url(key.public_key().bytes)},
                              {"enc", to_base64url(sealed->encapsulated_key)},
                              {"ciphertext", to_base64url(sealed->ciphertext)}};
    std::filesystem::create_directories(directory_ / "keys");
    const std::string text = file.dump(2) + "\n";
    app::write_file(directory_ / "keys" / (std::string(name) + ".sealed"), as_bytes(text), true);
}

std::vector<SealedKeyInfo> KeyStore::keys() const {
    std::vector<SealedKeyInfo> found;
    const std::filesystem::path dir = directory_ / "keys";
    if (!std::filesystem::is_directory(dir)) {
        return found;
    }
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.path().extension() != ".sealed") {
            continue;
        }
        const Bytes bytes = app::read_file(entry.path());
        const auto j = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false);
        if (!j.is_object() || !j.contains("algorithm") || !j["algorithm"].is_number_integer()) {
            throw std::runtime_error("a sealed key of the console's is damaged");
        }
        const auto alg = crypto::sig_alg_from_cose(j["algorithm"].get<std::int64_t>());
        if (!alg) {
            throw std::runtime_error("a sealed key of the console's is damaged");
        }
        found.push_back({entry.path().stem().string(), {*alg, decoded(j, "public_key")}});
    }
    std::ranges::sort(found, {}, &SealedKeyInfo::name);
    return found;
}

bool KeyStore::remove_key(std::string_view name) const {
    if (!valid_key_name(name)) {
        return false;
    }
    return std::filesystem::remove(directory_ / "keys" / (std::string(name) + ".sealed"));
}

crypto::openssl::KeyPair KeyStore::open(std::string_view name) const {
    if (!valid_key_name(name)) {
        throw std::invalid_argument("no such key");
    }
    const std::filesystem::path file = directory_ / "keys" / (std::string(name) + ".sealed");
    if (!std::filesystem::exists(file)) {
        throw std::invalid_argument("the console holds no key named " + std::string(name));
    }
    const Bytes bytes = app::read_file(file);
    const auto j = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false);
    if (!j.is_object()) {
        throw std::runtime_error("a sealed key of the console's is damaged");
    }
    const crypto::openssl::HpkeSealed sealed{decoded(j, "enc"), decoded(j, "ciphertext")};
    const std::lock_guard lock(mutex_);
    if (!node_) {
        throw std::runtime_error("the console is locked");
    }
    // The name is authenticated with the sealed key: a file renamed to
    // another key's name does not open.
    const auto pkcs8 = node_->open(sealed, as_bytes(sealed_info), as_bytes(name));
    if (!pkcs8) {
        throw std::runtime_error("the key " + std::string(name) + " does not open");
    }
    auto key = crypto::openssl::KeyPair::from_pkcs8(pkcs8->view());
    if (!key) {
        throw std::runtime_error("the key " + std::string(name) + " is damaged");
    }
    return std::move(*key);
}

} // namespace cexchain::console
