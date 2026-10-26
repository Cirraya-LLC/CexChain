// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/environment.hpp>

/// The console's keys, sealed at rest. The node key, an X25519 HPKE key, is
/// stored only wrapped, once per slot: an encrypted PKCS#8 (scrypt and AES)
/// under the slot's secret, which is the recovery code, a passphrase, or a
/// passkey's PRF output. Every key the console holds is its PKCS#8 sealed
/// with HPKE to the node key's public key, so sealing needs only the public
/// key, and opening needs the node key, which only an unlocked console holds,
/// in memory. Nothing here is new cryptography: it is OpenSSL's, through
/// crypto/openssl.
namespace cexchain::console {

enum class SlotKind : std::uint8_t { recovery, passphrase, prf };

[[nodiscard]] std::string_view name_of(SlotKind kind) noexcept;

struct Slot {
    SlotKind kind = SlotKind::passphrase;
    /// For a PRF slot, the passkey's credential id (base64url); else empty.
    std::string id;
};

/// A key the console holds, as its sealed file names it.
struct SealedKeyInfo {
    std::string name;
    crypto::PublicKey public_key;
};

/// A recovery code: 128 random bits as 26 base32 letters and digits, in
/// groups of four or two, joined by '-'.
[[nodiscard]] std::string make_recovery_code(ledger::Entropy& entropy);
/// A typed recovery code in its canonical form (upper case, no separators),
/// if it has the form of one.
[[nodiscard]] std::optional<std::string> canonical_recovery_code(std::string_view typed);

/// Whether `text` is a passkey's PRF output as the page sends it: 32 bytes,
/// base64url.
[[nodiscard]] bool is_prf_output(std::string_view text);

/// A key name: 1 to 64 lower-case letters, digits, '.', '_', or '-'.
[[nodiscard]] bool valid_key_name(std::string_view name) noexcept;

class KeyStore {
public:
    /// `directory` is the console's folder in the ledger directory.
    explicit KeyStore(std::filesystem::path directory);

    /// Whether the node key exists (setup made it).
    [[nodiscard]] bool initialized() const;
    /// Makes the node key and its recovery slot, and returns the recovery
    /// code, which only the caller ever sees. Leaves the store unlocked.
    /// Throws if the node key exists.
    [[nodiscard]] std::string initialize(ledger::Entropy& entropy);

    [[nodiscard]] bool unlocked() const;
    /// Unlocks with a slot's secret; false if the slot does not exist or the
    /// secret does not open it.
    bool unlock(const Slot& slot, std::string_view secret);
    /// Forgets the node key.
    void lock();

    /// Adds (or replaces) a slot. Needs the store unlocked.
    void add_slot(const Slot& slot, std::string_view secret);
    bool remove_slot(const Slot& slot);
    [[nodiscard]] std::vector<Slot> slots() const;

    /// Seals `key` under `name`, replacing any key of that name. Needs only
    /// the node key's public key.
    void seal(std::string_view name, const crypto::openssl::KeyPair& key) const;
    [[nodiscard]] std::vector<SealedKeyInfo> keys() const;
    bool remove_key(std::string_view name) const;
    /// Opens a sealed key. Needs the store unlocked.
    [[nodiscard]] crypto::openssl::KeyPair open(std::string_view name) const;

    /// The ledger's vault key (an X25519 HPKE key, which opens records'
    /// private data and kept files), sealed the same way as `vault.sealed`.
    void seal_vault_key(const crypto::openssl::HpkeKey& key) const;
    /// Its public key, if the console holds it.
    [[nodiscard]] std::optional<Bytes> vault_public_key() const;
    /// Opens it. Needs the store unlocked.
    [[nodiscard]] crypto::openssl::HpkeKey open_vault_key() const;
    bool remove_vault_key() const;

private:
    [[nodiscard]] std::filesystem::path slot_file(const Slot& slot) const;

    std::filesystem::path directory_;
    mutable std::mutex mutex_;
    std::optional<crypto::openssl::HpkeKey> node_;
};

} // namespace cexchain::console
