// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// An executor's config and state directory: files its tools write and
// the runtime, `executor journal`, and `executor secret` read back, which a
// damaged disk or someone with access to the directory could alter: the
// config (parse_config), a journal entry (parse_entry), the discovery cursor
// (parse_cursor), and a sealed secret (parse_sealed_secret, then opened with
// HPKE). No reader may crash; what parses must print back to text that
// parses to the same, and a sealed secret built from fuzz never opens. The
// first byte chooses the reader; the rest is the file.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#include <cexchain/crypto/openssl.hpp>
#include <cexchain/node/executor.hpp>

namespace executor = cexchain::node::executor;
namespace openssl = cexchain::crypto::openssl;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

/// A fixed X25519 key (PKCS #8), so that runs are reproducible.
const openssl::HpkeKey& secrets_key() {
    static const openssl::HpkeKey key = [] {
        std::array<std::uint8_t, 48> der{0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
                                         0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20};
        for (std::size_t i = 16; i < der.size(); ++i) {
            der[i] = static_cast<std::uint8_t>(i * 7 + 1);
        }
        auto loaded = openssl::HpkeKey::from_pkcs8(der);
        require(loaded.has_value());
        return std::move(*loaded);
    }();
    return key;
}

void config(std::string_view text) {
    const auto parsed = executor::parse_config(text);
    if (!parsed) {
        require(!parsed.error().empty());
        return;
    }
    const std::string printed = executor::config_text(*parsed);
    const auto again = executor::parse_config(printed);
    require(again.has_value() && executor::config_text(*again) == printed);
    require(again->connectors.size() == parsed->connectors.size());
}

void entry(std::string_view text) {
    const auto parsed = executor::parse_entry(text);
    if (!parsed) {
        return;
    }
    const std::string printed = executor::entry_text(*parsed);
    const auto again = executor::parse_entry(printed);
    require(again.has_value() && executor::entry_text(*again) == printed);
    require(again->request == parsed->request && again->stage == parsed->stage);
}

void cursor(std::string_view text) {
    const std::uint64_t after = executor::parse_cursor(text, "http://127.0.0.1:8080");
    // A cursor for another server is never taken.
    if (after != 0) {
        require(executor::parse_cursor(text, "http://127.0.0.1:8081") == 0);
    }
}

void sealed(std::string_view text) {
    const cexchain::ByteView file(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
    const auto parsed = executor::parse_sealed_secret(file);
    const auto opened = executor::open_sealed_secret("hook-key", file, secrets_key());
    if (!parsed) {
        require(!opened.has_value());
        return;
    }
    require(parsed->encapsulated_key.size() == openssl::hpke_public_key_size);
    const cexchain::Bytes printed = executor::encode_sealed_secret(*parsed);
    const auto again = executor::parse_sealed_secret(printed);
    require(again.has_value() && again->encapsulated_key == parsed->encapsulated_key &&
            again->ciphertext == parsed->ciphertext);
    // AES-256-GCM: no ciphertext from fuzz carries a valid tag.
    require(!opened.has_value());
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    const std::string_view text(reinterpret_cast<const char*>(data + 1), size - 1);
    switch (data[0] % 4) {
    case 0:
        config(text);
        break;
    case 1:
        entry(text);
        break;
    case 2:
        cursor(text);
        break;
    default:
        sealed(text);
        break;
    }
    return 0;
}
