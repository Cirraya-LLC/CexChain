// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

// An open-network witness for tests (spec section 10.2): a cosigner key of
// either C2SP kind, its verifier key, and its cosignatures of checkpoint
// notes, made here as tlog-cosignature says.

#include <cstdint>
#include <string>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/protocol/network.hpp>
#include <cexchain/crypto/openssl.hpp>

namespace cexchain::test {

class NetworkWitness {
public:
    /// Ed25519 (type 0x04) unless `ml_dsa_44` (type 0x06).
    explicit NetworkWitness(std::string name, bool ml_dsa_44 = false)
        : type_(ml_dsa_44 ? protocol::network::cosigner_ml_dsa_44
                          : protocol::network::cosigner_ed25519),
          key_(must(crypto::openssl::KeyPair::generate(ml_dsa_44 ? crypto::SigAlg::ml_dsa_44
                                                                 : crypto::SigAlg::ed25519))),
          vkey_(must(protocol::network::make_verifier_key(provider_, std::move(name), type_,
                                                          key_.public_key()))) {}

    [[nodiscard]] const protocol::network::VerifierKey& vkey() const { return vkey_; }

    /// Its cosignature, dated `time` (POSIX seconds), of the note of a tree
    /// of `size` entries with `root` under `origin`.
    [[nodiscard]] protocol::network::NoteSignature cosign(std::string_view origin,
                                                          std::uint64_t size,
                                                          const crypto::Digest& root,
                                                          std::uint64_t time) const {
        Bytes message;
        if (type_ == protocol::network::cosigner_ed25519) {
            const std::string text = "cosignature/v1\ntime " + std::to_string(time) + "\n" +
                                     protocol::network::checkpoint_note(origin, size, root);
            message.assign(text.begin(), text.end());
        } else {
            const std::string_view label("subtree/v1\n\0", 12);
            message.assign(label.begin(), label.end());
            message.push_back(static_cast<std::uint8_t>(vkey_.name.size()));
            message.insert(message.end(), vkey_.name.begin(), vkey_.name.end());
            put_be64(message, time);
            message.push_back(static_cast<std::uint8_t>(origin.size()));
            message.insert(message.end(), origin.begin(), origin.end());
            put_be64(message, 0);
            put_be64(message, size);
            message.insert(message.end(), root.bytes().begin(), root.bytes().end());
        }
        Bytes bytes(vkey_.id.begin(), vkey_.id.end());
        put_be64(bytes, time);
        const Bytes signature = must(key_.sign(message));
        bytes.insert(bytes.end(), signature.begin(), signature.end());
        return {vkey_.name, bytes};
    }

private:
    template <class T>
    static T must(Result<T> result) {
        REQUIRE(result);
        return std::move(*result);
    }

    static void put_be64(Bytes& out, std::uint64_t value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.push_back(static_cast<std::uint8_t>(value >> shift));
        }
    }

    crypto::openssl::Provider provider_;
    std::uint8_t type_;
    crypto::openssl::KeyPair key_;
    protocol::network::VerifierKey vkey_;
};

} // namespace cexchain::test
