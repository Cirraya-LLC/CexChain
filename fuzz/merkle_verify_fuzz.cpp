// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Feeds arbitrary sizes, roots, and proofs to the Merkle proof verifiers. They
// must reject or accept without crashing, hanging, or invoking undefined
// behavior.

#include <cstddef>
#include <cstdint>
#include <vector>

#include <cexchain/core/merkle.hpp>
#include <cexchain/crypto/openssl.hpp>

namespace {

class Reader {
public:
    Reader(const std::uint8_t* data, std::size_t size) : data_(data), size_(size) {}

    std::uint64_t u64() {
        std::uint64_t value = 0;
        for (int i = 0; i < 8 && pos_ < size_; ++i) {
            value = (value << 8) | data_[pos_++];
        }
        return value;
    }

    bool digest(cexchain::crypto::Digest& out) {
        if (size_ - pos_ < 32) {
            return false;
        }
        out = *cexchain::crypto::Digest::from_bytes(cexchain::ByteView(data_ + pos_, 32));
        pos_ += 32;
        return true;
    }

private:
    const std::uint8_t* data_;
    std::size_t size_;
    std::size_t pos_ = 0;
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const cexchain::crypto::openssl::Provider provider;
    using cexchain::crypto::HashAlg;

    Reader reader(data, size);
    const std::uint64_t index = reader.u64();
    const std::uint64_t old_size = reader.u64();
    const std::uint64_t new_size = reader.u64();
    cexchain::crypto::Digest leaf;
    cexchain::crypto::Digest old_root;
    cexchain::crypto::Digest new_root;
    if (!reader.digest(leaf) || !reader.digest(old_root) || !reader.digest(new_root)) {
        return 0;
    }
    std::vector<cexchain::crypto::Digest> proof;
    cexchain::crypto::Digest element;
    while (proof.size() <= cexchain::merkle::max_consistency_proof_length &&
           reader.digest(element)) {
        proof.push_back(element);
    }

    static_cast<void>(cexchain::merkle::verify_inclusion(provider, HashAlg::sha256, leaf, index,
                                                         new_size, proof, new_root));
    static_cast<void>(cexchain::merkle::verify_consistency(provider, HashAlg::sha256, old_size,
                                                           new_size, old_root, new_root, proof));
    return 0;
}
