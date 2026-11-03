// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <chrono>
#include <random>

#include <cexchain/core/protocol/id_map.hpp>

namespace cexchain::protocol {

IdKey key_of(const Id& id) noexcept {
    IdKey key{};
    const ByteView bytes = id.bytes();
    std::copy_n(bytes.begin(), std::min(bytes.size(), key.size()), key.begin());
    return key;
}

std::uint64_t table_seed() noexcept {
    // Only where elements sit in tables depends on it, never a result: it
    // keeps statements whose ids or nonces were chosen to collide from
    // degrading lookups.
    static const std::uint64_t seed = [] {
        std::uint64_t value = 0;
        try {
            std::random_device device;
            value = (std::uint64_t{device()} << 32) ^ device();
        } catch (...) {
            // No random device: fall back to what varies between runs.
        }
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        return mix64(value ^ static_cast<std::uint64_t>(now) ^
                     reinterpret_cast<std::uintptr_t>(&value));
    }();
    return seed;
}

std::uint64_t NonceSet::hash(std::uint32_t actor, const Nonce& nonce) noexcept {
    // Nonces are chosen by the signer: every bit goes through the keyed mix.
    static const std::uint64_t seed = table_seed();
    std::uint64_t h = mix64(load64(nonce.data()) ^ seed);
    h = mix64(h ^ load64(nonce.data() + 8));
    return mix64(h ^ actor);
}

bool NonceSet::contains(std::uint32_t actor, const Nonce& nonce) const noexcept {
    if (slots_.empty()) {
        return false;
    }
    for (std::size_t i = static_cast<std::size_t>(hash(actor, nonce)) & mask_;;
         i = (i + 1) & mask_) {
        const Slot& slot = slots_[i];
        if (slot.actor == empty) {
            return false;
        }
        if (slot.actor == actor && slot.nonce == nonce) {
            return true;
        }
    }
}

void NonceSet::insert(std::uint32_t actor, const Nonce& nonce) {
    if (contains(actor, nonce)) {
        return;
    }
    if ((size_ + 1) * 4 > slots_.size() * 3) {
        grow();
    }
    std::size_t i = static_cast<std::size_t>(hash(actor, nonce)) & mask_;
    while (slots_[i].actor != empty) {
        i = (i + 1) & mask_;
    }
    slots_[i] = Slot{actor, nonce};
    ++size_;
}

void NonceSet::grow() {
    std::vector<Slot> old = std::move(slots_);
    slots_.assign(std::max<std::size_t>(16, old.size() * 2), Slot{});
    mask_ = slots_.size() - 1;
    for (const Slot& slot : old) {
        if (slot.actor != empty) {
            std::size_t i = static_cast<std::size_t>(hash(slot.actor, slot.nonce)) & mask_;
            while (slots_[i].actor != empty) {
                i = (i + 1) & mask_;
            }
            slots_[i] = slot;
        }
    }
}

} // namespace cexchain::protocol
