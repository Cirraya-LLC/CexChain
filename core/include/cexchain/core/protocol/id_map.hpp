// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <iterator>
#include <memory>
#include <optional>
#include <stdexcept>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include <cexchain/core/protocol/common.hpp>

/// Containers for ledger state that holds millions of objects (D-048): no
/// allocation per element, and no ordering work on insert. Iteration is in
/// insertion order, which for ledger state is log order, so it is as
/// deterministic as the log. The hash tables only find elements; their
/// layout (which a per-process random seed perturbs, against inputs crafted
/// to collide) never shows in any result.
namespace cexchain::protocol {

/// Identifiers as map keys.
using IdKey = std::array<std::uint8_t, id_size>;
[[nodiscard]] IdKey key_of(const Id& id) noexcept;

/// An id as state objects keep it: its 32 bytes, without the room a Digest
/// has for longer hashes (32 bytes instead of 65 plus padding). Converts to
/// and from Id implicitly, so it reads like one.
class CompactId {
public:
    CompactId() noexcept = default;
    // NOLINTNEXTLINE(google-explicit-constructor): an Id in all but storage.
    CompactId(const Id& id) noexcept : key_(key_of(id)) {}
    explicit CompactId(const IdKey& key) noexcept : key_(key) {}
    // NOLINTNEXTLINE(google-explicit-constructor)
    operator Id() const noexcept { return id(); }

    [[nodiscard]] Id id() const noexcept { return *crypto::Digest::from_bytes(key_); }
    [[nodiscard]] ByteView bytes() const noexcept { return key_; }
    [[nodiscard]] const IdKey& key() const noexcept { return key_; }

    friend bool operator==(const CompactId&, const CompactId&) = default;
    friend bool operator==(const CompactId& a, const Id& b) noexcept {
        return std::ranges::equal(a.key_, b.bytes());
    }

private:
    IdKey key_{};
};

/// The per-process seed of every table's hash.
[[nodiscard]] std::uint64_t table_seed() noexcept;

/// A bijective 64-bit mix (the MurmurHash3 finalizer).
[[nodiscard]] constexpr std::uint64_t mix64(std::uint64_t x) noexcept {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

[[nodiscard]] inline std::uint64_t load64(const std::uint8_t* bytes) noexcept {
    std::uint64_t word = 0;
    std::memcpy(&word, bytes, sizeof word);
    return word;
}

/// An append-only sequence whose elements never move: chunks of 16, 32, ...
/// up to 4096 elements, each allocated once at its full size. Pointers and
/// references stay valid as it grows, and growing never copies.
template <class T>
class StableVector {
public:
    StableVector() = default;
    // The moved-from vector is left empty, size included.
    StableVector(StableVector&& other) noexcept
        : chunks_(std::move(other.chunks_)), size_(std::exchange(other.size_, 0)) {
        other.chunks_.clear();
    }
    StableVector& operator=(StableVector&& other) noexcept {
        chunks_ = std::move(other.chunks_);
        size_ = std::exchange(other.size_, 0);
        other.chunks_.clear();
        return *this;
    }
    StableVector(const StableVector& other) {
        for (const T& value : other) {
            push_back(value);
        }
    }
    StableVector& operator=(const StableVector& other) {
        if (this != &other) {
            StableVector copy(other);
            *this = std::move(copy);
        }
        return *this;
    }
    ~StableVector() = default;

    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

    T& push_back(T value) {
        const auto [chunk, offset] = locate(size_);
        if (chunk == chunks_.size()) {
            chunks_.emplace_back();
            chunks_.back().reserve(capacity_of(chunk));
        }
        T& stored = chunks_[chunk].emplace_back(std::move(value));
        ++size_;
        return stored;
    }

    [[nodiscard]] T& operator[](std::size_t index) noexcept {
        const auto [chunk, offset] = locate(index);
        return chunks_[chunk][offset];
    }
    [[nodiscard]] const T& operator[](std::size_t index) const noexcept {
        const auto [chunk, offset] = locate(index);
        return chunks_[chunk][offset];
    }

    template <bool Const>
    class Iterator {
    public:
        using Owner = std::conditional_t<Const, const StableVector, StableVector>;
        using iterator_category = std::forward_iterator_tag;
        using value_type = T;
        using difference_type = std::ptrdiff_t;
        using pointer = std::conditional_t<Const, const T*, T*>;
        using reference = std::conditional_t<Const, const T&, T&>;

        Iterator() = default;
        Iterator(Owner* owner, std::size_t index) noexcept : owner_(owner), index_(index) {}
        reference operator*() const noexcept { return (*owner_)[index_]; }
        pointer operator->() const noexcept { return &(*owner_)[index_]; }
        Iterator& operator++() noexcept {
            ++index_;
            return *this;
        }
        Iterator operator++(int) noexcept {
            Iterator before = *this;
            ++index_;
            return before;
        }
        friend bool operator==(const Iterator& a, const Iterator& b) noexcept {
            return a.index_ == b.index_;
        }

    private:
        Owner* owner_ = nullptr;
        std::size_t index_ = 0;
    };

    [[nodiscard]] Iterator<false> begin() noexcept { return {this, 0}; }
    [[nodiscard]] Iterator<false> end() noexcept { return {this, size_}; }
    [[nodiscard]] Iterator<true> begin() const noexcept { return {this, 0}; }
    [[nodiscard]] Iterator<true> end() const noexcept { return {this, size_}; }

private:
    static constexpr std::size_t first_shift = 4;  // the first chunk holds 16
    static constexpr std::size_t growing = 9;      // chunks 16 ... 4096
    static constexpr std::size_t max_chunk = 4096; // then all hold 4096
    static constexpr std::size_t growing_total =
        (std::size_t{1} << first_shift) * ((std::size_t{1} << growing) - 1);

    static constexpr std::size_t capacity_of(std::size_t chunk) noexcept {
        return chunk < growing ? std::size_t{1} << (first_shift + chunk) : max_chunk;
    }
    static constexpr std::pair<std::size_t, std::size_t> locate(std::size_t index) noexcept {
        if (index < growing_total) {
            const std::size_t chunk =
                static_cast<std::size_t>(std::bit_width((index >> first_shift) + 1)) - 1;
            return {chunk, index - ((std::size_t{1} << (first_shift + chunk)) -
                                    (std::size_t{1} << first_shift))};
        }
        const std::size_t past = index - growing_total;
        return {growing + past / max_chunk, past % max_chunk};
    }

    std::vector<std::vector<T>> chunks_;
    std::size_t size_ = 0;
};

/// Values that carry their own CompactId `id`: a map need not store the key
/// again.
template <class T>
concept CarriesId = requires(const T& t) {
    { t.id } -> std::convertible_to<const CompactId&>;
};

/// An element of an IdMap whose values carry their ids. Binds as
/// `const auto& [key, value]`, like the keyed kind below.
template <class T>
struct IdEntry {
    T value;

    template <std::size_t I>
    [[nodiscard]] const auto& get() const noexcept {
        if constexpr (I == 0) {
            return value.id.key();
        } else {
            return value;
        }
    }
};

template <class T>
struct KeyedEntry {
    IdKey key;
    T value;
};

/// A map from ids to values: the entries in a StableVector, in insertion
/// order, and an open-addressing index of 8-byte slots (32 bits of hash, to
/// skip most mismatches without touching the entry, and the entry's
/// position). Entries are never removed.
template <class T>
class IdMap {
public:
    using Entry = std::conditional_t<CarriesId<T>, IdEntry<T>, KeyedEntry<T>>;

    [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
    [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }
    [[nodiscard]] auto begin() const noexcept { return entries_.begin(); }
    [[nodiscard]] auto end() const noexcept { return entries_.end(); }

    /// The position of `key` in insertion order.
    [[nodiscard]] std::optional<std::uint32_t> position(const IdKey& key) const noexcept {
        if (index_.empty()) {
            return std::nullopt;
        }
        const auto tag = tag_of(key);
        for (std::size_t i = tag & mask_;; i = (i + 1) & mask_) {
            const std::uint64_t slot = index_[i];
            if (slot == 0) {
                return std::nullopt;
            }
            if (static_cast<std::uint32_t>(slot >> 32) == tag) {
                const auto at = static_cast<std::uint32_t>(slot) - 1;
                if (key_of_entry(entries_[at]) == key) {
                    return at;
                }
            }
        }
    }
    [[nodiscard]] const Entry& at_position(std::uint32_t position) const noexcept {
        return entries_[position];
    }

    [[nodiscard]] const T* find(const IdKey& key) const noexcept {
        const auto at = position(key);
        return at ? &entries_[*at].value : nullptr;
    }
    [[nodiscard]] T* find(const IdKey& key) noexcept {
        const auto at = position(key);
        return at ? &entries_[*at].value : nullptr;
    }
    [[nodiscard]] bool contains(const IdKey& key) const noexcept {
        return position(key).has_value();
    }
    /// The value of `key`, which must be present.
    [[nodiscard]] T& at(const IdKey& key) {
        T* value = find(key);
        if (value == nullptr) {
            throw std::out_of_range("no such id");
        }
        return *value;
    }

    /// Inserts `value` under `key`, or replaces the value already there.
    /// A value that carries its id must carry this one.
    T& insert_or_assign(const IdKey& key, T value) {
        if (T* existing = find(key)) {
            *existing = std::move(value);
            return *existing;
        }
        if ((entries_.size() + 1) * 4 > index_.size() * 3) {
            grow();
        }
        const auto position = static_cast<std::uint32_t>(entries_.size());
        T* stored = nullptr;
        if constexpr (CarriesId<T>) {
            stored = &entries_.push_back(Entry{std::move(value)}).value;
        } else {
            stored = &entries_.push_back(Entry{key, std::move(value)}).value;
        }
        place(tag_of(key), position);
        return *stored;
    }

private:
    [[nodiscard]] static const IdKey& key_of_entry(const Entry& entry) noexcept {
        if constexpr (CarriesId<T>) {
            return entry.value.id.key();
        } else {
            return entry.key;
        }
    }

    /// 32 bits of a keyed hash over the whole key: the slot's tag and its
    /// home bucket, so growing rehashes from the index alone, without
    /// touching (or missing the cache on) any entry. Tables stay far below
    /// 2^32 slots.
    [[nodiscard]] static std::uint32_t tag_of(const IdKey& key) noexcept {
        static const std::uint64_t seed = table_seed();
        std::uint64_t h = mix64(load64(key.data()) ^ seed);
        h = mix64(h ^ load64(key.data() + 8));
        h = mix64(h ^ load64(key.data() + 16));
        return static_cast<std::uint32_t>(mix64(h ^ load64(key.data() + 24)) >> 32);
    }

    void place(std::uint32_t tag, std::uint32_t position) noexcept {
        std::size_t i = tag & mask_;
        while (index_[i] != 0) {
            i = (i + 1) & mask_;
        }
        index_[i] = (std::uint64_t{tag} << 32) | (std::uint64_t{position} + 1);
    }

    void grow() {
        std::vector<std::uint64_t> old(std::max<std::size_t>(16, index_.size() * 2), 0);
        old.swap(index_);
        mask_ = index_.size() - 1;
        for (const std::uint64_t slot : old) {
            if (slot != 0) {
                place(static_cast<std::uint32_t>(slot >> 32), static_cast<std::uint32_t>(slot) - 1);
            }
        }
    }

    StableVector<Entry> entries_;
    std::vector<std::uint64_t> index_;
    std::size_t mask_ = 0;
};

/// Log indices of one object, ascending: inline while there is one (most
/// records have one), on the heap once there are more. 24 bytes and no
/// allocation, where a vector takes 24 plus one.
class IndexList {
public:
    IndexList() noexcept = default;
    IndexList(std::initializer_list<std::uint64_t> indices) {
        for (const std::uint64_t index : indices) {
            push_back(index);
        }
    }
    IndexList(const IndexList& other) : IndexList() {
        for (const std::uint64_t index : other) {
            push_back(index);
        }
    }
    IndexList& operator=(const IndexList& other) {
        if (this != &other) {
            IndexList copy(other);
            *this = std::move(copy);
        }
        return *this;
    }
    IndexList(IndexList&& other) noexcept
        : first_(other.first_), heap_(std::move(other.heap_)), size_(other.size_),
          capacity_(other.capacity_) {
        other.size_ = 0;
        other.capacity_ = 1;
    }
    IndexList& operator=(IndexList&& other) noexcept {
        first_ = other.first_;
        heap_ = std::move(other.heap_);
        size_ = other.size_;
        capacity_ = other.capacity_;
        other.size_ = 0;
        other.capacity_ = 1;
        return *this;
    }
    ~IndexList() = default;

    void push_back(std::uint64_t index) {
        // Invariant: without a heap buffer the list is `first_` (size 0 or
        // 1); with one, every element is in it.
        if (!heap_) {
            if (size_ == 0) {
                first_ = index;
                size_ = 1;
                return;
            }
            auto heap = std::make_unique_for_overwrite<std::uint64_t[]>(4);
            heap[0] = first_;
            heap_ = std::move(heap);
            capacity_ = 4;
        } else if (size_ == capacity_) {
            const std::uint32_t grown = capacity_ * 2;
            auto bigger = std::make_unique_for_overwrite<std::uint64_t[]>(grown);
            std::copy_n(heap_.get(), size_, bigger.get());
            heap_ = std::move(bigger);
            capacity_ = grown;
        }
        heap_[size_++] = index;
    }

    [[nodiscard]] const std::uint64_t* data() const noexcept {
        return heap_ ? heap_.get() : &first_;
    }
    [[nodiscard]] const std::uint64_t* begin() const noexcept { return data(); }
    [[nodiscard]] const std::uint64_t* end() const noexcept { return data() + size_; }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] std::uint64_t front() const noexcept { return data()[0]; }
    [[nodiscard]] std::uint64_t back() const noexcept { return data()[size_ - 1]; }
    [[nodiscard]] std::uint64_t operator[](std::size_t i) const noexcept { return data()[i]; }
    [[nodiscard]] std::vector<std::uint64_t> to_vector() const { return {begin(), end()}; }

    friend bool operator==(const IndexList& a, const IndexList& b) noexcept {
        return std::ranges::equal(a, b);
    }

private:
    std::uint64_t first_ = 0;
    std::unique_ptr<std::uint64_t[]> heap_;
    std::uint32_t size_ = 0;
    std::uint32_t capacity_ = 1;
};

/// The (signer, nonce) pairs already used: a flat open-addressing set,
/// 20 bytes a pair, with the signer as its position among the actors.
class NonceSet {
public:
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] bool contains(std::uint32_t actor, const Nonce& nonce) const noexcept;
    void insert(std::uint32_t actor, const Nonce& nonce);

private:
    struct Slot {
        std::uint32_t actor = empty;
        Nonce nonce{};
    };
    static constexpr std::uint32_t empty = 0xffff'ffffU;

    [[nodiscard]] static std::uint64_t hash(std::uint32_t actor, const Nonce& nonce) noexcept;
    void grow();

    std::vector<Slot> slots_;
    std::size_t mask_ = 0;
    std::size_t size_ = 0;
};

} // namespace cexchain::protocol

// IdEntry binds like a pair: `const auto& [key, value] = entry`.
template <class T>
struct std::tuple_size<cexchain::protocol::IdEntry<T>> : std::integral_constant<std::size_t, 2> {};
template <class T>
struct std::tuple_element<0, cexchain::protocol::IdEntry<T>> {
    using type = const cexchain::protocol::IdKey;
};
template <class T>
struct std::tuple_element<1, cexchain::protocol::IdEntry<T>> {
    using type = const T;
};
