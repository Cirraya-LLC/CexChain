// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// GZIP and DEFLATE (RFC 1952, RFC 1951). The decoder follows the structure of
// zlib's reference decoder "puff" (canonical Huffman codes decoded from their
// counts), with every read and every back-reference bounds-checked.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include <kanhe/verifier/gzip.hpp>

namespace kanhe::verifier {

namespace {

constexpr std::array<std::uint32_t, 256> crc_table = [] {
    std::array<std::uint32_t, 256> table{};
    for (std::uint32_t n = 0; n < 256; ++n) {
        std::uint32_t c = n;
        for (int k = 0; k < 8; ++k) {
            c = (c & 1U) != 0 ? 0xEDB88320U ^ (c >> 1) : c >> 1;
        }
        table[n] = c;
    }
    return table;
}();

// Lengths 3 to 258: symbols 257 to 285, their base lengths and extra bits.
constexpr std::array<std::uint16_t, 29> length_base{3,  4,  5,  6,   7,   8,   9,   10,  11, 13,
                                                    15, 17, 19, 23,  27,  31,  35,  43,  51, 59,
                                                    67, 83, 99, 115, 131, 163, 195, 227, 258};
constexpr std::array<std::uint8_t, 29> length_extra{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                                                    2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
constexpr std::array<std::uint16_t, 30> distance_base{
    1,   2,   3,   4,   5,   7,    9,    13,   17,   25,   33,   49,   65,    97,    129,
    193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
constexpr std::array<std::uint8_t, 30> distance_extra{0, 0, 0,  0,  1,  1,  2,  2,  3,  3,
                                                      4, 4, 5,  5,  6,  6,  7,  7,  8,  8,
                                                      9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

// ---- writing ------------------------------------------------------------

class BitWriter {
public:
    explicit BitWriter(Bytes& out) : out_(out) {}

    /// `count` bits of `value`, least significant first (DEFLATE's order
    /// for everything but Huffman codes).
    void bits(std::uint32_t value, int count) {
        for (int i = 0; i < count; ++i) {
            bit((value >> i) & 1U);
        }
    }

    /// A Huffman code of `length` bits, most significant first.
    void code(std::uint32_t code, int length) {
        for (int i = length - 1; i >= 0; --i) {
            bit((code >> i) & 1U);
        }
    }

    void flush() {
        if (count_ > 0) {
            out_.push_back(current_);
            current_ = 0;
            count_ = 0;
        }
    }

private:
    void bit(std::uint32_t b) {
        current_ = static_cast<std::uint8_t>(current_ | (b << count_));
        if (++count_ == 8) {
            out_.push_back(current_);
            current_ = 0;
            count_ = 0;
        }
    }

    Bytes& out_;
    std::uint8_t current_ = 0;
    int count_ = 0;
};

/// A literal or length symbol in the fixed code (RFC 1951 section 3.2.6).
void fixed_symbol(BitWriter& w, std::uint32_t symbol) {
    if (symbol <= 143) {
        w.code(0x30 + symbol, 8);
    } else if (symbol <= 255) {
        w.code(0x190 + (symbol - 144), 9);
    } else if (symbol <= 279) {
        w.code(symbol - 256, 7);
    } else {
        w.code(0xC0 + (symbol - 280), 8);
    }
}

/// A match of `length` (3 to 258) at distance 1.
void fixed_run(BitWriter& w, std::uint32_t length) {
    std::size_t i = length_base.size() - 1;
    while (length_base[i] > length) {
        --i;
    }
    fixed_symbol(w, 257 + static_cast<std::uint32_t>(i));
    w.bits(length - length_base[i], length_extra[i]);
    w.code(0, 5); // distance code 0: distance 1, no extra bits
}

void put32(Bytes& out, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }
}

// ---- reading ------------------------------------------------------------

/// The little-endian 16-bit number at `at`.
std::uint16_t le16(ByteView bytes, std::size_t at) {
    return static_cast<std::uint16_t>(bytes[at] | (bytes[at + 1] << 8U));
}

/// A canonical Huffman code: how many codes of each length, and the
/// symbols in code order.
struct Huffman {
    std::array<std::uint16_t, 16> count{};
    std::array<std::uint16_t, 288> symbol{};
};

class Inflater {
public:
    Inflater(ByteView in, std::size_t max_output, Bytes& out)
        : in_(in), max_(max_output), out_(out) {}

    Status run() {
        int last = 0;
        do {
            const auto header = bits(3);
            if (!header) {
                return std::unexpected(header.error());
            }
            last = static_cast<int>(*header & 1U);
            Status status;
            switch (*header >> 1) {
            case 0:
                status = stored();
                break;
            case 1:
                status = fixed();
                break;
            case 2:
                status = dynamic();
                break;
            default:
                return fail(Errc::malformed, "a DEFLATE block of the reserved type");
            }
            if (!status) {
                return status;
            }
        } while (last == 0);
        return {};
    }

    /// Where the DEFLATE stream ended: the next whole byte.
    [[nodiscard]] std::size_t end() const noexcept { return position_; }

private:
    Result<std::uint32_t> bits(int need) {
        std::uint32_t value = bit_buffer_;
        while (bit_count_ < need) {
            if (position_ >= in_.size()) {
                return fail(Errc::truncated, "the DEFLATE stream ends early");
            }
            value |= static_cast<std::uint32_t>(in_[position_++]) << bit_count_;
            bit_count_ += 8;
        }
        bit_buffer_ = need >= 32 ? 0 : value >> need;
        bit_count_ -= need;
        return need >= 32 ? value : value & ((1U << need) - 1U);
    }

    Status emit(std::uint8_t byte) {
        if (out_.size() >= max_) {
            return fail(Errc::limit_exceeded, "the GZIP data decompresses past the limit");
        }
        out_.push_back(byte);
        return {};
    }

    Status stored() {
        bit_buffer_ = 0;
        bit_count_ = 0;
        if (in_.size() - position_ < 4) {
            return fail(Errc::truncated, "a stored DEFLATE block ends early");
        }
        const std::uint32_t length = le16(in_, position_);
        const std::uint32_t inverse = le16(in_, position_ + 2);
        position_ += 4;
        if (length != (~inverse & 0xFFFFU)) {
            return fail(Errc::malformed, "a stored DEFLATE block's length does not check");
        }
        if (in_.size() - position_ < length) {
            return fail(Errc::truncated, "a stored DEFLATE block ends early");
        }
        for (std::uint32_t i = 0; i < length; ++i) {
            if (auto s = emit(in_[position_ + i]); !s) {
                return s;
            }
        }
        position_ += length;
        return {};
    }

    Result<int> decode(const Huffman& h) {
        int code = 0;
        int first = 0;
        int index = 0;
        for (int len = 1; len <= 15; ++len) {
            const auto b = bits(1);
            if (!b) {
                return std::unexpected(b.error());
            }
            code |= static_cast<int>(*b);
            const int count = h.count[static_cast<std::size_t>(len)];
            if (code - count < first) {
                return h.symbol[static_cast<std::size_t>(index + (code - first))];
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        return fail(Errc::malformed, "a DEFLATE code that no symbol has");
    }

    /// Builds a code from symbol lengths, and answers how many codes it
    /// leaves unused: 0 for a complete code (or one with no symbols). Fails
    /// on an over-subscribed set.
    static Result<int> build(Huffman& h, std::span<const std::uint8_t> lengths) {
        h.count.fill(0);
        for (const std::uint8_t len : lengths) {
            ++h.count[len];
        }
        if (h.count[0] == lengths.size()) {
            return 0;
        }
        int left = 1;
        for (std::size_t len = 1; len <= 15; ++len) {
            left <<= 1;
            left -= h.count[len];
            if (left < 0) {
                return fail(Errc::malformed, "an over-subscribed DEFLATE code");
            }
        }
        std::array<std::uint16_t, 16> offsets{};
        for (std::size_t len = 1; len < 15; ++len) {
            offsets[len + 1] = static_cast<std::uint16_t>(offsets[len] + h.count[len]);
        }
        for (std::size_t s = 0; s < lengths.size(); ++s) {
            if (lengths[s] != 0) {
                h.symbol[offsets[lengths[s]]++] = static_cast<std::uint16_t>(s);
            }
        }
        return left;
    }

    /// As zlib's reference decoder allows: a complete code, or a single
    /// code of length 1.
    static Status build_dynamic(Huffman& h, std::span<const std::uint8_t> lengths) {
        const auto left = build(h, lengths);
        if (!left) {
            return std::unexpected(left.error());
        }
        if (*left != 0 && h.count[0] + h.count[1] != lengths.size()) {
            return fail(Errc::malformed, "an incomplete DEFLATE code");
        }
        return {};
    }

    Status codes(const Huffman& lengths, const Huffman& distances) {
        for (;;) {
            const auto symbol = decode(lengths);
            if (!symbol) {
                return std::unexpected(symbol.error());
            }
            if (*symbol < 256) {
                if (auto s = emit(static_cast<std::uint8_t>(*symbol)); !s) {
                    return s;
                }
                continue;
            }
            if (*symbol == 256) {
                return {};
            }
            const auto li = static_cast<std::size_t>(*symbol - 257);
            if (li >= length_base.size()) {
                return fail(Errc::malformed, "a DEFLATE length symbol out of range");
            }
            const auto lx = bits(length_extra[li]);
            if (!lx) {
                return std::unexpected(lx.error());
            }
            const std::size_t length = length_base[li] + *lx;
            const auto ds = decode(distances);
            if (!ds) {
                return std::unexpected(ds.error());
            }
            const auto di = static_cast<std::size_t>(*ds);
            if (di >= distance_base.size()) {
                return fail(Errc::malformed, "a DEFLATE distance symbol out of range");
            }
            const auto dx = bits(distance_extra[di]);
            if (!dx) {
                return std::unexpected(dx.error());
            }
            const std::size_t distance = distance_base[di] + *dx;
            if (distance > out_.size()) {
                return fail(Errc::malformed, "a DEFLATE match reaches before the start");
            }
            for (std::size_t i = 0; i < length; ++i) {
                if (auto s = emit(out_[out_.size() - distance]); !s) {
                    return s;
                }
            }
        }
    }

    Status fixed() {
        static const auto tables = [] {
            std::array<std::uint8_t, 288> lengths{};
            std::fill(lengths.begin(), lengths.begin() + 144, std::uint8_t{8});
            std::fill(lengths.begin() + 144, lengths.begin() + 256, std::uint8_t{9});
            std::fill(lengths.begin() + 256, lengths.begin() + 280, std::uint8_t{7});
            std::fill(lengths.begin() + 280, lengths.end(), std::uint8_t{8});
            std::array<std::uint8_t, 30> dist{};
            dist.fill(5);
            std::pair<Huffman, Huffman> out;
            (void)build(out.first, lengths);
            (void)build(out.second, dist);
            return out;
        }();
        return codes(tables.first, tables.second);
    }

    Status dynamic() {
        static constexpr std::array<std::uint8_t, 19> order{16, 17, 18, 0, 8,  7, 9,  6, 10, 5,
                                                            11, 4,  12, 3, 13, 2, 14, 1, 15};
        const auto nlen = bits(5);
        const auto ndist = nlen ? bits(5) : nlen;
        const auto ncode = ndist ? bits(4) : ndist;
        if (!ncode) {
            return std::unexpected(ncode.error());
        }
        const std::size_t lengths_count = *nlen + 257;
        const std::size_t distances_count = *ndist + 1;
        if (lengths_count > 286 || distances_count > 30) {
            return fail(Errc::malformed, "a dynamic DEFLATE block with too many codes");
        }
        std::array<std::uint8_t, 19> code_lengths{};
        for (std::size_t i = 0; i < *ncode + 4; ++i) {
            const auto b = bits(3);
            if (!b) {
                return std::unexpected(b.error());
            }
            code_lengths[order[i]] = static_cast<std::uint8_t>(*b);
        }
        Huffman code_code;
        const auto unused = build(code_code, code_lengths);
        if (!unused || *unused != 0 || code_code.count[0] == code_lengths.size()) {
            return fail(Errc::malformed, "a DEFLATE code-length code that is not complete");
        }
        std::array<std::uint8_t, 316> lengths{};
        std::size_t index = 0;
        while (index < lengths_count + distances_count) {
            const auto symbol = decode(code_code);
            if (!symbol) {
                return std::unexpected(symbol.error());
            }
            if (*symbol < 16) {
                lengths[index++] = static_cast<std::uint8_t>(*symbol);
                continue;
            }
            std::uint8_t value = 0;
            Result<std::uint32_t> repeat = 0U;
            if (*symbol == 16) {
                if (index == 0) {
                    return fail(Errc::malformed, "a DEFLATE length repeat with nothing before it");
                }
                value = lengths[index - 1];
                repeat = bits(2);
                if (repeat) {
                    *repeat += 3;
                }
            } else if (*symbol == 17) {
                repeat = bits(3);
                if (repeat) {
                    *repeat += 3;
                }
            } else {
                repeat = bits(7);
                if (repeat) {
                    *repeat += 11;
                }
            }
            if (!repeat) {
                return std::unexpected(repeat.error());
            }
            if (index + *repeat > lengths_count + distances_count) {
                return fail(Errc::malformed, "DEFLATE code lengths run past their count");
            }
            for (std::uint32_t i = 0; i < *repeat; ++i) {
                lengths[index++] = value;
            }
        }
        if (lengths[256] == 0) {
            return fail(Errc::malformed, "a dynamic DEFLATE block without an end code");
        }
        Huffman literal;
        Huffman distance;
        if (auto s = build_dynamic(literal, std::span(lengths).first(lengths_count)); !s) {
            return s;
        }
        if (auto s =
                build_dynamic(distance, std::span(lengths).subspan(lengths_count, distances_count));
            !s) {
            return s;
        }
        return codes(literal, distance);
    }

    ByteView in_;
    std::size_t max_;
    Bytes& out_;
    std::size_t position_ = 0;
    std::uint32_t bit_buffer_ = 0;
    int bit_count_ = 0;
};

} // namespace

std::uint32_t crc32(ByteView data) noexcept {
    std::uint32_t c = 0xFFFFFFFFU;
    for (const std::uint8_t byte : data) {
        c = crc_table[(c ^ byte) & 0xFFU] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFFU;
}

Bytes gzip_compress(ByteView data) {
    // ID1 ID2, CM 8, no flags, MTIME 0, XFL 0, OS 255 (unknown).
    Bytes out{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff};
    {
        BitWriter w(out);
        w.bits(1, 1); // the final block
        w.bits(1, 2); // fixed codes
        std::size_t i = 0;
        while (i < data.size()) {
            fixed_symbol(w, data[i]);
            std::size_t run = 0;
            while (i + 1 + run < data.size() && data[i + 1 + run] == data[i]) {
                ++run;
            }
            std::size_t left = run;
            while (left >= 3) {
                const std::size_t length = std::min<std::size_t>(left, 258);
                // Leave at least 3 for a last match, or none.
                const std::size_t take =
                    (left - length != 0 && left - length < 3) ? length - 3 : length;
                fixed_run(w, static_cast<std::uint32_t>(take));
                left -= take;
            }
            for (std::size_t k = 0; k < left; ++k) {
                fixed_symbol(w, data[i]);
            }
            i += 1 + run;
        }
        fixed_symbol(w, 256);
        w.flush();
    }
    put32(out, crc32(data));
    put32(out, static_cast<std::uint32_t>(data.size()));
    return out;
}

Result<Bytes> gzip_decompress(ByteView data, std::size_t max_output) {
    if (data.size() < 18) {
        return fail(Errc::truncated, "GZIP data ends early");
    }
    if (data[0] != 0x1f || data[1] != 0x8b || data[2] != 8) {
        return fail(Errc::malformed, "not GZIP data with DEFLATE");
    }
    const std::uint8_t flags = data[3];
    if ((flags & 0xE0U) != 0) {
        return fail(Errc::malformed, "GZIP data with reserved flags set");
    }
    std::size_t at = 10;
    const std::size_t end = data.size() - 8; // the trailer
    if ((flags & 4U) != 0) {                 // FEXTRA
        if (end - at < 2) {
            return fail(Errc::truncated, "a GZIP extra field ends early");
        }
        const std::size_t length = le16(data, at);
        at += 2;
        if (end - at < length) {
            return fail(Errc::truncated, "a GZIP extra field ends early");
        }
        at += length;
    }
    for (const std::uint8_t text_flag : {std::uint8_t{8}, std::uint8_t{16}}) { // FNAME, FCOMMENT
        if ((flags & text_flag) != 0) {
            while (at < end && data[at] != 0) {
                ++at;
            }
            if (at >= end) {
                return fail(Errc::truncated, "a GZIP name or comment ends early");
            }
            ++at;
        }
    }
    if ((flags & 2U) != 0) { // FHCRC
        if (end - at < 2) {
            return fail(Errc::truncated, "a GZIP header checksum ends early");
        }
        const auto header_crc = static_cast<std::uint16_t>(crc32(data.first(at)) & 0xFFFFU);
        if (le16(data, at) != header_crc) {
            return fail(Errc::verification_failed, "a GZIP header checksum does not match");
        }
        at += 2;
    }
    Bytes out;
    Inflater inflater(data.subspan(at, end - at), max_output, out);
    if (auto s = inflater.run(); !s) {
        return std::unexpected(s.error());
    }
    if (at + inflater.end() != end) {
        return fail(Errc::malformed, "bytes after the GZIP data");
    }
    const auto le32 = [&](std::size_t p) {
        return static_cast<std::uint32_t>(data[p]) |
               (static_cast<std::uint32_t>(data[p + 1]) << 8) |
               (static_cast<std::uint32_t>(data[p + 2]) << 16) |
               (static_cast<std::uint32_t>(data[p + 3]) << 24);
    };
    if (le32(end) != crc32(out)) {
        return fail(Errc::verification_failed, "the GZIP data's checksum does not match");
    }
    if (le32(end + 4) != static_cast<std::uint32_t>(out.size())) {
        return fail(Errc::verification_failed, "the GZIP data's size does not match");
    }
    return out;
}

} // namespace kanhe::verifier
