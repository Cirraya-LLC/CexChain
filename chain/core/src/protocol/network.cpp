// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <charconv>
#include <format>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/network.hpp>

namespace kanhe::protocol::network {

namespace {

constexpr std::string_view origin_prefix = "cirraya.com/kanhe/";
constexpr std::string_view em_dash_space = "\xE2\x80\x94 ";
constexpr std::size_t ed25519_key_size = 32;
constexpr std::size_t ed25519_signature_size = 64;
constexpr std::size_t ml_dsa_44_key_size = 1312;
constexpr std::size_t ml_dsa_44_signature_size = 2420;
constexpr std::size_t time_offset = 4; // after the key ID
constexpr std::size_t signature_offset = 12;

/// The code points of Unicode's spaces beyond ASCII (White_Space, not
/// control characters), which names must not hold.
bool unicode_space(char32_t c) noexcept {
    return c == 0x85 || c == 0xA0 || c == 0x1680 || (c >= 0x2000 && c <= 0x200A) || c == 0x2028 ||
           c == 0x2029 || c == 0x202F || c == 0x205F || c == 0x3000;
}

void put_be64(Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

std::uint64_t be64(ByteView bytes) {
    std::uint64_t value = 0;
    for (const std::uint8_t b : bytes.first(8)) {
        value = (value << 8U) | b;
    }
    return value;
}

void append(Bytes& out, std::string_view text) {
    out.insert(out.end(), text.begin(), text.end());
}

Result<crypto::SigAlg> algorithm_of(std::uint8_t type) {
    switch (type) {
    case log_ed25519:
    case cosigner_ed25519:
        return crypto::SigAlg::ed25519;
    case cosigner_ml_dsa_44:
        return crypto::SigAlg::ml_dsa_44;
    default:
        return fail(Errc::unsupported, "a note signature type other than 0x01, 0x04, and 0x06");
    }
}

std::size_t key_size(crypto::SigAlg alg) noexcept {
    return alg == crypto::SigAlg::ed25519 ? ed25519_key_size : ml_dsa_44_key_size;
}

} // namespace

std::string origin(const Id& ledger_id) {
    return std::string(origin_prefix) + to_hex(ledger_id.bytes());
}

std::string checkpoint_note(std::string_view origin, std::uint64_t tree_size,
                            const crypto::Digest& root) {
    return std::format("{}\n{}\n{}\n", origin, tree_size, to_base64(root.bytes()));
}

Result<KeyId> key_id(const crypto::Provider& provider, std::string_view name, std::uint8_t type,
                     ByteView public_key) {
    const std::uint8_t newline = 0x0A;
    auto digest = provider.digest(crypto::HashAlg::sha256, {as_bytes(name), ByteView(&newline, 1),
                                                            ByteView(&type, 1), public_key});
    if (!digest) {
        return std::unexpected(digest.error());
    }
    KeyId id{};
    std::ranges::copy(digest->bytes().first(id.size()), id.begin());
    return id;
}

bool valid_name(std::string_view name) noexcept {
    if (name.empty() || name.size() > 255 || !cbor::is_valid_utf8(name)) {
        return false;
    }
    for (std::size_t i = 0; i < name.size();) {
        const auto lead = static_cast<unsigned char>(name[i]);
        if (lead < 0x80) {
            if (lead <= 0x20 || lead == '+') {
                return false;
            }
            ++i;
            continue;
        }
        // Valid UTF-8 (checked above): decode one code point.
        const std::size_t length = lead >= 0xF0 ? 4 : lead >= 0xE0 ? 3 : 2;
        char32_t c = lead & (0xFFU >> (length + 1));
        for (std::size_t k = 1; k < length; ++k) {
            c = (c << 6U) | (static_cast<unsigned char>(name[i + k]) & 0x3FU);
        }
        if (unicode_space(c)) {
            return false;
        }
        i += length;
    }
    return true;
}

Result<VerifierKey> make_verifier_key(const crypto::Provider& provider, std::string name,
                                      std::uint8_t type, const crypto::PublicKey& key) {
    if (!valid_name(name)) {
        return fail(Errc::invalid_argument, "a key name must be 1 to 255 bytes, no spaces or +");
    }
    auto alg = algorithm_of(type);
    if (!alg) {
        return std::unexpected(alg.error());
    }
    if (key.algorithm != *alg || key.bytes.size() != key_size(*alg)) {
        return fail(Errc::invalid_argument, "the key is not of its signature type's algorithm");
    }
    auto id = key_id(provider, name, type, key.bytes);
    if (!id) {
        return std::unexpected(id.error());
    }
    return VerifierKey{std::move(name), *id, type, key};
}

Result<VerifierKey> parse_verifier_key(const crypto::Provider& provider, std::string_view text) {
    // Names hold no '+' and key IDs are hex, so the first two '+' split it;
    // the base64 after them may hold more.
    const auto first = text.find('+');
    const auto second = first == std::string_view::npos ? first : text.find('+', first + 1);
    if (second == std::string_view::npos) {
        return fail(Errc::malformed, "a verifier key is <name>+<key ID>+<base64 key>");
    }
    const std::string_view name = text.substr(0, first);
    const std::string_view hex = text.substr(first + 1, second - first - 1);
    auto id = from_hex(hex);
    if (!id || id->size() != 4 || to_hex(*id) != hex) {
        return fail(Errc::malformed, "a verifier key's key ID is 8 lowercase hex digits");
    }
    auto material = from_base64(text.substr(second + 1));
    if (!material || material->empty()) {
        return fail(Errc::malformed, "a verifier key's key is not base64");
    }
    const std::uint8_t type = material->front();
    auto alg = algorithm_of(type);
    if (!alg) {
        return std::unexpected(alg.error());
    }
    if (material->size() - 1 != key_size(*alg)) {
        return fail(Errc::malformed, "a verifier key's key has the wrong size");
    }
    auto key =
        make_verifier_key(provider, std::string(name), type,
                          crypto::PublicKey{*alg, Bytes(material->begin() + 1, material->end())});
    if (!key) {
        return fail(Errc::malformed, "a verifier key's name is not a valid key name");
    }
    if (!std::ranges::equal(key->id, *id)) {
        return fail(Errc::malformed, "a verifier key's key ID is not its key's");
    }
    return key;
}

std::string verifier_key_text(const VerifierKey& key) {
    Bytes material{key.type};
    material.insert(material.end(), key.key.bytes.begin(), key.key.bytes.end());
    return std::format("{}+{}+{}", key.name, to_hex(key.id), to_base64(material));
}

std::string signature_line(const NoteSignature& signature) {
    return std::format("{}{} {}\n", em_dash_space, signature.name, to_base64(signature.bytes));
}

Result<std::vector<NoteSignature>> parse_signature_lines(std::string_view text,
                                                         std::size_t max_lines) {
    std::vector<NoteSignature> out;
    while (!text.empty()) {
        const auto end = text.find('\n');
        if (end == std::string_view::npos) {
            return fail(Errc::malformed, "a signature line does not end in a newline");
        }
        std::string_view line = text.substr(0, end);
        text.remove_prefix(end + 1);
        if (!line.starts_with(em_dash_space)) {
            return fail(Errc::malformed, "a signature line does not begin with an em dash");
        }
        line.remove_prefix(em_dash_space.size());
        const auto space = line.find(' ');
        if (space == std::string_view::npos) {
            return fail(Errc::malformed, "a signature line has no signature");
        }
        const std::string_view name = line.substr(0, space);
        if (!valid_name(name)) {
            return fail(Errc::malformed, "a signature line's name is not a valid key name");
        }
        auto bytes = from_base64(line.substr(space + 1));
        if (!bytes || bytes->size() < 4) {
            return fail(Errc::malformed, "a signature line's signature is not base64 of a key ID "
                                         "and more");
        }
        if (out.size() == max_lines) {
            return fail(Errc::limit_exceeded, "too many signature lines");
        }
        out.push_back({std::string(name), std::move(*bytes)});
    }
    if (out.empty()) {
        return fail(Errc::malformed, "no signature lines");
    }
    return out;
}

Result<std::string> sign_note(const crypto::Provider& provider, const crypto::Signer& note_key,
                              std::string_view name, std::string_view note) {
    if (note_key.algorithm() != crypto::SigAlg::ed25519) {
        return fail(Errc::invalid_argument, "a note key is an Ed25519 key");
    }
    if (!valid_name(name) || note.empty() || note.back() != '\n') {
        return fail(Errc::invalid_argument, "a note ends in a newline and its signer is named");
    }
    auto id = key_id(provider, name, log_ed25519, note_key.public_key().bytes);
    if (!id) {
        return std::unexpected(id.error());
    }
    auto signature = note_key.sign(as_bytes(note));
    if (!signature) {
        return std::unexpected(signature.error());
    }
    Bytes bytes(id->begin(), id->end());
    bytes.insert(bytes.end(), signature->begin(), signature->end());
    return std::string(note) + "\n" + signature_line({std::string(name), std::move(bytes)});
}

Result<std::uint64_t> cosignature_time(ByteView bytes) {
    if (bytes.size() < signature_offset) {
        return fail(Errc::malformed, "a cosignature is too short to hold its time");
    }
    return be64(bytes.subspan(time_offset));
}

Result<std::uint64_t> verify_cosignature(const crypto::Provider& provider, const VerifierKey& key,
                                         std::string_view origin, std::uint64_t tree_size,
                                         const crypto::Digest& root,
                                         const NoteSignature& signature) {
    if (signature.name != key.name || signature.bytes.size() < key.id.size() ||
        !std::ranges::equal(ByteView(signature.bytes).first(key.id.size()), key.id)) {
        return fail(Errc::invalid_argument, "the cosignature is not by this key");
    }
    auto time = cosignature_time(signature.bytes);
    if (!time) {
        return std::unexpected(time.error());
    }
    const ByteView sig = ByteView(signature.bytes).subspan(signature_offset);
    Bytes message;
    switch (key.type) {
    case cosigner_ed25519:
        if (sig.size() != ed25519_signature_size) {
            return fail(Errc::malformed, "an Ed25519 cosignature has the wrong size");
        }
        append(message, std::format("cosignature/v1\ntime {}\n", *time));
        append(message, checkpoint_note(origin, tree_size, root));
        break;
    case cosigner_ml_dsa_44:
        if (sig.size() != ml_dsa_44_signature_size) {
            return fail(Errc::malformed, "an ML-DSA-44 cosignature has the wrong size");
        }
        if (origin.size() > 255 || root.size() != 32) {
            return fail(Errc::invalid_argument, "a subtree cosignature needs a short origin and a "
                                                "32-byte root");
        }
        // CosignedSubtree (c2sp.org/tlog-cosignature), the whole tree.
        append(message, std::string_view("subtree/v1\n\0", 12));
        message.push_back(static_cast<std::uint8_t>(key.name.size()));
        append(message, key.name);
        put_be64(message, *time);
        message.push_back(static_cast<std::uint8_t>(origin.size()));
        append(message, origin);
        put_be64(message, 0);
        put_be64(message, tree_size);
        message.insert(message.end(), root.bytes().begin(), root.bytes().end());
        break;
    default:
        return fail(Errc::invalid_argument, "this key cosigns nothing (it is a log's)");
    }
    if (auto s = provider.verify(key.key, message, sig); !s) {
        return fail(Errc::verification_failed, "the cosignature does not verify");
    }
    return time;
}

std::string add_checkpoint_body(std::uint64_t old_size, std::span<const crypto::Digest> proof,
                                std::string_view signed_note) {
    std::string out = std::format("old {}\n", old_size);
    for (const crypto::Digest& hash : proof) {
        out += to_base64(hash.bytes());
        out += '\n';
    }
    out += '\n';
    out += signed_note;
    return out;
}

Result<std::uint64_t> parse_tlog_size(std::string_view body) {
    if (body.size() < 2 || body.back() != '\n' || (body[0] == '0' && body.size() > 2)) {
        return fail(Errc::malformed, "a tree size is a decimal number and a newline");
    }
    std::uint64_t size = 0;
    const auto digits = body.substr(0, body.size() - 1);
    const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), size);
    if (ec != std::errc{} || end != digits.data() + digits.size()) {
        return fail(Errc::malformed, "a tree size is a decimal number and a newline");
    }
    return size;
}

} // namespace kanhe::protocol::network
