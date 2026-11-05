// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>

/// Open witness networks (spec section 10.2, v0.13): the C2SP formats a
/// SHA-256 ledger's checkpoints take for witnesses that follow
/// c2sp.org/tlog-witness, and the checks a verifier makes on their
/// cosignatures. Only SHA-256 trees: C2SP's are RFC 6962 trees.
namespace cexchain::protocol::network {

/// A ledger's origin: "cirraya.com/cexchain/" and the ledger id in 64
/// lowercase hexadecimal digits.
[[nodiscard]] std::string origin(const Id& ledger_id);

/// The checkpoint note: the origin, the tree size in decimal, and the root
/// in base64, each line ending in a newline.
[[nodiscard]] std::string checkpoint_note(std::string_view origin, std::uint64_t tree_size,
                                          const crypto::Digest& root);

/// C2SP's note signature types (c2sp.org/signed-note).
inline constexpr std::uint8_t log_ed25519 = 0x01;        ///< the log's own key
inline constexpr std::uint8_t cosigner_ed25519 = 0x04;   ///< cosignature/v1
inline constexpr std::uint8_t cosigner_ml_dsa_44 = 0x06; ///< subtree/v1, from 0

using KeyId = std::array<std::uint8_t, 4>;

/// The first four bytes of SHA-256(name || 0x0A || type || public key).
[[nodiscard]] Result<KeyId> key_id(const crypto::Provider& provider, std::string_view name,
                                   std::uint8_t type, ByteView public_key);

/// A log's or a cosigner's verifier key ("vkey").
struct VerifierKey {
    std::string name;
    KeyId id{};
    std::uint8_t type = 0;
    crypto::PublicKey key;

    friend bool operator==(const VerifierKey&, const VerifierKey&) = default;
};

/// Makes one, its key ID computed: Ed25519 for types 0x01 and 0x04,
/// ML-DSA-44 for 0x06.
[[nodiscard]] Result<VerifierKey> make_verifier_key(const crypto::Provider& provider,
                                                    std::string name, std::uint8_t type,
                                                    const crypto::PublicKey& key);

/// Reads "<name>+<8 hex digits>+<base64(type || public key)>", refusing an
/// invalid name, an unknown type, a key of the wrong size, and a key ID
/// that is not the key's.
[[nodiscard]] Result<VerifierKey> parse_verifier_key(const crypto::Provider& provider,
                                                     std::string_view text);

/// The text form parse_verifier_key reads.
[[nodiscard]] std::string verifier_key_text(const VerifierKey& key);

/// Whether `name` may name a key or a log: 1 to 255 bytes of UTF-8 with no
/// spaces, no plus signs, and no control characters.
[[nodiscard]] bool valid_name(std::string_view name) noexcept;

/// A note signature: who signed, and the bytes its line carries in base64
/// (a key ID, then what the signature type defines).
struct NoteSignature {
    std::string name;
    Bytes bytes;

    friend bool operator==(const NoteSignature&, const NoteSignature&) = default;
};

/// "— <name> <base64 bytes>" and a newline.
[[nodiscard]] std::string signature_line(const NoteSignature& signature);

/// The signature lines of a witness's answer (each one ending in a
/// newline, nothing else), at most `max_lines` of them.
[[nodiscard]] Result<std::vector<NoteSignature>> parse_signature_lines(std::string_view text,
                                                                       std::size_t max_lines = 16);

/// The note signed with an Ed25519 note key, as a log signs it: the note,
/// an empty line, and the key's signature line under `name`.
[[nodiscard]] Result<std::string> sign_note(const crypto::Provider& provider,
                                            const crypto::Signer& note_key, std::string_view name,
                                            std::string_view note);

/// The witness's time, in POSIX seconds, of a cosignature's bytes (after
/// the key ID): Errc::malformed if they are too short to hold one.
[[nodiscard]] Result<std::uint64_t> cosignature_time(ByteView bytes);

/// Verifies `signature` as `key`'s cosignature (type 0x04 or 0x06) of the
/// note of a tree of `tree_size` entries with `root` under `origin`: the
/// name and key ID are the key's, and its signature verifies. Returns the
/// witness's time.
[[nodiscard]] Result<std::uint64_t>
verify_cosignature(const crypto::Provider& provider, const VerifierKey& key,
                   std::string_view origin, std::uint64_t tree_size, const crypto::Digest& root,
                   const NoteSignature& signature);

/// tlog-witness's add-checkpoint body: "old <size>", the consistency
/// proof's hashes in base64, one a line, an empty line, then the signed
/// note.
[[nodiscard]] std::string add_checkpoint_body(std::uint64_t old_size,
                                              std::span<const crypto::Digest> proof,
                                              std::string_view signed_note);

/// The body of a witness's 409 answer (text/x.tlog.size): the size it last
/// cosigned, in decimal, and a newline.
[[nodiscard]] Result<std::uint64_t> parse_tlog_size(std::string_view body);

/// The most hashes an add-checkpoint's proof may hold (tlog-witness).
inline constexpr std::size_t max_proof_lines = 63;

} // namespace cexchain::protocol::network
