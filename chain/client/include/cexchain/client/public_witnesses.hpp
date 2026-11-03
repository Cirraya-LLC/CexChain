// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/ledger/ledger.hpp>

/// The public witnesses a ledger asks to cosign its checkpoints (serve and
/// the console ask each one after every new checkpoint), as the command line
/// and the console share them. They are kept in witnesses.json in the ledger
/// directory:
///   [{"name": "...", "url": "https://...", "key": hex COSE public key,
///     "added": ms}, ...]
/// Each one was registered (public_witness.hpp): it follows this ledger
/// from its genesis entry.
namespace cexchain::client {

inline constexpr std::string_view witnesses_file = "witnesses.json";

struct UsedWitness {
    std::string name;
    std::string url;
    crypto::PublicKey key;
    protocol::Timestamp added = 0;
};

/// Throws ActionError if the file is damaged; none if there is no file.
[[nodiscard]] std::vector<UsedWitness> load_used_witnesses(const std::filesystem::path& ledger);
void save_used_witnesses(const std::filesystem::path& ledger,
                         const std::vector<UsedWitness>& witnesses);

/// A witness key as witnesses.json and GET /v1/witness carry it: the hex
/// of its COSE encoding. Throws UsageError if `hex` is not one.
[[nodiscard]] std::string witness_key_hex(const crypto::PublicKey& key);
[[nodiscard]] crypto::PublicKey witness_key_from_hex(std::string_view hex);

/// What a public witness says of itself (GET /v1/witness).
struct WitnessInfo {
    std::string name;
    crypto::PublicKey key;
    std::uint64_t ledgers = 0;
};

/// A witness's refusal: its status and message (422: the ledger is not
/// consistent with what it cosigned before: rewritten or forked).
struct WitnessRefused {
    int status = 0;
    std::string message;
};

/// Throws ActionError if the witness cannot be reached or is not one.
[[nodiscard]] WitnessInfo fetch_witness_info(const std::string& url);

/// Registers `ledger` with the witness at `url`: its genesis entry and a
/// cosign request of the latest checkpoint, consistent with what `key`
/// cosigned (else from size 0). Returns the cosignature, for the caller to
/// keep (which checks it). Throws WitnessRefused or ActionError.
[[nodiscard]] Bytes register_with_witness(const ledger::Ledger& ledger, const std::string& url,
                                          const crypto::PublicKey& key);

/// The latest checkpoint cosigned by `witness`, if it has not cosigned it:
/// the cosignature, for the caller to keep; nothing if there is nothing to
/// ask. Throws WitnessRefused or ActionError.
[[nodiscard]] std::optional<Bytes> ask_witness(const ledger::Ledger& ledger,
                                               const UsedWitness& witness);

/// A name for a witness here: 1 to 64 letters, digits, '-', '_', or '.'.
[[nodiscard]] bool valid_witness_name(std::string_view name);

struct Registered {
    UsedWitness witness;
    /// The checkpoint size it cosigned.
    std::uint64_t tree_size = 0;
};

/// Registers `ledger` (in `directory`) with the witness at `url`, which must
/// say its key is `key` (pinned: given by its operator, not by it), keeps
/// the cosignature with `keep` (which throws if it cannot), and lists the
/// witness in witnesses.json as `name`, or the witness's own name, or its
/// host. Registering again carries on (a cosign request like any other).
/// Throws UsageError, ActionError, or WitnessRefused.
[[nodiscard]] Registered register_witness(const ledger::Ledger& ledger,
                                          const std::filesystem::path& directory,
                                          const std::string& url, const crypto::PublicKey& key,
                                          const std::optional<std::string>& name,
                                          const std::function<void(ByteView cosignature)>& keep,
                                          protocol::Timestamp now);

/// The public witnesses this build knows (CMake
/// -DCEXCHAIN_PUBLIC_WITNESSES="name|https://...|keyhex,..."; none by
/// default), offered to people, never used unasked.
[[nodiscard]] std::vector<UsedWitness> built_in_public_witnesses();

/// [cosignature, witness public key]: what POST /v1/cosignatures and the
/// node's own add_cosignature take.
[[nodiscard]] Bytes cosignature_body(ByteView cosignature, const crypto::PublicKey& witness);

struct WitnessAsked {
    std::string name;
    /// The size it cosigned now, if it was asked and did.
    std::optional<std::uint64_t> cosigned;
    /// Why it did not, if it did not ("" if there was nothing to ask, or if
    /// it asked to wait: a quota, not a problem).
    std::string problem;
};

/// Asks every witness the ledger in `directory` registered with to cosign
/// its latest checkpoint, if it has not, and keeps each cosignature with
/// `keep` (cosignature_body in, the HTTP status of keeping it out; it may
/// wait). For serve and the console's poller.
[[nodiscard]] std::vector<WitnessAsked>
ask_used_witnesses(const ledger::Ledger& ledger, const std::filesystem::path& directory,
                   const std::function<int(Bytes body)>& keep);

} // namespace cexchain::client
