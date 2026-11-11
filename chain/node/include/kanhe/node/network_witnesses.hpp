// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <kanhe/core/crypto.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/network.hpp>
#include <kanhe/node/client.hpp>

/// Asking open-network witnesses to cosign checkpoints (spec section 10.2,
/// v0.13; c2sp.org/tlog-witness).
namespace kanhe::node {

/// A witness to ask: its add-checkpoint URL and its verifier key.
struct NetworkWitness {
    std::string url;
    protocol::network::VerifierKey key;

    friend bool operator==(const NetworkWitness&, const NetworkWitness&) = default;
};

/// The RFC 6962 consistency proof from one tree size to another.
using ConsistencyProof =
    std::function<Result<std::vector<crypto::Digest>>(std::uint64_t old_size, std::uint64_t size)>;

/// Asks `witness` to cosign the note of `checkpoint`, a SHA-256 ledger's,
/// signed with the Ed25519 `note_key`. `old_size` is the size the witness
/// cosigned last (0 for none), and `consistency` proves the step from it.
/// A 409 (the witness last cosigned another size) is answered once, from
/// the size it gives when that is no larger; a larger one means it saw a
/// longer history of this ledger, a fork or a restore from an old backup
/// (Errc::rejected). Returns the witness's cosignature, verified.
[[nodiscard]] Result<protocol::network::NoteSignature>
ask_network_witness(const crypto::Provider& provider, const protocol::SignedCheckpoint& checkpoint,
                    const crypto::Signer& note_key, const NetworkWitness& witness,
                    std::uint64_t old_size, const ConsistencyProof& consistency,
                    const ClientOptions& options = {});

} // namespace kanhe::node
