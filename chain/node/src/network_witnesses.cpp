// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <string>
#include <string_view>

#include <cexchain/node/network_witnesses.hpp>

namespace cexchain::node {

namespace network = protocol::network;

Result<network::NoteSignature>
ask_network_witness(const crypto::Provider& provider, const protocol::SignedCheckpoint& checkpoint,
                    const crypto::Signer& note_key, const NetworkWitness& witness,
                    std::uint64_t old_size, const ConsistencyProof& consistency,
                    const ClientOptions& options) {
    const protocol::Checkpoint& at = checkpoint.checkpoint;
    if (at.tree_hash != crypto::HashAlg::sha256) {
        return fail(Errc::unsupported, "only SHA-256 ledgers can be witnessed by open networks");
    }
    const std::string origin = network::origin(at.ledger_id);
    auto signed_note = network::sign_note(provider, note_key, origin,
                                          network::checkpoint_note(origin, at.tree_size, at.root));
    if (!signed_note) {
        return std::unexpected(signed_note.error());
    }
    auto url = Url::parse(witness.url);
    if (!url) {
        return std::unexpected(url.error());
    }
    // The witness's URL is the add-checkpoint endpoint itself.
    const std::string path = url->base_path.empty() ? "/" : url->base_path;
    url->base_path.clear();
    const Client client(*url, options);
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (old_size > at.tree_size) {
            return fail(Errc::rejected, "the witness cosigned a larger tree of this ledger: a "
                                        "fork, or a restore from an old backup");
        }
        std::vector<crypto::Digest> proof;
        if (old_size != 0 && old_size != at.tree_size) {
            auto made = consistency(old_size, at.tree_size);
            if (!made) {
                return std::unexpected(made.error());
            }
            proof = std::move(*made);
        }
        if (proof.size() > network::max_proof_lines) {
            return fail(Errc::limit_exceeded, "the consistency proof is too long for a witness");
        }
        const std::string body = network::add_checkpoint_body(old_size, proof, *signed_note);
        auto answer = client.request("POST", path, as_bytes(body), "text/plain; charset=utf-8");
        if (!answer) {
            return std::unexpected(answer.error());
        }
        const std::string_view text(reinterpret_cast<const char*>(answer->body.data()),
                                    answer->body.size());
        switch (answer->status) {
        case 200: {
            auto lines = network::parse_signature_lines(text);
            if (!lines) {
                return fail(Errc::malformed, "the witness's answer is not signature lines");
            }
            for (const network::NoteSignature& line : *lines) {
                if (network::verify_cosignature(provider, witness.key, origin, at.tree_size,
                                                at.root, line)) {
                    return line;
                }
            }
            return fail(Errc::verification_failed,
                        "the witness's answer holds no cosignature by its key");
        }
        case 409: {
            auto size = network::parse_tlog_size(text);
            if (!size) {
                return fail(Errc::malformed, "the witness's conflict does not give its size");
            }
            old_size = *size;
            continue;
        }
        case 403:
            return fail(Errc::rejected, "the witness does not know this ledger's note key");
        case 404:
            return fail(Errc::not_found, "the witness does not know this ledger (it is not on "
                                         "the witness's list of logs)");
        case 422:
            return fail(Errc::verification_failed, "the witness refused the consistency proof");
        default:
            return fail(Errc::unavailable, "the witness answered with an error");
        }
    }
    return fail(Errc::unavailable, "the witness disagreed twice about the size it cosigned");
}

} // namespace cexchain::node
