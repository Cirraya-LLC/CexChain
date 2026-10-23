// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <cexchain/app/session.hpp>
#include <cexchain/app/support.hpp>

#include "args.hpp"

/// What the command line adds to the app library: keys, passphrases, and
/// presence from options and the terminal, and sessions from --ledger or
/// --server.
namespace cexchain::cli {

/// A key passphrase, for the key file named `purpose`: read from the
/// `file_option` file if given, else from the `env` variable, else asked for
/// on the terminal (twice if `confirm`).
[[nodiscard]] std::string passphrase(const Args& args, const std::string& purpose,
                                     bool confirm = false,
                                     std::string_view file_option = "passphrase-file",
                                     const char* env = "CEXCHAIN_PASSPHRASE");

/// A key that signs: a private key file, or a key on a token (USB key, smart
/// card, HSM) named by a pkcs11: URI, whose PIN comes from the URI,
/// $CEXCHAIN_PKCS11_PIN, or a prompt.
[[nodiscard]] std::unique_ptr<crypto::Signer> load_signer(const std::string& source,
                                                          const Args& args);

/// Generates a key pair on the token a pkcs11: URI names (ESP256 or Ed25519).
[[nodiscard]] std::unique_ptr<crypto::Signer> generate_on_token(const std::string& uri,
                                                                crypto::SigAlg alg);

/// How the signer proves presence, from --presence (a passkey, in a one-time
/// page the browser opens unless --no-browser) or --presence-key (a hardware
/// key).
[[nodiscard]] std::optional<PresenceRequest> presence_request(const Args& args);

/// Loads a private key file, asking for its passphrase if it is encrypted.
[[nodiscard]] crypto::openssl::KeyPair load_key(const std::filesystem::path& path,
                                                const Args& args);

/// The public key in a public key file, or in a private key file (asking for
/// its passphrase if needed).
[[nodiscard]] crypto::PublicKey public_key_of(const std::filesystem::path& path, const Args& args);

/// The API token from --token-file or $CEXCHAIN_TOKEN, if any.
[[nodiscard]] std::optional<std::string> api_token(const Args& args);
/// A client for the API at `url`, with the API token and, if given, the CA
/// certificates to trust.
[[nodiscard]] node::Client client_for(const std::string& url, const Args& args,
                                      const std::optional<std::string>& ca_file);

/// The server a command works through (--server, or $CEXCHAIN_SERVER), if
/// the command takes --server and one is given.
[[nodiscard]] std::optional<std::string> server_option(const Args& args);

/// The log key from --log-key (and its passphrase), for what a session signs
/// on a ledger directory; refused with --server.
[[nodiscard]] LogKey log_key(const Args& args);

/// A session for a command: the ledger directory (--ledger, or
/// $CEXCHAIN_LEDGER), or, in client mode, a verified mirror of the ledger a
/// server serves: with --server URL (or $CEXCHAIN_SERVER), for commands that
/// list --server among their options. The mirror lives in the cache (--cache,
/// default $XDG_CACHE_HOME/cexchain or ~/.cache/cexchain); the ledger a URL
/// serves is pinned on first use (--ledger-id, required for http://).
class Session : public app::Session {
public:
    explicit Session(const std::filesystem::path& directory) : app::Session(directory) {}
    explicit Session(const Args& args);

    using app::Session::checkpoint;
    using app::Session::contract_evidence;
    using app::Session::evidence;
    using app::Session::receipt;
    using app::Session::submit;

    /// Signs and submits as the holder of --as, with --delegation, --model,
    /// --model-version, --inputs, --presence, and --no-browser taken from
    /// `args`.
    protocol::Id submit(const Args& args, protocol::Body body);

    /// AI provenance from --model, --model-version, and --inputs (hashed).
    [[nodiscard]] std::optional<protocol::Provenance> provenance(const Args& args) const;

    // With the log key from --log-key, or the server's (see log_key).
    [[nodiscard]] protocol::SignedCheckpoint checkpoint(const Args& args);
    [[nodiscard]] protocol::EvidenceBundle evidence(const Args& args, const protocol::Id& record);
    [[nodiscard]] Bytes contract_evidence(const Args& args, const protocol::Id& instance);
    [[nodiscard]] Bytes receipt(const Args& args, std::uint64_t index);
};

} // namespace cexchain::cli
