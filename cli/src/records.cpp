// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "records.hpp"

#include <algorithm>

namespace cexchain::cli {

crypto::openssl::HpkeKey load_hpke_key(const std::filesystem::path& path, const Args& args) {
    return app::load_hpke_key(path, [&] { return passphrase(args, path.string()); });
}

crypto::openssl::HpkeKey load_vault_key(const app::Session& session, const Args& args) {
    const std::filesystem::path path = args.has("vault-key")
                                           ? std::filesystem::path(*args.get("vault-key"))
                                           : default_vault_key_path(session);
    if (!std::filesystem::exists(path)) {
        throw CommandError{"no vault key at " + path.string() + "; pass --vault-key FILE"};
    }
    auto key = load_hpke_key(path, args);
    const Bytes expected = vault_public_key(session);
    if (!std::ranges::equal(key.public_key(), expected)) {
        throw CommandError{path.string() + " is not this ledger's vault key"};
    }
    return key;
}

Vault read_vault(const app::Session& session, const protocol::Id& record, const Args& args) {
    return app::read_vault(session, record, [&] { return load_vault_key(session, args); });
}

} // namespace cexchain::cli
