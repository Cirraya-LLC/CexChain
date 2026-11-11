// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <filesystem>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

#include <kanhe/client/records.hpp>
#include <kanhe/client/session.hpp>
#include <kanhe/client/support.hpp>
#include <kanhe/console/sessions.hpp>
#include <kanhe/console/setup.hpp>
#include <kanhe/console/users.hpp>
#include <kanhe/core/bytes.hpp>

namespace kanhe::console {

bool has_ledger(const std::filesystem::path& directory) {
    return std::filesystem::exists(directory / "statements");
}

protocol::Scope owner_scope() {
    using enum protocol::StatementType;
    protocol::Scope scope;
    // Everything but the ledger's own keys, which only the root key (the
    // recovery code) rotates.
    scope.statement_types = {
        actor_register,     actor_rotate_key, actor_revoke,   delegation_grant,  delegation_revoke,
        actor_set_presence, record_register,  record_endorse, record_transition, record_revoke,
        contract_deploy,    contract_call,    contract_retire};
    scope.may_delegate = true;
    scope.require_presence = true;
    return scope;
}

protocol::Scope machine_scope() {
    protocol::Scope scope;
    scope.statement_types = {protocol::StatementType::contract_call};
    scope.may_delegate = false;
    scope.require_presence = false;
    return scope;
}

crypto::PublicKey witness_public_key(KeyStore& keys) {
    // Made once: a second key would replace the one a code already carries.
    static std::mutex making;
    const std::lock_guard lock(making);
    for (const SealedKeyInfo& k : keys.keys()) {
        if (k.name == witness_key_name) {
            return k.public_key;
        }
    }
    auto made = crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519);
    if (!made) {
        throw std::runtime_error("making the witness key failed");
    }
    keys.seal(witness_key_name, *made);
    return made->public_key();
}

namespace {

std::set<std::filesystem::path> entries(const std::filesystem::path& directory) {
    std::set<std::filesystem::path> out;
    std::error_code ignored;
    for (const auto& e : std::filesystem::directory_iterator(directory, ignored)) {
        out.insert(e.path());
    }
    return out;
}

/// Removes what a failed first run made in `directory`, so that it can run
/// again: the entries that were not there before it.
void remove_new(const std::filesystem::path& directory,
                const std::set<std::filesystem::path>& before, const std::filesystem::path& keep) {
    std::error_code ignored;
    for (const auto& path : entries(directory)) {
        if (!before.contains(path) && path != keep) {
            std::filesystem::remove_all(path, ignored);
        }
    }
}

FirstRun make_first_run(const SetUp& request, KeyStore& keys, ledger::Entropy& entropy);

} // namespace

FirstRun set_up(const SetUp& request, KeyStore& keys, ledger::Entropy& entropy) {
    if (has_ledger(request.ledger)) {
        throw std::runtime_error("this directory holds a ledger already");
    }
    if (keys.initialized()) {
        throw std::runtime_error("the console's keys are set up already");
    }
    if (!valid_user_name(request.name)) {
        throw std::invalid_argument("a name is 1 to 64 letters, digits, spaces, '.', '_', or '-'");
    }
    if (request.passkey.method != protocol::PresenceMethod::webauthn ||
        request.passkey.rp_id.empty()) {
        throw std::invalid_argument("the owner signs in with a passkey, not a hardware key");
    }
    const std::filesystem::path state = state_directory(request.ledger);
    const auto ledger_before = entries(request.ledger);
    const auto state_before = entries(state);
    try {
        return make_first_run(request, keys, entropy);
    } catch (...) {
        keys.lock();
        remove_new(state, state_before, {});
        remove_new(request.ledger, ledger_before, state);
        throw;
    }
}

namespace {

FirstRun make_first_run(const SetUp& request, KeyStore& keys, ledger::Entropy& entropy) {
    auto root = crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519);
    auto log = crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519);
    auto owner = crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519);
    auto vault = crypto::openssl::HpkeKey::generate();
    auto machine = crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519);
    auto witness = crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519);
    if (!root || !log || !owner || !vault || !machine || !witness) {
        throw std::runtime_error("making the ledger's keys failed");
    }
    FirstRun out;
    out.recovery_code = keys.initialize(entropy);
    if (request.passphrase) {
        keys.add_slot({SlotKind::passphrase, {}}, *request.passphrase);
    }
    if (request.prf) {
        keys.add_slot({SlotKind::prf, to_base64url(request.passkey.credential_id)}, *request.prf);
    }
    keys.seal(root_key_name, *root);
    keys.seal(log_key_name, *log);
    keys.seal(owner_key_name, *owner);
    keys.seal(machine_key_name, *machine);
    keys.seal(witness_key_name, *witness);
    keys.seal_vault_key(*vault);

    std::filesystem::create_directories(request.ledger);
    client::create_ledger(request.ledger, *root, log->public_key(), crypto::HashAlg::sha256,
                          request.name);
    // The vault: its public key for whoever registers records, its private
    // key sealed in the console only.
    std::filesystem::create_directories(request.ledger / "vault" / "records");
    client::write_file(request.ledger / "vault" / "vault.pub",
                       client::encode_vault_public_key(vault->public_key()), false);
    {
        // The root key's statements, then it leaves memory with `root`.
        client::Session session(client::Location{request.ledger});
        out.ledger = session.state().ledger_id();
        out.owner = session.submit(*root,
                                   protocol::ActorRegisterBody{protocol::ActorKind::person,
                                                               request.name, owner->public_key(),
                                                               std::nullopt, std::nullopt},
                                   std::nullopt);
        static_cast<void>(session.submit(
            *root, protocol::ActorSetPresenceBody{out.owner, {request.passkey}}, std::nullopt));
        static_cast<void>(session.submit(
            *root, protocol::DelegationGrantBody{out.owner, owner_scope()}, std::nullopt));
        // The console's machine: the registrar and keeper the node runs.
        out.machine = session.submit(
            *root,
            protocol::ActorRegisterBody{protocol::ActorKind::device, std::string(machine_name),
                                        machine->public_key(), std::nullopt, std::nullopt},
            std::nullopt);
        static_cast<void>(session.submit(
            *root, protocol::DelegationGrantBody{out.machine, machine_scope()}, std::nullopt));
    }

    const std::filesystem::path state = state_directory(request.ledger);
    People people = load_people(state);
    people.users.push_back({request.name,
                            Role::owner,
                            ledger::SystemClock{}.now(),
                            {request.passkey},
                            to_hex(out.owner.bytes()),
                            std::string(owner_key_name)});
    std::erase_if(people.invitations, [](const Invitation& i) { return i.user.empty(); });
    save_people(state, people);
    return out;
}

} // namespace

} // namespace kanhe::console
