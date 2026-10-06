// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Proof of human presence with passkeys. A person enrolls a passkey (which
// never leaves their authenticator) and hands the credential file to an
// administrator, who registers it on the ledger; afterwards any command run
// with --presence asks for the passkey and binds the confirmation to exactly
// that statement.

#include <print>

#include <cexchain/core/protocol/presence.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "webauthn.hpp"

namespace cexchain::cli {

int cmd_presence_enroll(const Args& args) {
    const std::filesystem::path out = args.need("out");
    if (std::filesystem::exists(out)) {
        throw CommandError{out.string() + " already exists"};
    }
    const std::string name = args.need("name");
    std::array<std::uint8_t, 32> challenge{};
    std::array<std::uint8_t, 16> user_id{};
    unwrap(crypto::openssl::random_bytes(challenge), "generating a challenge");
    unwrap(crypto::openssl::random_bytes(user_id), "generating a user id");
    const nlohmann::json request{
        {"mode", "create"},
        {"rpId", local_rp_id},
        {"challenge", to_base64url(challenge)},
        {"userId", to_base64url(user_id)},
        {"userName", name},
        {"title", "Create a CexChain passkey for " + name},
        {"summary", "This passkey will prove that you, in person, approved what is signed "
                    "in your name on a CexChain ledger."}};
    const nlohmann::json response = run_webauthn_ceremony(request, !args.has("no-browser"));
    auto field = [&](const char* key) {
        if (!response.contains(key) || !response[key].is_string()) {
            throw CommandError{"the browser's passkey response is incomplete"};
        }
        return unwrap(from_base64url(response[key].get<std::string>()),
                      "reading the passkey response");
    };
    const crypto::openssl::Provider provider;
    const auto credential =
        unwrap(protocol::credential_from_registration(provider, field("attestationObject"),
                                                      field("clientDataJSON"), challenge,
                                                      local_rp_id, args.get("label")),
               "reading the new passkey");
    write_file(out,
               unwrap(protocol::encode_presence_credential(credential), "encoding the credential"),
               false);
    if (args.json()) {
        Json result = presence_credential_json(credential);
        result["file"] = out.string();
        print_json(result);
        return exit_ok;
    }
    std::println("passkey enrolled: {} key, credential {}", crypto::name(credential.key.algorithm),
                 to_base64url(credential.credential_id).substr(0, 16));
    std::println("Give {} to your administrator, who registers it with:", out.string());
    std::println("  cexchain actor set-presence <your actor id> --credential {} --as <their key>",
                 out.string());
    return exit_ok;
}

int cmd_actor_set_presence(const Args& args) {
    Session session(args.ledger());
    const protocol::Id actor = session.actor_id(args.positional().front());
    const protocol::ActorState& state = *session.state().actor(actor);
    protocol::ActorSetPresenceBody body{actor, {}};
    if (args.has("clear")) {
        if (args.has("credential") || args.has("add")) {
            throw UsageError{"--clear removes every passkey; it takes no --credential or --add"};
        }
    } else {
        if (!args.has("credential")) {
            throw UsageError{"give --credential FILE (repeatable), or --clear"};
        }
        if (args.has("add")) {
            body.credentials = state.presence;
        }
        for (const std::string& file : args.all("credential")) {
            body.credentials.push_back(
                unwrap(protocol::decode_presence_credential(read_file(file)), "reading " + file));
        }
    }
    const protocol::Id id = session.submit(args, body);
    Json credentials = Json::array();
    for (const protocol::PresenceCredential& c : body.credentials) {
        credentials.push_back(presence_credential_json(c));
    }
    return report_submitted(args, session, id,
                            {{"actor", id_json(actor)}, {"credentials", credentials}},
                            std::format("\"{}\" now has {} passkey(s) for proof of presence",
                                        state.display_name, body.credentials.size()));
}

} // namespace cexchain::cli
