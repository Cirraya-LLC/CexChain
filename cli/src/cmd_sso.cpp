// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The identity providers a console trusts for applicants' sign-in: OpenID
// Connect or CAS. Kept in the console's folder (identity.json), each OIDC
// client secret sealed to the console's node key.

#include <print>

#include <cexchain/console/console.hpp>
#include <cexchain/console/identity.hpp>
#include <cexchain/console/keystore.hpp>
#include <cexchain/ledger/storage.hpp>

#include "commands.hpp"
#include "output.hpp"

namespace cexchain::cli {

namespace {

void require_ledger_directory(const std::filesystem::path& dir) {
    if (!std::filesystem::exists(dir / "statements")) {
        throw CommandError{"no ledger at " + dir.string()};
    }
}

/// The console's JSON as the command line prints it (ordered).
Json shown(const nlohmann::json& value) {
    return Json::parse(value.dump());
}

console::IdentityProvider find_provider(const std::filesystem::path& state,
                                        const std::string& name) {
    const auto providers = console::load_providers(state);
    const auto it = std::ranges::find(providers, name, &console::IdentityProvider::name);
    if (it == providers.end()) {
        throw CommandError{"no identity provider named " + name + " (console sso list)"};
    }
    return *it;
}

} // namespace

int cmd_console_sso_add(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::filesystem::path state = console::state_directory(dir);
    console::IdentityProvider p;
    p.name = args.positional().front();
    const auto oidc = args.get("oidc");
    const auto cas = args.get("cas");
    if (oidc.has_value() == cas.has_value()) {
        throw UsageError{"give one of --oidc ISSUER and --cas URL"};
    }
    p.kind = oidc ? console::IdentityProvider::Kind::oidc : console::IdentityProvider::Kind::cas;
    p.url = oidc ? *oidc : *cas;
    while (p.url.ends_with('/')) {
        p.url.pop_back();
    }
    p.label = args.get("label").value_or(p.name);
    Bytes secret;
    if (oidc) {
        p.client_id = args.get("client-id").value_or("");
        const auto file = args.get("client-secret-file");
        if (!file) {
            throw UsageError{"an OpenID Connect provider needs --client-secret-file"};
        }
        secret = read_file(*file);
        while (!secret.empty() && (secret.back() == '\n' || secret.back() == '\r')) {
            secret.pop_back();
        }
        if (secret.empty()) {
            throw UsageError{*file + " holds no client secret"};
        }
        if (const auto scopes = args.all("scope"); !scopes.empty()) {
            p.scopes = scopes;
        }
    } else if (args.has("client-id") || args.has("client-secret-file") || args.has("scope")) {
        throw UsageError{"--client-id, --client-secret-file, and --scope are for --oidc"};
    }
    p.allow_domains = args.all("allow-domain");
    p.ca_file = args.get("ca-file");
    if (const auto problem = console::check_provider(p)) {
        throw UsageError{*problem};
    }
    std::filesystem::create_directories(state);
    const auto lock = unwrap(ledger::DirectoryLock::acquire(state), "locking the console");
    auto providers = console::load_providers(state);
    const auto same = std::ranges::find(providers, p.name, &console::IdentityProvider::name);
    if (same != providers.end() && !args.has("replace")) {
        throw CommandError{"an identity provider named " + p.name +
                           " exists (--replace replaces it)"};
    }
    console::KeyStore store(state);
    if (!store.initialized()) {
        throw CommandError{"the console is not set up yet (console run, or console setup)"};
    }
    if (!secret.empty()) {
        store.seal_secret(console::secret_name(p.name), secret);
    } else {
        store.remove_secret(console::secret_name(p.name));
    }
    if (same != providers.end()) {
        *same = p;
    } else {
        providers.push_back(p);
    }
    console::save_providers(state, providers);
    if (args.json()) {
        print_json(shown(console::provider_json(p)));
        return exit_ok;
    }
    std::println("{} identity provider {} ({}): applicants sign in at {}{}",
                 same != providers.end() ? "replaced" : "added", p.name, console::name(p.kind),
                 p.url,
                 p.kind == console::IdentityProvider::Kind::oidc
                     ? "\nregister the console's redirect URI with it: "
                       "<the console's address>/console/sso/callback"
                     : "");
    return exit_ok;
}

int cmd_console_sso_list(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const auto providers = console::load_providers(console::state_directory(dir));
    if (args.json()) {
        Json list = Json::array();
        for (const auto& p : providers) {
            list.push_back(shown(console::provider_json(p)));
        }
        print_json(list);
        return exit_ok;
    }
    if (providers.empty()) {
        std::println("no identity providers (console sso add NAME --oidc ISSUER ...)");
    }
    for (const auto& p : providers) {
        std::println("{:<20} {:<5} {}  \"{}\"", p.name, console::name(p.kind), p.url, p.label);
    }
    return exit_ok;
}

int cmd_console_sso_show(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::filesystem::path state = console::state_directory(dir);
    const auto p = find_provider(state, args.positional().front());
    Json out = shown(console::provider_json(p));
    out["secret_sealed"] = console::KeyStore(state).has_secret(console::secret_name(p.name));
    if (args.json()) {
        print_json(out);
        return exit_ok;
    }
    std::println("name:      {}", p.name);
    std::println("kind:      {}", console::name(p.kind));
    std::println("label:     {}", p.label);
    std::println("url:       {}", p.url);
    if (p.kind == console::IdentityProvider::Kind::oidc) {
        std::println("client id: {}", p.client_id);
        std::string scopes;
        for (const auto& s : p.scopes) {
            scopes += (scopes.empty() ? "" : " ") + s;
        }
        std::println("scopes:    {}", scopes);
        std::println("secret:    {}", out["secret_sealed"].get<bool>() ? "sealed in the console"
                                                                       : "none (add it again)");
    }
    std::string domains;
    for (const auto& d : p.allow_domains) {
        domains += (domains.empty() ? "" : ", ") + d;
    }
    std::println("allowed:   {}", domains.empty() ? "any account the provider vouches for"
                                                  : "accounts with a verified email at " + domains);
    if (p.ca_file) {
        std::println("CA file:   {}", *p.ca_file);
    }
    return exit_ok;
}

int cmd_console_sso_remove(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::filesystem::path state = console::state_directory(dir);
    const auto lock = unwrap(ledger::DirectoryLock::acquire(state), "locking the console");
    auto providers = console::load_providers(state);
    const std::string name = args.positional().front();
    if (std::erase_if(providers, [&](const auto& p) { return p.name == name; }) == 0) {
        throw CommandError{"no identity provider named " + name + " (console sso list)"};
    }
    console::save_providers(state, providers);
    console::KeyStore(state).remove_secret(console::secret_name(name));
    if (args.json()) {
        print_json({{"removed", name}});
        return exit_ok;
    }
    std::println("removed identity provider {}: its applicants are signed out at the next restart",
                 name);
    return exit_ok;
}

int cmd_console_sso_test(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const auto p = find_provider(console::state_directory(dir), args.positional().front());
    Json out{{"name", p.name}, {"kind", console::name(p.kind)}};
    if (p.kind == console::IdentityProvider::Kind::cas) {
        if (const auto problem = console::reach_cas(p)) {
            throw CommandError{p.name + ": " + *problem};
        }
        out["login"] = p.url + "/login";
    } else {
        auto found = console::discover(p);
        if (auto* problem = std::get_if<std::string>(&found)) {
            throw CommandError{p.name + ": " + *problem};
        }
        const auto& d = std::get<console::Discovery>(found);
        auto keys = console::fetch_keys(p, d);
        if (auto* problem = std::get_if<std::string>(&keys)) {
            throw CommandError{p.name + ": " + *problem};
        }
        const auto& k = std::get<std::vector<console::Jwk>>(keys);
        if (k.empty()) {
            throw CommandError{p.name +
                               ": the provider publishes no signing key the console can use"};
        }
        out["authorization_endpoint"] = d.authorization_endpoint;
        out["token_endpoint"] = d.token_endpoint;
        out["keys"] = k.size();
    }
    if (args.json()) {
        print_json(out);
        return exit_ok;
    }
    if (p.kind == console::IdentityProvider::Kind::cas) {
        std::println("{}: the CAS server answers at {}/login", p.name, p.url);
    } else {
        std::println("{}: discovery ok; {} signing key(s); applicants sign in at {}", p.name,
                     out["keys"].get<std::size_t>(),
                     out["authorization_endpoint"].get<std::string>());
    }
    return exit_ok;
}

} // namespace cexchain::cli
