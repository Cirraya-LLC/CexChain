// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Self-service forms a console publishes for applicants, and the intake
// actor that signs what they submit: a device of the organization whose
// delegation covers exactly the published forms.

#include <print>

#include <cexchain/console/console.hpp>
#include <cexchain/console/forms.hpp>
#include <cexchain/console/keystore.hpp>
#include <cexchain/console/setup.hpp>
#include <cexchain/core/protocol/state.hpp>
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

Json shown(const nlohmann::json& value) {
    return Json::parse(value.dump());
}

std::string secret_of(const std::string& file) {
    const Bytes bytes = read_file(file);
    std::string text(bytes.begin(), bytes.end());
    text = text.substr(0, text.find('\n'));
    if (text.size() < 8) {
        throw UsageError{"the unlock file " + file + " holds fewer than 8 characters"};
    }
    return text;
}

/// The intake actor's id, if its key is the console's and it is registered.
std::optional<protocol::Id> intake_actor(const app::Session& session,
                                         const crypto::PublicKey& key) {
    const auto kid = protocol::key_id(session.provider(), session.state().hash(), key);
    const protocol::ActorState* actor = kid ? session.state().actor_by_kid(*kid) : nullptr;
    return actor == nullptr ? std::nullopt : std::optional<protocol::Id>(actor->id);
}

} // namespace

int cmd_console_form_add(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::string file = args.positional().front();
    const Bytes bytes = read_file(file);
    const auto sheet = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false);
    console::SelfServiceForm form;
    try {
        form = console::parse_form(sheet);
    } catch (const std::invalid_argument& e) {
        throw UsageError{file + ": " + e.what()};
    }
    const std::filesystem::path state = console::state_directory(dir);
    std::filesystem::create_directories(state);
    const auto lock = unwrap(ledger::DirectoryLock::acquire(state), "locking the console");
    auto forms = console::load_forms(state);
    const auto same = std::ranges::find(forms, form.name, &console::SelfServiceForm::name);
    if (same != forms.end() && !args.has("replace")) {
        throw CommandError{"a form named " + form.name + " exists (--replace replaces it)"};
    }
    {
        Session session(args);
        const protocol::ContractState* contract = session.state().contract(form.contract);
        if (contract == nullptr || contract->retired) {
            throw CommandError{"no deployed contract " + short_id(form.contract) +
                               " on this ledger, or it is retired"};
        }
        for (const std::string& f : [&] {
                 auto all = form.steps;
                 all.push_back(form.create);
                 return all;
             }()) {
            if (!contract->interface.contains(f)) {
                throw CommandError{"the contract has no call " + f};
            }
        }
        if (contract->interface.at(form.create) != protocol::FunctionKind::create) {
            throw CommandError{form.create + " does not create things: name the creating call"};
        }
    }
    if (same != forms.end()) {
        *same = form;
    } else {
        forms.push_back(form);
    }
    console::save_forms(state, forms);
    if (args.json()) {
        print_json(shown(console::form_json(form)));
        return exit_ok;
    }
    std::println("{} form {}: applicants open /console/#/apply/{}\n"
                 "give the intake actor its delegation for it: console intake grant",
                 same != forms.end() ? "replaced" : "added", form.name, form.name);
    return exit_ok;
}

int cmd_console_form_list(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const auto forms = console::load_forms(console::state_directory(dir));
    if (args.json()) {
        Json list = Json::array();
        for (const auto& f : forms) {
            list.push_back(shown(console::form_json(f)));
        }
        print_json(list);
        return exit_ok;
    }
    if (forms.empty()) {
        std::println("no self-service forms (console form add FILE)");
    }
    for (const auto& f : forms) {
        std::println("{:<20} {}  (rules {}, {})", f.name, f.title, short_id(f.contract), f.create);
    }
    return exit_ok;
}

int cmd_console_form_show(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const auto forms = console::load_forms(console::state_directory(dir));
    const auto f =
        std::ranges::find(forms, args.positional().front(), &console::SelfServiceForm::name);
    if (f == forms.end()) {
        throw CommandError{"no form named " + args.positional().front() + " (console form list)"};
    }
    if (args.json()) {
        print_json(shown(console::form_json(*f)));
        return exit_ok;
    }
    std::println("name:      {}", f->name);
    std::println("title:     {}", f->title);
    std::println("rules:     {}", hex_id(f->contract));
    std::println("creates:   {}", f->create);
    std::string steps;
    for (const auto& s : f->steps) {
        steps += (steps.empty() ? "" : ", ") + s;
    }
    std::println("steps:     {}", steps.empty() ? "none" : steps);
    if (f->kind) {
        std::println("document:  {} (its id in {})", *f->kind, *f->record_field);
    }
    std::string providers;
    for (const auto& p : f->providers) {
        providers += (providers.empty() ? "" : ", ") + p;
    }
    std::println("sign in:   {}",
                 providers.empty() ? "any provider the console trusts" : providers);
    std::println("limit:     {} submissions an hour each", f->per_hour);
    return exit_ok;
}

int cmd_console_form_remove(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::filesystem::path state = console::state_directory(dir);
    const auto lock = unwrap(ledger::DirectoryLock::acquire(state), "locking the console");
    auto forms = console::load_forms(state);
    const std::string name = args.positional().front();
    if (std::erase_if(forms, [&](const auto& f) { return f.name == name; }) == 0) {
        throw CommandError{"no form named " + name + " (console form list)"};
    }
    console::save_forms(state, forms);
    if (args.json()) {
        print_json({{"removed", name}});
        return exit_ok;
    }
    std::println("removed form {}: its things stay; narrow the intake actor with console intake "
                 "grant",
                 name);
    return exit_ok;
}

int cmd_console_form_link(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const auto forms = console::load_forms(console::state_directory(dir));
    const std::string name = args.positional().front();
    if (std::ranges::find(forms, name, &console::SelfServiceForm::name) == forms.end()) {
        throw CommandError{"no form named " + name + " (console form list)"};
    }
    std::string base = args.get("url").value_or("http://localhost:7470");
    while (base.ends_with('/')) {
        base.pop_back();
    }
    const std::string link = base + "/console/#/apply/" + name;
    if (args.json()) {
        print_json({{"form", name}, {"link", link}});
        return exit_ok;
    }
    std::println("{}", link);
    return exit_ok;
}

int cmd_console_intake_grant(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::filesystem::path state = console::state_directory(dir);
    const auto forms = console::load_forms(state);
    if (forms.empty()) {
        throw CommandError{"publish a form first (console form add FILE)"};
    }
    console::KeyStore store(state);
    const auto file = args.get("unlock-file");
    if (!file) {
        throw UsageError{
            "the organization grants the delegation: --unlock-file FILE opens its key"};
    }
    if (!store.unlock({console::SlotKind::passphrase, {}}, secret_of(*file))) {
        throw UsageError{"--unlock-file does not unlock the console's keys"};
    }
    const crypto::openssl::KeyPair root = store.open(console::root_key_name);
    bool made_key = false;
    std::optional<crypto::openssl::KeyPair> intake;
    try {
        intake.emplace(store.open(console::intake_key_name));
    } catch (const std::exception&) {
        intake.emplace(unwrap(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519),
                              "making the intake key"));
        store.seal(console::intake_key_name, *intake);
        made_key = true;
    }
    app::Session session(app::Location{dir});
    std::optional<protocol::Id> actor = intake_actor(session, intake->public_key());
    if (!actor) {
        actor = session.submit(root,
                               protocol::ActorRegisterBody{
                                   protocol::ActorKind::device, std::string(console::intake_name),
                                   intake->public_key(), std::nullopt, std::nullopt},
                               std::nullopt);
    }
    // One delegation at a time: the old ones end, the new covers every form.
    std::vector<protocol::Id> old;
    for (const auto& [key, d] : session.state().delegations()) {
        if (protocol::Id(d.grantee) == *actor && !d.revoked) {
            old.push_back(protocol::Id(d.id));
        }
    }
    const protocol::Timestamp now =
        static_cast<protocol::Timestamp>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
    const protocol::Scope scope = console::intake_scope(forms, now + 366ULL * 86'400'000ULL);
    const protocol::Id grant =
        session.submit(root, protocol::DelegationGrantBody{*actor, scope}, std::nullopt);
    for (const protocol::Id& d : old) {
        session.submit(
            root, protocol::DelegationRevokeBody{d, std::string("replaced by a new intake grant")},
            std::nullopt);
    }
    if (args.json()) {
        print_json({{"actor", hex_id(*actor)},
                    {"delegation", hex_id(grant)},
                    {"revoked", old.size()},
                    {"forms", forms.size()},
                    {"new_key", made_key}});
        return exit_ok;
    }
    std::println("the intake actor {} may act for {} form(s) until {} (delegation {}; {} older "
                 "one(s) revoked)",
                 short_id(*actor), forms.size(), format_time(*scope.not_after), short_id(grant),
                 old.size());
    return exit_ok;
}

int cmd_console_intake_show(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::filesystem::path state = console::state_directory(dir);
    console::KeyStore store(state);
    const auto keys = store.keys();
    const auto sealed = std::ranges::find(keys, std::string(console::intake_key_name),
                                          &console::SealedKeyInfo::name);
    if (sealed == keys.end()) {
        throw CommandError{"this console has no intake actor yet (console intake grant)"};
    }
    app::Session session(app::Location{dir});
    const auto actor = intake_actor(session, sealed->public_key);
    Json delegations = Json::array();
    if (actor) {
        for (const auto& [key, d] : session.state().delegations()) {
            if (protocol::Id(d.grantee) == *actor && !d.revoked) {
                delegations.push_back(hex_id(d.id));
            }
        }
    }
    if (args.json()) {
        print_json(
            {{"actor", actor ? Json(hex_id(*actor)) : Json()}, {"delegations", delegations}});
        return exit_ok;
    }
    std::println("intake actor: {}",
                 actor ? hex_id(*actor) : "not registered (console intake grant)");
    std::println("delegations:  {}", delegations.size());
    return exit_ok;
}

} // namespace cexchain::cli
