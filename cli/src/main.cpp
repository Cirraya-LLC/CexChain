// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <array>
#include <cstdio>
#include <exception>
#include <print>
#include <string>
#include <string_view>

#include "args.hpp"
#include "commands.hpp"

namespace {

using cexchain::cli::Args;

struct Command {
    std::string_view first;
    std::string_view second;
    int (*run)(const Args&);
};

constexpr std::array commands{
    Command{"key", "generate", cexchain::cli::key_generate},
    Command{"key", "show", cexchain::cli::key_show},
    Command{"init", "", cexchain::cli::init},
    Command{"status", "", cexchain::cli::status},
    Command{"actor", "add", cexchain::cli::actor_add},
    Command{"actor", "list", cexchain::cli::actor_list},
    Command{"delegate", "", cexchain::cli::delegate},
    Command{"delegation", "revoke", cexchain::cli::revoke_delegation},
    Command{"issue", "", cexchain::cli::issue},
    Command{"endorse", "", cexchain::cli::endorse},
    Command{"transition", "", cexchain::cli::transition},
    Command{"revoke", "", cexchain::cli::revoke_record},
    Command{"record", "show", cexchain::cli::record_show},
    Command{"checkpoint", "", cexchain::cli::checkpoint},
    Command{"export", "", cexchain::cli::export_bundle},
    Command{"verify", "", cexchain::cli::verify},
};

constexpr std::string_view usage = R"(cexchain: verifiable records for business

Keys (PKCS #8, owner-only file permissions)
  cexchain key generate --out FILE [--alg ed25519|esp256|sm2-sm3|ml-dsa-44|ml-dsa-65|ml-dsa-87]
  cexchain key show FILE

Ledger
  cexchain init       --ledger DIR --org NAME --root-key FILE --log-key FILE [--hash sha256|sm3]
  cexchain status     --ledger DIR

Actors and delegation (--as KEY signs; the actor and a covering delegation are found automatically)
  cexchain actor add  --ledger DIR --as KEY --kind person|agent|device --name NAME --key FILE
                      [--responsible ACTOR] [--model M --model-version V --runtime R]
  cexchain actor list --ledger DIR
  cexchain delegate   --ledger DIR --as KEY --to ACTOR --allow TYPE[,TYPE...]
                      [--record-types T[,T...]] [--until DATE | --days N] [--may-delegate]
  cexchain delegation revoke --ledger DIR --as KEY --id DELEGATION [--reason TEXT]

Records
  cexchain issue      --ledger DIR --as KEY --type TYPE --field NAME=VALUE...
                      [--attach FILE...] [--meta NAME=VALUE...] [--model M]
  cexchain endorse    --ledger DIR --as KEY --record ID --role ROLE
  cexchain transition --ledger DIR --as KEY --record ID --to STATE
  cexchain revoke     --ledger DIR --as KEY --record ID [--reason TEXT]
  cexchain record show --ledger DIR --record ID

Evidence
  cexchain checkpoint --ledger DIR --log-key FILE
  cexchain export     --ledger DIR --log-key FILE --record ID --out FILE
                      [--disclose FIELD[,FIELD...]] [--with-attachments]
  cexchain verify     BUNDLE [--ledger-id ID] [--witness KEY...] [--attachment NAME=FILE...]

Statement types for --allow: actor-register, actor-rotate-key, actor-revoke, delegation-grant,
delegation-revoke, record-register, record-endorse, record-transition, record-revoke.
Built-in record types: cexchain.certificate/1, cexchain.delivery/1, cexchain.agreement/1.
IDs may be abbreviated to any unique prefix of 8 or more hex digits.
)";

} // namespace

int main(int argc, char** argv) {
    try {
        const Args args(argc, argv, {"may-delegate", "with-attachments", "help"});
        const auto& words = args.positional();
        if (words.empty() || args.has("help")) {
            std::print("{}", usage);
            return words.empty() && !args.has("help") ? 1 : 0;
        }
        for (const Command& command : commands) {
            if (words[0] != command.first) {
                continue;
            }
            if (!command.second.empty() && (words.size() < 2 || words[1] != command.second)) {
                continue;
            }
            const int code = command.run(args);
            for (const std::string& name : args.unused()) {
                std::println(stderr, "warning: option --{} was ignored", name);
            }
            return code;
        }
        std::println(stderr, "unknown command; run cexchain --help");
        return 1;
    } catch (const cexchain::cli::UsageError& e) {
        std::println(stderr, "usage error: {}", e.message);
        return 1;
    } catch (const cexchain::cli::CommandError& e) {
        std::println(stderr, "error: {}", e.message);
        return 2;
    } catch (const std::exception& e) {
        std::println(stderr, "error: {}", e.what());
        return 2;
    }
}
