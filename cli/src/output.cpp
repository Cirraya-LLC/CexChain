// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "output.hpp"

#include <print>

namespace cexchain::cli {

void print_json(const Json& value) {
    std::println("{}", value.dump(2));
}

int report_submitted(const Args& args, const app::Session& session, const protocol::Id& statement,
                     const Json& extra, const std::string& text) {
    if (args.json()) {
        Json out{{"statement_id", id_json(statement)},
                 {"index", session.state().statement_index(statement).value_or(0)}};
        for (const auto& [key, value] : extra.items()) {
            out[key] = value;
        }
        print_json(out);
    } else {
        std::println("{}", text);
    }
    return 0;
}

} // namespace cexchain::cli
