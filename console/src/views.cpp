// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The console's first views, read from the ledger the node serves under its
// readers' lock. Lists are hints: a thing's page fetches the thing's
// evidence from /v1 and verifies it in the browser.

#include <algorithm>
#include <cstddef>
#include <string>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/app/views.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/core/protocol/state.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

/// At most this many of each kind in a list, newest first.
constexpr std::size_t list_limit = 500;

nlohmann::json actor_name(const protocol::LedgerState& state, const protocol::Id& id) {
    const protocol::ActorState* actor = state.actor(id);
    return {{"id", app::id_json(id)},
            {"name", actor != nullptr ? nlohmann::json(actor->display_name) : nlohmann::json()}};
}

} // namespace

http::Response Console::home_route(const Signed& who) const {
    if (ledger_ == nullptr) {
        return error(503, "unavailable", "the console has no ledger yet");
    }
    nlohmann::json out;
    ledger_->read_state([&](const protocol::LedgerState& state) {
        std::size_t open_requests = 0;
        for (const auto& [key, request] : state.requests()) {
            open_requests += request.open() ? 1U : 0U;
        }
        out = {{"ledger",
                {{"id", app::id_json(state.ledger_id())}, {"organization", state.organization()}}},
               {"you", {{"user", who.user}, {"role", name_of(who.role)}}},
               {"counts",
                {{"actors", state.actors().size()},
                 {"records", state.records().size()},
                 {"contracts", state.contracts().size()},
                 {"instances", state.instances().size()},
                 {"open_requests", open_requests}}}};
    });
    return json(200, out);
}

http::Response Console::things_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    if (ledger_ == nullptr) {
        return error(503, "unavailable", "the console has no ledger yet");
    }
    nlohmann::json records = nlohmann::json::array();
    nlohmann::json instances = nlohmann::json::array();
    bool more = false;
    ledger_->read_state([&](const protocol::LedgerState& state) {
        std::vector<const protocol::RecordState*> rs;
        for (const auto& [key, r] : state.records()) {
            rs.push_back(&r);
        }
        std::ranges::sort(rs, std::greater{}, &protocol::RecordState::registered_at_index);
        more = rs.size() > list_limit;
        rs.resize(std::min(rs.size(), list_limit));
        for (const protocol::RecordState* r : rs) {
            records.push_back({{"id", app::id_json(r->id)},
                               {"type", r->record_type},
                               {"state", r->state},
                               {"revoked", r->revoked},
                               {"registrant", actor_name(state, r->registrant)},
                               {"endorsements", r->endorsements.size()},
                               {"index", r->registered_at_index}});
        }
        std::vector<const protocol::InstanceState*> is;
        for (const auto& [key, i] : state.instances()) {
            is.push_back(&i);
        }
        std::ranges::sort(is, std::greater{}, &protocol::InstanceState::head);
        more = more || is.size() > list_limit;
        is.resize(std::min(is.size(), list_limit));
        for (const protocol::InstanceState* i : is) {
            const protocol::ContractState* contract = state.contract(i->contract);
            instances.push_back(
                {{"id", app::id_json(i->id)},
                 {"contract", app::id_json(i->contract)},
                 {"contract_name", contract != nullptr && contract->name
                                       ? nlohmann::json(*contract->name)
                                       : nlohmann::json()},
                 {"status", i->status ? nlohmann::json(*i->status) : nlohmann::json()},
                 {"final", i->final},
                 {"open_requests", i->open_requests.size()},
                 {"head", i->head}});
        }
    });
    return json(200, {{"records", records}, {"instances", instances}, {"more", more}});
}

} // namespace cexchain::console
