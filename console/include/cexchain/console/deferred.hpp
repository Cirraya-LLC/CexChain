// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include <cexchain/console/console.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/server.hpp>

/// What a person's console serves: the console at once, and the ledger's API
/// once it can be served, which is when the first run has made the ledger,
/// or when the console has unlocked the sealed log key that the API signs
/// checkpoints with. Until then it answers the console only (sign-in, setup,
/// unlocking), and the API's routes say why they wait.
namespace cexchain::console {

class DeferredApi final : public node::Application {
public:
    /// Opens the API: called once the console is set up or unlocked; fails
    /// (by throwing) if the ledger cannot be served.
    using Open = std::function<std::unique_ptr<node::LedgerApi>()>;

    DeferredApi(std::shared_ptr<Console> console, Open open);

    /// Opens the API now, if not open yet, and gives the console its ledger
    /// and its submitter. True once it is open.
    bool open_now();
    [[nodiscard]] bool is_open() const;
    /// The API, once open (nullptr before).
    [[nodiscard]] node::LedgerApi* api() const;

    void handle(node::http::Request request, std::string peer, Respond respond) override;
    void tick() override;
    void stopping() override;
    void stop() override;

private:
    std::shared_ptr<Console> console_;
    Open open_;
    mutable std::mutex mutex_;
    std::unique_ptr<node::LedgerApi> api_;
};

} // namespace cexchain::console
