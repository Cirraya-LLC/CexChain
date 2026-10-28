// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <string>
#include <utility>

#include <cexchain/console/deferred.hpp>

#include "responses.hpp"

namespace cexchain::console {

DeferredApi::DeferredApi(std::shared_ptr<Console> console, Open open)
    : console_(std::move(console)), open_(std::move(open)) {}

bool DeferredApi::open_now() {
    const std::lock_guard lock(mutex_);
    if (api_) {
        return true;
    }
    api_ = open_();
    node::LedgerApi* api = api_.get();
    console_->set_ledger(&api->ledger());
    console_->set_evidence([api](const protocol::Id& record, auto done) {
        api->record_evidence(record, std::move(done));
    });
    console_->set_instance_evidence([api](const protocol::Id& instance, auto done) {
        api->instance_evidence(instance, std::move(done));
    });
    console_->set_submitter([api](Bytes body, bool submission, auto respond) {
        if (submission) {
            api->submit_submission(std::move(body), std::move(respond));
        } else {
            api->submit_statement(std::move(body), std::move(respond));
        }
    });
    return true;
}

bool DeferredApi::is_open() const {
    const std::lock_guard lock(mutex_);
    return api_ != nullptr;
}

node::LedgerApi* DeferredApi::api() const {
    const std::lock_guard lock(mutex_);
    return api_.get();
}

void DeferredApi::handle(node::http::Request request, std::string peer, Respond respond) {
    if (node::LedgerApi* api = this->api()) {
        api->handle(std::move(request), std::move(peer), std::move(respond));
        return;
    }
    if (request.path == "/console" || request.path.starts_with("/console/")) {
        console_->handle(request, std::move(respond));
        return;
    }
    if (request.path == "/healthz") {
        respond(text(200, "ok: the ledger is served once the console is set up or unlocked"));
        return;
    }
    respond(
        error(503, "unavailable", "the ledger is served once its console is set up or unlocked"));
}

void DeferredApi::tick() {
    if (node::LedgerApi* api = this->api()) {
        api->tick();
    }
}

void DeferredApi::stopping() {
    if (node::LedgerApi* api = this->api()) {
        api->stopping();
    }
}

void DeferredApi::stop() {
    if (node::LedgerApi* api = this->api()) {
        api->stop();
    }
}

} // namespace cexchain::console
