// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// QR codes for links to this console (an action link, printed or shown on a
// screen for a phone to scan), drawn as SVG (certificates.hpp). Only links to
// this console's own pages: it is no QR service for anything else.

#include <string>
#include <variant>

#include <cexchain/console/certificates.hpp>
#include <cexchain/console/console.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

constexpr std::size_t max_link = 1024;

} // namespace

http::Response Console::qr_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    if (request.method != "GET") {
        return error(405, "unsupported", "method not allowed");
    }
    const auto it = request.query.find("text");
    const std::string text = it == request.query.end() ? std::string() : it->second;
    const std::string own = api_url() + "/console/";
    if (api_url().empty() || !text.starts_with(own) || text.size() > max_link) {
        return error(400, "invalid_argument", "a QR code is drawn only for a link to this console");
    }
    const std::string svg = qr_svg(text);
    http::Response r;
    r.status = 200;
    r.content_type = "image/svg+xml";
    r.body.assign(svg.begin(), svg.end());
    secure(r);
    r.headers.emplace_back("Content-Security-Policy", "sandbox; default-src 'none'");
    return r;
}

} // namespace cexchain::console
