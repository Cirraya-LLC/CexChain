// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// QR codes for links to this console (an action link, printed or shown on a
// screen for a phone to scan), drawn here as SVG with the qrcodegen that the
// command line's `qr` uses. Only links to this console's own pages: it is
// no QR service for anything else.

#include <format>
#include <qrcodegen.hpp>
#include <string>
#include <variant>

#include <cexchain/console/console.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

// QR codes need a light margin of four modules (ISO/IEC 18004).
constexpr int quiet_zone = 4;
constexpr std::size_t max_link = 1024;

std::string svg_of(const qrcodegen::QrCode& qr) {
    const int size = qr.getSize() + 2 * quiet_zone;
    std::string path;
    for (int y = 0; y < qr.getSize(); ++y) {
        for (int x = 0; x < qr.getSize(); ++x) {
            if (qr.getModule(x, y)) {
                path += std::format("M{},{}h1v1h-1z", x + quiet_zone, y + quiet_zone);
            }
        }
    }
    return std::format(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" viewBox=\"0 0 {0} {0}\" "
        "stroke=\"none\" shape-rendering=\"crispEdges\"><rect width=\"100%\" height=\"100%\" "
        "fill=\"#FFFFFF\"/><path d=\"{1}\" fill=\"#000000\"/></svg>\n",
        size, path);
}

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
    const auto qr = qrcodegen::QrCode::encodeText(text.c_str(), qrcodegen::QrCode::Ecc::MEDIUM);
    const std::string svg = svg_of(qr);
    http::Response r;
    r.status = 200;
    r.content_type = "image/svg+xml";
    r.body.assign(svg.begin(), svg.end());
    secure(r);
    r.headers.emplace_back("Content-Security-Policy", "sandbox; default-src 'none'");
    return r;
}

} // namespace cexchain::console
