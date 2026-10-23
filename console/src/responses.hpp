// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include <cexchain/console/console.hpp>

// The console's answers, each with its security headers.
namespace cexchain::console {

/// Every console answer: no framing, no sniffing, no referrer, no caching
/// (no stale page code), and the CSP.
inline void secure(http::Response& response) {
    response.headers.emplace_back("Content-Security-Policy", std::string(content_security_policy));
    response.headers.emplace_back("X-Content-Type-Options", "nosniff");
    response.headers.emplace_back("X-Frame-Options", "DENY");
    response.headers.emplace_back("Referrer-Policy", "no-referrer");
    response.headers.emplace_back("Cross-Origin-Opener-Policy", "same-origin");
    response.headers.emplace_back("Cross-Origin-Resource-Policy", "same-origin");
    response.headers.emplace_back("Cache-Control", "no-store");
}

inline http::Response json(int status, const nlohmann::json& value) {
    http::Response response;
    response.status = status;
    response.content_type = "application/json";
    const std::string text = value.dump();
    response.body.assign(text.begin(), text.end());
    secure(response);
    return response;
}

inline http::Response error(int status, std::string_view code, std::string_view message) {
    return json(status, {{"error", {{"code", code}, {"message", message}}}});
}

inline http::Response text(int status, std::string_view message) {
    http::Response response;
    response.status = status;
    response.content_type = "text/plain; charset=utf-8";
    response.body.assign(message.begin(), message.end());
    response.body.push_back('\n');
    secure(response);
    return response;
}

} // namespace cexchain::console
