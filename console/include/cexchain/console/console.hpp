// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/error.hpp>
#include <cexchain/node/http.hpp>

/// The web console's server side: the page's files, compiled into the
/// binary; the headers every answer carries; and the checks every request
/// passes before anything else (its Host and its Origin). The node serves it
/// beside its API, through `node::ApiOptions::console`.
namespace cexchain::console {

namespace http = node::http;

/// The Content-Security-Policy of every console answer: the page's own
/// scripts, styles, and WebAssembly, nothing inline, nothing from elsewhere.
inline constexpr std::string_view content_security_policy =
    "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; "
    "img-src 'self' blob: data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'none'";

/// An origin the console answers for: "http://localhost:7470",
/// "https://ledger.example.com". Lower case, no path, no default port.
struct Origin {
    std::string scheme;
    std::string host;
    /// 0 for the scheme's default port.
    unsigned port = 0;

    /// "scheme://host[:port]", as browsers send it in an Origin header.
    [[nodiscard]] std::string text() const;
    /// "host[:port]", as a Host header names it.
    [[nodiscard]] std::string authority() const;
};

/// Parses a public URL ("https://ledger.example.com", with no path but "/")
/// into its origin. Errc::invalid_argument otherwise.
[[nodiscard]] Result<Origin> parse_origin(std::string_view url);

/// The origins of a console on this computer's loopback addresses at `port`:
/// localhost, 127.0.0.1, and [::1], over http.
[[nodiscard]] std::vector<Origin> loopback_origins(unsigned port);

class Console {
public:
    Console() = default;

    /// The origins it answers for. Until they are set (once the server knows
    /// its port), every request is refused.
    void set_origins(std::vector<Origin> origins);

    /// Answers a request whose path is /console or under /console/.
    [[nodiscard]] http::Response handle(const http::Request& request) const;

private:
    mutable std::mutex mutex_;
    std::vector<Origin> origins_;
};

} // namespace cexchain::console
