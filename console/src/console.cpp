// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <exception>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/console/console.hpp>
#include <cexchain/console/users.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

#if defined(__clang__)
#pragma clang diagnostic push
// Clang 23 accepts #embed in C++ as an extension of C23's.
#pragma clang diagnostic ignored "-Wc23-extensions"
#endif
constexpr unsigned char index_html[] = {
#if CEXCHAIN_CONSOLE_EMBED
#embed "../web/index.html"
#else
#include "index.html.inc"
#endif
};
constexpr unsigned char console_css[] = {
#if CEXCHAIN_CONSOLE_EMBED
#embed "../web/console.css"
#else
#include "console.css.inc"
#endif
};
constexpr unsigned char console_js[] = {
#if CEXCHAIN_CONSOLE_EMBED
#embed "../web/console.js"
#else
#include "console.js.inc"
#endif
};
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

struct File {
    std::string_view path;
    std::string_view content_type;
    std::span<const unsigned char> bytes;
};

constexpr std::array files{
    File{"/console/", "text/html; charset=utf-8", index_html},
    File{"/console/console.css", "text/css; charset=utf-8", console_css},
    File{"/console/console.js", "text/javascript; charset=utf-8", console_js},
};

std::string lower(std::string_view text) {
    std::string out(text);
    std::ranges::transform(out, out.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

unsigned default_port(std::string_view scheme) {
    return scheme == "https" ? 443 : 80;
}

/// A host as a URL or a Host header names it: a DNS name or IPv4 address
/// (letters, digits, '-', '.'), or an IPv6 address in brackets.
bool valid_host(std::string_view host) {
    if (host.empty() || host.size() > 253) {
        return false;
    }
    if (host.front() == '[') {
        return host.size() > 2 && host.back() == ']' &&
               std::ranges::all_of(host.substr(1, host.size() - 2), [](unsigned char c) {
                   return std::isxdigit(c) != 0 || c == ':' || c == '.';
               });
    }
    return std::ranges::all_of(
        host, [](unsigned char c) { return std::isalnum(c) != 0 || c == '-' || c == '.'; });
}

/// Splits "host[:port]" (lower case). Nothing if malformed.
std::optional<std::pair<std::string, unsigned>> split_authority(std::string_view authority) {
    std::string_view host = authority;
    unsigned port = 0;
    const auto colon = authority.rfind(':');
    const auto bracket = authority.rfind(']');
    if (colon != std::string_view::npos && (bracket == std::string_view::npos || colon > bracket)) {
        host = authority.substr(0, colon);
        const std::string_view digits = authority.substr(colon + 1);
        const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), port);
        if (digits.empty() || ec != std::errc{} || end != digits.data() + digits.size() ||
            port == 0 || port > 65535) {
            return std::nullopt;
        }
    }
    if (!valid_host(host)) {
        return std::nullopt;
    }
    return std::pair{std::string(host), port};
}

} // namespace

std::string Origin::authority() const {
    return port == 0 ? host : host + ":" + std::to_string(port);
}

std::string Origin::text() const {
    return scheme + "://" + authority();
}

Result<Origin> parse_origin(std::string_view url) {
    const std::string lowered = lower(url);
    std::string_view rest = lowered;
    Origin origin;
    for (const std::string_view scheme : {"https", "http"}) {
        if (rest.starts_with(scheme) && rest.substr(scheme.size()).starts_with("://")) {
            origin.scheme = std::string(scheme);
            rest.remove_prefix(scheme.size() + 3);
            break;
        }
    }
    if (origin.scheme.empty()) {
        return std::unexpected(
            Error{Errc::invalid_argument, "a URL starts with https:// or http://"});
    }
    if (rest.ends_with('/')) {
        rest.remove_suffix(1);
    }
    if (rest.find_first_of("/?#@") != std::string_view::npos) {
        return std::unexpected(
            Error{Errc::invalid_argument, "a public URL has no path, query, or user name"});
    }
    const auto split = split_authority(rest);
    if (!split) {
        return std::unexpected(
            Error{Errc::invalid_argument, "the URL's host or port is not valid"});
    }
    origin.host = split->first;
    origin.port = split->second == default_port(origin.scheme) ? 0 : split->second;
    return origin;
}

std::vector<Origin> loopback_origins(unsigned port) {
    const unsigned p = port == 80 ? 0 : port;
    return {{"http", "localhost", p}, {"http", "127.0.0.1", p}, {"http", "[::1]", p}};
}

void Console::set_origins(std::vector<Origin> origins) {
    const std::lock_guard lock(mutex_);
    origins_ = std::move(origins);
}

http::Response Console::handle(const http::Request& request) const {
    try {
        return route(request);
    } catch (const std::exception&) {
        // A damaged file of the console's, or a failed write: the request
        // fails, the server goes on.
        return error(500, "internal", "the console could not answer; see its files");
    }
}

http::Response Console::route(const http::Request& request) const {
    std::vector<Origin> origins;
    {
        const std::lock_guard lock(mutex_);
        origins = origins_;
    }
    if (origins.empty()) {
        return error(503, "unavailable", "the console is starting");
    }
    // A page on another name that resolves to this address (DNS rebinding)
    // must not reach the console: only its own names are answered.
    const auto host = request.header("host");
    if (!host) {
        return error(400, "invalid_argument", "the request names no Host");
    }
    const auto authority = split_authority(lower(*host));
    const bool known_host =
        authority && std::ranges::any_of(origins, [&](const Origin& o) {
            return authority->first == o.host &&
                   (authority->second == o.port ||
                    (o.port == 0 && authority->second == default_port(o.scheme)));
        });
    if (!known_host) {
        return error(421, "misdirected", "this console does not answer for that host name");
    }
    // Another site's page may send requests here, but browsers say whose
    // page it is; one that changes something must say it is the console's.
    const bool reads = request.method == "GET" || request.method == "HEAD";
    if (const auto origin = request.header("origin")) {
        const std::string sent = lower(*origin);
        if (!std::ranges::any_of(origins, [&](const Origin& o) { return o.text() == sent; })) {
            return error(403, "forbidden", "the request comes from another site's page");
        }
    } else if (!reads) {
        return error(403, "forbidden",
                     "a request that changes something must come from the console");
    }
    if (request.path == "/console") {
        http::Response moved = text(308, "the console is at /console/");
        moved.headers.emplace_back("Location", "/console/");
        return moved;
    }
    if (request.path == "/console/api/session") {
        return session_route(request);
    }
    using Route = http::Response (Console::*)(const http::Request&) const;
    static constexpr std::array<std::pair<std::string_view, Route>, 4> posts{{
        {"/console/api/enroll/begin", &Console::enroll_begin},
        {"/console/api/enroll/finish", &Console::enroll_finish},
        {"/console/api/sign-in/begin", &Console::sign_in_begin},
        {"/console/api/sign-in/finish", &Console::sign_in_finish},
    }};
    for (const auto& [path, route] : posts) {
        if (request.path != path) {
            continue;
        }
        if (request.method != "POST") {
            http::Response refused = error(405, "unsupported", "method not allowed");
            refused.headers.emplace_back("Allow", "POST");
            return refused;
        }
        if (!ready()) {
            return error(503, "unavailable", "this console keeps no users or sessions");
        }
        return (this->*route)(request);
    }
    if (request.path.starts_with("/console/api/")) {
        return error(404, "not_found", "no such console route");
    }
    const auto file = std::ranges::find(files, request.path, &File::path);
    if (file == files.end()) {
        return text(404, "not found");
    }
    if (!reads) {
        http::Response refused = text(405, "method not allowed");
        refused.headers.emplace_back("Allow", "GET");
        return refused;
    }
    http::Response response;
    response.content_type = std::string(file->content_type);
    response.body.assign(file->bytes.begin(), file->bytes.end());
    secure(response);
    return response;
}

/// GET: who is signed in with this session; DELETE: sign out.
bool Console::ready() const noexcept {
    return services_.sessions != nullptr && services_.provider != nullptr &&
           services_.clock != nullptr && services_.entropy != nullptr;
}

http::Response Console::session_route(const http::Request& request) const {
    if (!ready()) {
        return error(503, "unavailable", "this console keeps no sessions");
    }
    if (request.method != "GET" && request.method != "DELETE") {
        http::Response refused = error(405, "unsupported", "method not allowed");
        refused.headers.emplace_back("Allow", "GET, DELETE");
        return refused;
    }
    const auto authorization = request.header("authorization");
    const auto token = authorization ? bearer_token(*authorization) : std::nullopt;
    const auto session = token ? services_.sessions->use(*token) : std::nullopt;
    if (!session) {
        http::Response refused = error(401, "unauthorized", "sign in to the console");
        refused.headers.emplace_back("WWW-Authenticate", "Bearer");
        return refused;
    }
    if (request.method == "DELETE") {
        static_cast<void>(services_.sessions->end(*token));
        return json(200, {{"signed_out", true}});
    }
    // A user removed since signing in is signed out.
    const People people = load_people(services_.directory);
    const User* user = people.find(session->user);
    if (user == nullptr) {
        static_cast<void>(services_.sessions->end(*token));
        http::Response refused = error(401, "unauthorized", "sign in to the console");
        refused.headers.emplace_back("WWW-Authenticate", "Bearer");
        return refused;
    }
    return json(200, {{"id", session->id},
                      {"user", session->user},
                      {"role", name_of(user->role)},
                      {"created", session->created},
                      {"expires", session->expires()}});
}

} // namespace cexchain::console
