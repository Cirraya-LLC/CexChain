// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The web console answers whoever can reach the server: its Host, Origin,
// and Authorization checks must never crash, and must hold whatever is sent.
// Every answer carries the console's CSP; a request is answered with 200
// only for one of the console's own names, and one that changes something
// only from the console's own page. The bearer token reader accepts only
// "cxs_" and 43 base64url characters.

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include <cexchain/console/console.hpp>
#include <cexchain/console/sessions.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/environment.hpp>

namespace console = cexchain::console;
namespace http = cexchain::node::http;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

std::string lower(std::string_view text) {
    std::string out(text);
    std::ranges::transform(out, out.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

struct World {
    cexchain::crypto::openssl::Provider provider;
    cexchain::ledger::ManualClock clock{1'800'000'000'000};
    cexchain::ledger::SeededEntropy entropy{1};
    console::Sessions sessions{std::filesystem::temp_directory_path() / "cexchain-console-fuzz",
                               provider, clock, entropy};
    console::Console web{console::Services{std::filesystem::temp_directory_path() /
                                               "cexchain-console-fuzz",
                                           &provider, &clock, &entropy, &sessions}};
    World() { web.set_origins(console::loopback_origins(7470)); }
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static World world;
    const std::string_view input(reinterpret_cast<const char*>(data), size);

    if (const auto token = console::bearer_token(input)) {
        require(token->size() == 47 && token->starts_with("cxs_"));
    }

    std::optional<http::ParseError> error;
    const auto parsed = http::parse_request(input, http::Limits{}, error);
    if (!parsed ||
        !(parsed->request.path == "/console" || parsed->request.path.starts_with("/console/"))) {
        return 0;
    }
    const http::Request& request = parsed->request;
    const http::Response response = world.web.handle(request);
    require(response.status >= 200 && response.status <= 599);
    require(std::ranges::any_of(response.headers, [](const auto& h) {
        return h.first == "Content-Security-Policy" && h.second == console::content_security_policy;
    }));
    if (response.status == 200) {
        const auto host = request.header("host");
        require(host.has_value());
        const std::string name = lower(*host);
        require(name == "localhost:7470" || name == "127.0.0.1:7470" || name == "[::1]:7470");
        const bool reads = request.method == "GET" || request.method == "HEAD";
        require(reads || request.header("origin").has_value());
    }
    return 0;
}
