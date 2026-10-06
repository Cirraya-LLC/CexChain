// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "webauthn.hpp"

#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <netinet/in.h>
#include <poll.h>
#include <print>
#include <spawn.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include <cexchain/crypto/openssl.hpp>

#include "args.hpp"
#include "support.hpp"

extern char** environ;

namespace cexchain::cli {

namespace {

constexpr std::size_t max_request = 64 * 1024;
constexpr int ceremony_timeout_ms = 180'000;
constexpr int read_timeout_ms = 10'000;

constexpr std::string_view page_template = R"PAGE(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CexChain: confirm with your passkey</title>
<style>
:root { --bg: #f6f7f9; --card: #fff; --text: #16191d; --muted: #5d6670; --line: #e3e6ea; --accent: #2456d6; --ok: #137a3a; --bad: #b3261e; }
@media (prefers-color-scheme: dark) { :root { --bg: #0f1114; --card: #171a1f; --text: #e8eaed; --muted: #9aa3ad; --line: #2a2f36; --accent: #7aa2ff; --ok: #5fd08a; --bad: #ff8a80; } }
body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, "PingFang SC", sans-serif; }
main { max-width: 560px; margin: 64px auto; padding: 28px; background: var(--card); border: 1px solid var(--line); border-radius: 12px; }
h1 { font-size: 19px; margin: 0 0 12px; }
#summary { padding: 12px 14px; border-left: 3px solid var(--accent); background: var(--bg); border-radius: 4px; white-space: pre-wrap; }
#status { color: var(--muted); }
#status.ok { color: var(--ok); } #status.bad { color: var(--bad); }
button { font: inherit; padding: 8px 16px; border-radius: 8px; border: 1px solid var(--line); background: var(--accent); color: #fff; cursor: pointer; margin-right: 8px; }
button.secondary { background: none; color: var(--text); }
</style>
</head>
<body>
<main>
  <h1 id="title"></h1>
  <p id="summary"></p>
  <p id="status">Waiting for your passkey&hellip;</p>
  <p id="actions" hidden><button id="retry">Use passkey</button><button id="cancel" class="secondary">Cancel</button></p>
</main>
<script type="application/json" id="request">/*REQUEST*/</script>
<script>
"use strict";
const req = JSON.parse(document.getElementById("request").textContent);
document.getElementById("title").textContent = req.title;
document.getElementById("summary").textContent = req.summary;
const enc = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const dec = (text) => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const status = (text, kind) => { const s = document.getElementById("status"); s.textContent = text; s.className = kind || ""; };
async function post(body) {
  await fetch(location.pathname + "/result", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}
async function run() {
  document.getElementById("actions").hidden = true;
  status("Waiting for your passkey…");
  try {
    let result;
    if (req.mode === "create") {
      const credential = await navigator.credentials.create({ publicKey: {
        rp: { id: req.rpId, name: "CexChain" },
        user: { id: dec(req.userId), name: req.userName, displayName: req.userName },
        challenge: dec(req.challenge),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }],
        authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
        attestation: "none", timeout: 120000 } });
      result = { id: enc(credential.rawId), attestationObject: enc(credential.response.attestationObject),
                 clientDataJSON: enc(credential.response.clientDataJSON) };
    } else {
      const credential = await navigator.credentials.get({ publicKey: {
        rpId: req.rpId, challenge: dec(req.challenge),
        allowCredentials: req.allow.map((id) => ({ type: "public-key", id: dec(id) })),
        userVerification: "required", timeout: 120000 } });
      result = { id: enc(credential.rawId), authenticatorData: enc(credential.response.authenticatorData),
                 clientDataJSON: enc(credential.response.clientDataJSON), signature: enc(credential.response.signature) };
    }
    await post(result);
    status("Confirmed. You can close this tab and return to the terminal.", "ok");
  } catch (e) {
    status("Not confirmed (" + e.name + "). Try again, or cancel.", "bad");
    document.getElementById("actions").hidden = false;
  }
}
document.getElementById("retry").addEventListener("click", run);
document.getElementById("cancel").addEventListener("click", async () => {
  await post({ cancelled: true });
  status("Cancelled. You can close this tab.", "bad");
  document.getElementById("actions").hidden = true;
});
run();
</script>
</body>
</html>
)PAGE";

class Socket {
public:
    explicit Socket(int fd) : fd_(fd) {}
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    ~Socket() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }
    [[nodiscard]] int fd() const { return fd_; }

private:
    int fd_;
};

bool wait_readable(int fd, int timeout_ms) {
    pollfd p{fd, POLLIN, 0};
    return ::poll(&p, 1, timeout_ms) == 1;
}

void send_all(int fd, std::string_view data) {
    while (!data.empty()) {
        const ssize_t n = ::send(fd, data.data(), data.size(), 0);
        if (n <= 0) {
            return;
        }
        data.remove_prefix(static_cast<std::size_t>(n));
    }
}

void respond(int fd, std::string_view status, std::string_view type, std::string_view body) {
    send_all(
        fd,
        std::format(
            "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n"
            "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; "
            "style-src 'unsafe-inline'; connect-src 'self'\r\n"
            "Referrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
            status, type, body.size()));
    send_all(fd, body);
}

struct HttpRequest {
    std::string method;
    std::string path;
    std::string body;
};

/// Reads one HTTP/1.1 request, or nothing if it is malformed or too slow.
std::optional<HttpRequest> read_request(int fd) {
    std::string data;
    std::array<char, 4096> buffer{};
    std::size_t header_end = std::string::npos;
    std::size_t content_length = 0;
    while (true) {
        if (header_end != std::string::npos && data.size() >= header_end + 4 + content_length) {
            break;
        }
        if (data.size() > max_request || !wait_readable(fd, read_timeout_ms)) {
            return std::nullopt;
        }
        const ssize_t n = ::recv(fd, buffer.data(), buffer.size(), 0);
        if (n <= 0) {
            return std::nullopt;
        }
        data.append(buffer.data(), static_cast<std::size_t>(n));
        if (header_end == std::string::npos) {
            header_end = data.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                std::string headers = data.substr(0, header_end);
                for (char& c : headers) {
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                }
                if (const auto at = headers.find("\r\ncontent-length:"); at != std::string::npos) {
                    content_length = std::strtoul(headers.c_str() + at + 17, nullptr, 10);
                    if (content_length > max_request) {
                        return std::nullopt;
                    }
                }
            }
        }
    }
    const std::size_t line_end = data.find("\r\n");
    const std::string line = data.substr(0, line_end);
    const std::size_t first = line.find(' ');
    const std::size_t second = line.find(' ', first + 1);
    if (first == std::string::npos || second == std::string::npos) {
        return std::nullopt;
    }
    return HttpRequest{line.substr(0, first), line.substr(first + 1, second - first - 1),
                       data.substr(header_end + 4, content_length)};
}

void open_in_browser(const std::string& url) {
#ifdef __APPLE__
    const char* opener = "open";
#else
    const char* opener = "xdg-open";
#endif
    std::array<char*, 3> argv{const_cast<char*>(opener), const_cast<char*>(url.c_str()), nullptr};
    pid_t pid = 0;
    static_cast<void>(::posix_spawnp(&pid, opener, nullptr, nullptr, argv.data(), environ));
}

} // namespace

nlohmann::json run_webauthn_ceremony(const nlohmann::json& request, bool open_browser) {
    Socket listener(::socket(AF_INET, SOCK_STREAM, 0));
    if (listener.fd() < 0) {
        throw CommandError{"cannot open a local socket for the passkey page"};
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    socklen_t length = sizeof address;
    if (::bind(listener.fd(), reinterpret_cast<sockaddr*>(&address), sizeof address) != 0 ||
        ::listen(listener.fd(), 8) != 0 ||
        ::getsockname(listener.fd(), reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        throw CommandError{"cannot listen on localhost for the passkey page"};
    }
    std::array<std::uint8_t, 16> token_bytes{};
    unwrap(crypto::openssl::random_bytes(token_bytes), "generating a token");
    const std::string token = "/" + to_hex(token_bytes);
    const std::string url = std::format("http://localhost:{}{}", ntohs(address.sin_port), token);

    // The request is embedded in the page as JSON; "<" is escaped so the data
    // can never close the script element.
    std::string embedded = request.dump();
    std::string safe;
    for (const char c : embedded) {
        safe += c == '<' ? std::string("\\u003c") : std::string(1, c);
    }
    std::string page(page_template);
    page.replace(page.find("/*REQUEST*/"), std::string_view("/*REQUEST*/").size(), safe);

    std::println(stderr, "Confirm with your passkey in the browser: {}", url);
    const char* no_browser = std::getenv("CEXCHAIN_NO_BROWSER");
    if (open_browser && (no_browser == nullptr || *no_browser == '\0')) {
        open_in_browser(url);
    }

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(ceremony_timeout_ms);
    while (true) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0 || !wait_readable(listener.fd(), static_cast<int>(left.count()))) {
            throw CommandError{"no passkey response within three minutes"};
        }
        Socket client(::accept(listener.fd(), nullptr, nullptr));
        if (client.fd() < 0) {
            continue;
        }
        const auto http = read_request(client.fd());
        if (!http) {
            continue;
        }
        if (http->method == "GET" && http->path == token) {
            respond(client.fd(), "200 OK", "text/html; charset=utf-8", page);
            continue;
        }
        if (http->method == "POST" && http->path == token + "/result") {
            auto result = nlohmann::json::parse(http->body, nullptr, false);
            if (result.is_discarded() || !result.is_object()) {
                respond(client.fd(), "400 Bad Request", "text/plain", "bad request");
                continue;
            }
            respond(client.fd(), "200 OK", "text/plain", "ok");
            if (result.contains("cancelled")) {
                throw CommandError{"cancelled in the browser"};
            }
            return result;
        }
        respond(client.fd(), "404 Not Found", "text/plain", "not found");
    }
}

} // namespace cexchain::cli
