// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "webauthn.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <netinet/in.h>
#include <optional>
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
  await fetch(location.pathname + "/result", { method: "POST", body: JSON.stringify(body),
    headers: { "Content-Type": "application/json", "X-CexChain-Secret": req.secret } });
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

using Clock = std::chrono::steady_clock;

int remaining_ms(Clock::time_point deadline) {
    const auto left =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    return left <= 0 ? 0 : static_cast<int>(left);
}

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
    /// Header names in lowercase.
    std::map<std::string, std::string> headers;
    std::string body;
};

std::string lowercase(std::string text) {
    for (char& c : text) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return text;
}

/// Reads one HTTP/1.1 request, or nothing if it is malformed, too large, or
/// not complete by `deadline`.
std::optional<HttpRequest> read_request(int fd, Clock::time_point deadline) {
    std::string data;
    std::array<char, 4096> buffer{};
    std::size_t header_end = std::string::npos;
    std::size_t content_length = 0;
    while (header_end == std::string::npos || data.size() < header_end + 4 + content_length) {
        const int left = remaining_ms(deadline);
        if (data.size() > max_request || left == 0 || !wait_readable(fd, left)) {
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
                const std::string headers = lowercase(data.substr(0, header_end));
                if (const auto at = headers.find("\r\ncontent-length:"); at != std::string::npos) {
                    content_length = std::strtoul(headers.c_str() + at + 17, nullptr, 10);
                    if (content_length > max_request) {
                        return std::nullopt;
                    }
                }
            }
        }
    }
    HttpRequest request;
    std::size_t line_end = data.find("\r\n");
    const std::string line = data.substr(0, line_end);
    const std::size_t first = line.find(' ');
    const std::size_t second = line.find(' ', first + 1);
    if (first == std::string::npos || second == std::string::npos) {
        return std::nullopt;
    }
    request.method = line.substr(0, first);
    request.path = line.substr(first + 1, second - first - 1);
    while (line_end < header_end) {
        const std::size_t next = data.find("\r\n", line_end + 2);
        const std::string field = data.substr(line_end + 2, next - line_end - 2);
        if (const std::size_t colon = field.find(':'); colon != std::string::npos) {
            std::string value = field.substr(colon + 1);
            value.erase(0, value.find_first_not_of(' '));
            request.headers[lowercase(field.substr(0, colon))] = value;
        }
        line_end = next;
    }
    request.body = data.substr(header_end + 4, content_length);
    return request;
}

std::string header(const HttpRequest& request, const std::string& name) {
    const auto it = request.headers.find(name);
    return it == request.headers.end() ? std::string() : it->second;
}

/// A private directory with a page that redirects to the ceremony, so the
/// address, with its token, never appears in another process's arguments.
class RedirectFile {
public:
    explicit RedirectFile(const std::string& url) {
        const char* base = std::getenv("TMPDIR");
        std::string pattern =
            std::string(base != nullptr && *base != '\0' ? base : "/tmp") + "/cexchain-XXXXXX";
        if (::mkdtemp(pattern.data()) == nullptr) {
            return;
        }
        dir_ = pattern;
        path_ = dir_ + "/passkey.html";
        const std::string page =
            "<!doctype html><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0;url=" +
            url + "\"><title>CexChain</title><a href=\"" + url + "\">Continue</a>";
        write_file(path_, as_bytes(page), true);
    }
    RedirectFile(const RedirectFile&) = delete;
    RedirectFile& operator=(const RedirectFile&) = delete;
    ~RedirectFile() {
        if (!dir_.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(dir_, ignored);
        }
    }
    [[nodiscard]] const std::string& path() const { return path_; }

private:
    std::string dir_;
    std::string path_;
};

void open_in_browser(const std::string& target) {
#ifdef __APPLE__
    const char* opener = "open";
#else
    const char* opener = "xdg-open";
#endif
    std::array<char*, 3> argv{const_cast<char*>(opener), const_cast<char*>(target.c_str()),
                              nullptr};
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
    std::array<std::uint8_t, 16> secret_bytes{};
    unwrap(crypto::openssl::random_bytes(token_bytes), "generating a token");
    unwrap(crypto::openssl::random_bytes(secret_bytes), "generating a secret");
    const std::string token = "/" + to_hex(token_bytes);
    const std::string secret = to_hex(secret_bytes);
    const std::string host = std::format("localhost:{}", ntohs(address.sin_port));
    const std::string url = "http://" + host + token;

    // The page is served once, carrying a secret that the result must echo,
    // from the page's own origin. "<" is escaped so the embedded data can
    // never close the script element.
    nlohmann::json embedded = request;
    embedded["secret"] = secret;
    std::string safe;
    for (const char c : embedded.dump()) {
        safe += c == '<' ? std::string("\\u003c") : std::string(1, c);
    }
    std::string page(page_template);
    page.replace(page.find("/*REQUEST*/"), std::string_view("/*REQUEST*/").size(), safe);

    std::println(stderr, "Confirm with your passkey in the browser: {}", url);
    const char* no_browser = std::getenv("CEXCHAIN_NO_BROWSER");
    std::optional<RedirectFile> redirect;
    if (open_browser && (no_browser == nullptr || *no_browser == '\0')) {
        redirect.emplace(url);
        if (!redirect->path().empty()) {
            open_in_browser(redirect->path());
        }
    }

    const auto deadline = Clock::now() + std::chrono::milliseconds(ceremony_timeout_ms);
    bool served = false;
    while (true) {
        const int left = remaining_ms(deadline);
        if (left == 0 || !wait_readable(listener.fd(), left)) {
            throw CommandError{"no passkey response within three minutes"};
        }
        Socket client(::accept(listener.fd(), nullptr, nullptr));
        if (client.fd() < 0) {
            continue;
        }
        const auto http = read_request(
            client.fd(),
            std::min(deadline, Clock::now() + std::chrono::milliseconds(read_timeout_ms)));
        if (!http) {
            continue;
        }
        if (header(*http, "host") != host) {
            respond(client.fd(), "421 Misdirected Request", "text/plain", "wrong host");
            continue;
        }
        if (http->method == "GET" && http->path == token) {
            if (served) {
                respond(client.fd(), "410 Gone", "text/plain",
                        "This page was already opened once. Run the command again.");
                continue;
            }
            served = true;
            respond(client.fd(), "200 OK", "text/html; charset=utf-8", page);
            continue;
        }
        if (http->method == "POST" && http->path == token + "/result") {
            if (header(*http, "origin") != "http://" + host ||
                header(*http, "x-cexchain-secret") != secret) {
                respond(client.fd(), "403 Forbidden", "text/plain", "forbidden");
                continue;
            }
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
