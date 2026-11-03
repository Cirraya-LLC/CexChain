// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/error.hpp>
#include <cexchain/node/connector.hpp>

/// First-party connectors: `webhook` and `command`, which serve any
/// request kind, and the loop every connector built here runs. The
/// `cexchain connector webhook|command` commands run them over stdin and
/// stdout, as an executor's runtime starts any connector.
namespace cexchain::node::connector {

/// What a connector does with one request. Called one request at a time.
class Performer {
public:
    virtual ~Performer() = default;
    [[nodiscard]] virtual Outcome perform(const Perform& request) = 0;
    /// The kinds it serves; empty: any.
    [[nodiscard]] virtual std::vector<std::string> kinds() const { return {}; }

protected:
    Performer() = default;
};

/// Makes a connector's performer from the runtime's hello, or says why not
/// (a configuration error, as text for the log).
using PerformerFactory =
    std::function<std::unique_ptr<Performer>(const Hello& hello, std::string& error)>;

/// Line input and output: `read` returns the next line (without its
/// newline), or nothing at end of input; `write` writes one line (with its
/// newline), false once the other side is gone.
struct LineIo {
    std::function<std::optional<std::string>()> read;
    std::function<bool(std::string_view)> write;
};

/// A connector's loop: waits for hello, answers ready (or, if `make` fails,
/// logs why and returns 2), then performs each request and writes its
/// outcome, until stop or end of input (returns 0). Lines it cannot read are
/// logged and skipped; cancels of requests it is not performing are ignored.
int serve(const LineIo& io, std::string_view name, std::string_view version,
          const PerformerFactory& make);

/// The webhook connector: POSTs each request as JSON to a URL, signed with
/// HMAC-SHA-256 under a shared secret, and maps the HTTP answer to an
/// outcome. Its config: {"url": "https://...", "secret": NAME,
/// "timeout": seconds (default 30), "ca_file": PEM file (optional)}; http://
/// only to a loopback address. See spec/connectors.md for the headers and
/// the mapping.
[[nodiscard]] std::unique_ptr<Performer> make_webhook(const Hello& hello, std::string& error);

/// The command connector: runs a program per request, without a shell,
/// with the request as one JSON line on its stdin; exit 0 is done, 75
/// (EX_TEMPFAIL) or a timeout retry, anything else failed. Its config:
/// {"program": PATH, "args": [...], "timeout": seconds (default 30),
/// "secrets": [NAME, ...] (passed in the stdin line, never in argv or the
/// environment)}.
[[nodiscard]] std::unique_ptr<Performer> make_command(const Hello& hello, std::string& error);

/// The JSON a webhook receives and a command reads: the request as the
/// runtime's perform names it (id, kind, params, params_cbor, deadline,
/// asked_at, home, contract, instance, reply, attempt), with "protocol".
[[nodiscard]] std::string request_document(const Perform& request);

/// The HMAC-SHA-256 signature a webhook carries: hex of HMAC(secret,
/// timestamp + "." + body).
[[nodiscard]] Result<std::string> webhook_signature(ByteView secret, std::string_view timestamp,
                                                    std::string_view body);

} // namespace cexchain::node::connector
