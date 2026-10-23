// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "support.hpp"

#include <algorithm>
#include <cstdlib>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#ifdef CEXCHAIN_HAVE_PKCS11
#include <cexchain/crypto/pkcs11.hpp>
#endif

#include "registry.hpp"
#include "webauthn.hpp"

namespace cexchain::cli {

namespace {

std::string prompt_hidden(const std::string& prompt) {
    const int tty = ::open("/dev/tty", O_RDWR | O_CLOEXEC);
    if (tty < 0) {
        throw UsageError{
            "a key passphrase is needed: use --passphrase-file or set CEXCHAIN_PASSPHRASE"};
    }
    static_cast<void>(::write(tty, prompt.data(), prompt.size()));
    termios saved{};
    const bool have_termios = ::tcgetattr(tty, &saved) == 0;
    if (have_termios) {
        termios quiet = saved;
        quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        ::tcsetattr(tty, TCSAFLUSH, &quiet);
    }
    std::string line;
    char c = 0;
    while (::read(tty, &c, 1) == 1 && c != '\n') {
        line.push_back(c);
    }
    if (have_termios) {
        ::tcsetattr(tty, TCSAFLUSH, &saved);
    }
    static_cast<void>(::write(tty, "\n", 1));
    ::close(tty);
    return line;
}

/// A passkey ceremony in the one-time local page (see webauthn.hpp).
PasskeyCeremony browser_passkey(bool open_browser) {
    return [open_browser](const PasskeyRequest& request) {
        nlohmann::json allow = nlohmann::json::array();
        for (const Bytes& id : request.allow) {
            allow.push_back(to_base64url(id));
        }
        const nlohmann::json ceremony{{"mode", "get"},
                                      {"rpId", request.rp_id},
                                      {"challenge", to_base64url(request.challenge)},
                                      {"allow", allow},
                                      {"title", request.title},
                                      {"summary", request.summary}};
        const nlohmann::json response = run_webauthn_ceremony(ceremony, open_browser);
        auto field = [&](const char* name) {
            if (!response.contains(name) || !response[name].is_string()) {
                throw CommandError{"the browser's passkey response is incomplete"};
            }
            return unwrap(from_base64url(response[name].get<std::string>()),
                          "reading the passkey response");
        };
        return PasskeyAssertion{field("id"), field("authenticatorData"), field("clientDataJSON"),
                                field("signature")};
    };
}

} // namespace

std::string passphrase(const Args& args, const std::string& purpose, bool confirm,
                       std::string_view file_option, const char* env) {
    if (const auto file = args.get(file_option)) {
        const Bytes content = read_file(*file);
        std::string text(content.begin(), content.end());
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
            text.pop_back();
        }
        if (text.empty()) {
            throw UsageError{"the passphrase file " + *file + " is empty"};
        }
        return text;
    }
    if (const char* value = std::getenv(env); value != nullptr && *value != '\0') {
        return value;
    }
    std::string first = prompt_hidden("Passphrase for " + purpose + ": ");
    if (first.empty()) {
        throw UsageError{"the passphrase must not be empty"};
    }
    if (confirm && prompt_hidden("Repeat the passphrase: ") != first) {
        throw UsageError{"the passphrases do not match"};
    }
    return first;
}

crypto::openssl::KeyPair load_key(const std::filesystem::path& path, const Args& args) {
    return app::load_key(path, [&] { return passphrase(args, path.string()); });
}

#ifdef CEXCHAIN_HAVE_PKCS11
namespace {

std::string token_pin(const crypto::pkcs11::KeyUri& uri) {
    if (uri.pin_value) {
        return *uri.pin_value;
    }
    if (uri.pin_source) {
        const Bytes content = read_file(*uri.pin_source);
        std::string pin(content.begin(), content.end());
        while (!pin.empty() && (pin.back() == '\n' || pin.back() == '\r')) {
            pin.pop_back();
        }
        return pin;
    }
    if (const char* env = std::getenv("CEXCHAIN_PKCS11_PIN"); env != nullptr && *env != '\0') {
        return env;
    }
    return prompt_hidden("PIN for token " + uri.token.value_or(uri.serial.value_or("")) + ": ");
}

std::unique_ptr<crypto::Signer> token_key(Result<crypto::pkcs11::Key> key) {
    if (!key && key.error().code == Errc::verification_failed) {
        throw CommandError{"wrong PIN for the token"};
    }
    return std::make_unique<crypto::pkcs11::Key>(
        unwrap(std::move(key), "using the key on the token"));
}

} // namespace
#endif

std::unique_ptr<crypto::Signer> load_signer(const std::string& source, const Args& args) {
    if (source.starts_with("pkcs11:")) {
#ifdef CEXCHAIN_HAVE_PKCS11
        const auto uri = unwrap(crypto::pkcs11::parse_uri(source), "reading the PKCS #11 URI");
        return token_key(crypto::pkcs11::Key::open(uri, token_pin(uri), shared_provider()));
#else
        throw CommandError{
            "this build of cexchain has no PKCS #11 support (it needs p11-kit at build time)"};
#endif
    }
    return std::make_unique<crypto::openssl::KeyPair>(load_key(source, args));
}

std::unique_ptr<crypto::Signer> generate_on_token([[maybe_unused]] const std::string& source,
                                                  [[maybe_unused]] crypto::SigAlg alg) {
#ifdef CEXCHAIN_HAVE_PKCS11
    const auto uri = unwrap(crypto::pkcs11::parse_uri(source), "reading the PKCS #11 URI");
    return token_key(crypto::pkcs11::Key::generate(uri, token_pin(uri), alg, shared_provider()));
#else
    throw CommandError{
        "this build of cexchain has no PKCS #11 support (it needs p11-kit at build time)"};
#endif
}

std::optional<PresenceRequest> presence_request(const Args& args) {
    if (args.has("presence") && args.has("presence-key")) {
        throw UsageError{
            "give --presence (a passkey) or --presence-key (a hardware key), not both"};
    }
    if (const auto uri = args.get("presence-key")) {
        if (!uri->starts_with("pkcs11:")) {
            throw UsageError{"--presence-key takes a pkcs11: URI naming the hardware key"};
        }
#ifdef CEXCHAIN_HAVE_PKCS11
        // Presence means a person unlocked the key now: not a PIN written
        // into the URI, and not a key that can live outside the token.
        const auto parsed = unwrap(crypto::pkcs11::parse_uri(*uri), "reading the PKCS #11 URI");
        if (parsed.pin_value) {
            throw UsageError{"a presence key's PIN is entered, not written into its URI: remove "
                             "pin-value="};
        }
        auto key = std::make_shared<crypto::pkcs11::Key>(
            unwrap(crypto::pkcs11::Key::open(parsed, token_pin(parsed), shared_provider()),
                   "using the key on the token"));
        if (!key->hardware_bound()) {
            throw CommandError{"the token lets this key leave it (not sensitive, or extractable): "
                               "it cannot prove a person's presence"};
        }
        return PresenceRequest{std::move(key), {}};
#else
        throw CommandError{
            "this build of cexchain has no PKCS #11 support (it needs p11-kit at build time)"};
#endif
    }
    if (args.has("presence")) {
        return PresenceRequest{nullptr, browser_passkey(!args.has("no-browser"))};
    }
    return std::nullopt;
}

crypto::PublicKey public_key_of(const std::filesystem::path& path, const Args& args) {
    if (path.string().starts_with("pkcs11:")) {
        return load_signer(path.string(), args)->public_key();
    }
    if (const auto value = cbor::decode(read_file(path))) {
        if (auto key = protocol::decode_public_key(*value)) {
            return *key;
        }
    }
    return load_key(path, args).public_key();
}

std::optional<std::string> api_token(const Args& args) {
    if (const auto file = args.get("token-file")) {
        const Bytes bytes = read_file(*file);
        std::string text(bytes.begin(), bytes.end());
        while (!text.empty() &&
               (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) {
            text.pop_back();
        }
        return text;
    }
    if (const char* env = std::getenv("CEXCHAIN_TOKEN"); env != nullptr && *env != '\0') {
        return std::string(env);
    }
    return std::nullopt;
}

node::Client client_for(const std::string& url, const Args& args,
                        const std::optional<std::string>& ca_file) {
    return app::client_for(url, api_token(args), ca_file);
}

namespace {

/// The server URL if this command runs in client mode.
std::optional<std::string> server_url(const Args& args) {
    const bool takes_server = std::ranges::any_of(
        args.spec().options, [](const OptionSpec& o) { return o.name == "server"; });
    if (!takes_server) {
        return std::nullopt;
    }
    const auto flag = args.get("server");
    if (flag && args.has("ledger")) {
        throw UsageError{"--server and --ledger exclude each other: a ledger is either here or "
                         "on a server"};
    }
    if (flag) {
        return *flag;
    }
    if (args.has("ledger")) {
        return std::nullopt;
    }
    if (const char* env = std::getenv("CEXCHAIN_SERVER"); env != nullptr && *env != '\0') {
        if (const char* local = std::getenv("CEXCHAIN_LEDGER");
            local != nullptr && *local != '\0') {
            throw UsageError{"both CEXCHAIN_LEDGER and CEXCHAIN_SERVER are set: pass --ledger or "
                             "--server"};
        }
        return std::string(env);
    }
    return std::nullopt;
}

} // namespace

std::optional<std::string> server_option(const Args& args) {
    return server_url(args);
}

LogKey log_key(const Args& args) {
    return {args.has("log-key"), [&args] { return load_signer(args.need("log-key"), args); }};
}

namespace {

app::Location location_of(const Args& args) {
    if (const auto url = server_url(args)) {
        return ServerLocation{*url, args.get("ca-file"), api_token(args), args.get("ledger-id"),
                              args.get("cache")};
    }
    return args.ledger();
}

} // namespace

Session::Session(const Args& args) : app::Session(location_of(args)) {}

std::optional<protocol::Provenance> Session::provenance(const Args& args) const {
    if (!args.has("model") && !args.has("model-version") && !args.has("inputs")) {
        return std::nullopt;
    }
    protocol::Provenance provenance{args.get("model"), args.get("model-version"), std::nullopt, {}};
    if (const auto inputs = args.get("inputs")) {
        provenance.input_commitment = hash_text(provider(), state().hash(), *inputs);
    }
    return provenance;
}

protocol::Id Session::submit(const Args& args, protocol::Body body) {
    const auto signer = load_signer(args.need("as"), args);
    return submit(*signer, std::move(body), args.get("delegation"), provenance(args),
                  presence_request(args));
}

protocol::SignedCheckpoint Session::checkpoint(const Args& args) {
    return checkpoint(log_key(args));
}

protocol::EvidenceBundle Session::evidence(const Args& args, const protocol::Id& record) {
    return evidence(log_key(args), record);
}

Bytes Session::contract_evidence(const Args& args, const protocol::Id& instance) {
    return contract_evidence(log_key(args), instance);
}

Bytes Session::receipt(const Args& args, std::uint64_t index) {
    return receipt(log_key(args), index);
}

} // namespace cexchain::cli
