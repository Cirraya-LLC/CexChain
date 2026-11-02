// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Signing in with an organization's identity provider (OpenID Connect or
// CAS), for applicants: the flow's routes, the provider's documents and keys
// as fetched and cached, one-time codes, and applicants' sessions. Applicants
// are kept in memory only: a restart signs them out.
//
//   GET    /console/api/sso            the providers, for sign-in buttons
//   POST   /console/api/sso/begin      {provider, form?} -> {url}: go there
//   GET    /console/sso/callback       the provider sends the browser back
//                                      here; it goes on to the page with a
//                                      one-time code (#/signed-in/CODE)
//   POST   /console/api/sso/finish     {code} -> {token, applicant}
//   GET    /console/api/applicant      who the applicant's token is
//   DELETE /console/api/applicant      sign out

#include <chrono>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <variant>

#include <cexchain/console/console.hpp>
#include <cexchain/console/identity.hpp>
#include <cexchain/console/keystore.hpp>
#include <cexchain/console/sessions.hpp>
#include <cexchain/console/users.hpp>
#include <cexchain/node/client.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

constexpr protocol::Timestamp flow_lifetime = 10 * 60'000;
constexpr protocol::Timestamp code_lifetime = 60'000;
constexpr protocol::Timestamp cache_lifetime = 60 * 60'000;
constexpr std::size_t max_flows = 1024;
constexpr std::size_t max_applicants = 100'000;
constexpr std::size_t begins_a_minute = 120;
constexpr std::string_view callback_path = "/console/sso/callback";
constexpr std::string_view pseudonym_secret = "applicants";

/// A provider's endpoints and keys, fetched within the hour.
struct Cached {
    Discovery discovery;
    std::vector<Jwk> keys;
    protocol::Timestamp fetched = 0;
    protocol::Timestamp keys_fetched = 0;
};

struct Flow {
    std::string provider;
    /// Staff signing in (a console session), not an applicant.
    bool staff = false;
    std::string form;
    std::string nonce;
    std::string verifier;
    std::string redirect;
    protocol::Timestamp expires = 0;
};

struct Code {
    Applicant applicant;
    /// For staff: their user and the session's token.
    std::string staff_user;
    std::string staff_token;
    protocol::Timestamp expires = 0;
};

using Fields = std::vector<std::pair<std::string, std::string>>;

std::string form_encode(const Fields& fields) {
    std::string out;
    for (const auto& [k, v] : fields) {
        out += (out.empty() ? "" : "&") + node::http::percent_encode(k) + "=" +
               node::http::percent_encode(v);
    }
    return out;
}

std::string base64(ByteView bytes) {
    static constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    std::size_t i = 0;
    for (; i + 2 < bytes.size(); i += 3) {
        const unsigned v =
            (unsigned{bytes[i]} << 16U) | (unsigned{bytes[i + 1]} << 8U) | unsigned{bytes[i + 2]};
        out += alphabet[(v >> 18U) & 63U];
        out += alphabet[(v >> 12U) & 63U];
        out += alphabet[(v >> 6U) & 63U];
        out += alphabet[v & 63U];
    }
    if (i < bytes.size()) {
        const unsigned v = (unsigned{bytes[i]} << 16U) |
                           (i + 1 < bytes.size() ? unsigned{bytes[i + 1]} << 8U : 0U);
        out += alphabet[(v >> 18U) & 63U];
        out += alphabet[(v >> 12U) & 63U];
        out += i + 1 < bytes.size() ? alphabet[(v >> 6U) & 63U] : '=';
        out += '=';
    }
    return out;
}

struct Fetched {
    int status = 0;
    std::string body;
};

/// One request to a provider, over https (http on this computer only).
std::variant<Fetched, std::string>
fetch(const IdentityProvider& p, const std::string& url, std::string_view method = "GET",
      std::string_view body = {}, std::string_view content_type = {},
      std::vector<std::pair<std::string, std::string>> headers = {}) {
    if (!secure_url(url)) {
        return std::string("the provider's address is not https");
    }
    const bool tls = url.starts_with("https://");
    const std::string rest = url.substr(tls ? 8 : 7);
    const std::size_t slash = std::min(rest.find_first_of("/?"), rest.size());
    const std::string authority = rest.substr(0, slash);
    std::string target = rest.substr(slash);
    if (target.empty() || target.front() == '?') {
        target = "/" + target;
    }
    node::Url base;
    base.tls = tls;
    if (authority.starts_with('[')) {
        const std::size_t close = authority.find(']');
        if (close == std::string::npos) {
            return std::string("the provider's address is malformed");
        }
        base.host = authority.substr(1, close - 1);
        if (close + 1 < authority.size() && authority[close + 1] == ':') {
            base.port = static_cast<std::uint16_t>(std::stoul(authority.substr(close + 2)));
        }
    } else {
        const std::size_t colon = authority.rfind(':');
        base.host = authority.substr(0, colon);
        if (colon != std::string::npos) {
            const std::string port = authority.substr(colon + 1);
            if (port.empty() || port.size() > 5 ||
                !std::ranges::all_of(port, [](char c) { return c >= '0' && c <= '9'; }) ||
                std::stoul(port) > 65535) {
                return std::string("the provider's address is malformed");
            }
            base.port = static_cast<std::uint16_t>(std::stoul(port));
        }
    }
    if (base.port == 0) {
        base.port = tls ? 443 : 80;
    }
    node::ClientOptions options;
    if (p.ca_file) {
        options.ca_file = *p.ca_file;
    }
    options.timeout = std::chrono::seconds(10);
    options.max_body = 1024 * 1024;
    options.follow_redirects = false;
    options.headers = std::move(headers);
    options.headers.emplace_back("Accept", "application/json");
    const node::Client client(base, options);
    auto answer = client.request(method, target, as_bytes(body), content_type);
    if (!answer) {
        return std::string("the identity provider cannot be reached");
    }
    return Fetched{answer->status, std::string(answer->body.begin(), answer->body.end())};
}

std::variant<nlohmann::json, std::string> fetch_json(const IdentityProvider& p,
                                                     const std::string& url) {
    auto got = fetch(p, url);
    if (auto* problem = std::get_if<std::string>(&got)) {
        return *problem;
    }
    const auto& f = std::get<Fetched>(got);
    if (f.status != 200) {
        return std::string("the identity provider answered ") + std::to_string(f.status);
    }
    auto doc = nlohmann::json::parse(f.body, nullptr, false);
    if (doc.is_discarded()) {
        return std::string("the identity provider's answer is not JSON");
    }
    return doc;
}

std::string token_hash(const crypto::Provider& provider, std::string_view token) {
    const auto digest = provider.digest(crypto::HashAlg::sha256, as_bytes(token));
    return digest ? to_hex(digest->bytes()) : std::string();
}

} // namespace

std::variant<Discovery, std::string> discover(const IdentityProvider& p) {
    auto doc = fetch_json(p, p.url + "/.well-known/openid-configuration");
    if (auto* problem = std::get_if<std::string>(&doc)) {
        return *problem;
    }
    return parse_discovery(std::get<nlohmann::json>(doc), p.url);
}

std::variant<std::vector<Jwk>, std::string> fetch_keys(const IdentityProvider& p,
                                                       const Discovery& d) {
    auto jwks = fetch_json(p, d.jwks_uri);
    if (auto* problem = std::get_if<std::string>(&jwks)) {
        return *problem;
    }
    return parse_jwks(std::get<nlohmann::json>(jwks));
}

std::optional<std::string> reach_cas(const IdentityProvider& p) {
    auto got = fetch(p, p.url + "/login");
    if (auto* problem = std::get_if<std::string>(&got)) {
        return *problem;
    }
    const int status = std::get<Fetched>(got).status;
    if (status != 200 && status != 302 && status != 303) {
        return "the CAS server's login page answered " + std::to_string(status);
    }
    return std::nullopt;
}

struct SsoState {
    std::mutex mutex;
    std::map<std::string, Flow> flows;
    std::map<std::string, Code> codes;
    std::map<std::string, Applicant> applicants;
    std::map<std::string, Cached> cache;
    std::deque<protocol::Timestamp> begins;
};

std::shared_ptr<SsoState> make_sso_state() {
    return std::make_shared<SsoState>();
}

nlohmann::json applicant_json(const Applicant& a) {
    return {{"provider", a.provider},
            {"pseudonym", a.pseudonym},
            {"name", a.identity.name ? nlohmann::json(*a.identity.name) : nlohmann::json()},
            {"email", a.identity.email ? nlohmann::json(*a.identity.email) : nlohmann::json()},
            {"form", a.form.empty() ? nlohmann::json() : nlohmann::json(a.form)},
            {"expires", a.expires}};
}

std::optional<Applicant> Console::applicant_of(const http::Request& request) const {
    const auto auth = request.header("authorization");
    if (!auth || !auth->starts_with("Bearer cxa_") || services_.provider == nullptr) {
        return std::nullopt;
    }
    const std::string hash = token_hash(*services_.provider, auth->substr(7));
    const protocol::Timestamp now = services_.clock->now();
    const std::lock_guard lock(sso_->mutex);
    const auto it = sso_->applicants.find(hash);
    if (it == sso_->applicants.end()) {
        return std::nullopt;
    }
    if (it->second.expires <= now) {
        sso_->applicants.erase(it);
        return std::nullopt;
    }
    return it->second;
}

http::Response Console::sso_route(const http::Request& request) const {
    const std::string_view path = request.path;
    const protocol::Timestamp now = services_.clock->now();
    std::vector<IdentityProvider> providers;
    try {
        providers = load_providers(services_.directory);
    } catch (const std::exception&) {
        return error(503, "unavailable", "the console's identity providers file is damaged");
    }
    auto find = [&](std::string_view name) -> const IdentityProvider* {
        const auto it = std::ranges::find(providers, name, &IdentityProvider::name);
        return it == providers.end() ? nullptr : &*it;
    };

    if (path == "/console/api/sso") {
        nlohmann::json list = nlohmann::json::array();
        for (const IdentityProvider& p : providers) {
            list.push_back({{"name", p.name}, {"label", p.label}, {"kind", name(p.kind)}});
        }
        return json(200, {{"providers", list}});
    }

    if (path == "/console/api/applicant") {
        const auto who = applicant_of(request);
        if (!who) {
            http::Response refused = error(401, "unauthorized", "sign in with your account");
            refused.headers.emplace_back("WWW-Authenticate", "Bearer");
            return refused;
        }
        if (request.method == "DELETE") {
            const auto auth = request.header("authorization");
            const std::lock_guard lock(sso_->mutex);
            sso_->applicants.erase(token_hash(*services_.provider, auth->substr(7)));
            return json(200, {{"signed_out", true}});
        }
        return json(200, {{"applicant", applicant_json(*who)}});
    }

    if (path == "/console/api/sso/begin") {
        const auto body =
            nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
        if (!body.is_object() || !body.contains("provider") || !body["provider"].is_string()) {
            return error(400, "invalid_argument", "name the provider: {\"provider\": NAME}");
        }
        const IdentityProvider* p = find(body["provider"].get<std::string>());
        if (p == nullptr) {
            return error(404, "not_found", "this console has no such identity provider");
        }
        const std::string form = body.value("form", std::string());
        if (form.size() > 64) {
            return error(400, "invalid_argument", "a form's name is at most 64 bytes");
        }
        const auto origin = origin_of(request);
        if (!origin) {
            return error(421, "misdirected", "this console does not answer for that host name");
        }
        const std::string state = to_base64url(services_.entropy->bytes<16>());
        Flow flow{p->name,
                  body.contains("staff") && body["staff"].is_boolean() && body["staff"].get<bool>(),
                  form,
                  to_base64url(services_.entropy->bytes<16>()),
                  to_base64url(services_.entropy->bytes<32>()),
                  origin->text() + std::string(callback_path),
                  now + flow_lifetime};
        std::string url;
        if (p->kind == IdentityProvider::Kind::cas) {
            flow.redirect += "?state=" + state;
            url = p->url + "/login?service=" + node::http::percent_encode(flow.redirect);
        } else {
            Cached cached;
            {
                const std::lock_guard lock(sso_->mutex);
                if (const auto it = sso_->cache.find(p->name);
                    it != sso_->cache.end() && it->second.fetched + cache_lifetime > now) {
                    cached = it->second;
                }
            }
            if (cached.fetched == 0) {
                auto discovery = discover(*p);
                if (auto* problem = std::get_if<std::string>(&discovery)) {
                    return error(502, "unavailable", *problem);
                }
                cached.discovery = std::get<Discovery>(discovery);
                cached.fetched = now;
                const std::lock_guard lock(sso_->mutex);
                sso_->cache[p->name] = cached;
            }
            const auto challenge =
                services_.provider->digest(crypto::HashAlg::sha256, as_bytes(flow.verifier));
            if (!challenge) {
                return error(500, "internal", "hashing failed");
            }
            std::string scopes;
            for (const std::string& s : p->scopes) {
                scopes += (scopes.empty() ? "" : " ") + s;
            }
            url = cached.discovery.authorization_endpoint +
                  (cached.discovery.authorization_endpoint.find('?') == std::string::npos ? "?"
                                                                                          : "&") +
                  form_encode(Fields{{"response_type", "code"},
                                     {"client_id", p->client_id},
                                     {"redirect_uri", flow.redirect},
                                     {"scope", scopes},
                                     {"state", state},
                                     {"nonce", flow.nonce},
                                     {"code_challenge", to_base64url(challenge->bytes())},
                                     {"code_challenge_method", "S256"}});
        }
        const std::lock_guard lock(sso_->mutex);
        while (!sso_->begins.empty() && sso_->begins.front() + 60'000 <= now) {
            sso_->begins.pop_front();
        }
        if (sso_->begins.size() >= begins_a_minute) {
            return error(429, "limit_exceeded", "too many sign-ins at once: try again in a minute");
        }
        std::erase_if(sso_->flows, [&](const auto& f) { return f.second.expires <= now; });
        if (sso_->flows.size() >= max_flows) {
            return error(429, "limit_exceeded", "too many sign-ins at once: try again in a minute");
        }
        sso_->begins.push_back(now);
        sso_->flows.emplace(state, std::move(flow));
        return json(200, {{"url", url}});
    }

    if (path == callback_path) {
        // The browser comes back from the provider: on to the page, with a
        // one-time code or why not.
        auto back = [](const std::string& fragment) {
            http::Response moved = text(303, "on to the console");
            moved.headers.emplace_back("Location", "/console/#/" + fragment);
            return moved;
        };
        const auto state = request.query.find("state");
        Flow flow;
        {
            const std::lock_guard lock(sso_->mutex);
            const auto it =
                state == request.query.end() ? sso_->flows.end() : sso_->flows.find(state->second);
            if (it == sso_->flows.end() || it->second.expires <= now) {
                return back("sign-in-failed/expired");
            }
            flow = std::move(it->second);
            sso_->flows.erase(it);
        }
        const IdentityProvider* p = find(flow.provider);
        if (p == nullptr) {
            return back("sign-in-failed/provider");
        }
        if (request.query.contains("error")) {
            return back("sign-in-failed/refused");
        }
        std::variant<Identity, std::string> who = std::string("no answer");
        if (p->kind == IdentityProvider::Kind::cas) {
            const auto ticket = request.query.find("ticket");
            if (ticket == request.query.end()) {
                return back("sign-in-failed/refused");
            }
            auto got = fetch(*p, p->url + "/p3/serviceValidate?" +
                                     form_encode(Fields{{"service", flow.redirect},
                                                        {"ticket", ticket->second},
                                                        {"format", "JSON"}}));
            if (std::holds_alternative<std::string>(got)) {
                return back("sign-in-failed/unreachable");
            }
            who = parse_cas_validation(std::get<Fetched>(got).body, p->url);
        } else {
            const auto code = request.query.find("code");
            if (code == request.query.end()) {
                return back("sign-in-failed/refused");
            }
            Cached cached;
            {
                const std::lock_guard lock(sso_->mutex);
                cached = sso_->cache[p->name];
            }
            if (cached.fetched == 0) {
                return back("sign-in-failed/expired");
            }
            std::string secret;
            try {
                const Bytes s = services_.keys->open_secret(secret_name(p->name));
                secret.assign(s.begin(), s.end());
            } catch (const std::exception&) {
                return back("sign-in-failed/locked");
            }
            const std::string basic = base64(as_bytes(node::http::percent_encode(p->client_id) +
                                                      ":" + node::http::percent_encode(secret)));
            auto got =
                fetch(*p, cached.discovery.token_endpoint, "POST",
                      form_encode(Fields{{"grant_type", "authorization_code"},
                                         {"code", code->second},
                                         {"redirect_uri", flow.redirect},
                                         {"code_verifier", flow.verifier},
                                         {"client_id", p->client_id}}),
                      "application/x-www-form-urlencoded", {{"Authorization", "Basic " + basic}});
            if (std::holds_alternative<std::string>(got) || std::get<Fetched>(got).status != 200) {
                return back("sign-in-failed/refused");
            }
            const auto tokens = nlohmann::json::parse(std::get<Fetched>(got).body, nullptr, false);
            if (!tokens.is_object() || !tokens.contains("id_token") ||
                !tokens["id_token"].is_string()) {
                return back("sign-in-failed/refused");
            }
            const std::string id_token = tokens["id_token"].get<std::string>();
            const IdTokenCheck check{p->url, p->client_id, flow.nonce, now};
            // The provider's keys: cached, fetched again for a key it has
            // not seen (keys roll over), at most once a minute.
            for (int attempt = 0; attempt < 2; ++attempt) {
                if (attempt == 1 || cached.keys.empty()) {
                    if (attempt == 1 && cached.keys_fetched + 60'000 > now) {
                        break;
                    }
                    auto jwks = fetch_json(*p, cached.discovery.jwks_uri);
                    if (std::holds_alternative<std::string>(jwks)) {
                        return back("sign-in-failed/unreachable");
                    }
                    cached.keys = parse_jwks(std::get<nlohmann::json>(jwks));
                    cached.keys_fetched = now;
                    const std::lock_guard lock(sso_->mutex);
                    sso_->cache[p->name] = cached;
                }
                who = check_id_token(id_token, cached.keys, check);
                if (std::holds_alternative<Identity>(who) ||
                    std::get<std::string>(who).find("signature") == std::string::npos) {
                    break;
                }
            }
        }
        if (std::holds_alternative<std::string>(who)) {
            return back("sign-in-failed/refused");
        }
        const Identity& identity = std::get<Identity>(who);
        if (!allowed(*p, identity)) {
            return back("sign-in-failed/not-allowed");
        }
        // Staff: a console session for the user whose account this is.
        if (flow.staff) {
            std::string user;
            try {
                for (const User& u : load_people(services_.directory).users) {
                    if (std::ranges::contains(u.accounts, std::pair{p->name, identity.subject})) {
                        user = u.name;
                    }
                }
            } catch (const std::exception&) {
                return back("sign-in-failed/busy");
            }
            if (user.empty() || services_.sessions == nullptr) {
                return back("sign-in-failed/no-staff-account");
            }
            const std::string token = services_.sessions->create(user);
            const std::string code = to_base64url(services_.entropy->bytes<16>());
            const std::lock_guard lock(sso_->mutex);
            std::erase_if(sso_->codes, [&](const auto& c) { return c.second.expires <= now; });
            if (sso_->codes.size() >= max_flows) {
                return back("sign-in-failed/busy");
            }
            sso_->codes.emplace(code, Code{{}, user, token, now + code_lifetime});
            return back("signed-in/" + code);
        }
        // The applicant's pseudonym: under the console's own key, made once.
        Bytes key;
        try {
            if (!services_.keys->has_secret(pseudonym_secret)) {
                const auto fresh = services_.entropy->bytes<32>();
                services_.keys->seal_secret(pseudonym_secret, fresh);
            }
            key = services_.keys->open_secret(pseudonym_secret);
        } catch (const std::exception&) {
            return back("sign-in-failed/locked");
        }
        Applicant applicant{p->name, identity, pseudonym(key, identity), flow.form,
                            now + applicant_lifetime};
        const std::string code = to_base64url(services_.entropy->bytes<16>());
        {
            const std::lock_guard lock(sso_->mutex);
            std::erase_if(sso_->codes, [&](const auto& c) { return c.second.expires <= now; });
            if (sso_->codes.size() >= max_flows) {
                return back("sign-in-failed/busy");
            }
            sso_->codes.emplace(code, Code{std::move(applicant), {}, {}, now + code_lifetime});
        }
        return back("signed-in/" + code);
    }

    if (path == "/console/api/sso/finish") {
        const auto body =
            nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
        if (!body.is_object() || !body.contains("code") || !body["code"].is_string()) {
            return error(400, "invalid_argument", "give the one-time code: {\"code\": CODE}");
        }
        const std::string token = "cxa_" + to_base64url(services_.entropy->bytes<32>());
        const std::lock_guard lock(sso_->mutex);
        const auto it = sso_->codes.find(body["code"].get<std::string>());
        if (it == sso_->codes.end() || it->second.expires <= now) {
            return error(401, "unauthorized", "the sign-in has expired: sign in again");
        }
        if (!it->second.staff_token.empty()) {
            const nlohmann::json staff{{"session", it->second.staff_token},
                                       {"user", it->second.staff_user}};
            sso_->codes.erase(it);
            return json(200, staff);
        }
        Applicant applicant = std::move(it->second.applicant);
        sso_->codes.erase(it);
        std::erase_if(sso_->applicants, [&](const auto& a) { return a.second.expires <= now; });
        if (sso_->applicants.size() >= max_applicants) {
            return error(503, "unavailable", "too many people are signed in: try again later");
        }
        const nlohmann::json shown = applicant_json(applicant);
        sso_->applicants.emplace(token_hash(*services_.provider, token), std::move(applicant));
        return json(200, {{"token", token}, {"applicant", shown}});
    }
    return error(404, "not_found", "no such console route");
}

} // namespace cexchain::console
