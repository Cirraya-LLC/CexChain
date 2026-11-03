// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cexchain/node/responses.hpp>

namespace cexchain::node {

std::string_view errc_name(const Errc code) {
    switch (code) {
    case Errc::invalid_argument:
        return "invalid_argument";
    case Errc::truncated:
        return "truncated";
    case Errc::malformed:
        return "malformed";
    case Errc::non_canonical:
        return "non_canonical";
    case Errc::unsupported:
        return "unsupported";
    case Errc::limit_exceeded:
        return "limit_exceeded";
    case Errc::verification_failed:
        return "verification_failed";
    case Errc::crypto_failure:
        return "crypto_failure";
    case Errc::rejected:
        return "rejected";
    case Errc::not_found:
        return "not_found";
    case Errc::unavailable:
        return "unavailable";
    }
    return "unknown";
}

int status_of(const Errc code) {
    switch (code) {
    case Errc::limit_exceeded:
        return 413;
    case Errc::verification_failed:
        return 422;
    case Errc::rejected:
        return 409;
    case Errc::not_found:
        return 404;
    case Errc::unavailable:
        return 503;
    case Errc::crypto_failure:
        return 500;
    default:
        return 400;
    }
}

http::Response json_response(const int status, const nlohmann::json& body) {
    http::Response r;
    r.status = status;
    const std::string text = body.dump() + "\n";
    r.body.assign(text.begin(), text.end());
    return r;
}

http::Response error_response(const int status, const std::string_view code,
                              const std::string_view message) {
    return json_response(status, {{"error", {{"code", code}, {"message", message}}}});
}

http::Response error_response(const Error& error) {
    return error_response(status_of(error.code), errc_name(error.code), error.detail);
}

} // namespace cexchain::node
