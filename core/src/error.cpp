// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cexchain/core/error.hpp>

namespace cexchain {

std::string_view to_string(Errc code) noexcept {
    switch (code) {
    case Errc::invalid_argument:
        return "invalid argument";
    case Errc::truncated:
        return "truncated input";
    case Errc::malformed:
        return "malformed input";
    case Errc::non_canonical:
        return "non-canonical encoding";
    case Errc::unsupported:
        return "unsupported";
    case Errc::limit_exceeded:
        return "limit exceeded";
    case Errc::verification_failed:
        return "verification failed";
    case Errc::crypto_failure:
        return "cryptographic backend failure";
    case Errc::rejected:
        return "rejected by ledger rules";
    case Errc::not_found:
        return "not found";
    }
    return "unknown error";
}

} // namespace cexchain
