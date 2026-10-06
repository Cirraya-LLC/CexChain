// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The browser verifier's interface to JavaScript. Options are set one call at
// a time (so attachment contents need no encoding), then cexchain_verify runs
// the same verification as `cexchain verify` and returns the report as JSON.
// Strings returned to JavaScript are allocated with malloc; release them with
// cexchain_free.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <emscripten/emscripten.h>
#include <exception>
#include <string>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/verifier/report.hpp>

namespace {

using namespace cexchain;
using verifier::Json;

protocol::VerifyOptions options;

const crypto::openssl::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

char* to_c_string(const Json& value) {
    const std::string text = value.dump(-1, ' ', false, Json::error_handler_t::replace);
    char* out = static_cast<char*>(std::malloc(text.size() + 1));
    if (out != nullptr) {
        std::memcpy(out, text.c_str(), text.size() + 1);
    }
    return out;
}

Json failure(std::string_view message) {
    return {{"verified", false}, {"error", message}};
}

} // namespace

extern "C" {

EMSCRIPTEN_KEEPALIVE const char* cexchain_version() {
    return CEXCHAIN_VERSION;
}

EMSCRIPTEN_KEEPALIVE void cexchain_reset() {
    options = {};
}

/// Returns 0, or -1 if `hex` is not a ledger id.
EMSCRIPTEN_KEEPALIVE int cexchain_set_expected_ledger(const char* hex) {
    const auto bytes = from_hex(hex);
    if (!bytes) {
        return -1;
    }
    const auto id = protocol::to_id(*bytes);
    if (!id) {
        return -1;
    }
    options.expected_ledger = *id;
    return 0;
}

/// Trusts a witness, given its public key file. Returns 0, or -1 if the file
/// is not a CexChain public key.
EMSCRIPTEN_KEEPALIVE int cexchain_add_witness(const std::uint8_t* data, std::size_t size) {
    const auto value = cbor::decode(ByteView(data, size));
    if (!value) {
        return -1;
    }
    const auto key = protocol::decode_public_key(*value);
    if (!key) {
        return -1;
    }
    options.trusted_witnesses.push_back(*key);
    return 0;
}

EMSCRIPTEN_KEEPALIVE void cexchain_add_attachment(const char* name, const std::uint8_t* data,
                                                  std::size_t size) {
    options.attachment_contents[name] = Bytes(data, data + size);
}

/// Verifies an evidence bundle with the options set since the last reset.
EMSCRIPTEN_KEEPALIVE char* cexchain_verify(const std::uint8_t* bundle, std::size_t size) {
    try {
        const auto report = protocol::verify_bundle(provider(), ByteView(bundle, size), options);
        if (!report) {
            return to_c_string(failure(report.error().detail));
        }
        Json out = verifier::report_json(*report, options.expected_ledger.has_value());
        out["text"] = verifier::report_text(*report, options.expected_ledger.has_value());
        return to_c_string(out);
    } catch (const std::exception& e) {
        return to_c_string(failure(std::string("internal error: ") + e.what()));
    }
}

EMSCRIPTEN_KEEPALIVE void cexchain_free(char* text) {
    std::free(text);
}

} // extern "C"
