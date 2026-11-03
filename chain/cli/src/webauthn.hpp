// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <nlohmann/json.hpp>

/// WebAuthn ceremonies for the command line. A passkey can only be used from
/// a web page, so the tool serves a one-time page on http://localhost (a
/// secure context; the relying party id is "localhost"), opens it in the
/// browser, and waits for the page to post back the authenticator's
/// response. The page's address carries a random token, so other sites cannot
/// reach it.
namespace cexchain::cli {

inline constexpr std::string_view local_rp_id = "localhost";

/// Runs one ceremony. `request` holds:
///   mode       "create" (enroll a passkey) or "get" (prove presence)
///   rpId, challenge (base64url)
///   create: userId (base64url), userName
///   get:    allow (array of base64url credential ids)
///   title, summary  shown to the person
/// Returns the page's response; throws CommandError if the person cancels or
/// nothing arrives within three minutes. Unless `open_browser` is false (or
/// CEXCHAIN_NO_BROWSER is set), the page is opened in the default browser;
/// its address is always printed to stderr.
[[nodiscard]] nlohmann::json run_webauthn_ceremony(const nlohmann::json& request,
                                                   bool open_browser);

} // namespace cexchain::cli
