// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <string_view>

#include <nlohmann/json.hpp>

#include <kanhe/core/error.hpp>
#include <kanhe/node/http.hpp>

/// The API's JSON answers, for the server and its extensions alike: a body,
/// or an error as {"error": {"code", "message"}}.
namespace kanhe::node {

/// An error code's name in answers: "invalid_argument", "not_found", ...
[[nodiscard]] std::string_view errc_name(Errc code);
/// The HTTP status an error answers with.
[[nodiscard]] int status_of(Errc code);
[[nodiscard]] http::Response json_response(int status, const nlohmann::json& body);
[[nodiscard]] http::Response error_response(int status, std::string_view code,
                                            std::string_view message);
[[nodiscard]] http::Response error_response(const Error& error);

} // namespace kanhe::node
