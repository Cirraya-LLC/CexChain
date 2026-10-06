// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <charconv>
#include <span>

#include <cexchain/node/http.hpp>

namespace cexchain::node::http {

namespace {

bool is_tchar(char c) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
        return true;
    }
    return std::string_view("!#$%&'*+-.^_`|~").find(c) != std::string_view::npos;
}

bool is_token(std::string_view text) {
    return !text.empty() && std::ranges::all_of(text, is_tchar);
}

/// Field values: visible characters, spaces, tabs, and obs-text; never
/// controls.
bool is_field_value(std::string_view text) {
    return std::ranges::all_of(text, [](char c) {
        const auto u = static_cast<unsigned char>(c);
        return u == '\t' || (u >= 0x20 && u != 0x7f);
    });
}

std::string lower(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return out;
}

std::string_view trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
        text.remove_suffix(1);
    }
    return text;
}

int hex_digit(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/// Percent-decodes `text`; refuses broken escapes and NUL.
std::optional<std::string> percent_decode(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] != '%') {
            out.push_back(text[i]);
            continue;
        }
        if (i + 2 >= text.size()) {
            return std::nullopt;
        }
        const int hi = hex_digit(text[i + 1]);
        const int lo = hex_digit(text[i + 2]);
        if (hi < 0 || lo < 0 || (hi == 0 && lo == 0)) {
            return std::nullopt;
        }
        out.push_back(static_cast<char>((hi << 4) | lo));
        i += 2;
    }
    return out;
}

/// Whether the comma-separated list `value` holds `token`, ignoring case.
bool has_token(std::string_view value, std::string_view token) {
    while (!value.empty()) {
        const std::size_t comma = std::min(value.find(','), value.size());
        if (lower(trim(value.substr(0, comma))) == token) {
            return true;
        }
        value.remove_prefix(std::min(comma + 1, value.size()));
    }
    return false;
}

std::optional<std::uint64_t> parse_decimal(std::string_view text) {
    if (text.empty() || text.size() > 18 ||
        !std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; })) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    std::from_chars(text.data(), text.data() + text.size(), value);
    return value;
}

/// Splits a header section (without its final empty line) into lines, each
/// ending in CRLF; a bare CR or LF is refused.
std::optional<std::vector<std::string_view>> split_lines(std::string_view section) {
    std::vector<std::string_view> lines;
    while (!section.empty()) {
        const std::size_t end = section.find("\r\n");
        const std::string_view line = section.substr(0, end);
        if (line.find_first_of("\r\n") != std::string_view::npos) {
            return std::nullopt;
        }
        lines.push_back(line);
        if (end == std::string_view::npos) {
            break;
        }
        section.remove_prefix(end + 2);
    }
    return lines;
}

using Fields = std::vector<std::pair<std::string, std::string>>;

/// Parses header field lines. Returns false on a malformed field.
bool parse_fields(std::span<const std::string_view> lines, Fields& fields) {
    for (const std::string_view line : lines) {
        if (line.empty() || line.front() == ' ' || line.front() == '\t') {
            return false; // obsolete line folding, or an empty line too early
        }
        const std::size_t colon = line.find(':');
        if (colon == std::string_view::npos || !is_token(line.substr(0, colon))) {
            return false; // includes whitespace before the colon
        }
        const std::string_view value = trim(line.substr(colon + 1));
        if (!is_field_value(value)) {
            return false;
        }
        fields.emplace_back(lower(line.substr(0, colon)), std::string(value));
    }
    return true;
}

std::optional<std::string_view> find_field(const Fields& fields, std::string_view name) {
    std::optional<std::string_view> found;
    for (const auto& [n, v] : fields) {
        if (n == name) {
            if (found) {
                return std::nullopt; // repeated: treated as absent by callers that care
            }
            found = v;
        }
    }
    return found;
}

std::size_t count_field(const Fields& fields, std::string_view name) {
    return static_cast<std::size_t>(
        std::ranges::count_if(fields, [&](const auto& f) { return f.first == name; }));
}

} // namespace

std::optional<std::string_view> Request::header(std::string_view name) const {
    return find_field(headers, name);
}

std::optional<std::string_view> ClientResponse::header(std::string_view name) const {
    return find_field(headers, name);
}

std::optional<Parsed> parse_request(std::string_view buffer, const Limits& limits,
                                    std::optional<ParseError>& error, bool* wants_continue) {
    error.reset();
    if (wants_continue != nullptr) {
        *wants_continue = false;
    }
    const std::size_t end = buffer.find("\r\n\r\n");
    if (end == std::string_view::npos || end + 4 > limits.max_header_bytes) {
        if (buffer.size() >= limits.max_header_bytes) {
            error = ParseError{431, "the request header section is too large"};
        } else if (buffer.find("\n\n") != std::string_view::npos ||
                   buffer.find("\r\n\n") != std::string_view::npos) {
            error = ParseError{400, "header lines must end with CRLF"};
        }
        return std::nullopt;
    }
    auto lines = split_lines(buffer.substr(0, end));
    if (!lines || lines->empty()) {
        error = ParseError{400, "header lines must end with CRLF"};
        return std::nullopt;
    }

    // request-line = method SP request-target SP HTTP-version
    Request request;
    const std::string_view line = (*lines)[0];
    const std::size_t sp1 = line.find(' ');
    const std::size_t sp2 = sp1 == std::string_view::npos ? sp1 : line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos || line.find(' ', sp2 + 1) != std::string_view::npos) {
        error = ParseError{400, "malformed request line"};
        return std::nullopt;
    }
    const std::string_view method = line.substr(0, sp1);
    const std::string_view target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    const std::string_view version = line.substr(sp2 + 1);
    if (!is_token(method) || method.size() > 16) {
        error = ParseError{400, "malformed request method"};
        return std::nullopt;
    }
    if (version != "HTTP/1.1" && version != "HTTP/1.0") {
        error = version.starts_with("HTTP/") ? ParseError{505, "only HTTP/1.1 is supported"}
                                             : ParseError{400, "malformed request line"};
        return std::nullopt;
    }
    if (target.empty() || target.front() != '/' ||
        !std::ranges::all_of(target, [](char c) { return c > 0x20 && c < 0x7f; })) {
        error = ParseError{400, "the request target must be an absolute path"};
        return std::nullopt;
    }
    if (lines->size() - 1 > limits.max_headers) {
        error = ParseError{431, "too many header fields"};
        return std::nullopt;
    }
    if (!parse_fields(std::span(*lines).subspan(1), request.headers)) {
        error = ParseError{400, "malformed header field"};
        return std::nullopt;
    }
    const bool http11 = version == "HTTP/1.1";
    if (count_field(request.headers, "transfer-encoding") > 0) {
        error = ParseError{501, "request bodies need Content-Length, not Transfer-Encoding"};
        return std::nullopt;
    }
    if (http11 && count_field(request.headers, "host") != 1) {
        error = ParseError{400, "an HTTP/1.1 request needs exactly one Host field"};
        return std::nullopt;
    }
    std::uint64_t length = 0;
    if (const std::size_t n = count_field(request.headers, "content-length"); n > 1) {
        error = ParseError{400, "repeated Content-Length"};
        return std::nullopt;
    } else if (n == 1) {
        const auto parsed = parse_decimal(*request.header("content-length"));
        if (!parsed) {
            error = ParseError{400, "malformed Content-Length"};
            return std::nullopt;
        }
        if (*parsed > limits.max_body) {
            error = ParseError{413, "the request body is too large"};
            return std::nullopt;
        }
        length = *parsed;
    }
    bool expects_continue = false;
    if (const std::size_t n = count_field(request.headers, "expect"); n > 0) {
        if (n > 1 || lower(*request.header("expect")) != "100-continue") {
            error = ParseError{417, "only Expect: 100-continue is supported"};
            return std::nullopt;
        }
        expects_continue = true;
    }
    const auto connection = request.header("connection");
    request.keep_alive = http11 ? !(connection && has_token(*connection, "close"))
                                : (connection && has_token(*connection, "keep-alive"));

    const std::size_t body_start = end + 4;
    if (buffer.size() - body_start < length) {
        if (wants_continue != nullptr) {
            *wants_continue = expects_continue;
        }
        return std::nullopt;
    }
    const std::string_view body = buffer.substr(body_start, static_cast<std::size_t>(length));
    request.body.assign(body.begin(), body.end());

    // The target: path, then an optional query.
    request.method = std::string(method);
    request.target = std::string(target);
    const std::size_t question = target.find('?');
    auto path = percent_decode(target.substr(0, question));
    if (!path) {
        error = ParseError{400, "malformed percent-encoding in the path"};
        return std::nullopt;
    }
    request.path = std::move(*path);
    if (question != std::string_view::npos) {
        std::string_view query = target.substr(question + 1);
        while (!query.empty()) {
            const std::size_t amp = std::min(query.find('&'), query.size());
            const std::string_view pair = query.substr(0, amp);
            query.remove_prefix(std::min(amp + 1, query.size()));
            if (pair.empty()) {
                continue;
            }
            const std::size_t eq = pair.find('=');
            auto name = percent_decode(pair.substr(0, eq));
            auto value = percent_decode(eq == std::string_view::npos ? std::string_view()
                                                                     : pair.substr(eq + 1));
            if (!name || !value || name->empty()) {
                error = ParseError{400, "malformed query"};
                return std::nullopt;
            }
            if (!request.query.emplace(std::move(*name), std::move(*value)).second) {
                error = ParseError{400, "a query parameter is repeated"};
                return std::nullopt;
            }
        }
    }
    return Parsed{std::move(request), body_start + static_cast<std::size_t>(length)};
}

std::string serialize(const Response& response, bool keep_alive) {
    std::string out = "HTTP/1.1 " + std::to_string(response.status) + " ";
    out += reason(response.status);
    out += "\r\n";
    if (!response.content_type.empty()) {
        out += "Content-Type: " + response.content_type + "\r\n";
    }
    out += "Content-Length: " + std::to_string(response.body.size()) + "\r\n";
    out += keep_alive ? "Connection: keep-alive\r\n" : "Connection: close\r\n";
    for (const auto& [name, value] : response.headers) {
        out += name + ": " + value + "\r\n";
    }
    out += "\r\n";
    out.append(response.body.begin(), response.body.end());
    return out;
}

Result<std::optional<std::pair<ClientResponse, std::size_t>>>
parse_response(std::string_view buffer, std::size_t max_body, bool at_end_of_stream) {
    const std::size_t end = buffer.find("\r\n\r\n");
    if (end == std::string_view::npos) {
        if (buffer.size() > 64 * 1024 || at_end_of_stream) {
            return fail(Errc::malformed, "the server sent an incomplete or oversized response");
        }
        return std::nullopt;
    }
    auto lines = split_lines(buffer.substr(0, end));
    if (!lines || lines->empty()) {
        return fail(Errc::malformed, "the server's response is malformed");
    }
    // status-line = HTTP-version SP status-code SP [ reason-phrase ]
    const std::string_view line = (*lines)[0];
    if (line.size() < 12 || !line.starts_with("HTTP/1.") || line[8] != ' ' ||
        (line.size() > 12 && line[12] != ' ')) {
        return fail(Errc::malformed, "the server's status line is malformed");
    }
    const auto status = parse_decimal(line.substr(9, 3));
    if (!status || *status < 100) {
        return fail(Errc::malformed, "the server's status line is malformed");
    }
    ClientResponse response;
    response.status = static_cast<int>(*status);
    if (!parse_fields(std::span(*lines).subspan(1), response.headers)) {
        return fail(Errc::malformed, "the server sent a malformed header field");
    }
    const std::size_t body_start = end + 4;
    std::string_view rest = buffer.substr(body_start);
    auto finish =
        [&](std::string_view body,
            std::size_t consumed) -> Result<std::optional<std::pair<ClientResponse, std::size_t>>> {
        response.body.assign(body.begin(), body.end());
        return std::optional(std::pair(std::move(response), consumed));
    };
    if (response.status < 200 || response.status == 204 || response.status == 304) {
        return finish({}, body_start);
    }
    if (const auto te = response.header("transfer-encoding")) {
        if (lower(*te) != "chunked") {
            return fail(Errc::unsupported, "the server used an unsupported transfer coding");
        }
        std::string body;
        std::size_t pos = 0;
        while (true) {
            const std::size_t eol = rest.find("\r\n", pos);
            if (eol == std::string_view::npos) {
                break;
            }
            std::string_view size_text = rest.substr(pos, eol - pos);
            size_text = size_text.substr(0, size_text.find(';'));
            std::uint64_t size = 0;
            const auto [ptr, ec] =
                std::from_chars(size_text.data(), size_text.data() + size_text.size(), size, 16);
            if (ec != std::errc{} || ptr != size_text.data() + size_text.size() ||
                size_text.empty()) {
                return fail(Errc::malformed, "the server sent a malformed chunk");
            }
            if (size > max_body || body.size() + size > max_body) {
                return fail(Errc::limit_exceeded, "the server's response is too large");
            }
            if (size == 0) {
                // Trailer fields, then an empty line.
                const std::size_t trailers_end = rest.find("\r\n\r\n", eol);
                if (rest.substr(eol, 4) == "\r\n\r\n") {
                    return finish(body, body_start + eol + 4);
                }
                if (trailers_end == std::string_view::npos) {
                    break;
                }
                return finish(body, body_start + trailers_end + 4);
            }
            const std::size_t data = eol + 2;
            if (rest.size() < data + size + 2) {
                break;
            }
            if (rest.substr(data + size, 2) != "\r\n") {
                return fail(Errc::malformed, "the server sent a malformed chunk");
            }
            body.append(rest.substr(data, static_cast<std::size_t>(size)));
            pos = data + static_cast<std::size_t>(size) + 2;
        }
        if (at_end_of_stream) {
            return fail(Errc::malformed, "the server's response ended early");
        }
        return std::nullopt;
    }
    if (const auto cl = response.header("content-length")) {
        const auto length = parse_decimal(*cl);
        if (!length) {
            return fail(Errc::malformed, "the server sent a malformed Content-Length");
        }
        if (*length > max_body) {
            return fail(Errc::limit_exceeded, "the server's response is too large");
        }
        if (rest.size() < *length) {
            if (at_end_of_stream) {
                return fail(Errc::malformed, "the server's response ended early");
            }
            return std::nullopt;
        }
        return finish(rest.substr(0, static_cast<std::size_t>(*length)),
                      body_start + static_cast<std::size_t>(*length));
    }
    if (rest.size() > max_body) {
        return fail(Errc::limit_exceeded, "the server's response is too large");
    }
    if (!at_end_of_stream) {
        return std::nullopt;
    }
    return finish(rest, buffer.size());
}

std::string percent_encode(std::string_view text) {
    static constexpr std::string_view digits = "0123456789ABCDEF";
    std::string out;
    for (const char c : text) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '.' || c == '_' || c == '~') {
            out.push_back(c);
        } else {
            const auto u = static_cast<unsigned char>(c);
            out.push_back('%');
            out.push_back(digits[u >> 4]);
            out.push_back(digits[u & 0x0f]);
        }
    }
    return out;
}

std::string_view reason(int status) {
    switch (status) {
    case 100:
        return "Continue";
    case 200:
        return "OK";
    case 201:
        return "Created";
    case 204:
        return "No Content";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 408:
        return "Request Timeout";
    case 409:
        return "Conflict";
    case 413:
        return "Content Too Large";
    case 415:
        return "Unsupported Media Type";
    case 417:
        return "Expectation Failed";
    case 422:
        return "Unprocessable Content";
    case 429:
        return "Too Many Requests";
    case 431:
        return "Request Header Fields Too Large";
    case 500:
        return "Internal Server Error";
    case 501:
        return "Not Implemented";
    case 503:
        return "Service Unavailable";
    case 505:
        return "HTTP Version Not Supported";
    default:
        return "Unknown";
    }
}

} // namespace cexchain::node::http
