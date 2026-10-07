// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstdio>
#include <print>
#include <qrcodegen.hpp>
#include <unistd.h>

#include "commands.hpp"
#include "output.hpp"

namespace cexchain::cli {

namespace {

// QR codes need a light margin of four modules (ISO/IEC 18004).
constexpr int quiet_zone = 4;

std::string percent_encode(std::string_view text) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string out;
    for (const char c : text) {
        const auto byte = static_cast<unsigned char>(c);
        const bool plain = (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
                           (byte >= '0' && byte <= '9') || c == '-' || c == '_' || c == '.' ||
                           c == '~' || c == '/' || c == ':';
        if (plain) {
            out.push_back(c);
        } else {
            out.push_back('%');
            out.push_back(digits[byte >> 4U]);
            out.push_back(digits[byte & 0x0FU]);
        }
    }
    return out;
}

bool is_web_url(std::string_view url) {
    return url.starts_with("https://") || url.starts_with("http://");
}

bool dark(const qrcodegen::QrCode& qr, int x, int y) {
    return x >= 0 && y >= 0 && x < qr.getSize() && y < qr.getSize() && qr.getModule(x, y);
}

std::string to_svg(const qrcodegen::QrCode& qr) {
    const int size = qr.getSize() + 2 * quiet_zone;
    std::string path;
    for (int y = 0; y < qr.getSize(); ++y) {
        for (int x = 0; x < qr.getSize(); ++x) {
            if (qr.getModule(x, y)) {
                path += std::format("M{},{}h1v1h-1z", x + quiet_zone, y + quiet_zone);
            }
        }
    }
    return std::format(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" viewBox=\"0 0 {0} {0}\" "
        "stroke=\"none\" shape-rendering=\"crispEdges\">\n"
        "<rect width=\"100%\" height=\"100%\" fill=\"#FFFFFF\"/>\n"
        "<path d=\"{1}\" fill=\"#000000\"/>\n</svg>\n",
        size, path);
}

/// Two rows of modules per line of text, dark on light whatever the
/// terminal's colors.
std::string to_terminal(const qrcodegen::QrCode& qr, bool color) {
    std::string out;
    for (int y = -quiet_zone; y < qr.getSize() + quiet_zone; y += 2) {
        if (color) {
            out += "\x1b[30;47m";
        }
        for (int x = -quiet_zone; x < qr.getSize() + quiet_zone; ++x) {
            const bool top = dark(qr, x, y);
            const bool bottom = dark(qr, x, y + 1);
            out += top && bottom ? "█" : top ? "▀" : bottom ? "▄" : " ";
        }
        out += color ? "\x1b[0m\n" : "\n";
    }
    return out;
}

} // namespace

int cmd_qr(const Args& args) {
    Session session(args);
    const protocol::Id record = session.record_id(args.positional().front());
    const std::string verifier = args.need("verifier-url");
    const std::string bundle = args.need("bundle-url");
    if (!is_web_url(verifier) || verifier.find('#') != std::string::npos) {
        throw UsageError{"--verifier-url must be an http(s) URL without a #fragment"};
    }
    if (!is_web_url(bundle)) {
        throw UsageError{"--bundle-url must be an http(s) URL"};
    }
    const std::string url = verifier + "#l=" + hex_id(session.state().ledger_id()) +
                            "&r=" + hex_id(record) + "&b=" + percent_encode(bundle);
    const auto qr = qrcodegen::QrCode::encodeText(url.c_str(), qrcodegen::QrCode::Ecc::MEDIUM);
    const auto out = args.get("out");
    if (out) {
        const std::string svg = to_svg(qr);
        write_file(*out, as_bytes(svg), false);
    }
    if (args.json()) {
        print_json({{"url", url},
                    {"ledger_id", hex_id(session.state().ledger_id())},
                    {"record_id", hex_id(record)},
                    {"modules", qr.getSize()},
                    {"file", out ? Json(*out) : Json(nullptr)}});
        return exit_ok;
    }
    if (out) {
        std::println("QR code written to {} ({}x{} modules)", *out, qr.getSize(), qr.getSize());
    } else {
        std::print("{}", to_terminal(qr, ::isatty(STDOUT_FILENO) == 1));
    }
    std::println("{}", url);
    return exit_ok;
}

} // namespace cexchain::cli
