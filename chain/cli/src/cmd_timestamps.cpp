// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Time-stamp tokens over checkpoints (spec v0.11): asking an authority for
// one, keeping one got another way, and listing them.

#include <algorithm>
#include <format>
#include <optional>
#include <print>
#include <string>

#include <cexchain/client/support.hpp>
#include <cexchain/node/timestamps.hpp>
#include <cexchain/verifier/report.hpp>

#include "commands.hpp"
#include "output.hpp"

namespace cexchain::cli {

namespace {

/// The checkpoint to stamp: the latest, or with `--size`, the latest of
/// that size.
protocol::SignedCheckpoint chosen_checkpoint(const ledger::Ledger& ledger, const Args& args) {
    if (const auto size = args.get("size")) {
        auto of_size = unwrap(ledger.checkpoints_of_size(parse_number(*size, "--size")),
                              "reading checkpoints");
        if (of_size.empty()) {
            throw CommandError{"no checkpoint of size " + *size};
        }
        return std::move(of_size.back());
    }
    auto latest = ledger.latest_checkpoint();
    if (!latest) {
        throw CommandError{"the ledger has no checkpoints yet (cexchain checkpoint create)"};
    }
    return std::move(*latest);
}

Json token_json(const crypto::TimestampToken& read, std::uint64_t size, bool roots_given) {
    return {{"tree_size", size},
            {"time", verifier::iso_time(read.time)},
            {"accuracy_ms", read.accuracy},
            {"authority", read.authority},
            {"authority_key", to_hex(read.authority_key)},
            {"trusted", roots_given ? Json(read.trusted) : Json(nullptr)}};
}

void print_stored(const crypto::TimestampToken& read, std::uint64_t size) {
    std::println("stored a token from {}: it saw checkpoint size {} at {} (+/- {} ms)",
                 read.authority, size, verifier::format_time(read.time), read.accuracy);
}

} // namespace

int cmd_checkpoint_timestamp(const Args& args) {
    Session session(args);
    const protocol::SignedCheckpoint checkpoint = chosen_checkpoint(session.ledger(), args);
    node::ClientOptions options;
    if (const auto ca = args.get("ca-file")) {
        options.ca_file = *ca;
    }
    const Bytes token =
        unwrap(node::request_timestamp(session.provider(), args.need("tsa"),
                                       session.ledger().hash(), checkpoint, options),
               "asking the time-stamp authority");
    const std::uint64_t size = checkpoint.checkpoint.tree_size;
    session.add_timestamp(token, size);
    if (const auto out = args.get("out")) {
        write_file(*out, token, false);
    }
    const auto read = unwrap(session.provider().read_timestamp(token, {}), "reading the token");
    if (args.json()) {
        print_json(token_json(read, size, false));
    } else {
        print_stored(read, size);
    }
    return exit_ok;
}

int cmd_checkpoint_add_timestamp(const Args& args) {
    Session session(args);
    const protocol::SignedCheckpoint checkpoint = chosen_checkpoint(session.ledger(), args);
    const Bytes token = read_file(args.positional().front());
    const std::uint64_t size = checkpoint.checkpoint.tree_size;
    session.add_timestamp(token, size);
    const auto read = unwrap(session.provider().read_timestamp(token, {}), "reading the token");
    if (args.json()) {
        print_json(token_json(read, size, false));
    } else {
        print_stored(read, size);
    }
    return exit_ok;
}

int cmd_checkpoint_timestamps(const Args& args) {
    Session session(args);
    const auto roots_paths = args.all("tsa-root");
    const std::vector<Bytes> roots = client::load_certificates(roots_paths);
    std::optional<std::uint64_t> size;
    if (const auto text = args.get("size")) {
        size = parse_number(*text, "--size");
    }
    Json out = Json::array();
    std::vector<std::string> lines;
    for (const ledger::StoredTimestamp& t :
         unwrap(session.ledger().timestamps(), "reading time-stamp tokens")) {
        const std::uint64_t stamped = t.checkpoint.checkpoint.tree_size;
        if (size && stamped != *size) {
            continue;
        }
        const auto read = unwrap(session.provider().read_timestamp(t.token, roots), "a token");
        out.push_back(token_json(read, stamped, !roots.empty()));
        lines.push_back(std::format("{:>10}  {}  {}{}", stamped, verifier::format_time(read.time),
                                    read.authority,
                                    roots.empty()  ? ""
                                    : read.trusted ? "  (trusted)"
                                                   : "  (not trusted)"));
    }
    if (args.json()) {
        print_json(out);
    } else if (lines.empty()) {
        std::println("no time-stamp tokens yet (cexchain checkpoint timestamp --tsa URL)");
    } else {
        std::println("{:>10}  {:<23}  {}", "SIZE", "AUTHORITY'S TIME", "AUTHORITY");
        for (const std::string& line : lines) {
            std::println("{}", line);
        }
    }
    return exit_ok;
}

} // namespace cexchain::cli
