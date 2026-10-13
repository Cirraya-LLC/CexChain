// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The bo-source bundle a Bo deploy records, the compiler string, and the
// .boc file `bo build` writes (source.hpp). Bundles come from other
// organizations' deploys, so decoding checks every shape and limit, and
// opening checks every pack against its digest.

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/source.hpp>
#include <cexchain/core/vm.hpp>

#include "internal.hpp"

namespace cexchain::bo {

namespace {

std::unexpected<Error> malformed(std::string_view detail) {
    return fail(Errc::malformed, detail);
}

cbor::Value key(std::int64_t k) {
    return cbor::Value::integer(k);
}

/// Keys 1 to `last` only, each an unsigned integer.
bool keys_within(const cbor::Map& map, std::int64_t last) {
    return std::ranges::all_of(map, [&](const cbor::MapEntry& e) {
        const auto k = e.key.as_int64();
        return k && *k >= 1 && *k <= last;
    });
}

Status check_bundle(const SourceBundle& b) {
    if (b.edition == 0) {
        return malformed("a bo-source bundle's edition is 1 or more");
    }
    if (b.packs.empty() || b.packs.size() > max_bundle_packs) {
        return malformed("a bo-source bundle names 1 to 64 packs");
    }
    for (std::size_t i = 0; i < b.packs.size(); ++i) {
        const PackRef& ref = b.packs[i];
        if (!detail::valid_pack_id(ref.id)) {
            return malformed("a bo-source bundle names a pack by an id that is not a pack id");
        }
        if (ref.version == 0) {
            return malformed("a bo-source bundle names a pack version 0");
        }
        if (ref.digest.size() != pack_digest_size) {
            return malformed("a bo-source bundle's pack digest is not 32 bytes");
        }
        if (i > 0 && !(b.packs[i - 1].id < ref.id)) {
            return malformed("a bo-source bundle's packs do not ascend by id");
        }
    }
    if (b.embedded.size() > b.packs.size()) {
        return malformed("a bo-source bundle embeds more packs than it names");
    }
    for (const cbor::Value& pack : b.embedded) {
        if (pack.as_map() == nullptr) {
            return malformed("a bo-source bundle embeds a pack that is not a map");
        }
    }
    return {};
}

/// The text of an embedded pack's "id", if it has one.
const std::string* pack_id(const cbor::Value& pack) {
    const cbor::Value* id = pack.find("id");
    return id == nullptr ? nullptr : id->as_text();
}

} // namespace

Result<Bytes> encode_source_bundle(const SourceBundle& bundle) {
    if (auto ok = check_bundle(bundle); !ok) {
        return std::unexpected(ok.error());
    }
    cbor::Array packs;
    for (const PackRef& ref : bundle.packs) {
        packs.push_back(cbor::Value::array({cbor::Value::text(ref.id),
                                            cbor::Value::unsigned_integer(ref.version),
                                            cbor::Value::bytes(ref.digest)}));
    }
    cbor::Map map{{key(1), cbor::Value::unsigned_integer(source_format)},
                  {key(2), cbor::Value::unsigned_integer(bundle.edition)},
                  {key(3), cbor::Value::text(bundle.source)},
                  {key(4), cbor::Value::array(std::move(packs))}};
    if (!bundle.embedded.empty()) {
        map.push_back({key(5), cbor::Value::array(bundle.embedded)});
    }
    auto encoded = cbor::encode(cbor::Value::map(std::move(map)));
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    if (encoded->size() > max_bundle_size) {
        return fail(Errc::limit_exceeded,
                    "a bo-source bundle is at most 262,144 bytes (a deploy's source)");
    }
    return encoded;
}

Result<SourceBundle> decode_source_bundle(ByteView encoded) {
    if (encoded.size() > max_bundle_size) {
        return fail(Errc::limit_exceeded,
                    "a bo-source bundle is at most 262,144 bytes (a deploy's source)");
    }
    auto value = cbor::decode(encoded);
    if (!value) {
        return std::unexpected(value.error());
    }
    const cbor::Map* map = value->as_map();
    if (map == nullptr) {
        return malformed("a bo-source bundle is a map");
    }
    if (!keys_within(*map, 5)) {
        return malformed("a bo-source bundle has the keys 1 to 5 only");
    }
    const cbor::Value* format = value->find(1);
    if (format == nullptr || !format->as_uint64()) {
        return malformed("a bo-source bundle starts with its format (key 1)");
    }
    if (*format->as_uint64() != source_format) {
        return fail(Errc::unsupported,
                    "a bo-source bundle of a format this compiler does not read");
    }
    SourceBundle bundle;
    const cbor::Value* edition_value = value->find(2);
    if (edition_value == nullptr || !edition_value->as_uint64()) {
        return malformed("a bo-source bundle names its edition (key 2)");
    }
    bundle.edition = *edition_value->as_uint64();
    const cbor::Value* source = value->find(3);
    if (source == nullptr || source->as_text() == nullptr) {
        return malformed("a bo-source bundle holds the source as text (key 3)");
    }
    bundle.source = *source->as_text();
    const cbor::Value* packs = value->find(4);
    if (packs == nullptr || packs->as_array() == nullptr) {
        return malformed("a bo-source bundle lists its packs (key 4)");
    }
    for (const cbor::Value& item : *packs->as_array()) {
        const cbor::Array* ref = item.as_array();
        if (ref == nullptr || ref->size() != 3 || (*ref)[0].as_text() == nullptr ||
            !(*ref)[1].as_uint64() || (*ref)[2].as_bytes() == nullptr) {
            return malformed("a bo-source bundle's pack is [id, version, digest]");
        }
        bundle.packs.push_back(
            PackRef{*(*ref)[0].as_text(), *(*ref)[1].as_uint64(), *(*ref)[2].as_bytes()});
    }
    if (const cbor::Value* embedded = value->find(5)) {
        if (embedded->as_array() == nullptr || embedded->as_array()->empty()) {
            return malformed("a bo-source bundle's embedded packs (key 5) are a list of 1 or more");
        }
        bundle.embedded = *embedded->as_array();
    }
    if (auto ok = check_bundle(bundle); !ok) {
        return std::unexpected(ok.error());
    }
    return bundle;
}

Result<SourceBundle> make_source_bundle(std::string_view source, const std::uint64_t source_edition,
                                        const PackSet& packs, const crypto::Provider& provider,
                                        const crypto::HashAlg hash) {
    SourceBundle bundle;
    bundle.edition = source_edition;
    bundle.source = std::string(source);
    std::vector<const Pack*> sorted;
    for (const Pack& pack : packs.packs()) {
        sorted.push_back(&pack);
    }
    std::ranges::sort(sorted, {}, &Pack::id);
    for (const Pack* pack : sorted) {
        auto d = digest(*pack, provider, hash);
        if (!d) {
            return std::unexpected(d.error());
        }
        bundle.packs.push_back(
            PackRef{pack->id, pack->version, Bytes(d->bytes().begin(), d->bytes().end())});
        if (!pack->official) {
            auto value = cbor::decode(pack->canonical);
            if (!value) {
                return std::unexpected(value.error());
            }
            bundle.embedded.push_back(std::move(*value));
        }
    }
    // What a verifier will decode: the same bundle, within the limits.
    auto encoded = encode_source_bundle(bundle);
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    auto again = decode_source_bundle(*encoded);
    if (!again) {
        return std::unexpected(again.error());
    }
    return bundle;
}

OpenedSource open_source_bundle(const SourceBundle& bundle, const crypto::Provider& provider,
                                const crypto::HashAlg hash) {
    OpenedSource out;
    const auto problem = [&](OpenProblem p, std::string detail) {
        out.problem = p;
        out.detail = std::move(detail);
        return std::move(out);
    };
    if (bundle.edition == 0 || bundle.edition > edition) {
        return problem(OpenProblem::unknown_edition,
                       std::format("the source is Bo edition {}; this compiler reads edition {}",
                                   bundle.edition, edition));
    }
    // Embedded packs, read and paired with their references by id.
    std::vector<Pack> given;
    std::size_t next = 0;
    const std::string* previous = nullptr;
    for (const cbor::Value& value : bundle.embedded) {
        const std::string* id = pack_id(value);
        if (id == nullptr || (previous != nullptr && !(*previous < *id))) {
            return problem(OpenProblem::embedded,
                           "the embedded packs are not in order of their ids, or one has no id");
        }
        previous = id;
        PackRead read = read_pack(value);
        if (!read.pack) {
            return problem(OpenProblem::embedded,
                           std::format("the embedded pack {} does not read (bo packs check shows "
                                       "why): {}",
                                       detail::quote(*id), read.diagnostics.front().code));
        }
        if (read.pack->official) {
            return problem(OpenProblem::embedded,
                           std::format("the embedded pack {} calls itself official; official "
                                       "packs are named, never embedded",
                                       read.pack->id));
        }
        given.push_back(std::move(*read.pack));
    }
    for (const PackRef& ref : bundle.packs) {
        const Pack* named = nullptr;
        if (next < given.size() && given[next].id == ref.id) {
            named = &given[next++];
            if (named->version != ref.version) {
                return problem(OpenProblem::embedded,
                               std::format("the embedded pack {} is version {}, not the version "
                                           "{} the bundle names",
                                           ref.id, named->version, ref.version));
            }
        } else {
            named = official_pack(ref.id);
            if (named == nullptr) {
                return problem(OpenProblem::unknown_official,
                               std::format("the source was read with the pack {} version {}, "
                                           "which is neither in the bundle nor an official pack "
                                           "this compiler carries",
                                           ref.id, ref.version));
            }
            if (named->version != ref.version) {
                return problem(OpenProblem::unknown_official,
                               std::format("the source was read with the official pack {} "
                                           "version {}; this compiler carries version {}",
                                           ref.id, ref.version, named->version));
            }
        }
        const auto d = digest(*named, provider, hash);
        if (!d) {
            return problem(OpenProblem::embedded,
                           "the pack digests cannot be computed with the home's hash");
        }
        if (!std::ranges::equal(d->bytes(), ref.digest)) {
            const bool official = named->official;
            return problem(
                official ? OpenProblem::official_differs : OpenProblem::embedded,
                std::format("{} pack {} version {} has the digest {}, not {} as the bundle says",
                            official ? "the official" : "the embedded", ref.id, ref.version,
                            to_hex(d->bytes()), to_hex(ref.digest)));
        }
    }
    if (next != given.size()) {
        return problem(OpenProblem::embedded,
                       "the bundle embeds a pack it does not name, or names it twice");
    }
    for (const Pack& official : official_packs()) {
        if (std::ranges::none_of(bundle.packs,
                                 [&](const PackRef& ref) { return ref.id == official.id; })) {
            return problem(OpenProblem::official_missing,
                           std::format("the source was read without the official pack {}, "
                                       "which this compiler always reads",
                                       official.id));
        }
    }
    PackSetRead set = make_pack_set(std::move(given));
    if (!set.set) {
        return problem(OpenProblem::conflict,
                       std::format("the packs cannot be read together: {}",
                                   set.diagnostics.empty() ? std::string_view("?")
                                                           : set.diagnostics.front().code));
    }
    out.packs = std::move(*set.set);
    return out;
}

std::string format_compiler(const CompilerId& id) {
    return std::format("{} {}; codegen {}; edition {}", compiler_name, id.release, id.codegen,
                       id.edition);
}

std::optional<CompilerId> parse_compiler(std::string_view text) {
    const auto take_number = [](std::string_view& rest,
                                std::string_view prefix) -> std::optional<std::uint64_t> {
        if (!rest.starts_with(prefix)) {
            return std::nullopt;
        }
        rest.remove_prefix(prefix.size());
        std::uint64_t n = 0;
        const auto [end, ec] = std::from_chars(rest.data(), rest.data() + rest.size(), n);
        if (ec != std::errc{} || end == rest.data() ||
            (rest.front() == '0' && end - rest.data() > 1)) {
            return std::nullopt;
        }
        rest.remove_prefix(static_cast<std::size_t>(end - rest.data()));
        return n;
    };
    std::string_view rest = text;
    if (!rest.starts_with(compiler_name) || !rest.substr(compiler_name.size()).starts_with(' ')) {
        return std::nullopt;
    }
    rest.remove_prefix(compiler_name.size() + 1);
    const std::size_t semicolon = rest.find(';');
    if (semicolon == std::string_view::npos || semicolon == 0) {
        return std::nullopt;
    }
    CompilerId id;
    id.release = std::string(rest.substr(0, semicolon));
    if (id.release.find(' ') != std::string::npos) {
        return std::nullopt;
    }
    rest.remove_prefix(semicolon);
    const auto codegen = take_number(rest, "; codegen ");
    if (!codegen) {
        return std::nullopt;
    }
    const auto edition_number = take_number(rest, "; edition ");
    if (!edition_number || !rest.empty()) {
        return std::nullopt;
    }
    id.codegen = *codegen;
    id.edition = *edition_number;
    return id;
}

Result<Bytes> encode_built(const BuiltContract& built) {
    cbor::Map interface;
    for (const auto& [name, kind] : built.interface) {
        interface.push_back({cbor::Value::text(name),
                             cbor::Value::unsigned_integer(static_cast<std::uint64_t>(kind))});
    }
    auto encoded = cbor::encode(
        cbor::Value::map({{key(1), cbor::Value::bytes(built.code)},
                          {key(2), cbor::Value::map(std::move(interface))},
                          {key(3), cbor::Value::text("bo")},
                          {key(4), cbor::Value::text(built.compiler)},
                          {key(5), cbor::Value::bytes(built.source)},
                          {key(6), cbor::Value::text(built.name)},
                          {key(7), cbor::Value::integer(crypto::cose_id(built.hash))}}));
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    // Only what decodes is written.
    if (auto again = decode_built(*encoded); !again) {
        return std::unexpected(again.error());
    }
    return encoded;
}

Result<BuiltContract> decode_built(ByteView encoded) {
    if (encoded.size() > max_built_size) {
        return fail(Errc::limit_exceeded, "a built contract (.boc) is at most 1 MiB");
    }
    auto value = cbor::decode(encoded);
    if (!value) {
        return std::unexpected(value.error());
    }
    const cbor::Map* map = value->as_map();
    if (map == nullptr || map->size() != 7 || !keys_within(*map, 7)) {
        return malformed("a built contract (.boc) is a map of the keys 1 to 7");
    }
    BuiltContract built;
    const cbor::Value* code = value->find(1);
    const cbor::Value* interface = value->find(2);
    const cbor::Value* language = value->find(3);
    const cbor::Value* compiler = value->find(4);
    const cbor::Value* source = value->find(5);
    const cbor::Value* name = value->find(6);
    const cbor::Value* hash = value->find(7);
    if (code->as_bytes() == nullptr || code->as_bytes()->empty() ||
        code->as_bytes()->size() > vm::max_module_size) {
        return malformed("a built contract's code (key 1) is a module of at most 512 KiB");
    }
    built.code = *code->as_bytes();
    if (interface->as_map() == nullptr || interface->as_map()->empty() ||
        interface->as_map()->size() > protocol::max_contract_functions) {
        return malformed("a built contract's interface (key 2) maps 1 to 256 functions");
    }
    bool creates = false;
    for (const cbor::MapEntry& e : *interface->as_map()) {
        const std::string* function = e.key.as_text();
        const auto kind = e.value.as_uint64();
        if (function == nullptr || function->empty() ||
            function->size() > protocol::max_function_name || !kind || (*kind != 1 && *kind != 2)) {
            return malformed("a built contract's function is a name of 1 to 64 bytes and a "
                             "kind, 1 or 2");
        }
        creates = creates || *kind == 1;
        built.interface.emplace(*function, static_cast<protocol::FunctionKind>(*kind));
    }
    if (!creates) {
        return malformed("a built contract has a function that creates instances");
    }
    if (language->as_text() == nullptr || *language->as_text() != "bo") {
        return malformed("a built contract's language (key 3) is bo");
    }
    if (compiler->as_text() == nullptr || compiler->as_text()->empty() ||
        compiler->as_text()->size() > protocol::max_contract_compiler) {
        return malformed("a built contract names its compiler (key 4) in 1 to 128 bytes");
    }
    built.compiler = *compiler->as_text();
    if (source->as_bytes() == nullptr) {
        return malformed("a built contract holds its bo-source bundle (key 5)");
    }
    if (auto bundle = decode_source_bundle(*source->as_bytes()); !bundle) {
        return std::unexpected(bundle.error());
    }
    built.source = *source->as_bytes();
    if (name->as_text() == nullptr || name->as_text()->empty() ||
        name->as_text()->size() > protocol::max_contract_name) {
        return malformed("a built contract's name (key 6) is 1 to 256 bytes");
    }
    built.name = *name->as_text();
    const auto alg = hash->as_int64() ? crypto::hash_alg_from_cose(*hash->as_int64())
                                      : std::optional<crypto::HashAlg>();
    if (!alg || (*alg != crypto::HashAlg::sha256 && *alg != crypto::HashAlg::sm3)) {
        return malformed("a built contract names the hash of its digests (key 7): SHA-256 or SM3");
    }
    built.hash = *alg;
    return built;
}

} // namespace cexchain::bo
