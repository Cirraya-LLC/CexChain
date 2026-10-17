// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/bo/pack.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/statement.hpp>

/// What a Bo deploy records besides its code (D-053, plan section 2; spec
/// section 15 and `bo-source` in spec/cexchain.cddl), so that anyone can
/// rebuild the code from the source and compare:
///   - the compiler string: "cexchain-bo RELEASE; codegen N; edition E";
///   - the source, as a `bo-source` bundle: the source as written, its
///     edition, every language pack it was read with (id, version, and the
///     home's hash of the pack's canonical CBOR), the packs that are not
///     official embedded in full, and every vocabulary pack it uses (D-054;
///     vocab.hpp), each as its id, version, and digest:
///
///       {1: 1, 2: edition, 3: source, 4: [+ [id, version, digest]],
///        ? 5: [+ pack], ? 6: [+ [id, version, digest]],
///        ? 7: [+ vocabulary-pack]}
///
///     Pack references ascend by id; embedded packs (each a map, the pack's
///     canonical CBOR) ascend by id too, and each one's id is a reference's.
///     References without an embedded pack name official packs, which a
///     compiler carries in every released version. Key 6 lists exactly the
///     packs the source's `use` lines name; without `use` lines it is
///     absent. Key 7 embeds those of them that are not official (users'
///     vocabulary packs, G6) in full, each its canonical CBOR, by ascending
///     id, so that anyone rebuilds without fetching anything.
///   - `bo build --out` writes the same as a `.boc` file, ready to deploy.
///
/// Everything here reads untrusted bytes (a deploy comes from another
/// organization), so it is in the front end, which libFuzzer reaches
/// (bo_source_fuzz). Rebuilding itself (build.hpp) needs the compiler.
namespace cexchain::bo {

/// The bundle format this compiler writes and reads.
inline constexpr std::uint64_t source_format = 1;
/// A deploy's source is at most this many bytes (spec section 15).
inline constexpr std::size_t max_bundle_size = protocol::max_contract_source;
/// Packs one bundle names.
inline constexpr std::size_t max_bundle_packs = 64;
/// Digests are a ledger's hash: SHA-256 or SM3, 32 bytes.
inline constexpr std::size_t pack_digest_size = 32;

struct PackRef {
    std::string id;
    std::uint64_t version = 0;
    Bytes digest;

    friend bool operator==(const PackRef&, const PackRef&) = default;
};

struct SourceBundle {
    std::uint64_t edition = 1;
    /// The source as written, comments included.
    std::string source;
    /// Every pack the source was read with, by ascending id.
    std::vector<PackRef> packs;
    /// The packs that are not official, each as its canonical CBOR (a map),
    /// by ascending id.
    std::vector<cbor::Value> embedded;
    /// The vocabulary packs the source uses (key 6), by ascending id.
    std::vector<PackRef> vocabulary;
    /// Those that are not official (users' packs), each as its canonical
    /// CBOR (a map), by ascending id (key 7).
    std::vector<cbor::Value> embedded_vocabulary;

    friend bool operator==(const SourceBundle&, const SourceBundle&) = default;
};

/// Encodes a bundle; fails if it breaks the shape above or the size limit.
[[nodiscard]] Result<Bytes> encode_source_bundle(const SourceBundle& bundle);
/// Decodes a bundle: deterministic CBOR within the limits of spec section 2,
/// in the shape above, at most max_bundle_size bytes. Embedded packs are
/// only checked to be maps here; open_source_bundle reads them.
[[nodiscard]] Result<SourceBundle> decode_source_bundle(ByteView encoded);

/// The vocabulary packs a source's `use` lines name, read with `packs`, by
/// ascending id (whatever their order in the source, each once).
[[nodiscard]] std::vector<std::string> source_uses(std::string_view source, const PackSet& packs);

/// The bundle of a source read with `packs` (each pack's digest under
/// `hash`, the home's): what a deploy records as its source. Fails if a
/// `use` line names a vocabulary pack this compiler does not carry.
[[nodiscard]] Result<SourceBundle>
make_source_bundle(std::string_view source, std::uint64_t source_edition, const PackSet& packs,
                   const crypto::Provider& provider, crypto::HashAlg hash);

/// Why a bundle's packs cannot be used to rebuild.
enum class OpenProblem : std::uint8_t {
    none,
    /// The bundle names an official pack (or a version of one) this compiler
    /// does not carry: a newer compiler may.
    unknown_official,
    /// An official pack's digest is not that of the version this compiler
    /// carries.
    official_differs,
    /// The bundle leaves out an official pack this compiler always reads.
    official_missing,
    /// The bundle's edition is not one this compiler reads.
    unknown_edition,
    /// An embedded pack does not read, is not the pack its reference names,
    /// calls itself official, or does not match its digest; or embedded
    /// packs are out of order.
    embedded,
    /// The packs cannot be read together, or the official packs are not of
    /// one release (some from before vocabulary packs, some not), or a
    /// bundle read with the official packs of before vocabulary packs names
    /// vocabulary packs (they came later).
    conflict,
    /// The source's `use` lines are not the vocabulary packs the bundle
    /// names (key 6).
    uses_differ,
};

inline constexpr std::array<std::string_view, 8> open_problem_names{
    "none",     "unknown-official", "official-differs", "official-missing", "unknown-edition",
    "embedded", "conflict",         "uses-differ"};

struct OpenedSource {
    /// Set if the packs check: the set the source is read with.
    std::optional<PackSet> packs;
    OpenProblem problem = OpenProblem::none;
    /// What is wrong, for people (English), naming the pack.
    std::string detail;
};

/// Finds and checks the packs a bundle names, under the home's hash: the
/// official ones this compiler carries (current or earlier: a bundle read
/// with the official packs of before vocabulary packs opens with them, and
/// its source uses every vocabulary pack without `use`; pack.hpp,
/// Officials), the others from the bundle, and the vocabulary packs (key 6),
/// which must be official ones this compiler carries at those versions and
/// digests and exactly those the source's `use` lines name.
[[nodiscard]] OpenedSource open_source_bundle(const SourceBundle& bundle,
                                              const crypto::Provider& provider,
                                              crypto::HashAlg hash);

/// A Bo compiler's identity, as a deploy's compiler string spells it:
/// "cexchain-bo 0.0.1; codegen 1; edition 1".
struct CompilerId {
    std::string release;
    std::uint64_t codegen = 0;
    std::uint64_t edition = 0;

    friend bool operator==(const CompilerId&, const CompilerId&) = default;
};

inline constexpr std::string_view compiler_name = "cexchain-bo";

[[nodiscard]] std::string format_compiler(const CompilerId& id);
/// The identity a compiler string names, if it is cexchain-bo's: anything
/// else (another compiler, another shape) gives nothing.
[[nodiscard]] std::optional<CompilerId> parse_compiler(std::string_view text);

/// A built contract as `bo build --out` writes it (FILE.boc): the deploy's
/// fields, keyed as contract-deploy-body keys them, plus the hash its
/// bundle's digests were made with:
///
///   {1: code, 2: {+ name => kind}, 3: "bo", 4: compiler, 5: bundle, 6: name, 7: hash}
///
/// where the hash is a COSE algorithm id (SHA-256 -16, SM3 -65538).
struct BuiltContract {
    Bytes code;
    std::map<std::string, protocol::FunctionKind> interface;
    std::string compiler;
    /// The bo-source bundle, encoded.
    Bytes source;
    std::string name;
    crypto::HashAlg hash = crypto::HashAlg::sha256;

    friend bool operator==(const BuiltContract&, const BuiltContract&) = default;
};

/// A .boc file is at most this large (a module, a bundle, and the rest).
inline constexpr std::size_t max_built_size = std::size_t{1} << 20;

[[nodiscard]] Result<Bytes> encode_built(const BuiltContract& built);
/// Decodes a .boc: the shape and limits of a deploy (the module's own
/// validity is vm::load's to check), the bundle decoding as above.
[[nodiscard]] Result<BuiltContract> decode_built(ByteView encoded);

} // namespace cexchain::bo
