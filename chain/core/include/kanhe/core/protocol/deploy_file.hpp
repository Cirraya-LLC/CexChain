// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/statement.hpp>

/// A contract ready to deploy, as a file: what a compiler writes (bo build
/// --out writes one as FILE.boc) and what `contract export` writes of a
/// deployed contract. It is the deploy's fields, keyed as
/// contract-deploy-body keys them, and the hash its source's digests were
/// made with, so that a ledger of another hash refuses it:
///
///   {1: code, 2: {+ name => kind}, 3: language, 4: compiler, ? 5: source,
///    ? 6: name, 7: hash}
///
/// where the hash is a COSE algorithm id (SHA-256 -16, SM3 -65538). A file,
/// not a statement: nothing of it is signed until it is deployed.
namespace kanhe::protocol {

struct DeployFile {
    ContractDeployBody body;
    crypto::HashAlg hash = crypto::HashAlg::sha256;

    friend bool operator==(const DeployFile&, const DeployFile&) = default;
};

/// A deploy file is at most this large (a module, a source, and the rest).
inline constexpr std::size_t max_deploy_file = std::size_t{1} << 20;

[[nodiscard]] Result<Bytes> encode_deploy_file(const DeployFile& file);
/// Decodes a deploy file: the shape and limits of a deploy (the module's own
/// validity is vm::load's to check, the source's its language's).
[[nodiscard]] Result<DeployFile> decode_deploy_file(ByteView encoded);

} // namespace kanhe::protocol
