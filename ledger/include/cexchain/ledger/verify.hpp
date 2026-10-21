// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/evidence.hpp>

/// Evidence verification on all cores (D-056, P8). Core verifies a bundle
/// one signature after another (as the browser does); here a bundle's
/// signatures are checked first, in parallel, and core's verification then
/// takes those outcomes for exactly the same algorithm, key, message, and
/// signature bytes (`protocol::SignatureChecks`). Everything else, the
/// replay included, is core's, in order, so every report and every refusal
/// is the one core gives alone.
namespace cexchain::ledger {

/// Signatures that verified, remembered by a process so that one checked
/// again (the same genesis, deployment, checkpoint, and receipt in every
/// evidence of a ledger's instances) is not checked again: a bounded set of
/// (algorithm, key, message, signature), each compared byte for byte. Only
/// successes are kept; anything else is checked every time. A signature
/// check is a function of these four alone (no time, state, or randomness),
/// so a remembered success is the outcome a check would give. Safe to use
/// from several threads at once.
class SignatureCache final : public protocol::SignatureChecks {
public:
    /// Bytes of keys, messages, and signatures kept at most (with a fixed
    /// allowance per entry); the least recently used go first. A signature
    /// whose entry would take over a sixty-fourth of it is not kept.
    static constexpr std::size_t default_capacity = std::size_t{32} << 20;

    explicit SignatureCache(std::size_t capacity = default_capacity);
    SignatureCache(const SignatureCache&) = delete;
    SignatureCache& operator=(const SignatureCache&) = delete;
    SignatureCache(SignatureCache&&) = delete;
    SignatureCache& operator=(SignatureCache&&) = delete;
    ~SignatureCache() override;

    [[nodiscard]] std::optional<Status> find(const crypto::PublicKey& key, ByteView message,
                                             ByteView signature) override;
    void checked(const crypto::PublicKey& key, ByteView message, ByteView signature,
                 const Status& outcome) override;

    struct Stats {
        std::uint64_t hits = 0;
        std::uint64_t misses = 0;
        std::size_t entries = 0;
        std::size_t bytes = 0;
    };
    [[nodiscard]] Stats stats() const;
    void clear();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// The process's cache, for long-running processes (a server, an executor,
/// the MCP server).
[[nodiscard]] SignatureCache& signature_cache();

/// Contracts' modules a process loaded, remembered by their code, so that
/// verifying a ledger's evidence again (an executor, request after request)
/// does not load its contracts again: at most `capacity` modules, the least
/// recently used going first, each found only for exactly the same code.
/// Safe to use from several threads at once.
class LoadedModules final : public protocol::ModuleCache {
public:
    static constexpr std::size_t default_capacity = 32;
    /// Larger code is loaded every time.
    static constexpr std::size_t max_code_size = std::size_t{1} << 20;

    explicit LoadedModules(std::size_t capacity = default_capacity);
    LoadedModules(const LoadedModules&) = delete;
    LoadedModules& operator=(const LoadedModules&) = delete;
    LoadedModules(LoadedModules&&) = delete;
    LoadedModules& operator=(LoadedModules&&) = delete;
    ~LoadedModules() override;

    [[nodiscard]] std::optional<vm::Module> find(ByteView code) override;
    void loaded(const vm::Module& module) override;

    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] std::uint64_t hits() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// The process's modules, as `signature_cache`.
[[nodiscard]] LoadedModules& loaded_modules();

/// How to verify.
struct Verifying {
    /// Check the signatures first on all cores (the process's pool, see
    /// `parallel_for`); otherwise only `cache` speeds verification up.
    bool ahead = true;
    /// Successes remembered: asked after the checks made ahead, and told
    /// every new one.
    SignatureCache* cache = nullptr;
};

/// As `protocol::verify_bundle`, with the same outcome. `options.signatures`,
/// if set, is asked first, then the signatures checked ahead, then `cache`.
[[nodiscard]] Result<protocol::EvidenceReport>
verify_bundle(const crypto::Provider& provider, ByteView encoded,
              const protocol::VerifyOptions& options = {}, const Verifying& how = {});

/// As `protocol::verify_contract_evidence`, with the same outcome; the
/// consent bundles' signatures are checked ahead with the instance's.
[[nodiscard]] Result<protocol::ContractReport>
verify_contract_evidence(const crypto::Provider& provider, ByteView encoded,
                         const protocol::VerifyOptions& options = {}, const Verifying& how = {});

} // namespace cexchain::ledger
