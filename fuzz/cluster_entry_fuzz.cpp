// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Raft entries and snapshot objects reach a cluster member only from members
// that hold the cluster's secret, but a member may be buggy or compromised.
// Applying any of them must never crash, nor leave the ledger unusable: an
// entry that does not hold up is refused, the same way on every member.
//
// Input: [kind][payload]; kind 0-2 applies the payload as a Raft entry, kind
// 3-5 receives it as snapshot object 0, 1, or 2.

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <unistd.h>

#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/ledger/ledger.hpp>

#include "cluster_parts.hpp"

namespace cd = cexchain::node::cluster_detail;
namespace ledger = cexchain::ledger;
namespace protocol = cexchain::protocol;

namespace {

struct Member {
    std::filesystem::path dir;
    cexchain::crypto::openssl::Provider provider;
    ledger::ManualClock clock{1'791'244'800'000};
    std::optional<ledger::PosixFileSystem> fs;
    std::optional<ledger::Ledger> ledger;
    std::shared_ptr<cd::LedgerMachine> machine;
    nuraft::ulong index = 0;

    Member() {
        dir = std::filesystem::temp_directory_path() /
              ("cexchain-cluster-fuzz-" + std::to_string(::getpid()));
        std::filesystem::remove_all(dir);
        std::filesystem::create_directories(dir / "cluster");
        std::filesystem::create_directories(dir / "vault" / "records");
        fs.emplace(*ledger::PosixFileSystem::open_directory(dir));
        const auto org =
            *cexchain::crypto::openssl::KeyPair::from_ed25519_seed(cexchain::Bytes(32, 1));
        const auto log =
            *cexchain::crypto::openssl::KeyPair::from_ed25519_seed(cexchain::Bytes(32, 2));
        protocol::Statement genesis;
        genesis.issued_at = clock.now();
        genesis.body = protocol::GenesisBody{cexchain::crypto::HashAlg::sha256, "Fuzz Org",
                                             org.public_key(), log.public_key()};
        const auto signed_genesis =
            *protocol::sign_statement(org, provider, cexchain::crypto::HashAlg::sha256, genesis);
        ledger.emplace(*ledger::Ledger::create(*fs, clock, provider, signed_genesis.encoded));
        machine = std::make_shared<cd::LedgerMachine>(dir, *ledger, nullptr);
    }
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static Member member;
    if (size < 1) {
        return 0;
    }
    const std::uint8_t kind = data[0] % 6;
    const auto payload = cd::to_buffer(cexchain::ByteView(data + 1, size - 1));
    if (kind < 3) {
        static_cast<void>(member.machine->commit(++member.index, *payload));
    } else {
        nuraft::snapshot snapshot(1, 1, nuraft::cs_new<nuraft::cluster_config>());
        nuraft::ulong object = kind - 3U;
        member.machine->save_logical_snp_obj(snapshot, object, *payload, object == 0, false);
    }
    if (!member.ledger->usable()) {
        std::abort();
    }
    return 0;
}
