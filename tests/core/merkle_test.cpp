// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators_all.hpp>

#include <cexchain/core/crypto.hpp>
#include <cexchain/core/merkle.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "support/vectors.hpp"

namespace crypto = cexchain::crypto;
namespace merkle = cexchain::merkle;
using cexchain::as_bytes;
using cexchain::Bytes;
using cexchain::Errc;
using cexchain::to_hex;
using cexchain::test::hex;
using cexchain::test::load_vectors;
using crypto::Digest;
using crypto::HashAlg;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

Digest digest_from_hex(const std::string& text) {
    const auto digest = Digest::from_bytes(hex(text));
    REQUIRE(digest);
    return *digest;
}

std::vector<Digest> proof_from_json(const nlohmann::json& proof) {
    std::vector<Digest> out;
    for (const auto& element : proof) {
        out.push_back(digest_from_hex(element.get<std::string>()));
    }
    return out;
}

std::vector<std::string> to_hex_list(const std::vector<Digest>& proof) {
    std::vector<std::string> out;
    for (const Digest& d : proof) {
        out.push_back(to_hex(d.bytes()));
    }
    return out;
}

Digest mutate(Digest d) {
    Bytes bytes(d.bytes().begin(), d.bytes().end());
    bytes[bytes.size() / 2] ^= 0x01;
    return *Digest::from_bytes(bytes);
}

merkle::Tree build_tree(HashAlg alg, std::uint64_t size) {
    merkle::Tree tree(provider(), alg);
    for (std::uint64_t i = 0; i < size; ++i) {
        const std::string entry = "entry " + std::to_string(i);
        REQUIRE(tree.append(as_bytes(entry)));
    }
    return tree;
}

} // namespace

TEST_CASE("Merkle trees match independent RFC 9162 vectors", "[core][merkle][vectors]") {
    const std::string file = GENERATE("merkle-sha256.json", "merkle-sm3.json");
    INFO(file);
    const auto document = load_vectors(file);
    const auto alg = crypto::hash_alg_from_cose(document["algorithm"].get<std::int64_t>());
    REQUIRE(alg);

    merkle::Tree tree(provider(), *alg);
    std::vector<Digest> leaves;
    for (const auto& entry : document["entries"]) {
        const Bytes bytes = hex(entry.get<std::string>());
        REQUIRE(tree.append(bytes));
        const auto leaf = merkle::leaf_hash(provider(), *alg, bytes);
        REQUIRE(leaf);
        leaves.push_back(*leaf);
    }

    const auto& roots = document["roots"];
    for (std::uint64_t n = 0; n < roots.size(); ++n) {
        const auto root = tree.root(n);
        REQUIRE(root);
        CHECK(to_hex(root->bytes()) == roots[n].get<std::string>());
    }

    for (const auto& vector : document["inclusion"]) {
        const auto index = vector["index"].get<std::uint64_t>();
        const auto size = vector["tree_size"].get<std::uint64_t>();
        INFO("inclusion of " << index << " in " << size);
        const auto proof = tree.inclusion_proof(index, size);
        REQUIRE(proof);
        CHECK(to_hex_list(*proof) == vector["proof"].get<std::vector<std::string>>());

        const auto expected = proof_from_json(vector["proof"]);
        const Digest root = digest_from_hex(roots[size].get<std::string>());
        CHECK(
            merkle::verify_inclusion(provider(), *alg, leaves[index], index, size, expected, root));
    }

    for (const auto& vector : document["consistency"]) {
        const auto old_size = vector["old_size"].get<std::uint64_t>();
        const auto new_size = vector["new_size"].get<std::uint64_t>();
        INFO("consistency from " << old_size << " to " << new_size);
        const auto proof = tree.consistency_proof(old_size, new_size);
        REQUIRE(proof);
        CHECK(to_hex_list(*proof) == vector["proof"].get<std::vector<std::string>>());

        const auto expected = proof_from_json(vector["proof"]);
        CHECK(merkle::verify_consistency(provider(), *alg, old_size, new_size,
                                         digest_from_hex(roots[old_size].get<std::string>()),
                                         digest_from_hex(roots[new_size].get<std::string>()),
                                         expected));
    }
}

TEST_CASE("every proof in trees up to 70 entries verifies", "[core][merkle][property]") {
    const auto tree = build_tree(HashAlg::sha256, 70);
    std::vector<Digest> roots;
    for (std::uint64_t n = 0; n <= tree.size(); ++n) {
        roots.push_back(*tree.root(n));
    }
    for (std::uint64_t n = 1; n <= tree.size(); ++n) {
        for (std::uint64_t i = 0; i < n; ++i) {
            const auto proof = tree.inclusion_proof(i, n);
            REQUIRE(proof);
            REQUIRE(merkle::verify_inclusion(provider(), HashAlg::sha256, *tree.leaf(i), i, n,
                                             *proof, roots[n]));
        }
        for (std::uint64_t m = 0; m <= n; ++m) {
            const auto proof = tree.consistency_proof(m, n);
            REQUIRE(proof);
            REQUIRE(merkle::verify_consistency(provider(), HashAlg::sha256, m, n, roots[m],
                                               roots[n], *proof));
        }
    }
}

TEST_CASE("a compact range grows to the same roots as the tree", "[core][merkle][property]") {
    for (std::uint64_t start = 0; start <= 40; ++start) {
        merkle::Tree tree(provider(), HashAlg::sha256);
        for (std::uint64_t i = 0; i < start; ++i) {
            REQUIRE(tree.append(as_bytes("entry " + std::to_string(i))));
        }
        auto range = tree.compact_range();
        CHECK(range.size() == start);
        CHECK(*range.root() == *tree.root());
        for (std::uint64_t i = start; i < start + 20; ++i) {
            const std::string entry = "entry " + std::to_string(i);
            REQUIRE(range.append(as_bytes(entry)));
            REQUIRE(tree.append(as_bytes(entry)));
            REQUIRE(*range.root() == *tree.root());
        }
    }
}

TEST_CASE("inclusion verification rejects every tampering", "[core][merkle]") {
    const auto tree = build_tree(HashAlg::sm3, 37);
    const std::uint64_t size = 37;
    const std::uint64_t index = 21;
    const Digest leaf = *tree.leaf(index);
    const Digest root = *tree.root(size);
    const auto proof = *tree.inclusion_proof(index, size);
    const auto verify = [&](const Digest& l, std::uint64_t i, std::uint64_t n,
                            const std::vector<Digest>& p, const Digest& r) {
        return merkle::verify_inclusion(provider(), HashAlg::sm3, l, i, n, p, r);
    };

    REQUIRE(verify(leaf, index, size, proof, root));
    CHECK_FALSE(verify(mutate(leaf), index, size, proof, root));
    CHECK_FALSE(verify(leaf, index, size, proof, mutate(root)));
    CHECK_FALSE(verify(leaf, index + 1, size, proof, root));
    CHECK_FALSE(verify(leaf, index - 1, size, proof, root));
    // A proof's shape depends on the tree size only through the leaf's
    // position. Leaf 21 lies in the complete subtree [0, 32) for every size
    // from 33 to 64, so the same proof reaches the same root for all of them:
    // proofs do not authenticate the tree size, which is why the size must
    // come from the same signed checkpoint as the root.
    CHECK(verify(leaf, index, 33, proof, root));
    CHECK(verify(leaf, index, 64, proof, root));
    CHECK_FALSE(verify(leaf, index, 32, proof, root));
    CHECK_FALSE(verify(leaf, index, 65, proof, root));
    CHECK_FALSE(verify(leaf, size, size, proof, root));
    for (std::size_t i = 0; i < proof.size(); ++i) {
        auto tampered = proof;
        tampered[i] = mutate(tampered[i]);
        CHECK_FALSE(verify(leaf, index, size, tampered, root));
    }
    auto shorter = proof;
    shorter.pop_back();
    CHECK_FALSE(verify(leaf, index, size, shorter, root));
    auto longer = proof;
    longer.push_back(root);
    CHECK_FALSE(verify(leaf, index, size, longer, root));
    auto wrong_size = proof;
    wrong_size[0] = *Digest::from_bytes(Bytes(48, 0));
    CHECK(verify(leaf, index, size, wrong_size, root).error().code == Errc::verification_failed);
    CHECK(verify(leaf, index, size, std::vector<Digest>(65, leaf), root).error().code ==
          Errc::verification_failed);
}

TEST_CASE("consistency verification rejects every tampering", "[core][merkle]") {
    const auto tree = build_tree(HashAlg::sha256, 50);
    const auto verify = [&](std::uint64_t m, std::uint64_t n, const Digest& old_root,
                            const Digest& new_root, const std::vector<Digest>& p) {
        return merkle::verify_consistency(provider(), HashAlg::sha256, m, n, old_root, new_root, p);
    };

    for (const auto& [m, n] : {std::pair<std::uint64_t, std::uint64_t>{13, 50}, {16, 50}, {1, 2}}) {
        INFO(m << " -> " << n);
        const Digest old_root = *tree.root(m);
        const Digest new_root = *tree.root(n);
        const auto proof = *tree.consistency_proof(m, n);
        REQUIRE(verify(m, n, old_root, new_root, proof));
        CHECK_FALSE(verify(m, n, mutate(old_root), new_root, proof));
        CHECK_FALSE(verify(m, n, old_root, mutate(new_root), proof));
        CHECK_FALSE(verify(m + 1, n, old_root, new_root, proof));
        CHECK_FALSE(verify(m, n * 2, old_root, new_root, proof));
        CHECK_FALSE(verify(n, m, new_root, old_root, proof));
        CHECK_FALSE(verify(m, n, old_root, new_root, {}));
        for (std::size_t i = 0; i < proof.size(); ++i) {
            auto tampered = proof;
            tampered[i] = mutate(tampered[i]);
            CHECK_FALSE(verify(m, n, old_root, new_root, tampered));
        }
        auto longer = proof;
        longer.push_back(new_root);
        CHECK_FALSE(verify(m, n, old_root, new_root, longer));
    }

    // A forked history: same size, different content.
    const auto fork = build_tree(HashAlg::sha256, 13);
    merkle::Tree forked(provider(), HashAlg::sha256);
    for (int i = 0; i < 13; ++i) {
        const std::string entry = i == 7 ? "rewritten" : "entry " + std::to_string(i);
        REQUIRE(forked.append(as_bytes(entry)));
    }
    const auto proof = *tree.consistency_proof(13, 50);
    CHECK(verify(13, 50, *fork.root(), *tree.root(50), proof));
    CHECK_FALSE(verify(13, 50, *forked.root(), *tree.root(50), proof));
}

TEST_CASE("edge cases for empty and equal trees", "[core][merkle]") {
    merkle::Tree tree(provider(), HashAlg::sha256);
    const auto empty = tree.root();
    REQUIRE(empty);
    CHECK(to_hex(empty->bytes()) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(tree.inclusion_proof(0, 0).error().code == Errc::invalid_argument);
    CHECK(tree.root(1).error().code == Errc::invalid_argument);

    REQUIRE(tree.append(as_bytes("a")));
    REQUIRE(tree.append(as_bytes("b")));
    const Digest root = *tree.root();
    CHECK(tree.consistency_proof(2, 1).error().code == Errc::invalid_argument);
    CHECK(tree.consistency_proof(0, 3).error().code == Errc::invalid_argument);
    CHECK(tree.consistency_proof(0, 2)->empty());
    CHECK(tree.consistency_proof(2, 2)->empty());

    CHECK(merkle::verify_consistency(provider(), HashAlg::sha256, 0, 2, *empty, root, {}));
    CHECK_FALSE(merkle::verify_consistency(provider(), HashAlg::sha256, 0, 2, root, root, {}));
    CHECK(merkle::verify_consistency(provider(), HashAlg::sha256, 2, 2, root, root, {}));
    CHECK_FALSE(merkle::verify_consistency(provider(), HashAlg::sha256, 2, 2, root, *empty, {}));

    const Digest leaf = *tree.leaf(0);
    CHECK(tree.append_leaf_hash(*Digest::from_bytes(Bytes(20, 0))).error().code ==
          Errc::invalid_argument);
    CHECK(tree.size() == 2);
    REQUIRE(tree.append_leaf_hash(leaf));
    CHECK(*tree.leaf(2) == leaf);
}

TEST_CASE("historical roots are stable as the tree grows", "[core][merkle]") {
    merkle::Tree tree(provider(), HashAlg::sm3);
    std::vector<Digest> recorded;
    std::mt19937_64 rng(7);
    for (int i = 0; i < 200; ++i) {
        Bytes entry(rng() % 40);
        for (auto& b : entry) {
            b = static_cast<std::uint8_t>(rng());
        }
        REQUIRE(tree.append(entry));
        recorded.push_back(*tree.root());
    }
    for (std::uint64_t n = 1; n <= tree.size(); ++n) {
        CHECK(*tree.root(n) == recorded[n - 1]);
    }
}
