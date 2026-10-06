// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/decoder.h>
#include <openssl/ec.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <cexchain/crypto/openssl.hpp>

namespace cexchain::crypto::openssl {

namespace {

template <auto Free>
struct Deleter {
    template <class T>
    void operator()(T* p) const noexcept {
        Free(p);
    }
};

using PkeyPtr = std::unique_ptr<EVP_PKEY, Deleter<&EVP_PKEY_free>>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, Deleter<&EVP_PKEY_CTX_free>>;
using MdPtr = std::unique_ptr<EVP_MD, Deleter<&EVP_MD_free>>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, Deleter<&EVP_MD_CTX_free>>;
using SignaturePtr = std::unique_ptr<EVP_SIGNATURE, Deleter<&EVP_SIGNATURE_free>>;
using KeymgmtPtr = std::unique_ptr<EVP_KEYMGMT, Deleter<&EVP_KEYMGMT_free>>;
using EcdsaSigPtr = std::unique_ptr<ECDSA_SIG, Deleter<&ECDSA_SIG_free>>;
using BignumPtr = std::unique_ptr<BIGNUM, Deleter<&BN_free>>;
using EncoderCtxPtr = std::unique_ptr<OSSL_ENCODER_CTX, Deleter<&OSSL_ENCODER_CTX_free>>;
using DecoderCtxPtr = std::unique_ptr<OSSL_DECODER_CTX, Deleter<&OSSL_DECODER_CTX_free>>;
using Pkcs8InfoPtr = std::unique_ptr<PKCS8_PRIV_KEY_INFO, Deleter<&PKCS8_PRIV_KEY_INFO_free>>;
using X509SigPtr = std::unique_ptr<X509_SIG, Deleter<&X509_SIG_free>>;
using X509AlgorPtr = std::unique_ptr<X509_ALGOR, Deleter<&X509_ALGOR_free>>;

constexpr std::size_t ec_scalar_size = 32;
constexpr std::uint8_t sec1_uncompressed_prefix = 0x04;

/// Returns an error after discarding OpenSSL's thread-local error queue, so
/// stale entries never surface in unrelated calls.
std::unexpected<Error> openssl_fail(Errc code, std::string_view detail) {
    ERR_clear_error();
    return fail(code, detail);
}

/// OpenSSL may treat a null pointer as an error even when the length is zero.
const unsigned char* data_or_empty(ByteView bytes) noexcept {
    static constexpr unsigned char empty = 0;
    return bytes.empty() ? &empty : bytes.data();
}

struct SigSpec {
    const char* key_type;  ///< OpenSSL key management name.
    const char* group;     ///< EC group, or nullptr.
    const char* digest;    ///< Digest for hash-then-sign algorithms, or nullptr.
    const char* signature; ///< OpenSSL signature algorithm name.
};

SigSpec spec(SigAlg alg) noexcept {
    switch (alg) {
    case SigAlg::esp256:
        return {"EC", "P-256", "SHA256", "ECDSA"};
    case SigAlg::ed25519:
        return {"ED25519", nullptr, nullptr, "ED25519"};
    case SigAlg::ml_dsa_44:
        return {"ML-DSA-44", nullptr, nullptr, "ML-DSA-44"};
    case SigAlg::ml_dsa_65:
        return {"ML-DSA-65", nullptr, nullptr, "ML-DSA-65"};
    case SigAlg::ml_dsa_87:
        return {"ML-DSA-87", nullptr, nullptr, "ML-DSA-87"};
    case SigAlg::sm2_sm3:
        return {"SM2", "SM2", "SM3", "SM2"};
    }
    return {nullptr, nullptr, nullptr, nullptr};
}

bool is_ec(SigAlg alg) noexcept {
    return alg == SigAlg::esp256 || alg == SigAlg::sm2_sm3;
}

const char* digest_name(HashAlg alg) noexcept {
    switch (alg) {
    case HashAlg::sha256:
        return "SHA256";
    case HashAlg::sha384:
        return "SHA384";
    case HashAlg::sha512:
        return "SHA512";
    case HashAlg::sm3:
        return "SM3";
    }
    return nullptr;
}

std::size_t hash_index(HashAlg alg) noexcept {
    for (std::size_t i = 0; i < all_hash_algs.size(); ++i) {
        if (all_hash_algs[i] == alg) {
            return i;
        }
    }
    return all_hash_algs.size();
}

std::size_t sig_index(SigAlg alg) noexcept {
    for (std::size_t i = 0; i < all_sig_algs.size(); ++i) {
        if (all_sig_algs[i] == alg) {
            return i;
        }
    }
    return all_sig_algs.size();
}

/// Signature parameters. SM2 binds the signer's distinguishing identifier
/// into the signed digest; every other algorithm takes no parameters.
class SignatureParams {
public:
    explicit SignatureParams(SigAlg alg) noexcept : sm2_(alg == SigAlg::sm2_sm3) {
        // OSSL_PARAM stores a non-const pointer, but OpenSSL only reads it.
        params_[0] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_DIST_ID, const_cast<char*>(sm2_distinguishing_id.data()),
            sm2_distinguishing_id.size());
        params_[1] = OSSL_PARAM_construct_end();
    }

    [[nodiscard]] const OSSL_PARAM* get() const noexcept { return sm2_ ? params_.data() : nullptr; }

private:
    bool sm2_;
    std::array<OSSL_PARAM, 2> params_{};
};

Result<Bytes> raw_to_der(ByteView raw) {
    BignumPtr r(BN_bin2bn(raw.data(), ec_scalar_size, nullptr));
    BignumPtr s(BN_bin2bn(raw.data() + ec_scalar_size, ec_scalar_size, nullptr));
    EcdsaSigPtr sig(ECDSA_SIG_new());
    if (!r || !s || !sig || ECDSA_SIG_set0(sig.get(), r.get(), s.get()) != 1) {
        return openssl_fail(Errc::crypto_failure, "could not build an ECDSA signature structure");
    }
    // ECDSA_SIG_set0 took ownership.
    static_cast<void>(r.release());
    static_cast<void>(s.release());

    const int length = i2d_ECDSA_SIG(sig.get(), nullptr);
    if (length <= 0) {
        return openssl_fail(Errc::crypto_failure, "could not DER-encode an ECDSA signature");
    }
    Bytes der(static_cast<std::size_t>(length));
    unsigned char* out = der.data();
    if (i2d_ECDSA_SIG(sig.get(), &out) != length) {
        return openssl_fail(Errc::crypto_failure, "could not DER-encode an ECDSA signature");
    }
    return der;
}

Result<Bytes> der_to_raw(ByteView der) {
    const unsigned char* in = der.data();
    EcdsaSigPtr sig(d2i_ECDSA_SIG(nullptr, &in, static_cast<long>(der.size())));
    if (!sig) {
        return openssl_fail(Errc::crypto_failure,
                            "backend produced an undecodable ECDSA signature");
    }
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig.get(), &r, &s);
    Bytes raw(2 * ec_scalar_size);
    if (BN_bn2binpad(r, raw.data(), ec_scalar_size) != static_cast<int>(ec_scalar_size) ||
        BN_bn2binpad(s, raw.data() + ec_scalar_size, ec_scalar_size) !=
            static_cast<int>(ec_scalar_size)) {
        return openssl_fail(Errc::crypto_failure, "ECDSA signature component is out of range");
    }
    return raw;
}

Result<PkeyPtr> import_public_key(const PublicKey& key) {
    const SigSpec s = spec(key.algorithm);
    if (!is_ec(key.algorithm)) {
        PkeyPtr pkey(EVP_PKEY_new_raw_public_key_ex(nullptr, s.key_type, nullptr, key.bytes.data(),
                                                    key.bytes.size()));
        if (!pkey) {
            return openssl_fail(Errc::invalid_argument, "public key could not be decoded");
        }
        return pkey;
    }

    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, s.key_type, nullptr));
    if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1) {
        return openssl_fail(Errc::crypto_failure, "could not prepare EC key import");
    }
    std::array params{
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(s.group), 0),
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, const_cast<std::uint8_t*>(key.bytes.data()), key.bytes.size()),
        OSSL_PARAM_construct_end()};
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.data()) != 1) {
        return openssl_fail(Errc::invalid_argument, "EC public key is not a valid curve point");
    }
    PkeyPtr pkey(raw);

    // Reject points that are off the curve or not in the prime-order subgroup.
    PkeyCtxPtr check(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr));
    if (!check || EVP_PKEY_public_check(check.get()) != 1) {
        return openssl_fail(Errc::invalid_argument, "EC public key is not a valid curve point");
    }
    return pkey;
}

std::optional<SigAlg> identify(EVP_PKEY* pkey) {
    if (EVP_PKEY_is_a(pkey, "ED25519") == 1) {
        return SigAlg::ed25519;
    }
    if (EVP_PKEY_is_a(pkey, "ML-DSA-44") == 1) {
        return SigAlg::ml_dsa_44;
    }
    if (EVP_PKEY_is_a(pkey, "ML-DSA-65") == 1) {
        return SigAlg::ml_dsa_65;
    }
    if (EVP_PKEY_is_a(pkey, "ML-DSA-87") == 1) {
        return SigAlg::ml_dsa_87;
    }
    if (EVP_PKEY_is_a(pkey, "SM2") == 1) {
        return SigAlg::sm2_sm3;
    }
    if (EVP_PKEY_is_a(pkey, "EC") == 1) {
        std::array<char, 64> group{};
        std::size_t length = 0;
        if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, group.data(),
                                           group.size(), &length) == 1) {
            const std::string_view name(group.data(), length);
            if (name == "prime256v1" || name == "P-256") {
                return SigAlg::esp256;
            }
        }
    }
    return std::nullopt;
}

Result<Bytes> export_public_key(EVP_PKEY* pkey, SigAlg alg) {
    Bytes out(public_key_size(alg));
    std::size_t length = out.size();
    if (is_ec(alg)) {
        if (EVP_PKEY_set_utf8_string_param(pkey, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                           "uncompressed") != 1 ||
            EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, out.data(), out.size(),
                                            &length) != 1) {
            return openssl_fail(Errc::crypto_failure, "could not export EC public key");
        }
    } else if (EVP_PKEY_get_raw_public_key(pkey, out.data(), &length) != 1) {
        return openssl_fail(Errc::crypto_failure, "could not export public key");
    }
    if (length != out.size() || (is_ec(alg) && out.front() != sec1_uncompressed_prefix)) {
        return openssl_fail(Errc::crypto_failure, "exported public key has an unexpected encoding");
    }
    return out;
}

Status verify_with(const PublicKey& key, ByteView message, ByteView signature) {
    auto pkey = import_public_key(key);
    if (!pkey) {
        return std::unexpected(pkey.error());
    }

    Bytes der;
    ByteView encoded = signature;
    if (is_ec(key.algorithm)) {
        auto converted = raw_to_der(signature);
        if (!converted) {
            return std::unexpected(converted.error());
        }
        der = std::move(*converted);
        encoded = der;
    }

    const SignatureParams params(key.algorithm);
    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestVerifyInit_ex(ctx.get(), nullptr, spec(key.algorithm).digest, nullptr,
                                        nullptr, pkey->get(), params.get()) != 1) {
        return openssl_fail(Errc::crypto_failure, "could not initialize signature verification");
    }
    if (EVP_DigestVerify(ctx.get(), encoded.data(), encoded.size(), data_or_empty(message),
                         message.size()) != 1) {
        return openssl_fail(Errc::verification_failed, "signature does not verify");
    }
    return {};
}

Result<Bytes> sign_with(EVP_PKEY* pkey, SigAlg alg, ByteView message) {
    const SignatureParams params(alg);
    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestSignInit_ex(ctx.get(), nullptr, spec(alg).digest, nullptr, nullptr, pkey,
                                      params.get()) != 1) {
        return openssl_fail(Errc::crypto_failure, "could not initialize signing");
    }
    const int max_size = EVP_PKEY_get_size(pkey);
    if (max_size <= 0) {
        return openssl_fail(Errc::crypto_failure, "could not determine the signature size");
    }
    Bytes signature(static_cast<std::size_t>(max_size));
    std::size_t length = signature.size();
    if (EVP_DigestSign(ctx.get(), signature.data(), &length, data_or_empty(message),
                       message.size()) != 1) {
        return openssl_fail(Errc::crypto_failure, "signing failed");
    }
    signature.resize(length);
    if (is_ec(alg)) {
        auto raw = der_to_raw(signature);
        if (raw) {
            canonicalize_signature(alg, *raw);
        }
        return raw;
    }
    if (signature.size() != signature_size(alg)) {
        return openssl_fail(Errc::crypto_failure,
                            "backend produced a signature of unexpected size");
    }
    return signature;
}

/// Confirms that the private key produces signatures that the advertised
/// public key verifies. Catches imported key files whose embedded public key
/// does not belong to the private key.
Status check_key_pair(EVP_PKEY* pkey, const PublicKey& public_key) {
    static constexpr std::string_view probe = "CexChain key pair consistency check";
    const auto signature = sign_with(pkey, public_key.algorithm, as_bytes(probe));
    if (!signature) {
        return std::unexpected(signature.error());
    }
    if (!verify_with(public_key, as_bytes(probe), *signature)) {
        return openssl_fail(Errc::invalid_argument, "private key does not match its public key");
    }
    return {};
}

} // namespace

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

struct Provider::Impl {
    std::array<MdPtr, all_hash_algs.size()> digests;
    std::array<bool, all_sig_algs.size()> signatures{};
};

Provider::Provider() : impl_(std::make_unique<Impl>()) {
    for (std::size_t i = 0; i < all_hash_algs.size(); ++i) {
        impl_->digests[i].reset(EVP_MD_fetch(nullptr, digest_name(all_hash_algs[i]), nullptr));
    }
    for (std::size_t i = 0; i < all_sig_algs.size(); ++i) {
        const SigSpec s = spec(all_sig_algs[i]);
        const SignaturePtr signature(EVP_SIGNATURE_fetch(nullptr, s.signature, nullptr));
        const KeymgmtPtr keymgmt(EVP_KEYMGMT_fetch(nullptr, s.key_type, nullptr));
        bool digest_ok = true;
        if (s.digest != nullptr) {
            const MdPtr md(EVP_MD_fetch(nullptr, s.digest, nullptr));
            digest_ok = md != nullptr;
        }
        impl_->signatures[i] = signature && keymgmt && digest_ok;
    }
    ERR_clear_error();
}

Provider::~Provider() = default;

bool Provider::supports(HashAlg alg) const noexcept {
    const std::size_t i = hash_index(alg);
    return i < impl_->digests.size() && impl_->digests[i] != nullptr;
}

bool Provider::supports(SigAlg alg) const noexcept {
    const std::size_t i = sig_index(alg);
    return i < impl_->signatures.size() && impl_->signatures[i];
}

Result<Digest> Provider::do_digest(HashAlg alg, std::span<const ByteView> parts) const {
    const EVP_MD* md = impl_->digests[hash_index(alg)].get();
    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestInit_ex2(ctx.get(), md, nullptr) != 1) {
        return openssl_fail(Errc::crypto_failure, "could not initialize digest");
    }
    for (const ByteView part : parts) {
        if (!part.empty() && EVP_DigestUpdate(ctx.get(), part.data(), part.size()) != 1) {
            return openssl_fail(Errc::crypto_failure, "digest update failed");
        }
    }
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> out{};
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(ctx.get(), out.data(), &length) != 1) {
        return openssl_fail(Errc::crypto_failure, "digest finalization failed");
    }
    return Digest::from_bytes(ByteView(out.data(), length));
}

Status Provider::do_verify(const PublicKey& key, ByteView message, ByteView signature) const {
    return verify_with(key, message, signature);
}

Status random_bytes(std::span<std::uint8_t> out) {
    // RAND_bytes takes an int length; fill in bounded chunks.
    constexpr std::size_t chunk = 1 << 20;
    for (std::size_t offset = 0; offset < out.size(); offset += chunk) {
        const std::size_t length = std::min(chunk, out.size() - offset);
        if (RAND_bytes(out.data() + offset, static_cast<int>(length)) != 1) {
            return openssl_fail(Errc::crypto_failure, "the random number generator failed");
        }
    }
    return {};
}

// ---------------------------------------------------------------------------
// KeyPair
// ---------------------------------------------------------------------------

struct KeyPair::Impl {
    PkeyPtr pkey;
    PublicKey public_key;
};

KeyPair::KeyPair(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
KeyPair::KeyPair(KeyPair&&) noexcept = default;
KeyPair& KeyPair::operator=(KeyPair&&) noexcept = default;
KeyPair::~KeyPair() = default;

Result<KeyPair> KeyPair::generate(SigAlg alg) {
    const SigSpec s = spec(alg);
    if (s.key_type == nullptr) {
        return fail(Errc::unsupported, "unknown signature algorithm");
    }
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, s.key_type, nullptr));
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1) {
        return openssl_fail(Errc::unsupported,
                            "key generation is not available for this algorithm");
    }
    if (s.group != nullptr) {
        std::array params{OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                           const_cast<char*>(s.group), 0),
                          OSSL_PARAM_construct_end()};
        if (EVP_PKEY_CTX_set_params(ctx.get(), params.data()) != 1) {
            return openssl_fail(Errc::crypto_failure, "could not select the EC group");
        }
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_generate(ctx.get(), &raw) != 1) {
        return openssl_fail(Errc::crypto_failure, "key generation failed");
    }
    PkeyPtr pkey(raw);
    auto public_key = export_public_key(pkey.get(), alg);
    if (!public_key) {
        return std::unexpected(public_key.error());
    }
    return KeyPair(
        std::make_unique<Impl>(Impl{std::move(pkey), PublicKey{alg, std::move(*public_key)}}));
}

Result<KeyPair> KeyPair::from_pkcs8(ByteView der) {
    // The decoder below also accepts other private key formats (such as SEC 1),
    // so first require the outer structure to be exactly one PrivateKeyInfo.
    {
        const unsigned char* begin = data_or_empty(der);
        const unsigned char* cursor = begin;
        const Pkcs8InfoPtr info(
            d2i_PKCS8_PRIV_KEY_INFO(nullptr, &cursor, static_cast<long>(der.size())));
        if (!info || cursor != begin + der.size()) {
            return openssl_fail(Errc::invalid_argument, "input is not a PKCS #8 PrivateKeyInfo");
        }
    }

    EVP_PKEY* raw = nullptr;
    DecoderCtxPtr decoder(OSSL_DECODER_CTX_new_for_pkey(&raw, "DER", "PrivateKeyInfo", nullptr,
                                                        EVP_PKEY_KEYPAIR, nullptr, nullptr));
    if (!decoder) {
        return openssl_fail(Errc::crypto_failure, "could not create a PKCS #8 decoder");
    }
    const unsigned char* in = data_or_empty(der);
    std::size_t remaining = der.size();
    const int decoded = OSSL_DECODER_from_data(decoder.get(), &in, &remaining);
    PkeyPtr pkey(raw);
    if (decoded != 1 || !pkey) {
        return openssl_fail(Errc::invalid_argument, "input is not a PKCS #8 private key");
    }
    if (remaining != 0) {
        return openssl_fail(Errc::malformed, "trailing bytes after the PKCS #8 private key");
    }
    const auto alg = identify(pkey.get());
    if (!alg) {
        return openssl_fail(Errc::unsupported, "private key uses an unsupported algorithm");
    }
    auto public_key = export_public_key(pkey.get(), *alg);
    if (!public_key) {
        return std::unexpected(public_key.error());
    }
    PublicKey advertised{*alg, std::move(*public_key)};
    if (auto s = check_key_pair(pkey.get(), advertised); !s) {
        return std::unexpected(s.error());
    }
    return KeyPair(std::make_unique<Impl>(Impl{std::move(pkey), std::move(advertised)}));
}

Result<KeyPair> KeyPair::from_ed25519_seed(ByteView seed) {
    if (seed.size() != 32) {
        return fail(Errc::invalid_argument, "Ed25519 seed must be 32 bytes");
    }
    PkeyPtr pkey(
        EVP_PKEY_new_raw_private_key_ex(nullptr, "ED25519", nullptr, seed.data(), seed.size()));
    if (!pkey) {
        return openssl_fail(Errc::crypto_failure, "could not import the Ed25519 seed");
    }
    auto public_key = export_public_key(pkey.get(), SigAlg::ed25519);
    if (!public_key) {
        return std::unexpected(public_key.error());
    }
    return KeyPair(std::make_unique<Impl>(
        Impl{std::move(pkey), PublicKey{SigAlg::ed25519, std::move(*public_key)}}));
}

SigAlg KeyPair::algorithm() const noexcept {
    return public_key().algorithm;
}

const PublicKey& KeyPair::public_key() const noexcept {
    static const PublicKey moved_from{SigAlg::ed25519, {}};
    return impl_ ? impl_->public_key : moved_from;
}

Result<Bytes> KeyPair::sign(ByteView message) const {
    if (!impl_) {
        return fail(Errc::invalid_argument, "key pair has been moved from");
    }
    return sign_with(impl_->pkey.get(), algorithm(), message);
}

std::string_view library_version() noexcept {
    return OpenSSL_version(OPENSSL_VERSION);
}

bool is_encrypted_pkcs8(ByteView der) {
    const unsigned char* begin = data_or_empty(der);
    const unsigned char* cursor = begin;
    const X509SigPtr sig(d2i_X509_SIG(nullptr, &cursor, static_cast<long>(der.size())));
    ERR_clear_error();
    return sig && cursor == begin + der.size();
}

Result<KeyPair> KeyPair::from_encrypted_pkcs8(ByteView der, std::string_view passphrase) {
    const unsigned char* begin = data_or_empty(der);
    const unsigned char* cursor = begin;
    const X509SigPtr sig(d2i_X509_SIG(nullptr, &cursor, static_cast<long>(der.size())));
    if (!sig || cursor != begin + der.size()) {
        return openssl_fail(Errc::invalid_argument, "input is not an encrypted PKCS #8 key");
    }
    const Pkcs8InfoPtr info(
        PKCS8_decrypt(sig.get(), passphrase.data(), static_cast<int>(passphrase.size())));
    if (!info) {
        return openssl_fail(Errc::verification_failed, "wrong passphrase, or the key is damaged");
    }
    const int length = i2d_PKCS8_PRIV_KEY_INFO(info.get(), nullptr);
    if (length <= 0) {
        return openssl_fail(Errc::crypto_failure, "could not re-encode the decrypted key");
    }
    SecureBytes plain(Bytes(static_cast<std::size_t>(length)));
    unsigned char* out = const_cast<unsigned char*>(plain.view().data());
    if (i2d_PKCS8_PRIV_KEY_INFO(info.get(), &out) != length) {
        return openssl_fail(Errc::crypto_failure, "could not re-encode the decrypted key");
    }
    return from_pkcs8(plain.view());
}

Result<Bytes> KeyPair::to_encrypted_pkcs8(std::string_view passphrase) const {
    if (!impl_) {
        return fail(Errc::invalid_argument, "key pair has been moved from");
    }
    if (passphrase.empty()) {
        return fail(Errc::invalid_argument, "the passphrase must not be empty");
    }
    Pkcs8InfoPtr info(EVP_PKEY2PKCS8(impl_->pkey.get()));
    if (!info) {
        return openssl_fail(Errc::crypto_failure, "could not encode the private key");
    }
    X509AlgorPtr pbe(
        PKCS5_pbe2_set_scrypt(EVP_aes_256_cbc(), nullptr, 0, nullptr, 1U << 14U, 8, 1));
    if (!pbe) {
        return openssl_fail(Errc::crypto_failure, "could not set up key encryption");
    }
    // PKCS8_set0_pbe takes ownership of the algorithm on success.
    X509SigPtr sig(PKCS8_set0_pbe(passphrase.data(), static_cast<int>(passphrase.size()),
                                  info.get(), pbe.get()));
    if (!sig) {
        return openssl_fail(Errc::crypto_failure, "could not encrypt the private key");
    }
    static_cast<void>(pbe.release());
    const int length = i2d_X509_SIG(sig.get(), nullptr);
    if (length <= 0) {
        return openssl_fail(Errc::crypto_failure, "could not encode the encrypted key");
    }
    Bytes der(static_cast<std::size_t>(length));
    unsigned char* out = der.data();
    if (i2d_X509_SIG(sig.get(), &out) != length) {
        return openssl_fail(Errc::crypto_failure, "could not encode the encrypted key");
    }
    return der;
}

Result<SecureBytes> KeyPair::to_pkcs8() const {
    if (!impl_) {
        return fail(Errc::invalid_argument, "key pair has been moved from");
    }
    EncoderCtxPtr encoder(OSSL_ENCODER_CTX_new_for_pkey(impl_->pkey.get(), EVP_PKEY_KEYPAIR, "DER",
                                                        "PrivateKeyInfo", nullptr));
    unsigned char* data = nullptr;
    std::size_t length = 0;
    if (!encoder || OSSL_ENCODER_to_data(encoder.get(), &data, &length) != 1) {
        return openssl_fail(Errc::crypto_failure, "could not encode the private key");
    }
    SecureBytes out(Bytes(data, data + length));
    OPENSSL_clear_free(data, length);
    return out;
}

} // namespace cexchain::crypto::openssl
