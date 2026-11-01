// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <memory>
#include <string_view>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

#include <cexchain/crypto/openssl.hpp>

namespace cexchain::crypto::openssl {

namespace {

struct PkeyFree {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
struct PkeyCtxFree {
    void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
};
struct MdCtxFree {
    void operator()(EVP_MD_CTX* p) const noexcept { EVP_MD_CTX_free(p); }
};
struct BldFree {
    void operator()(OSSL_PARAM_BLD* p) const noexcept { OSSL_PARAM_BLD_free(p); }
};
struct ParamFree {
    void operator()(OSSL_PARAM* p) const noexcept { OSSL_PARAM_free(p); }
};
struct BnFree {
    void operator()(BIGNUM* p) const noexcept { BN_free(p); }
};
struct SigFree {
    void operator()(ECDSA_SIG* p) const noexcept { ECDSA_SIG_free(p); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyFree>;

/// A key from its parameters, as OpenSSL's provider builds it.
Pkey from_params(const char* type, OSSL_PARAM_BLD* bld) {
    const std::unique_ptr<OSSL_PARAM, ParamFree> params(OSSL_PARAM_BLD_to_param(bld));
    const std::unique_ptr<EVP_PKEY_CTX, PkeyCtxFree> ctx(
        EVP_PKEY_CTX_new_from_name(nullptr, type, nullptr));
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1) {
        return nullptr;
    }
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &key, EVP_PKEY_PUBLIC_KEY, params.get()) != 1) {
        return nullptr;
    }
    return Pkey(key);
}

Pkey rsa_key(const JoseKey& k) {
    const std::unique_ptr<BIGNUM, BnFree> n(
        BN_bin2bn(k.n.data(), static_cast<int>(k.n.size()), nullptr));
    const std::unique_ptr<BIGNUM, BnFree> e(
        BN_bin2bn(k.e.data(), static_cast<int>(k.e.size()), nullptr));
    const std::unique_ptr<OSSL_PARAM_BLD, BldFree> bld(OSSL_PARAM_BLD_new());
    if (!n || !e || !bld ||
        OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_N, n.get()) != 1 ||
        OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_E, e.get()) != 1) {
        return nullptr;
    }
    Pkey key = from_params("RSA", bld.get());
    if (key && EVP_PKEY_get_bits(key.get()) < 2048) {
        return nullptr;
    }
    return key;
}

Pkey p256_key(const JoseKey& k) {
    if (k.x.size() != 32 || k.y.size() != 32) {
        return nullptr;
    }
    Bytes point{0x04};
    point.insert(point.end(), k.x.begin(), k.x.end());
    point.insert(point.end(), k.y.begin(), k.y.end());
    const std::unique_ptr<OSSL_PARAM_BLD, BldFree> bld(OSSL_PARAM_BLD_new());
    if (!bld ||
        OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) !=
            1 ||
        OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, point.data(),
                                         point.size()) != 1) {
        return nullptr;
    }
    return from_params("EC", bld.get());
}

/// ES256's r || s as the DER ECDSA-Sig-Value OpenSSL verifies.
Bytes der_of(ByteView raw) {
    std::unique_ptr<ECDSA_SIG, SigFree> sig(ECDSA_SIG_new());
    BIGNUM* r = BN_bin2bn(raw.data(), 32, nullptr);
    BIGNUM* s = BN_bin2bn(raw.data() + 32, 32, nullptr);
    if (!sig || r == nullptr || s == nullptr || ECDSA_SIG_set0(sig.get(), r, s) != 1) {
        BN_free(r);
        BN_free(s);
        return {};
    }
    const int size = i2d_ECDSA_SIG(sig.get(), nullptr);
    if (size <= 0) {
        return {};
    }
    Bytes out(static_cast<std::size_t>(size));
    unsigned char* at = out.data();
    i2d_ECDSA_SIG(sig.get(), &at);
    return out;
}

} // namespace

bool verify_jose(std::string_view alg, const JoseKey& key, ByteView signing_input,
                 ByteView signature) {
    Pkey pkey;
    const EVP_MD* md = EVP_sha256();
    Bytes der;
    ByteView sig = signature;
    if (alg == "RS256" || alg == "PS256") {
        if (key.type != JoseKey::Type::rsa) {
            return false;
        }
        pkey = rsa_key(key);
    } else if (alg == "ES256") {
        if (key.type != JoseKey::Type::p256 || signature.size() != 64) {
            return false;
        }
        pkey = p256_key(key);
        der = der_of(signature);
        if (der.empty()) {
            return false;
        }
        sig = der;
    } else if (alg == "EdDSA") {
        if (key.type != JoseKey::Type::ed25519 || key.x.size() != 32 || signature.size() != 64) {
            return false;
        }
        pkey = Pkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, key.x.data(), 32));
        md = nullptr; // Ed25519 hashes inside
    } else {
        return false;
    }
    if (!pkey) {
        return false;
    }
    const std::unique_ptr<EVP_MD_CTX, MdCtxFree> ctx(EVP_MD_CTX_new());
    EVP_PKEY_CTX* pctx = nullptr;
    if (!ctx || EVP_DigestVerifyInit(ctx.get(), &pctx, md, nullptr, pkey.get()) != 1) {
        return false;
    }
    if (alg == "PS256" && (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1 ||
                           EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) != 1 ||
                           EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32) != 1)) {
        return false;
    }
    return EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), signing_input.data(),
                            signing_input.size()) == 1;
}

} // namespace cexchain::crypto::openssl
