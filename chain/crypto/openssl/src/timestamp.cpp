// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// RFC 3161 time-stamp tokens: reading and checking them, asking an authority
// for one, and the certificates a verifier trusts. All of it is OpenSSL's
// code (its TS, PKCS #7, and X.509 modules); this file only adapts it.

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

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

using Pkcs7Ptr = std::unique_ptr<PKCS7, Deleter<&PKCS7_free>>;
using TstInfoPtr = std::unique_ptr<TS_TST_INFO, Deleter<&TS_TST_INFO_free>>;
using TsReqPtr = std::unique_ptr<TS_REQ, Deleter<&TS_REQ_free>>;
using TsRespPtr = std::unique_ptr<TS_RESP, Deleter<&TS_RESP_free>>;
using TsMsgImprintPtr = std::unique_ptr<TS_MSG_IMPRINT, Deleter<&TS_MSG_IMPRINT_free>>;
using TsVerifyCtxPtr = std::unique_ptr<TS_VERIFY_CTX, Deleter<&TS_VERIFY_CTX_free>>;
using X509Ptr = std::unique_ptr<X509, Deleter<&X509_free>>;
using X509StorePtr = std::unique_ptr<X509_STORE, Deleter<&X509_STORE_free>>;
using X509AlgorPtr = std::unique_ptr<X509_ALGOR, Deleter<&X509_ALGOR_free>>;
using Asn1IntegerPtr = std::unique_ptr<ASN1_INTEGER, Deleter<&ASN1_INTEGER_free>>;
using Asn1TimePtr = std::unique_ptr<ASN1_TIME, Deleter<&ASN1_TIME_free>>;
using BioPtr = std::unique_ptr<BIO, Deleter<&BIO_free>>;

/// Whatever OpenSSL queued while failing, dropped: callers say what failed.
void forget_errors() noexcept {
    ERR_clear_error();
}

[[nodiscard]] std::optional<HashAlg> hash_of_nid(int nid) noexcept {
    switch (nid) {
    case NID_sha256:
        return HashAlg::sha256;
    case NID_sha384:
        return HashAlg::sha384;
    case NID_sha512:
        return HashAlg::sha512;
    case NID_sm3:
        return HashAlg::sm3;
    default:
        return std::nullopt;
    }
}

[[nodiscard]] int nid_of_hash(HashAlg alg) noexcept {
    switch (alg) {
    case HashAlg::sha256:
        return NID_sha256;
    case HashAlg::sha384:
        return NID_sha384;
    case HashAlg::sha512:
        return NID_sha512;
    case HashAlg::sm3:
        return NID_sm3;
    }
    return NID_undef;
}

[[nodiscard]] Bytes bytes_of(const ASN1_STRING* s) {
    const unsigned char* data = ASN1_STRING_get0_data(s);
    return Bytes(data, data + ASN1_STRING_length(s));
}

/// A GeneralizedTime as Unix time in milliseconds: the whole seconds from
/// OpenSSL, the fraction (RFC 3161 allows one) from its text, to the
/// millisecond, rounded down.
[[nodiscard]] Result<std::uint64_t> unix_millis(const ASN1_GENERALIZEDTIME* time) {
    const Asn1TimePtr epoch(ASN1_TIME_set(nullptr, 0));
    int days = 0;
    int seconds = 0;
    if (!epoch || ASN1_TIME_diff(&days, &seconds, epoch.get(), time) != 1 || days < 0 ||
        seconds < 0) {
        forget_errors();
        return fail(Errc::malformed, "the time-stamp token's time does not parse");
    }
    std::uint64_t millis =
        (static_cast<std::uint64_t>(days) * 86'400 + static_cast<std::uint64_t>(seconds)) * 1000;
    const unsigned char* text = ASN1_STRING_get0_data(time);
    const auto length = static_cast<std::size_t>(ASN1_STRING_length(time));
    const auto* dot = std::find(text, text + length, '.');
    std::uint64_t scale = 100;
    for (const auto* digit = dot + 1; dot != text + length && digit < text + length && scale > 0;
         ++digit, scale /= 10) {
        if (*digit < '0' || *digit > '9') {
            break;
        }
        millis += static_cast<std::uint64_t>(*digit - '0') * scale;
    }
    return millis;
}

/// The accuracy a token states, in milliseconds, rounded up.
[[nodiscard]] std::uint64_t accuracy_millis(const TS_ACCURACY* accuracy) noexcept {
    if (accuracy == nullptr) {
        return 0;
    }
    auto value = [](const ASN1_INTEGER* n) -> std::uint64_t {
        std::uint64_t v = 0;
        return n != nullptr && ASN1_INTEGER_get_uint64(&v, n) == 1 ? v : 0;
    };
    const std::uint64_t micros = value(TS_ACCURACY_get_micros(accuracy));
    return value(TS_ACCURACY_get_seconds(accuracy)) * 1000 +
           value(TS_ACCURACY_get_millis(accuracy)) + (micros + 999) / 1000;
}

[[nodiscard]] std::string subject_of(X509* certificate) {
    const BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio ||
        X509_NAME_print_ex(bio.get(), X509_get_subject_name(certificate), 0, XN_FLAG_RFC2253) < 0) {
        forget_errors();
        return {};
    }
    char* data = nullptr;
    const long length = BIO_get_mem_data(bio.get(), &data);
    return length > 0 ? std::string(data, static_cast<std::size_t>(length)) : std::string();
}

[[nodiscard]] Result<Bytes> key_digest(X509* certificate) {
    unsigned char* der = nullptr;
    const int length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(certificate), &der);
    if (length <= 0) {
        forget_errors();
        return fail(Errc::malformed, "the authority's certificate has no readable public key");
    }
    Bytes digest(EVP_MAX_MD_SIZE);
    unsigned int size = 0;
    const bool ok = EVP_Digest(der, static_cast<std::size_t>(length), digest.data(), &size,
                               EVP_sha256(), nullptr) == 1;
    OPENSSL_free(der);
    if (!ok) {
        forget_errors();
        return fail(Errc::crypto_failure, "hashing the authority's public key failed");
    }
    digest.resize(size);
    return digest;
}

[[nodiscard]] Result<X509Ptr> parse_certificate(ByteView der) {
    const unsigned char* p = der.data();
    X509Ptr certificate(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
    if (!certificate || p != der.data() + der.size()) {
        forget_errors();
        return fail(Errc::invalid_argument, "a trusted root is not a DER certificate");
    }
    return certificate;
}

/// Verifies the token's signature, its signing-certificate attribute, and its
/// signing certificate's chain to an anchor in `store`, for time stamping, at
/// `at` (Unix seconds).
[[nodiscard]] bool token_verifies(PKCS7* token, X509StorePtr store, std::int64_t at) {
    X509_VERIFY_PARAM* param = X509_STORE_get0_param(store.get());
    X509_VERIFY_PARAM_set_time(param, static_cast<time_t>(at));
    const TsVerifyCtxPtr context(TS_VERIFY_CTX_new());
    if (!context) {
        forget_errors();
        return false;
    }
    TS_VERIFY_CTX_set_flags(context.get(), TS_VFY_SIGNATURE);
    TS_VERIFY_CTX_set0_store(context.get(), store.release());
    const bool ok = TS_RESP_verify_token(context.get(), token) == 1;
    forget_errors();
    return ok;
}

} // namespace

Result<TimestampToken> Provider::do_read_timestamp(ByteView token,
                                                   std::span<const Bytes> trusted_roots) const {
    const unsigned char* p = token.data();
    const Pkcs7Ptr pkcs7(d2i_PKCS7(nullptr, &p, static_cast<long>(token.size())));
    if (!pkcs7 || p != token.data() + token.size()) {
        forget_errors();
        return fail(Errc::malformed, "not a time-stamp token (DER CMS SignedData)");
    }
    const TstInfoPtr info(PKCS7_to_TS_TST_INFO(pkcs7.get()));
    if (!info) {
        forget_errors();
        return fail(Errc::malformed, "the token holds no time-stamp information (TSTInfo)");
    }

    TimestampToken out;
    const auto time = unix_millis(TS_TST_INFO_get_time(info.get()));
    if (!time) {
        return std::unexpected(time.error());
    }
    out.time = *time;
    out.accuracy = accuracy_millis(TS_TST_INFO_get_accuracy(info.get()));
    TS_MSG_IMPRINT* imprint = TS_TST_INFO_get_msg_imprint(info.get());
    const ASN1_OBJECT* algorithm = nullptr;
    X509_ALGOR_get0(&algorithm, nullptr, nullptr, TS_MSG_IMPRINT_get_algo(imprint));
    out.imprint_alg = hash_of_nid(OBJ_obj2nid(algorithm));
    out.imprint = bytes_of(TS_MSG_IMPRINT_get_msg(imprint));

    // The signing certificate, which a verifier needs: an authority asked
    // with certReq puts it in the token.
    STACK_OF(X509)* signers = PKCS7_get0_signers(pkcs7.get(), nullptr, 0);
    if (signers == nullptr || sk_X509_num(signers) != 1) {
        sk_X509_free(signers);
        forget_errors();
        return fail(Errc::malformed,
                    "the token does not carry its signing certificate (ask with certReq)");
    }
    X509* signer = sk_X509_value(signers, 0);
    sk_X509_free(signers);
    out.authority = subject_of(signer);
    auto key = key_digest(signer);
    if (!key) {
        return std::unexpected(key.error());
    }
    out.authority_key = std::move(*key);

    const auto at = static_cast<std::int64_t>(out.time / 1000);
    // First as its own anchor: does the token verify at all?
    X509StorePtr own(X509_STORE_new());
    if (!own || X509_STORE_add_cert(own.get(), signer) != 1) {
        forget_errors();
        return fail(Errc::crypto_failure, "preparing to verify the token failed");
    }
    X509_STORE_set_flags(own.get(), X509_V_FLAG_PARTIAL_CHAIN);
    if (!token_verifies(pkcs7.get(), std::move(own), at)) {
        return fail(Errc::verification_failed,
                    "the time-stamp token does not verify with its signing certificate");
    }
    // Then with the roots the caller trusts.
    if (!trusted_roots.empty()) {
        X509StorePtr roots(X509_STORE_new());
        if (!roots) {
            forget_errors();
            return fail(Errc::crypto_failure, "preparing to verify the token failed");
        }
        for (const Bytes& der : trusted_roots) {
            const auto root = parse_certificate(der);
            if (!root) {
                return std::unexpected(root.error());
            }
            if (X509_STORE_add_cert(roots.get(), root->get()) != 1) {
                forget_errors();
            }
        }
        out.trusted = token_verifies(pkcs7.get(), std::move(roots), at);
    }
    return out;
}

Result<Bytes> timestamp_request(HashAlg alg, ByteView imprint, std::uint64_t nonce) {
    const TsReqPtr request(TS_REQ_new());
    const TsMsgImprintPtr message(TS_MSG_IMPRINT_new());
    const X509AlgorPtr algorithm(X509_ALGOR_new());
    const Asn1IntegerPtr nonce_value(ASN1_INTEGER_new());
    const int nid = nid_of_hash(alg);
    if (!request || !message || !algorithm || !nonce_value || nid == NID_undef ||
        X509_ALGOR_set0(algorithm.get(), OBJ_nid2obj(nid), V_ASN1_NULL, nullptr) != 1 ||
        TS_MSG_IMPRINT_set_algo(message.get(), algorithm.get()) != 1 ||
        TS_MSG_IMPRINT_set_msg(message.get(), const_cast<unsigned char*>(imprint.data()),
                               static_cast<int>(imprint.size())) != 1 ||
        ASN1_INTEGER_set_uint64(nonce_value.get(), nonce) != 1 ||
        TS_REQ_set_version(request.get(), 1) != 1 ||
        TS_REQ_set_msg_imprint(request.get(), message.get()) != 1 ||
        TS_REQ_set_nonce(request.get(), nonce_value.get()) != 1 ||
        TS_REQ_set_cert_req(request.get(), 1) != 1) {
        forget_errors();
        return fail(Errc::crypto_failure, "building the time-stamp request failed");
    }
    unsigned char* der = nullptr;
    const int length = i2d_TS_REQ(request.get(), &der);
    if (length <= 0) {
        forget_errors();
        return fail(Errc::crypto_failure, "encoding the time-stamp request failed");
    }
    Bytes out(der, der + length);
    OPENSSL_free(der);
    return out;
}

Result<Bytes> timestamp_from_response(ByteView response, HashAlg alg, ByteView imprint,
                                      std::uint64_t nonce) {
    const unsigned char* p = response.data();
    const TsRespPtr parsed(d2i_TS_RESP(nullptr, &p, static_cast<long>(response.size())));
    if (!parsed || p != response.data() + response.size()) {
        forget_errors();
        return fail(Errc::malformed, "the authority's answer is not a time-stamp response");
    }
    const ASN1_INTEGER* status = TS_STATUS_INFO_get0_status(TS_RESP_get_status_info(parsed.get()));
    std::uint64_t code = 0;
    if (status == nullptr || ASN1_INTEGER_get_uint64(&code, status) != 1 || code > 1) {
        forget_errors();
        return fail(Errc::rejected, "the time-stamp authority did not grant the request");
    }
    PKCS7* token = TS_RESP_get_token(parsed.get());
    TS_TST_INFO* info = TS_RESP_get_tst_info(parsed.get());
    if (token == nullptr || info == nullptr) {
        return fail(Errc::malformed, "the authority's answer holds no token");
    }
    TS_MSG_IMPRINT* answered = TS_TST_INFO_get_msg_imprint(info);
    const ASN1_OBJECT* algorithm = nullptr;
    X509_ALGOR_get0(&algorithm, nullptr, nullptr, TS_MSG_IMPRINT_get_algo(answered));
    const Bytes answered_imprint = bytes_of(TS_MSG_IMPRINT_get_msg(answered));
    const ASN1_INTEGER* answered_nonce = TS_TST_INFO_get_nonce(info);
    std::uint64_t answered_nonce_value = 0;
    if (OBJ_obj2nid(algorithm) != nid_of_hash(alg) ||
        !std::ranges::equal(answered_imprint, imprint) || answered_nonce == nullptr ||
        ASN1_INTEGER_get_uint64(&answered_nonce_value, answered_nonce) != 1 ||
        answered_nonce_value != nonce) {
        forget_errors();
        return fail(Errc::verification_failed,
                    "the authority's token does not answer the request (imprint or nonce)");
    }
    unsigned char* der = nullptr;
    const int length = i2d_PKCS7(token, &der);
    if (length <= 0) {
        forget_errors();
        return fail(Errc::crypto_failure, "encoding the token failed");
    }
    Bytes out(der, der + length);
    OPENSSL_free(der);
    return out;
}

Result<std::vector<Bytes>> read_certificates(ByteView data) {
    std::vector<Bytes> out;
    auto encode = [&](X509* certificate) -> Status {
        unsigned char* der = nullptr;
        const int length = i2d_X509(certificate, &der);
        if (length <= 0) {
            forget_errors();
            return fail(Errc::crypto_failure, "encoding a certificate failed");
        }
        out.emplace_back(der, der + length);
        OPENSSL_free(der);
        return {};
    };
    // One DER certificate.
    {
        const unsigned char* p = data.data();
        const X509Ptr certificate(d2i_X509(nullptr, &p, static_cast<long>(data.size())));
        if (certificate && p == data.data() + data.size()) {
            if (const Status encoded = encode(certificate.get()); !encoded) {
                return std::unexpected(encoded.error());
            }
            return out;
        }
        forget_errors();
    }
    // PEM text, one certificate after another.
    const BioPtr bio(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())));
    if (!bio) {
        return fail(Errc::crypto_failure, "reading certificates failed");
    }
    while (true) {
        X509Ptr certificate(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
        if (!certificate) {
            break;
        }
        if (const Status encoded = encode(certificate.get()); !encoded) {
            return std::unexpected(encoded.error());
        }
    }
    // The loop ends at the end of the text, or at a block that does not parse.
    const unsigned long last = ERR_peek_last_error();
    forget_errors();
    if (out.empty()) {
        return fail(Errc::invalid_argument, "no certificate in the file (PEM or DER)");
    }
    if (last != 0 && ERR_GET_REASON(last) != PEM_R_NO_START_LINE) {
        return fail(Errc::invalid_argument, "a certificate in the file does not parse");
    }
    return out;
}

} // namespace cexchain::crypto::openssl
