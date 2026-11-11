// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/crypto/openssl.hpp>

// A time-stamp authority for tests (RFC 3161): a root and a time-stamping
// certificate it issued, valid from 2020 to 2040, on P-256 keys, answering
// requests with OpenSSL's own responder at a time the test chooses.
namespace kanhe::test {

class TimestampAuthority {
public:
    explicit TimestampAuthority(const std::string& name = "Test Time-Stamp Authority")
        : root_key_(EVP_EC_gen("P-256")), key_(EVP_EC_gen("P-256")) {
        if (!root_key_ || !key_) {
            throw std::runtime_error("generating the authority's keys failed");
        }
        root_.reset(
            make(root_key_.get(), root_key_.get(), nullptr, name + " Root", 1, true, false));
        certificate_.reset(make(key_.get(), root_key_.get(), root_.get(), name, 2, false, true));
    }

    [[nodiscard]] Bytes root_der() const { return der(root_.get()); }
    [[nodiscard]] Bytes certificate_der() const { return der(certificate_.get()); }
    [[nodiscard]] std::string root_pem() const {
        const std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
        PEM_write_bio_X509(bio.get(), root_.get());
        char* data = nullptr;
        const long length = BIO_get_mem_data(bio.get(), &data);
        return std::string(data, static_cast<std::size_t>(length));
    }

    /// The response to a TimeStampReq (DER), dated `at` (Unix time in
    /// milliseconds), stating `accuracy_seconds`.
    [[nodiscard]] Bytes respond(ByteView request, std::uint64_t at,
                                int accuracy_seconds = 1) const {
        const std::unique_ptr<TS_RESP_CTX, decltype(&TS_RESP_CTX_free)> context(TS_RESP_CTX_new(),
                                                                                &TS_RESP_CTX_free);
        ASN1_OBJECT* policy = OBJ_txt2obj("1.2.3.4.1", 1);
        STACK_OF(X509)* chain = sk_X509_new_null();
        sk_X509_push(chain, root_.get());
        TS_RESP_CTX_set_signer_cert(context.get(), certificate_.get());
        TS_RESP_CTX_set_signer_key(context.get(), key_.get());
        TS_RESP_CTX_set_def_policy(context.get(), policy);
        TS_RESP_CTX_add_md(context.get(), EVP_sha256());
        TS_RESP_CTX_add_md(context.get(), EVP_sm3());
        TS_RESP_CTX_set_accuracy(context.get(), accuracy_seconds, 0, 0);
        TS_RESP_CTX_set_clock_precision_digits(context.get(), 3);
        TS_RESP_CTX_set_signer_digest(context.get(), EVP_sha256());
        TS_RESP_CTX_set_certs(context.get(), chain);
        std::uint64_t time = at;
        TS_RESP_CTX_set_time_cb(context.get(), &clock, &time);
        sk_X509_free(chain);
        ASN1_OBJECT_free(policy);
        const std::unique_ptr<BIO, decltype(&BIO_free)> in(
            BIO_new_mem_buf(request.data(), static_cast<int>(request.size())), &BIO_free);
        const std::unique_ptr<TS_RESP, decltype(&TS_RESP_free)> response(
            TS_RESP_create_response(context.get(), in.get()), &TS_RESP_free);
        if (!response) {
            throw std::runtime_error("the test authority could not answer");
        }
        unsigned char* bytes = nullptr;
        const int length = i2d_TS_RESP(response.get(), &bytes);
        Bytes out(bytes, bytes + length);
        OPENSSL_free(bytes);
        return out;
    }

    /// A token over `imprint` (a digest under `alg`), dated `at`.
    [[nodiscard]] Bytes token(crypto::HashAlg alg, ByteView imprint, std::uint64_t at,
                              int accuracy_seconds = 1) const {
        const std::uint64_t nonce = 0x1234'5678'9abcULL;
        const auto request = crypto::openssl::timestamp_request(alg, imprint, nonce);
        const auto token = crypto::openssl::timestamp_from_response(
            respond(*request, at, accuracy_seconds), alg, imprint, nonce);
        if (!token) {
            throw std::runtime_error("the test authority's answer holds no token");
        }
        return *token;
    }

private:
    struct KeyFree {
        void operator()(EVP_PKEY* key) const noexcept { EVP_PKEY_free(key); }
    };
    struct CertificateFree {
        void operator()(X509* certificate) const noexcept { X509_free(certificate); }
    };

    static int clock(TS_RESP_CTX* /*context*/, void* data, long* seconds, long* micros) {
        const std::uint64_t at = *static_cast<const std::uint64_t*>(data);
        *seconds = static_cast<long>(at / 1000);
        *micros = static_cast<long>(at % 1000 * 1000);
        return 1;
    }

    [[nodiscard]] static Bytes der(X509* certificate) {
        unsigned char* bytes = nullptr;
        const int length = i2d_X509(certificate, &bytes);
        Bytes out(bytes, bytes + length);
        OPENSSL_free(bytes);
        return out;
    }

    static void extend(X509* certificate, X509* issuer, int nid, const char* value) {
        X509V3_CTX context;
        X509V3_set_ctx_nodb(&context);
        X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
        X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, &context, nid, value);
        X509_add_ext(certificate, extension, -1);
        X509_EXTENSION_free(extension);
    }

    [[nodiscard]] static X509* make(EVP_PKEY* key, EVP_PKEY* issuer_key, X509* issuer,
                                    const std::string& name, long serial, bool ca,
                                    bool time_stamping) {
        X509* certificate = X509_new();
        X509_set_version(certificate, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(certificate), serial);
        ASN1_TIME_set_string(X509_getm_notBefore(certificate), "20200101000000Z");
        ASN1_TIME_set_string(X509_getm_notAfter(certificate), "20400101000000Z");
        X509_set_pubkey(certificate, key);
        X509_NAME* subject = X509_get_subject_name(certificate);
        X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(name.c_str()), -1, -1, 0);
        X509_set_issuer_name(certificate,
                             issuer != nullptr ? X509_get_subject_name(issuer) : subject);
        X509* signer = issuer != nullptr ? issuer : certificate;
        extend(certificate, signer, NID_basic_constraints,
               ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
        extend(certificate, signer, NID_key_usage,
               ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature");
        extend(certificate, signer, NID_subject_key_identifier, "hash");
        if (issuer != nullptr) {
            extend(certificate, signer, NID_authority_key_identifier, "keyid");
        }
        if (time_stamping) {
            extend(certificate, signer, NID_ext_key_usage, "critical,timeStamping");
        }
        X509_sign(certificate, issuer_key, EVP_sha256());
        return certificate;
    }

    std::unique_ptr<EVP_PKEY, KeyFree> root_key_;
    std::unique_ptr<EVP_PKEY, KeyFree> key_;
    std::unique_ptr<X509, CertificateFree> root_;
    std::unique_ptr<X509, CertificateFree> certificate_;
};

} // namespace kanhe::test
