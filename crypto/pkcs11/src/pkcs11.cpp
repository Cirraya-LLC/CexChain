// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <map>
#include <mutex>
#include <p11-kit/pkcs11.h>
#include <vector>

#include <cexchain/crypto/pkcs11.hpp>

namespace cexchain::crypto::pkcs11 {

namespace {

// DER encodings of the curve parameters (CKA_EC_PARAMS).
constexpr std::array<std::uint8_t, 10> oid_p256{0x06, 0x08, 0x2A, 0x86, 0x48,
                                                0xCE, 0x3D, 0x03, 0x01, 0x07};
constexpr std::array<std::uint8_t, 10> oid_sm2{0x06, 0x08, 0x2A, 0x81, 0x1C,
                                               0xCF, 0x55, 0x01, 0x82, 0x2D};
constexpr std::array<std::uint8_t, 5> oid_ed25519{0x06, 0x03, 0x2B, 0x65, 0x70};
constexpr std::string_view printable_ed25519 = "edwards25519";

std::unexpected<Error> token_fail(std::string_view detail) {
    return fail(Errc::crypto_failure, detail);
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/// RFC 3986 percent-decoding.
Result<std::string> percent_decode(std::string_view text) {
    std::string out;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] != '%') {
            out.push_back(text[i]);
            continue;
        }
        if (i + 2 >= text.size()) {
            return fail(Errc::malformed, "a PKCS #11 URI has a broken percent-escape");
        }
        const int hi = hex_value(text[i + 1]);
        const int lo = hex_value(text[i + 2]);
        if (hi < 0 || lo < 0) {
            return fail(Errc::malformed, "a PKCS #11 URI has a broken percent-escape");
        }
        out.push_back(static_cast<char>((hi << 4) | lo));
        i += 2;
    }
    return out;
}

std::string trimmed(const unsigned char* data, std::size_t size) {
    std::string text(reinterpret_cast<const char*>(data), size);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\0')) {
        text.pop_back();
    }
    return text;
}

/// A loaded PKCS #11 module, shared by every key that uses it.
struct Module {
    void* handle = nullptr;
    CK_FUNCTION_LIST_PTR functions = nullptr;
    bool finalize = false;

    Module() = default;
    Module(const Module&) = delete;
    Module& operator=(const Module&) = delete;
    ~Module() {
        if (finalize) {
            functions->C_Finalize(nullptr);
        }
        if (handle != nullptr) {
            ::dlclose(handle);
        }
    }
};

Result<std::shared_ptr<Module>> load_module(const std::string& path) {
    static std::mutex mutex;
    static std::map<std::string, std::weak_ptr<Module>> loaded;
    const std::lock_guard lock(mutex);
    if (auto existing = loaded[path].lock()) {
        return existing;
    }
    auto module = std::make_shared<Module>();
    module->handle = ::dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (module->handle == nullptr) {
        return fail(Errc::not_found, "cannot load the PKCS #11 module");
    }
    auto* get_function_list =
        reinterpret_cast<CK_C_GetFunctionList>(::dlsym(module->handle, "C_GetFunctionList"));
    if (get_function_list == nullptr || get_function_list(&module->functions) != CKR_OK) {
        return token_fail("the library is not a PKCS #11 module");
    }
    CK_C_INITIALIZE_ARGS args{};
    args.flags = CKF_OS_LOCKING_OK;
    const CK_RV rv = module->functions->C_Initialize(&args);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        return token_fail("the PKCS #11 module failed to initialize");
    }
    module->finalize = rv == CKR_OK;
    loaded[path] = module;
    return module;
}

/// Reads one attribute of an object.
Result<Bytes> attribute(CK_FUNCTION_LIST_PTR f, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                        CK_ATTRIBUTE_TYPE type) {
    CK_ATTRIBUTE query{type, nullptr, 0};
    if (f->C_GetAttributeValue(session, object, &query, 1) != CKR_OK ||
        query.ulValueLen == CK_UNAVAILABLE_INFORMATION) {
        return token_fail("the token does not show a key attribute");
    }
    Bytes value(query.ulValueLen);
    query.pValue = value.data();
    if (f->C_GetAttributeValue(session, object, &query, 1) != CKR_OK) {
        return token_fail("the token does not show a key attribute");
    }
    value.resize(query.ulValueLen);
    return value;
}

std::optional<SigAlg> algorithm_of(CK_KEY_TYPE type, ByteView params) {
    auto is = [&](ByteView expected) {
        return std::ranges::equal(params, expected);
    };
    if (type == CKK_EC && is(oid_p256)) {
        return SigAlg::esp256;
    }
    if (type == CKK_EC && is(oid_sm2)) {
        return SigAlg::sm2_sm3;
    }
    const bool printable = params.size() == printable_ed25519.size() + 2 && params[0] == 0x13 &&
                           std::ranges::equal(params.subspan(2), as_bytes(printable_ed25519));
    if ((type == CKK_EC_EDWARDS || type == CKK_EC) && (is(oid_ed25519) || printable)) {
        return SigAlg::ed25519;
    }
    return std::nullopt;
}

/// CKA_EC_POINT is a DER OCTET STRING around the point; some tokens return
/// the bare point.
Bytes unwrap_point(Bytes point, std::size_t size) {
    if (point.size() == size + 2 && point[0] == 0x04 && point[1] == size) {
        return Bytes(point.begin() + 2, point.end());
    }
    return point;
}

/// DER ECDSA-Sig-Value to raw r || s (lenient: tokens are trusted to send
/// well-formed DER; the result is verified anyway).
std::optional<Bytes> der_to_raw(ByteView der) {
    if (der.size() < 8 || der[0] != 0x30) {
        return std::nullopt;
    }
    std::size_t i = der[1] == 0x81 ? 3 : 2;
    Bytes raw(64, 0);
    for (std::size_t k = 0; k < 2; ++k) {
        if (i + 2 > der.size() || der[i] != 0x02) {
            return std::nullopt;
        }
        std::size_t n = der[i + 1];
        i += 2;
        if (i + n > der.size()) {
            return std::nullopt;
        }
        ByteView value = der.subspan(i, n);
        while (value.size() > 32 && value[0] == 0) {
            value = value.subspan(1);
        }
        if (value.size() > 32) {
            return std::nullopt;
        }
        std::ranges::copy(value,
                          raw.begin() + static_cast<std::ptrdiff_t>((k + 1) * 32 - value.size()));
        i += n;
    }
    return raw;
}

} // namespace

bool is_uri(std::string_view text) noexcept {
    return text.starts_with("pkcs11:");
}

Result<KeyUri> parse_uri(std::string_view text) {
    if (!is_uri(text)) {
        return fail(Errc::invalid_argument, "a PKCS #11 URI starts with pkcs11:");
    }
    text.remove_prefix(7);
    const std::size_t question = text.find('?');
    const std::string_view path = text.substr(0, question);
    const std::string_view query =
        question == std::string_view::npos ? std::string_view() : text.substr(question + 1);
    KeyUri uri;
    auto each = [](std::string_view list, char separator, auto&& handle) -> Status {
        while (!list.empty()) {
            const std::size_t end = std::min(list.find(separator), list.size());
            const std::string_view item = list.substr(0, end);
            list.remove_prefix(std::min(end + 1, list.size()));
            if (item.empty()) {
                continue;
            }
            const std::size_t eq = item.find('=');
            if (eq == std::string_view::npos) {
                return fail(Errc::malformed, "a PKCS #11 URI attribute has no value");
            }
            auto value = percent_decode(item.substr(eq + 1));
            if (!value) {
                return std::unexpected(value.error());
            }
            if (auto s = handle(item.substr(0, eq), std::move(*value)); !s) {
                return s;
            }
        }
        return {};
    };
    auto path_status = each(path, ';', [&](std::string_view name, std::string value) -> Status {
        if (name == "token") {
            uri.token = std::move(value);
        } else if (name == "serial") {
            uri.serial = std::move(value);
        } else if (name == "object") {
            uri.object = std::move(value);
        } else if (name == "id") {
            uri.id = Bytes(value.begin(), value.end());
        } else if (name != "type" && name != "manufacturer" && name != "model" &&
                   name != "library-description" && name != "library-manufacturer" &&
                   name != "library-version" && name != "slot-id") {
            return fail(Errc::unsupported, "a PKCS #11 URI has an unknown attribute");
        }
        return {};
    });
    if (!path_status) {
        return std::unexpected(path_status.error());
    }
    auto query_status = each(query, '&', [&](std::string_view name, std::string value) -> Status {
        if (name == "module-path") {
            uri.module_path = std::move(value);
        } else if (name == "pin-value") {
            uri.pin_value = std::move(value);
        } else if (name == "pin-source") {
            uri.pin_source = value.starts_with("file:") ? value.substr(5) : std::move(value);
        } else if (name == "x-sm2-mechanism") {
            std::string_view digits = value;
            if (digits.starts_with("0x") || digits.starts_with("0X")) {
                digits.remove_prefix(2);
            }
            if (digits.empty() || digits.size() > 2 * sizeof(unsigned long) ||
                !std::ranges::all_of(digits, [](char c) { return hex_value(c) >= 0; })) {
                return fail(Errc::malformed, "x-sm2-mechanism must be a hex number");
            }
            unsigned long mechanism = 0;
            for (const char c : digits) {
                mechanism = (mechanism << 4) | static_cast<unsigned long>(hex_value(c));
            }
            uri.sm2_mechanism = mechanism;
        } else if (name != "module-name") {
            return fail(Errc::unsupported, "a PKCS #11 URI has an unknown query attribute");
        }
        return {};
    });
    if (!query_status) {
        return std::unexpected(query_status.error());
    }
    if (uri.module_path.empty()) {
        return fail(Errc::invalid_argument, "a PKCS #11 URI needs module-path=");
    }
    if (!uri.object && !uri.id) {
        return fail(Errc::invalid_argument, "a PKCS #11 URI needs object= or id= to name the key");
    }
    return uri;
}

struct Key::Impl {
    std::shared_ptr<Module> module;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE;
    PublicKey public_key;
    std::string token_label;
    std::optional<unsigned long> sm2_mechanism;
    const crypto::Provider* provider = nullptr;

    Impl() = default;
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    ~Impl() {
        if (session != CK_INVALID_HANDLE) {
            module->functions->C_CloseSession(session);
        }
    }

    [[nodiscard]] CK_FUNCTION_LIST_PTR f() const { return module->functions; }

    /// Opens a logged-in read-write session on the URI's token.
    Status open_session(const KeyUri& uri, std::string_view pin) {
        CK_ULONG count = 0;
        if (f()->C_GetSlotList(CK_TRUE, nullptr, &count) != CKR_OK) {
            return token_fail("cannot list the PKCS #11 slots");
        }
        std::vector<CK_SLOT_ID> slots(count);
        if (count > 0 && f()->C_GetSlotList(CK_TRUE, slots.data(), &count) != CKR_OK) {
            return token_fail("cannot list the PKCS #11 slots");
        }
        std::optional<CK_SLOT_ID> chosen;
        for (const CK_SLOT_ID slot : slots) {
            CK_TOKEN_INFO info{};
            if (f()->C_GetTokenInfo(slot, &info) != CKR_OK) {
                continue;
            }
            const std::string label = trimmed(info.label, sizeof info.label);
            const std::string serial = trimmed(info.serialNumber, sizeof info.serialNumber);
            if ((uri.token && *uri.token != label) || (uri.serial && *uri.serial != serial)) {
                continue;
            }
            if (chosen) {
                return fail(Errc::invalid_argument,
                            "several tokens match; name one with token= or serial=");
            }
            chosen = slot;
            token_label = label;
        }
        if (!chosen) {
            return fail(Errc::not_found, "no token matches the PKCS #11 URI (is it plugged in?)");
        }
        if (f()->C_OpenSession(*chosen, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                               &session) != CKR_OK) {
            return token_fail("cannot open a session on the token");
        }
        const ByteView pin_bytes = as_bytes(pin);
        Bytes pin_copy(pin_bytes.begin(), pin_bytes.end());
        const CK_RV rv = f()->C_Login(session, CKU_USER, pin_copy.data(),
                                      static_cast<CK_ULONG>(pin_copy.size()));
        secure_wipe(pin_copy);
        if (rv == CKR_PIN_INCORRECT) {
            return fail(Errc::verification_failed, "wrong PIN for the token");
        }
        if (rv == CKR_PIN_LOCKED) {
            return fail(Errc::rejected, "the token's PIN is locked");
        }
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
            return token_fail("cannot log in to the token");
        }
        return {};
    }

    /// Finds exactly one object of `cls` named like the URI.
    Result<CK_OBJECT_HANDLE> find(const KeyUri& uri, CK_OBJECT_CLASS cls) const {
        std::vector<CK_ATTRIBUTE> templ{{CKA_CLASS, &cls, sizeof cls}};
        std::string label = uri.object.value_or("");
        Bytes id = uri.id.value_or(Bytes{});
        if (uri.object) {
            templ.push_back({CKA_LABEL, label.data(), label.size()});
        }
        if (uri.id) {
            templ.push_back({CKA_ID, id.data(), id.size()});
        }
        if (f()->C_FindObjectsInit(session, templ.data(), static_cast<CK_ULONG>(templ.size())) !=
            CKR_OK) {
            return token_fail("cannot search the token");
        }
        std::array<CK_OBJECT_HANDLE, 2> found{};
        CK_ULONG count = 0;
        const CK_RV rv = f()->C_FindObjects(session, found.data(), found.size(), &count);
        f()->C_FindObjectsFinal(session);
        if (rv != CKR_OK) {
            return token_fail("cannot search the token");
        }
        if (count == 0) {
            return fail(Errc::not_found, "the token has no such key");
        }
        if (count > 1) {
            return fail(Errc::invalid_argument,
                        "several keys on the token match; name one with id=");
        }
        return found[0];
    }

    Status load_keys(const KeyUri& uri) {
        auto priv = find(uri, CKO_PRIVATE_KEY);
        if (!priv) {
            return std::unexpected(priv.error());
        }
        private_key = *priv;
        auto pub = find(uri, CKO_PUBLIC_KEY);
        if (!pub) {
            return fail(Errc::not_found, "the token shows no public key next to the private key");
        }
        auto type_bytes = attribute(f(), session, *pub, CKA_KEY_TYPE);
        auto params = attribute(f(), session, *pub, CKA_EC_PARAMS);
        auto point = attribute(f(), session, *pub, CKA_EC_POINT);
        if (!type_bytes || !params || !point || type_bytes->size() != sizeof(CK_KEY_TYPE)) {
            return fail(Errc::unsupported,
                        "the token's key is not an elliptic-curve key CexChain uses");
        }
        CK_KEY_TYPE type = 0;
        std::memcpy(&type, type_bytes->data(), sizeof type);
        const auto alg = algorithm_of(type, *params);
        if (!alg) {
            return fail(Errc::unsupported,
                        "the token's key uses a curve CexChain does not (P-256, SM2, Ed25519)");
        }
        public_key = PublicKey{*alg, unwrap_point(std::move(*point), public_key_size(*alg))};
        if (public_key.bytes.size() != public_key_size(*alg) ||
            is_weak_public_key(*alg, public_key.bytes)) {
            return fail(Errc::unsupported, "the token's public key is malformed");
        }
        return {};
    }
};

Key::Key(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
Key::Key(Key&&) noexcept = default;
Key& Key::operator=(Key&&) noexcept = default;
Key::~Key() = default;

Result<Key> Key::open(const KeyUri& uri, std::string_view pin, const crypto::Provider& provider) {
    auto impl = std::make_unique<Impl>();
    auto module = load_module(uri.module_path);
    if (!module) {
        return std::unexpected(module.error());
    }
    impl->module = std::move(*module);
    impl->provider = &provider;
    impl->sm2_mechanism = uri.sm2_mechanism;
    if (auto s = impl->open_session(uri, pin); !s) {
        return std::unexpected(s.error());
    }
    if (auto s = impl->load_keys(uri); !s) {
        return std::unexpected(s.error());
    }
    return Key(std::move(impl));
}

Result<Key> Key::generate(const KeyUri& uri, std::string_view pin, SigAlg alg,
                          const crypto::Provider& provider) {
    if (!uri.object) {
        return fail(Errc::invalid_argument, "name the new key with object= in the PKCS #11 URI");
    }
    CK_MECHANISM mechanism{};
    ByteView params;
    if (alg == SigAlg::esp256) {
        mechanism.mechanism = CKM_EC_KEY_PAIR_GEN;
        params = oid_p256;
    } else if (alg == SigAlg::ed25519) {
        mechanism.mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN;
        params = oid_ed25519;
    } else {
        return fail(Errc::unsupported,
                    "CexChain generates ESP256 or Ed25519 keys on tokens; use the vendor's "
                    "tools for SM2");
    }
    auto impl = std::make_unique<Impl>();
    auto module = load_module(uri.module_path);
    if (!module) {
        return std::unexpected(module.error());
    }
    impl->module = std::move(*module);
    impl->provider = &provider;
    if (auto s = impl->open_session(uri, pin); !s) {
        return std::unexpected(s.error());
    }
    if (impl->find(uri, CKO_PRIVATE_KEY)) {
        return fail(Errc::rejected, "the token already has a key with this name");
    }
    // Without an id in the URI, derive one from the label.
    Bytes id;
    if (uri.id) {
        id = *uri.id;
    } else {
        auto digest = provider.digest(HashAlg::sha256, as_bytes(*uri.object));
        if (!digest) {
            return std::unexpected(digest.error());
        }
        id.assign(digest->bytes().begin(), digest->bytes().begin() + 16);
    }
    std::string label = *uri.object;
    Bytes params_copy(params.begin(), params.end());
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    std::array public_template{
        CK_ATTRIBUTE{CKA_TOKEN, &yes, sizeof yes},
        CK_ATTRIBUTE{CKA_VERIFY, &yes, sizeof yes},
        CK_ATTRIBUTE{CKA_EC_PARAMS, params_copy.data(), params_copy.size()},
        CK_ATTRIBUTE{CKA_LABEL, label.data(), label.size()},
        CK_ATTRIBUTE{CKA_ID, id.data(), id.size()},
    };
    std::array private_template{
        CK_ATTRIBUTE{CKA_TOKEN, &yes, sizeof yes},
        CK_ATTRIBUTE{CKA_PRIVATE, &yes, sizeof yes},
        CK_ATTRIBUTE{CKA_SENSITIVE, &yes, sizeof yes},
        CK_ATTRIBUTE{CKA_EXTRACTABLE, &no, sizeof no},
        CK_ATTRIBUTE{CKA_SIGN, &yes, sizeof yes},
        CK_ATTRIBUTE{CKA_LABEL, label.data(), label.size()},
        CK_ATTRIBUTE{CKA_ID, id.data(), id.size()},
    };
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    if (impl->f()->C_GenerateKeyPair(impl->session, &mechanism, public_template.data(),
                                     public_template.size(), private_template.data(),
                                     private_template.size(), &pub, &priv) != CKR_OK) {
        return token_fail("the token could not generate the key pair");
    }
    KeyUri named = uri;
    named.id = id;
    if (auto s = impl->load_keys(named); !s) {
        return std::unexpected(s.error());
    }
    return Key(std::move(impl));
}

SigAlg Key::algorithm() const noexcept {
    return public_key().algorithm;
}

const PublicKey& Key::public_key() const noexcept {
    static const PublicKey moved_from{SigAlg::ed25519, {}};
    return impl_ ? impl_->public_key : moved_from;
}

const std::string& Key::token_label() const noexcept {
    static const std::string none;
    return impl_ ? impl_->token_label : none;
}

Result<Bytes> Key::sign(ByteView message) const {
    if (!impl_) {
        return fail(Errc::invalid_argument, "key has been moved from");
    }
    CK_MECHANISM mechanism{};
    Bytes input(message.begin(), message.end());
    switch (algorithm()) {
    case SigAlg::esp256: {
        // Hash here: plain CKM_ECDSA over a digest is the most widely supported.
        auto digest = impl_->provider->digest(HashAlg::sha256, message);
        if (!digest) {
            return std::unexpected(digest.error());
        }
        input.assign(digest->bytes().begin(), digest->bytes().end());
        mechanism.mechanism = CKM_ECDSA;
        break;
    }
    case SigAlg::ed25519:
        mechanism.mechanism = CKM_EDDSA;
        break;
    case SigAlg::sm2_sm3:
        if (!impl_->sm2_mechanism) {
            return fail(Errc::unsupported,
                        "SM2 tokens need the vendor's mechanism: add x-sm2-mechanism= to the URI");
        }
        mechanism.mechanism = *impl_->sm2_mechanism;
        break;
    default:
        return fail(Errc::unsupported, "unsupported token key");
    }
    CK_FUNCTION_LIST_PTR f = impl_->f();
    if (f->C_SignInit(impl_->session, &mechanism, impl_->private_key) != CKR_OK) {
        return token_fail("the token refused to start signing");
    }
    CK_ULONG length = 0;
    if (f->C_Sign(impl_->session, input.data(), input.size(), nullptr, &length) != CKR_OK) {
        return token_fail("the token failed to sign");
    }
    Bytes signature(length);
    if (f->C_Sign(impl_->session, input.data(), input.size(), signature.data(), &length) !=
        CKR_OK) {
        return token_fail("the token failed to sign");
    }
    signature.resize(length);
    if (signature.size() != signature_size(algorithm())) {
        if (auto raw = der_to_raw(signature)) {
            signature = std::move(*raw);
        } else {
            return token_fail("the token returned a signature in an unknown format");
        }
    }
    canonicalize_signature(algorithm(), signature);
    if (!impl_->provider->verify(public_key(), message, signature)) {
        return token_fail("the token's signature does not verify (for SM2, check x-sm2-mechanism)");
    }
    return signature;
}

} // namespace cexchain::crypto::pkcs11
