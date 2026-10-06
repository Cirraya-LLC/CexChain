// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "records.hpp"

#include <algorithm>
#include <format>
#include <string>

#include <cexchain/core/cbor.hpp>
#include <cexchain/crypto/openssl.hpp>

namespace cexchain::cli {

namespace {

std::string media_type_for(const std::filesystem::path& path) {
    const std::string extension = path.extension().string();
    if (extension == ".pdf") {
        return "application/pdf";
    }
    if (extension == ".ofd") {
        return "application/ofd";
    }
    if (extension == ".json") {
        return "application/json";
    }
    if (extension == ".png") {
        return "image/png";
    }
    if (extension == ".jpg" || extension == ".jpeg") {
        return "image/jpeg";
    }
    return "application/octet-stream";
}

} // namespace

namespace {

constexpr std::uint64_t vault_format_version = 1;

Bytes encode_vault_content(const Vault& vault) {
    cbor::Array fields;
    for (const protocol::RecordField& f : vault.fields) {
        fields.push_back(
            cbor::Value::array({cbor::Value::text(f.name), cbor::Value::bytes(f.salt), f.value}));
    }
    cbor::Array attachments;
    for (const VaultAttachment& a : vault.attachments) {
        attachments.push_back(
            cbor::Value::array({cbor::Value::text(a.name), cbor::Value::bytes(a.salt)}));
    }
    return unwrap(cbor::encode(cbor::Value::map(
                      {{cbor::Value::integer(1), cbor::Value::array(std::move(fields))},
                       {cbor::Value::integer(2), cbor::Value::array(std::move(attachments))}})),
                  "encoding the vault");
}

Vault decode_vault_content(const cbor::Value& value) {
    auto corrupted = [] {
        return CommandError{"the record vault is corrupted"};
    };
    auto salt_of = [&](const cbor::Value& v) {
        protocol::Nonce salt{};
        const Bytes* bytes = v.as_bytes();
        if (bytes == nullptr || bytes->size() != salt.size()) {
            throw corrupted();
        }
        std::ranges::copy(*bytes, salt.begin());
        return salt;
    };
    const cbor::Value* fields = value.find(1);
    const cbor::Value* attachments = value.find(2);
    if (fields == nullptr || fields->as_array() == nullptr || attachments == nullptr ||
        attachments->as_array() == nullptr) {
        throw corrupted();
    }
    Vault vault;
    for (const cbor::Value& item : *fields->as_array()) {
        const cbor::Array* parts = item.as_array();
        if (parts == nullptr || parts->size() != 3 || (*parts)[0].as_text() == nullptr) {
            throw corrupted();
        }
        vault.fields.push_back({*(*parts)[0].as_text(), salt_of((*parts)[1]), (*parts)[2]});
    }
    for (const cbor::Value& item : *attachments->as_array()) {
        const cbor::Array* parts = item.as_array();
        if (parts == nullptr || parts->size() != 2 || (*parts)[0].as_text() == nullptr) {
            throw corrupted();
        }
        vault.attachments.push_back({*(*parts)[0].as_text(), salt_of((*parts)[1])});
    }
    return vault;
}

bool is_sealed(const cbor::Value& file) {
    const cbor::Value* version = file.find(1);
    return version != nullptr && version->as_uint64().has_value() && file.find(3) != nullptr;
}

Bytes vault_aad(const protocol::Id& ledger, const protocol::Id& record) {
    Bytes aad(ledger.bytes().begin(), ledger.bytes().end());
    aad.insert(aad.end(), record.bytes().begin(), record.bytes().end());
    return aad;
}

} // namespace

Bytes encode_vault_public_key(ByteView key) {
    return unwrap(cbor::encode(cbor::Value::map(
                      {{cbor::Value::integer(1),
                        cbor::Value::unsigned_integer(crypto::openssl::hpke_suite.kem)},
                       {cbor::Value::integer(2), cbor::Value::bytes(key)}})),
                  "encoding the vault public key");
}

std::optional<Bytes> decode_vault_public_key(ByteView file) {
    const auto value = cbor::decode(file);
    if (!value || value->as_map() == nullptr || value->as_map()->size() != 2) {
        return std::nullopt;
    }
    const cbor::Value* kem = value->find(1);
    const cbor::Value* key = value->find(2);
    if (kem == nullptr || kem->as_uint64() != crypto::openssl::hpke_suite.kem || key == nullptr ||
        key->as_bytes() == nullptr ||
        key->as_bytes()->size() != crypto::openssl::hpke_public_key_size) {
        return std::nullopt;
    }
    return *key->as_bytes();
}

std::filesystem::path vault_public_key_path(const Session& session) {
    return session.directory() / "vault.pub";
}

std::filesystem::path default_vault_key_path(const Session& session) {
    return session.directory() / "vault.key";
}

Bytes vault_public_key(const Session& session) {
    const std::filesystem::path path = vault_public_key_path(session);
    if (!std::filesystem::exists(path)) {
        throw CommandError{
            "this ledger has no vault key yet; create one with: cexchain vault rekey"};
    }
    auto key = decode_vault_public_key(read_file(path));
    if (!key) {
        throw CommandError{path.string() + " is not a vault public key"};
    }
    return std::move(*key);
}

crypto::openssl::HpkeKey load_hpke_key(const std::filesystem::path& path, const Args& args) {
    const Bytes der = read_file(path);
    if (crypto::openssl::is_encrypted_pkcs8(der)) {
        auto key =
            crypto::openssl::HpkeKey::from_encrypted_pkcs8(der, passphrase(args, path.string()));
        if (!key && key.error().code == Errc::verification_failed) {
            throw CommandError{"wrong passphrase for " + path.string()};
        }
        return unwrap(std::move(key), "loading the vault key " + path.string());
    }
    return unwrap(crypto::openssl::HpkeKey::from_pkcs8(der),
                  "loading the vault key " + path.string());
}

crypto::openssl::HpkeKey load_vault_key(const Session& session, const Args& args) {
    const std::filesystem::path path = args.has("vault-key")
                                           ? std::filesystem::path(*args.get("vault-key"))
                                           : default_vault_key_path(session);
    if (!std::filesystem::exists(path)) {
        throw CommandError{"no vault key at " + path.string() + "; pass --vault-key FILE"};
    }
    auto key = load_hpke_key(path, args);
    const Bytes expected = vault_public_key(session);
    if (!std::ranges::equal(key.public_key(), expected)) {
        throw CommandError{path.string() + " is not this ledger's vault key"};
    }
    return key;
}

bool is_sealed_vault(ByteView file) {
    const auto value = cbor::decode(file);
    return value && is_sealed(*value);
}

Bytes seal_vault(const protocol::Id& ledger, const protocol::Id& record, const Vault& vault,
                 ByteView public_key) {
    const Bytes content = encode_vault_content(vault);
    const SecureBytes plain(Bytes(content.begin(), content.end()));
    const auto sealed = unwrap(crypto::openssl::hpke_seal(public_key, as_bytes(vault_info),
                                                          vault_aad(ledger, record), plain.view()),
                               "sealing the vault");
    const auto& suite = crypto::openssl::hpke_suite;
    return unwrap(
        cbor::encode(cbor::Value::map(
            {{cbor::Value::integer(1), cbor::Value::unsigned_integer(vault_format_version)},
             {cbor::Value::integer(2),
              cbor::Value::array({cbor::Value::unsigned_integer(suite.kem),
                                  cbor::Value::unsigned_integer(suite.kdf),
                                  cbor::Value::unsigned_integer(suite.aead)})},
             {cbor::Value::integer(3), cbor::Value::bytes(sealed.encapsulated_key)},
             {cbor::Value::integer(4), cbor::Value::bytes(sealed.ciphertext)}})),
        "encoding the vault");
}

void save_vault(const Session& session, const protocol::Id& record, const Vault& vault) {
    const Bytes sealed =
        seal_vault(session.state().ledger_id(), record, vault, vault_public_key(session));
    std::filesystem::create_directories(session.vault_path(record).parent_path());
    write_file(session.vault_path(record), sealed, true);
}

Vault load_vault(const Session& session, const protocol::Id& record,
                 const crypto::openssl::HpkeKey* key) {
    const std::filesystem::path path = session.vault_path(record);
    if (!std::filesystem::exists(path)) {
        throw CommandError{
            "this ledger holds no private data for the record (it was issued elsewhere)"};
    }
    const auto value = unwrap(cbor::decode(read_file(path)), "reading the vault");
    if (!is_sealed(value)) {
        return decode_vault_content(value);
    }
    if (key == nullptr) {
        throw CommandError{"reading private record data needs the vault key"};
    }
    const cbor::Value* version = value.find(1);
    const cbor::Value* suite = value.find(2);
    const cbor::Value* enc = value.find(3);
    const cbor::Value* ciphertext = value.find(4);
    const auto& expected = crypto::openssl::hpke_suite;
    const bool suite_ok = suite != nullptr && suite->as_array() != nullptr &&
                          suite->as_array()->size() == 3 &&
                          (*suite->as_array())[0].as_uint64() == expected.kem &&
                          (*suite->as_array())[1].as_uint64() == expected.kdf &&
                          (*suite->as_array())[2].as_uint64() == expected.aead;
    if (version->as_uint64() != vault_format_version || !suite_ok || enc->as_bytes() == nullptr ||
        ciphertext == nullptr || ciphertext->as_bytes() == nullptr) {
        throw CommandError{"unsupported or corrupted vault file " + path.string()};
    }
    const auto plain =
        unwrap(key->open({*enc->as_bytes(), *ciphertext->as_bytes()}, as_bytes(vault_info),
                         vault_aad(session.state().ledger_id(), record)),
               "opening the vault for " + short_id(record));
    return decode_vault_content(unwrap(cbor::decode(plain.view()), "reading the vault"));
}

Vault read_vault(const Session& session, const protocol::Id& record, const Args& args) {
    const std::filesystem::path path = session.vault_path(record);
    if (std::filesystem::exists(path) && is_sealed_vault(read_file(path))) {
        const auto key = load_vault_key(session, args);
        return load_vault(session, record, &key);
    }
    return load_vault(session, record, nullptr);
}

protocol::Id issue_record(Session& session, const crypto::Signer& signer,
                          const IssueRequest& request) {
    ledger::SystemEntropy entropy;
    if (request.fields.empty()) {
        throw UsageError{"a record needs at least one field"};
    }
    Vault vault;
    for (const auto& [name, value] : request.fields) {
        vault.fields.push_back({name, entropy.bytes<16>(), cbor::Value::text(value)});
    }
    const auto commitment =
        unwrap(protocol::commit_fields(session.provider(), session.state().hash(), vault.fields),
               "committing to the fields");
    vault.fields = commitment.fields;

    protocol::RecordRegisterBody body;
    body.record_type = request.record_type;
    body.field_root = Bytes(commitment.root.bytes().begin(), commitment.root.bytes().end());
    body.field_count = commitment.leaves.size();
    for (const std::filesystem::path& path : request.attachments) {
        const Bytes content = read_file(path);
        const VaultAttachment attachment{path.filename().string(), entropy.bytes<16>()};
        const auto digest =
            unwrap(protocol::attachment_commitment(session.provider(), session.state().hash(),
                                                   attachment.salt, content),
                   "committing to an attachment");
        body.attachments.push_back({attachment.name, media_type_for(path), content.size(),
                                    Bytes(digest.bytes().begin(), digest.bytes().end())});
        vault.attachments.push_back(attachment);
    }
    if (!request.metadata.empty()) {
        cbor::Map metadata;
        for (const auto& [name, value] : request.metadata) {
            metadata.push_back({cbor::Value::text(name), cbor::Value::text(value)});
        }
        body.metadata = cbor::Value::map(std::move(metadata));
    }
    const protocol::Id id =
        session.submit(signer, body, request.delegation, request.provenance, request.presence);
    save_vault(session, id, vault);
    return id;
}

} // namespace cexchain::cli
