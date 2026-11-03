// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "reader.hpp"

namespace cexchain::protocol::detail {

Result<MapReader> MapReader::open(const cbor::Value& value) {
    const cbor::Map* map = value.as_map();
    if (map == nullptr) {
        return fail(Errc::malformed, "expected a map");
    }
    return MapReader(*map);
}

const cbor::Value* MapReader::get(std::int64_t key) {
    for (std::size_t i = 0; i < map_->size(); ++i) {
        if ((*map_)[i].key.as_int64() == key) {
            seen_[i] = true;
            return &(*map_)[i].value;
        }
    }
    return nullptr;
}

Result<const cbor::Value*> MapReader::need(std::int64_t key) {
    const cbor::Value* value = get(key);
    if (value == nullptr) {
        return fail(Errc::malformed, "a required map key is missing");
    }
    return value;
}

Result<std::uint64_t> MapReader::need_uint(std::int64_t key) {
    auto value = need(key);
    if (!value) {
        return std::unexpected(value.error());
    }
    return as_uint(**value);
}

Result<std::int64_t> MapReader::need_int(std::int64_t key) {
    auto value = need(key);
    if (!value) {
        return std::unexpected(value.error());
    }
    const auto integer = (*value)->as_int64();
    if (!integer) {
        return fail(Errc::malformed, "expected an integer");
    }
    return *integer;
}

Result<std::string> MapReader::need_text(std::int64_t key) {
    auto value = need(key);
    if (!value) {
        return std::unexpected(value.error());
    }
    return as_text(**value);
}

Result<Bytes> MapReader::need_bytes(std::int64_t key) {
    auto value = need(key);
    if (!value) {
        return std::unexpected(value.error());
    }
    return as_bytes_value(**value);
}

Result<Id> MapReader::need_id(std::int64_t key) {
    auto bytes = need_bytes(key);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    return to_id(*bytes);
}

Result<std::optional<std::uint64_t>> MapReader::opt_uint(std::int64_t key) {
    const cbor::Value* value = get(key);
    if (value == nullptr) {
        return std::optional<std::uint64_t>{};
    }
    auto integer = as_uint(*value);
    if (!integer) {
        return std::unexpected(integer.error());
    }
    return std::optional<std::uint64_t>(*integer);
}

Result<std::optional<std::string>> MapReader::opt_text(std::int64_t key) {
    const cbor::Value* value = get(key);
    if (value == nullptr) {
        return std::optional<std::string>{};
    }
    auto text = as_text(*value);
    if (!text) {
        return std::unexpected(text.error());
    }
    return std::optional<std::string>(std::move(*text));
}

Result<std::optional<Bytes>> MapReader::opt_bytes(std::int64_t key) {
    const cbor::Value* value = get(key);
    if (value == nullptr) {
        return std::optional<Bytes>{};
    }
    auto bytes = as_bytes_value(*value);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    return std::optional<Bytes>(std::move(*bytes));
}

Result<std::optional<Id>> MapReader::opt_id(std::int64_t key) {
    auto bytes = opt_bytes(key);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    if (!*bytes) {
        return std::optional<Id>{};
    }
    auto id = to_id(**bytes);
    if (!id) {
        return std::unexpected(id.error());
    }
    return std::optional<Id>(*id);
}

Result<std::optional<bool>> MapReader::opt_bool(std::int64_t key) {
    const cbor::Value* value = get(key);
    if (value == nullptr) {
        return std::optional<bool>{};
    }
    const auto flag = value->as_bool();
    if (!flag) {
        return fail(Errc::malformed, "expected a boolean");
    }
    return std::optional<bool>(*flag);
}

Status MapReader::finish() const {
    for (std::size_t i = 0; i < map_->size(); ++i) {
        if (!(*map_)[i].key.as_int64()) {
            return fail(Errc::malformed, "protocol map keys must be integers");
        }
        if (!seen_[i]) {
            return fail(Errc::malformed, "map has an unknown key");
        }
    }
    return {};
}

Result<std::string> as_text(const cbor::Value& value) {
    const std::string* text = value.as_text();
    if (text == nullptr) {
        return fail(Errc::malformed, "expected a text string");
    }
    return *text;
}

Result<Bytes> as_bytes_value(const cbor::Value& value) {
    const Bytes* bytes = value.as_bytes();
    if (bytes == nullptr) {
        return fail(Errc::malformed, "expected a byte string");
    }
    return *bytes;
}

Result<std::uint64_t> as_uint(const cbor::Value& value) {
    const auto integer = value.as_uint64();
    if (!integer) {
        return fail(Errc::malformed, "expected an unsigned integer");
    }
    return *integer;
}

Result<const cbor::Array*> as_array(const cbor::Value& value) {
    const cbor::Array* array = value.as_array();
    if (array == nullptr) {
        return fail(Errc::malformed, "expected an array");
    }
    return array;
}

} // namespace cexchain::protocol::detail
