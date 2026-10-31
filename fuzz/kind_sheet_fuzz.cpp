// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A kind sheet comes from a person's page (Kinds) or a file someone
// shares: reading one must refuse what is not one, never crash, and what it
// accepts must write back to a sheet that reads the same. Values typed for
// a field are checked against its type, whatever they are.

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string_view>

#include <nlohmann/json.hpp>

#include <cexchain/console/kinds.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    const auto sheet = nlohmann::json::parse(text, nullptr, false);
    if (sheet.is_discarded()) {
        return 0;
    }
    cexchain::console::Kind kind;
    try {
        kind = cexchain::console::parse_kind(sheet);
    } catch (const std::invalid_argument&) {
        return 0; // Refused, saying why.
    }
    const auto again = cexchain::console::parse_kind(cexchain::console::kind_json(kind));
    if (cexchain::console::kind_json(again) != cexchain::console::kind_json(kind)) {
        __builtin_trap();
    }
    for (const auto& field : kind.fields) {
        static_cast<void>(cexchain::console::check_value(field, text));
        static_cast<void>(cexchain::console::check_value(field, field.name));
    }
    return 0;
}
