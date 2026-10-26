// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The kept files' readers: a sealed file as stored or sent (its shape), a
// submission's list of files (key 4), and the check of a file against the
// attachment it claims to be. Whatever arrives, they must not crash; a
// sealed file accepted for an attachment holds exactly that attachment's
// size; and a list accepted has ascending, distinct indexes that encode back
// to the same list.

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/node/record_files.hpp>

namespace node = cexchain::node;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const cexchain::ByteView input(data, size);

    const auto box = node::parse_sealed_box(input);
    // A registration whose second attachment is 5 bytes long.
    cexchain::protocol::RecordRegisterBody record;
    record.attachments.push_back({"a.txt", "text/plain", 3, cexchain::Bytes(32, 1)});
    record.attachments.push_back({"b.jpg", "image/jpeg", 5, cexchain::Bytes(32, 2)});
    for (std::uint64_t index = 0; index < 3; ++index) {
        const node::SealedFile file{index, cexchain::Bytes(input.begin(), input.end())};
        if (node::check_sealed_file(record, file)) {
            require(box.has_value() && index < record.attachments.size());
            require(box->ciphertext.size() ==
                    record.attachments[index].size + node::sealed_file_overhead);
        }
    }

    if (const auto value = cexchain::cbor::decode(input)) {
        if (const auto files = node::decode_sealed_files(*value)) {
            for (std::size_t i = 1; i < files->size(); ++i) {
                require((*files)[i - 1].index < (*files)[i].index);
            }
            const auto again = node::decode_sealed_files(node::encode_sealed_files(*files));
            require(again && *again == *files);
        }
    }
    return 0;
}
