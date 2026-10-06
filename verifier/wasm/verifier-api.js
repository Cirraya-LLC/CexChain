// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A small JavaScript interface over the WebAssembly verifier. Works in
// browsers and in Node.js; expects the Emscripten factory `CexChainVerifier`.
//
//   const verifier = await createCexChainVerifier();
//   const report = verifier.verify(bundleBytes, {
//     ledgerId: "<64 hex digits>",             // learned out of band
//     witnesses: [publicKeyFileBytes],         // trusted witness keys
//     attachments: { "report.pdf": pdfBytes }, // contents to check
//   });
//   report.verified  // true or false; report.error explains a failure

async function createCexChainVerifier(factory) {
  const module = await (factory || CexChainVerifier)();

  function withBytes(bytes, use) {
    const pointer = module._malloc(Math.max(bytes.length, 1));
    try {
      module.HEAPU8.set(bytes, pointer);
      return use(pointer, bytes.length);
    } finally {
      module._free(pointer);
    }
  }

  function withString(text, use) {
    const size = module.lengthBytesUTF8(text) + 1;
    const pointer = module._malloc(size);
    try {
      module.stringToUTF8(text, pointer, size);
      return use(pointer);
    } finally {
      module._free(pointer);
    }
  }

  function verify(bundle, options = {}) {
    module._cexchain_reset();
    if (options.ledgerId) {
      const ok = withString(options.ledgerId.trim().toLowerCase(), (p) => module._cexchain_set_expected_ledger(p));
      if (ok !== 0) {
        return { verified: false, error: "the expected ledger id must be 64 hex digits" };
      }
    }
    for (const witness of options.witnesses || []) {
      if (withBytes(witness, (p, n) => module._cexchain_add_witness(p, n)) !== 0) {
        return { verified: false, error: "a witness key file is not a CexChain public key" };
      }
    }
    for (const [name, content] of Object.entries(options.attachments || {})) {
      withString(name, (namePointer) =>
        withBytes(content, (p, n) => module._cexchain_add_attachment(namePointer, p, n)));
    }
    const resultPointer = withBytes(bundle, (p, n) => module._cexchain_verify(p, n));
    try {
      return JSON.parse(module.UTF8ToString(resultPointer));
    } finally {
      module._cexchain_free(resultPointer);
    }
  }

  return { version: module.UTF8ToString(module._cexchain_version()), verify };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { createCexChainVerifier };
}
