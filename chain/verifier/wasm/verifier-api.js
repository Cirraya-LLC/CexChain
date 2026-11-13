// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A small JavaScript interface over the WebAssembly verifier. Works in
// browsers and in Node.js; expects the Emscripten factory `KanheVerifier`.
//
//   const verifier = await createKanheVerifier();
//   const report = verifier.verify(bundleBytes, {
//     ledgerId: "<64 hex digits>",             // learned out of band
//     witnesses: [publicKeyFileBytes],         // trusted witness keys
//     timestampRoots: [certificateFileBytes],  // trusted time-stamp authorities' roots
//     attachments: { "report.pdf": pdfBytes }, // contents to check
//     trustNodes: [{ ledger: "<64 hex digits>", name: "HK Trust" }], // trust nodes believed
//   });
//   report.verified  // true or false; report.error explains a failure
//
// A W3C Verifiable Credential issued from a Kanhe record (spec/credentials.md):
//   const where = verifier.credentialAddresses(jwsText); // {evidence, did_document, status_list, ledger}
//   const report = verifier.verifyCredential(jwsText, evidenceBytes, {
//     didDocument: didJsonText, statusList: statusListJwsText, // when fetched
//     ledgerId, witnesses, timestampRoots, trustNodes,         // as for verify
//   });

async function createKanheVerifier(factory) {
  const module = await (factory || KanheVerifier)();

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

  function read(resultPointer) {
    try {
      return JSON.parse(module.UTF8ToString(resultPointer));
    } finally {
      module._kanhe_free(resultPointer);
    }
  }

  // Sets the options; a problem's report, or null.
  function configure(options) {
    module._kanhe_reset();
    if (options.ledgerId) {
      const ok = withString(options.ledgerId.trim().toLowerCase(), (p) => module._kanhe_set_expected_ledger(p));
      if (ok !== 0) {
        return { verified: false, error: "the expected ledger id must be 64 hex digits" };
      }
    }
    for (const witness of options.witnesses || []) {
      if (withBytes(witness, (p, n) => module._kanhe_add_witness(p, n)) !== 0) {
        return { verified: false, error: "a witness key file is not a Kanhe public key" };
      }
    }
    for (const vkey of options.networkWitnesses || []) {
      if (withString(vkey.trim(), (p) => module._kanhe_add_network_witness(p)) !== 0) {
        return { verified: false, error: "a network witness's verifier key is not one: " + vkey };
      }
    }
    for (const root of options.timestampRoots || []) {
      if (withBytes(root, (p, n) => module._kanhe_add_timestamp_root(p, n)) !== 0) {
        return { verified: false, error: "a time-stamp authority's root is not a certificate (PEM or DER)" };
      }
    }
    for (const node of options.trustNodes || []) {
      const ok = withString(node.ledger.trim().toLowerCase(), (ledger) =>
        withString(node.name, (name) => module._kanhe_add_trust_node(ledger, name)));
      if (ok !== 0) {
        return { verified: false, error: "a trust node is a ledger id (64 hex digits) and a name" };
      }
    }
    for (const [name, content] of Object.entries(options.attachments || {})) {
      withString(name, (namePointer) =>
        withBytes(content, (p, n) => module._kanhe_add_attachment(namePointer, p, n)));
    }
    return null;
  }

  function verify(bundle, options = {}) {
    const problem = configure(options);
    if (problem) return problem;
    return read(withBytes(bundle, (p, n) => module._kanhe_verify(p, n)));
  }

  function credentialAddresses(credential) {
    return read(withString(credential.trim(), (p) => module._kanhe_credential_addresses(p)));
  }

  function verifyCredential(credential, evidence, options = {}) {
    const problem = configure(options);
    if (problem) return problem;
    const optional = (text, use) => (text == null ? use(0) : withString(text, use));
    return read(withString(credential.trim(), (c) =>
      withBytes(evidence, (b, n) =>
        optional(options.didDocument, (d) =>
          optional(options.statusList, (l) => module._kanhe_verify_credential(c, b, n, d, l))))));
  }

  return { version: module.UTF8ToString(module._kanhe_version()), verify, credentialAddresses, verifyCredential };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { createKanheVerifier };
}
