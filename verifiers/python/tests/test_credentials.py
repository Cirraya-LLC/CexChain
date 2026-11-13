# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""The credential test vectors (testvectors/credentials-v1.json), against
kanhe_verify/credentials.py: JCS, thumbprints, base URLs, roles, credentials,
DID documents, and status lists, each reproduced or refused as the vectors
say."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from kanhe_verify import credentials, crypto  # noqa: E402
from kanhe_verify.errors import VerifyError  # noqa: E402

VECTORS = json.loads((HERE.parents[2] / "testvectors" / "credentials-v1.json").read_text())


def key(hex_point: str) -> crypto.PublicKey:
    return crypto.PublicKey(crypto.ESP256, bytes.fromhex(hex_point))


def did_document(base: str, keys: list, ledger: str) -> str:
    """Section 3, from the text."""
    b = credentials.base_url(base)
    methods = {}
    for k in keys:
        methods[credentials.thumbprint(k)] = k
    order = sorted(methods)
    return credentials.jcs({
        "@context": ["https://www.w3.org/ns/did/v1", "https://www.w3.org/ns/cid/v1"],
        "id": b.did,
        "verificationMethod": [{"id": b.did + "#" + t, "type": "JsonWebKey", "controller": b.did,
                                "publicKeyJwk": {**credentials.jwk(methods[t]), "alg": "ES256"}} for t in order],
        "assertionMethod": [b.did + "#" + t for t in order],
        "service": [{"id": b.did + "#kanhe", "type": "KanheLedger", "serviceEndpoint": b.url, "ledger": ledger}],
    })


class CredentialVectors(unittest.TestCase):
    def test_jcs(self):
        for case in VECTORS["jcs"]:
            self.assertEqual(credentials.jcs(case["value"]), case["jcs"])
            self.assertEqual(credentials.parse_jcs(case["jcs"]), case["value"])
        for text in VECTORS["jcs_refused"]:
            with self.subTest(text=text), self.assertRaises(VerifyError):
                credentials.parse_jcs(text)

    def test_thumbprints(self):
        for t in VECTORS["thumbprints"]:
            self.assertEqual(credentials.thumbprint(key(t["key"])), t["thumbprint"])
            self.assertEqual(credentials.jwk(key(t["key"])), t["jwk"])
            self.assertEqual(credentials.jwk_key(t["jwk"]), key(t["key"]))

    def test_base_urls(self):
        for b in VECTORS["base_urls"]:
            base = credentials.base_url(b["url"])
            self.assertEqual((base.url, base.did, base.did_document), (b["base"], b["did"], b["did_document"]))
        for url in VECTORS["base_urls_refused"]:
            with self.subTest(url=url), self.assertRaises(VerifyError):
                credentials.base_url(url)

    def test_roles(self):
        for r in VECTORS["roles"]:
            self.assertEqual(credentials.role_entry(r["role"]), (r["list"], r["index"]))
        for role in VECTORS["roles_refused"]:
            self.assertIsNone(credentials.role_entry(role), role)

    def test_credentials(self):
        for c in VECTORS["credentials"]:
            with self.subTest(c["description"]):
                parsed = credentials.parse_credential(c["jws"])
                self.assertEqual(credentials.jcs(parsed.jws.header), c["header"])
                self.assertEqual(credentials.jcs(parsed.jws.payload), c["payload"])
                self.assertTrue(crypto.verify_signature(key(c["key"]), parsed.jws.signing_input,
                                                        parsed.jws.signature))
                self.assertEqual(parsed.thumbprint, credentials.thumbprint(key(c["key"])))
                content = c["content"]
                self.assertEqual(parsed.subject, {name: value for name, value in content["subject"]})
                self.assertEqual((parsed.list, parsed.index), (content["list"], content["index"]))
                self.assertEqual(parsed.record.hex(), content["record"])

    def test_did_documents(self):
        for d in VECTORS["did_documents"]:
            with self.subTest(d["description"]):
                self.assertEqual(did_document(d["base"], [key(k) for k in d["keys"]], d["ledger"]), d["document"])

    def test_status_lists(self):
        for s in VECTORS["status_lists"]:
            with self.subTest(s["description"]):
                bits = credentials.decode_list(s["encoded"])
                self.assertEqual(hashlib.sha256(bits).hexdigest(), s["sha256"])
                for i in s["set"]:
                    self.assertTrue(credentials.bit(bits, i))
        for s in VECTORS["status_lists_refused"]:
            with self.subTest(s["why"]), self.assertRaises(VerifyError):
                credentials.decode_list(s["encoded"])


if __name__ == "__main__":
    unittest.main()
