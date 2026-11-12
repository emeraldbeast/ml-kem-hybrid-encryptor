from __future__ import annotations

import unittest

from xwing.openssl_backend import OpenSSLBackend, OpenSSLCommandError
from xwing.paper_baseline import SIZES, XWING_LABEL, run_original_paper_roundtrip


class PaperBaselineTests(unittest.TestCase):
    def test_paper_label_and_sizes(self) -> None:
        self.assertEqual(len(XWING_LABEL), 6)
        self.assertEqual(XWING_LABEL, b"\\.//^\\")
        self.assertEqual(SIZES["combiner_input"], 134)
        self.assertEqual(SIZES["xwing_public_key"], 1216)
        self.assertEqual(SIZES["xwing_private_key"], 2464)
        self.assertEqual(SIZES["xwing_ciphertext"], 1120)

    def test_backend_requires_mlkem_capable_openssl(self) -> None:
        backend = OpenSSLBackend()
        self.assertGreaterEqual(backend.version, (3, 5, 0))

    def test_real_xwing_roundtrip(self) -> None:
        report = run_original_paper_roundtrip()
        self.assertTrue(report["ok"])
        self.assertEqual(report["actual_lengths_bytes"]["combiner_input"], 134)
        self.assertEqual(report["actual_lengths_bytes"]["mlkem_ciphertext"], 1088)
        self.assertEqual(report["actual_lengths_bytes"]["x25519_ciphertext"], 32)
        self.assertEqual(report["actual_lengths_bytes"]["xwing_ciphertext"], 1120)
        self.assertTrue(report["checks"]["mlkem_component_match"])
        self.assertTrue(report["checks"]["x25519_component_match"])
        self.assertTrue(report["checks"]["hybrid_shared_secret_match"])
        self.assertEqual(
            report["fingerprints"]["sender_hybrid_secret_sha256_prefix"],
            report["fingerprints"]["receiver_hybrid_secret_sha256_prefix"],
        )
        self.assertNotIn("sender_shared_secret_hex", report)
        self.assertNotIn("private_key_pem", report)


if __name__ == "__main__":
    unittest.main()
