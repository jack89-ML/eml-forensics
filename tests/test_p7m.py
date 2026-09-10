"""Offline tests: CAdES/.p7m detection and unwrapping.

A real attached CMS envelope is generated at test time with OpenSSL when
available; the whole test is skipped on hosts without the binary. The pure
detection helpers run everywhere.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from eml_forensics import p7m
from eml_forensics.errors import ForensicsError

OPENSSL = shutil.which("openssl")


class DetectionTest(unittest.TestCase):
    def test_filename_detection(self):
        self.assertTrue(p7m.is_p7m(filename="report.pdf.p7m"))
        self.assertTrue(p7m.is_p7m(filename="postacert.p7m"))
        self.assertFalse(p7m.is_p7m(filename="report.pdf"))

    def test_mime_detection(self):
        self.assertTrue(p7m.is_p7m(content_type="application/pkcs7-mime"))
        self.assertTrue(p7m.is_p7m(content_type="application/x-pkcs7-mime"))
        self.assertFalse(p7m.is_p7m(content_type="application/pdf"))

    def test_payload_stem(self):
        self.assertEqual(p7m.payload_stem("report.pdf.p7m"), "report.pdf")
        self.assertEqual(p7m.payload_stem("file.p7m"), "file")
        self.assertEqual(p7m.payload_stem("x.dat"), "x.dat.payload")


@unittest.skipUnless(OPENSSL, "openssl binary not available")
class UnpackTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.payload = b"hello from inside the envelope\n"
        payload_path = self.dir / "original.txt"
        payload_path.write_bytes(self.payload)
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(self.dir / "key.pem"),
             "-out", str(self.dir / "cert.pem"), "-days", "1",
             "-subj", "/CN=Alice Example/O=Acme Corp"],
            check=True, capture_output=True)
        subprocess.run(
            ["openssl", "smime", "-sign", "-binary", "-nodetach",
             "-in", str(payload_path), "-outform", "DER",
             "-out", str(self.dir / "signed.pdf.p7m"),
             "-signer", str(self.dir / "cert.pem"),
             "-inkey", str(self.dir / "key.pem")],
            check=True, capture_output=True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_unpack_attached_payload(self):
        envelope = self.dir / "signed.pdf.p7m"
        out_path = self.dir / "original.txt"
        result = p7m.unpack_p7m(envelope, out_path)
        self.assertTrue(result["ok"])
        self.assertTrue(result["payload_path"].endswith("original.txt"))
        self.assertEqual(result["sha256_payload"],
                         p7m.sha256_file(out_path))
        self.assertTrue(out_path.read_bytes() == self.payload)

    def test_signer_metadata_extracted(self):
        envelope = self.dir / "signed.pdf.p7m"
        signers = p7m.signer_certificates(envelope)
        self.assertTrue(signers)
        self.assertIn("Alice Example", signers[0]["cn"])

    def test_envelope_hash_recorded(self):
        envelope = self.dir / "signed.pdf.p7m"
        result = p7m.unpack_p7m(envelope, self.dir / "out.txt")
        self.assertEqual(result["sha256_envelope"],
                         p7m.sha256_file(envelope))

    def test_missing_envelope_raises(self):
        with self.assertRaises(ForensicsError):
            p7m.unpack_p7m(self.dir / "absent.p7m", self.dir / "x.txt")


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(OPENSSL, "openssl binary not available")
class CertificateMetadataTest(unittest.TestCase):
    """The chain-of-custody report needs subject, validity and fingerprint —
    and must state that the signature was not verified."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.key = self.dir / "key.pem"
        self.cert = self.dir / "cert.pem"
        self.envelope = self.dir / "signed.p7m"
        self.payload = self.dir / "payload.txt"
        self.payload.write_text("signed payload\n", encoding="utf-8")
        subprocess.run([OPENSSL, "req", "-x509", "-newkey", "rsa:2048",
                        "-keyout", str(self.key), "-out", str(self.cert),
                        "-days", "30", "-nodes", "-subj", "/CN=Test Signer/O=Unit"],
                       capture_output=True, check=False)
        subprocess.run([OPENSSL, "smime", "-sign", "-in", str(self.payload),
                        "-signer", str(self.cert), "-inkey", str(self.key),
                        "-out", str(self.envelope), "-outform", "DER",
                        "-nodetach"],
                       capture_output=True, check=False)

    def tearDown(self):
        self._tmp.cleanup()

    def test_certificates_carry_validity_and_fingerprint(self):
        if not self.envelope.is_file():
            self.skipTest("openssl could not build the envelope")
        signers = p7m.signer_certificates(self.envelope)
        self.assertTrue(signers)
        signer = signers[0]
        self.assertIn("Test Signer", signer["cn"])
        self.assertTrue(signer["not_after"])
        self.assertTrue(signer["not_before"])
        self.assertEqual(len(signer["fingerprint_sha256"]), 64)

    def test_unwrap_reports_that_the_signature_was_not_verified(self):
        if not self.envelope.is_file():
            self.skipTest("openssl could not build the envelope")
        out = self.dir / "payload.out"
        result = p7m.unpack_p7m(self.envelope, out)
        self.assertIn("signature_verified", result)
        self.assertFalse(result["signature_verified"])
        self.assertTrue(result["signers"])
