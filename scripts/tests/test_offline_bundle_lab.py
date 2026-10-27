"""G2g deterministic offline verifier lab tests; no device deployment.

The Ed25519 keypair is generated only in an ephemeral test directory and
deleted with that directory. No private keys or signatures are committed.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify_offline_bundle_lab.py"
TARGET = "armv7-unknown-linux-gnueabihf"


class LabVerifierTest(unittest.TestCase):
    def setUp(self):
        if not shutil.which("openssl"):
            self.skipTest("OpenSSL Ed25519 provider required for lab proof")
        self.directory = tempfile.TemporaryDirectory(prefix="rusti-g2g-tests-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.private = self.root / "test-only-private.pem"
        self.public = self.root / "trusted-public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(self.private)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        with self.public.open("wb") as out:
            subprocess.run(
                ["openssl", "pkey", "-in", str(self.private), "-pubout"],
                check=True, stdout=out, stderr=subprocess.DEVNULL,
            )
        self.payload = self.bundle / "rusti_rc.bin"
        self.payload.write_bytes(b"synthetic offline lab payload, never executable\n")
        self.data = {
            "schema": "rusti-offline-lab-v1",
            "sequence": 11,
            "target": TARGET,
            "source_commit": "b" * 40,
            "payload_name": "rusti_rc.bin",
            "payload_size": self.payload.stat().st_size,
            "payload_sha256": hashlib.sha256(self.payload.read_bytes()).hexdigest(),
        }
        self.sign()

    def sign(self, raw=None):
        if raw is None:
            raw = (json.dumps(
                self.data, sort_keys=True, separators=(",", ":")
            ) + "\n").encode("utf-8")
        manifest = self.bundle / "manifest.json"
        manifest.write_bytes(raw)
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(self.private),
             "-rawin", "-in", str(manifest), "-out", str(self.bundle / "manifest.sig")],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def run_verifier(self, *, target=TARGET, minimum=9, key=None):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--lab-only",
             "--bundle", str(self.bundle),
             "--trusted-public-key", str(key or self.public),
             "--expected-target", target,
             "--minimum-sequence", str(minimum)],
            check=False, capture_output=True, text=True, timeout=15,
        )

    def assert_refused(self, expected):
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refused:" + expected, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_signature_and_hash_valid_still_never_authorize_deployment(self):
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            "lab_signature_target_payload_and_floor=verified\ndeployment=blocked\n",
        )

    def test_payload_tampering_rejected(self):
        self.payload.write_bytes(b"tampered-bytes")
        self.assert_refused("payload_integrity_rejected")

    def test_manifest_tampering_rejected_before_json_parse(self):
        manifest = self.bundle / "manifest.json"
        manifest.write_bytes(manifest.read_bytes().replace(b'"sequence":11', b'"sequence":12'))
        self.assert_refused("signature_rejected")

    def test_older_validly_signed_bundle_rejected_by_supplied_lab_floor(self):
        result = self.run_verifier(minimum=12)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sequence_below_supplied_floor", result.stderr)

    def test_wrong_target_rejected(self):
        result = self.run_verifier(target="aarch64-unknown-linux-gnu")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("target_mismatch", result.stderr)

    def test_unknown_signed_metadata_field_rejected(self):
        self.data["allow_unsafe_install"] = True
        self.sign()
        self.assert_refused("unsupported_metadata_schema")

    def test_duplicate_signed_json_key_rejected(self):
        raw = (
            b'{"schema":"rusti-offline-lab-v1","schema":"rusti-offline-lab-v1"}\n'
        )
        self.sign(raw)
        self.assert_refused("duplicate_metadata_key")

    def test_signature_corruption_rejected(self):
        signature = self.bundle / "manifest.sig"
        payload = bytearray(signature.read_bytes())
        payload[0] ^= 0x40
        signature.write_bytes(payload)
        self.assert_refused("signature_rejected")

    def test_untrusted_signer_rejected(self):
        alternative = self.root / "other-key.pem"
        alternative_public = self.root / "other-public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "Ed25519",
             "-out", str(alternative)], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        with alternative_public.open("wb") as out:
            subprocess.run(
                ["openssl", "pkey", "-in", str(alternative), "-pubout"],
                check=True, stdout=out, stderr=subprocess.DEVNULL,
            )
        result = self.run_verifier(key=alternative_public)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature_rejected", result.stderr)

    def test_symlinked_payload_rejected_even_with_valid_signature(self):
        other = self.root / "other-payload.bin"
        other.write_bytes(self.payload.read_bytes())
        self.payload.unlink()
        try:
            self.payload.symlink_to(other)
        except (OSError, NotImplementedError):
            self.skipTest("Platform does not allow local symlinks")
        self.assert_refused("unsafe_payload")

    def test_unknown_bundle_file_rejected(self):
        (self.bundle / "unreviewed.sh").write_text("irrelevant\n")
        self.assert_refused("unknown_or_missing_bundle_entry")

    def test_missing_trust_anchor_rejected(self):
        result = self.run_verifier(key=self.root / "missing-public.pem")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no_independent_trust_root", result.stderr)

    def test_signed_oversized_payload_claim_rejected_before_read(self):
        self.data["payload_size"] = 100 * 1024 * 1024
        self.sign()
        self.assert_refused("invalid_numeric_field")

    def test_signed_boolean_sequence_never_passes_as_int(self):
        self.data["sequence"] = True
        self.sign()
        self.assert_refused("invalid_numeric_field")


if __name__ == "__main__":
    unittest.main()
