"""
test_sign_g4_pilot_token_offline.py - Offline mock test for sign_g4_pilot_token.py.
Tests argument parsing, envelope decryption, and signature compatibility with g4_pilot_runner.py verifier.
"""

import base64
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

import benchmark.scripts.cockroachdb.g4.sign_g4_pilot_token as signer
import benchmark.scripts.cockroachdb.g4.g4_pilot_runner as runner

class TestSignG4PilotTokenOffline(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_sign_g4_")
        self.key_dir = os.path.join(self.test_dir, "keys")
        os.makedirs(self.key_dir, exist_ok=True)

        if HAS_CRYPTOGRAPHY:
            self.priv_key = ed25519.Ed25519PrivateKey.generate()
            self.pub_key = self.priv_key.public_key()
            pub_bytes = self.pub_key.public_bytes_raw()
            self.pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
            self.pub_fp = hashlib.sha256(pub_bytes).hexdigest()

            self.pub_file = os.path.join(self.key_dir, "pub.key")
            with open(self.pub_file, "w") as f:
                f.write(self.pub_b64)

            # Create test envelope
            seed = self.priv_key.private_bytes_raw()
            derived_key = b"\x01" * 32
            aesgcm = AESGCM(derived_key)
            nonce = b"\x02" * 12
            ciphertext = aesgcm.encrypt(nonce, seed, b"G3-OPERATOR-KEY-ENVELOPE-v1")

            self.envelope_file = os.path.join(self.key_dir, "priv.envelope.json")
            envelope_doc = {
                "format": "G3-OPERATOR-KEY-ENVELOPE-v1",
                "kdf": {
                    "salt_b64": base64.b64encode(b"salt1234").decode("ascii"),
                    "key_length": 32,
                    "n": 1024,
                    "r": 8,
                    "p": 1
                },
                "cipher": {
                    "nonce_b64": base64.b64encode(nonce).decode("ascii")
                },
                "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii")
            }
            with open(self.envelope_file, "w") as f:
                json.dump(envelope_doc, f)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "Requires cryptography")
    def test_signer_generates_token_verified_by_runner(self):
        token_output = os.path.join(self.test_dir, "output.auth.json")
        fake_runner = os.path.join(self.test_dir, "g4_pilot_runner.py")
        with open(fake_runner, "w") as f:
            f.write("# runner test")
        runner_sha = hashlib.sha256(open(fake_runner, "rb").read()).hexdigest()

        test_args = [
            "sign_g4_pilot_token.py",
            "--run-id", "crdb-g4l1-p01",
            "--level", "L1",
            "--load", "80",
            "--workers", "1",
            "--duration", "180",
            "--runner-hash", runner_sha,
            "--manifest-hash", "c6254254a7267aa923654177a5a9c0b3b5b7ecaf954b6db9cfe7fb8949cbd10e",
            "--pod-uid", "1a98abd7-7ac3-4bd6-96ee-1dcfd67f0f67",
            "--pubkey", self.pub_file,
            "--envelope", self.envelope_file,
            "--output", token_output
        ]

        with patch.object(signer, "TRUSTED_PUBKEY_FP", self.pub_fp):
            with patch("sys.argv", test_args):
                with patch("getpass.getpass", return_value="dummy_pass"):
                    with patch("cryptography.hazmat.primitives.kdf.scrypt.Scrypt.derive", return_value=b"\x01"*32):
                        signer.main()

        self.assertTrue(os.path.isfile(token_output))

        # Now test that runner's verify_and_consume_authorization verifies and consumes it!
        with patch.object(runner, "TRUSTED_OPERATOR_PUBKEY_SHA256", self.pub_fp):
            auth_res = runner.verify_and_consume_authorization(
                auth_file_path=token_output,
                run_id="crdb-g4l1-p01",
                level="L1",
                duration_sec=180,
                manifest_sha256="c6254254a7267aa923654177a5a9c0b3b5b7ecaf954b6db9cfe7fb8949cbd10e",
                target_pod_uid="1a98abd7-7ac3-4bd6-96ee-1dcfd67f0f67",
                runner_path=fake_runner,
                public_key_path=self.pub_file
            )

            self.assertTrue(auth_res["signature_verified"])
            self.assertEqual(auth_res["authorized_run_id"], "crdb-g4l1-p01")
            self.assertTrue(os.path.exists(f"{token_output}.consumed"))

if __name__ == "__main__":
    unittest.main()
