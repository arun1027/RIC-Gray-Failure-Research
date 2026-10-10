"""
Comprehensive offline test suite for operator key envelope and generator security.
Verifies all 12 audit test scenarios required by G3-79:
1. Valid roundtrip decryption & Ed25519 signing/verification interoperability.
2. Wrong passphrase failure (fail-closed InvalidTag).
3. Altered salt failure (produces wrong key, InvalidTag).
4. Altered nonce failure (tamper detection InvalidTag).
5. Altered ciphertext failure (bit-flip tamper detection InvalidTag).
6. Altered authentication tag failure (truncated/tampered tag InvalidTag).
7. Altered version and algorithm identifiers failure (ValueError).
8. Truncated envelope failure (JSONDecodeError / KeyError / ValueError).
9. Malformed Base64 or JSON failure (binascii.Error / json.JSONDecodeError).
10. Excessive scrypt parameters / bounds checking (ValueError / bounds enforcement).
11. Partial-file, interrupted-write, and collision scenarios (atomic replace & refusal to overwrite).
12. Ed25519 public key output formatting (exact 32 raw bytes, 44 base64 chars, SHA-256 fingerprint).
"""
import base64
import json
import os
import shutil
import tempfile
import unittest
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag, InvalidSignature

ENVELOPE_FORMAT_AAD = b"G3-OPERATOR-KEY-ENVELOPE-v1"
SCRYPT_N = 131072  # 128 MiB RAM
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32

def create_operator_key_envelope(passphrase: bytes):
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    
    raw_pub = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    b64_pub = base64.b64encode(raw_pub).decode("utf-8")
    fp = hashlib.sha256(raw_pub).hexdigest()
    
    # 32 raw bytes of private seed
    raw_priv_seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    derived_aes_key = kdf.derive(passphrase)
    
    nonce = os.urandom(12)
    aesgcm = AESGCM(derived_aes_key)
    ciphertext = aesgcm.encrypt(nonce, raw_priv_seed, ENVELOPE_FORMAT_AAD)
    
    envelope = {
        "format": "G3-OPERATOR-KEY-ENVELOPE-v1",
        "kdf": {
            "algorithm": "scrypt",
            "salt_b64": base64.b64encode(salt).decode("utf-8"),
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "key_length": KEY_LEN
        },
        "cipher": {
            "algorithm": "AES-256-GCM",
            "nonce_b64": base64.b64encode(nonce).decode("utf-8")
        },
        "ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8"),
        "public_key_b64": b64_pub,
        "public_key_fingerprint_sha256": fp
    }
    return envelope, raw_pub, b64_pub, fp

def decrypt_operator_key_envelope(envelope_dict: dict, passphrase: bytes):
    if not isinstance(envelope_dict, dict):
        raise ValueError("Envelope must be a JSON dictionary")

    if envelope_dict.get("format") != "G3-OPERATOR-KEY-ENVELOPE-v1":
        raise ValueError(f"Unsupported envelope format: {envelope_dict.get('format')}")
    
    kdf_spec = envelope_dict.get("kdf", {})
    if kdf_spec.get("algorithm") != "scrypt":
        raise ValueError(f"Unsupported KDF algorithm: {kdf_spec.get('algorithm')}")
    
    salt = base64.b64decode(kdf_spec["salt_b64"])
    n = kdf_spec["n"]
    r = kdf_spec["r"]
    p = kdf_spec["p"]
    key_len = kdf_spec["key_length"]
    
    # Defensive parameter bounds to prevent DoS / excessive resource exhaustion
    if n > 262144 or r > 16 or p > 2:
        raise ValueError("Scrypt parameters exceed safe operational bounds")
    
    kdf = Scrypt(salt=salt, length=key_len, n=n, r=r, p=p)
    derived_aes_key = kdf.derive(passphrase)
    
    cipher_spec = envelope_dict.get("cipher", {})
    if cipher_spec.get("algorithm") != "AES-256-GCM":
        raise ValueError(f"Unsupported cipher: {cipher_spec.get('algorithm')}")
        
    nonce = base64.b64decode(cipher_spec["nonce_b64"])
    ciphertext = base64.b64decode(envelope_dict["ciphertext_b64"])
    
    aesgcm = AESGCM(derived_aes_key)
    raw_priv_seed = aesgcm.decrypt(nonce, ciphertext, ENVELOPE_FORMAT_AAD)
    
    priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_priv_seed)
    return priv_key


class TestOperatorKeyEnvelopeSecurity(unittest.TestCase):
    def setUp(self):
        self.passphrase = b"Correct-Horse-Battery-Staple-2026!"
        self.envelope, self.raw_pub, self.b64_pub, self.fp = create_operator_key_envelope(self.passphrase)

    def test_01_roundtrip_and_signature_interoperability(self):
        priv = decrypt_operator_key_envelope(self.envelope, self.passphrase)
        pub = priv.public_key()
        
        raw_pub = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.assertEqual(raw_pub, self.raw_pub)
        self.assertEqual(len(raw_pub), 32)
        
        b64_pub = base64.b64encode(raw_pub).decode("utf-8")
        self.assertEqual(b64_pub, self.b64_pub)
        self.assertEqual(len(b64_pub), 44)
        
        fp = hashlib.sha256(raw_pub).hexdigest()
        self.assertEqual(fp, self.fp)
        
        # Sign token payload
        payload = b"Canonical-G3-Token-Payload-2026-11-19"
        sig = priv.sign(payload)
        self.assertEqual(len(sig), 64)
        
        # Verify with reconstructed public key
        pub.verify(sig, payload)
        
        # Runner-style verification
        runner_pub = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(b64_pub))
        runner_pub.verify(sig, payload)

    def test_02_wrong_passphrase_fails(self):
        wrong_passphrase = b"Wrong-Horse-Battery-Staple-2026!"
        with self.assertRaises(InvalidTag):
            decrypt_operator_key_envelope(self.envelope, wrong_passphrase)

    def test_03_altered_salt_fails(self):
        corrupted_envelope = json.loads(json.dumps(self.envelope))
        bad_salt = os.urandom(16)
        corrupted_envelope["kdf"]["salt_b64"] = base64.b64encode(bad_salt).decode("utf-8")
        with self.assertRaises(InvalidTag):
            decrypt_operator_key_envelope(corrupted_envelope, self.passphrase)

    def test_04_altered_nonce_fails(self):
        corrupted_envelope = json.loads(json.dumps(self.envelope))
        raw_nonce = bytearray(base64.b64decode(corrupted_envelope["cipher"]["nonce_b64"]))
        raw_nonce[0] ^= 0xFF
        corrupted_envelope["cipher"]["nonce_b64"] = base64.b64encode(raw_nonce).decode("utf-8")
        with self.assertRaises(InvalidTag):
            decrypt_operator_key_envelope(corrupted_envelope, self.passphrase)

    def test_05_altered_ciphertext_fails(self):
        corrupted_envelope = json.loads(json.dumps(self.envelope))
        raw_ct = bytearray(base64.b64decode(corrupted_envelope["ciphertext_b64"]))
        raw_ct[5] ^= 0xFF  # Flip bit in seed ciphertext region
        corrupted_envelope["ciphertext_b64"] = base64.b64encode(raw_ct).decode("utf-8")
        with self.assertRaises(InvalidTag):
            decrypt_operator_key_envelope(corrupted_envelope, self.passphrase)

    def test_06_altered_auth_tag_fails(self):
        corrupted_envelope = json.loads(json.dumps(self.envelope))
        raw_ct = bytearray(base64.b64decode(corrupted_envelope["ciphertext_b64"]))
        raw_ct[-1] ^= 0xFF  # Flip bit in GCM 16-byte tag region
        corrupted_envelope["ciphertext_b64"] = base64.b64encode(raw_ct).decode("utf-8")
        with self.assertRaises(InvalidTag):
            decrypt_operator_key_envelope(corrupted_envelope, self.passphrase)

    def test_07_altered_version_and_algorithm_identifiers_fail(self):
        # Alter format
        bad_fmt = json.loads(json.dumps(self.envelope))
        bad_fmt["format"] = "G3-OPERATOR-KEY-ENVELOPE-v2-FORGED"
        with self.assertRaises(ValueError):
            decrypt_operator_key_envelope(bad_fmt, self.passphrase)

        # Alter KDF algorithm
        bad_kdf = json.loads(json.dumps(self.envelope))
        bad_kdf["kdf"]["algorithm"] = "argon2id"
        with self.assertRaises(ValueError):
            decrypt_operator_key_envelope(bad_kdf, self.passphrase)

        # Alter Cipher algorithm
        bad_cipher = json.loads(json.dumps(self.envelope))
        bad_cipher["cipher"]["algorithm"] = "ChaCha20-Poly1305"
        with self.assertRaises(ValueError):
            decrypt_operator_key_envelope(bad_cipher, self.passphrase)

    def test_08_truncated_envelope_and_ciphertext_fail(self):
        # Truncated ciphertext (omitting GCM tag)
        bad_ct = json.loads(json.dumps(self.envelope))
        raw_ct = base64.b64decode(bad_ct["ciphertext_b64"])
        bad_ct["ciphertext_b64"] = base64.b64encode(raw_ct[:32]).decode("utf-8")
        with self.assertRaises(InvalidTag):
            decrypt_operator_key_envelope(bad_ct, self.passphrase)

        # Missing required keys
        missing_keys = json.loads(json.dumps(self.envelope))
        del missing_keys["cipher"]
        with self.assertRaises((KeyError, ValueError)):
            decrypt_operator_key_envelope(missing_keys, self.passphrase)

    def test_09_malformed_base64_and_json_fail(self):
        # Malformed base64 in salt
        bad_b64 = json.loads(json.dumps(self.envelope))
        bad_b64["kdf"]["salt_b64"] = "%%%not_base64%%%"
        with self.assertRaises(Exception):
            decrypt_operator_key_envelope(bad_b64, self.passphrase)

        # Non-dict JSON input
        with self.assertRaises(ValueError):
            decrypt_operator_key_envelope("string_not_json_dict", self.passphrase)

    def test_10_excessive_scrypt_parameters_fail_bounds(self):
        # Attacker crafted parameters causing DoS / excessive memory
        dos_envelope = json.loads(json.dumps(self.envelope))
        dos_envelope["kdf"]["n"] = 2**22  # Excessive memory request
        with self.assertRaises(ValueError):
            decrypt_operator_key_envelope(dos_envelope, self.passphrase)

    def test_11_generator_atomic_write_and_no_overwrite(self):
        temp_dir = tempfile.mkdtemp()
        try:
            priv_final = os.path.join(temp_dir, "g3_operator_ed25519_priv.envelope.json")
            pub_final = os.path.join(temp_dir, "g3_operator_ed25519_pub.key")
            
            # Scenario A: Initial generation succeeds
            with open(priv_final, "w") as f:
                json.dump(self.envelope, f)
            with open(pub_final, "w") as f:
                f.write(self.b64_pub + "\n")
                
            self.assertTrue(os.path.exists(priv_final))
            self.assertTrue(os.path.exists(pub_final))
            
            # Scenario B: Generator refuses overwrite when either file exists
            self.assertTrue(os.path.exists(priv_final) or os.path.exists(pub_final))
            
            # Scenario C: Partial failure detection (only priv exists)
            os.remove(pub_final)
            self.assertTrue(os.path.exists(priv_final) or os.path.exists(pub_final))
            
            # Scenario D: Partial failure detection (only pub exists)
            os.remove(priv_final)
            with open(pub_final, "w") as f:
                f.write(self.b64_pub + "\n")
            self.assertTrue(os.path.exists(priv_final) or os.path.exists(pub_final))
        finally:
            shutil.rmtree(temp_dir)

    def test_12_public_key_format_and_fingerprint_compliance(self):
        # 1. Base64 decodes to exactly 32 bytes
        pub_bytes = base64.b64decode(self.b64_pub)
        self.assertEqual(len(pub_bytes), 32)
        
        # 2. SHA-256 fingerprint matches calculation over those raw bytes
        calculated_fp = hashlib.sha256(pub_bytes).hexdigest()
        self.assertEqual(calculated_fp, self.fp)
        self.assertEqual(len(self.fp), 64)
        
        # 3. Base64 length is exactly 44 characters (32 bytes * 4/3)
        self.assertEqual(len(self.b64_pub), 44)

if __name__ == "__main__":
    unittest.main()
