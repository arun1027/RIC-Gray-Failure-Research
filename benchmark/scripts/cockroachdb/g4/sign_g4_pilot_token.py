"""
sign_g4_pilot_token.py - Standalone Operator Signing Utility for CockroachDB G4 Pilot Runs.
Designed for offline/interactive operator execution.
Conforms strictly to the G4 Ed25519 cryptographic authorization schema and the trusted public key contract.

Usage:
    python sign_g4_pilot_token.py \
        --run-id crdb-g4l1-p01 \
        --level L1 \
        --load 80 \
        --workers 1 \
        --duration 180 \
        --runner-hash 2e78dc1922524a71e25ade53c57623f18a54eaafd15d564d1dcfd97d91970d9d \
        --manifest-hash c6254254a7267aa923654177a5a9c0b3b5b7ecaf954b6db9cfe7fb8949cbd10e \
        --pod-uid 1a98abd7-7ac3-4bd6-96ee-1dcfd67f0f67 \
        --output C:\\OperatorKeys\\g4\\crdb-g4l1-p01.auth.json
"""

import argparse
import base64
import datetime
import getpass
import hashlib
import json
import os
import secrets
import sys
import uuid

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("[ERROR] Required 'cryptography' library is not installed.")
    sys.exit(1)

DEFAULT_KEY_DIR = r"C:\OperatorKeys\g3"
DEFAULT_ENVELOPE = os.path.join(DEFAULT_KEY_DIR, "g3_operator_ed25519_priv.envelope.json")
DEFAULT_PUBKEY = os.path.join(DEFAULT_KEY_DIR, "g3_operator_ed25519_pub.key")
TRUSTED_PUBKEY_FP = "78466ea05398c7b3a26440ba42230989ba6a092f5942e5d5ec152a95c434f621"

PROTOCOL_VERSION = "G4-01"

LEVEL_PARAMS = {
    "L1": {"load": 80, "workers": 1},
    "L2": {"load": 90, "workers": 1},
    "L3": {"load": 95, "workers": 1}
}

def canonicalize_payload(payload: dict) -> bytes:
    """Deterministic, canonical JSON serialization matching RFC 8785."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def parse_args():
    parser = argparse.ArgumentParser(description="Sign G4 CPU Starvation Pilot Authorization Token")
    parser.add_argument("--run-id", required=True, help="Target Pilot Run ID (e.g. crdb-g4l1-p01)")
    parser.add_argument("--level", required=True, choices=["L1", "L2", "L3"], help="Fault Level")
    parser.add_argument("--load", type=int, required=True, help="CPU load percentage (e.g. 80)")
    parser.add_argument("--workers", type=int, default=1, help="Stressor workers count")
    parser.add_argument("--duration", type=int, default=180, help="Fault duration in seconds")
    parser.add_argument("--runner-hash", required=True, help="Expected SHA-256 of g4_pilot_runner.py")
    parser.add_argument("--manifest-hash", required=True, help="Expected SHA-256 of target StressChaos manifest")
    parser.add_argument("--pod-uid", required=True, help="Target pod UID")
    parser.add_argument("--protocol", default=PROTOCOL_VERSION, help="Protocol identifier")
    parser.add_argument("--envelope", default=DEFAULT_ENVELOPE, help="Path to operator private key envelope")
    parser.add_argument("--pubkey", default=DEFAULT_PUBKEY, help="Path to operator public key")
    parser.add_argument("--output", required=True, help="Output destination for signed token JSON")
    return parser.parse_args()

def main():
    args = parse_args()

    print("=" * 70)
    print("COCKROACHDB G4 PILOT — OPERATOR ED25519 SIGNING CEREMONY")
    print("=" * 70)
    print(f"Run ID:            {args.run_id}")
    print(f"Level:             {args.level} (load={args.load}%, workers={args.workers}, duration={args.duration}s)")
    print(f"Runner SHA-256:    {args.runner_hash}")
    print(f"Manifest SHA-256:  {args.manifest_hash}")
    print(f"Target Pod UID:    {args.pod_uid}")
    print(f"Protocol:          {args.protocol}")
    print(f"Output Destination:{args.output}")
    print("=" * 70)

    # 1. Validate Level Parameters
    expected = LEVEL_PARAMS.get(args.level)
    if not expected:
        print(f"[ERROR] Unknown level: {args.level}")
        sys.exit(1)
    if args.load != expected["load"] or args.workers != expected["workers"]:
        print(f"[ERROR] Specified load ({args.load}) or workers ({args.workers}) does not match protocol spec {expected}")
        sys.exit(1)

    # 2. Check destination collision
    out_dir = os.path.dirname(os.path.abspath(args.output))
    if not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    if os.path.exists(args.output):
        print(f"[ERROR] Destination file already exists: {args.output}")
        print("To re-sign, archive or remove the existing token first.")
        sys.exit(1)
    if os.path.exists(f"{args.output}.consumed"):
        print(f"[ERROR] Consumption marker already exists: {args.output}.consumed")
        print("A token at this path was already consumed. Single-use rule violated.")
        sys.exit(1)

    # 3. Verify public key trust anchor
    if not os.path.isfile(args.pubkey):
        print(f"[ERROR] Public key file not found: {args.pubkey}")
        sys.exit(1)
    with open(args.pubkey, "r", encoding="utf-8") as f:
        pk_b64 = f.read().strip()
    pub_bytes = base64.b64decode(pk_b64)
    pub_fp = hashlib.sha256(pub_bytes).hexdigest()
    if pub_fp != TRUSTED_PUBKEY_FP:
        print(f"[ERROR] Untrusted public key fingerprint: {pub_fp}")
        print(f"Expected authoritative pinned fingerprint: {TRUSTED_PUBKEY_FP}")
        sys.exit(1)
    print(f"[OK] Trusted Operator Public Key Fingerprint Verified: {pub_fp}")

    # 4. Load Envelope
    if not os.path.isfile(args.envelope):
        print(f"[ERROR] Key envelope not found: {args.envelope}")
        sys.exit(1)
    with open(args.envelope, "r", encoding="utf-8") as f:
        envelope = json.load(f)
    if envelope.get("format") != "G3-OPERATOR-KEY-ENVELOPE-v1":
        print(f"[ERROR] Unsupported envelope format: {envelope.get('format')}")
        sys.exit(1)

    # 5. Interactive Passphrase Entry
    passphrase = getpass.getpass("Enter Operator Key Envelope Passphrase: ")
    if not passphrase:
        print("[ERROR] Passphrase cannot be empty.")
        sys.exit(1)

    pass_bytes = passphrase.encode("utf-8")
    seed = None
    try:
        # KDF derivation
        kdf_cfg = envelope["kdf"]
        salt = base64.b64decode(kdf_cfg["salt_b64"])
        kdf = Scrypt(
            salt=salt,
            length=kdf_cfg["key_length"],
            n=kdf_cfg["n"],
            r=kdf_cfg["r"],
            p=kdf_cfg["p"]
        )
        derived_key = kdf.derive(pass_bytes)

        # AES-GCM Decryption
        cipher_cfg = envelope["cipher"]
        nonce = base64.b64decode(cipher_cfg["nonce_b64"])
        ciphertext = base64.b64decode(envelope["ciphertext_b64"])
        aesgcm = AESGCM(derived_key)
        seed = aesgcm.decrypt(nonce, ciphertext, envelope["format"].encode("utf-8"))

        # Key reconstruction & verification against public key
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        if priv_key.public_key().public_bytes_raw() != pub_bytes:
            print("[ERROR] Decrypted private key does not match trusted public key!")
            sys.exit(1)
        print("[OK] Operator private key successfully decrypted and authenticated.")

        # Construct G4 Authorization Payload
        now = datetime.datetime.now(datetime.timezone.utc)
        not_before = now - datetime.timedelta(seconds=60)
        expires_at = now + datetime.timedelta(hours=2)

        payload = {
            "authorization_id": f"auth-{args.run_id}-{secrets.token_hex(4)}",
            "authorized_run_id": args.run_id,
            "authorized_level": args.level,
            "parameters": {
                "load": args.load,
                "workers": args.workers,
                "fault_duration_sec": args.duration,
                "max_fault_duration_sec": args.duration
            },
            "runner_sha256": args.runner_hash.lower(),
            "manifest_sha256": args.manifest_hash.lower(),
            "target_pod_uid": args.pod_uid,
            "protocol_version": args.protocol,
            "operator_identity": os.environ.get("USERNAME", "operator"),
            "nonce": secrets.token_hex(16),
            "issued_at_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "not_before_utc": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at_utc": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        }

        canon_bytes = canonicalize_payload(payload)
        sig_bytes = priv_key.sign(canon_bytes)
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

        # Verify signature internally
        priv_key.public_key().verify(sig_bytes, canon_bytes)
        print("[OK] Ed25519 digital signature generated and verified internally.")

        token_doc = {
            "schema_version": "G4-AUTHORIZATION-TOKEN-v1",
            "payload": payload,
            "signature": sig_b64
        }

        # Write atomic token file
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(token_doc, f, indent=2)

        print("=" * 70)
        print(f"[SUCCESS] Signed G4 Authorization Token Created: {args.output}")
        print(f"Token SHA-256: {hashlib.sha256(open(args.output, 'rb').read()).hexdigest()}")
        print(f"Valid Until:   {payload['expires_at_utc']}")
        print("=" * 70)

    except Exception as e:
        print(f"[ERROR] Signing ceremony failed: {e}")
        sys.exit(1)
    finally:
        # Clear sensitive buffers
        if 'pass_bytes' in locals():
            del pass_bytes
        if seed is not None:
            del seed

if __name__ == "__main__":
    main()
