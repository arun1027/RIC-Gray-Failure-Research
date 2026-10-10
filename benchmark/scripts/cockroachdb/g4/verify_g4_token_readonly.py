
import os
import sys
import json
import base64
import hashlib
import datetime
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519



token_path = Path(r"C:\OperatorKeys\g4\crdb-g4l1-p01-retry6.auth.json")
consumed_path = token_path.with_suffix(token_path.suffix + ".consumed")
pubkey_path = r"C:\OperatorKeys\g3\g3_operator_ed25519_pub.key"

trusted_fp = "78466ea05398c7b3a26440ba42230989ba6a092f5942e5d5ec152a95c434f621"

expected_runner_sha = "f6c67a675b8c5dd65dff6f8b0ac99de6f9a1d2abb4ccca1b15b81118ebafa1f9"

expected_manifest_sha = "c6254254a7267aa923654177a5a9c0b3b5b7ecaf954b6db9cfe7fb8949cbd10e"

expected_pod_uid = "1a98abd7-7ac3-4bd6-96ee-1dcfd67f0f67"
expected_token_sha = "4895291a9c7e052dab62571ad16aeef3d05693e22feecc252621692829a464ab"

results = {}

# Check 10: Token file SHA-256
if not os.path.exists(token_path):
    print(f"FAIL: Token file not found at {token_path}")
    sys.exit(1)

with open(token_path, "rb") as f:
    token_bytes = f.read()

actual_token_sha = hashlib.sha256(token_bytes).hexdigest()

results["10_token_file_sha256"] = (
    "PASS" if actual_token_sha == expected_token_sha
    else f"FAIL (got {actual_token_sha})"
)

# Check 9: Consumption marker non-existence
results["09_not_previously_consumed"] = (
    "PASS" if not os.path.exists(consumed_path)
    else "FAIL (already consumed)"
)

# Parse token document
token_doc = json.loads(token_bytes.decode("utf-8"))
payload = token_doc.get("payload", {})
sig_b64 = token_doc.get("signature", "")

# Check 2: Public key fingerprint
with open(pubkey_path, "r", encoding="utf-8") as f:
    pk_b64 = f.read().strip()

pub_bytes = base64.b64decode(pk_b64)
actual_pub_fp = hashlib.sha256(pub_bytes).hexdigest()

results["02_pubkey_fingerprint"] = (
    "PASS" if actual_pub_fp == trusted_fp
    else f"FAIL (got {actual_pub_fp})"
)

# Check 1: Ed25519 signature
def canonicalize_payload(p: dict) -> bytes:
    return json.dumps(
        p,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


canon_bytes = canonicalize_payload(payload)
sig_bytes = base64.b64decode(sig_b64)

pub_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

try:
    pub_key_obj.verify(sig_bytes, canon_bytes)
    results["01_ed25519_signature"] = "PASS"
except Exception as e:
    results["01_ed25519_signature"] = f"FAIL ({e})"

# Check 3: Run ID
actual_run_id = payload.get("authorized_run_id")

results["03_run_id"] = (
    "PASS" if actual_run_id == "crdb-g4l1-p01"
    else f"FAIL (got {actual_run_id})"
)

# Check 4: Runner and manifest SHA-256 bindings
actual_runner_sha = payload.get("runner_sha256")
actual_manifest_sha = payload.get("manifest_sha256")

runner_pass = actual_runner_sha == expected_runner_sha
manifest_pass = actual_manifest_sha == expected_manifest_sha

results["04_runner_and_manifest_sha256"] = (
    "PASS" if runner_pass and manifest_pass
    else f"FAIL (runner={actual_runner_sha}, manifest={actual_manifest_sha})"
)

# Check 5: Target pod UID
actual_pod_uid = payload.get("target_pod_uid")

results["05_target_pod_uid"] = (
    "PASS" if actual_pod_uid == expected_pod_uid
    else f"FAIL (got {actual_pod_uid})"
)

# Check 6: L1 parameters
params = payload.get("parameters", {})

p_load = params.get("load") == 80
p_workers = params.get("workers") == 1

p_dur = (
    params.get("fault_duration_sec") == 180
    and params.get("max_fault_duration_sec") == 180
)

results["06_l1_parameters"] = (
    "PASS" if p_load and p_workers and p_dur
    else (
        f"FAIL (load={params.get('load')}, "
        f"workers={params.get('workers')}, "
        f"dur={params.get('fault_duration_sec')})"
    )
)

# Check 7: Protocol
actual_proto = payload.get("protocol_version")

results["07_protocol"] = (
    "PASS" if actual_proto == "G4-01"
    else f"FAIL (got {actual_proto})"
)

# Check 8: Validity window against current UTC time
now = datetime.datetime.now(datetime.timezone.utc)

nb = datetime.datetime.fromisoformat(
    payload.get("not_before_utc").replace("Z", "+00:00")
)

exp = datetime.datetime.fromisoformat(
    payload.get("expires_at_utc").replace("Z", "+00:00")
)

valid_window = nb <= now <= exp

results["08_validity_window"] = (
    "PASS" if valid_window
    else (
        f"FAIL (now={now.isoformat()}, "
        f"nb={nb.isoformat()}, exp={exp.isoformat()})"
    )
)

# Final results
print(json.dumps(results, indent=2))

# Non-zero exit if any check fails
if not all(value == "PASS" for value in results.values()):
    sys.exit(1)
