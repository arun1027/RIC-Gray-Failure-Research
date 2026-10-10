"""
g3_pilot_runner.py - Complete Hardened Orchestrator for CockroachDB G3 Controlled Disk I/O Throttling Pilots.
Target Mechanism: Linux Cgroups v2 io.max via ephemeral helper Job.
Adheres strictly to the four-clock timing model, Option B dataset safety, fail-closed rollback,
idempotent cleanup traps, explicit 15-state execution coordinator, and independent emergency recovery.
"""

import argparse
import base64
import datetime
import enum
import hashlib
import json
import os
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Dict, Any, List, Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

NAMESPACE = "cockroachdb"
CHAOS_NAMESPACE = "g1-chaos"
CLIENT_POD = "crdb-benchmark-client-hardened"
HELPER_IMAGE = "397916376204.dkr.ecr.us-east-1.amazonaws.com/ric-g2-helper@sha256:c91021ab1a9ab57edecb8a72ad2e872b60e85231f600a3a030f81360d6cb5924"

PROTOCOL_VERSION = "G3-04"
DEFAULT_PUBLIC_KEY_PATH = "security/keys/g3_operator_ed25519_pub.key"
TRUSTED_OPERATOR_PUBKEY_SHA256 = "78466ea05398c7b3a26440ba42230989ba6a092f5942e5d5ec152a95c434f621"

PSQL_CONN = (
    "sslmode=verify-full "
    "sslrootcert=/cockroach-certs/ca.crt "
    "sslcert=/cockroach-certs/client.root.crt "
    "sslkey=/cockroach-certs/client.root.key "
    "host=cockroachdb-public port=26257 user=root dbname=benchdb"
)

# Proposed severity limits (provisional pending calibration).
# NOTE: Units are binary MiB/s byte values (e.g., 5.0 MiB/s = 5,242,880 B/s).
SEVERITY_LIMITS = {
    "L1": {"wbps": 5242880, "wiops": 600, "desc": "5.0 MiB/s (5,242,880 B/s), 600 IOPS [PROVISIONAL]"},
    "L2": {"wbps": 2097152, "wiops": 250, "desc": "2.0 MiB/s (2,097,152 B/s), 250 IOPS [PROVISIONAL]"},
    "L3": {"wbps": 524288, "wiops": 75, "desc": "0.5 MiB/s (524,288 B/s), 75 IOPS [PROVISIONAL]"},
}

class ExecutionState(enum.Enum):
    PREFLIGHT = "PREFLIGHT"
    TARGET_VERIFICATION = "TARGET_VERIFICATION"
    WORKLOAD_START = "WORKLOAD_START"
    WARMUP = "WARMUP"
    BASELINE_MEASUREMENT = "BASELINE_MEASUREMENT"
    FAULT_APPLICATION = "FAULT_APPLICATION"
    FAULT_VERIFICATION = "FAULT_VERIFICATION"
    FAULT_MEASUREMENT = "FAULT_MEASUREMENT"
    FAULT_REMOVAL = "FAULT_REMOVAL"
    RESTORATION_VERIFICATION = "RESTORATION_VERIFICATION"
    POST_FAULT_MEASUREMENT = "POST_FAULT_MEASUREMENT"
    WREC_OBSERVATION = "WREC_OBSERVATION"
    FINAL_HEALTH_CHECK = "FINAL_HEALTH_CHECK"
    EVIDENCE_COLLECTION = "EVIDENCE_COLLECTION"
    FINAL_DISPOSITION = "FINAL_DISPOSITION"

def log(msg: str) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(f"[{now}] {msg}", flush=True)

def run_cmd(cmd: List[str], check: bool = True, timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout)

def query_sql(query: str) -> str:
    cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "psql", PSQL_CONN, "-t", "-A", "-c", query
    ]
    res = run_cmd(cmd, check=True, timeout=15.0)
    return res.stdout.strip()

def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

IO_MAX_LIMIT_KEYS = ("rbps", "wbps", "riops", "wiops")

def decode_linux_st_dev(dev_stat_dec: int) -> Tuple[int, int]:
    """
    Decode a Linux st_dev integer (`stat -c %d`) into (major, minor)
    matching glibc sysmacros major()/minor() for both legacy and extended minors.
    """
    if not isinstance(dev_stat_dec, int) or isinstance(dev_stat_dec, bool) or dev_stat_dec < 0:
        raise ValueError(f"Invalid st_dev integer: {dev_stat_dec!r}")
    major = ((dev_stat_dec >> 8) & 0xFFF) | ((dev_stat_dec >> 32) & ~0xFFF)
    minor = (dev_stat_dec & 0xFF) | ((dev_stat_dec >> 12) & ~0xFF)
    return major, minor

def parse_io_max_content(io_max_text: str) -> Dict[str, Dict[str, str]]:
    """
    Strictly parse Linux cgroups v2 io.max content.
    Every non-empty line must be `<major>:<minor> rbps=<v> wbps=<v> riops=<v> wiops=<v>`
    with valid uint device numbers, all four keys present, and values equal to 'max' or uint.
    """
    if not isinstance(io_max_text, str):
        raise ValueError("io.max content must be a string")
    parsed: Dict[str, Dict[str, str]] = {}
    for line_no, raw_line in enumerate(io_max_text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        dev_tok = parts[0]
        dev_parts = dev_tok.split(":")
        if len(dev_parts) != 2 or not dev_parts[0].isdigit() or not dev_parts[1].isdigit():
            raise ValueError(f"Malformed device identifier on io.max line {line_no}: {dev_tok!r}")
        dev_id = f"{int(dev_parts[0])}:{int(dev_parts[1])}"
        if dev_id in parsed:
            raise ValueError(f"Duplicate device entry {dev_id} on io.max line {line_no}")
        limits: Dict[str, str] = {}
        for tok in parts[1:]:
            if "=" not in tok:
                raise ValueError(f"Malformed token {tok!r} on io.max line {line_no}")
            k, v = tok.split("=", 1)
            if k not in IO_MAX_LIMIT_KEYS:
                raise ValueError(f"Unexpected io.max key {k!r} on line {line_no}")
            if k in limits:
                raise ValueError(f"Duplicate key {k!r} for device {dev_id} on line {line_no}")
            if v != "max" and not v.isdigit():
                raise ValueError(f"Malformed limit value {tok!r} on io.max line {line_no}")
            limits[k] = v
        missing = [k for k in IO_MAX_LIMIT_KEYS if k not in limits]
        if missing:
            raise ValueError(f"Incomplete io.max entry for {dev_id} on line {line_no}; missing {missing}")
        parsed[dev_id] = limits
    return parsed

def extract_device_io_max_line(io_max_text: str, dev_major: int, dev_minor: int) -> str:
    """Validate io.max content and return the normalized line for <dev_major>:<dev_minor>, or ''."""
    entries = parse_io_max_content(io_max_text)
    dev_id = f"{dev_major}:{dev_minor}"
    if dev_id not in entries:
        return ""
    e = entries[dev_id]
    return f"{dev_id} rbps={e['rbps']} wbps={e['wbps']} riops={e['riops']} wiops={e['wiops']}"

def verify_io_max_applied(
    io_max_text: str,
    dev_major: int,
    dev_minor: int,
    expected_wbps: int,
    expected_wiops: int,
    original_io_max_raw: str = ""
) -> Tuple[bool, str]:
    """Verify exact fault application for target device across all four io.max limits."""
    try:
        entries = parse_io_max_content(io_max_text)
    except ValueError as e:
        return False, f"Malformed io.max during fault verification: {e}"
    try:
        orig_entries = parse_io_max_content(original_io_max_raw) if original_io_max_raw.strip() else {}
    except ValueError as e:
        return False, f"Malformed baseline io.max during fault verification: {e}"
    dev_id = f"{dev_major}:{dev_minor}"
    if dev_id not in entries:
        return False, f"Target device {dev_id} not present in io.max"
    orig_dev = orig_entries.get(dev_id, {})
    exp_rbps = orig_dev.get("rbps", "max")
    exp_riops = orig_dev.get("riops", "max")
    curr = entries[dev_id]
    if (
        curr["rbps"] != exp_rbps
        or curr["wbps"] != str(expected_wbps)
        or curr["riops"] != exp_riops
        or curr["wiops"] != str(expected_wiops)
    ):
        return False, (
            f"io.max mismatch for {dev_id}: expected rbps={exp_rbps} wbps={expected_wbps} "
            f"riops={exp_riops} wiops={expected_wiops}, got {curr}"
        )
    return True, f"Verified exact four-limit rule for {dev_id}: {curr}"

def verify_io_max_restored(
    current_io_max: str,
    dev_major: int,
    dev_minor: int,
    original_io_max_raw: str = ""
) -> Tuple[bool, str]:
    """
    Fail-closed verification that target device io.max matches its exact pre-fault baseline
    across all four limits (rbps, wbps, riops, wiops). Distinguishes legitimate 'max' from
    partial clearance, residual limits, and malformed io.max data.
    """
    try:
        curr_entries = parse_io_max_content(current_io_max)
    except ValueError as e:
        return False, f"Malformed current io.max: {e}"
    try:
        orig_entries = parse_io_max_content(original_io_max_raw) if original_io_max_raw.strip() else {}
    except ValueError as e:
        return False, f"Malformed original io.max baseline: {e}"

    dev_id = f"{dev_major}:{dev_minor}"
    orig_dev = orig_entries.get(dev_id)
    curr_dev = curr_entries.get(dev_id)

    orig_is_unthrottled = (
        orig_dev is None or all(orig_dev[k] == "max" for k in IO_MAX_LIMIT_KEYS)
    )
    if orig_is_unthrottled:
        if curr_dev is None:
            return True, f"Device {dev_id} absent from io.max (unthrottled)"
        if all(curr_dev[k] == "max" for k in IO_MAX_LIMIT_KEYS):
            return True, f"Device {dev_id} restored to rbps=max wbps=max riops=max wiops=max"
        return False, f"Device {dev_id} remains throttled or partial: {curr_dev}"

    if curr_dev is None:
        return False, f"Device {dev_id} missing from io.max; expected original baseline {orig_dev}"
    if all(curr_dev[k] == orig_dev[k] for k in IO_MAX_LIMIT_KEYS):
        return True, f"Device {dev_id} restored to exact original limits: {curr_dev}"
    return False, f"Device {dev_id} limits {curr_dev} do not match original baseline {orig_dev}"

def construct_warmup_command(duration_sec: int = 120) -> List[str]:
    """
    Construct the standalone unlogged pgbench warmup command with '-n' (--no-vacuum)
    so pgbench_history is strictly preserved and never cleared.
    """
    return [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "pgbench", "-h", "cockroachdb-public", "-p", "26257", "-U", "root",
        "-n", "-c", "20", "-j", "4", "-T", str(duration_sec),
        "--max-tries=1", "-M", "simple", "benchdb"
    ]

def compute_tx_stream_span_sec(tx_log_paths: List[str]) -> Optional[float]:
    """
    Calculate Clock 3 (Client Transaction Stream Span: t_last_tx - t_first_tx in seconds)
    from retrieved pgbench microsecond transaction log files.
    """
    min_ts: Optional[float] = None
    max_ts: Optional[float] = None
    row_count = 0
    for path in tx_log_paths:
        if not path or not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 6:
                    continue
                try:
                    epoch_sec = int(parts[4])
                    epoch_usec = int(parts[5])
                except ValueError:
                    continue
                ts = epoch_sec + (epoch_usec / 1_000_000.0)
                if min_ts is None or ts < min_ts:
                    min_ts = ts
                if max_ts is None or ts > max_ts:
                    max_ts = ts
                row_count += 1
    if row_count < 2 or min_ts is None or max_ts is None:
        return None
    return max(0.0, max_ts - min_ts)

def extract_job_name_from_manifest(manifest_yaml: str) -> str:
    """Extract metadata.name from a generated Kubernetes Job YAML string."""
    in_metadata = False
    for line in manifest_yaml.splitlines():
        if line.strip() == "metadata:":
            in_metadata = True
            continue
        if in_metadata:
            if line and not line[0].isspace():
                break
            stripped = line.strip()
            if stripped.startswith("name:"):
                return stripped.split(":", 1)[1].strip()
    return ""

def _utc_now() -> datetime.datetime:
    """Actual UTC wall clock. Tests patch this seam; production never overrides it."""
    return datetime.datetime.now(datetime.timezone.utc)

def canonicalize_payload(payload: Dict[str, Any]) -> bytes:
    """
    Produces deterministic, canonical UTF-8 JSON bytes (RFC 8785 style)
    sorted by keys with no unnecessary whitespace.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def verify_and_consume_authorization(
    auth_file_path: str,
    run_id: str,
    level: str,
    duration_sec: int,
    runner_path: Optional[str] = None,
    public_key_path: Optional[str] = None,
    expected_protocol: str = PROTOCOL_VERSION
) -> Dict[str, Any]:
    """
    Verifies an Ed25519-signed operator authorization token and atomically consumes it.
    Strict fail-closed validation:
    1. Cryptography availability and symlink/path validation.
    2. Handle-bound file opening, regular file check, and token content read.
    3. JSON parsing, schema structure, and parameter binding.
    4. Current runner SHA-256 integrity binding.
    5. Protocol version binding.
    6. UTC timestamp boundaries (not_before <= now <= expires_at).
    7. Pinned public-key fingerprint verification and Ed25519 digital signature.
    8. Post-verification content integrity re-check (TOCTOU mitigation).
    9. Atomic single-use exclusive consumption record (<auth_file_path>.consumed).
    """
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("FAIL-CLOSED: 'cryptography' library is not available for Ed25519 signature verification.")

    if not auth_file_path:
        raise RuntimeError("FAIL-CLOSED: Authorization file path cannot be empty.")

    # 1. Symlink and Path Protections (F04)
    abs_auth_path = os.path.abspath(auth_file_path)
    if os.path.islink(abs_auth_path):
        raise RuntimeError(f"FAIL-CLOSED: Authorization token cannot be a symlink: {abs_auth_path}")

    parent_dir = os.path.dirname(abs_auth_path)
    if os.path.islink(parent_dir):
        raise RuntimeError(f"FAIL-CLOSED: Authorization token parent directory cannot be a symlink: {parent_dir}")

    consumed_marker_path = f"{abs_auth_path}.consumed"
    if os.path.islink(consumed_marker_path):
        raise RuntimeError(f"FAIL-CLOSED: Consumption marker path cannot be a symlink: {consumed_marker_path}")

    if not os.path.exists(abs_auth_path):
        raise RuntimeError(f"FAIL-CLOSED: Authorization file does not exist: {abs_auth_path}")

    # 2. Handle-bound File Opening and Regular File Check (F03 TOCTOU mitigation)
    open_flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        open_flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        open_flags |= os.O_NOFOLLOW

    try:
        token_fd = os.open(abs_auth_path, open_flags)
    except Exception as e:
        raise RuntimeError(f"FAIL-CLOSED: Failed to safely open authorization file: {e}")

    try:
        try:
            token_st = os.fstat(token_fd)
            if not stat.S_ISREG(token_st.st_mode):
                raise RuntimeError(f"FAIL-CLOSED: Authorization file is not a regular file (mode: {token_st.st_mode})")

            with os.fdopen(token_fd, "rb", closefd=True) as f:
                raw_bytes = f.read()
        except Exception:
            try:
                os.close(token_fd)
            except OSError:
                pass
            raise
    except Exception as e:
        raise RuntimeError(f"FAIL-CLOSED: Error reading authorization token handle: {e}")

    token_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    try:
        token_doc = json.loads(raw_bytes.decode("utf-8"))
    except Exception as e:
        raise RuntimeError(f"FAIL-CLOSED: Malformed authorization token JSON: {e}")

    if not isinstance(token_doc, dict):
        raise RuntimeError("FAIL-CLOSED: Authorization token root must be a JSON object.")

    payload = token_doc.get("payload")
    sig_b64 = token_doc.get("signature")

    if not payload or not isinstance(payload, dict):
        raise RuntimeError("FAIL-CLOSED: Authorization token missing valid 'payload' dictionary.")
    if not sig_b64 or not isinstance(sig_b64, str):
        raise RuntimeError("FAIL-CLOSED: Authorization token missing valid 'signature' string.")

    # Validate required payload fields
    required_fields = [
        "authorization_id", "authorized_run_id", "authorized_level", "parameters",
        "runner_sha256", "protocol_version", "operator_identity", "nonce",
        "issued_at_utc", "not_before_utc", "expires_at_utc"
    ]
    for rf in required_fields:
        if rf not in payload:
            raise RuntimeError(f"FAIL-CLOSED: Authorization payload missing required field '{rf}'")

    # 3. Parameter Bindings
    if payload["authorized_run_id"] != run_id:
        raise RuntimeError(f"FAIL-CLOSED: Authorization token bound to run_id '{payload['authorized_run_id']}', but coordinator requested '{run_id}'")

    if payload["authorized_level"] != level:
        raise RuntimeError(f"FAIL-CLOSED: Authorization token bound to level '{payload['authorized_level']}', but coordinator requested '{level}'")

    expected_limits = SEVERITY_LIMITS.get(level)
    if not expected_limits:
        raise RuntimeError(f"FAIL-CLOSED: Unknown severity level '{level}'")

    token_params = payload["parameters"]
    if not isinstance(token_params, dict):
        raise RuntimeError("FAIL-CLOSED: Authorization token parameters must be a dictionary.")

    if token_params.get("wbps") != expected_limits["wbps"]:
        raise RuntimeError(f"FAIL-CLOSED: Token wbps ({token_params.get('wbps')}) does not match level limits ({expected_limits['wbps']})")
    if token_params.get("wiops") != expected_limits["wiops"]:
        raise RuntimeError(f"FAIL-CLOSED: Token wiops ({token_params.get('wiops')}) does not match level limits ({expected_limits['wiops']})")

    max_dur = token_params.get("max_fault_duration_sec")
    if not isinstance(max_dur, (int, float)) or duration_sec > max_dur:
        raise RuntimeError(f"FAIL-CLOSED: Requested fault duration {duration_sec}s exceeds authorized maximum {max_dur}s")

    # 4. Protocol version binding
    if payload["protocol_version"] != expected_protocol:
        raise RuntimeError(f"FAIL-CLOSED: Authorization bound to protocol '{payload['protocol_version']}', expected '{expected_protocol}'")

    # 5. Runner SHA-256 binding
    target_runner = runner_path if runner_path else os.path.abspath(__file__)
    if not os.path.exists(target_runner):
        raise RuntimeError(f"FAIL-CLOSED: Runner source file not found at {target_runner}")
    current_runner_hash = compute_sha256(target_runner)
    if payload["runner_sha256"] != current_runner_hash:
        raise RuntimeError(f"FAIL-CLOSED: Runner hash mismatch! Token expects {payload['runner_sha256']}, actual runner hash is {current_runner_hash}")

    # 6. UTC Timestamp validity window
    now_utc = _utc_now()
    try:
        not_before = datetime.datetime.fromisoformat(payload["not_before_utc"].replace("Z", "+00:00"))
        expires_at = datetime.datetime.fromisoformat(payload["expires_at_utc"].replace("Z", "+00:00"))
    except Exception as e:
        raise RuntimeError(f"FAIL-CLOSED: Invalid ISO-8601 timestamp in authorization token: {e}")

    if now_utc < not_before:
        raise RuntimeError(f"FAIL-CLOSED: Authorization token is not yet valid (valid from {payload['not_before_utc']}, current {now_utc.isoformat()})")
    if now_utc > expires_at:
        raise RuntimeError(f"FAIL-CLOSED: Authorization token has EXPIRED (expired at {payload['expires_at_utc']}, current {now_utc.isoformat()})")

    # 7. Public Key Trust & Fingerprint Verification (F01 & F02)
    # G3-72: no in-memory key injection and no caller-supplied fingerprint exist in this API.
    # The key is always loaded from a file and must match the module-level pinned fingerprint.
    pk_path = public_key_path if public_key_path else DEFAULT_PUBLIC_KEY_PATH
    if os.path.islink(pk_path):
        raise RuntimeError(f"FAIL-CLOSED: Public key file cannot be a symlink: {pk_path}")
    if not os.path.isfile(pk_path):
        raise RuntimeError(f"FAIL-CLOSED: Trusted public key file not found: {pk_path}")
    with open(pk_path, "r", encoding="utf-8") as f:
        pk_str = f.read().strip()
    try:
        pub_bytes = base64.b64decode(pk_str, validate=True)
        if len(pub_bytes) != 32:
            raise ValueError("Ed25519 public key must be exactly 32 bytes")
        pub_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
    except Exception as e:
        raise RuntimeError(f"FAIL-CLOSED: Failed to load Ed25519 public key from {pk_path}: {e}")

    actual_fingerprint = hashlib.sha256(pub_bytes).hexdigest()
    trusted_fp = TRUSTED_OPERATOR_PUBKEY_SHA256
    if not trusted_fp or actual_fingerprint != trusted_fp:
        raise RuntimeError(
            f"FAIL-CLOSED: Untrusted public key! Key fingerprint {actual_fingerprint} "
            f"does not match authoritative pinned fingerprint {trusted_fp}"
        )

    canon_bytes = canonicalize_payload(payload)
    try:
        sig_bytes = base64.b64decode(sig_b64)
    except Exception as e:
        raise RuntimeError(f"FAIL-CLOSED: Invalid base64 signature in token: {e}")

    try:
        pub_key_obj.verify(sig_bytes, canon_bytes)
    except InvalidSignature:
        raise RuntimeError("FAIL-CLOSED: Ed25519 signature verification FAILED! Token signature is invalid.")
    except Exception as e:
        raise RuntimeError(f"FAIL-CLOSED: Error during signature verification: {e}")

    # 8. Post-verification content integrity re-check (F03 TOCTOU mitigation)
    # Ensure disk file content has not been mutated or swapped since read
    try:
        with open(abs_auth_path, "rb") as check_f:
            post_bytes = check_f.read()
        if hashlib.sha256(post_bytes).hexdigest() != token_sha256:
            raise RuntimeError("FAIL-CLOSED: TOCTOU violation: Token file modified during verification!")
    except Exception as e:
        raise RuntimeError(f"FAIL-CLOSED: Failed to re-verify token content integrity: {e}")

    # 9. Single-Use Atomic Exclusive Consumption Lock
    consumption_data = {
        "authorization_id": payload["authorization_id"],
        "token_sha256": token_sha256,
        "consumed_at_utc": now_utc.isoformat(),
        "run_id": run_id,
        "runner_sha256": current_runner_hash,
        "public_key_fingerprint": actual_fingerprint,
        "pid": os.getpid()
    }
    
    try:
        # Atomic creation using O_CREAT | os.O_EXCL
        fd = os.open(consumed_marker_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(consumption_data, f, indent=2)
    except FileExistsError:
        raise RuntimeError(f"FAIL-CLOSED: Authorization token '{payload['authorization_id']}' has ALREADY BEEN CONSUMED ({consumed_marker_path} exists). Single-use invariant enforced.")
    except Exception as e:
        raise RuntimeError(f"FAIL-CLOSED: Failed to persist atomic consumption record: {e}")

    log(f"[AUTH VERIFIED] Token {payload['authorization_id']} verified and atomically consumed.")

    return {
        "authorization_id": payload["authorization_id"],
        "token_sha256": token_sha256,
        "signature_verified": True,
        "public_key_fingerprint": actual_fingerprint,
        "operator_identity": payload["operator_identity"],
        "nonce": payload["nonce"],
        "authorized_run_id": payload["authorized_run_id"],
        "authorized_level": payload["authorized_level"],
        "parameters": payload["parameters"],
        "runner_sha256": payload["runner_sha256"],
        "protocol_version": payload["protocol_version"],
        "issued_at_utc": payload["issued_at_utc"],
        "not_before_utc": payload["not_before_utc"],
        "expires_at_utc": payload["expires_at_utc"],
        "consumed_at_utc": consumption_data["consumed_at_utc"],
        "consumed_marker_path": consumed_marker_path
    }

def build_manifest(output_dir: str) -> str:
    manifest_path = os.path.join(output_dir, "SHA256SUMS.txt")
    lines = []
    for root, _, files in os.walk(output_dir):
        for file in sorted(files):
            if file == "SHA256SUMS.txt":
                continue
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, output_dir).replace("\\", "/")
            digest = compute_sha256(full_path)
            lines.append(f"{digest}  {rel_path}\n")
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    log(f"Generated SHA-256 manifest at {manifest_path}")
    return manifest_path

def verify_manifest(output_dir: str) -> bool:
    """
    Verifies that every entry in SHA256SUMS.txt exists and matches its recorded hash.
    """
    manifest_path = os.path.join(output_dir, "SHA256SUMS.txt")
    if not os.path.exists(manifest_path):
        log(f"[MANIFEST ERROR] SHA256SUMS.txt missing in {output_dir}")
        return False
    with open(manifest_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                continue
            expected_hash, rel_path = parts
            target_file = os.path.join(output_dir, rel_path.replace("/", os.sep))
            if not os.path.exists(target_file):
                log(f"[MANIFEST ERROR] File {rel_path} in manifest does not exist!")
                return False
            actual_hash = compute_sha256(target_file)
            if actual_hash != expected_hash:
                log(f"[MANIFEST ERROR] Hash mismatch for {rel_path}: expected {expected_hash}, got {actual_hash}")
                return False
    log("[MANIFEST VERIFIED] SHA256SUMS.txt cryptographic verification passed.")
    return True

def check_storage_capacity(min_avail_mb: float = 30.0) -> Dict[str, Any]:
    cmd = ["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "df", "-k", "/tmp"]
    res = run_cmd(cmd, check=False, timeout=10.0)
    if res.returncode != 0:
        raise RuntimeError(f"Storage check failed with code {res.returncode}: {res.stderr}")
    
    lines = res.stdout.strip().split("\n")
    if len(lines) < 2:
        raise RuntimeError(f"Unexpected df output: {res.stdout}")
    parts = lines[1].split()
    total_kb = int(parts[1])
    used_kb = int(parts[2])
    avail_kb = int(parts[3])
    avail_mb = avail_kb / 1024.0
    
    log(f"[STORAGE MONITOR] /tmp capacity: Total={total_kb/1024.0:.1f}MB, Used={used_kb/1024.0:.1f}MB, Avail={avail_mb:.1f}MB")
    if avail_mb < min_avail_mb:
        raise RuntimeError(f"FAIL-CLOSED: Available /tmp storage ({avail_mb:.1f}MB) is below safety threshold ({min_avail_mb:.1f}MB)")
    
    return {
        "total_kb": total_kb,
        "used_kb": used_kb,
        "avail_kb": avail_kb,
        "avail_mb": avail_mb
    }

def construct_in_pod_wrapper(run_id: str, duration_sec: int) -> str:
    log_prefix = f"/tmp/pgbench_log_{run_id}"
    awk_filter = (
        "mawk -W interactive '"
        "BEGIN { count = 0; } "
        "/^NOTICE:  No license is installed/ { "
        "  count++; "
        f"  if (count <= 10) {{ print $0 > \"/tmp/pgbench_{run_id}_notice_samples.txt\"; }} "
        "  next; "
        "} "
        "{ "
        f"  print $0 > \"/tmp/pgbench_{run_id}_stderr.txt\"; "
        "} "
        "END { "
        f"  print count > \"/tmp/pgbench_{run_id}_notice_count.txt\"; "
        "}'"
    )
    script = (
        f": > /tmp/pgbench_{run_id}_stderr.txt; "
        f"df -k /tmp > /tmp/disk_pre_{run_id}.txt; "
        f"setsid pgbench -h cockroachdb-public -p 26257 -U root -n -c 20 -j 4 -T {duration_sec} --max-tries=1 -M simple "
        f"-l --log-prefix={log_prefix} benchdb > /tmp/pgbench_{run_id}_stdout.txt 2> >({awk_filter}) & "
        f"BENCH_PGID=$!; "
        f'echo "${{BENCH_PGID}}" > /tmp/pgbench_{run_id}_pgid.txt; '
        f"wait ${{BENCH_PGID}}; "
        f"EXIT_CODE=$?; "
        f'echo "${{EXIT_CODE}}" > /tmp/pgbench_{run_id}_exit_code.tmp && mv /tmp/pgbench_{run_id}_exit_code.tmp /tmp/pgbench_{run_id}_exit_code.txt; '
        f"wait 2>/dev/null || true; "
        f"sleep 1; "
        f"df -k /tmp > /tmp/disk_post_{run_id}.txt"
    )
    return script

def query_live_processes_in_pgid(pgid: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    cmd = ["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "ps", "-eo", "pid,pgid,stat,comm"]
    res = run_cmd(cmd, check=False, timeout=10.0)
    if res.returncode != 0:
        raise RuntimeError(f"ps command failed with code {res.returncode}: {res.stderr}")
    
    lines = res.stdout.strip().split("\n")
    if not lines or not lines[0]:
        raise RuntimeError("Empty output from ps command")
    
    header = lines[0].split()
    if len(header) < 4 or header[0] != "PID" or header[1] != "PGID":
        raise RuntimeError(f"Unexpected ps header format: {lines[0]}")
    
    live_procs = []
    zombie_procs = []
    
    for line in lines[1:]:
        line_clean = line.strip()
        if not line_clean:
            continue
        parts = line_clean.split(None, 3)
        if len(parts) < 4:
            raise RuntimeError(f"Malformed ps output row (fewer than 4 fields): '{line_clean}'")
        try:
            p_pid = int(parts[0])
            p_pgid = int(parts[1])
        except ValueError as e:
            raise RuntimeError(f"Failed to parse PID/PGID as integer from row '{line_clean}': {e}")
        
        stat = parts[2]
        comm = parts[3]
        
        if p_pgid == pgid:
            entry = {"pid": p_pid, "pgid": p_pgid, "stat": stat, "comm": comm}
            if stat.startswith("Z"):
                zombie_procs.append(entry)
            else:
                live_procs.append(entry)
                
    return live_procs, zombie_procs

def terminate_remote_process_group(pgid: int, timeout_grace_sec: float = 5.0) -> Dict[str, Any]:
    if pgid <= 0:
        raise ValueError(f"Invalid PGID {pgid}; must be positive integer.")
    
    log(f"[PROCESS LIFECYCLE] Initiating termination of remote process group -{pgid}...")
    run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "/usr/bin/kill", "-TERM", f"-{pgid}"], check=False, timeout=10.0)
    
    start_t = time.time()
    live_procs = []
    zombies = []
    
    while time.time() - start_t < timeout_grace_sec:
        time.sleep(0.5)
        try:
            live_procs, zombies = query_live_processes_in_pgid(pgid)
            if not live_procs:
                log(f"[PROCESS LIFECYCLE] Process group -{pgid} terminated gracefully via SIGTERM (Live: 0, Zombies: {len(zombies)}).")
                return {
                    "verified_dead": True,
                    "escalated_to_sigkill": False,
                    "surviving_live_count": 0,
                    "zombie_count": len(zombies),
                    "hard_failure": False
                }
        except Exception as e:
            log(f"[PROCESS LIFECYCLE] Warning: failed to query live processes during grace wait: {e}")
            break
            
    log(f"[PROCESS LIFECYCLE] Process group -{pgid} has {len(live_procs)} live processes remaining after {timeout_grace_sec}s grace. Escalating to SIGKILL...")
    run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "/usr/bin/kill", "-KILL", f"-{pgid}"], check=False, timeout=10.0)
    time.sleep(1.0)
    
    try:
        live_post, zombies_post = query_live_processes_in_pgid(pgid)
        if not live_post:
            log(f"[PROCESS LIFECYCLE] Process group -{pgid} confirmed DEAD following SIGKILL (Live: 0, Zombies: {len(zombies_post)}).")
            return {
                "verified_dead": True,
                "escalated_to_sigkill": True,
                "surviving_live_count": 0,
                "zombie_count": len(zombies_post),
                "hard_failure": False
            }
        else:
            log(f"[CRITICAL ERROR] HARD_FAILURE: Process group -{pgid} has {len(live_post)} live processes surviving SIGKILL: {live_post}")
            return {
                "verified_dead": False,
                "escalated_to_sigkill": True,
                "surviving_live_count": len(live_post),
                "zombie_count": len(zombies_post),
                "hard_failure": True,
                "surviving_processes": live_post
            }
    except Exception as e:
        log(f"[CRITICAL ERROR] POST_KILL_VERIFICATION_FAILED: Could not query process table: {e}")
        return {
            "verified_dead": False,
            "escalated_to_sigkill": True,
            "surviving_live_count": -1,
            "zombie_count": -1,
            "hard_failure": True,
            "error": str(e)
        }

def sample_cgroup_iostat(target_pod: str) -> Dict[str, Any]:
    cmd = ["kubectl", "exec", "-n", NAMESPACE, target_pod, "--", "cat", "/sys/fs/cgroup/io.stat"]
    res = run_cmd(cmd, check=False, timeout=5.0)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    raw = res.stdout.strip() if res.returncode == 0 else ""
    err = None if res.returncode == 0 else (res.stderr.strip() or f"exit {res.returncode}")
    return {
        "timestamp": now,
        "raw": raw,
        "pod": target_pod,
        "returncode": res.returncode,
        "success": res.returncode == 0,
        "error": err,
    }

def sample_crdb_metrics(target_pod: str, timeout: float = 15.0, max_retries: int = 3) -> Dict[str, Any]:
    """
    Query CockroachDB /status/vars endpoint with bounded retry and timeout policy.
    Does not interpolate or fabricate missing metrics. Records attempt count and elapsed time.
    """
    cmd = ["kubectl", "exec", "-n", NAMESPACE, target_pod, "--", "curl", "-s", "-k", "https://localhost:8080/_status/vars"]
    attempts = 0
    start_t = time.time()
    last_err = None
    
    for attempt in range(1, max_retries + 1):
        attempts = attempt
        try:
            res = run_cmd(cmd, check=False, timeout=timeout)
            if res.returncode == 0 and res.stdout:
                metrics = {}
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if any(k in line for k in ["storage_disk_", "ranges_underreplicated", "rebalancing_writespersecond"]):
                        parts = line.split()
                        if len(parts) >= 2:
                            metrics[parts[0]] = parts[1]
                return {
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "metrics": metrics,
                    "pod": target_pod,
                    "attempts": attempts,
                    "elapsed_sec": time.time() - start_t,
                    "success": True,
                    "error": None
                }
            else:
                last_err = f"curl exit {res.returncode}: {res.stderr.strip() if res.stderr else 'empty output'}"
        except Exception as e:
            last_err = str(e)
            
        if attempt < max_retries:
            time.sleep(1.0)
            
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    log(f"[METRICS WARNING] Failed to sample CRDB metrics from {target_pod} after {attempts} attempts ({time.time() - start_t:.2f}s): {last_err}")
    return {
        "timestamp": now,
        "metrics": {},
        "pod": target_pod,
        "attempts": attempts,
        "elapsed_sec": time.time() - start_t,
        "success": False,
        "error": last_err
    }

def incremental_telemetry_poller(target_pod: str, stop_event: threading.Event, telemetry_file_path: str, interval: float = 5.0):
    log(f"Incremental telemetry poller started -> {telemetry_file_path}")
    with open(telemetry_file_path, "a", encoding="utf-8") as f:
        while not stop_event.is_set():
            t_poll_start = time.time()
            try:
                iostat = sample_cgroup_iostat(target_pod)
                crdb = sample_crdb_metrics(target_pod)
                record = {
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "iostat": iostat,
                    "crdb_metrics": crdb
                }
                f.write(json.dumps(record) + "\n")
                f.flush()
                os.fsync(f.fileno())
            except Exception as e:
                log(f"[TELEMETRY WARNING] Failed to collect telemetry sample: {e}")
            
            elapsed = time.time() - t_poll_start
            sleep_time = max(0.0, interval - elapsed)
            time.sleep(sleep_time)
    log("Incremental telemetry poller stopped.")

def run_preflight_audit(dry_run: bool = False) -> Dict[str, Any]:
    log("Executing G3 preflight audit...")
    audit: Dict[str, Any] = {}

    # 1. AWS caller identity & Kubernetes cluster context
    aws_res = run_cmd(["aws", "sts", "get-caller-identity", "--output", "json"], check=False, timeout=15.0)
    if aws_res.returncode != 0:
        raise RuntimeError(f"Preflight FAILED: AWS identity verification failed: {aws_res.stderr.strip()}")
    try:
        aws_data = json.loads(aws_res.stdout)
    except Exception as e:
        raise RuntimeError(f"Preflight FAILED: Malformed AWS identity JSON: {e}")
    if not aws_data.get("Account"):
        raise RuntimeError("Preflight FAILED: AWS account ID missing from sts get-caller-identity")
    audit["aws_account"] = aws_data["Account"]
    audit["aws_arn"] = aws_data.get("Arn", "")

    ctx_res = run_cmd(["kubectl", "config", "current-context"], check=False, timeout=10.0)
    if ctx_res.returncode != 0 or not ctx_res.stdout.strip():
        raise RuntimeError(f"Preflight FAILED: Unable to resolve Kubernetes current-context: {ctx_res.stderr.strip()}")
    audit["kube_context"] = ctx_res.stdout.strip()

    # 2. Check EKS worker nodes
    nodes_res = run_cmd(["kubectl", "get", "nodes", "-o", "json"], check=False, timeout=15.0)
    if nodes_res.returncode != 0:
        raise RuntimeError(f"Preflight FAILED: Unable to query nodes: {nodes_res.stderr.strip()}")
    nodes_data = json.loads(nodes_res.stdout)
    ready_nodes = [
        n["metadata"]["name"] for n in nodes_data.get("items", [])
        if any(c.get("type") == "Ready" and c.get("status") == "True" for c in n.get("status", {}).get("conditions", []))
    ]
    if len(ready_nodes) < 3:
        raise RuntimeError(f"Preflight FAILED: Fewer than 3 ready nodes found ({len(ready_nodes)})")
    audit["ready_nodes"] = ready_nodes

    # 3. Check CockroachDB broker pods (exclude completed init Job pods; require Running, Ready, 0 restarts)
    pods_res = run_cmd(["kubectl", "get", "pods", "-n", NAMESPACE, "-l", "app.kubernetes.io/name=cockroachdb,app.kubernetes.io/component=cockroachdb", "-o", "json"], check=False, timeout=15.0)
    if pods_res.returncode != 0:
        raise RuntimeError(f"Preflight FAILED: Unable to query CockroachDB pods: {pods_res.stderr.strip()}")
    pods_data = json.loads(pods_res.stdout)
    crdb_pods = []
    crdb_restarts = {}
    for p in pods_data.get("items", []):
        pname = p["metadata"]["name"]
        phase = p.get("status", {}).get("phase")
        cstatuses = p.get("status", {}).get("containerStatuses", [])
        if phase != "Running" or not cstatuses or not all(cs.get("ready") is True for cs in cstatuses):
            raise RuntimeError(f"Preflight FAILED: CockroachDB pod {pname} is not Running/Ready (phase={phase})")
        restarts = sum(int(cs.get("restartCount", 0)) for cs in cstatuses)
        crdb_restarts[pname] = restarts
        if restarts > 0:
            raise RuntimeError(f"Preflight FAILED: CockroachDB pod {pname} has non-zero restartCount={restarts}")
        crdb_pods.append(pname)
    if len(crdb_pods) < 3:
        raise RuntimeError(f"Preflight FAILED: Fewer than 3 running CockroachDB pods found ({len(crdb_pods)})")
    audit["crdb_pods"] = crdb_pods
    audit["crdb_restarts"] = crdb_restarts

    # 4. Check PVCs in cockroachdb namespace
    pvc_res = run_cmd(["kubectl", "get", "pvc", "-n", NAMESPACE, "-o", "json"], check=False, timeout=15.0)
    if pvc_res.returncode != 0:
        raise RuntimeError(f"Preflight FAILED: Unable to query PVCs: {pvc_res.stderr.strip()}")
    pvc_data = json.loads(pvc_res.stdout)
    pvcs = pvc_data.get("items", [])
    bound_pvcs = [v["metadata"]["name"] for v in pvcs if v.get("status", {}).get("phase") == "Bound"]
    if len(pvcs) < 3 or len(bound_pvcs) != len(pvcs):
        raise RuntimeError(f"Preflight FAILED: Expected all PVCs Bound (>=3), found {len(bound_pvcs)}/{len(pvcs)} Bound")
    audit["bound_pvcs"] = bound_pvcs

    # 5. Check benchmark client pod
    client_res = run_cmd(["kubectl", "get", "pod", CLIENT_POD, "-n", NAMESPACE, "-o", "json"], check=False, timeout=15.0)
    if client_res.returncode != 0:
        raise RuntimeError(f"Preflight FAILED: Unable to inspect benchmark client pod {CLIENT_POD}: {client_res.stderr.strip()}")
    client_data = json.loads(client_res.stdout)
    client_cstatuses = client_data.get("status", {}).get("containerStatuses", [])
    if client_data.get("status", {}).get("phase") != "Running" or (client_cstatuses and not all(cs.get("ready") is True for cs in client_cstatuses)):
        raise RuntimeError(f"Preflight FAILED: Benchmark client {CLIENT_POD} is not Running/Ready")
    audit["client_status"] = "Running"

    # 6. Check mutual TLS SQL connectivity & dataset row count
    row_count_str = query_sql("SELECT count(*) FROM benchdb.public.pgbench_accounts;")
    if row_count_str != "5000000":
        raise RuntimeError(f"Preflight FAILED: Expected 5,000,000 accounts, found {row_count_str}")
    audit["dataset_rows"] = 5000000
    audit["tls_verified"] = True

    # 7. Record pgbench_history count (read-only; never cleared)
    hist_raw = query_sql("SELECT count(*) FROM benchdb.public.pgbench_history;")
    try:
        hist_count = int(hist_raw.splitlines()[-1].strip())
    except Exception as e:
        raise RuntimeError(f"Preflight FAILED: Unable to parse pgbench_history count ({hist_raw!r}): {e}")
    if hist_count < 0:
        raise RuntimeError(f"Preflight FAILED: Invalid pgbench_history count {hist_count}")
    audit["s0_preflight_history"] = hist_count

    # 8. Check under-replicated ranges == 0
    underrep_raw = query_sql(
        "SET allow_unsafe_internals = true; "
        "SELECT count(*) FROM crdb_internal.ranges WHERE array_length(replicas, 1) < 3;"
    )
    underrep_lines = [ln.strip() for ln in underrep_raw.splitlines() if ln.strip() and ln.strip() != "SET"]
    if not underrep_lines or underrep_lines[-1] != "0":
        raise RuntimeError(f"Preflight FAILED: Under-replicated ranges non-zero or unreadable: {underrep_raw!r}")
    audit["underreplicated_ranges"] = 0

    # 9. Check chaos namespace is clean (both pods and jobs)
    chaos_pods_res = run_cmd(["kubectl", "get", "pods", "-n", CHAOS_NAMESPACE, "-o", "json"], check=False, timeout=15.0)
    if chaos_pods_res.returncode != 0:
        raise RuntimeError(f"Preflight FAILED: Unable to query pods in {CHAOS_NAMESPACE}: {chaos_pods_res.stderr.strip()}")
    chaos_pods = json.loads(chaos_pods_res.stdout).get("items", [])
    if len(chaos_pods) > 0:
        raise RuntimeError(f"Preflight FAILED: Chaos namespace {CHAOS_NAMESPACE} contains active pods")

    chaos_jobs_res = run_cmd(["kubectl", "get", "jobs", "-n", CHAOS_NAMESPACE, "-o", "json"], check=False, timeout=15.0)
    if chaos_jobs_res.returncode != 0:
        raise RuntimeError(f"Preflight FAILED: Unable to query jobs in {CHAOS_NAMESPACE}: {chaos_jobs_res.stderr.strip()}")
    chaos_jobs = json.loads(chaos_jobs_res.stdout).get("items", [])
    if len(chaos_jobs) > 0:
        raise RuntimeError(f"Preflight FAILED: Chaos namespace {CHAOS_NAMESPACE} contains active jobs")
    audit["chaos_namespace_clean"] = True

    # 10. Check benchmark client temporary storage (>= 30 MiB)
    storage_info = check_storage_capacity(min_avail_mb=30.0)
    audit["client_tmp_avail_mb"] = storage_info["avail_mb"]

    log("Preflight audit PASSED successfully.")
    return audit

def _resolve_pod_from_gossip(lease_holder: int) -> str:
    """Resolve lease_holder node_id to an active CockroachDB pod via crdb_internal.gossip_nodes."""
    gossip_raw = query_sql(
        "SET allow_unsafe_internals = true; "
        "SELECT node_id, address, is_live FROM crdb_internal.gossip_nodes;"
    )
    matches = []
    for raw_line in gossip_raw.splitlines():
        line = raw_line.strip()
        if not line or line == "SET":
            continue
        cols = line.split("|")
        if len(cols) < 3:
            raise RuntimeError(f"FAIL-CLOSED: Malformed gossip_nodes row: {line!r}")
        nid_str, addr_str, live_str = cols[0].strip(), cols[1].strip(), cols[2].strip()
        if not nid_str.isdigit():
            raise RuntimeError(f"FAIL-CLOSED: Non-integer node_id in gossip_nodes: {line!r}")
        if int(nid_str) == lease_holder:
            if live_str.lower() not in ("t", "true"):
                raise RuntimeError(f"FAIL-CLOSED: Target leaseholder node {lease_holder} is not live in gossip_nodes (is_live={live_str!r})")
            host_part = addr_str.split(":", 1)[0].split(".", 1)[0].strip()
            if not host_part:
                raise RuntimeError(f"FAIL-CLOSED: Could not extract pod name from gossip address {addr_str!r}")
            matches.append(host_part)
    if len(matches) != 1:
        raise RuntimeError(f"FAIL-CLOSED: Expected exactly 1 gossip_nodes entry for leaseholder {lease_holder}, found {matches!r}")
    return matches[0]

def resolve_target_leaseholder(target_override: Optional[str] = None) -> Dict[str, Any]:
    log("Resolving target CockroachDB leaseholder via two-cycle consensus check...")
    if target_override:
        log(f"MANUAL OVERRIDE: Using specified target pod {target_override}")
        target_pod = target_override
        range_id = -1
        lease_holder = -1
        raw_range = "MANUAL_OVERRIDE"
    else:
        raw_range_1 = query_sql("SHOW RANGE FROM TABLE benchdb.public.pgbench_accounts FOR ROW (1);")
        parts_1 = raw_range_1.split("|")
        if len(parts_1) < 4:
            raise RuntimeError(f"FAIL-CLOSED: Unexpected SHOW RANGE output in Cycle 1: {raw_range_1!r}")
        range_id_1 = int(parts_1[2])
        lease_holder_1 = int(parts_1[3])

        time.sleep(1.0)

        raw_range_2 = query_sql("SHOW RANGE FROM TABLE benchdb.public.pgbench_accounts FOR ROW (1);")
        parts_2 = raw_range_2.split("|")
        if len(parts_2) < 4:
            raise RuntimeError(f"FAIL-CLOSED: Unexpected SHOW RANGE output in Cycle 2: {raw_range_2!r}")
        range_id_2 = int(parts_2[2])
        lease_holder_2 = int(parts_2[3])

        if range_id_1 != range_id_2 or lease_holder_1 != lease_holder_2:
            raise RuntimeError(
                f"FAIL-CLOSED: Dynamic leaseholder resolution consensus failure! "
                f"Cycle 1: Range={range_id_1}, Leaseholder={lease_holder_1}; "
                f"Cycle 2: Range={range_id_2}, Leaseholder={lease_holder_2}"
            )

        range_id = range_id_1
        lease_holder = lease_holder_1
        raw_range = raw_range_1
        target_pod = _resolve_pod_from_gossip(lease_holder)

    pod_res = run_cmd(["kubectl", "get", "pod", target_pod, "-n", NAMESPACE, "-o", "json"], check=False, timeout=15.0)
    if pod_res.returncode != 0:
        raise RuntimeError(f"FAIL-CLOSED: Unable to query target pod {target_pod}: {pod_res.stderr.strip()}")
    pod_json = json.loads(pod_res.stdout)
    node_name = pod_json.get("spec", {}).get("nodeName", "")
    raw_pod_uid = pod_json.get("metadata", {}).get("uid", "")
    pod_uid = raw_pod_uid.strip() if isinstance(raw_pod_uid, str) else ""
    if not node_name:
        raise RuntimeError(f"FAIL-CLOSED: Target pod {target_pod} has no scheduled nodeName")
    if not pod_uid or any(ch.isspace() for ch in pod_uid):
        raise RuntimeError(f"FAIL-CLOSED: Target pod {target_pod} has missing or empty pod UID: {raw_pod_uid!r}")

    cstatuses = pod_json.get("status", {}).get("containerStatuses", [])
    db_cs = next((cs for cs in cstatuses if cs.get("name") == "db"), cstatuses[0] if len(cstatuses) == 1 else None)
    if not db_cs or not db_cs.get("containerID"):
        raise RuntimeError(f"FAIL-CLOSED: Unable to resolve database containerID for pod {target_pod}")
    cid = db_cs["containerID"].replace("containerd://", "").strip()
    if not cid or any(ch not in "0123456789abcdefABCDEF" for ch in cid):
        raise RuntimeError(f"FAIL-CLOSED: Invalid container ID resolved for {target_pod}: {cid!r}")

    stat_res = run_cmd(
        ["kubectl", "exec", "-n", NAMESPACE, target_pod, "--", "stat", "-c", "%d", "/cockroach/cockroach-data"],
        check=False,
        timeout=10.0,
    )
    if stat_res.returncode != 0 or not stat_res.stdout.strip().isdigit():
        raise RuntimeError(f"FAIL-CLOSED: Failed to read /cockroach/cockroach-data st_dev on {target_pod}: {stat_res.stderr.strip()}")
    dev_stat_dec = int(stat_res.stdout.strip())
    dev_major, dev_minor = decode_linux_st_dev(dev_stat_dec)
    if (
        not isinstance(dev_major, int)
        or isinstance(dev_major, bool)
        or not isinstance(dev_minor, int)
        or isinstance(dev_minor, bool)
        or dev_major <= 0
        or dev_minor < 0
    ):
        raise RuntimeError(
            f"FAIL-CLOSED: Invalid or non-positive device major:minor {dev_major}:{dev_minor} "
            f"decoded from st_dev {dev_stat_dec} on {target_pod}"
        )

    mnt_res = run_cmd(
        ["kubectl", "exec", "-n", NAMESPACE, target_pod, "--", "cat", "/proc/self/mountinfo"],
        check=False,
        timeout=10.0,
    )
    if mnt_res.returncode != 0 or not mnt_res.stdout.strip():
        raise RuntimeError(
            f"FAIL-CLOSED: Failed to read /proc/self/mountinfo on {target_pod}: {mnt_res.stderr.strip()}"
        )
    data_mounts = []
    for raw_mnt_line in mnt_res.stdout.splitlines():
        mnt_parts = raw_mnt_line.split()
        if len(mnt_parts) >= 5 and (mnt_parts[4].rstrip("/") or "/") == "/cockroach/cockroach-data":
            data_mounts.append(mnt_parts)
    if len(data_mounts) == 0:
        raise RuntimeError(
            f"FAIL-CLOSED: Missing /cockroach/cockroach-data mount entry in /proc/self/mountinfo on {target_pod}"
        )
    if len(data_mounts) > 1:
        raise RuntimeError(
            f"FAIL-CLOSED: Ambiguous or duplicate /cockroach/cockroach-data mount entries ({len(data_mounts)}) "
            f"in /proc/self/mountinfo on {target_pod}"
        )
    mnt_dev_tok = data_mounts[0][2]
    mnt_dev_parts = mnt_dev_tok.split(":")
    if len(mnt_dev_parts) != 2 or not mnt_dev_parts[0].isdigit() or not mnt_dev_parts[1].isdigit():
        raise RuntimeError(
            f"FAIL-CLOSED: Malformed major:minor {mnt_dev_tok!r} for /cockroach/cockroach-data "
            f"in /proc/self/mountinfo on {target_pod}"
        )
    mnt_major, mnt_minor = int(mnt_dev_parts[0]), int(mnt_dev_parts[1])
    if mnt_major <= 0 or mnt_minor < 0 or (mnt_major, mnt_minor) != (dev_major, dev_minor):
        raise RuntimeError(
            f"FAIL-CLOSED: Mount device mismatch for /cockroach/cockroach-data on {target_pod}: "
            f"stat resolved {dev_major}:{dev_minor}, mountinfo reported {mnt_major}:{mnt_minor}"
        )

    uevent_path = f"/sys/dev/block/{dev_major}:{dev_minor}/uevent"
    uevent_res = run_cmd(
        ["kubectl", "exec", "-n", NAMESPACE, target_pod, "--", "cat", uevent_path],
        check=False,
        timeout=10.0,
    )
    if uevent_res.returncode != 0 or not uevent_res.stdout.strip():
        raise RuntimeError(
            f"FAIL-CLOSED: Missing or unreadable {uevent_path} on {target_pod}: {uevent_res.stderr.strip()}"
        )
    uevent_kv: Dict[str, str] = {}
    for raw_uev_line in uevent_res.stdout.splitlines():
        uev_line = raw_uev_line.strip()
        if not uev_line:
            continue
        if "=" not in uev_line:
            raise RuntimeError(
                f"FAIL-CLOSED: Malformed line {raw_uev_line!r} in {uevent_path} on {target_pod}"
            )
        uk, uv = uev_line.split("=", 1)
        uk, uv = uk.strip(), uv.strip()
        if not uk or not uv or uk in uevent_kv:
            raise RuntimeError(
                f"FAIL-CLOSED: Invalid or duplicate key {uk!r} in {uevent_path} on {target_pod}"
            )
        uevent_kv[uk] = uv
    if uevent_kv.get("DEVTYPE") != "disk":
        raise RuntimeError(
            f"FAIL-CLOSED: Target device {dev_major}:{dev_minor} on {target_pod} is not a whole disk "
            f"(DEVTYPE={uevent_kv.get('DEVTYPE')!r})"
        )
    uev_maj_str = uevent_kv.get("MAJOR", "")
    uev_min_str = uevent_kv.get("MINOR", "")
    if not uev_maj_str.isdigit() or not uev_min_str.isdigit():
        raise RuntimeError(
            f"FAIL-CLOSED: Malformed MAJOR/MINOR in {uevent_path} on {target_pod} "
            f"(MAJOR={uev_maj_str!r}, MINOR={uev_min_str!r})"
        )
    if int(uev_maj_str) != dev_major or int(uev_min_str) != dev_minor:
        raise RuntimeError(
            f"FAIL-CLOSED: uevent MAJOR:MINOR mismatch for {dev_major}:{dev_minor} on {target_pod} "
            f"(MAJOR={uev_maj_str}, MINOR={uev_min_str})"
        )

    ctrl_res = run_cmd(
        ["kubectl", "exec", "-n", NAMESPACE, target_pod, "--", "cat", "/sys/fs/cgroup/cgroup.controllers"],
        check=False,
        timeout=10.0,
    )
    if ctrl_res.returncode != 0:
        raise RuntimeError(f"FAIL-CLOSED: Failed to read cgroup.controllers on {target_pod}: {ctrl_res.stderr.strip()}")
    controllers = ctrl_res.stdout.strip().split()
    if "io" not in controllers:
        raise RuntimeError(f"FAIL-CLOSED: cgroup v2 'io' controller not enabled on {target_pod}: {controllers!r}")

    iostat_res = run_cmd(
        ["kubectl", "exec", "-n", NAMESPACE, target_pod, "--", "cat", "/sys/fs/cgroup/io.stat"],
        check=False,
        timeout=10.0,
    )
    if iostat_res.returncode != 0:
        raise RuntimeError(f"FAIL-CLOSED: cgroup io.stat unreadable on {target_pod}: {iostat_res.stderr.strip()}")

    io_res = run_cmd(
        ["kubectl", "exec", "-n", NAMESPACE, target_pod, "--", "cat", "/sys/fs/cgroup/io.max"],
        check=False,
        timeout=10.0,
    )
    if io_res.returncode != 0:
        raise RuntimeError(f"FAIL-CLOSED: cgroup io.max unreadable on {target_pod}: {io_res.stderr.strip()}")
    io_max_curr = io_res.stdout.strip()
    initial_dev_line = extract_device_io_max_line(io_max_curr, dev_major, dev_minor)

    target_info = {
        "range_id": range_id,
        "lease_holder_id": lease_holder,
        "target_pod": target_pod,
        "pod_uid": pod_uid,
        "target_node": node_name,
        "container_id": cid,
        "dev_major": dev_major,
        "dev_minor": dev_minor,
        "dev_stat_dec": dev_stat_dec,
        "raw_show_range": raw_range,
        "cgroup_controllers": controllers,
        "io_stat_readable": True,
        "initial_io_max": io_max_curr,
        "initial_device_io_max": initial_dev_line,
    }
    log(f"Target resolved: {target_pod} on {node_name}, Device: {dev_major}:{dev_minor}, CID: {cid[:12]}, Initial io.max: '{io_max_curr}'")
    return target_info

def validate_target_unchanged(expected: Dict[str, Any], current: Dict[str, Any], phase_label: str) -> None:
    """Abort fail-closed if leaseholder, pod, pod UID, node, container ID, device, or baseline io.max changed."""
    if current.get("target_pod") != expected.get("target_pod"):
        if phase_label == "warmup":
            raise RuntimeError(
                f"Leaseholder migrated during warmup! Was {expected.get('target_pod')}, now {current.get('target_pod')}"
            )
        raise RuntimeError(
            f"Target pod changed during {phase_label}! Was {expected.get('target_pod')}, now {current.get('target_pod')}"
        )
    exp_uid_raw = expected.get("pod_uid")
    cur_uid_raw = current.get("pod_uid")
    exp_uid = exp_uid_raw.strip() if isinstance(exp_uid_raw, str) else ""
    cur_uid = cur_uid_raw.strip() if isinstance(cur_uid_raw, str) else ""
    if not exp_uid or not cur_uid or any(ch.isspace() for ch in exp_uid) or any(ch.isspace() for ch in cur_uid):
        raise RuntimeError(
            f"FAIL-CLOSED: Missing or empty pod_uid during {phase_label} target revalidation "
            f"(expected={exp_uid_raw!r}, current={cur_uid_raw!r})"
        )
    for field in ("range_id", "lease_holder_id", "pod_uid", "target_node", "container_id", "dev_major", "dev_minor", "initial_io_max"):
        if current.get(field) != expected.get(field):
            raise RuntimeError(
                f"Target identity field '{field}' changed during {phase_label}! "
                f"Was {expected.get(field)!r}, now {current.get(field)!r}"
            )

def _build_posix_io_max_helpers() -> str:
    """Shared pure-POSIX (Dash-compatible) cgroup v2 validation and io.max parsing functions."""
    return """is_uint() {
  case "$1" in
    ""|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

is_hex() {
  case "$1" in
    ""|*[!0-9a-fA-F]*) return 1 ;;
    *) return 0 ;;
  esac
}

is_limit_val() {
  case "$1" in
    "max") return 0 ;;
    *) is_uint "$1" ;;
  esac
}

parse_device_line() {
  _pdl_line="$1"
  _pdl_dev="$2"
  P_RBPS=""
  P_WBPS=""
  P_RIOPS=""
  P_WIOPS=""
  set -f
  # shellcheck disable=SC2086
  set -- ${_pdl_line}
  set +f
  _pdl_first=1
  for _pdl_tok in "$@"; do
    if [ "${_pdl_first}" = "1" ]; then
      if [ "${_pdl_tok}" != "${_pdl_dev}" ]; then
        return 1
      fi
      _pdl_first=0
      continue
    fi
    case "${_pdl_tok}" in
      rbps=*)
        _pdl_val="${_pdl_tok#rbps=}"
        is_limit_val "${_pdl_val}" || return 1
        [ -z "${P_RBPS}" ] || return 1
        P_RBPS="${_pdl_val}"
        ;;
      wbps=*)
        _pdl_val="${_pdl_tok#wbps=}"
        is_limit_val "${_pdl_val}" || return 1
        [ -z "${P_WBPS}" ] || return 1
        P_WBPS="${_pdl_val}"
        ;;
      riops=*)
        _pdl_val="${_pdl_tok#riops=}"
        is_limit_val "${_pdl_val}" || return 1
        [ -z "${P_RIOPS}" ] || return 1
        P_RIOPS="${_pdl_val}"
        ;;
      wiops=*)
        _pdl_val="${_pdl_tok#wiops=}"
        is_limit_val "${_pdl_val}" || return 1
        [ -z "${P_WIOPS}" ] || return 1
        P_WIOPS="${_pdl_val}"
        ;;
      *)
        return 1
        ;;
    esac
  done
  if [ "${_pdl_first}" = "1" ] || [ -z "${P_RBPS}" ] || [ -z "${P_WBPS}" ] || [ -z "${P_RIOPS}" ] || [ -z "${P_WIOPS}" ]; then
    return 1
  fi
  return 0
}

read_and_validate_io_max() {
  _rvm_file="$1"
  _rvm_dev="$2"
  FOUND_DEV_LINE=""
  FOUND_DEV_COUNT=0
  if [ ! -r "${_rvm_file}" ]; then
    return 1
  fi
  while IFS= read -r _rvm_raw || [ -n "${_rvm_raw}" ]; do
    set -f
    # shellcheck disable=SC2086
    set -- ${_rvm_raw}
    set +f
    if [ "$#" -eq 0 ]; then
      continue
    fi
    _rvm_line_dev="$1"
    _rvm_maj="${_rvm_line_dev%%:*}"
    _rvm_min="${_rvm_line_dev#*:}"
    if [ "${_rvm_line_dev}" = "${_rvm_maj}" ] || ! is_uint "${_rvm_maj}" || ! is_uint "${_rvm_min}"; then
      return 3
    fi
    if ! parse_device_line "$*" "${_rvm_line_dev}"; then
      return 3
    fi
    if [ "${_rvm_line_dev}" = "${_rvm_dev}" ]; then
      FOUND_DEV_COUNT=$((FOUND_DEV_COUNT + 1))
      FOUND_DEV_LINE="$*"
    fi
  done < "${_rvm_file}"
  if [ "${FOUND_DEV_COUNT}" -gt 1 ]; then
    return 2
  fi
  return 0
}

verify_io_max_values() {
  _viv_exp_rbps="$1"
  _viv_exp_wbps="$2"
  _viv_exp_riops="$3"
  _viv_exp_wiops="$4"
  _viv_allow_absent="$5"
  if ! read_and_validate_io_max "${CGROUP_PATH}/io.max" "${DEV_ID}"; then
    return 1
  fi
  if [ "${FOUND_DEV_COUNT}" -eq 0 ]; then
    if [ "${_viv_allow_absent}" = "1" ]; then
      return 0
    fi
    return 1
  fi
  if ! parse_device_line "${FOUND_DEV_LINE}" "${DEV_ID}"; then
    return 1
  fi
  if [ "${P_RBPS}" != "${_viv_exp_rbps}" ] || [ "${P_WBPS}" != "${_viv_exp_wbps}" ] || [ "${P_RIOPS}" != "${_viv_exp_riops}" ] || [ "${P_WIOPS}" != "${_viv_exp_wiops}" ]; then
    return 1
  fi
  return 0
}

resolve_unique_cgroup_path() {
  _rcp_root="$1"
  _rcp_cid="$2"
  if [ ! -d "${_rcp_root}" ]; then
    return 1
  fi
  FOUND_DIRS=$(find "${_rcp_root}" -name "*${_rcp_cid}*" -type d 2>/dev/null || true)
  MATCH_COUNT=0
  CGROUP_PATH=""
  while IFS= read -r _rcp_dir; do
    [ -z "${_rcp_dir}" ] && continue
    MATCH_COUNT=$((MATCH_COUNT + 1))
    CGROUP_PATH="${_rcp_dir}"
  done <<EOF
${FOUND_DIRS}
EOF
  if [ "${MATCH_COUNT}" -ne 1 ] || [ -z "${CGROUP_PATH}" ] || [ ! -f "${CGROUP_PATH}/io.max" ] || [ ! -r "${CGROUP_PATH}/io.max" ]; then
    return 1
  fi
  return 0
}"""

def _indent_block(block: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join(pad + line if line else pad.rstrip() for line in block.splitlines())

def _validate_target_info_for_manifest(target_info: Dict[str, Any]) -> Tuple[str, str, str, int, int]:
    """Validate target metadata strictly before generating Kubernetes manifests."""
    if not isinstance(target_info, dict):
        raise ValueError("target_info must be a dictionary for manifest generation")
    cid = str(target_info.get("container_id", "")).strip()
    if not cid or len(cid) < 12 or any(c not in "0123456789abcdefABCDEF" for c in cid):
        raise ValueError(f"Invalid container_id for manifest generation: {cid!r}")
    target_node = str(target_info.get("target_node", "")).strip()
    target_pod = str(target_info.get("target_pod", "")).strip()
    if not target_node or any(ch.isspace() for ch in target_node):
        raise ValueError(f"Invalid target_node for manifest generation: {target_node!r}")
    if not target_pod or any(ch.isspace() for ch in target_pod):
        raise ValueError(f"Invalid target_pod for manifest generation: {target_pod!r}")
    if "dev_major" not in target_info or "dev_minor" not in target_info:
        raise ValueError("Missing dev_major or dev_minor in target_info for manifest generation")
    raw_maj = target_info.get("dev_major")
    raw_min = target_info.get("dev_minor")
    if isinstance(raw_maj, bool) or isinstance(raw_min, bool) or raw_maj is None or raw_min is None:
        raise ValueError(f"Malformed device major:minor for manifest generation: {raw_maj!r}:{raw_min!r}")
    if isinstance(raw_maj, int):
        dev_major = raw_maj
    elif isinstance(raw_maj, str) and raw_maj.strip().isdigit():
        dev_major = int(raw_maj.strip())
    else:
        raise ValueError(f"Malformed dev_major for manifest generation: {raw_maj!r}")
    if isinstance(raw_min, int):
        dev_minor = raw_min
    elif isinstance(raw_min, str) and raw_min.strip().isdigit():
        dev_minor = int(raw_min.strip())
    else:
        raise ValueError(f"Malformed dev_minor for manifest generation: {raw_min!r}")
    if dev_major <= 0 or dev_minor < 0:
        raise ValueError(f"Invalid or non-positive device major:minor for manifest generation: {dev_major}:{dev_minor}")
    return cid, target_node, target_pod, dev_major, dev_minor

def generate_helper_job_manifest(run_id: str, target_info: Dict[str, Any], level: str, duration_sec: int, dry_run: bool) -> str:
    if not run_id or any(ch.isspace() for ch in str(run_id)):
        raise ValueError(f"Invalid run_id for helper manifest: {run_id!r}")
    if level not in SEVERITY_LIMITS:
        raise ValueError(f"Unsupported severity level: {level!r}")
    if int(duration_sec) <= 0:
        raise ValueError(f"Fault duration_sec must be > 0, got {duration_sec!r}")
    _validate_target_info_for_manifest(target_info)
    limits = SEVERITY_LIMITS[level]
    job_name = f"g3-helper-{run_id.lower()}-{secrets.token_hex(3)}"
    dry_run_str = "true" if dry_run else "false"
    script_body = "set -eu\n\n" + _build_posix_io_max_helpers() + """

log_helper() {
  _lh_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown-utc")
  echo "[G3 Helper][${_lh_ts}] $1"
}

if [ -z "${G3_RUN_ID:-}" ] || ! is_hex "${G3_CONTAINER_ID:-}" || ! is_uint "${G3_DEV_MAJOR:-}" || ! is_uint "${G3_DEV_MINOR:-}" || ! is_uint "${G3_LIMIT_WBPS:-}" || ! is_uint "${G3_LIMIT_WIOPS:-}" || ! is_uint "${G3_DURATION_SEC:-}"; then
  echo "[G3 Helper] ERROR: Missing or invalid helper parameters (CID/Dev/Limits/Duration)."
  exit 1
fi

CGROUP_ROOT="${G3_CGROUP_ROOT:-/host/sys/fs/cgroup}"
DEV_ID="${G3_DEV_MAJOR}:${G3_DEV_MINOR}"
log_helper "Starting helper execution for ${G3_RUN_ID} (Pod=${G3_TARGET_POD:-unknown}, Dev=${DEV_ID}, CID=${G3_CONTAINER_ID})"

if ! resolve_unique_cgroup_path "${CGROUP_ROOT}" "${G3_CONTAINER_ID}"; then
  echo "[G3 Helper] ERROR: Unique cgroup path with readable io.max not found for container ${G3_CONTAINER_ID} (matches=${MATCH_COUNT:-0})"
  exit 1
fi
log_helper "Target cgroup resolved: ${CGROUP_PATH}"

if ! read_and_validate_io_max "${CGROUP_PATH}/io.max" "${DEV_ID}"; then
  echo "[G3 Helper] [CRITICAL ERROR] Initial io.max is missing or malformed on ${CGROUP_PATH}/io.max"
  exit 1
fi

ORIGINAL_IO_MAX="${FOUND_DEV_LINE}"
if [ -n "${ORIGINAL_IO_MAX}" ]; then
  if ! parse_device_line "${ORIGINAL_IO_MAX}" "${DEV_ID}"; then
    echo "[G3 Helper] [CRITICAL ERROR] Failed parsing baseline io.max entry: '${ORIGINAL_IO_MAX}'"
    exit 1
  fi
  ORIG_RBPS="${P_RBPS}"
  ORIG_WBPS="${P_WBPS}"
  ORIG_RIOPS="${P_RIOPS}"
  ORIG_WIOPS="${P_WIOPS}"
  ALLOW_ABSENT_ON_RESTORE=0
  if [ "${ORIG_RBPS}" = "max" ] && [ "${ORIG_WBPS}" = "max" ] && [ "${ORIG_RIOPS}" = "max" ] && [ "${ORIG_WIOPS}" = "max" ]; then
    ALLOW_ABSENT_ON_RESTORE=1
  fi
else
  ORIG_RBPS="max"
  ORIG_WBPS="max"
  ORIG_RIOPS="max"
  ORIG_WIOPS="max"
  ALLOW_ABSENT_ON_RESTORE=1
fi
log_helper "Original device ${DEV_ID} state: '${ORIGINAL_IO_MAX}'"

FAULT_APPLIED=0
CLEANUP_IN_PROGRESS=0
CLEANUP_DONE=0
SLEEP_PID=""

cleanup() {
  if [ "${CLEANUP_DONE}" = "1" ] || [ "${CLEANUP_IN_PROGRESS}" = "1" ]; then
    return 0
  fi
  CLEANUP_IN_PROGRESS=1
  trap '' INT TERM
  if [ -n "${SLEEP_PID}" ]; then
    kill -TERM "${SLEEP_PID}" 2>/dev/null || true
    wait "${SLEEP_PID}" 2>/dev/null || true
    SLEEP_PID=""
  fi
  if [ "${FAULT_APPLIED}" = "0" ]; then
    log_helper "[CLEANUP] No fault applied; skipping io.max write."
    CLEANUP_DONE=1
    CLEANUP_IN_PROGRESS=0
    return 0
  fi
  echo "[G3 Helper] [CLEANUP] Invoking rollback for device ${DEV_ID}..."
  if [ -n "${ORIGINAL_IO_MAX}" ]; then
    _rest_rule="${ORIGINAL_IO_MAX}"
  else
    _rest_rule="${DEV_ID} rbps=max wbps=max riops=max wiops=max"
  fi
  if ! printf '%s\\n' "${_rest_rule}" > "${CGROUP_PATH}/io.max" 2>/dev/null; then
    echo "[G3 Helper] [CRITICAL ERROR] Write failed during rollback for ${DEV_ID}!"
    echo "[G3 Helper] [CRITICAL ERROR] Failed to clear throttle on ${DEV_ID}!"
    CLEANUP_DONE=1
    CLEANUP_IN_PROGRESS=0
    return 2
  fi
  if ! verify_io_max_values "${ORIG_RBPS}" "${ORIG_WBPS}" "${ORIG_RIOPS}" "${ORIG_WIOPS}" "${ALLOW_ABSENT_ON_RESTORE}"; then
    echo "[G3 Helper] [CRITICAL ERROR] Post-restoration io.max entry failed four-limit verification: '${FOUND_DEV_LINE:-}'"
    echo "[G3 Helper] [CRITICAL ERROR] Failed to clear throttle on ${DEV_ID}!"
    CLEANUP_DONE=1
    CLEANUP_IN_PROGRESS=0
    return 2
  fi
  log_helper "[CLEANUP] Post-restoration io.max entry: '${FOUND_DEV_LINE:-}'"
  echo "[G3 Helper] [CLEANUP] Restoration VERIFIED successfully."
  FAULT_APPLIED=0
  CLEANUP_DONE=1
  CLEANUP_IN_PROGRESS=0
  return 0
}

on_signal() {
  _sig_name="$1"
  _sig_code="$2"
  if [ "${CLEANUP_IN_PROGRESS}" = "1" ] || [ "${CLEANUP_DONE}" = "1" ]; then
    echo "[G3 Helper] [SIGNAL SHIELDED] Duplicate ${_sig_name} ignored during/after cleanup."
    return 0
  fi
  trap '' INT TERM
  trap - EXIT
  log_helper "[SIGNAL] Caught ${_sig_name}; terminating active window and rolling back..."
  if ! cleanup; then
    exit 2
  fi
  exit "${_sig_code}"
}

on_exit() {
  _orig_rc=$?
  trap '' INT TERM
  trap - EXIT
  if [ "${CLEANUP_DONE}" = "0" ]; then
    if ! cleanup; then
      exit 2
    fi
  fi
  exit "${_orig_rc}"
}

trap 'on_signal INT 130' INT
trap 'on_signal TERM 143' TERM
trap on_exit EXIT

if [ "${G3_DRY_RUN:-false}" = "true" ]; then
  log_helper "DRY RUN MODE: Simulating ${G3_DURATION_SEC}s fault duration"
  sleep "${G3_DURATION_SEC}" &
  SLEEP_PID=$!
  wait "${SLEEP_PID}" || true
  SLEEP_PID=""
  log_helper "DRY RUN complete"
  exit 0
fi

if [ ! -w "${CGROUP_PATH}/io.max" ]; then
  echo "[G3 Helper] [CRITICAL ERROR] ${CGROUP_PATH}/io.max is not writable!"
  exit 1
fi

log_helper "[FAULT APPLY] Setting ${DEV_ID} rbps=${ORIG_RBPS} wbps=${G3_LIMIT_WBPS} riops=${ORIG_RIOPS} wiops=${G3_LIMIT_WIOPS}"
FAULT_APPLIED=1
if ! printf '%s rbps=%s wbps=%s riops=%s wiops=%s\\n' "${DEV_ID}" "${ORIG_RBPS}" "${G3_LIMIT_WBPS}" "${ORIG_RIOPS}" "${G3_LIMIT_WIOPS}" > "${CGROUP_PATH}/io.max" 2>/dev/null; then
  echo "[G3 Helper] [CRITICAL ERROR] Write to ${CGROUP_PATH}/io.max failed!"
  exit 1
fi

if ! verify_io_max_values "${ORIG_RBPS}" "${G3_LIMIT_WBPS}" "${ORIG_RIOPS}" "${G3_LIMIT_WIOPS}" 0; then
  echo "[G3 Helper] [CRITICAL ERROR] Throttle limit verification failed immediately after write ('${FOUND_DEV_LINE:-}')!"
  exit 1
fi
log_helper "Verified applied state: ${FOUND_DEV_LINE}"

log_helper "Sleeping for ${G3_DURATION_SEC} seconds (Active fault window)..."
sleep "${G3_DURATION_SEC}" &
SLEEP_PID=$!
wait "${SLEEP_PID}" || true
SLEEP_PID=""
log_helper "Active fault window finished. Normal exit invoking cleanup."
exit 0"""

    indented_script = _indent_block(script_body, 14)

    manifest = f"""apiVersion: batch/v1
kind: Job
metadata:
  name: {job_name}
  namespace: {CHAOS_NAMESPACE}
  labels:
    app.kubernetes.io/name: g3-chaos-helper
    ric.research/scenario: g3
spec:
  backoffLimit: 0
  activeDeadlineSeconds: {duration_sec + 120}
  ttlSecondsAfterFinished: 300
  template:
    metadata:
      labels:
        app.kubernetes.io/name: g3-chaos-helper
    spec:
      serviceAccountName: g1-chaos-helper-sa
      restartPolicy: Never
      nodeName: {target_info["target_node"]}
      hostPID: false
      hostNetwork: false
      terminationGracePeriodSeconds: 30
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      volumes:
        - name: host-cgroup
          hostPath:
            path: /sys/fs/cgroup
            type: Directory
      containers:
        - name: g3-helper
          image: {HELPER_IMAGE}
          imagePullPolicy: IfNotPresent
          env:
            - name: G3_RUN_ID
              value: "{run_id}"
            - name: G3_TARGET_POD
              value: "{target_info["target_pod"]}"
            - name: G3_CONTAINER_ID
              value: "{target_info["container_id"]}"
            - name: G3_DEV_MAJOR
              value: "{target_info["dev_major"]}"
            - name: G3_DEV_MINOR
              value: "{target_info["dev_minor"]}"
            - name: G3_LIMIT_WBPS
              value: "{limits["wbps"]}"
            - name: G3_LIMIT_WIOPS
              value: "{limits["wiops"]}"
            - name: G3_DURATION_SEC
              value: "{duration_sec}"
            - name: G3_DRY_RUN
              value: "{dry_run_str}"
          volumeMounts:
            - name: host-cgroup
              mountPath: /host/sys/fs/cgroup
              readOnly: false
          securityContext:
            runAsUser: 0
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
              add:
                - SYS_ADMIN
          command:
            - /bin/sh
            - -c
            - |
{indented_script}
"""
    return manifest

def generate_rollback_job_manifest(run_id: str, target_info: Dict[str, Any]) -> Tuple[str, str]:
    """Generate a privileged out-of-band host-cgroup rollback Job for G3 io.max restoration."""
    if not run_id or any(ch.isspace() for ch in str(run_id)):
        raise ValueError(f"Invalid run_id for rollback manifest: {run_id!r}")
    _validate_target_info_for_manifest(target_info)
    job_name = f"g3-rollback-{run_id.lower()}-{secrets.token_hex(3)}"
    orig_dev_line = target_info.get("initial_device_io_max", "")
    if not orig_dev_line and target_info.get("initial_io_max"):
        try:
            orig_dev_line = extract_device_io_max_line(
                target_info["initial_io_max"],
                int(target_info["dev_major"]),
                int(target_info["dev_minor"]),
            )
        except ValueError:
            orig_dev_line = ""

    script_body = "set -eu\n\n" + _build_posix_io_max_helpers() + """

if ! is_hex "${G3_CONTAINER_ID:-}" || ! is_uint "${G3_DEV_MAJOR:-}" || ! is_uint "${G3_DEV_MINOR:-}"; then
  echo "[G3 Rollback] ERROR: Missing or invalid rollback target identity."
  exit 2
fi

CGROUP_ROOT="${G3_CGROUP_ROOT:-/host/sys/fs/cgroup}"
DEV_ID="${G3_DEV_MAJOR}:${G3_DEV_MINOR}"
if ! resolve_unique_cgroup_path "${CGROUP_ROOT}" "${G3_CONTAINER_ID}"; then
  echo "[G3 Rollback] ERROR: Unique cgroup path not found for ${G3_CONTAINER_ID} (matches=${MATCH_COUNT:-0})."
  exit 2
fi

ORIG_LINE="${G3_ORIGINAL_IO_MAX:-}"
if [ -n "${ORIG_LINE}" ]; then
  if ! parse_device_line "${ORIG_LINE}" "${DEV_ID}"; then
    echo "[G3 Rollback] ERROR: Invalid G3_ORIGINAL_IO_MAX '${ORIG_LINE}'."
    exit 2
  fi
  ORIG_RBPS="${P_RBPS}"
  ORIG_WBPS="${P_WBPS}"
  ORIG_RIOPS="${P_RIOPS}"
  ORIG_WIOPS="${P_WIOPS}"
  ALLOW_ABSENT=0
  if [ "${ORIG_RBPS}" = "max" ] && [ "${ORIG_WBPS}" = "max" ] && [ "${ORIG_RIOPS}" = "max" ] && [ "${ORIG_WIOPS}" = "max" ]; then
    ALLOW_ABSENT=1
  fi
  RESTORE_RULE="${ORIG_LINE}"
else
  ORIG_RBPS="max"
  ORIG_WBPS="max"
  ORIG_RIOPS="max"
  ORIG_WIOPS="max"
  ALLOW_ABSENT=1
  RESTORE_RULE="${DEV_ID} rbps=max wbps=max riops=max wiops=max"
fi

if ! printf '%s\\n' "${RESTORE_RULE}" > "${CGROUP_PATH}/io.max" 2>/dev/null; then
  echo "[G3 Rollback] CRITICAL ERROR: Write to ${CGROUP_PATH}/io.max failed."
  exit 2
fi

if ! verify_io_max_values "${ORIG_RBPS}" "${ORIG_WBPS}" "${ORIG_RIOPS}" "${ORIG_WIOPS}" "${ALLOW_ABSENT}"; then
  echo "[G3 Rollback] CRITICAL ERROR: Readback verification failed ('${FOUND_DEV_LINE:-}')."
  exit 2
fi
echo "[G3 Rollback] Restoration VERIFIED on ${DEV_ID}."
exit 0"""

    indented_script = _indent_block(script_body, 14)

    manifest = f"""apiVersion: batch/v1
kind: Job
metadata:
  name: {job_name}
  namespace: {CHAOS_NAMESPACE}
  labels:
    app.kubernetes.io/name: g3-chaos-rollback
    ric.research/scenario: g3
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 60
  ttlSecondsAfterFinished: 120
  template:
    metadata:
      labels:
        app.kubernetes.io/name: g3-chaos-rollback
    spec:
      serviceAccountName: g1-chaos-helper-sa
      restartPolicy: Never
      nodeName: {target_info["target_node"]}
      hostPID: false
      hostNetwork: false
      terminationGracePeriodSeconds: 15
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      volumes:
        - name: host-cgroup
          hostPath:
            path: /sys/fs/cgroup
            type: Directory
      containers:
        - name: g3-rollback
          image: {HELPER_IMAGE}
          imagePullPolicy: IfNotPresent
          env:
            - name: G3_CONTAINER_ID
              value: "{target_info["container_id"]}"
            - name: G3_DEV_MAJOR
              value: "{target_info["dev_major"]}"
            - name: G3_DEV_MINOR
              value: "{target_info["dev_minor"]}"
            - name: G3_ORIGINAL_IO_MAX
              value: "{orig_dev_line}"
          volumeMounts:
            - name: host-cgroup
              mountPath: /host/sys/fs/cgroup
              readOnly: false
          securityContext:
            runAsUser: 0
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
              add:
                - SYS_ADMIN
          command:
            - /bin/sh
            - -c
            - |
{indented_script}
"""
    return job_name, manifest

def collect_helper_job_logs(label_selector: str, output_dir: Optional[str] = None, prefix: str = "helper") -> Dict[str, Any]:
    """Capture helper Job pod status, exit codes, and logs prior to Job deletion."""
    info: Dict[str, Any] = {
        "label_selector": label_selector,
        "collected_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "pods": [],
        "errors": [],
    }
    pods_res = run_cmd(["kubectl", "get", "pods", "-n", CHAOS_NAMESPACE, "-l", label_selector, "-o", "json"], check=False, timeout=10.0)
    if pods_res.returncode != 0:
        info["errors"].append(f"get pods failed ({pods_res.returncode}): {pods_res.stderr.strip()}")
        return info
    try:
        items = json.loads(pods_res.stdout).get("items", [])
    except Exception as e:
        info["errors"].append(f"malformed pods json: {e}")
        return info

    all_logs: List[str] = []
    for pod in items:
        pod_name = pod.get("metadata", {}).get("name", "")
        phase = pod.get("status", {}).get("phase", "")
        cstatuses = pod.get("status", {}).get("containerStatuses", [])
        exit_codes = {}
        for cs in cstatuses:
            term = cs.get("state", {}).get("terminated", {})
            if term:
                exit_codes[cs.get("name", "unknown")] = term.get("exitCode")
        logs_res = run_cmd(["kubectl", "logs", "-n", CHAOS_NAMESPACE, pod_name], check=False, timeout=10.0)
        pod_entry = {
            "pod_name": pod_name,
            "phase": phase,
            "exit_codes": exit_codes,
            "logs_returncode": logs_res.returncode,
        }
        info["pods"].append(pod_entry)
        all_logs.append(f"=== Pod: {pod_name} (phase={phase}, exit_codes={exit_codes}) ===\n{logs_res.stdout}\n{logs_res.stderr}\n")

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        with open(os.path.join(output_dir, f"{prefix}_job_status.json"), "w", encoding="utf-8") as sf:
            json.dump(info, sf, indent=2)
        with open(os.path.join(output_dir, f"{prefix}_job_logs.txt"), "w", encoding="utf-8") as lf:
            lf.write("".join(all_logs))
    return info

_EMERGENCY_ROLLBACK_LOCK = threading.Lock()
_ACTIVE_ROLLBACK_KEYS = set()
LAST_ROLLBACK_REPORTS: List[Dict[str, Any]] = []

def emergency_independent_rollback(target_info: Dict[str, Any]) -> bool:
    """
    Fail-closed independent emergency rollback.
    Executes restoration through a privileged host-cgroup Job (never writing read-only
    in-pod cgroup mounts), cleans up active helper Jobs, and verifies exact four-limit
    restoration via readback. Failed kubectl or verification ALWAYS returns False.
    """
    report: Dict[str, Any] = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "FAILED",
        "errors": [],
    }
    try:
        target_pod = target_info["target_pod"]
        target_node = target_info["target_node"]
        dev_major = int(target_info["dev_major"])
        dev_minor = int(target_info["dev_minor"])
        cid = target_info["container_id"]
    except Exception as e:
        report["errors"].append(f"Invalid target_info for rollback: {e}")
        LAST_ROLLBACK_REPORTS.append(report)
        log(f"[INDEPENDENT RECOVERY ERROR] Invalid target_info: {e}")
        return False

    if not target_pod or not target_node or not cid or any(c not in "0123456789abcdefABCDEF" for c in cid):
        report["errors"].append("Missing target_pod, target_node, or valid hex container_id")
        LAST_ROLLBACK_REPORTS.append(report)
        log("[INDEPENDENT RECOVERY ERROR] Refusing rollback with invalid target identity.")
        return False

    orig_io_max = target_info.get("initial_io_max", "")
    rb_key = (target_pod, cid)

    with _EMERGENCY_ROLLBACK_LOCK:
        if rb_key in _ACTIVE_ROLLBACK_KEYS:
            report["errors"].append(f"Concurrent rollback already active for {target_pod} ({cid[:12]})")
            LAST_ROLLBACK_REPORTS.append(report)
            log(f"[INDEPENDENT RECOVERY SHIELDED] Concurrent second rollback prevented for {target_pod} ({cid[:12]}).")
            return False
        _ACTIVE_ROLLBACK_KEYS.add(rb_key)

    try:
        log(f"[INDEPENDENT RECOVERY] Initiating emergency out-of-band rollback for {target_pod} (Dev {dev_major}:{dev_minor}, CID {cid[:12]})...")
        pod_res = run_cmd(["kubectl", "get", "pod", target_pod, "-n", NAMESPACE, "-o", "json"], check=False, timeout=10.0)
        if pod_res.returncode != 0:
            err = f"kubectl get pod {target_pod} failed ({pod_res.returncode}): {pod_res.stderr.strip()}"
            report["errors"].append(err)
            log(f"[INDEPENDENT RECOVERY ERROR] {err}")
            return False
        try:
            pod_json = json.loads(pod_res.stdout)
            cstatuses = pod_json["status"]["containerStatuses"]
            db_cs = next((cs for cs in cstatuses if cs.get("name") == "db"), cstatuses[0])
            live_cid = db_cs["containerID"].replace("containerd://", "").strip()
        except Exception as e:
            err = f"Failed parsing pod JSON during rollback: {e}"
            report["errors"].append(err)
            log(f"[INDEPENDENT RECOVERY ERROR] {err}")
            return False

        if live_cid != cid:
            log(f"[INDEPENDENT RECOVERY] Container ID mismatch! Target was {cid[:12]}, live is {live_cid[:12]}. Verifying live cgroup io.max before confirming...")
            restart_verify = run_cmd(["kubectl", "exec", "-n", NAMESPACE, target_pod, "--", "cat", "/sys/fs/cgroup/io.max"], check=False, timeout=10.0)
            if restart_verify.returncode != 0:
                err = f"Post-restart io.max verification kubectl exec failed ({restart_verify.returncode}): {restart_verify.stderr.strip()}"
                report["errors"].append(err)
                log(f"[INDEPENDENT RECOVERY ERROR] {err}")
                return False
            ok, msg = verify_io_max_restored(restart_verify.stdout, dev_major, dev_minor, "")
            report["post_restart_verify"] = msg
            if not ok:
                report["errors"].append(msg)
                log(f"[INDEPENDENT RECOVERY ERROR] {msg}")
                return False
            report["status"] = "VERIFIED_AFTER_RESTART"
            return True

        # Ensure any remaining helper Job is deleted so it cannot re-apply or linger
        run_cmd(["kubectl", "delete", "job", "-n", CHAOS_NAMESPACE, "-l", "app.kubernetes.io/name=g3-chaos-helper", "--ignore-not-found=true"], check=False, timeout=15.0)

        rb_job_name, rb_manifest = generate_rollback_job_manifest("emergency", target_info)
        report["rollback_job_name"] = rb_job_name
        with tempfile.TemporaryDirectory(prefix="g3rb_") as rb_dir:
            rb_path = os.path.join(rb_dir, "rollback_job.yaml")
            with open(rb_path, "w", encoding="utf-8") as rbf:
                rbf.write(rb_manifest)
            apply_res = run_cmd(["kubectl", "apply", "-f", rb_path], check=False, timeout=15.0)
        if apply_res.returncode != 0:
            err = f"Rollback Job submit failed ({apply_res.returncode}): {apply_res.stderr.strip()}"
            report["errors"].append(err)
            log(f"[INDEPENDENT RECOVERY ERROR] {err}")
            return False

        wait_res = run_cmd(["kubectl", "wait", "--for=condition=complete", "--timeout=30s", f"job/{rb_job_name}", "-n", CHAOS_NAMESPACE], check=False, timeout=35.0)
        rb_logs = run_cmd(["kubectl", "logs", "-n", CHAOS_NAMESPACE, "-l", f"job-name={rb_job_name}"], check=False, timeout=10.0)
        report["rollback_job_logs"] = rb_logs.stdout.strip()
        run_cmd(["kubectl", "delete", "job", rb_job_name, "-n", CHAOS_NAMESPACE, "--ignore-not-found=true"], check=False, timeout=15.0)

        if wait_res.returncode != 0:
            err = f"Rollback Job {rb_job_name} did not complete successfully ({wait_res.returncode}): {wait_res.stderr.strip()}"
            report["errors"].append(err)
            log(f"[INDEPENDENT RECOVERY ERROR] {err}")
            return False

        verify_res = run_cmd(["kubectl", "exec", "-n", NAMESPACE, target_pod, "--", "cat", "/sys/fs/cgroup/io.max"], check=False, timeout=10.0)
        if verify_res.returncode != 0:
            err = f"Post-recovery io.max readback kubectl exec failed ({verify_res.returncode}): {verify_res.stderr.strip()}"
            report["errors"].append(err)
            log(f"[INDEPENDENT RECOVERY ERROR] {err}")
            return False

        current_io = verify_res.stdout.strip()
        report["post_recovery_io_max"] = current_io
        log(f"[INDEPENDENT RECOVERY] Post-recovery io.max: '{current_io}'")

        ok, msg = verify_io_max_restored(verify_res.stdout, dev_major, dev_minor, orig_io_max)
        report["verification_detail"] = msg
        if not ok:
            report["errors"].append(msg)
            log(f"[INDEPENDENT RECOVERY ERROR] {msg}")
            return False

        report["status"] = "VERIFIED_RESTORED"
        log("[INDEPENDENT RECOVERY] Emergency rollback succeeded and verified.")
        return True
    finally:
        LAST_ROLLBACK_REPORTS.append(report)
        with _EMERGENCY_ROLLBACK_LOCK:
            _ACTIVE_ROLLBACK_KEYS.discard(rb_key)

def resolve_output_directory(run_id: str, level: str, output_dir: Optional[str] = None) -> str:
    """
    Explicitly and deterministically resolves the output directory for G3 executions.
    - If output_dir is explicitly specified, validates it is not a symlink and uses it.
    - If run_id designates an exploratory or calibration pilot (contains 'pilot' or starts with 'dry'),
      routes to thesis-evidence/07-g3-chaos/pilots/{run_id}/.
    - Otherwise (formal repetitions r01..r05), routes to
      thesis-evidence/experiments/cockroachdb/G3-{level}/{run_id}/.
    """
    if output_dir:
        abs_path = os.path.abspath(output_dir)
        if os.path.islink(abs_path):
            raise RuntimeError(f"FAIL-CLOSED: Output directory cannot be a symlink: {abs_path}")
        return abs_path

    clean_id = run_id.strip()
    clean_level = level.strip().upper()

    if "pilot" in clean_id.lower() or "dry" in clean_id.lower():
        return os.path.abspath(os.path.join("thesis-evidence", "07-g3-chaos", "pilots", clean_id))

    return os.path.abspath(
        os.path.join("thesis-evidence", "experiments", "cockroachdb", f"G3-{clean_level}", clean_id)
    )

class SignalInterruptionError(BaseException):
    """Raised when an operating system signal (e.g. SIGTERM, SIGINT) is received during coordinator execution."""
    def __init__(self, signum: int, signame: str):
        self.signum = signum
        self.signame = signame
        super().__init__(f"Lifecycle interrupted by operating system signal {signame} ({signum})")

class G3PilotExecutionCoordinator:
    """
    15-state explicit execution state machine for CockroachDB G3 Disk I/O Throttling Pilots.
    Ensures rigorous fail-closed transitions, four-clock timing adherence, and guaranteed rollback.
    """
    def __init__(
        self,
        run_id: str,
        level: str,
        duration_sec: int,
        dry_run: bool = False,
        target_override: Optional[str] = None,
        output_dir: Optional[str] = None,
    ):
        self.run_id = run_id
        self.level = level
        self.duration_sec = duration_sec
        self.dry_run = dry_run
        self.target_override = target_override
        
        self.output_dir = resolve_output_directory(self.run_id, self.level, output_dir)
        self.current_state: Optional[ExecutionState] = None
        self.state_history: List[Dict[str, Any]] = []
        
        self.target_info: Optional[Dict[str, Any]] = None
        self.preflight_audit: Optional[Dict[str, Any]] = None
        self.helper_job_name: Optional[str] = None
        self.helper_manifest_path: Optional[str] = None
        
        self.stop_telemetry_event = threading.Event()
        self.telemetry_thread: Optional[threading.Thread] = None
        self.telemetry_file_path = os.path.join(self.output_dir, "telemetry_timeseries.jsonl")
        
        self.measurement_proc: Optional[subprocess.Popen] = None
        self.remote_pgid: Optional[int] = None
        self.fault_applied: bool = False
        self.error_occurred: bool = False
        self.cleanup_error: Optional[str] = None
        self.evidence_missing: List[str] = []
        self.signal_received: Optional[Dict[str, Any]] = None
        self.secondary_signals: List[Dict[str, Any]] = []
        self.cleanup_in_progress: bool = False
        self.final_disposition: str = "PENDING"
        self.authorization_metadata: Optional[Dict[str, Any]] = None
        self.history_counts: Dict[str, Any] = {}
        self.helper_logs_metadata: Optional[Dict[str, Any]] = None
        self.rollback_audit: List[Dict[str, Any]] = []
        self.command_audit: Dict[str, Any] = {}
        self.timing_definitions: Dict[str, Any] = {
            "DT": "Active fault duration (T_clear - T_applied)",
            "RTO": "Recovery time objective metric from external monitoring (kept distinct from Wrec)",
            "Wrec": "Post-clearance recovery observation window anchored strictly to T_clear (T_obs_end - T_clear >= 300s)",
            "clock3_tx_stream_span_sec": "Client transaction stream span (t_last_tx - t_first_tx from pgbench logs)",
        }
        
        # Timing Clocks
        self.clocks = {
            "clock1_fault_duration_sec": 0.0,
            "clock2_wrec_duration_sec": 0.0,
            "clock3_tx_stream_span_sec": 0.0,
            "clock4_wall_clock_meas_sec": 0.0,
        }
        self.timestamps = {
            "T_meas_start": None,
            "T_applied": None,
            "T_clear": None,
            "T_obs_end": None,
            "T_meas_end": None,
        }

    def transition_to(self, new_state: ExecutionState):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if self.current_state is not None:
            self.state_history[-1]["completed_at"] = now
            self.state_history[-1]["status"] = "COMPLETED"
        log(f"[STATE MACHINE] Entering state: {new_state.value}")
        self.current_state = new_state
        self.state_history.append({
            "state": new_state.value,
            "started_at": now,
            "completed_at": None,
            "status": "RUNNING",
            "error": None
        })

    def record_error(self, err_msg: str):
        self.error_occurred = True
        log(f"[STATE MACHINE ERROR] In state {self.current_state.value if self.current_state else 'NONE'}: {err_msg}")
        if self.state_history:
            self.state_history[-1]["status"] = "FAILED"
            self.state_history[-1]["error"] = err_msg

    def execute_lifecycle(self) -> Dict[str, Any]:
        """
        Executes the complete 15-state pilot lifecycle.
        Fail-closed: if any state fails, triggers cleanup/rollback and halts without retry.
        Registers explicit POSIX/OS signal handlers (SIGTERM, SIGINT) and restores prior handlers on exit.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        t_applied_epoch: Optional[float] = None
        t_clear_epoch: Optional[float] = None
        
        # Save prior signal handlers and register coordinator handlers if running in main thread
        prior_sigterm = None
        prior_sigint = None
        in_main_thread = (threading.current_thread() is threading.main_thread())
        
        if in_main_thread:
            def _signal_handler(signum, frame):
                sig_names = {signal.SIGINT: "SIGINT"}
                if hasattr(signal, "SIGTERM"):
                    sig_names[signal.SIGTERM] = "SIGTERM"
                name = sig_names.get(signum, f"SIGNAL_{signum}")
                now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
                current_state_str = self.current_state.value if self.current_state else "NONE"

                # Check if cleanup/rollback is currently in progress
                if self.cleanup_in_progress:
                    sec_info = {
                        "signal_number": signum,
                        "signal_name": name,
                        "received_at": now_str,
                        "state": current_state_str
                    }
                    self.secondary_signals.append(sec_info)
                    log(f"[SIGNAL SHIELDED] Captured secondary signal {name} ({signum}) during active cleanup/rollback in state {current_state_str}. Shielded to prevent rollback interruption.")
                    return

                self.signal_received = {
                    "signal_number": signum,
                    "signal_name": name,
                    "received_at": now_str,
                    "state": current_state_str
                }
                log(f"[SIGNAL RECEIVED] Captured {name} ({signum}) in state {current_state_str}. Initiating controlled lifecycle interruption.")
                raise SignalInterruptionError(signum, name)

            try:
                prior_sigint = signal.signal(signal.SIGINT, _signal_handler)
            except (ValueError, OSError) as e:
                log(f"[SIGNAL WARNING] Could not register SIGINT handler: {e}")
                
            if hasattr(signal, "SIGTERM"):
                try:
                    prior_sigterm = signal.signal(signal.SIGTERM, _signal_handler)
                except (ValueError, OSError) as e:
                    log(f"[SIGNAL WARNING] Could not register SIGTERM handler: {e}")

        try:
            # 1. PREFLIGHT
            self.transition_to(ExecutionState.PREFLIGHT)
            self.preflight_audit = run_preflight_audit(dry_run=self.dry_run)
            check_storage_capacity(min_avail_mb=30.0)

            # 2. TARGET_VERIFICATION
            self.transition_to(ExecutionState.TARGET_VERIFICATION)
            self.target_info = resolve_target_leaseholder(target_override=self.target_override)
            dev_major = int(self.target_info["dev_major"])
            dev_minor = int(self.target_info["dev_minor"])
            clean_ok, clean_msg = verify_io_max_restored(self.target_info.get("initial_io_max", ""), dev_major, dev_minor, "")
            if not clean_ok:
                raise RuntimeError(f"Pre-existing throttling detected on target: {clean_msg} ({self.target_info['initial_io_max']})")

            manifest_content = generate_helper_job_manifest(
                run_id=self.run_id,
                target_info=self.target_info,
                level=self.level,
                duration_sec=self.duration_sec,
                dry_run=self.dry_run
            )
            self.helper_manifest_path = os.path.join(self.output_dir, "03_helper_job_manifest.yaml")
            with open(self.helper_manifest_path, "w", encoding="utf-8") as f:
                f.write(manifest_content)
            self.helper_job_name = extract_job_name_from_manifest(manifest_content) or f"g3-helper-{self.run_id.lower()}"

            # 3. WORKLOAD_START
            self.transition_to(ExecutionState.WORKLOAD_START)
            s0_str = query_sql("SELECT count(*) FROM benchdb.public.pgbench_history;")
            s0_history = int(s0_str)
            self.history_counts["s0_before_warmup"] = s0_history
            log(f"Initial history count (S0): {s0_history}")

            # 4. WARMUP
            self.transition_to(ExecutionState.WARMUP)
            log("Executing 120s standalone unlogged warmup (with -n history preservation)...")
            if not self.dry_run:
                warmup_cmd = construct_warmup_command(duration_sec=120)
                w_res = run_cmd(warmup_cmd, check=False, timeout=140.0)
                self.command_audit["warmup"] = {
                    "returncode": w_res.returncode,
                    "completed_at_utc": _utc_now().isoformat(),
                    "preserved_history_flag_n": ("-n" in warmup_cmd),
                }
                if w_res.returncode != 0:
                    raise RuntimeError(f"Warmup workload failed with code {w_res.returncode}: {w_res.stderr}")
            else:
                log("[DRY RUN] Simulating 120s warmup completion.")
            
            s1_history = int(query_sql("SELECT count(*) FROM benchdb.public.pgbench_history;"))
            self.history_counts["s1_after_warmup"] = s1_history
            self.history_counts["warmup_delta"] = s1_history - s0_history
            log(f"Post-warmup history count (S1): {s1_history} (Delta: {s1_history - s0_history})")
            if s1_history < s0_history:
                raise RuntimeError(f"FAIL-CLOSED: pgbench_history count decreased during warmup ({s0_history} -> {s1_history}); unintended clearing detected!")

            # Verify target didn't move during warmup
            post_warmup_target = resolve_target_leaseholder(target_override=self.target_override)
            validate_target_unchanged(self.target_info, post_warmup_target, phase_label="warmup")

            # Launch background telemetry only in non-dry-run mode
            if not self.dry_run:
                self.telemetry_thread = threading.Thread(
                    target=incremental_telemetry_poller,
                    args=(self.target_info["target_pod"], self.stop_telemetry_event, self.telemetry_file_path, 5.0),
                    daemon=True
                )
                self.telemetry_thread.start()

            # Launch in-pod measurement wrapper (600s)
            log("Launching 600s measurement stream via in-pod wrapper...")
            meas_script = construct_in_pod_wrapper(self.run_id, duration_sec=600)
            t_meas_start_epoch = time.time()
            self.timestamps["T_meas_start"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            
            if not self.dry_run:
                meas_cmd = ["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "bash", "-c", meas_script]
                self.measurement_proc = subprocess.Popen(meas_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # Poll for remote PGID
                for _ in range(30):
                    time.sleep(1.0)
                    pgid_raw = run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "sh", "-c", f"cat /tmp/pgbench_{self.run_id}_pgid.txt 2>/dev/null || true"], check=False).stdout.strip()
                    if pgid_raw.isdigit():
                        self.remote_pgid = int(pgid_raw)
                        break
                if not self.remote_pgid:
                    raise RuntimeError("Failed to capture remote PGID from benchmark client wrapper.")
                log(f"Benchmark client wrapper active under PGID {self.remote_pgid}")
            else:
                log("[DRY RUN] Simulating in-pod measurement launch under mocked PGID 9999")
                self.remote_pgid = 9999

            # 5. BASELINE_MEASUREMENT (180s)
            self.transition_to(ExecutionState.BASELINE_MEASUREMENT)
            log("Holding 180s pre-fault baseline measurement window...")
            if not self.dry_run:
                time.sleep(180)
            else:
                time.sleep(1)
            pre_fault_target = resolve_target_leaseholder(target_override=self.target_override)
            validate_target_unchanged(self.target_info, pre_fault_target, phase_label="pre_fault_application")

            # 6. FAULT_APPLICATION
            self.transition_to(ExecutionState.FAULT_APPLICATION)
            log(f"Applying G3 disk I/O throttling fault (Level {self.level})...")
            t_applied_epoch = time.time()
            self.timestamps["T_applied"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            if not self.dry_run:
                apply_res = run_cmd(["kubectl", "apply", "-f", self.helper_manifest_path], check=False, timeout=15.0)
                if apply_res.returncode != 0:
                    raise RuntimeError(f"Failed to submit helper Job manifest: {apply_res.stderr}")
            else:
                log("[DRY RUN] Simulating helper Job submission.")
            self.fault_applied = True

            # 7. FAULT_VERIFICATION
            self.transition_to(ExecutionState.FAULT_VERIFICATION)
            log("Verifying kernel block throttle rule in cgroup io.max...")
            if not self.dry_run:
                verified = False
                last_verify_detail = ""
                limits = SEVERITY_LIMITS[self.level]
                orig_io = self.target_info.get("initial_io_max", "")
                for _ in range(15):
                    time.sleep(1.0)
                    io_res = run_cmd(["kubectl", "exec", "-n", NAMESPACE, self.target_info["target_pod"], "--", "cat", "/sys/fs/cgroup/io.max"], check=False, timeout=10.0)
                    if io_res.returncode != 0:
                        last_verify_detail = f"kubectl exec failed ({io_res.returncode}): {io_res.stderr.strip()}"
                        continue
                    ok, detail = verify_io_max_applied(
                        io_res.stdout,
                        dev_major,
                        dev_minor,
                        limits["wbps"],
                        limits["wiops"],
                        orig_io,
                    )
                    last_verify_detail = detail
                    if ok:
                        verified = True
                        log(f"Verified applied throttle in kernel io.max: {io_res.stdout.strip()}")
                        break
                if not verified:
                    raise RuntimeError(f"Fault application verification FAILED: Throttle limit did not appear in io.max within 15s ({last_verify_detail})")
            else:
                log("[DRY RUN] Simulating fault verification success.")

            # 8. FAULT_MEASUREMENT
            self.transition_to(ExecutionState.FAULT_MEASUREMENT)
            log(f"Maintaining active fault window for {self.duration_sec}s...")
            t_fault_start = time.time()
            if not self.dry_run:
                time.sleep(self.duration_sec)
            else:
                time.sleep(1)
            self.clocks["clock1_fault_duration_sec"] = time.time() - t_fault_start

            # 9. FAULT_REMOVAL
            self.transition_to(ExecutionState.FAULT_REMOVAL)
            log("Active fault window completed. Initiating fault removal...")
            t_clear_epoch = time.time()
            self.timestamps["T_clear"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            if not self.dry_run:
                # Wait briefly for self-timed helper completion, capture logs BEFORE Job deletion, then delete Job cleanly.
                # Note: Job deletion delivers kubelet SIGTERM to container entrypoint; helper traps SIGTERM and restores io.max.
                if self.helper_job_name:
                    run_cmd(["kubectl", "wait", "--for=condition=complete", "--timeout=15s", f"job/{self.helper_job_name}", "-n", CHAOS_NAMESPACE], check=False, timeout=20.0)
                self.helper_logs_metadata = collect_helper_job_logs(
                    "app.kubernetes.io/name=g3-chaos-helper",
                    output_dir=self.output_dir,
                    prefix="04_helper",
                )
                run_cmd(["kubectl", "delete", "job", "-n", CHAOS_NAMESPACE, "-l", "app.kubernetes.io/name=g3-chaos-helper", "--ignore-not-found=true"], check=False, timeout=30.0)
            else:
                log("[DRY RUN] Simulating helper Job deletion.")

            # 10. RESTORATION_VERIFICATION
            self.transition_to(ExecutionState.RESTORATION_VERIFICATION)
            log("Verifying io.max throttle clearance...")
            if not self.dry_run:
                restored = False
                last_rest_detail = ""
                orig_io = self.target_info.get("initial_io_max", "")
                for _ in range(15):
                    time.sleep(1.0)
                    io_res = run_cmd(["kubectl", "exec", "-n", NAMESPACE, self.target_info["target_pod"], "--", "cat", "/sys/fs/cgroup/io.max"], check=False, timeout=10.0)
                    if io_res.returncode != 0:
                        last_rest_detail = f"kubectl exec failed ({io_res.returncode}): {io_res.stderr.strip()}"
                        continue
                    ok, detail = verify_io_max_restored(io_res.stdout, dev_major, dev_minor, orig_io)
                    last_rest_detail = detail
                    if ok:
                        restored = True
                        log(f"Confirmed io.max restored cleanly: {detail}")
                        break
                if not restored:
                    log(f"[CRITICAL WARNING] Helper trap clearance verification failed ({last_rest_detail})! Invoking emergency independent rollback...")
                    rb_ok = emergency_independent_rollback(self.target_info)
                    if LAST_ROLLBACK_REPORTS:
                        self.rollback_audit.append(LAST_ROLLBACK_REPORTS[-1])
                    if not rb_ok:
                        raise RuntimeError("EMERGENCY ROLLBACK FAILED: Target device remains throttled in kernel!")
            else:
                log("[DRY RUN] Simulating restoration verification success.")
            t_clear_epoch = time.time()
            self.timestamps["T_clear"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            if t_applied_epoch is not None:
                self.clocks["clock1_fault_duration_sec"] = t_clear_epoch - t_applied_epoch
            self.fault_applied = False

            # 11. POST_FAULT_MEASUREMENT
            self.transition_to(ExecutionState.POST_FAULT_MEASUREMENT)
            log("Awaiting completion of client measurement workload stream (Clock 3)...")
            if not self.dry_run:
                wrapper_proc_retcode = None
                wrapper_timed_out = False
                stdout_str = ""
                stderr_str = ""
                if self.measurement_proc:
                    try:
                        stdout_str, stderr_str = self.measurement_proc.communicate(timeout=300.0)
                        wrapper_proc_retcode = self.measurement_proc.returncode
                    except subprocess.TimeoutExpired:
                        log("[MEASUREMENT WARNING] Measurement wrapper process timed out after 300s in communicate().")
                        wrapper_timed_out = True
                        wrapper_proc_retcode = -1
                    except Exception as comm_exc:
                        log(f"[MEASUREMENT WARNING] Exception during measurement wrapper communicate(): {comm_exc}")
                        wrapper_proc_retcode = self.measurement_proc.poll() or -1

                    with open(os.path.join(self.output_dir, "05_measurement_wrapper_stdout.txt"), "w", encoding="utf-8") as mf:
                        mf.write(stdout_str or "")
                    with open(os.path.join(self.output_dir, "05_measurement_wrapper_stderr.txt"), "w", encoding="utf-8") as mf:
                        mf.write(stderr_str or "")
                    self.command_audit["measurement_wrapper"] = {
                        "returncode": wrapper_proc_retcode,
                        "timed_out": wrapper_timed_out,
                        "completed_at_utc": _utc_now().isoformat(),
                    }
                    log(f"Measurement wrapper stream completed with returncode={wrapper_proc_retcode} (timed_out={wrapper_timed_out})")

                # Transport vs remote workload decoupling verification:
                # If the wrapper streaming process dropped (e.g. WebSocket connection dropped),
                # do NOT immediately fail. Wait for remote workload process completion via bounded polling.
                # In testing/offline environments where ps/exit checks are mocked or absent, do not hang.
                exit_check_cmd = ["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "sh", "-c", f"test -f /tmp/pgbench_{self.run_id}_exit_code.txt"]
                exit_check_res = run_cmd(exit_check_cmd, check=False, timeout=15.0)

                # If the exit code marker is not yet present, poll remote process group until termination
                if exit_check_res.returncode != 0 and self.remote_pgid:
                    workload_finished = False
                    poll_interval = 2.0
                    max_wait_sec = max(60.0, (t_meas_start_epoch + 600.0 + 180.0) - time.time())
                    consecutive_ps_errors = 0
                    poll_start = time.time()
                    while time.time() - poll_start < max_wait_sec:
                        try:
                            live, zombies = query_live_processes_in_pgid(self.remote_pgid)
                            consecutive_ps_errors = 0
                            if not live:
                                workload_finished = True
                                log(f"Remote process group -{self.remote_pgid} confirmed finished (Zombies: {len(zombies)}).")
                                break
                        except Exception as poll_err:
                            consecutive_ps_errors += 1
                            log(f"[PROCESS MONITOR] Warning querying remote PGID -{self.remote_pgid}: {poll_err}")
                            if consecutive_ps_errors >= 3:
                                log(f"[PROCESS MONITOR] Consecutive ps query failures ({consecutive_ps_errors}); breaking wait loop.")
                                break
                        time.sleep(poll_interval)

                    if not workload_finished and consecutive_ps_errors < 3:
                        raise RuntimeError(
                            f"Remote workload process group -{self.remote_pgid} did not terminate within {max_wait_sec}s grace period!"
                        )

                    # Re-check exit code marker following remote process group termination
                    exit_check_res = run_cmd(exit_check_cmd, check=False, timeout=15.0)

                # In non-dry-run mode, if wrapper returned non-zero AND exit code marker is missing,
                # fail-closed with clear transport vs workload diagnostics.
                if exit_check_res.returncode != 0 and (wrapper_proc_retcode != 0 or not self.remote_pgid):
                    raise RuntimeError(
                        f"Remote workload exit code marker /tmp/pgbench_{self.run_id}_exit_code.txt is missing after workload termination!"
                    )
            else:
                log("[DRY RUN] Simulating measurement workload completion.")
            self.timestamps["T_meas_end"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.clocks["clock4_wall_clock_meas_sec"] = time.time() - t_meas_start_epoch
            post_fault_workload_sec = (time.time() - t_clear_epoch) if t_clear_epoch is not None else 0.0

            # 12. WREC_OBSERVATION (Clock 2, >= 300s anchored strictly to T_clear)
            self.transition_to(ExecutionState.WREC_OBSERVATION)
            elapsed_since_clear = (time.time() - t_clear_epoch) if t_clear_epoch is not None else 0.0
            remaining_wrec_sec = max(0.0, 300.0 - elapsed_since_clear)
            log(f"Observing post-clearance quiescence and compaction (Wrec anchored to T_clear: elapsed={elapsed_since_clear:.1f}s, remaining_quiet={remaining_wrec_sec:.1f}s)...")
            t_quiet_start = time.time()
            if not self.dry_run:
                if remaining_wrec_sec > 0.0:
                    time.sleep(remaining_wrec_sec)
            else:
                time.sleep(1)
            quiet_obs_sec = time.time() - t_quiet_start
            self.clocks["clock2_wrec_duration_sec"] = (time.time() - t_clear_epoch) if t_clear_epoch is not None else quiet_obs_sec
            self.timestamps["T_obs_end"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.timing_definitions["post_fault_workload_tail_sec"] = post_fault_workload_sec
            self.timing_definitions["post_workload_quiet_obs_sec"] = quiet_obs_sec

            # Stop telemetry poller
            self.stop_telemetry_event.set()
            if self.telemetry_thread:
                self.telemetry_thread.join(timeout=10.0)

            # 13. FINAL_HEALTH_CHECK
            self.transition_to(ExecutionState.FINAL_HEALTH_CHECK)
            log("Executing post-experiment health and dataset audit...")
            s2_history = int(query_sql("SELECT count(*) FROM benchdb.public.pgbench_history;"))
            self.history_counts["s2_final"] = s2_history
            self.history_counts["measurement_delta"] = s2_history - s1_history
            log(f"Final history count (S2): {s2_history} (Total measurement txs: {s2_history - s1_history})")
            if s2_history < s1_history:
                raise RuntimeError(f"FAIL-CLOSED: pgbench_history count decreased during measurement ({s1_history} -> {s2_history})!")
            
            acc_check = query_sql("SELECT count(*) FROM benchdb.public.pgbench_accounts;")
            if acc_check != "5000000":
                raise RuntimeError(f"Accounts corrupted! Expected 5000000, got {acc_check}")
                
            metrics = sample_crdb_metrics(self.target_info["target_pod"])
            underrep = metrics["metrics"].get(f'ranges_underreplicated{{store="{self.target_info["lease_holder_id"]}",node_id="{self.target_info["lease_holder_id"]}"}}', '0')
            if underrep != "0":
                raise RuntimeError(f"Under-replicated ranges detected post-experiment: {underrep}")

            # 14. EVIDENCE_COLLECTION
            self.transition_to(ExecutionState.EVIDENCE_COLLECTION)
            log("Retrieving diagnostic and transaction logs from client pod...")
            if not self.dry_run:
                required_pod_files = [
                    f"pgbench_{self.run_id}_stdout.txt",
                    f"pgbench_{self.run_id}_stderr.txt",
                    f"pgbench_{self.run_id}_pgid.txt",
                    f"pgbench_{self.run_id}_exit_code.txt",
                    f"pgbench_{self.run_id}_notice_count.txt",
                    f"disk_pre_{self.run_id}.txt",
                    f"disk_post_{self.run_id}.txt",
                ]
                optional_pod_files = [
                    f"pgbench_{self.run_id}_notice_samples.txt",
                ]
                
                for pf in required_pod_files:
                    local_p = os.path.join(self.output_dir, pf)
                    res = run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "cat", f"/tmp/{pf}"], check=False, timeout=30.0)
                    if res.returncode == 0:
                        with open(local_p, "w", encoding="utf-8") as f:
                            f.write(res.stdout)
                        if os.path.getsize(local_p) == 0 and pf != f"pgbench_{self.run_id}_stderr.txt":
                            log(f"[EVIDENCE WARNING] Required file {pf} retrieved but empty!")
                            self.evidence_missing.append(f"{pf} (empty)")
                    else:
                        log(f"[EVIDENCE ERROR] Failed to retrieve required artifact /tmp/{pf}: {res.stderr}")
                        self.evidence_missing.append(f"{pf} (missing)")

                exit_code_local = os.path.join(self.output_dir, f"pgbench_{self.run_id}_exit_code.txt")
                if os.path.isfile(exit_code_local):
                    with open(exit_code_local, "r", encoding="utf-8") as ecf:
                        raw_ec = ecf.read().strip()
                    self.command_audit["pgbench_exit_code"] = raw_ec
                    if not raw_ec.isdigit() or int(raw_ec) != 0:
                        self.evidence_missing.append(f"pgbench_{self.run_id}_exit_code.txt (non-zero: {raw_ec!r})")
                else:
                    self.evidence_missing.append(f"pgbench_{self.run_id}_exit_code.txt (missing)")

                for pf in optional_pod_files:
                    local_p = os.path.join(self.output_dir, pf)
                    res = run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "cat", f"/tmp/{pf}"], check=False, timeout=30.0)
                    if res.returncode == 0 and res.stdout:
                        with open(local_p, "w", encoding="utf-8") as f:
                            f.write(res.stdout)
                
                # Copy transaction log chunks
                tx_files_raw = run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "sh", "-c", f"ls /tmp/pgbench_log_{self.run_id}.* 2>/dev/null || true"], check=False, timeout=30.0).stdout
                found_tx = False
                retrieved_tx_paths: List[str] = []
                for tf in tx_files_raw.splitlines():
                    tf = tf.strip()
                    if tf:
                        local_name = os.path.basename(tf)
                        res = run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "cat", tf], check=False, timeout=30.0)
                        if res.returncode == 0:
                            content = res.stdout
                            local_path = os.path.join(self.output_dir, local_name)
                            with open(local_path, "w", encoding="utf-8") as f:
                                f.write(content)
                            if os.path.getsize(local_path) > 0:
                                found_tx = True
                                retrieved_tx_paths.append(local_path)
                            else:
                                log(f"[EVIDENCE WARNING] Transaction log {local_name} retrieved but empty (0 bytes)!")
                        else:
                            log(f"[EVIDENCE ERROR] Failed to retrieve transaction log chunk {tf}: {res.stderr}")
                if not found_tx:
                    self.evidence_missing.append("transaction_logs (missing or empty)")
                else:
                    tx_span = compute_tx_stream_span_sec(retrieved_tx_paths)
                    if tx_span is not None:
                        self.clocks["clock3_tx_stream_span_sec"] = tx_span
                    else:
                        self.timing_definitions["clock3_warning"] = "Insufficient timestamped pgbench rows for Clock 3 calculation"

                if self.evidence_missing:
                    raise RuntimeError(f"Critical evidence collection failed: {', '.join(self.evidence_missing)}")
            else:
                log("[DRY RUN] Simulating evidence retrieval and file persistence.")

            # 15. FINAL_DISPOSITION
            self.transition_to(ExecutionState.FINAL_DISPOSITION)
            self.final_disposition = "SIMULATED_SUCCESS" if self.dry_run else "EXECUTED_VALIDATED"
            log(f"Execution lifecycle reached FINAL_DISPOSITION: {self.final_disposition}")

        except BaseException as e:
            self.cleanup_in_progress = True
            self.record_error(str(e))
            self.final_disposition = "FAILED"
            log(f"[LIFECYCLE ABORT] State machine aborted with error or interruption: {type(e).__name__}: {e}")
            
            # Guaranteed Rollback Trigger for all Exceptions, Interruptions, and Signals
            if self.fault_applied and self.target_info:
                log("[CRITICAL CLEANUP] Fault was applied prior to error; executing mandatory emergency rollback...")
                try:
                    if not self.dry_run:
                        self.helper_logs_metadata = collect_helper_job_logs(
                            "app.kubernetes.io/name=g3-chaos-helper",
                            output_dir=self.output_dir,
                            prefix="04_helper_abort",
                        )
                    rb_ok = emergency_independent_rollback(self.target_info)
                    if LAST_ROLLBACK_REPORTS:
                        self.rollback_audit.append(LAST_ROLLBACK_REPORTS[-1])
                    if not rb_ok:
                        self.cleanup_error = "Emergency rollback FAILED to verify unthrottled device state"
                        log(f"[CRITICAL CLEANUP ERROR] {self.cleanup_error}")
                except Exception as rb_exc:
                    self.cleanup_error = f"Emergency rollback threw exception: {rb_exc}"
                    log(f"[CRITICAL CLEANUP ERROR] {self.cleanup_error}")
                finally:
                    self.fault_applied = False
                
            if self.remote_pgid and not self.dry_run:
                log(f"[PROCESS CLEANUP] Terminating active client process group -{self.remote_pgid}...")
                try:
                    terminate_remote_process_group(self.remote_pgid)
                except Exception as term_exc:
                    log(f"[PROCESS CLEANUP ERROR] Failed to terminate remote PGID: {term_exc}")

            # Stop telemetry poller as part of mandatory emergency cleanup
            self.stop_telemetry_event.set()
            if self.telemetry_thread and self.telemetry_thread.is_alive():
                self.telemetry_thread.join(timeout=5.0)

            # Mandatory emergency cleanup completed; clear cleanup_in_progress before re-raising
            self.cleanup_in_progress = False

            if isinstance(e, KeyboardInterrupt):
                log("[LIFECYCLE INTERRUPTED] KeyboardInterrupt captured and handled. Re-raising after cleanup.")
                raise e
            if isinstance(e, SignalInterruptionError):
                log(f"[LIFECYCLE INTERRUPTED] SignalInterruptionError ({e.signame}) captured and handled. Re-raising after cleanup.")
                raise e
                
        finally:
            self.cleanup_in_progress = False

            # Restore prior signal handlers
            if in_main_thread:
                if prior_sigint is not None:
                    try:
                        signal.signal(signal.SIGINT, prior_sigint)
                    except (ValueError, OSError):
                        pass
                if prior_sigterm is not None and hasattr(signal, "SIGTERM"):
                    try:
                        signal.signal(signal.SIGTERM, prior_sigterm)
                    except (ValueError, OSError):
                        pass

            self.stop_telemetry_event.set()
            if self.telemetry_thread and self.telemetry_thread.is_alive():
                self.telemetry_thread.join(timeout=5.0)
            record = {
                "run_id": self.run_id,
                "level": self.level,
                "duration_sec": self.duration_sec,
                "dry_run": self.dry_run,
                "authorization": self.authorization_metadata,
                "final_disposition": self.final_disposition,
                "error_occurred": self.error_occurred,
                "cleanup_error": self.cleanup_error,
                "signal_received": self.signal_received,
                "secondary_signals": self.secondary_signals,
                "evidence_missing": self.evidence_missing,
                "target_info": self.target_info,
                "history_counts": self.history_counts,
                "helper_logs_metadata": self.helper_logs_metadata,
                "rollback_audit": self.rollback_audit,
                "command_audit": self.command_audit,
                "timing_definitions": self.timing_definitions,
                "clocks": self.clocks,
                "timestamps": self.timestamps,
                "state_history": self.state_history
            }
            record_path = os.path.join(self.output_dir, "00_execution_record.json")
            with open(record_path, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2)
            build_manifest(self.output_dir)
            if not verify_manifest(self.output_dir):
                self.final_disposition = "FAILED"
                record["final_disposition"] = "FAILED"
                record["error_occurred"] = True
                record["manifest_verification"] = "FAILED"
                with open(record_path, "w", encoding="utf-8") as f:
                    json.dump(record, f, indent=2)
            
        return record

def main():
    parser = argparse.ArgumentParser(description="CockroachDB G3 Disk I/O Throttling Pilot Runner & Coordinator")
    parser.add_argument("--run-id", required=True, help="Pilot Run ID (e.g., crdb-g3l1-pilot-p01)")
    parser.add_argument("--level", required=True, choices=["L1", "L2", "L3"], help="Severity level")
    parser.add_argument("--duration", type=int, default=180, help="Fault duration in seconds (default: 180)")
    parser.add_argument("--dry-run", action="store_true", help="Execute simulated coordinator dry run without live writes")
    parser.add_argument("--preflight-only", action="store_true", help="Run preflight checks only and exit")
    parser.add_argument("--target-node", help="Optional override for target CockroachDB pod")
    parser.add_argument("--auth-token", dest="auth_token", help="Path to signed single-use operator authorization JSON token")
    parser.add_argument("--public-key", dest="public_key", help="Path to trusted Ed25519 public key file (defaults to security/keys/g3_operator_ed25519_pub.key)")
    parser.add_argument("--output-dir", dest="output_dir", help="Optional override path for evidence output directory")
    args = parser.parse_args()

    log(f"=== CockroachDB G3 Pilot Coordinator: {args.run_id} ===")
    log(f"Configuration: Level={args.level} ({SEVERITY_LIMITS[args.level]['desc']}), Fault Duration={args.duration}s, DryRun={args.dry_run}")

    coordinator = G3PilotExecutionCoordinator(
        run_id=args.run_id,
        level=args.level,
        duration_sec=args.duration,
        dry_run=args.dry_run,
        target_override=args.target_node,
        output_dir=args.output_dir,
    )

    if args.preflight_only:
        log("Preflight-only requested. Executing comprehensive read-only preflight audit...")
        try:
            audit = run_preflight_audit(dry_run=args.dry_run)
            target = resolve_target_leaseholder(target_override=args.target_node)
            clean_ok, clean_msg = verify_io_max_restored(
                target.get("initial_io_max", ""),
                int(target["dev_major"]),
                int(target["dev_minor"]),
                "",
            )
            if not clean_ok:
                raise RuntimeError(f"Preflight FAILED: Residual or malformed io.max detected on target: {clean_msg}")
        except Exception as e:
            log(f"[PREFLIGHT ERROR] {e}")
            sys.exit(1)
        log(
            f"Preflight summary: aws_account={audit.get('aws_account')}, "
            f"nodes={len(audit.get('ready_nodes', []))}, pods={len(audit.get('crdb_pods', []))}, "
            f"pvcs={len(audit.get('bound_pvcs', []))}, accounts={audit.get('dataset_rows')}, "
            f"history={audit.get('s0_preflight_history')}, underrep={audit.get('underreplicated_ranges')}, "
            f"tmp_avail_mb={audit.get('client_tmp_avail_mb'):.1f}, "
            f"target={target.get('target_pod')}@{target.get('target_node')} ({target.get('dev_major')}:{target.get('dev_minor')})."
        )
        log("Preflight note: read-only preflight does NOT exercise live privileged host-cgroup write permission.")
        log("Preflight-only completed successfully.")
        sys.exit(0)

    if args.dry_run:
        log("Executing coordinator in DRY RUN mode (State transition validation)...")
        record = coordinator.execute_lifecycle()
        log(f"Dry run complete. Record saved at {coordinator.output_dir}")
        if isinstance(record, dict) and record.get("final_disposition") not in ("EXECUTED_VALIDATED", "SIMULATED_SUCCESS"):
            sys.exit(1)
        return

    # Real Execution Path: Requires valid single-use Ed25519 operator authorization
    if not args.auth_token:
        log("FAIL-CLOSED: Real execution requires explicit operator authorization via --auth-token <path>.")
        sys.exit(1)

    try:
        auth_data = verify_and_consume_authorization(
            auth_file_path=args.auth_token,
            run_id=args.run_id,
            level=args.level,
            duration_sec=args.duration,
            public_key_path=args.public_key
        )
    except Exception as e:
        log(f"[AUTH ERROR] Authorization verification failed: {e}")
        sys.exit(1)

    coordinator.authorization_metadata = auth_data
    log(f"OPERATOR AUTHORIZATION VERIFIED & CONSUMED: Token {auth_data['authorization_id']} bound to {args.run_id}.")
    record = coordinator.execute_lifecycle()
    log(f"Execution complete. Record saved at {coordinator.output_dir}")
    if isinstance(record, dict) and "final_disposition" in record and record["final_disposition"] not in ("EXECUTED_VALIDATED", "SIMULATED_SUCCESS"):
        log(f"[EXIT FAIL-CLOSED] Coordinator ended with non-passing disposition: {record['final_disposition']}")
        sys.exit(1)

if __name__ == "__main__":
    main()
