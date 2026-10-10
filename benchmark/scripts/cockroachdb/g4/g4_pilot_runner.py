#!/usr/bin/env python3
"""
g4_pilot_runner.py - Orchestrator for CockroachDB G4 Controlled CPU Starvation Pilots.
Target Mechanism: Chaos Mesh StressChaos CRD targeting container 'db' on pod 'cockroachdb-1'.
Adheres strictly to the four-clock timing model, Option B dataset safety, fail-closed rollback,
idempotent cleanup traps, explicit 15-state execution coordinator, and cryptographic operator authorization.
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

PROTOCOL_VERSION = "G4-01"
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "g4_runner_config.json")
DEFAULT_PUBLIC_KEY_PATH = r"C:\OperatorKeys\g3\g3_operator_ed25519_pub.key"
FALLBACK_PUBLIC_KEY_PATH = "security/keys/g3_operator_ed25519_pub.key"
TRUSTED_OPERATOR_PUBKEY_SHA256 = "78466ea05398c7b3a26440ba42230989ba6a092f5942e5d5ec152a95c434f621"

PSQL_CONN = (
    "sslmode=verify-full "
    "sslrootcert=/cockroach-certs/ca.crt "
    "sslcert=/cockroach-certs/client.root.crt "
    "sslkey=/cockroach-certs/client.root.key "
    "host=cockroachdb-public port=26257 user=root dbname=benchdb"
)

LEVEL_SPECS = {
    "L1": {
        "load": 80,
        "workers": 1,
        "manifest_path": "kubernetes/chaos/g4/g4-cpu-stress-l1.yaml",
        "manifest_sha256": "c6254254a7267aa923654177a5a9c0b3b5b7ecaf954b6db9cfe7fb8949cbd10e",
        "stresschaos_name": "g4-cpu-starvation-l1"
    },
    "L2": {
        "load": 90,
        "workers": 1,
        "manifest_path": "kubernetes/chaos/g4/g4-cpu-stress-l2.yaml",
        "manifest_sha256": "8947ebee544d8a445ad0a13278c34a70d1061a73bdc23a64b80e0931a35f8966",
        "stresschaos_name": "g4-cpu-starvation-l2"
    },
    "L3": {
        "load": 95,
        "workers": 1,
        "manifest_path": "kubernetes/chaos/g4/g4-cpu-stress-l3.yaml",
        "manifest_sha256": "61db405b4dca887da7084b2bc1526cde2726f993292f2ae928fdcaa93b16d5da",
        "stresschaos_name": "g4-cpu-starvation-l3"
    }
}

MAX_TELEMETRY_GAP_SEC = 30.0

class TelemetryContinuityError(RuntimeError):
    """Raised when telemetry collection exhibits a gap exceeding MAX_TELEMETRY_GAP_SEC."""
    pass

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

def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def _utc_now() -> datetime.datetime:
    """Actual UTC wall clock. Can be patched in unit tests."""
    return datetime.datetime.now(datetime.timezone.utc)

def canonicalize_payload(payload: Dict[str, Any]) -> bytes:
    """Produces deterministic, canonical UTF-8 JSON bytes (RFC 8785 style)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def parse_cgroup_cpu_stat(raw_text: str) -> Dict[str, int]:
    """Parse Linux cgroup v2 /sys/fs/cgroup/cpu.stat into key-value integers."""
    stats = {}
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) == 2 and parts[1].isdigit():
            stats[parts[0]] = int(parts[1])
    return stats

def query_live_processes_in_pgid(client_namespace: str, client_pod: str, pgid: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Query remote processes in the benchmark pod matching a specific process group (PGID).
    Returns (live_procs, zombie_procs).
    """
    cmd = ["kubectl", "exec", "-n", client_namespace, client_pod, "--", "ps", "-eo", "pid,pgid,stat,comm"]
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
            continue
        try:
            p_pid = int(parts[0])
            p_pgid = int(parts[1])
        except ValueError:
            continue

        p_stat = parts[2]
        comm = parts[3]

        if p_pgid == pgid:
            entry = {"pid": p_pid, "pgid": p_pgid, "stat": p_stat, "comm": comm}
            if p_stat.startswith("Z"):
                zombie_procs.append(entry)
            else:
                live_procs.append(entry)

    return live_procs, zombie_procs

def terminate_remote_process_group(
    client_namespace: str,
    client_pod: str,
    pgid: int,
    timeout_grace_sec: float = 5.0
) -> Dict[str, Any]:
    """
    Terminates remote process group (-pgid) via SIGTERM, then escalates to SIGKILL if necessary.
    Verifies that no live processes survive.
    """
    if pgid <= 0:
        raise ValueError(f"Invalid PGID {pgid}; must be positive integer.")

    log(f"[PROCESS LIFECYCLE] Initiating termination of remote process group -{pgid} in pod {client_pod}...")
    run_cmd(["kubectl", "exec", "-n", client_namespace, client_pod, "--", "/usr/bin/kill", "-TERM", f"-{pgid}"], check=False, timeout=10.0)

    start_t = time.time()
    live_procs = []
    zombies = []

    while time.time() - start_t < timeout_grace_sec:
        time.sleep(0.5)
        try:
            live_procs, zombies = query_live_processes_in_pgid(client_namespace, client_pod, pgid)
            if not live_procs:
                log(f"[PROCESS LIFECYCLE] Remote process group -{pgid} terminated gracefully via SIGTERM (Live: 0, Zombies: {len(zombies)}).")
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

    log(f"[PROCESS LIFECYCLE] Remote process group -{pgid} has {len(live_procs)} live processes remaining after {timeout_grace_sec}s grace. Escalating to SIGKILL...")
    run_cmd(["kubectl", "exec", "-n", client_namespace, client_pod, "--", "/usr/bin/kill", "-KILL", f"-{pgid}"], check=False, timeout=10.0)
    time.sleep(1.0)

    try:
        live_post, zombies_post = query_live_processes_in_pgid(client_namespace, client_pod, pgid)
        if not live_post:
            log(f"[PROCESS LIFECYCLE] Remote process group -{pgid} confirmed DEAD following SIGKILL (Live: 0, Zombies: {len(zombies_post)}).")
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
        log(f"[PROCESS LIFECYCLE ERROR] Failed to query post-SIGKILL process status: {e}")
        return {
            "verified_dead": False,
            "escalated_to_sigkill": True,
            "surviving_live_count": -1,
            "zombie_count": -1,
            "hard_failure": True,
            "error": str(e)
        }

def parse_stresschaos_manifest(manifest_path: str) -> Dict[str, Any]:
    """
    Parse a Chaos Mesh StressChaos YAML manifest to extract name, load, workers, pod selector, container.
    Simple lightweight parser to avoid external PyYAML dependencies while strictly validating fields.
    """
    if not os.path.isfile(manifest_path):
        raise FileNotFoundError(f"StressChaos manifest not found: {manifest_path}")

    with open(manifest_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    info: Dict[str, Any] = {
        "apiVersion": "",
        "kind": "",
        "name": "",
        "namespace": "",
        "target_pod": "",
        "target_container": "",
        "workers": None,
        "load": None,
        "duration": ""
    }

    in_metadata = False
    in_selector = False
    in_stressors = False
    in_cpu = False
    in_pods = False

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())

        if indent == 0:
            in_metadata = stripped.startswith("metadata:")
            in_selector = False
            in_stressors = False
            in_cpu = False
            in_pods = False
            if stripped.startswith("apiVersion:"):
                info["apiVersion"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("kind:"):
                info["kind"] = stripped.split(":", 1)[1].strip()
            continue

        if in_metadata:
            if stripped.startswith("name:"):
                info["name"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("namespace:"):
                info["namespace"] = stripped.split(":", 1)[1].strip()

        if stripped.startswith("selector:"):
            in_selector = True
            in_stressors = False
            continue

        if in_selector and stripped.startswith("pods:"):
            in_pods = True
            continue

        if in_selector and stripped.startswith("- cockroachdb-"):
            info["target_pod"] = stripped.split("- ", 1)[1].strip()

        if stripped.startswith("containerNames:"):
            in_selector = False
            continue

        if stripped.startswith("- db") and not info["target_container"]:
            info["target_container"] = "db"

        if stripped.startswith("stressors:"):
            in_stressors = True
            in_selector = False
            continue

        if in_stressors and stripped.startswith("cpu:"):
            in_cpu = True
            continue

        if in_cpu:
            if stripped.startswith("workers:"):
                info["workers"] = int(stripped.split(":", 1)[1].strip())
            elif stripped.startswith("load:"):
                info["load"] = int(stripped.split(":", 1)[1].strip())

        if stripped.startswith("duration:"):
            info["duration"] = stripped.split(":", 1)[1].strip().strip('"').strip("'")

    if info["kind"] != "StressChaos":
        raise ValueError(f"Invalid manifest kind: {info['kind']}")
    return info

def verify_and_consume_authorization(
    auth_file_path: str,
    run_id: str,
    level: str,
    duration_sec: int,
    manifest_sha256: str,
    target_pod_uid: str,
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
    5. Manifest SHA-256 and target pod UID binding.
    6. Protocol version binding.
    7. UTC timestamp boundaries (not_before <= now <= expires_at).
    8. Pinned public-key fingerprint verification and Ed25519 digital signature.
    9. Post-verification content integrity re-check (TOCTOU mitigation).
    10. Atomic single-use exclusive consumption record (<auth_file_path>.consumed).
    """
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("FAIL-CLOSED: 'cryptography' library is not available for Ed25519 signature verification.")

    if not auth_file_path:
        raise RuntimeError("FAIL-CLOSED: Authorization file path cannot be empty.")

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

    required_fields = [
        "authorization_id", "authorized_run_id", "authorized_level", "parameters",
        "runner_sha256", "manifest_sha256", "target_pod_uid", "protocol_version",
        "operator_identity", "nonce", "issued_at_utc", "not_before_utc", "expires_at_utc"
    ]
    for rf in required_fields:
        if rf not in payload:
            raise RuntimeError(f"FAIL-CLOSED: Authorization payload missing required field '{rf}'")

    if payload["authorized_run_id"] != run_id:
        raise RuntimeError(f"FAIL-CLOSED: Authorization token bound to run_id '{payload['authorized_run_id']}', but coordinator requested '{run_id}'")

    if payload["authorized_level"] != level:
        raise RuntimeError(f"FAIL-CLOSED: Authorization token bound to level '{payload['authorized_level']}', but coordinator requested '{level}'")

    expected_level = LEVEL_SPECS.get(level)
    if not expected_level:
        raise RuntimeError(f"FAIL-CLOSED: Unknown severity level '{level}'")

    token_params = payload["parameters"]
    if not isinstance(token_params, dict):
        raise RuntimeError("FAIL-CLOSED: Authorization token parameters must be a dictionary.")

    if token_params.get("load") != expected_level["load"]:
        raise RuntimeError(f"FAIL-CLOSED: Token load ({token_params.get('load')}) does not match level specification ({expected_level['load']})")

    if token_params.get("workers") != expected_level["workers"]:
        raise RuntimeError(f"FAIL-CLOSED: Token workers ({token_params.get('workers')}) does not match level specification ({expected_level['workers']})")

    max_dur = token_params.get("max_fault_duration_sec", token_params.get("fault_duration_sec"))
    if not isinstance(max_dur, (int, float)) or duration_sec > max_dur:
        raise RuntimeError(f"FAIL-CLOSED: Requested fault duration {duration_sec}s exceeds authorized maximum {max_dur}s")

    if payload["protocol_version"] != expected_protocol:
        raise RuntimeError(f"FAIL-CLOSED: Authorization bound to protocol '{payload['protocol_version']}', expected '{expected_protocol}'")

    target_runner = runner_path if runner_path else os.path.abspath(__file__)
    if not os.path.exists(target_runner):
        raise RuntimeError(f"FAIL-CLOSED: Runner source file not found at {target_runner}")
    current_runner_hash = compute_sha256(target_runner)
    if payload["runner_sha256"] != current_runner_hash:
        raise RuntimeError(f"FAIL-CLOSED: Runner hash mismatch! Token expects {payload['runner_sha256']}, actual runner hash is {current_runner_hash}")

    if payload["manifest_sha256"] != manifest_sha256:
        raise RuntimeError(f"FAIL-CLOSED: Manifest hash mismatch! Token expects {payload['manifest_sha256']}, actual manifest hash is {manifest_sha256}")

    if payload["target_pod_uid"] != target_pod_uid:
        raise RuntimeError(f"FAIL-CLOSED: Target pod UID mismatch! Token expects {payload['target_pod_uid']}, actual pod UID is {target_pod_uid}")

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

    pk_path = public_key_path
    if not pk_path:
        if os.path.isfile(DEFAULT_PUBLIC_KEY_PATH):
            pk_path = DEFAULT_PUBLIC_KEY_PATH
        elif os.path.isfile(FALLBACK_PUBLIC_KEY_PATH):
            pk_path = FALLBACK_PUBLIC_KEY_PATH
        else:
            pk_path = DEFAULT_PUBLIC_KEY_PATH

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

    try:
        with open(abs_auth_path, "rb") as check_f:
            post_bytes = check_f.read()
        if hashlib.sha256(post_bytes).hexdigest() != token_sha256:
            raise RuntimeError("FAIL-CLOSED: TOCTOU violation: Token file modified during verification!")
    except Exception as e:
        raise RuntimeError(f"FAIL-CLOSED: Failed to re-verify token content integrity: {e}")

    consumption_data = {
        "authorization_id": payload["authorization_id"],
        "token_sha256": token_sha256,
        "consumed_at_utc": now_utc.isoformat(),
        "run_id": run_id,
        "runner_sha256": current_runner_hash,
        "manifest_sha256": manifest_sha256,
        "target_pod_uid": target_pod_uid,
        "public_key_fingerprint": actual_fingerprint,
        "pid": os.getpid()
    }

    try:
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
        "manifest_sha256": payload["manifest_sha256"],
        "target_pod_uid": payload["target_pod_uid"],
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

class G4PilotExecutionCoordinator:
    """
    Coordinator executing the 15-state sequence for CockroachDB G4 CPU starvation experiments.
    """
    def __init__(
        self,
        run_id: str,
        level: str,
        output_dir: str,
        auth_file: Optional[str] = None,
        dry_run: bool = False,
        config_path: Optional[str] = None,
        public_key_path: Optional[str] = None,
        warmup_sec: Optional[int] = None,
        baseline_sec: Optional[int] = None,
        fault_sec: Optional[int] = None,
        recovery_sec: Optional[int] = None,
        telemetry_interval: Optional[float] = None
    ):
        self.run_id = run_id
        self.level = level
        self.output_dir = os.path.abspath(output_dir)
        self.auth_file = auth_file
        self.dry_run = dry_run
        self.config_path = config_path or DEFAULT_CONFIG_PATH
        self.public_key_path = public_key_path or DEFAULT_PUBLIC_KEY_PATH

        self.current_state = ExecutionState.PREFLIGHT
        self.state_history: List[Dict[str, Any]] = []

        # Load configuration
        self.config = self._load_config()
        self.target_spec = self.config.get("target", {})
        self.chaos_namespace = self.config.get("chaos_namespace", "chaos-mesh")
        self.client_pod = self.config.get("client_pod", "crdb-benchmark-client-hardened")
        self.client_namespace = self.config.get("client_namespace", "cockroachdb")
        if not public_key_path and self.config.get("trusted_public_key_path"):
            cfg_pk = self.config.get("trusted_public_key_path")
            if os.path.isfile(cfg_pk):
                self.public_key_path = cfg_pk

        # Level configuration
        level_cfg = self.config.get("levels", {}).get(level) or LEVEL_SPECS.get(level)
        if not level_cfg:
            raise ValueError(f"Unknown level '{level}'")
        self.level_cfg = level_cfg
        self.manifest_path = level_cfg["manifest_path"]
        self.expected_manifest_sha256 = level_cfg["manifest_sha256"]
        self.stresschaos_name = level_cfg["stresschaos_name"]

        # Timings
        timings = self.config.get("timing_defaults", {})
        self.warmup_sec = warmup_sec if warmup_sec is not None else timings.get("warmup_sec", 120)
        self.baseline_sec = baseline_sec if baseline_sec is not None else timings.get("baseline_sec", 180)
        self.fault_sec = fault_sec if fault_sec is not None else timings.get("fault_duration_sec", 180)
        self.recovery_sec = recovery_sec if recovery_sec is not None else timings.get("recovery_observation_sec", 300)
        self.telemetry_interval = telemetry_interval if telemetry_interval is not None else timings.get("telemetry_interval_sec", 5.0)
        self.max_telemetry_gap_sec = timings.get("max_telemetry_gap_sec", MAX_TELEMETRY_GAP_SEC)

        # Execution tracking
        self.target_pod_uid: Optional[str] = None
        self.target_node: Optional[str] = None
        self.auth_record: Optional[Dict[str, Any]] = None
        self.preflight_report: Dict[str, Any] = {}
        self.telemetry_data: List[Dict[str, Any]] = []
        self.telemetry_thread: Optional[threading.Thread] = None
        self.stop_telemetry_event = threading.Event()
        self.telemetry_status: Dict[str, Any] = {
            "thread_alive": False,
            "started_at_epoch": 0.0,
            "last_sample_epoch": 0.0,
            "sample_count": 0,
            "max_observed_gap_sec": 0.0,
            "gap_exceeded": False,
            "error": None,
            "missed_samples": 0
        }
        self.workload_process: Optional[subprocess.Popen] = None
        self.workload_stdout_file: Optional[str] = None
        self.workload_fd = None
        self.warmup_fd = None
        self.remote_pgid: Optional[int] = None
        self.workload_phase: Optional[str] = None
        self.remote_workload_dir: Optional[str] = None
        self.workload_start_time: float = 0.0
        self.expected_workload_duration: float = 0.0
        self.fault_injected = False
        self.disposition = "PENDING"
        self.failure_reason: Optional[str] = None
        self.rollback_reports: List[Dict[str, Any]] = []

    def _load_config(self) -> Dict[str, Any]:
        if os.path.exists(self.config_path):
            with open(self.config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {
            "protocol": PROTOCOL_VERSION,
            "chaos_namespace": "chaos-mesh",
            "target": {
                "namespace": "cockroachdb",
                "pod_name": "cockroachdb-1",
                "pod_uid": "1a98abd7-7ac3-4bd6-96ee-1dcfd67f0f67",
                "node_name": "ip-10-0-1-160.ec2.internal",
                "container_name": "db"
            },
            "client_pod": "crdb-benchmark-client-hardened",
            "client_namespace": "cockroachdb",
            "timing_defaults": {
                "warmup_sec": 120,
                "baseline_sec": 180,
                "fault_duration_sec": 180,
                "recovery_observation_sec": 300,
                "total_measurement_window_sec": 660,
                "telemetry_interval_sec": 5.0,
                "max_telemetry_gap_sec": 30.0
            },
            "levels": LEVEL_SPECS
        }

    def _transition(self, new_state: ExecutionState) -> None:
        now_str = _utc_now().isoformat()
        log(f"[STATE TRANSITION] {self.current_state.value} -> {new_state.value}")
        self.state_history.append({
            "from": self.current_state.value,
            "to": new_state.value,
            "timestamp": now_str
        })
        self.current_state = new_state

    def _check_telemetry_health(self, window_name: str = "current_window") -> None:
        """Fail-closed check ensuring no telemetry exception or continuity gap occurred."""
        if self.dry_run:
            return

        now = time.time()
        status = self.telemetry_status

        if not status.get("thread_alive"):
            err_msg = status.get("error") or "Telemetry thread is not running"
            raise TelemetryContinuityError(f"Telemetry continuity check failed in {window_name}: poller thread is not running (error: {err_msg})")

        if status.get("gap_exceeded"):
            raise TelemetryContinuityError(f"Telemetry continuity check failed in {window_name}: {status.get('error')}")

        if status.get("error"):
            raise TelemetryContinuityError(f"Telemetry continuity check failed in {window_name}: {status.get('error')}")

        last_sample = status.get("last_sample_epoch", 0.0)
        if last_sample > 0.0:
            gap_to_now = now - last_sample
            if gap_to_now > self.max_telemetry_gap_sec:
                err_text = f"Telemetry continuity gap {gap_to_now:.2f}s exceeded limit {self.max_telemetry_gap_sec}s"
                status["gap_exceeded"] = True
                status["error"] = err_text
                raise TelemetryContinuityError(f"Telemetry continuity check failed in {window_name}: {err_text}")

    def execute(self) -> Dict[str, Any]:
        """Runs the complete 15-state lifecycle."""
        try:
            self._ensure_output_dir()
            self._state_preflight()
            self._state_target_verification()

            if self.dry_run:
                log("[DRY-RUN] Preflight and Target Verification complete. Exiting read-only mode successfully.")
                self.disposition = "SIMULATED_SUCCESS"
                self._state_final_disposition()
                return self._build_result()

            self._state_workload_start()
            self._state_warmup()
            self._check_telemetry_health("warmup_end")
            self._state_baseline_measurement()
            self._check_telemetry_health("baseline_measurement")
            self._state_fault_application()
            self._state_fault_verification()
            self._check_telemetry_health("fault_verification")
            self._state_fault_measurement()
            self._check_telemetry_health("fault_measurement")
            self._state_fault_removal()
            self._state_restoration_verification()
            self._check_telemetry_health("restoration_verification")
            self._state_post_fault_measurement()
            self._state_wrec_observation()
            self._check_telemetry_health("wrec_observation")
            self._stop_telemetry()
            self._state_final_health_check()
            self._state_evidence_collection()
            self.disposition = "EXECUTED_VALIDATED"
            self._state_final_disposition()
            return self._build_result()

        except Exception as e:
            self.failure_reason = str(e)
            log(f"[EXECUTION FAILURE] Exception during state {self.current_state.value}: {e}")
            self.disposition = "FAILED"
            self._emergency_rollback()
            self._state_final_disposition()
            raise

    def _ensure_output_dir(self) -> None:
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)
        else:
            files = os.listdir(self.output_dir)
            if files and not self.dry_run:
                raise RuntimeError(f"FAIL-CLOSED: Output directory {self.output_dir} is not empty: {files}")

    def _state_preflight(self) -> None:
        """State 1: PREFLIGHT"""
        self._transition(ExecutionState.PREFLIGHT)
        log(f"Starting PREFLIGHT for run '{self.run_id}', level '{self.level}'")

        # 1. Verify manifest existence and SHA-256 hash
        if not os.path.isfile(self.manifest_path):
            raise RuntimeError(f"StressChaos manifest not found at {self.manifest_path}")
        actual_manifest_sha = compute_sha256(self.manifest_path)
        if actual_manifest_sha.lower() != self.expected_manifest_sha256.lower():
            raise RuntimeError(
                f"Manifest SHA-256 mismatch for {self.manifest_path}: "
                f"expected {self.expected_manifest_sha256}, got {actual_manifest_sha}"
            )

        manifest_info = parse_stresschaos_manifest(self.manifest_path)
        if manifest_info["name"] != self.stresschaos_name:
            raise RuntimeError(f"Manifest metadata.name mismatch: expected {self.stresschaos_name}, got {manifest_info['name']}")
        if manifest_info["load"] != self.level_cfg["load"]:
            raise RuntimeError(f"Manifest CPU load mismatch: expected {self.level_cfg['load']}, got {manifest_info['load']}")
        if manifest_info["workers"] != self.level_cfg["workers"]:
            raise RuntimeError(f"Manifest workers mismatch: expected {self.level_cfg['workers']}, got {manifest_info['workers']}")

        self.preflight_report["manifest"] = {
            "path": self.manifest_path,
            "sha256": actual_manifest_sha,
            "parsed": manifest_info
        }

        # 2. Check cluster readiness (read-only)
        self._check_cluster_readiness()

    def _check_cluster_readiness(self) -> None:
        """Read-only check of Chaos Mesh, CockroachDB, and Benchmark client."""
        if self.dry_run:
            log("[PREFLIGHT] Dry-run read-only check mode active.")

        # Check CRD
        res = run_cmd(["kubectl", "get", "crd", "stresschaos.chaos-mesh.org"], check=False)
        if res.returncode != 0:
            raise RuntimeError("StressChaos CRD stresschaos.chaos-mesh.org is not installed on the cluster")

        # Check Chaos Daemon on target node
        res = run_cmd(["kubectl", "get", "pods", "-n", self.chaos_namespace, "-l", "app.kubernetes.io/component=chaos-daemon", "-o", "json"], check=False)
        if res.returncode != 0:
            raise RuntimeError(f"Failed to query chaos-daemon pods in namespace {self.chaos_namespace}: {res.stderr}")
        daemons = json.loads(res.stdout).get("items", [])
        if not daemons:
            raise RuntimeError(f"No chaos-daemon pods found running in namespace {self.chaos_namespace}")

        # Check existing StressChaos resources in chaos namespace
        res = run_cmd(["kubectl", "get", "stresschaos", "-n", self.chaos_namespace, "-o", "json"], check=False)
        if res.returncode == 0:
            existing_chaos = json.loads(res.stdout).get("items", [])
            if existing_chaos:
                names = [item["metadata"]["name"] for item in existing_chaos]
                raise RuntimeError(f"FAIL-CLOSED: Existing StressChaos resources detected in {self.chaos_namespace}: {names}")

        self.preflight_report["cluster_status"] = "READY"

    def _state_target_verification(self) -> None:
        """State 2: TARGET_VERIFICATION"""
        self._transition(ExecutionState.TARGET_VERIFICATION)
        target_pod = self.target_spec.get("pod_name", "cockroachdb-1")
        target_ns = self.target_spec.get("namespace", "cockroachdb")

        # Query live pod
        res = run_cmd(["kubectl", "get", "pod", target_pod, "-n", target_ns, "-o", "json"], check=True)
        pod_data = json.loads(res.stdout)

        self.target_pod_uid = pod_data["metadata"]["uid"]
        self.target_node = pod_data["spec"]["nodeName"]
        expected_uid = self.target_spec.get("pod_uid")
        expected_node = self.target_spec.get("node_name")

        if expected_uid and self.target_pod_uid != expected_uid:
            raise RuntimeError(f"Target pod UID mismatch: expected {expected_uid}, got {self.target_pod_uid}")
        if expected_node and self.target_node != expected_node:
            raise RuntimeError(f"Target node mismatch: expected {expected_node}, got {self.target_node}")

        phase = pod_data.get("status", {}).get("phase")
        if phase != "Running":
            raise RuntimeError(f"Target pod {target_pod} is not Running (phase: {phase})")

        container_names = [c["name"] for c in pod_data["spec"]["containers"]]
        if "db" not in container_names:
            raise RuntimeError(f"Target container 'db' not found in pod {target_pod}: {container_names}")

        log(f"[TARGET VERIFIED] Pod: {target_pod}, UID: {self.target_pod_uid}, Node: {self.target_node}")

        # Validate authorization token if not in dry-run
        if not self.dry_run:
            if not self.auth_file:
                raise RuntimeError("FAIL-CLOSED: Execution requires --auth-file pointing to signed operator token")
            self.auth_record = verify_and_consume_authorization(
                auth_file_path=self.auth_file,
                run_id=self.run_id,
                level=self.level,
                duration_sec=self.fault_sec,
                manifest_sha256=self.expected_manifest_sha256,
                target_pod_uid=self.target_pod_uid,
                runner_path=os.path.abspath(__file__),
                public_key_path=self.public_key_path,
                expected_protocol=PROTOCOL_VERSION
            )

    def _state_workload_start(self) -> None:
        """State 3: WORKLOAD_START"""
        self._transition(ExecutionState.WORKLOAD_START)
        log("Launching background telemetry and standalone unlogged pgbench warm-up workload")
        self._start_telemetry()

        # Phase 1: Standalone Warmup (120s) with -n (--no-vacuum)
        self.workload_phase = "warmup"
        self.warmup_stdout_file = os.path.join(self.output_dir, "04_warmup_stdout.txt")
        self.remote_workload_dir = f"/tmp/g4_{self.run_id}_warmup"
        self.expected_workload_duration = float(self.warmup_sec)
        self.workload_start_time = time.time()

        if self.dry_run:
            log("[DRY-RUN] Simulating remote warmup launch.")
            return

        # Prepare remote workspace directory and launch detached background process
        # The launch command creates the remote directory, spawns pgbench detached via setsid in subshell,
        # logs stdout/stderr locally into container directory, records exit code on completion,
        # captures PGID, and exits immediately.
        # This prevents long-lived streaming connections from breaking if WAN/TCP drops.
        launch_script = (
            f"mkdir -p {self.remote_workload_dir} && "
            f"cd {self.remote_workload_dir} && "
            f"setsid sh -c '"
            f"pgbench -h cockroachdb-public -p 26257 -U root -n -c 20 -j 4 -T {self.warmup_sec} "
            f"--max-tries=1 -M simple benchdb > stdout.log 2> stderr.log; "
            f"echo $? > exit_code.txt' >/dev/null 2>&1 & "
            f"echo $! > pgid.txt && "
            f"cat pgid.txt"
        )
        launch_cmd = [
            "kubectl", "exec", "-n", self.client_namespace, self.client_pod, "--",
            "sh", "-c", launch_script
        ]

        log(f"Launching detached remote warmup workload for {self.warmup_sec}s in {self.remote_workload_dir}")
        launch_res = run_cmd(launch_cmd, check=False, timeout=15.0)
        if launch_res.returncode != 0:
            raise RuntimeError(f"FAIL-CLOSED: Failed to launch detached remote warmup workload: {launch_res.stderr}")

        pgid_str = launch_res.stdout.strip()
        if pgid_str.isdigit():
            self.remote_pgid = int(pgid_str)
            log(f"Warmup remote process group captured: PGID {self.remote_pgid}")
        else:
            # Resilient fallback poll for pgid.txt
            for _ in range(10):
                time.sleep(1.0)
                chk = run_cmd([
                    "kubectl", "exec", "-n", self.client_namespace, self.client_pod, "--",
                    "cat", f"{self.remote_workload_dir}/pgid.txt"
                ], check=False, timeout=5.0)
                if chk.returncode == 0 and chk.stdout.strip().isdigit():
                    self.remote_pgid = int(chk.stdout.strip())
                    log(f"Warmup remote process group captured via poll: PGID {self.remote_pgid}")
                    break

        if not self.remote_pgid:
            raise RuntimeError(f"FAIL-CLOSED: Failed to capture remote PGID for warmup workload in {self.remote_workload_dir}")

    def _state_warmup(self) -> None:
        """State 4: WARMUP"""
        self._transition(ExecutionState.WARMUP)
        log(f"Warmup state: awaiting completion of active {self.warmup_sec}s warm-up period")

        if not self.dry_run:
            warmup_rc = self._poll_and_wait_remote_workload(
                phase_name="warmup",
                duration_sec=self.warmup_sec,
                output_local_file=self.warmup_stdout_file
            )
            warmup_elapsed = time.time() - self.workload_start_time
            log(f"Standalone warm-up workload completed in {warmup_elapsed:.2f}s with returncode {warmup_rc}")

            if warmup_rc != 0:
                raise RuntimeError(f"FAIL-CLOSED: Warmup pgbench process failed with exit code {warmup_rc}")

        self.remote_pgid = None

        # Phase 2: Continuous Measurement Stream (baseline + fault + recovery = 660s)
        self.workload_phase = "measurement"
        total_measurement_time = self.baseline_sec + self.fault_sec + self.recovery_sec
        self.expected_workload_duration = float(total_measurement_time)
        self.workload_stdout_file = os.path.join(self.output_dir, "05_measurement_wrapper_stdout.txt")
        self.remote_workload_dir = f"/tmp/g4_{self.run_id}_measurement"
        self.workload_start_time = time.time()

        if self.dry_run:
            log("[DRY-RUN] Simulating remote measurement launch.")
            return

        meas_launch_script = (
            f"mkdir -p {self.remote_workload_dir} && "
            f"cd {self.remote_workload_dir} && "
            f"setsid sh -c '"
            f"pgbench -h cockroachdb-public -p 26257 -U root -n -c 20 -j 4 -T {total_measurement_time} "
            f"--max-tries=1 -M simple benchdb > stdout.log 2> stderr.log; "
            f"echo $? > exit_code.txt' >/dev/null 2>&1 & "
            f"echo $! > pgid.txt && "
            f"cat pgid.txt"
        )
        meas_launch_cmd = [
            "kubectl", "exec", "-n", self.client_namespace, self.client_pod, "--",
            "sh", "-c", meas_launch_script
        ]

        log(f"Launching detached continuous measurement pgbench wrapper for {total_measurement_time}s in {self.remote_workload_dir}")
        launch_res = run_cmd(meas_launch_cmd, check=False, timeout=15.0)
        if launch_res.returncode != 0:
            raise RuntimeError(f"FAIL-CLOSED: Failed to launch detached measurement workload: {launch_res.stderr}")

        pgid_str = launch_res.stdout.strip()
        if pgid_str.isdigit():
            self.remote_pgid = int(pgid_str)
            log(f"Measurement remote process group captured: PGID {self.remote_pgid}")
        else:
            for _ in range(10):
                time.sleep(1.0)
                chk = run_cmd([
                    "kubectl", "exec", "-n", self.client_namespace, self.client_pod, "--",
                    "cat", f"{self.remote_workload_dir}/pgid.txt"
                ], check=False, timeout=5.0)
                if chk.returncode == 0 and chk.stdout.strip().isdigit():
                    self.remote_pgid = int(chk.stdout.strip())
                    log(f"Measurement remote process group captured via poll: PGID {self.remote_pgid}")
                    break

        if not self.remote_pgid:
            raise RuntimeError(f"FAIL-CLOSED: Failed to capture remote PGID for measurement workload in {self.remote_workload_dir}")

    def _poll_and_wait_remote_workload(
        self,
        phase_name: str,
        duration_sec: float,
        output_local_file: str,
        poll_interval: float = 2.0,
        grace_period_sec: float = 60.0
    ) -> int:
        """
        Durable polling loop for detached remote workload.
        Decoupled from streaming connections: uses short-lived kubectl commands with retry.
        Continuously verifies telemetry health while remote process runs.
        """
        start_t = time.time()
        timeout_t = start_t + duration_sec + grace_period_sec
        remote_completed = False
        consecutive_probe_failures = 0
        max_probe_failures = 10

        log(f"[REMOTE WORKLOAD] Polling remote {phase_name} execution (expected ~{duration_sec}s, timeout in {duration_sec + grace_period_sec}s)")

        while time.time() < timeout_t:
            self._check_telemetry_health(f"{phase_name}_monitoring")

            # Check if exit_code.txt exists and contains an exit code
            chk_cmd = [
                "kubectl", "exec", "-n", self.client_namespace, self.client_pod, "--",
                "sh", "-c", f"test -f {self.remote_workload_dir}/exit_code.txt && cat {self.remote_workload_dir}/exit_code.txt || echo PENDING"
            ]
            res = run_cmd(chk_cmd, check=False, timeout=8.0)

            if res.returncode == 0:
                consecutive_probe_failures = 0
                out = res.stdout.strip()
                if out != "PENDING" and out != "":
                    # Process completed
                    remote_completed = True
                    log(f"[REMOTE WORKLOAD] Remote {phase_name} process recorded completion: '{out}'")
                    break
            else:
                consecutive_probe_failures += 1
                log(f"[REMOTE WORKLOAD] Warning: Probe failed ({consecutive_probe_failures}/{max_probe_failures}): {res.stderr.strip() or res.stdout.strip()}")
                if consecutive_probe_failures >= max_probe_failures:
                    raise RuntimeError(f"FAIL-CLOSED: Lost connection to cluster: {consecutive_probe_failures} consecutive probe failures during {phase_name}")

            time.sleep(poll_interval)

        if not remote_completed:
            log(f"[REMOTE WORKLOAD ERROR] Remote {phase_name} timed out after {duration_sec + grace_period_sec}s")
            self._terminate_workload_process()
            raise subprocess.TimeoutExpired(cmd=f"remote_{phase_name}", timeout=duration_sec + grace_period_sec)

        return self._retrieve_and_validate_remote_workload(output_local_file)

    def _retrieve_and_validate_remote_workload(self, output_local_file: str) -> int:
        """
        Retrieves remote stdout, stderr, and exit_code from container workspace.
        Persists stdout and stderr into output_local_file and validates exit code.
        """
        # Read exit code
        exit_code_res = run_cmd([
            "kubectl", "exec", "-n", self.client_namespace, self.client_pod, "--",
            "cat", f"{self.remote_workload_dir}/exit_code.txt"
        ], check=False, timeout=10.0)

        if exit_code_res.returncode != 0:
            raise RuntimeError(f"FAIL-CLOSED: Missing remote exit status file at {self.remote_workload_dir}/exit_code.txt")

        exit_code_raw = exit_code_res.stdout.strip()
        try:
            exit_code = int(exit_code_raw)
        except ValueError:
            raise RuntimeError(f"FAIL-CLOSED: Corrupted remote exit code: '{exit_code_raw}'")

        # Retrieve stdout.log
        stdout_res = run_cmd([
            "kubectl", "exec", "-n", self.client_namespace, self.client_pod, "--",
            "cat", f"{self.remote_workload_dir}/stdout.log"
        ], check=False, timeout=30.0)

        # Retrieve stderr.log
        stderr_res = run_cmd([
            "kubectl", "exec", "-n", self.client_namespace, self.client_pod, "--",
            "cat", f"{self.remote_workload_dir}/stderr.log"
        ], check=False, timeout=30.0)

        remote_stdout = stdout_res.stdout if stdout_res.returncode == 0 else ""
        remote_stderr = stderr_res.stdout if stderr_res.returncode == 0 else ""

        # Write to local evidence file
        with open(output_local_file, "w", encoding="utf-8") as f:
            if remote_stdout:
                f.write(remote_stdout)
            if remote_stderr:
                if remote_stdout and not remote_stdout.endswith("\n"):
                    f.write("\n")
                f.write("=== STDERR ===\n")
                f.write(remote_stderr)

        log(f"[REMOTE WORKLOAD] Retrieved logs for {self.remote_workload_dir}: stdout {len(remote_stdout)} bytes, stderr {len(remote_stderr)} bytes, exit {exit_code}")
        return exit_code

    def _sleep_and_monitor(self, duration_sec: float, step: float = 2.0) -> None:
        """Sleep in increments while continuously validating telemetry health."""
        start = time.time()
        while time.time() - start < duration_sec:
            self._check_telemetry_health(self.current_state.value)
            remaining = duration_sec - (time.time() - start)
            time.sleep(min(step, max(0.0, remaining)))
        self._check_telemetry_health(self.current_state.value)

    def _state_baseline_measurement(self) -> None:
        """State 5: BASELINE_MEASUREMENT"""
        self._transition(ExecutionState.BASELINE_MEASUREMENT)
        log(f"Measuring pre-fault baseline for {self.baseline_sec}s")
        self._sleep_and_monitor(self.baseline_sec)

    def _state_fault_application(self) -> None:
        """State 6: FAULT_APPLICATION"""
        self._transition(ExecutionState.FAULT_APPLICATION)
        log(f"Applying StressChaos manifest: {self.manifest_path}")

        # Fail-closed re-verification of target pod identity immediately before fault injection
        self._reverify_target_identity()

        cmd = ["kubectl", "apply", "-f", self.manifest_path]
        res = run_cmd(cmd, check=True, timeout=15.0)
        log(f"Chaos Mesh StressChaos applied: {res.stdout.strip()}")
        self.fault_injected = True

    def _reverify_target_identity(self) -> None:
        """Verify target pod UID has not migrated or drifted."""
        target_pod = self.target_spec.get("pod_name", "cockroachdb-1")
        target_ns = self.target_spec.get("namespace", "cockroachdb")
        res = run_cmd(["kubectl", "get", "pod", target_pod, "-n", target_ns, "-o", "json"], check=True, timeout=10.0)
        pod_data = json.loads(res.stdout)
        current_uid = pod_data["metadata"]["uid"]
        current_node = pod_data["spec"]["nodeName"]

        if current_uid != self.target_pod_uid:
            raise RuntimeError(f"FAIL-CLOSED: Target pod migrated! Expected UID {self.target_pod_uid}, got {current_uid}")
        if current_node != self.target_node:
            raise RuntimeError(f"FAIL-CLOSED: Target node drifted! Expected {self.target_node}, got {current_node}")

    def _state_fault_verification(self) -> None:
        """State 7: FAULT_VERIFICATION"""
        self._transition(ExecutionState.FAULT_VERIFICATION)
        log("Verifying StressChaos status and injection into container before measurement starts")
        # Poll StressChaos status
        injected = False
        start_wait = time.time()
        while time.time() - start_wait < 30.0:
            res = run_cmd(["kubectl", "get", "stresschaos", self.stresschaos_name, "-n", self.chaos_namespace, "-o", "json"], check=False, timeout=10.0)
            if res.returncode == 0:
                sc_data = json.loads(res.stdout)
                status = sc_data.get("status", {})
                conditions = status.get("conditions", [])
                for cond in conditions:
                    if cond.get("type") in ("Injected", "AllInjected") and cond.get("status") == "True":
                        injected = True
                        break
                if injected:
                    break
            time.sleep(2.0)

        if not injected:
            raise RuntimeError(
                f"FAIL-CLOSED: StressChaos {self.stresschaos_name} failed to reach Injected=True state within 30s. "
                "Fault application cannot be verified before fault measurement."
            )
        log(f"StressChaos {self.stresschaos_name} verified injected and active.")

    def _state_fault_measurement(self) -> None:
        """State 8: FAULT_MEASUREMENT"""
        self._transition(ExecutionState.FAULT_MEASUREMENT)
        log(f"Active fault measurement period: {self.fault_sec}s")
        self._sleep_and_monitor(self.fault_sec)

    def _state_fault_removal(self) -> None:
        """State 9: FAULT_REMOVAL"""
        self._transition(ExecutionState.FAULT_REMOVAL)
        log(f"Removing StressChaos custom resource '{self.stresschaos_name}'")
        cmd = ["kubectl", "delete", "stresschaos", self.stresschaos_name, "-n", self.chaos_namespace, "--ignore-not-found=true"]
        run_cmd(cmd, check=True, timeout=15.0)
        self.fault_injected = False
        log("StressChaos resource deletion command executed.")

    def _state_restoration_verification(self) -> None:
        """State 10: RESTORATION_VERIFICATION"""
        self._transition(ExecutionState.RESTORATION_VERIFICATION)
        log("Verifying removal of StressChaos and cgroup stressor termination")
        res = run_cmd(["kubectl", "get", "stresschaos", self.stresschaos_name, "-n", self.chaos_namespace], check=False, timeout=10.0)
        if res.returncode == 0 and "NotFound" not in res.stderr:
            # Wait up to 15 seconds for finalizers
            time.sleep(5.0)
            res2 = run_cmd(["kubectl", "get", "stresschaos", self.stresschaos_name, "-n", self.chaos_namespace], check=False, timeout=10.0)
            if res2.returncode == 0 and "NotFound" not in res2.stderr:
                raise RuntimeError(f"StressChaos resource {self.stresschaos_name} failed to delete completely")
        log("StressChaos resource confirmed removed from cluster.")

    def _state_post_fault_measurement(self) -> None:
        """State 11: POST_FAULT_MEASUREMENT"""
        self._transition(ExecutionState.POST_FAULT_MEASUREMENT)
        log("Monitoring post-fault workload execution")

    def _state_wrec_observation(self) -> None:
        """State 12: WREC_OBSERVATION"""
        self._transition(ExecutionState.WREC_OBSERVATION)
        log(f"Recovery observation window ({self.recovery_sec}s anchored to T_clear)")
        self._sleep_and_monitor(self.recovery_sec)

        # In durable detached mode, wait for remote measurement workload to complete, retrieve logs, and validate exit code
        if not self.dry_run and self.remote_workload_dir:
            log("Awaiting completion of continuous measurement pgbench workload in container")
            total_duration = self.baseline_sec + self.fault_sec + self.recovery_sec
            meas_rc = self._poll_and_wait_remote_workload(
                phase_name="measurement",
                duration_sec=total_duration,
                output_local_file=self.workload_stdout_file,
                poll_interval=2.0,
                grace_period_sec=60.0
            )
            log(f"Continuous measurement workload completed with exit code {meas_rc}")
            if meas_rc != 0:
                raise RuntimeError(f"FAIL-CLOSED: Measurement pgbench process failed with exit code {meas_rc}")
            self.remote_pgid = None

        elif self.workload_process:
            # Fallback for mock/local subprocess tests
            log("Waiting for measurement pgbench process to conclude")
            t_wait_start = time.time()
            wait_timeout = 60.0
            while self.workload_process.poll() is None:
                self._check_telemetry_health("wrec_observation_workload_drain")
                if time.time() - t_wait_start > wait_timeout:
                    log("[WARNING] Measurement pgbench process timed out waiting to conclude. Cleaning up.")
                    self._terminate_workload_process()
                    self.workload_process.poll()
                    break
                time.sleep(1.0)

    def _state_final_health_check(self) -> None:
        """State 13: FINAL_HEALTH_CHECK"""
        self._transition(ExecutionState.FINAL_HEALTH_CHECK)
        log("Performing final CockroachDB cluster health check")
        target_pod = self.target_spec.get("pod_name", "cockroachdb-1")
        target_ns = self.target_spec.get("namespace", "cockroachdb")
        res = run_cmd(["kubectl", "get", "pod", target_pod, "-n", target_ns, "-o", "json"], check=True)
        pod_data = json.loads(res.stdout)
        phase = pod_data.get("status", {}).get("phase")
        if phase != "Running":
            raise RuntimeError(f"Final health check failed: target pod is {phase}")

    def _state_evidence_collection(self) -> None:
        """State 14: EVIDENCE_COLLECTION"""
        self._transition(ExecutionState.EVIDENCE_COLLECTION)
        log(f"Persisting evidence artifacts into {self.output_dir}")

        # 00_execution_record.json
        exec_record_path = os.path.join(self.output_dir, "00_execution_record.json")
        with open(exec_record_path, "w", encoding="utf-8") as f:
            json.dump({
                "run_id": self.run_id,
                "level": self.level,
                "protocol": PROTOCOL_VERSION,
                "disposition": self.disposition,
                "target": {
                    "pod": self.target_spec.get("pod_name"),
                    "pod_uid": self.target_pod_uid,
                    "node": self.target_node,
                    "container": self.target_spec.get("container_name")
                },
                "timings": {
                    "warmup_sec": self.warmup_sec,
                    "baseline_sec": self.baseline_sec,
                    "fault_sec": self.fault_sec,
                    "recovery_sec": self.recovery_sec
                },
                "authorization": self.auth_record,
                "state_history": self.state_history,
                "rollback_reports": self.rollback_reports
            }, f, indent=2)

        # 01_preflight_audit.json
        preflight_path = os.path.join(self.output_dir, "01_preflight_audit.json")
        with open(preflight_path, "w", encoding="utf-8") as f:
            json.dump(self.preflight_report, f, indent=2)

        # 02_telemetry_timeseries.jsonl
        telemetry_path = os.path.join(self.output_dir, "02_telemetry_timeseries.jsonl")
        with open(telemetry_path, "w", encoding="utf-8") as f:
            for sample in self.telemetry_data:
                f.write(json.dumps(sample) + "\n")

        # Copy manifest
        manifest_copy_path = os.path.join(self.output_dir, "03_stresschaos_manifest.yaml")
        if os.path.isfile(self.manifest_path):
            with open(self.manifest_path, "r", encoding="utf-8") as src, open(manifest_copy_path, "w", encoding="utf-8") as dst:
                dst.write(src.read())

        # Generate SHA256SUMS.txt
        build_manifest(self.output_dir)
        verify_manifest(self.output_dir)

    def _state_final_disposition(self) -> None:
        """State 15: FINAL_DISPOSITION"""
        self._transition(ExecutionState.FINAL_DISPOSITION)
        log(f"[FINAL DISPOSITION] {self.disposition}")

    def _terminate_workload_process(self) -> Dict[str, Any]:
        """
        Safely and comprehensively terminates local and remote workload processes.
        1. Gracefully terminate local kubectl exec wrapper via terminate() if active.
        2. Escalate to kill() if necessary. If already exited, record already_exited.
        3. If remote_pgid is known, terminate remote process group (-remote_pgid) via terminate_remote_process_group.
        4. Close open file descriptors.
        """
        report: Dict[str, Any] = {
            "local_pid": self.workload_process.pid if self.workload_process else None,
            "local_terminated": False,
            "local_already_exited": False,
            "remote_pgid": self.remote_pgid,
            "remote_termination_result": None
        }

        # 1. Local process cleanup
        if self.workload_process:
            if self.workload_process.poll() is None:
                log(f"Terminating local child workload process PID {self.workload_process.pid}")
                try:
                    self.workload_process.terminate()
                    self.workload_process.wait(timeout=5.0)
                    report["local_terminated"] = True
                except Exception:
                    try:
                        self.workload_process.kill()
                        self.workload_process.wait(timeout=5.0)
                        report["local_terminated"] = True
                    except Exception as ke:
                        log(f"[WARNING] Could not kill local workload process: {ke}")
            else:
                report["local_already_exited"] = True

        # 2. Close file handles
        if hasattr(self, "workload_fd") and self.workload_fd and not self.workload_fd.closed:
            try:
                self.workload_fd.close()
            except Exception:
                pass
        if hasattr(self, "warmup_fd") and self.warmup_fd and not self.warmup_fd.closed:
            try:
                self.warmup_fd.close()
            except Exception:
                pass

        # 3. Remote process cleanup via tracked PGID
        if self.remote_pgid and not self.dry_run:
            try:
                res = terminate_remote_process_group(self.client_namespace, self.client_pod, self.remote_pgid)
                report["remote_termination_result"] = res
            except Exception as e:
                log(f"[PROCESS CLEANUP ERROR] Failed to terminate remote PGID -{self.remote_pgid}: {e}")
                report["remote_termination_result"] = {"error": str(e), "verified_dead": False}

        return report

    def _emergency_rollback(self) -> Dict[str, Any]:
        """
        Comprehensive, idempotent fail-closed emergency recovery:
        1. Stop or remove the active StressChaos resource.
        2. Verify the fault is no longer active.
        3. Terminate runner-owned pgbench processes (local + remote).
        4. Verify all runner-owned processes have exited.
        5. Stop telemetry workers.
        6. Close output files and subprocess handles.
        7. Preserve incident evidence artifacts.
        8. Write final incident disposition.
        """
        log(f"[EMERGENCY ROLLBACK] Invoking isolated emergency cleanup for StressChaos resource '{self.stresschaos_name}'")
        rollback_report: Dict[str, Any] = {
            "timestamp_utc": _utc_now().isoformat(),
            "stresschaos_deleted": False,
            "fault_removal_verified": False,
            "workload_cleanup": None,
            "errors": []
        }

        # Step 1: Remove StressChaos resource
        try:
            res = run_cmd([
                "kubectl", "delete", "stresschaos", self.stresschaos_name,
                "-n", self.chaos_namespace, "--force", "--grace-period=0", "--ignore-not-found=true"
            ], check=False, timeout=15.0)
            log(f"[EMERGENCY ROLLBACK] Rollback command for {self.stresschaos_name} completed: {res.stdout.strip()}")
            rollback_report["stresschaos_deleted"] = (res.returncode == 0)
        except Exception as e:
            msg = f"Rollback command failed: {e}"
            log(f"[CRITICAL ROLLBACK ERROR] {msg}")
            rollback_report["errors"].append(msg)
        finally:
            self.fault_injected = False

        # Step 2: Verify fault is no longer active
        try:
            res_chk = run_cmd(["kubectl", "get", "stresschaos", self.stresschaos_name, "-n", self.chaos_namespace], check=False, timeout=10.0)
            if res_chk.returncode != 0 or "NotFound" in res_chk.stderr or not res_chk.stdout.strip():
                rollback_report["fault_removal_verified"] = True
            else:
                rollback_report["fault_removal_verified"] = False
                rollback_report["errors"].append("StressChaos resource still visible after deletion")
        except Exception as e:
            rollback_report["errors"].append(f"Error checking fault removal: {e}")

        # Step 3 & 4: Terminate runner-owned pgbench processes and verify
        try:
            wl_report = self._terminate_workload_process()
            rollback_report["workload_cleanup"] = wl_report
        except Exception as e:
            msg = f"Error during workload process termination: {e}"
            log(f"[CRITICAL WORKLOAD CLEANUP ERROR] {msg}")
            rollback_report["errors"].append(msg)

        # Step 5: Stop telemetry
        try:
            self._stop_telemetry()
        except Exception as e:
            rollback_report["errors"].append(f"Error stopping telemetry: {e}")

        # Step 6 & 7: Preserve partial measurements & incident record
        try:
            self._preserve_partial_evidence(rollback_report)
        except Exception as e:
            log(f"[WARNING] Failed to preserve incident evidence: {e}")

        self.rollback_reports.append(rollback_report)
        return rollback_report

    def _preserve_partial_evidence(self, rollback_report: Dict[str, Any]) -> None:
        """Persists incident execution record, partial telemetry, and rollback report."""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

        incident_path = os.path.join(self.output_dir, "00_incident_record.json")
        try:
            with open(incident_path, "w", encoding="utf-8") as f:
                json.dump({
                    "run_id": self.run_id,
                    "level": self.level,
                    "protocol": PROTOCOL_VERSION,
                    "disposition": "FAILED",
                    "failure_reason": self.failure_reason,
                    "state_at_failure": self.current_state.value,
                    "state_history": self.state_history,
                    "target": {
                        "pod": self.target_spec.get("pod_name"),
                        "pod_uid": self.target_pod_uid,
                        "node": self.target_node,
                        "container": self.target_spec.get("container_name")
                    },
                    "rollback_report": rollback_report,
                    "telemetry_samples_captured": len(self.telemetry_data)
                }, f, indent=2)
        except Exception as e:
            log(f"[WARNING] Could not write incident record: {e}")

        # Flush partial telemetry
        telemetry_path = os.path.join(self.output_dir, "02_telemetry_timeseries.jsonl")
        try:
            with open(telemetry_path, "w", encoding="utf-8") as f:
                for s in self.telemetry_data:
                    f.write(json.dumps(s) + "\n")
        except Exception as e:
            log(f"[WARNING] Could not write partial telemetry: {e}")

    def _start_telemetry(self) -> None:
        self.stop_telemetry_event.clear()
        self.telemetry_status["thread_alive"] = True
        self.telemetry_status["started_at_epoch"] = time.time()
        self.telemetry_status["last_sample_epoch"] = time.time()
        self.telemetry_status["sample_count"] = 0
        self.telemetry_status["max_observed_gap_sec"] = 0.0
        self.telemetry_status["gap_exceeded"] = False
        self.telemetry_status["error"] = None
        self.telemetry_status["missed_samples"] = 0

        self.telemetry_thread = threading.Thread(target=self._telemetry_worker, daemon=True)
        self.telemetry_thread.start()

    def _stop_telemetry(self) -> None:
        self.stop_telemetry_event.set()
        if self.telemetry_thread:
            self.telemetry_thread.join(timeout=10.0)
            if self.telemetry_thread.is_alive():
                log("[WARNING] Telemetry thread did not exit within timeout")
        self.telemetry_status["thread_alive"] = False

    def _telemetry_worker(self) -> None:
        log("Continuous telemetry sampling worker started.")
        target_pod = self.target_spec.get("pod_name", "cockroachdb-1")
        target_ns = self.target_spec.get("namespace", "cockroachdb")

        try:
            while not self.stop_telemetry_event.is_set():
                t_poll_start = time.time()
                sample_success = False

                sample: Dict[str, Any] = {
                    "timestamp_utc": _utc_now().isoformat(),
                    "epoch_sec": t_poll_start,
                    "state": self.current_state.value
                }

                # 1. Sample cgroup cpu.stat from target container
                try:
                    cgroup_cmd = [
                        "kubectl", "exec", "-n", target_ns, target_pod, "-c", "db", "--",
                        "cat", "/sys/fs/cgroup/cpu.stat"
                    ]
                    res = run_cmd(cgroup_cmd, check=False, timeout=4.0)
                    if res.returncode == 0:
                        sample["cgroup_cpu_stat"] = parse_cgroup_cpu_stat(res.stdout)
                        sample_success = True
                    else:
                        sample["cgroup_error"] = f"Exit code {res.returncode}: {res.stderr.strip()}"
                except subprocess.TimeoutExpired:
                    sample["cgroup_error"] = "Command timed out after 4.0s"
                except Exception as e:
                    sample["cgroup_error"] = str(e)

                # 2. Sample node and pod top stats
                try:
                    top_cmd = ["kubectl", "top", "pod", target_pod, "-n", target_ns, "--no-headers"]
                    res = run_cmd(top_cmd, check=False, timeout=4.0)
                    if res.returncode == 0 and res.stdout.strip():
                        parts = res.stdout.strip().split()
                        if len(parts) >= 3:
                            sample["pod_cpu_millicores"] = parts[1]
                            sample["pod_memory_bytes"] = parts[2]
                            sample_success = True
                    else:
                        sample["top_error"] = f"Exit code {res.returncode}: {res.stderr.strip()}"
                except subprocess.TimeoutExpired:
                    sample["top_error"] = "Command timed out after 4.0s"
                except Exception as e:
                    sample["top_error"] = str(e)

                now_epoch = time.time()
                if sample_success:
                    gap = now_epoch - self.telemetry_status["last_sample_epoch"]
                    if self.telemetry_status["sample_count"] > 0 and gap > self.telemetry_status["max_observed_gap_sec"]:
                        self.telemetry_status["max_observed_gap_sec"] = gap
                    self.telemetry_status["last_sample_epoch"] = now_epoch
                    self.telemetry_status["sample_count"] += 1
                else:
                    self.telemetry_status["missed_samples"] += 1
                    gap = now_epoch - self.telemetry_status["last_sample_epoch"]
                    if gap > self.telemetry_status["max_observed_gap_sec"]:
                        self.telemetry_status["max_observed_gap_sec"] = gap
                    if gap > self.max_telemetry_gap_sec:
                        self.telemetry_status["gap_exceeded"] = True
                        err_msg = f"Telemetry continuity gap {gap:.2f}s exceeded limit {self.max_telemetry_gap_sec}s"
                        self.telemetry_status["error"] = err_msg
                        log(f"[CRITICAL] {err_msg}")

                self.telemetry_data.append(sample)

                elapsed = time.time() - t_poll_start
                sleep_time = max(0.0, self.telemetry_interval - elapsed)
                if self.stop_telemetry_event.wait(timeout=sleep_time):
                    break
        except Exception as te:
            err_msg = f"Fatal telemetry worker exception: {te}"
            self.telemetry_status["error"] = err_msg
            log(f"[CRITICAL] {err_msg}")
        finally:
            self.telemetry_status["thread_alive"] = False
            log("Continuous telemetry sampling worker stopped.")

    def _build_result(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "level": self.level,
            "disposition": self.disposition,
            "output_dir": self.output_dir,
            "state_history": self.state_history,
            "preflight": self.preflight_report,
            "failure_reason": self.failure_reason,
            "rollback_reports": self.rollback_reports
        }

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CockroachDB G4 CPU Starvation Pilot Runner")
    parser.add_argument("--run-id", required=True, help="Unique run identifier (e.g. crdb-g4l1-p01)")
    parser.add_argument("--level", required=True, choices=["L1", "L2", "L3"], help="CPU starvation severity level")
    parser.add_argument("--output-dir", required=True, help="Directory to persist run evidence")
    parser.add_argument("--auth-file", help="Path to signed operator authorization token")
    parser.add_argument("--preflight-only", action="store_true", help="Perform read-only preflight and target verification without fault injection")
    parser.add_argument("--config", help="Path to custom runner configuration JSON")
    parser.add_argument("--public-key", help="Path to trusted operator public key file")
    parser.add_argument("--warmup-sec", type=int, help="Override warmup duration")
    parser.add_argument("--baseline-sec", type=int, help="Override baseline measurement duration")
    parser.add_argument("--fault-sec", type=int, help="Override fault duration")
    parser.add_argument("--recovery-sec", type=int, help="Override recovery observation duration")
    return parser.parse_args()

def main():
    args = parse_args()
    coordinator = G4PilotExecutionCoordinator(
        run_id=args.run_id,
        level=args.level,
        output_dir=args.output_dir,
        auth_file=args.auth_file,
        dry_run=args.preflight_only,
        config_path=args.config,
        public_key_path=args.public_key,
        warmup_sec=args.warmup_sec,
        baseline_sec=args.baseline_sec,
        fault_sec=args.fault_sec,
        recovery_sec=args.recovery_sec
    )
    result = coordinator.execute()
    print(json.dumps(result, indent=2))
    if result["disposition"] not in ("SIMULATED_SUCCESS", "EXECUTED_VALIDATED"):
        sys.exit(1)

if __name__ == "__main__":
    main()
